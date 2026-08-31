import db from '@adonisjs/lucid/services/db'
import { v7 as uuidv7 } from 'uuid'
import type {
  AuthorizationDriver,
  CatalogRoleRef,
  DenyRef,
  GrantOptions,
  GrantOutcome,
  NormalizedRoleQuery,
  RoleQuery,
  ScopeRef,
  ScopeType,
  SubjectRef,
} from '../types.js'
import type { ScopeChainResolver } from '../types.js'
import { APP_SCOPE_TYPE } from '../types.js'
import { assertCatalogUuid, assertIdentity, assertScope, chainKeysFrom, normalizeRoleQuery, scopeKey } from '../identity.js'
import { resolveGrantExpiry, sameInstant } from '../expiry.js'
import {
  AuthorizationBackendError,
  AuthorizationConfigError,
  AuthorizationInternalError,
  InvalidIdentityError,
  RoleNotVisibleError,
  UnknownPermissionError,
  UnknownRoleError,
} from '../errors.js'
import { assertKnownScope, canonicalScope, guardSql, resolveChain, rootOnlyResolver } from './backend_guard.js'
import { assertAssignableAt } from '../catalog.js'
import { CatalogCache, GLOBAL_OWNER_KEY, assertCatalogOptions, isRoleVisibleWith, withAuthzCatalogWrite } from '../catalog_cache.js'
import type { CatalogRevalidate, CatalogRole, CatalogView } from '../catalog_cache.js'
import { isClock, systemClock } from '../clock.js'
import type { Clock } from '../clock.js'
import { sqlExpiryCodec } from './sql_expiry.js'
import type { ExpiryCodec } from './sql_expiry.js'

export type QueryBuilder = ReturnType<typeof db.from>

/**
 * UUID centinela para el scope 'app' en las columnas scope_uuid (NOT NULL):
 * permite que el unique de assignments/denies cubra también el nivel app
 * (los NULL serían "distintos" para el motor SQL). Detalle de almacenamiento
 * de ESTE driver — la API pública sigue usando uuid null para app.
 */
export const APP_SCOPE_DB_UUID = '00000000-0000-0000-0000-000000000000'

function toDbScopeUuid(scope: ScopeRef): string {
  // Defensa en profundidad (L0.10/L0.15): es el único punto donde el scope
  // se serializa a columnas, así que aquí se garantiza que `app` no lleve
  // uuid y que ningún otro tipo use el centinela de la raíz.
  assertScope(scope)
  return scope.uuid ?? APP_SCOPE_DB_UUID
}

function fromDbScopeUuid(uuid: string): string | null {
  return uuid === APP_SCOPE_DB_UUID ? null : uuid
}

/**
 * Clave de agrupación por scope de las filas de `authz_*` (3D · N5: UNA sola
 * codificación en el driver). No es `scopeKey` de `identity.ts`: aquí el
 * uuid es el de la COLUMNA (con el centinela de la raíz), porque es lo que
 * devuelven las consultas. `\u001f` separa: ningún componente lo admite.
 */
function dbScopeKey(scope: ScopeRef): string {
  return `${scope.type}\u001f${toDbScopeUuid(scope)}`
}

function rowScopeKey(row: { scope_type: string; scope_uuid: string }): string {
  return `${row.scope_type}\u001f${row.scope_uuid}`
}

/**
 * El rol `(slug, scopeType)` que existe en el scope cuya cadena empieza por
 * `chainKeys`, o 422: `E_AUTHZ_ROLE_NOT_VISIBLE` si hay roles con ese nombre
 * pero todos son locales a otro contenedor; `E_AUTHZ_UNKNOWN_ROLE` si no hay
 * ninguno. Compartido por ambos drivers (3B · B2).
 */
export function visibleRoleOrFail(catalog: CatalogView, slug: string, scope: ScopeRef, chainKeys: readonly string[]): CatalogRole {
  const visible = catalog.roleVisible(slug, scope.type, chainKeys)
  if (visible) return visible
  const named = catalog.rolesNamed(slug, scope.type)
  if (named.length === 0) throw new UnknownRoleError(slug, scope.type)
  // 3E · Q2 (auditor A6): NO se nombran los owners. Si ninguno es visible
  // desde este scope, todos son locales a un contenedor que NO está en la
  // cadena preguntada: imprimir sus claves regalaba a un tenant los
  // identificadores de scope de otro (un 422 es lo que un framework devuelve
  // tal cual al cliente). Lo que el llamante necesita saber —que el nombre
  // existe pero no aquí— cabe sin ellos.
  throw new RoleNotVisibleError(
    `El rol '${slug}' (nivel '${scope.type}') no existe en ${scope.type}:${scope.uuid ?? ''}: hay ${named.length} ` +
      `${named.length === 1 ? 'rol' : 'roles'} con ese nombre en el catálogo, ${named.length === 1 ? 'local' : 'locales'} ` +
      `a un scope que no está en la cadena de este. Un rol local solo se asigna en su owner o en sus descendientes.`
  )
}

/**
 * EL rol al que apunta un `RoleQuery` en un scope concreto (3D · M1), para
 * las rutas que direccionan un rol exacto (`grant`, `listSubjects`):
 *
 *  - `{ uuid }`: resolución EXACTA, sin ambigüedad posible. Fuera del
 *    catálogo ⇒ 422 `E_AUTHZ_UNKNOWN_ROLE`; declarado para otro nivel o con
 *    el owner fuera de la cadena ⇒ 422 `E_AUTHZ_ROLE_NOT_VISIBLE` (no existe
 *    AQUÍ, que es lo mismo que decía la ruta por slug).
 *  - slug (con nivel opcional): `visibleRoleOrFail`, que ahora falla cerrado
 *    si hay más de un homónimo visible (422 `E_AUTHZ_AMBIGUOUS_ROLE`).
 *
 * Compartido por ambos drivers.
 */
export function resolveRoleQuery(catalog: CatalogView, role: RoleQuery, scope: ScopeRef, chainKeys: readonly string[]): CatalogRole {
  const query = normalizeRoleQuery(role)
  if (query.uuid !== undefined) {
    const declared = catalog.roleByUuid(query.uuid)
    if (!declared) throw new UnknownRoleError(query.uuid)
    if (declared.scopeType !== scope.type || !isRoleVisibleWith(declared, chainKeys)) {
      // 3E · Q2: el uuid de un rol de OTRO árbol no devuelve su slug ni su
      // owner (sería una sonda: pruebo uuids y aprendo el catálogo ajeno).
      // Cuando el owner SÍ está en la cadena, el rol es del llamante y
      // nombrarlo le dice exactamente qué pasa (nivel equivocado).
      throw new RoleNotVisibleError(
        isRoleVisibleWith(declared, chainKeys)
          ? `El rol '${declared.slug}' (${declared.uuid}, owner ${declared.owner}) está declarado para el nivel ` +
              `'${declared.scopeType}' y no existe en ${scope.type}:${scope.uuid ?? ''}.`
          : `El rol ${declared.uuid} no existe en ${scope.type}:${scope.uuid ?? ''}: es local a un scope que no está ` +
              `en la cadena de ese scope.`
      )
    }
    return declared
  }
  if (query.scopeType !== undefined && query.scopeType !== scope.type) {
    // `{ slug, scopeType }` apunta a un rol de OTRO nivel: en un scope de tipo
    // `scope.type` ese rol no existe (un rol vive en su nivel, D5/L0.6).
    throw new UnknownRoleError(query.slug, scope.type)
  }
  return visibleRoleOrFail(catalog, query.slug, scope, chainKeys)
}

/**
 * EL rol al que apunta un `RoleQuery` en un scope, para el camino de LECTURA
 * (`listSubjects`): `null` si el catálogo no declara ninguno que exista ahí
 * (invariante 5: desconocido no lanza). La AMBIGÜEDAD sí lanza (3D · M1):
 * elegir uno de dos homónimos era enumerar los holders del otro tenant.
 */
export function visibleRoleFor(
  catalog: CatalogView,
  query: NormalizedRoleQuery,
  scope: ScopeRef,
  chainKeys: readonly string[]
): CatalogRole | null {
  if (query.uuid !== undefined) {
    const declared = catalog.roleByUuid(query.uuid)
    if (!declared || declared.scopeType !== scope.type || !isRoleVisibleWith(declared, chainKeys)) return null
    return declared
  }
  if (query.scopeType !== undefined && query.scopeType !== scope.type) return null
  return catalog.roleVisible(query.slug, scope.type, chainKeys)
}

/**
 * Los roles a los que un `RoleQuery` puede referirse en un scope, para
 * `revoke` (3D · M1): por uuid, ESE rol (422 si el catálogo no lo declara);
 * por slug, TODOS los homónimos `(slug, nivel)` — quitar nunca concede y el
 * scope puede no existir ya para el árbol (D8), así que no se resuelve la
 * ambigüedad: se quitan todos. 422 `E_AUTHZ_UNKNOWN_ROLE` si no hay ninguno.
 */
export function rolesToRevoke(catalog: CatalogView, role: RoleQuery, scope: ScopeRef): CatalogRole[] {
  const query = normalizeRoleQuery(role)
  if (query.uuid !== undefined) {
    const declared = catalog.roleByUuid(query.uuid)
    if (!declared) throw new UnknownRoleError(query.uuid)
    return [declared]
  }
  const level = query.scopeType ?? scope.type
  const named = catalog.rolesNamed(query.slug, level)
  if (named.length === 0) throw new UnknownRoleError(query.slug, level)
  return named
}

/**
 * Los niveles de la cadena donde una asignación de ESE rol contaría, para
 * `hasRole` (3D · M1): los scopes del tipo del rol desde los que el rol es
 * visible por owner. `null` = el catálogo no declara nada que responda (la
 * membresía es `false`, nunca un throw: invariante 5).
 */
export function hasRoleTargets(
  catalog: CatalogView,
  role: RoleQuery,
  chain: ScopeRef[]
): Array<{ scope: ScopeRef; roleUuid: string }> {
  const query = normalizeRoleQuery(role)
  const keysFrom = chainKeysFrom(chain)
  if (query.uuid !== undefined) {
    const declared = catalog.roleByUuid(query.uuid)
    if (!declared) return []
    return chain.flatMap((s, i) =>
      s.type === declared.scopeType && isRoleVisibleWith(declared, keysFrom[i]) ? [{ scope: s, roleUuid: declared.uuid }] : []
    )
  }
  return chain.flatMap((s, i) => {
    if (query.scopeType !== undefined && s.type !== query.scopeType) return []
    const declared = catalog.roleVisible(query.slug, s.type, keysFrom[i])
    return declared ? [{ scope: s, roleUuid: declared.uuid }] : []
  })
}

/**
 * Control de COMPOSICIÓN en la escritura (3B · B5, defensa en profundidad):
 * un rol de nivel L que lleve un permiso cuyo `assignableAt` no incluye L no
 * se asigna (422 `E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT`). El sync y
 * `defineScopedRole` ya lo rechazan al componer; aquí se cierra el vínculo
 * escrito a mano. `authorize` NUNCA lo mira: lo ya asignado sigue
 * concediendo (invariante 1).
 */
export function assertRoleAssignableAt(catalog: CatalogView, role: CatalogRole): void {
  // La regla es UNA (3D · N5): la misma que aplican `syncAuthzCatalog` y
  // `defineScopedRole` al componer (`assertAssignableAt`, `catalog.ts`).
  for (const permission of catalog.rolePermissionsOf(role.uuid)) {
    assertAssignableAt(role, permission, catalog.permission(permission)?.assignableAt ?? null)
  }
}

/**
 * EL rol de un uuid, si EXISTE en un scope de nivel `scopeType` cuya cadena
 * tiene esas claves: declarado para ese nivel (D5/L0.6) y global o con el
 * owner en la cadena desde ahí (3B · B2). `null` si no. Es la regla de
 * visibilidad por uuid, en UN sitio (3D · N5): la usan `listRoles`,
 * `rolesInChain`, `listRoleScopes`/`listScopes` (`visibleAt`) en `database`
 * y `declaredRole` en `openfga`.
 */
export function declaredRoleAt(
  catalog: CatalogView,
  roleUuid: string,
  scopeType: ScopeType,
  chainKeys: readonly string[]
): CatalogRole | null {
  const declared = catalog.roleByUuid(roleUuid)
  if (!declared || declared.scopeType !== scopeType) return null
  return isRoleVisibleWith(declared, chainKeys) ? declared : null
}

/**
 * Filtro (scope_type, scope_uuid) ∈ scopes (centinela para el nivel app).
 *
 * Con `scopes` VACÍO no hay filtro que construir, y "sin filtro" en SQL es
 * "todas las filas": la consulta de denies sobre-bloquearía (cerrado) pero la
 * de asignaciones concedería en CUALQUIER scope (abierto) — L0.1. Hoy ningún
 * call-site pasa un conjunto vacío (la cadena siempre contiene el scope), pero
 * `descendantsOf`/`authorizedScopes` (Fase 2) lo harán alcanzable:
 *  - lectura ⇒ `null`: nada puede coincidir, el llamante responde vacío/false
 *    SIN ejecutar la consulta;
 *  - escritura ⇒ 500: escribir "en ningún scope" es un bug de programación.
 * Exportada (no método privado) para poder fijarlo con un test.
 */
export function whereScopeIn(
  query: QueryBuilder,
  column: string,
  scopes: ScopeRef[],
  intent: 'write'
): QueryBuilder
export function whereScopeIn(
  query: QueryBuilder,
  column: string,
  scopes: ScopeRef[],
  intent: 'read'
): QueryBuilder | null
export function whereScopeIn(
  query: QueryBuilder,
  column: string,
  scopes: ScopeRef[],
  intent: 'read' | 'write'
): QueryBuilder | null {
  if (scopes.length === 0) {
    if (intent === 'write') {
      throw new AuthorizationInternalError(
        `whereScopeIn: una escritura sin scopes no tiene destino (columna '${column}')`
      )
    }
    return null
  }
  return query.where((outer) => {
    for (const s of scopes) {
      outer.orWhere((inner) => {
        inner.where(`${column}_type`, s.type).where(`${column}_uuid`, toDbScopeUuid(s))
      })
    }
  })
}

export interface DatabaseDriverOptions {
  /** Jerarquía del consumidor: la cadena canónica de cada scope (ver `ScopeChainResolver`). */
  resolveChain?: ScopeChainResolver
  /**
   * Deadline de cada consulta SQL en ms (default 5000). Vencido ⇒ 503
   * `E_AUTHZ_BACKEND_TIMEOUT`. Sin deadline, una base saturada convertía cada
   * request autorizada en un socket retenido para siempre (L0.13).
   */
  timeoutMs?: number
  /**
   * Memo del catálogo compartido con otro driver del mismo proceso (2A). Si
   * se omite, el driver construye el suyo. Se revalida contra la versión
   * compartida de la base (`authz_catalog_version`) según `catalogRevalidate`.
   */
  catalog?: CatalogCache
  /**
   * Cuándo contrastar el memo con la versión compartida (2D · F1): `'always'`
   * (default; un SELECT por clave primaria por pregunta) o `{ everyMs }`
   * (opt-in: ventana acotada en la que un sync de OTRO proceso aún no se ve).
   * Solo aplica al memo que construye este driver.
   */
  catalogRevalidate?: CatalogRevalidate
  /**
   * Reloj de pared con el que el driver DECIDE la caducidad (2.5 · J1):
   * `expires_at > now()` en cada lectura y los tres estados del re-grant.
   * Default `() => new Date()`. Inyectable para fijar el instante en tests;
   * en producción lo normal es no tocarlo (o pasar `clock` en el config del
   * manager, que lo aplica con `withClock`). Los sellos de auditoría
   * (`created_at`) NO lo usan (2.5-B · K5): son «cuándo se escribió», no
   * una decisión, y con `TIMESTAMP` de MySQL un reloj inyectado en 2040
   * hacía imposible escribir.
   */
  now?: Clock
}

export const DEFAULT_TIMEOUT_MS = 5_000

/**
 * Driver `database`: motor de autorización propio sobre las tablas `authz_*`.
 * Default autosuficiente del chasis (cero piezas extra en el appliance).
 *
 * Resolución de `authorize`: NO hay deny en la cadena de scopes Y alguna
 * asignación vigente (expires_at null o futuro) en la cadena concede el
 * permiso vía su rol. La cadena es `[scope, ...ancestros]` — herencia solo
 * hacia abajo. Solo SQL estándar vía query builder (regla M6: nada
 * específico de un motor).
 *
 * Toda consulta pasa por `sql()`: un fallo del cliente SQL (conexión, tabla,
 * deadline) sale como `AuthorizationBackendError` 503, nunca como el error
 * crudo de knex (L0.11).
 */
export class DatabaseAuthorizationDriver implements AuthorizationDriver {
  /**
   * Lo que este driver declara (3b-2e · E2). El árbol es del consumidor
   * (`resolveChain`), así que no hay hechos de jerarquía ni deriva que
   * mitigar; `authorize` son varias consultas SQL; la membresía la resuelve
   * el propio SQL contra la cadena que le pasan; los `list*` no enumeran
   * herencia (invariante 7); y `purgeRole` está implementado en una
   * transacción.
   */
  readonly capabilities = Object.freeze({
    hierarchyFacts: false,
    singleCheckAuthorize: false,
    roleInheritanceNative: false,
    listObjectsInherited: false,
    purgeRole: true,
    countRoleAssignments: true,
  })
  /**
   * Resolutor de jerarquía inyectado por el consumidor (el chasis pasa el
   * suyo, que conoce organizations/units, en `config/authorization.ts`).
   * Sin él, el driver solo conoce la raíz (L0.3: ya no hay default plano).
   */
  private chainResolver: ScopeChainResolver
  private timeoutMs: number
  /** Reloj de pared del driver (J1): el ÚNICO `now` de todas sus DECISIONES temporales (no de los sellos, K5). */
  private now: Clock
  /**
   * Cómo viaja `expires_at` con este motor (2.5-B · K2): cadena UTC explícita
   * en MySQL (sin depender de `timezone`/`TZ`), identidad en el resto. Se
   * decide por dialecto en el primer uso (la conexión puede no estar lista al
   * construir el driver).
   */
  private expiryCodec: ExpiryCodec | null = null
  /**
   * Memo del catálogo (2A): `findPermission`/`findRole` leen de aquí; los
   * hechos (asignaciones, denies y el join con los vínculos) siguen en SQL en
   * cada pregunta. Se revalida contra `authz_catalog_version` (2D · F1);
   * `catalog.invalidate()` fuerza la recarga de ESTE memo.
   */
  readonly catalog: CatalogCache

  constructor(options: DatabaseDriverOptions = {}) {
    this.chainResolver = options.resolveChain ?? rootOnlyResolver
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    if (options.now !== undefined && !isClock(options.now)) {
      throw new AuthorizationConfigError(
        `DatabaseAuthorizationDriver: 'now' debe ser una función () => Date (llegó ${typeof options.now})`
      )
    }
    this.now = options.now ?? systemClock
    assertCatalogOptions('DatabaseAuthorizationDriver', options)
    this.catalog =
      options.catalog ??
      new CatalogCache({ driver: 'database', timeoutMs: this.timeoutMs, revalidate: options.catalogRevalidate })
  }

  /**
   * Vista de este driver con OTRO resolutor de la cadena y el mismo estado
   * (conexión, memo del catálogo, deadline). Es lo que usa
   * `AuthorizationManager.forRequest()` para leer con un resolutor memoizado
   * sin tocar el driver compartido: el objeto devuelto hereda del original
   * por prototipo y solo sobrescribe el resolutor.
   */
  withChainResolver(resolveChain: ScopeChainResolver): AuthorizationDriver {
    const view: this = Object.create(this)
    view.chainResolver = resolveChain
    return view
  }

  /**
   * Vista de este driver con OTRO reloj de pared (2.5 · J1) y el mismo estado
   * (conexión, memo, deadline, resolutor). Es lo que aplica el manager con
   * `config.clock` y lo que el juez usa para fijar el instante. Misma
   * técnica que `withChainResolver`: herencia por prototipo, un campo.
   */
  withClock(now: Clock): AuthorizationDriver {
    if (!isClock(now)) {
      throw new AuthorizationConfigError(`withClock: now debe ser una función () => Date (llegó ${typeof now})`)
    }
    const view: this = Object.create(this)
    view.now = now
    return view
  }

  /**
   * `[scope canónico, ...ancestros]`, o `null` si el scope no existe
   * (lecturas: denegar). `chain[0]` —la fila del consumidor, no lo que
   * escribió el llamante— es la identidad con la que se leen y escriben los
   * hechos de ese scope (2.5-B · K1): un alias del uuid que el árbol funde
   * con la fila real (tipo `uuid` de PG, collation `*_ci`) llega aquí ya
   * canónico y el deny escrito canónico casa.
   */
  private chain(scope: ScopeRef, operation: string): Promise<ScopeRef[] | null> {
    return resolveChain(this.chainResolver, scope, operation)
  }

  /** La cadena o 422: una escritura no puede ir a un scope que nadie reconoce. */
  private knownScope(scope: ScopeRef, operation: string): Promise<ScopeRef[]> {
    return assertKnownScope(this.chainResolver, scope, operation)
  }

  /** El scope canónico para `revoke`/`removeDeny`/`purgeScope` (ver `canonicalScope`). */
  private canonicalOrSelf(scope: ScopeRef, operation: string): Promise<ScopeRef> {
    return canonicalScope(this.chainResolver, scope, operation)
  }

  /**
   * Ejecuta una consulta clasificando su fallo (503 con código propio). `fn`
   * devuelve el BUILDER sin ejecutar: el guard le fija el deadline y luego lo
   * ejecuta. Por eso no se usa `.first()` de Lucid (ejecuta al instante, sin
   * dejar poner el timeout): `first()` de abajo hace `limit(1)` y toma la fila.
   */
  private sql<T>(operation: string, fn: () => Promise<T>): Promise<T> {
    return guardSql('database', operation, this.timeoutMs, fn)
  }

  private async first(operation: string, fn: () => QueryBuilder): Promise<any | null> {
    const rows = await this.sql(operation, () => fn().limit(1))
    return rows[0] ?? null
  }

  private get expiry(): ExpiryCodec {
    // Decidir el dialecto no cuesta ninguna consulta: una vista por
    // prototipo (`withClock`/`withChainResolver`) hereda el codec del driver
    // si ya lo tiene y, si no, lo decide una vez para sí.
    this.expiryCodec ??= sqlExpiryCodec(db.connection())
    return this.expiryCodec
  }

  /** Asignación vigente: sin expiración o con expiración futura (estricta: la que vence AHORA ya no cuenta). */
  private whereActive(query: QueryBuilder, column: string = 'expires_at'): QueryBuilder {
    const now = this.expiry.bind(this.now())
    return query.where((builder) => {
      builder.whereNull(column).orWhere(column, '>', now as any)
    })
  }

  // Catálogo desde el memo (2A): una carga por proceso/driver, no una
  // consulta por pregunta. Un fallo de carga sale como 503, igual que antes.
  private async findPermission(slug: string): Promise<{ uuid: string } | null> {
    return (await this.catalog.view()).permission(slug)
  }

  /**
   * Filtro «asignación VISIBLE en algún nivel de la cadena» (3B · B2), en
   * SQL, sobre `authz_assignments as a` unida a `authz_roles as r`: por cada
   * nivel `i`, el scope exacto Y el rol declarado para ese nivel Y (global O
   * owner en `chain.slice(i)`). Sustituye a `whereScopeIn(chain)` en la
   * consulta de `authorize`: mismo número de consultas, ahora con el owner
   * decidido en la base (`owner_scope_key IN (...) OR 'global'`). La cadena
   * viene validada (nunca vacía); L0.1 se conserva por si acaso.
   */
  private whereVisibleAssignmentIn(query: QueryBuilder, chain: ScopeRef[]): QueryBuilder | null {
    if (chain.length === 0) return null
    const keysFrom = chainKeysFrom(chain)
    return query.where((outer) => {
      chain.forEach((s, i) => {
        outer.orWhere((level) => {
          level
            .where('a.scope_type', s.type)
            .where('a.scope_uuid', toDbScopeUuid(s))
            .where('r.scope_type', s.type)
            .where((owner) => {
              owner.where('r.owner_scope_key', GLOBAL_OWNER_KEY).orWhereIn('r.owner_scope_key', keysFrom[i])
            })
        })
      })
    })
  }

  async authorize(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, permission, scope })
    const perm = await this.findPermission(permission)
    if (!perm) return false

    const chain = await this.chain(scope, 'authorize')
    if (!chain) return false

    const deniedQuery = whereScopeIn(
      db
        .from('authz_denies')
        .where('holder_type', subject.type)
        .where('holder_uuid', subject.uuid)
        .where('permission_uuid', perm.uuid),
      'scope',
      chain,
      'read'
    )
    if (!deniedQuery) return false
    if (await this.first('authorize.denies', () => deniedQuery)) return false

    // Una asignación vigente, en la cadena, cuyo rol concede el permiso Y es
    // visible en su nivel (global u owner ancestro-o-igual del scope de la
    // asignación, 3B · B2). `assignableAt`/`rank` no entran: composición.
    const grantedQuery = this.whereVisibleAssignmentIn(
      db
        .from('authz_assignments as a')
        .join('authz_role_permissions as rp', 'rp.role_uuid', 'a.role_uuid')
        .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
        .where('rp.permission_uuid', perm.uuid)
        .where('a.holder_type', subject.type)
        .where('a.holder_uuid', subject.uuid),
      chain
    )
    if (!grantedQuery) return false
    const granted = await this.first('authorize.assignments', () =>
      this.whereActive(grantedQuery, 'a.expires_at')
    )

    return Boolean(granted)
  }

  async grant(
    subject: SubjectRef,
    role: RoleQuery,
    scope: ScopeRef,
    options: GrantOptions = {}
  ): Promise<GrantOutcome> {
    assertIdentity({ subject, role, scope, expiresAt: options.expiresAt })
    // Se escribe bajo la identidad canónica del árbol (K1), nunca bajo la
    // forma del llamante; y el rol tiene que EXISTIR en ese scope (3B · B2:
    // global, o local a un ancestro-o-igual), con una composición legal (B5).
    const chain = await this.knownScope(scope, 'grant')
    const [target] = chain
    const catalog = await this.catalog.view()
    const declared = resolveRoleQuery(catalog, role, target, chainKeysFrom(chain)[0])
    assertRoleAssignableAt(catalog, declared)
    const roleUuid = declared.uuid

    const findExisting = () =>
      whereScopeIn(
        db
          .from('authz_assignments')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('role_uuid', roleUuid),
        'scope',
        [target],
        'write'
      ).select('uuid', this.expiry.select('expires_at') as any)

    // Dos carreras posibles, ambas acotadas (2.5-B · K4): la fila que se
    // leyó desaparece antes del UPDATE (una purga concurrente) ⇒ se vuelve a
    // empezar como inserción; el INSERT choca con el unique (otro grant
    // concurrente) ⇒ se relee y se refresca lo del ganador. Ninguna deja un
    // «hecho» que no está escrito. Más de tres vueltas es contención
    // patológica: 503, nunca un bucle.
    for (let attempt = 0; attempt < 3; attempt++) {
      const existing = await this.first('grant.find', findExisting)
      if (existing) {
        const refreshed = await this.refreshAssignment(existing, options.expiresAt)
        if (refreshed) return refreshed
        continue
      }

      // No había nada: la caducidad es la pedida, o ninguna.
      const expiresAt = options.expiresAt ?? null
      try {
        await this.sql('grant.insert', () =>
          db.table('authz_assignments').insert({
            uuid: uuidv7(),
            holder_type: subject.type,
            holder_uuid: subject.uuid,
            role_uuid: roleUuid,
            scope_type: target.type,
            scope_uuid: toDbScopeUuid(target),
            expires_at: this.expiry.toDb(expiresAt),
            // Sello de auditoría, no decisión (2.5-B · K5): reloj del sistema.
            created_at: systemClock(),
          })
        )
        return { existed: false, expiresAt }
      } catch (error) {
        // Carrera check-then-insert: el unique (que cubre también el nivel app
        // vía centinela) la detecta — el perdedor degrada a re-grant sobre lo
        // que escribió el ganador (con la misma semántica de tres estados).
        // Si no era una carrera, el fallo del insert (ya clasificado) se propaga.
        const raced = await this.first('grant.race', findExisting)
        if (!raced) throw error
        const refreshed = await this.refreshAssignment(raced, options.expiresAt)
        if (refreshed) return refreshed
      }
    }
    throw new AuthorizationBackendError(
      'database',
      'grant',
      new Error(`la asignación de ${subject.type}:${subject.uuid} aparece y desaparece entre lecturas (contención); no se pudo dejar escrita`)
    )
  }

  /**
   * Re-grant sobre una asignación existente (L0.4): omitido preserva una
   * caducidad vigente (o revive una expirada sin caducidad), `null` la quita,
   * `Date` la fija. Solo se escribe si la caducidad cambia de verdad; si el
   * UPDATE no toca ninguna fila (otro proceso la borró entre la lectura y la
   * escritura, K4) devuelve `null`: no hay «existed: true» sobre nada.
   */
  private async refreshAssignment(
    row: { uuid: string; expires_at: unknown },
    requested: Date | null | undefined
  ): Promise<GrantOutcome | null> {
    const previous = this.expiry.fromDb(row.expires_at)
    const expiresAt = resolveGrantExpiry(previous, requested, this.now())
    if (!sameInstant(previous, expiresAt)) {
      const updated: unknown = await this.sql('grant.update', () =>
        db.from('authz_assignments').where('uuid', row.uuid).update({ expires_at: this.expiry.toDb(expiresAt) })
      )
      if (Number(Array.isArray(updated) ? updated[0] : updated) === 0) return null
    }
    return { existed: true, previousExpiresAt: previous, expiresAt }
  }

  async revoke(subject: SubjectRef, role: RoleQuery, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, role, scope })
    // Rol fuera del catálogo para ese nivel ⇒ 422, como en `grant` (D10). El
    // no-op es para una asignación inexistente de un rol válido. Se quitan
    // los hechos de TODOS los roles con ese nombre en el scope exacto (3B):
    // a lo sumo uno es visible ahí y los demás serían filas huérfanas; el
    // scope puede no existir ya para el árbol (D8), así que no se filtra por
    // visibilidad — quitar nunca concede.
    const named = rolesToRevoke(await this.catalog.view(), role, scope)
    const target = await this.canonicalOrSelf(scope, 'revoke')

    await this.sql('revoke', () =>
      whereScopeIn(
        db
          .from('authz_assignments')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .whereIn(
            'role_uuid',
            named.map((r) => r.uuid)
          ),
        'scope',
        [target],
        'write'
      ).delete()
    )
  }

  async hasRole(subject: SubjectRef, role: RoleQuery, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, role, scope })
    const catalog = await this.catalog.view()
    const chain = await this.chain(scope, 'hasRole')
    if (!chain) return false
    // Identidad por uuid (3A · A2): en cada nivel de la cadena cuenta SOLO el
    // rol que el catálogo declara con ese slug para el tipo de ESE nivel
    // (L0.6) —con `{ slug, scopeType }` se recortan los niveles a ese tipo—
    // y la asignación se busca por `(scope, role_uuid)`, no por el slug de
    // un join: dos roles con el mismo slug y owner distinto (3B) no se
    // confunden. Sin rol declarado en ningún nivel no hay consulta que hacer.
    const targets = hasRoleTargets(catalog, role, chain)
    if (targets.length === 0) return false
    const query = db
      .from('authz_assignments as a')
      .where('a.holder_type', subject.type)
      .where('a.holder_uuid', subject.uuid)
      .where((outer) => {
        for (const { scope: s, roleUuid } of targets) {
          outer.orWhere((inner) => {
            inner.where('a.scope_type', s.type).where('a.scope_uuid', toDbScopeUuid(s)).where('a.role_uuid', roleUuid)
          })
        }
      })
    const found = await this.first('hasRole', () => this.whereActive(query, 'a.expires_at'))
    return Boolean(found)
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    const perm = await this.findPermission(permission)
    if (!perm) throw new UnknownPermissionError(permission)
    const [target] = await this.knownScope(scope, 'deny')

    const findExisting = () =>
      whereScopeIn(
        db
          .from('authz_denies')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('permission_uuid', perm.uuid),
        'scope',
        [target],
        'write'
      )

    const existing = await this.first('deny.find', findExisting)
    if (existing) return

    try {
      await this.sql('deny.insert', () =>
        db.table('authz_denies').insert({
          uuid: uuidv7(),
          holder_type: subject.type,
          holder_uuid: subject.uuid,
          permission_uuid: perm.uuid,
          scope_type: target.type,
          scope_uuid: toDbScopeUuid(target),
          created_at: systemClock(),
        })
      )
    } catch (error) {
      // Carrera: si otro proceso insertó el mismo deny, el unique lo detecta
      // y el resultado deseado ya existe.
      const raced = await this.first('deny.race', findExisting)
      if (!raced) throw error
    }
  }

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    const perm = await this.findPermission(permission)
    if (!perm) throw new UnknownPermissionError(permission)
    const target = await this.canonicalOrSelf(scope, 'removeDeny')

    await this.sql('removeDeny', () =>
      whereScopeIn(
        db
          .from('authz_denies')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('permission_uuid', perm.uuid),
        'scope',
        [target],
        'write'
      ).delete()
    )
  }

  async listSubjects(role: RoleQuery, scope: ScopeRef): Promise<SubjectRef[]> {
    assertIdentity({ role, scope })
    // Un rol que el catálogo no declara para ese nivel (en ningún owner) no
    // tiene holders (D5): nada que leer, ni árbol ni hechos. Un scope que el
    // árbol no conoce no existe para el motor (D8, K1): nada; uno que conoce
    // se lee bajo su identidad canónica, y el rol tiene que existir AHÍ (3B ·
    // B2: global o local a un ancestro-o-igual); se busca por su uuid (3A).
    const catalog = await this.catalog.view()
    const asked = normalizeRoleQuery(role)
    // Atajo D5: nada que leer (ni árbol ni hechos) si el catálogo no declara
    // NINGÚN rol que pueda responder — por uuid, si no existe; por slug, si
    // nadie lo declara para ese nivel.
    if (asked.uuid !== undefined ? catalog.roleByUuid(asked.uuid) === null : catalog.rolesNamed(asked.slug, asked.scopeType ?? scope.type).length === 0) {
      return []
    }
    const chain = await this.chain(scope, 'listSubjects')
    if (!chain) return []
    const declared = visibleRoleFor(catalog, asked, scope, chainKeysFrom(chain)[0])
    if (!declared) return []
    const query = whereScopeIn(
      db.from('authz_assignments as a').where('a.role_uuid', declared.uuid),
      'a.scope',
      [chain[0]],
      'read'
    )
    if (!query) return []
    const rows = await this.sql('listSubjects', () =>
      this.whereActive(query, 'a.expires_at').distinct('a.holder_type', 'a.holder_uuid')
    )

    return rows.map((row: any) => ({ type: row.holder_type, uuid: row.holder_uuid }))
  }

  async listRoles(subject: SubjectRef, scope: ScopeRef): Promise<string[]> {
    assertIdentity({ subject, scope })
    // Un scope que el árbol no conoce no existe para el motor (D8): nada.
    const chain = await this.chain(scope, 'listRoles')
    if (!chain) return []
    const query = whereScopeIn(
      db
        .from('authz_assignments as a')
        .where('a.holder_type', subject.type)
        .where('a.holder_uuid', subject.uuid),
      'a.scope',
      [chain[0]],
      'read'
    )
    if (!query) return []
    const rows = await this.sql('listRoles', () =>
      this.whereActive(query, 'a.expires_at').distinct('a.role_uuid')
    )
    // Del uuid al slug por el memo (3A · A2): un rol retirado del catálogo no
    // es membresía (D5), uno declarado para OTRO nivel tampoco, ni uno local
    // a un scope que ya no está en la cadena (3B · B2: la unit se movió).
    const catalog = await this.catalog.view()
    const keys = chainKeysFrom(chain)[0]
    const slugs = new Set<string>()
    for (const row of rows) {
      const declared = declaredRoleAt(catalog, row.role_uuid, chain[0].type, keys)
      if (declared) slugs.add(declared.slug)
    }
    return [...slugs]
  }

  /**
   * Roles directos vigentes del holder en cada scope de la cadena (2D · G5):
   * UNA consulta con `whereScopeIn(chain)` en vez de un `listRoles` por
   * nivel. El filtro por catálogo (D5) es el memo, por uuid (3A · A2): el
   * rol tiene que existir y estar declarado para el nivel de la asignación.
   * La cadena viene ya resuelta por el manager.
   */
  async rolesInChain(subject: SubjectRef, chain: ScopeRef[]): Promise<Array<{ scope: ScopeRef; role: CatalogRoleRef }>> {
    assertIdentity({ subject })
    for (const scope of chain) assertScope(scope)
    const query = whereScopeIn(
      db
        .from('authz_assignments as a')
        .where('a.holder_type', subject.type)
        .where('a.holder_uuid', subject.uuid),
      'a.scope',
      chain,
      'read'
    )
    if (!query) return []
    const rows = await this.sql('rolesInChain', () =>
      this.whereActive(query, 'a.expires_at').distinct('a.scope_type', 'a.scope_uuid', 'a.role_uuid')
    )
    const catalog = await this.catalog.view()
    const keysFrom = chainKeysFrom(chain)
    const levelOf = new Map(chain.map((s, i) => [dbScopeKey(s), i]))
    const result: Array<{ scope: ScopeRef; role: CatalogRoleRef }> = []
    const seen = new Set<string>()
    for (const row of rows) {
      // Visible desde el nivel de la ASIGNACIÓN (3B · B2): owner global o en la cadena desde ahí.
      const level = levelOf.get(rowScopeKey(row))
      if (level === undefined) continue
      const declared = declaredRoleAt(catalog, row.role_uuid, row.scope_type, keysFrom[level])
      if (!declared) continue
      // Dedupe por IDENTIDAD (3D · M1: el uuid, no el slug): dos homónimos
      // asignados en el mismo scope son dos roles y cuentan los dos.
      const dedupe = `${rowScopeKey(row)}\u001f${declared.uuid}`
      if (seen.has(dedupe)) continue
      seen.add(dedupe)
      result.push({ scope: { type: row.scope_type, uuid: fromDbScopeUuid(row.scope_uuid) }, role: declared })
    }
    return result
  }

  async listRoleScopes(subject: SubjectRef, scopeType: ScopeType): Promise<ScopeRef[]> {
    assertIdentity({ subject, scopeType })
    const rows = await this.sql('listRoleScopes', () =>
      this.whereActive(
        db
          .from('authz_assignments as a')
          .where('a.holder_type', subject.type)
          .where('a.holder_uuid', subject.uuid)
          .where('a.scope_type', scopeType),
        'a.expires_at'
      ).distinct('a.scope_type', 'a.scope_uuid', 'a.role_uuid')
    )
    // Por scope: los roles asignados; cuenta si el árbol lo conoce (D8, una
    // consulta al resolutor por scope, que el memo por request amortiza) Y
    // alguno de sus roles existe ahí (D5; 3B · B2: declarado para ese nivel y
    // global u owner en la cadena).
    const catalog = await this.catalog.view()
    const byScope = new Map<string, { scope: ScopeRef; roles: string[] }>()
    for (const row of rows) {
      const k = rowScopeKey(row)
      if (!byScope.has(k)) byScope.set(k, { scope: { type: row.scope_type, uuid: fromDbScopeUuid(row.scope_uuid) }, roles: [] })
      byScope.get(k)!.roles.push(row.role_uuid)
    }
    const result: ScopeRef[] = []
    for (const { scope, roles } of byScope.values()) {
      const chain = await this.chain(scope, 'listRoleScopes')
      if (!chain) continue
      const keys = chainKeysFrom(chain)[0]
      if (roles.some((uuid) => this.visibleAt(catalog, uuid, scope, keys))) result.push(scope)
    }
    return result
  }

  /** ¿El rol (por uuid) existe en el scope cuya cadena tiene esas claves? (3B · B2, `declaredRoleAt`) */
  private visibleAt(catalog: CatalogView, roleUuid: string, scope: ScopeRef, chainKeys: readonly string[]): boolean {
    return declaredRoleAt(catalog, roleUuid, scope.type, chainKeys) !== null
  }

  async listScopes(subject: SubjectRef, permission: string): Promise<ScopeRef[]> {
    assertIdentity({ subject, permission })
    const perm = await this.findPermission(permission)
    if (!perm) return []

    const rows = await this.sql('listScopes.assignments', () =>
      this.whereActive(
        db
          .from('authz_assignments as a')
          .join('authz_role_permissions as rp', 'rp.role_uuid', 'a.role_uuid')
          .where('rp.permission_uuid', perm.uuid)
          .where('a.holder_type', subject.type)
          .where('a.holder_uuid', subject.uuid),
        'a.expires_at'
      ).distinct('a.scope_type', 'a.scope_uuid', 'a.role_uuid')
    )

    const denies = await this.sql('listScopes.denies', () =>
      db
        .from('authz_denies')
        .where('holder_type', subject.type)
        .where('holder_uuid', subject.uuid)
        .where('permission_uuid', perm.uuid)
        .select('scope_type', 'scope_uuid')
    )

    const deniedKeys = new Set(
      denies.map((d: any) => `${d.scope_type}:${fromDbScopeUuid(d.scope_uuid) ?? ''}`)
    )

    // Por scope: el conjunto de roles que conceden; el scope se lista si el
    // árbol lo conoce, alguno de esos roles existe ahí (3B · B2) y ningún
    // deny de la cadena lo bloquea — exactamente lo que `authorize` diría.
    const catalog = await this.catalog.view()
    const byScope = new Map<string, { scope: ScopeRef; roles: string[] }>()
    for (const row of rows) {
      const k = rowScopeKey(row)
      if (!byScope.has(k)) byScope.set(k, { scope: { type: row.scope_type, uuid: fromDbScopeUuid(row.scope_uuid) }, roles: [] })
      byScope.get(k)!.roles.push(row.role_uuid)
    }
    const result: ScopeRef[] = []
    for (const { scope: candidate, roles } of byScope.values()) {
      // Un scope que el árbol ya no conoce no concede (authorize daría false):
      // no se lista, igual que uno denegado.
      const chain = await this.chain(candidate, 'listScopes')
      if (!chain) continue
      const keys = chainKeysFrom(chain)[0]
      if (!roles.some((uuid) => this.visibleAt(catalog, uuid, candidate, keys))) continue
      const blocked = chain.some((s) => deniedKeys.has(`${s.type}:${s.uuid ?? ''}`))
      if (!blocked) result.push(candidate)
    }
    return result
  }

  /**
   * Denies directos del holder (2.1, B5): del scope exacto o todos. Solo los
   * de permisos que el catálogo declara (memo); los de scopes que el árbol
   * no conoce no se listan (D8), como en `listRoleScopes`.
   */
  async listDenies(subject: SubjectRef, scope?: ScopeRef): Promise<DenyRef[]> {
    assertIdentity(scope ? { subject, scope } : { subject })
    const chain = scope ? await this.chain(scope, 'listDenies') : null
    if (scope && !chain) return []
    const base = db
      .from('authz_denies')
      .where('holder_type', subject.type)
      .where('holder_uuid', subject.uuid)
    const query = chain ? whereScopeIn(base, 'scope', [chain[0]], 'read') : base
    if (!query) return []
    const rows = await this.sql('listDenies', () => query.select('permission_uuid', 'scope_type', 'scope_uuid'))
    const view = await this.catalog.view()
    const result: DenyRef[] = []
    for (const row of rows) {
      const permission = view.permissionSlug(row.permission_uuid)
      if (!permission) continue
      const denyScope: ScopeRef = { type: row.scope_type, uuid: fromDbScopeUuid(row.scope_uuid) }
      if (!scope && !(await this.chain(denyScope, 'listDenies'))) continue
      result.push({ permission, scope: denyScope })
    }
    return result
  }

  /**
   * Borra asignaciones y denies del scope exacto, en una transacción. Si el
   * árbol aún lo conoce se purga su identidad canónica (K1); si ya no (el
   * consumidor borró la fila antes de avisar) se purga tal cual llegó. Con
   * `DELETE` en SQL la propia sentencia demuestra el cero: no hay residuo
   * posible.
   */
  async purgeScope(purged: ScopeRef): Promise<void> {
    assertScope(purged)
    if (purged.type === APP_SCOPE_TYPE) {
      throw new InvalidIdentityError('purgeScope: la raíz `app` no se purga')
    }
    const scope = await this.canonicalOrSelf(purged, 'purgeScope')
    // La transacción no es un builder: `guardSql` no puede fijarle el
    // deadline, así que cada DELETE pasa por él por separado (D4). El guard
    // exterior clasifica lo que falle al abrir o confirmar la transacción.
    await this.sql('purgeScope', () =>
      db.transaction(async (trx) => {
        await this.sql('purgeScope.assignments', () =>
          trx
            .from('authz_assignments')
            .where('scope_type', scope.type)
            .where('scope_uuid', toDbScopeUuid(scope))
            .delete()
        )
        await this.sql('purgeScope.denies', () =>
          trx
            .from('authz_denies')
            .where('scope_type', scope.type)
            .where('scope_uuid', toDbScopeUuid(scope))
            .delete()
        )
      })
    )
  }

  /**
   * Purga un rol con sus hechos (3B · B4): sus asignaciones en TODOS los
   * scopes, sus vínculos y la fila, en UNA transacción que sube la versión
   * compartida del catálogo como última sentencia (`withAuthzCatalogWrite`):
   * los demás procesos dejan de verlo en su siguiente pregunta. Se lee la
   * fila en fresco (no el memo): purgar es escribir. Con `DELETE` la propia
   * sentencia demuestra el cero. Global o local: la barrera «los globales son
   * inmutables» es del manager (`deleteScopedRole`); por aquí (plataforma,
   * `manager.driver()`) se purga lo que se pida.
   */
  async purgeRole(roleUuid: string): Promise<void> {
    assertCatalogUuid('rol', roleUuid)
    const existing = await this.first('purgeRole.role', () => db.from('authz_roles').where('uuid', roleUuid).select('uuid'))
    if (!existing) throw new UnknownRoleError(roleUuid)
    try {
      await this.sql('purgeRole', () =>
        withAuthzCatalogWrite(
          async (trx) => {
            await this.sql('purgeRole.assignments', () => trx.from('authz_assignments').where('role_uuid', roleUuid).delete())
            await this.sql('purgeRole.links', () => trx.from('authz_role_permissions').where('role_uuid', roleUuid).delete())
            const deleted: unknown = await this.sql('purgeRole.role.delete', () => trx.from('authz_roles').where('uuid', roleUuid).delete())
            if (Number(Array.isArray(deleted) ? deleted[0] : deleted) === 0) throw new UnknownRoleError(roleUuid)
          },
          { driver: 'database', timeoutMs: this.timeoutMs }
        )
      )
    } finally {
      // Como el sync (2A): este proceso lo ve al instante también con `everyMs`.
      this.catalog.invalidate()
    }
  }

  /**
   * Cuántos hechos VIGENTES tiene cada rol, en todos los scopes (3b-2j). Es
   * lo que `pruneOrphanRoles` necesita para decir si un huérfano todavía
   * concede, y es una pregunta del PUERTO porque los hechos son del driver:
   * aquí son filas de `authz_assignments`, en `openfga` son tuplas del store.
   *
   * Una consulta agrupada para todos los uuids (no una por rol) y la misma
   * caducidad ESTRICTA que el resto del driver, con SU reloj (`whereActive`,
   * J1): la asignación que vence ahora ya no cuenta, como no cuenta en
   * `authorize`. Un rol sin hechos —o que no está en la tabla— es `0`.
   */
  async countRoleAssignments(roleUuids: string[]): Promise<number[]> {
    for (const uuid of roleUuids) assertCatalogUuid('rol', uuid)
    if (roleUuids.length === 0) return []
    const rows = await this.sql('countRoleAssignments', () =>
      this.whereActive(db.from('authz_assignments').whereIn('role_uuid', roleUuids))
        .groupBy('role_uuid')
        .select('role_uuid')
        .count('* as total')
    )
    const totals = new Map<string, number>()
    for (const row of rows) totals.set(String(row.role_uuid), Number(row.total ?? row.count ?? 0))
    return roleUuids.map((uuid) => totals.get(uuid) ?? 0)
  }
}
