import db from '@adonisjs/lucid/services/db'
import { v7 as uuidv7 } from 'uuid'
import type {
  AuthorizationDriver,
  DenyRef,
  GrantOptions,
  GrantOutcome,
  RoleQuery,
  ScopeRef,
  ScopeType,
  SubjectRef,
} from '../types.js'
import type { ScopeAncestorsResolver } from '../types.js'
import { APP_SCOPE_TYPE } from '../types.js'
import { assertIdentity, assertScope, normalizeRoleQuery } from '../identity.js'
import { resolveGrantExpiry, sameInstant, toExpiryDate } from '../expiry.js'
import {
  AuthorizationConfigError,
  AuthorizationInternalError,
  InvalidIdentityError,
  UnknownPermissionError,
  UnknownRoleError,
} from '../errors.js'
import { assertKnownScope, guardSql, resolveChain, rootOnlyResolver } from './backend_guard.js'
import { CatalogCache, assertCatalogOptions } from '../catalog_cache.js'
import type { CatalogRevalidate } from '../catalog_cache.js'
import { isClock, systemClock } from '../clock.js'
import type { Clock } from '../clock.js'

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
  /** Jerarquía del consumidor (ver ScopeAncestorsResolver). */
  resolveAncestors?: ScopeAncestorsResolver
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
   * Reloj de pared con el que el driver decide la caducidad (2.5 · J1):
   * `expires_at > now()` en cada lectura, los tres estados del re-grant y el
   * sello de `created_at`. Default `() => new Date()`. Inyectable para
   * fijar el instante en tests; en producción lo normal es no tocarlo (o
   * pasar `clock` en el config del manager, que lo aplica con `withClock`).
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
   * Resolutor de jerarquía inyectado por el consumidor (el chasis pasa el
   * suyo, que conoce organizations/units, en `config/authorization.ts`).
   * Sin él, el driver solo conoce la raíz (L0.3: ya no hay default plano).
   */
  private resolveAncestors: ScopeAncestorsResolver
  private timeoutMs: number
  /** Reloj de pared del driver (J1): el ÚNICO `now` de todas sus decisiones temporales. */
  private now: Clock
  /**
   * Memo del catálogo (2A): `findPermission`/`findRole` leen de aquí; los
   * hechos (asignaciones, denies y el join con los vínculos) siguen en SQL en
   * cada pregunta. Se revalida contra `authz_catalog_version` (2D · F1);
   * `catalog.invalidate()` fuerza la recarga de ESTE memo.
   */
  readonly catalog: CatalogCache

  constructor(options: DatabaseDriverOptions = {}) {
    this.resolveAncestors = options.resolveAncestors ?? rootOnlyResolver
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
   * Vista de este driver con OTRO resolutor de ancestros y el mismo estado
   * (conexión, memo del catálogo, deadline). Es lo que usa
   * `AuthorizationManager.forRequest()` para leer con un resolutor memoizado
   * sin tocar el driver compartido: el objeto devuelto hereda del original
   * por prototipo y solo sobrescribe el resolutor.
   */
  withAncestorsResolver(resolveAncestors: ScopeAncestorsResolver): AuthorizationDriver {
    const view: this = Object.create(this)
    view.resolveAncestors = resolveAncestors
    return view
  }

  /**
   * Vista de este driver con OTRO reloj de pared (2.5 · J1) y el mismo estado
   * (conexión, memo, deadline, resolutor). Es lo que aplica el manager con
   * `config.clock` y lo que el juez usa para fijar el instante. Misma
   * técnica que `withAncestorsResolver`: herencia por prototipo, un campo.
   */
  withClock(now: Clock): AuthorizationDriver {
    if (!isClock(now)) {
      throw new AuthorizationConfigError(`withClock: now debe ser una función () => Date (llegó ${typeof now})`)
    }
    const view: this = Object.create(this)
    view.now = now
    return view
  }

  /** `[scope, ...ancestros]`, o `null` si el scope no existe (lecturas: denegar). */
  private chain(scope: ScopeRef, operation: string): Promise<ScopeRef[] | null> {
    return resolveChain(this.resolveAncestors, scope, operation)
  }

  /** La cadena o 422: una escritura no puede ir a un scope que nadie reconoce. */
  private knownScope(scope: ScopeRef, operation: string): Promise<ScopeRef[]> {
    return assertKnownScope(this.resolveAncestors, scope, operation)
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

  /** Asignación vigente: sin expiración o con expiración futura (estricta: la que vence AHORA ya no cuenta). */
  private whereActive(query: QueryBuilder, column: string = 'expires_at'): QueryBuilder {
    const now = this.now()
    return query.where((builder) => {
      builder.whereNull(column).orWhere(column, '>', now)
    })
  }

  // Catálogo desde el memo (2A): una carga por proceso/driver, no una
  // consulta por pregunta. Un fallo de carga sale como 503, igual que antes.
  private async findPermission(slug: string): Promise<{ uuid: string } | null> {
    return (await this.catalog.view()).permission(slug)
  }

  private async findRole(slug: string, scopeType: string): Promise<{ uuid: string } | null> {
    return (await this.catalog.view()).role(slug, scopeType)
  }

  private async findRoleOrFail(slug: string, scopeType: string): Promise<{ uuid: string }> {
    const role = await this.findRole(slug, scopeType)
    if (!role) throw new UnknownRoleError(slug, scopeType)
    return role
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

    const grantedQuery = whereScopeIn(
      db
        .from('authz_assignments as a')
        .join('authz_role_permissions as rp', 'rp.role_uuid', 'a.role_uuid')
        .where('rp.permission_uuid', perm.uuid)
        .where('a.holder_type', subject.type)
        .where('a.holder_uuid', subject.uuid),
      'a.scope',
      chain,
      'read'
    )
    if (!grantedQuery) return false
    const granted = await this.first('authorize.assignments', () =>
      this.whereActive(grantedQuery, 'a.expires_at')
    )

    return Boolean(granted)
  }

  async grant(
    subject: SubjectRef,
    role: string,
    scope: ScopeRef,
    options: GrantOptions = {}
  ): Promise<GrantOutcome> {
    assertIdentity({ subject, roleSlug: role, scope, expiresAt: options.expiresAt })
    const { uuid: roleUuid } = await this.findRoleOrFail(role, scope.type)
    await this.knownScope(scope, 'grant')

    const findExisting = () =>
      whereScopeIn(
        db
          .from('authz_assignments')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('role_uuid', roleUuid),
        'scope',
        [scope],
        'write'
      )

    const existing = await this.first('grant.find', findExisting)
    if (existing) return this.refreshAssignment(existing, options.expiresAt)

    // No había nada: la caducidad es la pedida, o ninguna.
    const expiresAt = options.expiresAt ?? null
    try {
      await this.sql('grant.insert', () =>
        db.table('authz_assignments').insert({
          uuid: uuidv7(),
          holder_type: subject.type,
          holder_uuid: subject.uuid,
          role_uuid: roleUuid,
          scope_type: scope.type,
          scope_uuid: toDbScopeUuid(scope),
          expires_at: expiresAt,
          created_at: this.now(),
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
      return this.refreshAssignment(raced, options.expiresAt)
    }
  }

  /**
   * Re-grant sobre una asignación existente (L0.4): omitido preserva una
   * caducidad vigente (o revive una expirada sin caducidad), `null` la quita,
   * `Date` la fija. Solo se escribe si la caducidad cambia de verdad.
   */
  private async refreshAssignment(
    row: { uuid: string; expires_at: unknown },
    requested: Date | null | undefined
  ): Promise<GrantOutcome> {
    const previous = toExpiryDate(row.expires_at)
    const expiresAt = resolveGrantExpiry(previous, requested, this.now())
    if (!sameInstant(previous, expiresAt)) {
      await this.sql('grant.update', () =>
        db.from('authz_assignments').where('uuid', row.uuid).update({ expires_at: expiresAt })
      )
    }
    return { existed: true, previousExpiresAt: previous, expiresAt }
  }

  async revoke(subject: SubjectRef, role: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, roleSlug: role, scope })
    // Rol fuera del catálogo para ese nivel ⇒ 422, como en `grant` (D10). El
    // no-op es para una asignación inexistente de un rol válido.
    const roleRow = await this.findRoleOrFail(role, scope.type)

    await this.sql('revoke', () =>
      whereScopeIn(
        db
          .from('authz_assignments')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('role_uuid', roleRow.uuid),
        'scope',
        [scope],
        'write'
      ).delete()
    )
  }

  async hasRole(subject: SubjectRef, role: RoleQuery, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, role, scope })
    const { slug, scopeType } = normalizeRoleQuery(role)
    const chain = await this.chain(scope, 'hasRole')
    if (!chain) return false
    // Con `{ slug, scopeType }` solo cuentan los niveles de la cadena de ese
    // tipo; con string, cada nivel casa solo con el rol de SU tipo (L0.6):
    // `r.scope_type = a.scope_type` lo hace explícito aunque `grant` ya lo
    // garantice por construcción.
    const levels = scopeType ? chain.filter((s) => s.type === scopeType) : chain
    const query = whereScopeIn(
      db
        .from('authz_assignments as a')
        .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
        .where('r.slug', slug)
        .whereColumn('r.scope_type', 'a.scope_type')
        .where('a.holder_type', subject.type)
        .where('a.holder_uuid', subject.uuid),
      'a.scope',
      levels,
      'read'
    )
    if (!query) return false
    const found = await this.first('hasRole', () => this.whereActive(query, 'a.expires_at'))
    return Boolean(found)
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    const perm = await this.findPermission(permission)
    if (!perm) throw new UnknownPermissionError(permission)
    await this.knownScope(scope, 'deny')

    const findExisting = () =>
      whereScopeIn(
        db
          .from('authz_denies')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('permission_uuid', perm.uuid),
        'scope',
        [scope],
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
          scope_type: scope.type,
          scope_uuid: toDbScopeUuid(scope),
          created_at: this.now(),
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

    await this.sql('removeDeny', () =>
      whereScopeIn(
        db
          .from('authz_denies')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('permission_uuid', perm.uuid),
        'scope',
        [scope],
        'write'
      ).delete()
    )
  }

  async listSubjects(role: string, scope: ScopeRef): Promise<SubjectRef[]> {
    assertIdentity({ roleSlug: role, scope })
    const query = whereScopeIn(
      db
        .from('authz_assignments as a')
        .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
        .where('r.slug', role)
        .where('r.scope_type', scope.type),
      'a.scope',
      [scope],
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
    if (!(await this.chain(scope, 'listRoles'))) return []
    const query = whereScopeIn(
      db
        .from('authz_assignments as a')
        .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
        .where('a.holder_type', subject.type)
        .where('a.holder_uuid', subject.uuid),
      'a.scope',
      [scope],
      'read'
    )
    if (!query) return []
    const rows = await this.sql('listRoles', () =>
      this.whereActive(query, 'a.expires_at').distinct('r.slug')
    )
    return rows.map((row: any) => row.slug)
  }

  /**
   * Roles directos vigentes del holder en cada scope de la cadena (2D · G5):
   * UNA consulta con `whereScopeIn(chain)` en vez de un `listRoles` por
   * nivel. El join con `authz_roles` (mismo `scope_type`) es el filtro por
   * catálogo (D5). La cadena viene ya resuelta por el manager.
   */
  async rolesInChain(subject: SubjectRef, chain: ScopeRef[]): Promise<Array<{ scope: ScopeRef; role: string }>> {
    assertIdentity({ subject })
    for (const scope of chain) assertScope(scope)
    const query = whereScopeIn(
      db
        .from('authz_assignments as a')
        .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
        .whereColumn('r.scope_type', 'a.scope_type')
        .where('a.holder_type', subject.type)
        .where('a.holder_uuid', subject.uuid),
      'a.scope',
      chain,
      'read'
    )
    if (!query) return []
    const rows = await this.sql('rolesInChain', () =>
      this.whereActive(query, 'a.expires_at').distinct('a.scope_type', 'a.scope_uuid', 'r.slug')
    )
    return rows.map((row: any) => ({
      scope: { type: row.scope_type, uuid: fromDbScopeUuid(row.scope_uuid) },
      role: row.slug,
    }))
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
      ).distinct('a.scope_type', 'a.scope_uuid')
    )
    return this.knownOnly(
      rows.map((row: any) => ({ type: row.scope_type, uuid: fromDbScopeUuid(row.scope_uuid) })),
      'listRoleScopes'
    )
  }

  /**
   * Filtra los scopes que el árbol ya no conoce (D8). Una consulta al
   * resolutor por scope: es el coste de no tener el árbol como hechos
   * propios; el memo por request (Fase 2) lo amortiza.
   */
  private async knownOnly(scopes: ScopeRef[], operation: string): Promise<ScopeRef[]> {
    const known: ScopeRef[] = []
    for (const scope of scopes) {
      if (await this.chain(scope, operation)) known.push(scope)
    }
    return known
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
      ).distinct('a.scope_type', 'a.scope_uuid')
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

    const result: ScopeRef[] = []
    for (const row of rows) {
      const candidate: ScopeRef = { type: row.scope_type, uuid: fromDbScopeUuid(row.scope_uuid) }
      // Un scope que el árbol ya no conoce no concede (authorize daría false):
      // no se lista, igual que uno denegado.
      const chain = await this.chain(candidate, 'listScopes')
      if (!chain) continue
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
    if (scope && !(await this.chain(scope, 'listDenies'))) return []
    const base = db
      .from('authz_denies')
      .where('holder_type', subject.type)
      .where('holder_uuid', subject.uuid)
    const query = scope ? whereScopeIn(base, 'scope', [scope], 'read') : base
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
   * Borra asignaciones y denies del scope exacto, en una transacción. No
   * consulta el árbol (el scope puede ya no existir). Con `DELETE` en SQL
   * la propia sentencia demuestra el cero: no hay residuo posible.
   */
  async purgeScope(scope: ScopeRef): Promise<void> {
    assertScope(scope)
    if (scope.type === APP_SCOPE_TYPE) {
      throw new InvalidIdentityError('purgeScope: la raíz `app` no se purga')
    }
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
}
