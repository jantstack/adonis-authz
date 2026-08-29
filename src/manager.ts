import { Exception } from '@adonisjs/core/exceptions'
import { v7 as uuidv7 } from 'uuid'
import type { AuthorizationConfig } from './define_config.js'
import {
  assertCatalogUuid,
  assertIdentity,
  assertScope,
  assertScopeType,
  assertSubject,
  assertValidSlug,
  chainKeysFrom,
  normalizeRoleQuery,
  scopeFromKey,
  scopeKey,
} from './identity.js'
import { expiryChanged } from './expiry.js'
import { assertKnownScope, isAuthzError, resolveChain, rootOnlyResolver } from './drivers/backend_guard.js'
import { CatalogCache, GLOBAL_OWNER_KEY, invalidateAuthzCatalog, isRoleVisibleWith, readRolesOwnedBy, withAuthzCatalogWrite } from './catalog_cache.js'
import type { CatalogView } from './catalog_cache.js'
import { assertAssignableAt } from './catalog.js'
import { systemClock } from './clock.js'
import {
  ActorRequiredError,
  AuthorizationBackendTimeoutError,
  AuthorizationConfigError,
  AuthorizationInternalError,
  CatalogConflictError,
  InvalidIdentityError,
  NoDescendantsResolverError,
  NotWithinError,
  PermissionNotDelegableError,
  RankExceededError,
  RoleImmutableError,
  RoleLevelAboveOwnerError,
  ScopeCycleError,
  ScopeResolverError,
  TooManyScopesError,
  UnknownPermissionError,
  UnknownRoleError,
  UnsupportedOperationError,
  ViewExpiredError,
  WithinRequiredError,
  WithinRootForbiddenError,
} from './errors.js'
import { APP_SCOPE_TYPE } from './types.js'
import { memoizeAncestors } from './memoize_ancestors.js'
import type {
  AuthorizationDriver,
  AuthorizationDriverFactory,
  AuthorizedScopes,
  AuthzCatalogWriteEvent,
  AuthzWriteEvent,
  CatalogRole,
  CatalogRoleRef,
  DenyOptions,
  DenyRef,
  ExcludedSubtree,
  GrantOptions,
  GrantOutcome,
  RoleQuery,
  ScopeChainResolver,
  ScopeDescendantsResolver,
  ScopeDetachOutcome,
  ScopedRoleChanges,
  ScopedRoleSpec,
  ScopedWriteOptions,
  ScopeRef,
  ScopeType,
  SubjectRef,
  WriteOptions,
} from './types.js'

/** Longitudes de `authz_roles.name`/`description` (el esquema publicado). */
const ROLE_NAME_MAX = 100
const ROLE_DESCRIPTION_MAX = 500

/** Descripción corta de una respuesta inválida de `authorizeMany`, para el mensaje del 500. */
function describeAnswer(answer: unknown): string {
  if (!Array.isArray(answer)) return `${answer === null ? 'null' : typeof answer} (no es un array)`
  const offending = answer.find((b) => typeof b !== 'boolean')
  if (offending !== undefined || answer.some((b) => typeof b !== 'boolean')) {
    return `un array de ${answer.length} con un elemento que no es boolean (${typeof offending})`
  }
  return `un array de ${answer.length}`
}

/**
 * Configs que ya recibieron el aviso de seguridad opt-in (B7/B1): una vez
 * por config, no por instancia — `forRequest()` construye managers hijos con
 * la misma config y no debe repetirlo en cada request.
 */
const warnedConfigs = new WeakSet<object>()

/**
 * Lo que devuelve `AuthorizationManager.forRequest()`: la misma API que el
 * manager (lecturas, escrituras, `scopes.*`), con los ancestros memoizados
 * SOLO en las lecturas. Es un tipo, no otra clase: la vista es un manager
 * hijo que comparte config, driver y hooks con su padre.
 */
export type AuthorizationView = Pick<
  AuthorizationManager,
  | 'authorize'
  | 'hasRole'
  | 'listSubjects'
  | 'listScopes'
  | 'listRoles'
  | 'listRoleScopes'
  | 'grant'
  | 'revoke'
  | 'deny'
  | 'removeDeny'
  | 'scopes'
  | 'driver'
  | 'forRequest'
  | 'isWithin'
  | 'listDenies'
  | 'effectivePermissions'
  | 'authorizeMany'
  | 'authorizedScopes'
  | 'expandExcludedSubtrees'
  | 'defineScopedRole'
  | 'updateScopedRole'
  | 'deleteScopedRole'
>

/**
 * Expande los `excludedSubtrees` de un `all` (2D · F10) a la lista plana de
 * scopes que hay que restar: cada scope denegado y TODOS sus descendientes,
 * con el `descendantsOf` del config. Es la forma correcta del `NOT IN`;
 * restar solo los scopes con deny dejaría dentro sus subárboles.
 */
export function expandExcludedSubtrees(view: AuthorizationView, excluded: ExcludedSubtree[]): Promise<ScopeRef[]> {
  return view.expandExcludedSubtrees(excluded)
}

/** Cotas por defecto de `authorizedScopes` (config `scopes.maxScopes` / `scopes.maxDescendants`). */
export const DEFAULT_MAX_SCOPES = 1_000
export const DEFAULT_MAX_DESCENDANTS = 10_000
/**
 * Tope sano de `maxScopes`/`maxDescendants` (2.5-B, auditor ⚪6): por encima
 * de ~4,29e9 el hint `SET_VAR(cte_max_recursion_depth)` de MySQL sale de
 * rango y un ciclo en la tabla deja de ser el 422 «posible ciclo» del
 * contrato (503); y ya con 1e6 un ciclo cuesta segundos de CPU por llamada.
 * Una cota mayor es config rota (500), nunca una pregunta.
 */
export const MAX_SCOPE_BOUND = 10_000_000
/** Vida por defecto de una vista de `forRequest()` para LEER (F9): un request, no un módulo. */
export const DEFAULT_VIEW_MAX_AGE_MS = 30_000

export interface ForRequestOptions {
  /**
   * Milisegundos durante los que la vista puede LEER (default 30 000).
   * Después, cualquier lectura es 500 `E_AUTHZ_VIEW_EXPIRED`: el memo de
   * ancestros solo es correcto mientras dura el request y una vista guardada
   * por error serviría la cadena vieja para siempre. `0` = sin límite, a
   * sabiendas. Las escrituras e `isWithin` no caducan (resuelven en fresco).
   * Se mide con un reloj MONÓTONO (`performance.now()`, 2E · H3): un salto
   * del reloj de pared hacia atrás no resucita una vista caducada.
   */
  maxAgeMs?: number
  /**
   * SOLO TESTS: fuente del reloj monótono, en ms (default `performance.now`).
   * Sirve para fijar la frontera exacta de `maxAgeMs` sin dormir; en
   * producción no se toca.
   */
  now?: () => number
}

/** Reloj monótono del proceso: inmune a NTP, snapshots y `Date.now` parcheado. */
const monotonicNow = (): number => performance.now()

/**
 * Manager de autorización — la fachada que usan middleware, services y
 * seeders. Resuelve el driver activo del config y notifica cada escritura
 * al hook `onWrite` del consumidor (el chasis lo usa para auditar + SSE).
 *
 * Pieza del "paquete" de autorización: NO conoce config files, modelos ni
 * módulos del consumidor — recibe todo por constructor. El singleton de la
 * app vive en `main.ts` (el único archivo de wiring, fuera del paquete).
 */
export class AuthorizationManager {
  #config: AuthorizationConfig
  #driver: AuthorizationDriver | null = null
  /** Manager del que esta vista toma el driver (solo en vistas de `forRequest`). */
  #parent: AuthorizationManager | null = null
  /** Resolutor memoizado de ESTA vista; `null` = leer con el driver tal cual. */
  #readResolver: ScopeChainResolver | null = null
  #readDriver: AuthorizationDriver | null = null
  /** Memo del catálogo propio, solo si el driver no expone el suyo (composición sin puerto). */
  #ownCatalog: CatalogCache | null = null
  /** Instante (reloj monótono, `#clock`) a partir del cual esta vista ya no puede leer; `null` = sin límite / no es vista. */
  #readsUntil: number | null = null
  /** Reloj monótono con el que se mide `#readsUntil` (inyectable solo en tests). */
  #clock: () => number = monotonicNow

  constructor(config: AuthorizationConfig) {
    this.#config = config
    if (config.clock !== undefined && typeof config.clock !== 'function') {
      throw new AuthorizationConfigError(
        `AuthorizationManager: config.clock debe ser una función () => Date (llegó ${typeof config.clock})`
      )
    }
    this.#warnOptInSecurity()
  }

  /**
   * `requireWithin` y `requireActor` son opt-in en 2.1 (auditor E2, aceptado
   * y nombrado): con los defaults, un call-site que no pase `within` concede
   * donde le digan y una escritura sin `actor` se audita sin autor. Se avisa
   * UNA vez por config al construir el manager; `warnOnOptInSecurity: false`
   * es la forma explícita de asumirlo.
   */
  #warnOptInSecurity(): void {
    const config = this.#config
    if (config.warnOnOptInSecurity === false) return
    const missing = (['requireWithin', 'requireActor'] as const).filter((flag) => !config[flag])
    if (missing.length === 0 || warnedConfigs.has(config)) return
    warnedConfigs.add(config)
    const consequences: Record<(typeof missing)[number], string> = {
      requireWithin: "las escrituras sin 'within' van al scope que les digan, sea de quien sea",
      requireActor: 'las escrituras se auditan sin autor',
    }
    console.warn(
      `authz: seguridad opt-in sin activar — ${missing.join(', ')}: ` +
        `${missing.map((flag) => consequences[flag]).join('; ')}. ` +
        `Actívalo en config/authorization.ts o silencia este aviso con warnOnOptInSecurity: false.`
    )
  }

  /**
   * Vista por request (2A/A3): las LECTURAS (`authorize`, `hasRole`, `list*`)
   * resuelven ancestros con `memoizeAncestors(config.scopes.resolveChain)`
   * —una llamada al árbol por scope durante la vida de la vista—; las
   * ESCRITURAS (`grant`, `revoke`, `deny`, `removeDeny`, `scopes.*`) siguen
   * resolviendo en fresco, porque una lectura obsoleta caduca sola y un
   * grant sobre una cadena que ya cambió queda escrito para siempre (auditor
   * C3/E3). El memo es de ANCESTROS, nunca de decisiones: un deny escrito
   * entre dos `authorize` de la misma vista cambia la segunda respuesta.
   *
   * Patrón en Adonis: un middleware hace `ctx.authz = authorization.forRequest()`
   * y controladores y policies leen de `ctx.authz`. Sin `AsyncLocalStorage`:
   * la vista es un objeto explícito con la vida que le des. Sin
   * `config.scopes.resolveChain`, o con un driver de terceros sin
   * `withChainResolver`, la vista lee con el driver tal cual (sin memo)
   * y sigue siendo correcta.
   */
  forRequest(options: ForRequestOptions = {}): AuthorizationView {
    const maxAgeMs = options.maxAgeMs ?? DEFAULT_VIEW_MAX_AGE_MS
    if (!Number.isInteger(maxAgeMs) || maxAgeMs < 0) {
      throw new AuthorizationConfigError(
        `forRequest: maxAgeMs debe ser un entero >= 0 (0 = sin límite; llegó ${String(maxAgeMs)})`
      )
    }
    if (options.now !== undefined && typeof options.now !== 'function') {
      throw new AuthorizationConfigError(`forRequest: now debe ser una función (llegó ${typeof options.now})`)
    }
    const view = new AuthorizationManager(this.#config)
    view.#parent = this.#parent ?? this
    const resolver = this.#config.scopes?.resolveChain
    view.#readResolver = resolver ? memoizeAncestors(resolver) : null
    view.#clock = options.now ?? monotonicNow
    view.#readsUntil = maxAgeMs === 0 ? null : view.#clock() + maxAgeMs
    return view
  }

  /**
   * El driver activo, TAL CUAL. Es la salida explícita de las barreras del
   * manager (2D · G4, auditor 8): lo que escribas por aquí no pasa por
   * `actor`/`requireActor`, `within`/`requireWithin` ni `onWrite`, y lo que
   * leas no pasa por el memo de ancestros. Está pensado para el código de
   * PLATAFORMA (seeders, comandos, la escritura en la raíz con
   * `requireWithin: 'non-root'`) y para tests; un call-site de tenant nunca
   * debería llamarlo. No se ofrece nada más por aquí a propósito.
   *
   * Lo único que el manager le aplica al resolverlo es el reloj del config
   * (`clock`, 2.5 · J1) vía `withClock`: no es una barrera, es la hora con
   * la que el driver decide, y vale igual para la plataforma, los tests y
   * cada vista de `forRequest()` (todas leen el driver del padre). Un driver
   * sin `withClock` con `clock` declarado es 500 `E_AUTHZ_CONFIG`.
   */
  async driver(): Promise<AuthorizationDriver> {
    if (this.#parent) return this.#parent.driver()
    if (this.#driver) return this.#driver
    const registry: Record<string, AuthorizationDriverFactory> = this.#config.drivers
    const factory = registry[this.#config.default]
    if (!factory) {
      throw new Exception(
        `Driver de autorización '${this.#config.default}' no registrado. ` +
          `Registrados: ${Object.keys(this.#config.drivers).join(', ')}`,
        { status: 500 }
      )
    }
    let driver = await factory()
    const clock = this.#config.clock
    if (clock !== undefined) {
      if (typeof driver.withClock !== 'function') {
        throw new AuthorizationConfigError(
          `config.clock está declarado pero el driver '${this.#config.default}' no implementa withClock(now): ` +
            `el reloj no llegaría a ninguna decisión. Implementa withClock en el driver o quita clock del config.`
        )
      }
      driver = driver.withClock(clock)
    }
    this.#driver = driver
    return driver
  }

  /** Solo tests: fuerza re-resolución del driver. */
  clearCachedDriver(): void {
    this.#driver = null
    this.#readDriver = null
  }

  /**
   * El driver para LEER: en una vista de `forRequest`, el driver con el
   * resolutor memoizado (si el driver sabe darlo); fuera de una vista, el
   * driver tal cual. Las escrituras nunca pasan por aquí.
   */
  /**
   * Una vista caducada no lee (F9): su memo de ancestros puede describir un
   * árbol que ya cambió. Ruidoso a propósito. Lo mide el reloj monótono (H3).
   * Pasan por aquí TODAS las lecturas, `expandExcludedSubtrees` incluida (I2).
   */
  #assertReadable(): void {
    if (this.#readsUntil !== null && this.#clock() >= this.#readsUntil) {
      throw new ViewExpiredError(
        `La vista de forRequest() superó su maxAgeMs y ya no puede leer: su memo de ancestros puede estar obsoleto. ` +
          `Crea la vista por request (un middleware) o pasa forRequest({ maxAgeMs: 0 }) a sabiendas.`
      )
    }
  }

  async #reader(): Promise<AuthorizationDriver> {
    this.#assertReadable()
    const driver = await this.driver()
    if (!this.#readResolver) return driver
    if (this.#readDriver) return this.#readDriver
    this.#readDriver = driver.withChainResolver?.(this.#readResolver) ?? driver
    return this.#readDriver
  }

  /**
   * El árbol de scopes es un hecho del contrato: el consumidor notifica sus
   * cambios aquí, en TODOS los drivers, y el PAQUETE valida antes de tocar
   * el driver — la raíz no cuelga de nada, el padre tiene que existir y no
   * puede haber ciclos. FGA acepta un ciclo de `parent` y lo evalúa (un grant
   * en cualquier nodo concede en la raíz, S2), así que la barrera es esta.
   * Espía: si la validación falla, cero llamadas al driver.
   */
  readonly scopes = {
    // `within` (2D · F2; origen y destino desde 2E · H1) se contrasta con el
    // PADRE —colgar o mover algo bajo un scope es escribir en ese scope— Y con
    // la cadena ACTUAL del hijo cuando ya está en el árbol: llevarse un
    // subárbol de otro tenant es peor que purgarlo (se hereda todo lo robado).
    // Por eso el consumidor notifica ANTES de recolgar su fila: la cadena que
    // se contrasta es la de origen, resuelta en fresco.
    attached: async (child: ScopeRef, parent: ScopeRef, options?: ScopedWriteOptions): Promise<void> => {
      this.#writeOptions(options, 'scopes.attached')
      const chain = await this.#assertEdge(child, parent, 'scopes.attached')
      this.#assertWithinChain(parent, chain, options, 'scopes.attached')
      // Un hijo que el árbol ya conoce se está MOVIENDO (el `attach` de un
      // nodo existente es un `move`): su origen también tiene que estar dentro.
      await this.#assertWithinOrigin(child, options, 'scopes.attached', 'if-known')
      await (await this.driver()).onScopeAttached?.(child, parent)
    },
    moved: async (child: ScopeRef, newParent: ScopeRef, options?: ScopedWriteOptions): Promise<void> => {
      this.#writeOptions(options, 'scopes.moved')
      const chain = await this.#assertEdge(child, newParent, 'scopes.moved')
      this.#assertWithinChain(newParent, chain, options, 'scopes.moved')
      await this.#assertWithinOrigin(child, options, 'scopes.moved', 'required')
      await (await this.driver()).onScopeMoved?.(child, newParent)
    },
    /**
     * Hechos primero (el driver demuestra cero o lanza), arista después
     * (S6): si la purga muere a medias, el subárbol sigue colgado y los
     * denies heredados siguen valiendo. Sin `within` no comprueba que el
     * scope exista (el consumidor puede haber borrado ya su fila); con
     * `within` (2D · F2) el hijo tiene que seguir en el árbol para
     * contrastar su cadena: purga ANTES de borrar la fila.
     */
    detached: async (child: ScopeRef, options?: ScopedWriteOptions): Promise<ScopeDetachOutcome> => {
      const actor = this.#writeOptions(options, 'scopes.detached')
      this.#resolver('scopes.detached')
      assertScope(child)
      if (child.type === APP_SCOPE_TYPE) {
        throw new InvalidIdentityError('scopes.detached: la raíz `app` no se puede borrar ni purgar')
      }
      await this.#assertWithin(child, options, 'scopes.detached')
      const driver = await this.driver()
      // La identidad CANÓNICA, una sola vez y para TODO (3E · P2, auditor
      // A2): hasta aquí los hechos se canonizaban dentro del driver y los
      // roles no, así que un alias del uuid del scope —el mismo uuid sin
      // guiones, que el tipo `uuid` de PostgreSQL resuelve a la misma fila y
      // `assertScope` acepta— purgaba las asignaciones y dejaba VIVOS los
      // roles: la mina de V5 volvía, en silencio y sin error.
      // Una SOLA resolución para las dos cosas que dependen de ella: la
      // identidad canónica de los hechos y si el árbol todavía conoce el
      // scope (3G · W2, auditor P2: con `descendantsOf` declarado, un scope
      // que ya no resuelve NO permite demostrar que la purga alcanzó al
      // subárbol, y el resultado tiene que decirlo).
      const chain = await resolveChain(this.#freshResolver(), child, 'scopes.detached')
      const purged = chain ? chain[0] : child
      // Los roles LOCALES cuyo owner es este scope, PRIMERO (3D · M4, auditor
      // V5): un rol sin owner no es visible en ninguna parte —no concede, no
      // es membresía— pero su fila sobrevivía, `deleteScopedRole` respondía
      // 422 `E_AUTHZ_UNKNOWN_SCOPE` (resuelve el owner en fresco) y ese
      // `(slug, nivel)` quedaba bloqueado para el catálogo global PARA
      // SIEMPRE. Antes que los hechos, para que un driver que no sabe purgar
      // roles (openfga hasta 3b) lo diga con 500 `E_AUTHZ_UNSUPPORTED` sin
      // haber tocado nada.
      const outcome = await this.#purgeRolesOwnedBy(driver, purged, chain, actor.actor)
      const event: AuthzWriteEvent = {
        action: 'scope_purged',
        scope: purged,
        ...actor,
        ...(outcome.reason ? { reason: outcome.reason } : {}),
        ...(outcome.truncated ? { truncated: true as const } : {}),
      }
      await this.#write(event, () => driver.purgeScope(purged))
      await driver.onScopeDetached?.(purged)
      await this.#notify(event)
      return outcome
    },
  }

  /**
   * Purga los roles LOCALES cuyo owner es `scope` —ya CANÓNICO— y, cuando el
   * consumidor declara `scopes.descendantsOf`, los de todo su SUBÁRBOL (3D ·
   * M4; 3E · P2, auditor A4: `detached(padre)` es lo que un consumidor
   * notifica al borrar una rama, y los roles de los hijos quedaban huérfanos
   * e indeleteables, bloqueando su `(slug, nivel)` global para siempre).
   * Sin `descendantsOf` la promesa del invariante 18 se acota al scope
   * exacto y así está escrito.
   *
   * Los roles se leen de la BASE (`readRolesOwnedBy`), no del memo: con una
   * ventana `{ everyMs }` la foto puede no tener lo que otro proceso acaba
   * de confirmar (auditor A2 bis).
   *
   * Policy de rango (3E · P3, auditor A3): `scopes.*` puede colgar de la
   * sesión de un tenant —el invariante 15 lo invita—, así que esta purga de
   * CATÁLOGO exige lo mismo que `deleteScopedRole`: rank del actor MAYOR que
   * el de cada rol, comprobado sobre TODOS antes de tocar ninguno. Sin
   * `actor` (plataforma) se comporta como hasta ahora, y el README lo dice.
   * Si el árbol YA NO conoce el scope, la purga PROCEDE (3F · S1, auditor
   * N2): `detached` es la operación que limpia DESPUÉS de borrar la fila y
   * bloquearla dejaba vivos el rol, sus asignaciones y los denies de un
   * scope que ya no existe —sin ninguna salida por el manager con
   * `requireActor: true`—. Lo que se salta es la comprobación de rango **de
   * los roles cuyo PROPIO owner tampoco resuelve**, no la de todos (3G · W1,
   * auditor P1): medirla en la cadena del scope notificado y aplicarla a
   * roles de otros owners destruía roles de descendientes VIVOS —de
   * cualquier rango, concediendo en ese instante— que `deleteScopedRole` y
   * el `detached` del propio scope niegan con 422. El evento y el valor de
   * retorno lo dicen (`reason`).
   *
   * Cada `purgeRole` es atómico (asignaciones + vínculos + fila + versión) y
   * se notifica `role_purged`; el conjunto no lo es, pero un rol cuyo owner
   * ya no está en el árbol no es visible en ningún sitio, así que una purga
   * a medias no cambia ninguna decisión — solo deja filas que la siguiente
   * llamada recoge.
   */
  async #purgeRolesOwnedBy(
    driver: AuthorizationDriver,
    scope: ScopeRef,
    chain: ScopeRef[] | null,
    actor: SubjectRef | undefined
  ): Promise<ScopeDetachOutcome> {
    const ownerKeys = [scopeKey(scope)]
    const { below, declared, enumerated } = await this.#descendantsOrDegrade(scope, 'scopes.detached')
    for (const node of below) ownerKeys.push(scopeKey(node))
    // 3G · W2 (auditor P2): con el scope FUERA del árbol, un `descendantsOf`
    // que responde vacío (o `null`, que aquí es lo mismo) no demuestra que
    // debajo no quede nada — el puerto no le exige responder por un scope
    // que `resolveChain` ya no conoce (docblock de
    // `ScopeDescendantsResolver`)—, así que el resultado no puede decir
    // «completa»: `truncated: true`. Con una lista NO vacía sí se enumeró.
    const unknownScope = chain === null
    const truncated = declared && (!enumerated || (unknownScope && below.length === 0))
    const owned = await readRolesOwnedBy(ownerKeys, { driver: this.#config.default })
    if (owned.length === 0) {
      // El `reason` sale también con cero roles (3G · W2): lo que dice es que
      // el árbol ya no conoce el scope, y eso vale igual para el consumidor
      // que audita una purga que no encontró nada que purgar.
      return { purgedRoles: 0, truncated, ...(unknownScope ? { reason: 'owner-detached-unknown' as const } : {}) }
    }
    const purgeRole = this.#optional(driver, 'purgeRole', 'scopes.detached')
    const skipped = actor ? await this.#assertAboveOwnedRoles(driver, actor, owned.map((o) => o.role)) : false
    const reason = unknownScope || skipped ? ('owner-detached-unknown' as const) : undefined
    for (const { role, permissions } of owned) {
      const owner = scopeFromKey(role.owner) ?? scope
      try {
        await purgeRole(role.uuid)
      } finally {
        invalidateAuthzCatalog()
      }
      await this.#notifyCatalog({ action: 'role_purged', actor, role, owner, permissions })
    }
    return { purgedRoles: owned.length, truncated, ...(reason ? { reason } : {}) }
  }

  /**
   * El actor de un `scopes.detached` solo tumba roles de rango MENOR que el
   * suyo (3E · P3, auditor A3): un admin de unit con rank 5 no puede
   * destruir por la vía del árbol el rol de rank 40 que `deleteScopedRole`
   * le niega. Se comprueban TODOS antes de purgar ninguno (nada a medias).
   *
   * **El rango se mide POR ROL, en la cadena del OWNER de cada uno** — lo
   * mismo que `deleteScopedRole`, que es la otra puerta a lo mismo (3G · W1,
   * auditor P1). Medirlo en la cadena del scope NOTIFICADO y aplicarlo a
   * roles de OTROS owners era un fail-open de manual: con `descendantsOf`
   * declarado (S2) y la fila del padre ya borrada (S1), `detached(padre)`
   * destruía los roles locales de descendientes VIVOS —de cualquier rango,
   * concediendo en ese instante— porque la cadena del padre no resolvía y la
   * policy no llegaba a correr. Las dos piezas eran correctas por separado.
   *
   * La comprobación se salta SOLO para los roles cuyo PROPIO owner tampoco
   * resuelve: esos son los realmente inalcanzables (no conceden, no son
   * membresía, no se pueden asignar ni borrar por `deleteScopedRole`) y son
   * los que S1 vino a desbloquear. Devuelve `true` si se saltó alguno, para
   * que el evento y el `ScopeDetachOutcome` lo digan (`reason`).
   *
   * Coste: un `resolveChain` y una lectura de roles del actor por OWNER
   * distinto (memoizados por clave), no por rol.
   */
  async #assertAboveOwnedRoles(
    driver: AuthorizationDriver,
    actor: SubjectRef,
    roles: readonly CatalogRole[]
  ): Promise<boolean> {
    const catalog = await this.#catalogFor(driver).view()
    // `null` = el owner de ese rol tampoco está en el árbol: nada que medir.
    const rankIn = new Map<string, number | null>()
    let skipped = false
    for (const role of roles) {
      if (!rankIn.has(role.owner)) {
        const owner = this.#ownerOf(role)
        const ownerChain = await resolveChain(this.#freshResolver(), owner, 'scopes.detached')
        rankIn.set(role.owner, ownerChain ? (await this.#rolesAlong(driver, actor, ownerChain, catalog)).rank : null)
      }
      const rank = rankIn.get(role.owner)!
      if (rank === null) {
        skipped = true
        continue
      }
      this.#assertAboveRole(rank, role)
    }
    return skipped
  }

  /**
   * Valida las opciones comunes de una escritura (B7) ANTES de identidad,
   * catálogo, árbol y driver: `actor` bien formado si viene; obligatorio con
   * `requireActor`. Devuelve `{ actor }` listo para fundir en el evento (o
   * `{}` si no hay actor: el evento no inventa autores).
   */
  #writeOptions(options: WriteOptions | undefined, operation: string): { actor?: SubjectRef } {
    if (options?.actor !== undefined) assertSubject(options.actor)
    if (this.#config.requireActor === true && !options?.actor) {
      throw new ActorRequiredError(
        `${operation}: el config exige 'actor' en toda escritura (requireActor: true) y no llegó ninguno.`
      )
    }
    return options?.actor ? { actor: options.actor } : {}
  }

  /** El resolutor con el que LEE este manager: el memo de la vista, o el fresco. */
  #readResolverOrFresh(): ScopeChainResolver {
    return this.#readResolver ?? this.#freshResolver()
  }

  /**
   * El catálogo para las composiciones (B5/B3): el memo del driver si lo
   * expone (`driver.catalog`, ambos drivers del paquete: una sola carga por
   * proceso) y, si no, uno propio del manager. El catálogo es propiedad
   * local siempre (`authz_*`), así que leerlo desde el manager no acopla a
   * ningún driver.
   */
  #catalogFor(driver: AuthorizationDriver): CatalogCache {
    const shared = (driver as { catalog?: unknown }).catalog
    if (shared instanceof CatalogCache) return shared
    if (this.#parent) return this.#parent.#catalogFor(driver)
    this.#ownCatalog ??= new CatalogCache({ driver: this.#config.default })
    return this.#ownCatalog
  }

  /** Un método opcional del puerto, o 500 `E_AUTHZ_UNSUPPORTED` nombrándolo. */
  #optional<K extends keyof AuthorizationDriver>(
    driver: AuthorizationDriver,
    method: K,
    primitive: string,
    hint?: string
  ): NonNullable<AuthorizationDriver[K]> {
    const fn = driver[method]
    if (typeof fn !== 'function') {
      throw new UnsupportedOperationError(method, primitive, this.#config.default, hint)
    }
    return fn.bind(driver) as NonNullable<AuthorizationDriver[K]>
  }

  /** El resolutor FRESCO del config (o solo-raíz): el de las escrituras y de `isWithin`. */
  #freshResolver(): ScopeChainResolver {
    return this.#config.scopes?.resolveChain ?? rootOnlyResolver
  }

  static #sameScope(a: ScopeRef, b: ScopeRef): boolean {
    return a.type === b.type && (a.uuid ?? null) === (b.uuid ?? null)
  }

  /**
   * ¿`outer` contiene a `inner`? = `outer ∈ chain(inner)`, inclusive: un scope
   * se contiene a sí mismo y `APP_SCOPE` contiene todo. Un `inner` que el
   * árbol no conoce no está dentro de nada (`false`). Siempre con el resolutor
   * fresco (nunca el memo por request): la contención decide escrituras.
   */
  async isWithin(inner: ScopeRef, outer: ScopeRef): Promise<boolean> {
    assertScope(inner)
    assertScope(outer)
    const chain = await resolveChain(this.#freshResolver(), inner, 'isWithin')
    if (!chain) return false
    return chain.some((s) => AuthorizationManager.#sameScope(s, outer))
  }

  /**
   * Contención de una escritura (B1; las seis desde 2D · F2). El scope tiene
   * que existir (422 `E_AUTHZ_UNKNOWN_SCOPE`, la misma regla que el driver
   * aplicará después) y `within`, si viene, estar en su cadena (422
   * `E_AUTHZ_NOT_WITHIN`). Con `requireWithin`, omitirlo es 422
   * `E_AUTHZ_WITHIN_REQUIRED`; con `'non-root'`, `APP_SCOPE` como `within`
   * es 422 `E_AUTHZ_WITHIN_ROOT_FORBIDDEN`. Todo antes del driver: nada se
   * escribe. Siempre con el resolutor fresco (nunca el memo por request).
   */
  async #assertWithin(scope: ScopeRef, options: ScopedWriteOptions | undefined, operation: string): Promise<void> {
    const within = this.#requiredWithin(scope, options, operation)
    if (!within) return
    const chain = await assertKnownScope(this.#freshResolver(), scope, operation)
    this.#assertWithinChain(scope, chain, options, operation)
  }

  /**
   * Contención del ORIGEN de un movimiento (2E · H1, auditor 1): la cadena
   * ACTUAL del hijo, resuelta en fresco, también tiene que contener `within`.
   * Con `'required'` (`scopes.moved`) el hijo tiene que existir en el árbol
   * (422 `E_AUTHZ_UNKNOWN_SCOPE`: sin cadena no hay origen que contrastar);
   * con `'if-known'` (`scopes.attached`) un hijo nuevo (`null`) no tiene
   * origen y pasa, y uno ya colgado se trata como un `move`. Solo cuando hay
   * `within` que contrastar: sin él no se consulta el árbol de más.
   */
  async #assertWithinOrigin(
    child: ScopeRef,
    options: ScopedWriteOptions | undefined,
    operation: string,
    presence: 'required' | 'if-known'
  ): Promise<void> {
    const within = this.#requiredWithin(child, options, operation)
    if (!within) return
    const resolver = this.#freshResolver()
    const chain =
      presence === 'required'
        ? await assertKnownScope(resolver, child, operation)
        : await resolveChain(resolver, child, operation)
    if (!chain) return
    this.#assertWithinChain(child, chain, options, operation)
  }

  /** Lo mismo con una cadena ya resuelta (en fresco) por el llamante. */
  #assertWithinChain(scope: ScopeRef, chain: ScopeRef[], options: ScopedWriteOptions | undefined, operation: string): void {
    const within = this.#requiredWithin(scope, options, operation)
    if (!within) return
    if (!chain.some((s) => AuthorizationManager.#sameScope(s, within))) {
      throw new NotWithinError(
        `${operation}: ${scope.type}:${scope.uuid ?? ''} no está dentro de ` +
          `${within.type}:${within.uuid ?? ''} (la cadena es ${chain.map((s) => `${s.type}:${s.uuid ?? ''}`).join(' → ')}); ` +
          `no se escribe fuera del scope declarado.`
      )
    }
  }

  /** El `within` a contrastar, validado y exigido según `requireWithin`; `null` si no hay que contrastar nada. */
  #requiredWithin(scope: ScopeRef, options: ScopedWriteOptions | undefined, operation: string): ScopeRef | null {
    const within = options?.within
    const policy = this.#config.requireWithin
    if (within === undefined) {
      if (policy === true || policy === 'non-root') {
        throw new WithinRequiredError(
          `${operation}: el config exige 'within' (requireWithin: ${JSON.stringify(policy)}) y la escritura sobre ` +
            `${scope.type}:${scope.uuid ?? ''} no lo declara.`
        )
      }
      return null
    }
    assertScope(within)
    if (policy === 'non-root' && within.type === APP_SCOPE_TYPE) {
      throw new WithinRootForbiddenError(
        `${operation}: el config exige un 'within' que acote (requireWithin: 'non-root') y llegó la raíz 'app', ` +
          `que contiene todo. Declara el tenant; la plataforma escribe en la raíz con manager.driver() o con una config sin el flag.`
      )
    }
    return within
  }

  #resolver(operation: string): ScopeChainResolver {
    const resolver = this.#config.scopes?.resolveChain
    if (!resolver) {
      throw new AuthorizationConfigError(
        `${operation} necesita 'scopes.resolveChain' en config/authorization.ts: ` +
          `sin el árbol del consumidor no se puede validar la arista.`
      )
    }
    return resolver
  }

  /** Valida la arista y devuelve la cadena (fresca) del padre. */
  async #assertEdge(child: ScopeRef, parent: ScopeRef, operation: string): Promise<ScopeRef[]> {
    const resolver = this.#resolver(operation)
    assertScope(child)
    assertScope(parent)
    if (child.type === APP_SCOPE_TYPE) {
      throw new InvalidIdentityError(`${operation}: la raíz \`app\` no puede colgar de nada`)
    }
    // 422 E_AUTHZ_UNKNOWN_SCOPE si el padre no existe.
    const chain = await assertKnownScope(resolver, parent, operation)
    // El hijo, si el árbol ya lo conoce, con su identidad canónica (K1): un
    // alias del uuid no puede colarse por debajo de la comprobación de ciclo.
    const known = await resolveChain(resolver, child, operation)
    const childKey = AuthorizationManager.#scopeKey(known ? known[0] : child)
    if (chain.some((s) => AuthorizationManager.#scopeKey(s) === childKey)) {
      throw new ScopeCycleError(
        `${operation}: ${parent.type}:${parent.uuid} desciende de ${childKey.replace('\u001f', ':')} (o es él mismo); ` +
          `colgarlo cerraría un ciclo y la herencia dejaría de ser solo hacia abajo.`
      )
    }
    return chain
  }

  // La identidad se valida AQUÍ, antes de resolver siquiera el driver: una
  // pregunta mal formada (uuid ausente, `{app, uuid}`, slug con `~`) es 422
  // sin tocar catálogo, árbol ni backend, y sin que el hook `onWrite` audite
  // una escritura que no ocurrió. Los drivers repiten la misma función por
  // defensa en profundidad (el juez y un driver suelto no pasan por aquí).

  async authorize(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, permission, scope })
    return (await this.#reader()).authorize(subject, permission, scope)
  }

  async hasRole(subject: SubjectRef, role: RoleQuery, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, role, scope })
    return (await this.#reader()).hasRole(subject, role, scope)
  }

  /**
   * `authorize` sobre varios scopes, un booleano por posición (2.1, B6).
   * Delegado al driver si trae `authorizeMany` (openfga: un batchCheck);
   * si no, `Promise.all` de `authorize` sobre una vista con los ancestros
   * memoizados (una llamada al árbol por scope distinto, aunque se repita).
   * Idéntico a N `authorize`: duplicados por posición, desconocido ⇒ false,
   * y si una posición no se puede responder, lanza entero. Vacío ⇒ `[]`
   * sin tocar backend ni árbol.
   */
  async authorizeMany(subject: SubjectRef, permission: string, scopes: ScopeRef[]): Promise<boolean[]> {
    assertIdentity({ subject, permission })
    if (!Array.isArray(scopes)) {
      throw new InvalidIdentityError(`authorizeMany: se esperaba un array de scopes y llegó ${typeof scopes}`)
    }
    for (const scope of scopes) assertIdentity({ scope })
    if (scopes.length === 0) return []
    // Fuera de una vista, la composición abre una propia para que los N
    // scopes compartan el memo de ancestros durante esta llamada.
    const view = this.#readResolver ? this : (this.forRequest() as AuthorizationManager)
    const driver = await view.#reader()
    if (typeof driver.authorizeMany === 'function') {
      const answer: unknown = await driver.authorizeMany(subject, permission, scopes)
      // Un `boolean[]` desalineado se leería por posición (F5, CR3): es un
      // bug del driver, no una decisión. 500 nombrando al culpable.
      if (!Array.isArray(answer) || answer.length !== scopes.length || answer.some((b) => typeof b !== 'boolean')) {
        throw new AuthorizationInternalError(
          `authorizeMany: el driver '${this.#config.default}' devolvió ${describeAnswer(answer)} para ${scopes.length} scopes; ` +
            `el puerto exige un boolean[] con exactamente una posición por scope.`
        )
      }
      return answer as boolean[]
    }
    return Promise.all(scopes.map((scope) => driver.authorize(subject, permission, scope)))
  }

  /** Holders con asignación vigente del rol en ese scope exacto. `{ uuid }` es la forma exacta (3D · M1). */
  async listSubjects(role: RoleQuery, scope: ScopeRef): Promise<SubjectRef[]> {
    assertIdentity({ role, scope })
    return (await this.#reader()).listSubjects(role, scope)
  }

  async listScopes(subject: SubjectRef, permission: string): Promise<ScopeRef[]> {
    assertIdentity({ subject, permission })
    return (await this.#reader()).listScopes(subject, permission)
  }

  async listRoles(subject: SubjectRef, scope: ScopeRef): Promise<string[]> {
    assertIdentity({ subject, scope })
    return (await this.#reader()).listRoles(subject, scope)
  }

  async listRoleScopes(subject: SubjectRef, scopeType: ScopeType): Promise<ScopeRef[]> {
    assertIdentity({ subject, scopeType })
    return (await this.#reader()).listRoleScopes(subject, scopeType)
  }

  /** Denies directos del holder (scope exacto, o todos). 500 `E_AUTHZ_UNSUPPORTED` si el driver no lo implementa. */
  async listDenies(subject: SubjectRef, scope?: ScopeRef): Promise<DenyRef[]> {
    assertIdentity(scope ? { subject, scope } : { subject })
    const driver = await this.#reader()
    return this.#optional(driver, 'listDenies', 'listDenies')(subject, scope)
  }

  /**
   * Permisos efectivos del holder en un scope (2.1, B5): la unión de lo que
   * conceden sus roles vigentes en toda la cadena (`listRoles` por nivel +
   * catálogo) MENOS lo denegado en cualquier nivel de la cadena
   * (`listDenies` por nivel). Es exactamente el conjunto `{ p | authorize(p) }`,
   * calculado sin preguntar permiso a permiso. Scope desconocido ⇒ `[]`.
   * Prerrequisito de `catalog/` (Fase 3).
   */
  async effectivePermissions(subject: SubjectRef, scope: ScopeRef): Promise<string[]> {
    assertIdentity({ subject, scope })
    const driver = await this.#reader()
    this.#optional(driver, 'listDenies', 'effectivePermissions')
    const chain = await resolveChain(this.#readResolverOrFresh(), scope, 'effectivePermissions')
    if (!chain) return []
    const catalog = await this.#catalogFor(driver).view()
    const { granted } = await this.#rolesAlong(driver, subject, chain, catalog)
    const denied = await this.#deniedAlong(driver, subject, chain, 'effectivePermissions')
    return [...granted].filter((permission) => !denied.has(permission))
  }

  /**
   * Lo que los roles VIGENTES del holder conceden a lo largo de una cadena
   * (ya resuelta), y el rank más alto entre ellos (3B · B3). Roles de toda la
   * cadena en UNA lectura (`rolesInChain`, G5) o, sin el método opcional, N
   * `listRoles`.
   *
   * **Por UUID, nunca por slug (3D · M1).** `rolesInChain` devuelve
   * `CatalogRoleRef`, así que aquí se lee el rol EXACTO que el holder tiene
   * y sus permisos por uuid. El ida y vuelta por slug —resolver otra vez con
   * `roleVisible`— atribuía al holder los permisos de un homónimo: el
   * auditor lo llevó hasta una escalada completa (V1, `effectivePermissions`
   * decía `billing:write` mientras `authorize` decía `false`, y
   * `defineScopedRole` delegaba lo que el actor no tenía). Se conserva la
   * defensa en profundidad: el rol tiene que seguir en el catálogo,
   * declarado para el nivel de la asignación y visible desde ese nivel.
   *
   * Un driver de terceros sin `rolesInChain` solo sabe hablar en slugs: la
   * composición pasa por `roleVisible`, que desde M1 falla CERRADA (422
   * `E_AUTHZ_AMBIGUOUS_ROLE`) si hay homónimos visibles. Nunca elige uno.
   */
  async #rolesAlong(
    driver: AuthorizationDriver,
    subject: SubjectRef,
    chain: ScopeRef[],
    catalog: CatalogView
  ): Promise<{ granted: Set<string>; rank: number }> {
    const keysFrom = chainKeysFrom(chain)
    const levelIndex = new Map(chain.map((s, i) => [scopeKey(s), i]))
    const roles: Array<{ scope: ScopeRef; role: CatalogRoleRef | null }> =
      typeof driver.rolesInChain === 'function'
        ? await driver.rolesInChain(subject, chain)
        : await this.#rolesFromSlugs(driver, subject, chain, keysFrom, catalog)
    const granted = new Set<string>()
    let rank = 0
    for (const { scope: level, role } of roles) {
      if (!role) continue
      const index = levelIndex.get(scopeKey(level))
      if (index === undefined) continue
      const declared = catalog.roleByUuid(role.uuid)
      if (!declared || declared.scopeType !== level.type) continue
      if (!isRoleVisibleWith(declared, keysFrom[index])) continue
      if (declared.rank > rank) rank = declared.rank
      for (const permission of catalog.rolePermissionsOf(declared.uuid)) granted.add(permission)
    }
    return { granted, rank }
  }

  /**
   * La composición por defecto de `#rolesAlong` cuando el driver NO trae
   * `rolesInChain` (opcional en el puerto): `listRoles` devuelve slugs y hay
   * que volver del slug al catálogo. Es el camino de un driver de terceros
   * escrito para 2.0/2.1, y hasta 3E tenía dos defectos (tester 3D · R3):
   *
   *  - usaba `roleVisible`, que desde M1 LANZA 422 `E_AUTHZ_AMBIGUOUS_ROLE`
   *    con dos homónimos visibles: `effectivePermissions` —una LECTURA que
   *    promete una lista— explotaba con un 422 en cuanto un `scopes.moved`
   *    legítimo juntaba dos roles del mismo nombre;
   *  - y elegir uno sería la escalada del auditor V1 (atribuir al holder los
   *    permisos del homónimo que NO tiene).
   *
   * La salida es no elegir NI adivinar: con homónimos visibles se pregunta
   * al driver por `{ uuid }` —resolución exacta, parte del puerto desde 3D ·
   * M1— cuál tiene de verdad. Cuesta una consulta más por slug ambiguo (que
   * es deriva y el diff la reporta), y solo en drivers sin `rolesInChain`.
   */
  async #rolesFromSlugs(
    driver: AuthorizationDriver,
    subject: SubjectRef,
    chain: ScopeRef[],
    keysFrom: string[][],
    catalog: CatalogView
  ): Promise<Array<{ scope: ScopeRef; role: CatalogRoleRef | null }>> {
    const roles: Array<{ scope: ScopeRef; role: CatalogRoleRef | null }> = []
    for (const [index, level] of chain.entries()) {
      for (const slug of await driver.listRoles(subject, level)) {
        const visible = catalog.rolesNamed(slug, level.type).filter((role) => isRoleVisibleWith(role, keysFrom[index]))
        if (visible.length === 1) {
          roles.push({ scope: level, role: visible[0] })
          continue
        }
        for (const role of visible) {
          if (await driver.hasRole(subject, { uuid: role.uuid }, level)) roles.push({ scope: level, role })
        }
      }
    }
    return roles
  }

  /**
   * El/los rol(es) a los que apunta un `RoleQuery` en un scope, para el
   * EVENTO de auditoría (3E · Q7). Best-effort a propósito: NUNCA cambia el
   * resultado de la escritura —lo que decide es el driver, con su catálogo y
   * su árbol—, solo enriquece lo que se notifica. Si algo no cuadra (scope
   * que el árbol no conoce, rol fuera del catálogo, ambigüedad en un grant)
   * el evento sale sin `roles` y el driver dirá lo que corresponda.
   *
   * Solo se calcula si hay un `onWrite` que lo vaya a leer: sin hook no
   * cuesta ni una consulta.
   */
  async #resolvedRoles(role: RoleQuery, scope: ScopeRef, operation: 'grant' | 'revoke'): Promise<CatalogRoleRef[] | undefined> {
    if (!this.#config.hooks?.onWrite) return undefined
    try {
      const driver = await this.driver()
      const chain = await resolveChain(this.#freshResolver(), scope, operation)
      if (!chain) return undefined
      const catalog = await this.#catalogFor(driver).view()
      const target = chain[0]
      const keys = chainKeysFrom(chain)[0]
      const query = normalizeRoleQuery(role)
      if (query.uuid !== undefined) {
        const declared = catalog.roleByUuid(query.uuid)
        if (!declared || declared.scopeType !== target.type || !isRoleVisibleWith(declared, keys)) return undefined
        return [declared]
      }
      if (query.scopeType !== undefined && query.scopeType !== target.type) return undefined
      const visible = catalog.rolesNamed(query.slug, target.type).filter((r) => isRoleVisibleWith(r, keys))
      if (visible.length === 0) return undefined
      // Un `revoke` por slug quita los hechos de TODOS los homónimos del
      // scope, así que el evento los lleva todos; un `grant` ambiguo no
      // llega a escribir (422), y el evento no elige por él.
      return operation === 'revoke' || visible.length === 1 ? visible : undefined
    } catch {
      return undefined
    }
  }

  /** Permisos DENEGADOS al holder en algún scope de la cadena: `listDenies` en UNA lectura (500 `E_AUTHZ_UNSUPPORTED` sin él). */
  async #deniedAlong(driver: AuthorizationDriver, subject: SubjectRef, chain: ScopeRef[], primitive: string): Promise<Set<string>> {
    const listDenies = this.#optional(driver, 'listDenies', primitive)
    const key = AuthorizationManager.#scopeKey
    const chainKeys = new Set(chain.map(key))
    const denied = new Set<string>()
    for (const deny of await listDenies(subject)) {
      if (chainKeys.has(key(deny.scope))) denied.add(deny.permission)
    }
    return denied
  }

  // ── Roles locales a un scope (3B · B3): la API de DELEGACIÓN ─────────
  // Un administrador de un scope (el actor) define roles que solo existen
  // dentro de ese scope (owner) con permisos que él mismo tiene efectivos
  // ahí y que la plataforma declaró delegables, por debajo de su rank. Es
  // policy de ESCRITURA (composición): `authorize` no cambia (invariantes
  // 1, 2, 8). Todo se resuelve en FRESCO (auditor C3): una vista de
  // `forRequest` con la cadena vieja no puede delegar en una unit que ya
  // cambió de tenant. Escribe con `withAuthzCatalogWrite`: la versión
  // compartida sube como última sentencia y los demás procesos ven el rol
  // en su siguiente pregunta (B7).

  /**
   * Define un rol LOCAL a `ownerScope`. Policy, en este orden y antes de
   * escribir nada: `actor` obligatorio y bien formado; `ownerScope` válido,
   * no la raíz (los roles de la raíz son globales: config + sync) y conocido
   * por el árbol (fresco); `spec` bien formado (slug, nivel ≠ `app`, rank
   * entero, permisos); cada permiso en `config.delegablePermissions`, en el
   * catálogo, componible en ese nivel (`assignableAt`, B5) y EFECTIVO para
   * el actor en el owner (lo concede un rol suyo de la cadena y no lo tiene
   * denegado en ella — C2); `0 < rank < min(rank del actor, rank máximo
   * global)`; y ningún rol `(slug, scopeType)` visible en el owner (global,
   * o local a un ancestro) ni local a un descendiente (colisión, 422
   * `E_AUTHZ_CATALOG_CONFLICT`, re-comprobada dentro de la transacción
   * serializada — 3D · M2). `options.within` contiene la escritura contra el
   * OWNER y `requireWithin` la exige, como en las otras ocho (3D · M3).
   * Devuelve el rol y notifica `role_defined`.
   */
  async defineScopedRole(
    actor: SubjectRef,
    ownerScope: ScopeRef,
    spec: ScopedRoleSpec,
    options?: ScopedWriteOptions
  ): Promise<CatalogRole> {
    const who = this.#requireActor(actor, 'defineScopedRole')
    this.#assertOwnerScope(ownerScope, 'defineScopedRole')
    const parsed = this.#parseScopedRoleSpec(spec)
    const driver = await this.driver()
    // 3E · P4 (code-review): un rol local que este driver no sabrá purgar es
    // estado que NADA puede borrar — `deleteScopedRole` responde 500 y
    // `scopes.detached` de ese scope (y de cualquier ancestro que lo
    // arrastre) queda muerto para siempre, hechos incluidos. Se dice ANTES
    // de crear nada, no al intentar deshacerlo.
    this.#optional(
      driver,
      'purgeRole',
      'defineScopedRole',
      'Los roles locales a un scope necesitan poder purgarse; en el driver openfga llegan con el modo `facts` (fase 3b).'
    )
    const chain = await assertKnownScope(this.#freshResolver(), ownerScope, 'defineScopedRole')
    // Contención (3D · M3, auditor V4): es la SÉPTIMA escritura y hasta 3C no
    // la cubría `requireWithin`, así que un holder con un rol en la RAÍZ
    // creaba roles dentro de cualquier tenant (squatting de slugs incluido)
    // con el `ownerScope` que le llegara en el cuerpo de la petición. La
    // cadena ya está resuelta en fresco: se contrasta contra ella.
    this.#assertWithinChain(ownerScope, chain, options, 'defineScopedRole')
    const owner = chain[0]
    const ownerKey = scopeKey(owner)
    const catalog = await this.#catalogFor(driver).view()
    // Composición y lista blanca antes de leer hechos: lo barato primero.
    this.#assertComposable(parsed.permissions, parsed, catalog)
    await this.#assertLevelUnderOwner(parsed.scopeType, chain, 'defineScopedRole')
    const { granted, rank: actorRank } = await this.#rolesAlong(driver, who, chain, catalog)
    const denied = await this.#deniedAlong(driver, who, chain, 'defineScopedRole')
    this.#assertDelegable(parsed.permissions, granted, denied, owner)
    this.#assertRank(parsed.rank, actorRank, catalog.topGlobalRank)
    const shadowedByAncestor = await this.#assertNoRoleCollision(parsed.slug, parsed.scopeType, owner, chain, catalog.rolesNamed(parsed.slug, parsed.scopeType))
    this.#assertAboveShadowed(actorRank, shadowedByAncestor, 'defineScopedRole')

    const uuid = uuidv7()
    const permissionUuids = parsed.permissions.map((slug) => catalog.permission(slug)!.uuid)
    await this.#writeCatalog(async (trx) => {
      // La colisión, OTRA VEZ, dentro de la transacción SERIALIZADA (M2) y
      // contra la BASE: entre el chequeo de arriba y este hubo un
      // `resolveChain` y dos lecturas al driver —cientos de ms con un árbol
      // SQL— y el memo no ve lo que otro proceso confirmó en esa ventana.
      const rows: any[] = await trx
        .from('authz_roles')
        .where('slug', parsed.slug)
        .where('scope_type', parsed.scopeType)
        .select('owner_scope_key')
      const known = new Set(catalog.rolesNamed(parsed.slug, parsed.scopeType).map((r) => r.owner))
      const fresh = [...new Set(rows.map((r) => String(r.owner_scope_key)).filter((o) => !known.has(o)))]
      if (fresh.length) {
        // Los homónimos que el memo no tenía son de una escritura confirmada
        // mientras validábamos. Los que se pueden juzgar SIN salir de la
        // transacción (global, o un ancestro-o-igual del owner: la cadena ya
        // está resuelta) dan el 422 preciso; el resto se rechaza igual —
        // resolver su cadena aquí dentro pediría otra conexión mientras se
        // sostiene el cerrojo del catálogo (con un pool de 1, un abrazo
        // mortal). Reintentar es correcto: el memo ya está invalidado y el
        // segundo intento valida con la foto buena.
        await this.#assertNoRoleCollision(parsed.slug, parsed.scopeType, owner, chain, fresh.map((o) => ({ owner: o })), 'sin-árbol')
        throw new CatalogConflictError(
          `El catálogo cambió mientras se validaba '${parsed.slug}@${parsed.scopeType}': apareció un rol con ese nombre ` +
            `(owner ${fresh.join(', ')}) que no estaba en la foto con la que se comprobaron las colisiones. ` +
            `No se escribe a ciegas; reintenta la operación.`
        )
      }
      const now = systemClock()
      await trx.table('authz_roles').insert({
        uuid,
        slug: parsed.slug,
        name: parsed.name,
        description: parsed.description,
        scope_type: parsed.scopeType,
        rank: parsed.rank,
        owner_scope_key: ownerKey,
        created_at: now,
        updated_at: now,
      })
      for (const permissionUuid of permissionUuids) {
        await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: uuid, permission_uuid: permissionUuid, created_at: now })
      }
    })
    const role: CatalogRole = Object.freeze({ uuid, slug: parsed.slug, scopeType: parsed.scopeType, owner: ownerKey, rank: parsed.rank })
    await this.#notifyCatalog({
      action: 'role_defined',
      actor: who,
      role,
      owner,
      permissions: [...parsed.permissions].sort(),
      ...(shadowedByAncestor.length ? { shadowedByAncestor } : {}),
    })
    return role
  }

  /**
   * Cambia `name`/`description`/`rank`/`permissions` de un rol LOCAL (nunca
   * su slug, nivel ni owner). Un global es 422 `E_AUTHZ_ROLE_IMMUTABLE`. El
   * actor tiene que tener, en el owner del rol, rank MAYOR que el del rol
   * (no se toca un rol de rango ≥ al propio) y la misma policy que al
   * definir para lo que cambia: los permisos nuevos delegables/efectivos y
   * componibles, el rank nuevo por debajo del suyo. Sin cambios reales no
   * escribe ni notifica (idempotente). Notifica `role_updated`.
   */
  async updateScopedRole(
    actor: SubjectRef,
    roleUuid: string,
    changes: ScopedRoleChanges,
    options?: ScopedWriteOptions
  ): Promise<CatalogRole> {
    const who = this.#requireActor(actor, 'updateScopedRole')
    assertCatalogUuid('rol', roleUuid)
    const parsed = this.#parseScopedRoleChanges(changes)
    const driver = await this.driver()
    const catalog = await this.#catalogFor(driver).view()
    const role = this.#localRoleOrFail(catalog, roleUuid)
    const owner = this.#ownerOf(role)
    const chain = await assertKnownScope(this.#freshResolver(), owner, 'updateScopedRole')
    // El scope contrastado es el OWNER del rol (3D · M3): editar un rol es
    // escribir dentro de su contenedor.
    this.#assertWithinChain(owner, chain, options, 'updateScopedRole')
    const current = [...catalog.rolePermissionsOf(role.uuid)].sort()
    const next = {
      name: parsed.name ?? null,
      description: parsed.description,
      rank: parsed.rank ?? role.rank,
      permissions: parsed.permissions ?? current,
    }
    if (parsed.permissions) this.#assertComposable(parsed.permissions, role, catalog)
    // 3E · P1: el nivel no cambia por esta API, pero un rol cuyo nivel está
    // POR ENCIMA de su owner (creado antes de 3E o a mano) no se perpetúa:
    // es una mina de slug y lo que toca es purgarlo, no editarlo.
    await this.#assertLevelUnderOwner(role.scopeType, chain, 'updateScopedRole')
    const { granted, rank: actorRank } = await this.#rolesAlong(driver, who, chain, catalog)
    this.#assertAboveRole(actorRank, role)
    // 3G · W3: este rol puede estar ENSOMBRECIENDO al homónimo de un
    // descendiente (3F · S3). Cambiarle rank o permisos es seguir ejerciendo
    // esa autoridad, así que exige lo mismo que crearlo: superarlo en rango.
    this.#assertAboveShadowed(
      actorRank,
      await this.#shadowedBelow(
        scopeKey(owner),
        new Set(chain.map(scopeKey)),
        catalog.rolesNamed(role.slug, role.scopeType).filter((other) => other.uuid !== role.uuid),
        'updateScopedRole'
      ),
      'updateScopedRole'
    )
    if (parsed.permissions) {
      const denied = await this.#deniedAlong(driver, who, chain, 'updateScopedRole')
      this.#assertDelegable(parsed.permissions, granted, denied, owner)
    }
    if (parsed.rank !== undefined) this.#assertRank(parsed.rank, actorRank, catalog.topGlobalRank)

    const nextPermissions = [...next.permissions].sort()
    const permissionsChanged = nextPermissions.join('\u001f') !== current.join('\u001f')
    const wanted = new Set(nextPermissions.map((slug) => catalog.permission(slug)!.uuid))
    const changed = await this.#writeCatalog(async (trx) => {
      const row: any = (await trx.from('authz_roles').where('uuid', role.uuid).select('name', 'description', 'rank'))[0]
      if (!row) throw new UnknownRoleError(role.uuid)
      const patch: Record<string, unknown> = {}
      if (next.name !== null && next.name !== row.name) patch.name = next.name
      if (next.description !== undefined && (next.description ?? null) !== (row.description ?? null)) patch.description = next.description
      if (next.rank !== Number(row.rank)) patch.rank = next.rank
      let touched = false
      if (Object.keys(patch).length) {
        await trx.from('authz_roles').where('uuid', role.uuid).update({ ...patch, updated_at: systemClock() })
        touched = true
      }
      if (permissionsChanged) {
        const links: any[] = await trx.from('authz_role_permissions').where('role_uuid', role.uuid).select('uuid', 'permission_uuid')
        const linked = new Set(links.map((l) => l.permission_uuid as string))
        const stale = links.filter((l) => !wanted.has(l.permission_uuid))
        if (stale.length) {
          await trx
            .from('authz_role_permissions')
            .whereIn(
              'uuid',
              stale.map((l) => l.uuid)
            )
            .delete()
        }
        for (const permissionUuid of wanted) {
          if (linked.has(permissionUuid)) continue
          await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: role.uuid, permission_uuid: permissionUuid, created_at: systemClock() })
        }
        touched = true
      }
      return touched
    }, { skipIfNoop: true })
    const updated: CatalogRole = Object.freeze({ ...role, rank: next.rank })
    if (changed) await this.#notifyCatalog({ action: 'role_updated', actor: who, role: updated, owner, permissions: nextPermissions })
    return updated
  }

  /**
   * Purga un rol LOCAL: sus asignaciones en todos los scopes, sus vínculos y
   * el rol (`driver.purgeRole`, B4; 500 `E_AUTHZ_UNSUPPORTED` en un driver
   * que no lo trae, sin tocar nada). Un global es 422
   * `E_AUTHZ_ROLE_IMMUTABLE`; el actor necesita rank MAYOR que el del rol en
   * su owner. Notifica `role_purged`. No necesita `listDenies`.
   */
  async deleteScopedRole(actor: SubjectRef, roleUuid: string, options?: ScopedWriteOptions): Promise<void> {
    const who = this.#requireActor(actor, 'deleteScopedRole')
    assertCatalogUuid('rol', roleUuid)
    const driver = await this.driver()
    const purgeRole = this.#optional(driver, 'purgeRole', 'deleteScopedRole')
    const catalog = await this.#catalogFor(driver).view()
    const role = this.#localRoleOrFail(catalog, roleUuid)
    const owner = this.#ownerOf(role)
    const chain = await assertKnownScope(this.#freshResolver(), owner, 'deleteScopedRole')
    this.#assertWithinChain(owner, chain, options, 'deleteScopedRole')
    const { rank: actorRank } = await this.#rolesAlong(driver, who, chain, catalog)
    this.#assertAboveRole(actorRank, role)
    const permissions = [...catalog.rolePermissionsOf(role.uuid)].sort()
    try {
      await purgeRole(role.uuid)
    } finally {
      invalidateAuthzCatalog()
    }
    await this.#notifyCatalog({ action: 'role_purged', actor: who, role, owner, permissions })
  }

  /** El actor de la API de delegación: obligatorio SIEMPRE (sin él no hay policy que evaluar) y bien formado. */
  #requireActor(actor: SubjectRef | undefined, operation: string): SubjectRef {
    if (actor === undefined || actor === null) {
      throw new ActorRequiredError(`${operation}: el actor es obligatorio (es quien delega; sin él no hay policy que evaluar).`)
    }
    assertSubject(actor)
    return actor
  }

  /** El owner de un rol local: un scope válido que no sea la raíz (sus roles son globales y se declaran en el config). */
  #assertOwnerScope(ownerScope: ScopeRef, operation: string): void {
    assertScope(ownerScope)
    if (ownerScope.type === APP_SCOPE_TYPE) {
      throw new InvalidIdentityError(
        `${operation}: la raíz 'app' no puede ser owner de un rol local; los roles de la raíz son globales y se declaran ` +
          `en el catálogo del config (syncAuthzCatalog).`
      )
    }
  }

  #parseScopedRoleSpec(spec: ScopedRoleSpec): { slug: string; scopeType: ScopeType; name: string; description: string | null; rank: number; permissions: string[] } {
    if (!spec || typeof spec !== 'object') throw new InvalidIdentityError(`Spec de rol local inválido: llegó ${spec === null ? 'null' : typeof spec}`)
    assertValidSlug('rol', spec.slug)
    assertScopeType(spec.scopeType)
    if (spec.scopeType === APP_SCOPE_TYPE) {
      throw new InvalidIdentityError(`Spec de rol local inválido: un rol local no puede ser de nivel 'app' (la raíz no está dentro de ningún owner).`)
    }
    const rank = this.#parseRank(spec.rank)
    if (rank === undefined) throw new InvalidIdentityError(`Spec de rol local inválido: 'rank' es obligatorio (entero).`)
    const name = this.#parseName(spec.name) ?? spec.slug
    const description = this.#parseDescription(spec.description) ?? null
    const permissions = this.#parsePermissions(spec.permissions)
    // 3D · N3 (auditor V7): un rol sin permisos no concede nada y ocupa el
    // `(slug, nivel)` del owner —y del subárbol— para siempre. Es squatting
    // con forma de spec: 422.
    if (permissions.length === 0) {
      throw new InvalidIdentityError(
        `Spec de rol local inválido: 'permissions' está vacío. Un rol que no concede nada solo ocupa el ` +
          `(slug, nivel) de su owner; si lo que quieres es reservarlo, hazlo con un permiso real.`
      )
    }
    return { slug: spec.slug, scopeType: spec.scopeType, name, description, rank, permissions }
  }

  #parseScopedRoleChanges(changes: ScopedRoleChanges): { name?: string; description?: string | null; rank?: number; permissions?: string[] } {
    if (!changes || typeof changes !== 'object') throw new InvalidIdentityError(`Cambios de rol local inválidos: llegó ${changes === null ? 'null' : typeof changes}`)
    // 3D · N2 (tester H6): `slug`, `scopeType` y `owner` NO se cambian por
    // esta API —el README lo promete— y hasta aquí se ignoraban EN SILENCIO:
    // quien pasaba `{ slug: 'otro' }` creía haber renombrado el rol. Lo que
    // no se puede hacer se dice.
    const allowed = new Set(['name', 'description', 'rank', 'permissions'])
    const unknown = Object.keys(changes).filter((key) => !allowed.has(key))
    if (unknown.length) {
      throw new InvalidIdentityError(
        `Cambios de rol local inválidos: '${unknown.join("', '")}' no se puede${unknown.length > 1 ? 'n' : ''} cambiar ` +
          `(un rol local no cambia de slug, nivel ni owner: purga y define otro). Campos admitidos: ${[...allowed].join(', ')}.`
      )
    }
    return {
      name: this.#parseName(changes.name),
      description: this.#parseDescription(changes.description),
      rank: this.#parseRank(changes.rank),
      permissions: changes.permissions === undefined ? undefined : this.#parsePermissions(changes.permissions),
    }
  }

  #parseRank(rank: unknown): number | undefined {
    if (rank === undefined) return undefined
    if (typeof rank !== 'number' || !Number.isInteger(rank)) {
      throw new InvalidIdentityError(`rank inválido: se esperaba un entero y llegó ${typeof rank === 'number' ? rank : typeof rank}`)
    }
    return rank
  }

  #parseName(name: unknown): string | undefined {
    if (name === undefined) return undefined
    if (typeof name !== 'string' || name.length === 0 || name.length > ROLE_NAME_MAX) {
      throw new InvalidIdentityError(`name inválido: se esperaba una cadena de 1 a ${ROLE_NAME_MAX} caracteres`)
    }
    return name
  }

  #parseDescription(description: unknown): string | null | undefined {
    if (description === undefined) return undefined
    if (description === null) return null
    if (typeof description !== 'string' || description.length > ROLE_DESCRIPTION_MAX) {
      throw new InvalidIdentityError(`description inválida: se esperaba una cadena de hasta ${ROLE_DESCRIPTION_MAX} caracteres, o null`)
    }
    return description
  }

  #parsePermissions(permissions: unknown): string[] {
    if (!Array.isArray(permissions)) throw new InvalidIdentityError(`permissions inválido: se esperaba una lista de slugs y llegó ${typeof permissions}`)
    for (const slug of permissions) assertValidSlug('permiso', slug)
    return [...new Set(permissions as string[])]
  }

  /** Lista blanca, existencia en el catálogo y composición por nivel (B5), en ese orden. */
  #assertComposable(permissions: string[], role: { slug: string; scopeType: ScopeType }, catalog: CatalogView): void {
    const delegable = new Set(this.#config.delegablePermissions ?? [])
    for (const slug of permissions) {
      if (!delegable.has(slug)) {
        throw new PermissionNotDelegableError(
          `'${slug}' no se puede delegar: no está en config.delegablePermissions ` +
            `(${delegable.size ? [...delegable].join(', ') : 'vacía: nadie delega nada hasta declararla'}).`
        )
      }
      const permission = catalog.permission(slug)
      if (!permission) throw new UnknownPermissionError(slug)
      assertAssignableAt(role, slug, permission.assignableAt)
    }
  }

  /** Cada permiso tiene que ser EFECTIVO para el actor en el owner: concedido por un rol suyo de la cadena y no denegado en ella (C2). */
  #assertDelegable(permissions: string[], granted: Set<string>, denied: Set<string>, owner: ScopeRef): void {
    for (const slug of permissions) {
      if (denied.has(slug)) {
        throw new PermissionNotDelegableError(
          `'${slug}' no se puede delegar: el actor lo tiene DENEGADO en ${owner.type}:${owner.uuid ?? ''} (o en un ancestro); ` +
            `un deny no se lava componiendo un rol para otro.`
        )
      }
      if (!granted.has(slug)) {
        throw new PermissionNotDelegableError(
          `'${slug}' no se puede delegar: el actor no lo tiene efectivo en ${owner.type}:${owner.uuid ?? ''} ` +
            `(ningún rol vigente suyo en esa cadena lo concede).`
        )
      }
    }
  }

  /** `0 < rank < min(rank del actor, rank máximo global)`: policy de escritura, no de evaluación (invariante 8). */
  #assertRank(rank: number, actorRank: number, topGlobalRank: number): void {
    const ceiling = Math.min(actorRank, topGlobalRank)
    if (!(rank > 0 && rank < ceiling)) {
      throw new RankExceededError(
        `rank ${rank} fuera de la policy: tiene que cumplir 0 < rank < ${ceiling} (min(rank del actor = ${actorRank}, rank máximo global = ${topGlobalRank})).`
      )
    }
  }

  /**
   * El nivel de un rol local nunca está POR ENCIMA de su owner (3E · P1,
   * auditor A1). La regla es mínima a propósito y se decide con la cadena
   * que ya está resuelta, sin pedirle nada más al consumidor:
   *
   *  - `scopeType === owner.type` ⇒ vale (el caso propio).
   *  - `scopeType` es el nivel de un ANCESTRO del owner (`app` incluida,
   *    que está en toda cadena) ⇒ 422 `E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER`. Es
   *    la mina: un `operador@organization` cuyo owner es una unit jamás es
   *    visible —no concede, no es membresía, nadie lo puede asignar— y lo
   *    único que hace es OCUPAR ese `(slug, nivel)` para el dueño del árbol
   *    y para el catálogo GLOBAL; el actor de menor privilegio del sistema
   *    bloqueando a la plataforma (y, hasta 3E, su deploy entero).
   *  - Cualquier otro tipo se presume DESCENDIENTE y vale: es el caso común
   *    (`lead@unit` con owner una organization) y exigir `descendantsOf`
   *    para él rompía a todo consumidor con el stub publicado, que no lo
   *    declara.
   *  - Con `scopes.descendantsOf` declarado se ENDURECE: el tipo tiene que
   *    aparecer de verdad bajo el owner en el árbol de HOY; si no, 422.
   *
   * **Lo que cuesta la degradación, dicho** (3G · X1, auditor P4): si el
   * subárbol no se puede enumerar (cota superada o `descendantsOf` caído) la
   * regla vuelve a ser la MÍNIMA — y el propio actor puede provocarlo
   * creando más hijos de su scope que `maxDescendants`, porque crear scopes
   * es una función normal del producto. Es un control que el vigilado apaga.
   * Se acepta a sabiendas: la regla mínima no concede NADA (es la que corre
   * en todo consumidor con el stub publicado), y el daño residual —ocupar un
   * `(slug, nivel)`— es reparable por AUTORIDAD + RANGO: un ancestro con
   * rango por encima define el suyo y lo ensombrece (3F · S3 + 3G · W3), y
   * la plataforma siempre puede `purgeRole`. Quien no acepte ese trato deja
   * `maxDescendants` por encima de su subárbol mayor y vigila `truncated`.
   *
   * (Un `scopeType` de nivel `app` muere antes, en `#parseScopedRoleSpec`:
   * la raíz no cuelga de ningún owner. Si llegara aquí sería un ancestro.)
   */
  async #assertLevelUnderOwner(scopeType: ScopeType, chain: ScopeRef[], operation: string): Promise<void> {
    const owner = chain[0]
    if (scopeType === owner.type) return
    const above = chain.slice(1).find((scope) => scope.type === scopeType)
    if (above) {
      throw new RoleLevelAboveOwnerError(
        `${operation}: un rol local de nivel '${scopeType}' está POR ENCIMA de su owner ${owner.type}:${owner.uuid ?? ''} ` +
          `('${scopeType}' es el nivel de ${above.type}:${above.uuid ?? ''}, un ancestro suyo en la cadena). Un rol así no ` +
          `sería visible en ninguna parte: no concedería nada y solo ocuparía ese (slug, nivel) para el resto del árbol y ` +
          `para el catálogo global. Defínelo en el nivel del owner o en uno por debajo.`
      )
    }
    // Lo demás se presume por debajo; con el árbol del consumidor a mano, se comprueba.
    const { below, enumerated } = await this.#descendantsOrDegrade(owner, operation)
    if (!enumerated) return
    if (below.some((scope) => scope.type === scopeType)) return
    const levels = [...new Set(below.map((scope) => scope.type))].sort()
    throw new RoleLevelAboveOwnerError(
      `${operation}: un rol local de nivel '${scopeType}' no cuelga de ${owner.type}:${owner.uuid ?? ''} ` +
        `(bajo él hoy hay ${levels.length ? `niveles ${levels.join(', ')}` : 'ningún scope'}), así que no sería visible en ` +
        `ninguna parte: no concedería nada y solo ocuparía ese (slug, nivel) para el resto del árbol y para el catálogo global. ` +
        `Define el rol en el nivel del owner o en uno que cuelgue de él.`
    )
  }

  /**
   * Solo se toca un rol de rango MENOR que el propio.
   *
   * El mensaje solo nombra el rol cuando el actor tiene ALGO en esa cadena
   * (rank > 0): con rank 0 no tiene ningún rol vigente ahí, así que el rol
   * pertenece a un árbol que no es suyo y decirle su slug y su rank
   * convertía el 422 en una sonda de catálogo ajeno —`scopes.detached` de la
   * unit de otro tenant, sin `within`, enumeraba sus roles locales sin
   * escribir nada (3G · X5, auditor P7)—. Es la misma regla que ya se aplicó
   * a `E_AUTHZ_AMBIGUOUS_ROLE` (3E · Q2): se nombra lo que el llamante ya
   * puede ver, nada más.
   */
  #assertAboveRole(actorRank: number, role: CatalogRole): void {
    if (actorRank > role.rank) return
    if (actorRank === 0) {
      throw new RankExceededError(
        `El actor no tiene ningún rol vigente en la cadena de ese scope (rank 0), así que no puede tocar los roles ` +
          `locales que hay ahí: hace falta rank mayor que el del rol.`
      )
    }
    throw new RankExceededError(
      `El actor (rank ${actorRank} en el owner del rol) no puede tocar '${role.slug}' (rank ${role.rank}): hace falta rank mayor que el del rol.`
    )
  }

  /** El rol por uuid, y LOCAL: un global es inmutable por esta API. */
  #localRoleOrFail(catalog: CatalogView, roleUuid: string): CatalogRole {
    const role = catalog.roleByUuid(roleUuid)
    if (!role) throw new UnknownRoleError(roleUuid)
    if (role.owner === GLOBAL_OWNER_KEY) {
      throw new RoleImmutableError(
        `El rol '${role.slug}@${role.scopeType}' es GLOBAL (catálogo del config): se cambia en el config y se sincroniza; ` +
          `por la API de delegación es inmutable.`
      )
    }
    return role
  }

  /** El scope owner de un rol local (de su clave). Una clave que no es un scope es catálogo corrupto (500). */
  #ownerOf(role: CatalogRole): ScopeRef {
    const owner = scopeFromKey(role.owner)
    if (!owner || owner.type === APP_SCOPE_TYPE) {
      throw new AuthorizationInternalError(`El owner del rol '${role.slug}' (${role.uuid}) no es una clave de scope: '${role.owner}'`)
    }
    return owner
  }

  /**
   * La colisión se decide por AUTORIDAD (3F · S3, auditor N1): *una
   * definición más autorizada gana y ensombrece a la menos autorizada* —
   * global > local de un ancestro > local de un descendiente—, que es la
   * regla que 3E ya tomó para los globales frente a los locales.
   *
   *  - Un homónimo GLOBAL, o local a un ancestro-o-igual del owner, es 422
   *    `E_AUTHZ_CATALOG_CONFLICT`: hacia ARRIBA no se ensombrece a nadie.
   *  - Un homónimo local a un DESCENDIENTE del owner ya NO colisiona: el
   *    nuevo se crea —si el actor SUPERA EN RANGO al que va a ensombrecer
   *    (3G · W3, `#assertAboveShadowed`: la autoridad no es solo posición)—
   *    y el del descendiente queda ENSOMBRECIDO (se devuelve para el evento
   *    `role_defined` y el diff lo lista como `shadowedByAncestor`). Hasta 3E era 422, y con eso el actor de menor
   *    privilegio del sistema le ocupaba el nombre al DUEÑO del árbol —para
   *    siempre, salvo purga rol a rol— y dejaba `authz:catalog:diff` en rojo,
   *    que es el gate de CI del deploy. Ahora la mina solo se ensombrece a sí
   *    misma: dentro de SU subárbol el slug pasa a 422 `E_AUTHZ_AMBIGUOUS_ROLE`
   *    (M1, fail-closed) y se opera por `{ uuid }`, exactamente como con un
   *    global. No concede nada de más: el hecho apunta al uuid del rol.
   *
   * Los owners de los homónimos se resuelven en fresco; uno que el árbol ya
   * no conoce no colisiona ni se ensombrece (no es visible en ningún sitio).
   *
   * `others` son los homónimos a contrastar: la foto del memo en el chequeo
   * BARATO (antes de abrir la transacción, para no pagar una transacción por
   * una colisión evidente) y las filas leídas de la BASE dentro de la
   * transacción serializada (3D · M2), que es el que manda. Con solo el
   * primero, dos `define` en paralelo —o un `define` contra un `sync`—
   * insertaban los dos homónimos y el estado era permanente (auditor V2).
   * En modo `sin-árbol` (dentro de la transacción, con el cerrojo sostenido)
   * no se resuelve ninguna cadena: el llamante rechaza igual lo que no puede
   * juzgar y pide reintentar.
   */
  async #assertNoRoleCollision(
    slug: string,
    scopeType: ScopeType,
    owner: ScopeRef,
    ownerChain: ScopeRef[],
    others: ReadonlyArray<{ owner: string }>,
    mode: 'con-árbol' | 'sin-árbol' = 'con-árbol'
  ): Promise<CatalogRole[]> {
    const ownerKey = scopeKey(owner)
    const ancestors = new Set(ownerChain.map(scopeKey))
    // Lo que se juzga SIN tocar el árbol, primero: un 422 evidente no paga
    // un `resolveChain` por homónimo.
    for (const other of others) {
      let where: string | null = null
      if (other.owner === GLOBAL_OWNER_KEY) where = 'global (catálogo del config)'
      else if (ancestors.has(other.owner)) where = other.owner === ownerKey ? 'este mismo scope' : `un ancestro (${other.owner})`
      if (where) {
        throw new CatalogConflictError(
          `Ya existe un rol '${slug}' de nivel '${scopeType}' visible desde ${owner.type}:${owner.uuid ?? ''}: es ${where}. ` +
            `Dentro de un scope un (slug, nivel) identifica un solo rol; elige otro slug.`
        )
      }
    }
    if (mode === 'sin-árbol') return []
    return this.#shadowedBelow(ownerKey, ancestors, others, 'defineScopedRole')
  }

  /**
   * Los homónimos LOCALES a un DESCENDIENTE del owner: los que una
   * definición en `ownerKey` ENSOMBRECE (3F · S3). Los owners se resuelven
   * en fresco; uno que el árbol ya no conoce no ensombrece a nadie (no es
   * visible en ninguna parte). Lo usan `defineScopedRole` (la colisión) y
   * `updateScopedRole` (que no crea sombras nuevas, pero tampoco deja tocar
   * un rol que ya ensombrece a otro de más rango — 3G · W3).
   */
  async #shadowedBelow(
    ownerKey: string,
    ancestors: ReadonlySet<string>,
    others: ReadonlyArray<{ owner: string }>,
    operation: string
  ): Promise<CatalogRole[]> {
    const shadowed: CatalogRole[] = []
    for (const other of others) {
      if (other.owner === GLOBAL_OWNER_KEY || ancestors.has(other.owner)) continue
      if (!('uuid' in other) || !('rank' in other)) continue
      const otherOwner = scopeFromKey(other.owner)
      const chain = otherOwner ? await resolveChain(this.#freshResolver(), otherOwner, operation) : null
      if (chain && chain.some((s) => scopeKey(s) === ownerKey)) shadowed.push(other as CatalogRole)
    }
    return shadowed
  }

  /**
   * Sobre un rol solo actúa quien lo SUPERA EN RANGO — también para
   * ensombrecerlo (3G · W3, auditor P3′). Ensombrecer es tan destructivo
   * como borrar: dentro del subárbol del ensombrecido toda ruta por slug
   * pasa a 422 `E_AUTHZ_AMBIGUOUS_ROLE` para TODOS, y la víctima no puede
   * repararlo (su rango se mide en la cadena del owner del rol que
   * ensombrece, donde no vale nada). Hasta 3F la autoridad era solo POSICIÓN
   * y un actor de rank 3 en la organization inutilizaba por slug un rol de
   * rank 40 de una unit, en toda su cadena y para siempre.
   *
   * El mensaje NO nombra el rank ni el owner del ensombrecido: un ancestro
   * no ve los roles de sus descendientes (la visibilidad solo baja), así que
   * el 422 no puede ser una sonda del catálogo de abajo (misma regla que
   * `E_AUTHZ_AMBIGUOUS_ROLE`, 3E · Q2).
   */
  #assertAboveShadowed(actorRank: number, shadowed: readonly CatalogRole[], operation: string): void {
    for (const role of shadowed) {
      if (actorRank > role.rank) continue
      throw new RankExceededError(
        `${operation}: por debajo de este owner ya hay un rol local '${role.slug}' de nivel '${role.scopeType}' con rank ` +
          `MAYOR O IGUAL al tuyo (tu rank aquí es ${actorRank}). Definir el tuyo lo ensombrecería —dentro de su subárbol ` +
          `ese slug pasaría a ser ambiguo para todos y su dueño no podría repararlo—, y sobre un rol solo actúa quien lo ` +
          `supera en rango, igual que en deleteScopedRole. Elige otro slug.`
      )
    }
  }

  /**
   * LA escritura del catálogo por el manager: `withAuthzCatalogWrite` (la
   * versión compartida sube como última sentencia, dentro) y, al salir
   * —bien o mal—, se invalidan los memos de este proceso (como el sync). Con
   * `skipIfNoop`, un `fn` que devuelve `false` no ha escrito nada y la
   * versión no se toca (se revierte la transacción vacía).
   */
  async #writeCatalog<T>(fn: (trx: any) => Promise<T>, options: { skipIfNoop?: boolean } = {}): Promise<T> {
    const noop = Symbol('noop')
    try {
      return await withAuthzCatalogWrite(
        async (trx) => {
          const result = await fn(trx)
          if (options.skipIfNoop && result === false) throw noop
          return result
        },
        { driver: this.#config.default }
      )
    } catch (error) {
      if (error === noop) return false as T
      throw error
    } finally {
      invalidateAuthzCatalog()
    }
  }

  async #notifyCatalog(event: AuthzCatalogWriteEvent): Promise<void> {
    try {
      await this.#config.hooks?.onCatalogWrite?.(event)
    } catch (error) {
      const context = `authz: el hook onCatalogWrite falló tras '${event.action}' (la escritura sí se aplicó)`
      try {
        const { default: logger } = await import('@adonisjs/core/services/logger')
        logger.error({ err: error, event }, context)
      } catch {
        console.error(context, error)
      }
    }
  }

  /**
   * Asigna un rol al holder en un scope. `role` es un `RoleQuery` (3D · M1):
   * un slug, `{ slug, scopeType }` o `{ uuid }` — esta última es la forma
   * exacta, la única que responde cuando dos roles locales homónimos son
   * visibles en la misma cadena (las otras dos son 422
   * `E_AUTHZ_AMBIGUOUS_ROLE`, nunca «el más cercano gana»).
   */
  async grant(
    subject: SubjectRef,
    role: RoleQuery,
    scope: ScopeRef,
    options?: GrantOptions
  ): Promise<GrantOutcome> {
    const actor = this.#writeOptions(options, 'grant')
    assertIdentity({ subject, role, scope, expiresAt: options?.expiresAt })
    await this.#assertWithin(scope, options, 'grant')
    // 3E · Q7: el evento lleva el rol RESUELTO (uuid + slug + nivel + owner),
    // no la pregunta cruda. Solo se resuelve si hay hook que lo vaya a leer.
    const roles = await this.#resolvedRoles(role, scope, 'grant')
    const outcome: GrantOutcome =
      (await this.#write(
        { action: 'granted', subject, scope, roles, expiresAt: options?.expiresAt ?? null, ...actor },
        async () => (await this.driver()).grant(subject, role, scope, options)
      )) ??
      // Un driver de terceros que aún devuelva `void`: la firma promete un
      // `GrantOutcome` y no miente (E1). Sin lectura previa no hay caducidad
      // anterior que contar: es lo que pidió el llamante, y `existed: false`.
      { existed: false, expiresAt: options?.expiresAt ?? null }
    // Un re-grant que cambia la caducidad de una asignación existente es un
    // evento distinto (L0.4): quien audita necesita ver de cuál a cuál.
    if (expiryChanged(outcome)) {
      await this.#notify({
        action: 'extended',
        subject,
        scope,
        roles,
        expiresAt: outcome.expiresAt,
        previousExpiresAt: outcome.previousExpiresAt,
        ...actor,
      })
    } else {
      await this.#notify({
        action: 'granted',
        subject,
        scope,
        roles,
        expiresAt: outcome.expiresAt,
        ...actor,
      })
    }
    return outcome
  }

  /**
   * Quita la asignación del rol en ese scope exacto. Por slug se quitan las
   * de TODOS los homónimos `(slug, nivel)` (3B; quitar nunca concede, y el
   * scope puede no existir ya para el árbol); por `{ uuid }`, solo la de ese
   * rol.
   */
  async revoke(subject: SubjectRef, role: RoleQuery, scope: ScopeRef, options?: ScopedWriteOptions): Promise<void> {
    const actor = this.#writeOptions(options, 'revoke')
    assertIdentity({ subject, role, scope })
    await this.#assertWithin(scope, options, 'revoke')
    const event: AuthzWriteEvent = { action: 'revoked', subject, scope, roles: await this.#resolvedRoles(role, scope, 'revoke'), ...actor }
    await this.#write(event, async () => (await this.driver()).revoke(subject, role, scope))
    await this.#notify(event)
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef, options?: DenyOptions): Promise<void> {
    const actor = this.#writeOptions(options, 'deny')
    assertIdentity({ subject, permission, scope })
    await this.#assertWithin(scope, options, 'deny')
    const event: AuthzWriteEvent = { action: 'denied', subject, scope, permission, ...actor }
    await this.#write(event, async () => (await this.driver()).deny(subject, permission, scope))
    await this.#notify(event)
  }

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef, options?: ScopedWriteOptions): Promise<void> {
    const actor = this.#writeOptions(options, 'removeDeny')
    assertIdentity({ subject, permission, scope })
    await this.#assertWithin(scope, options, 'removeDeny')
    const event: AuthzWriteEvent = { action: 'deny_removed', subject, scope, permission, ...actor }
    await this.#write(event, async () => (await this.driver()).removeDeny(subject, permission, scope))
    await this.#notify(event)
  }

  /**
   * Scopes de un tipo donde el holder tiene el permiso (2.1, B3). La ÚNICA
   * API del paquete que enumera descendientes — excepción explícita al
   * invariante 7 (`list*` siguen siendo directos) — y lo hace con el
   * `descendantsOf` del consumidor, nunca con N+1 `resolveChain` a ciegas.
   *
   * Regla:
   *  1. `listScopes(subject, permission)`: los scopes DIRECTOS que conceden,
   *     ya sin los bloqueados por un deny en su cadena y sin los que el árbol
   *     no conoce. Vacío ⇒ `none`.
   *  2. Si la raíz está entre ellos ⇒ `all`, con `excludedSubtrees` = todos
   *     los scopes con deny vivo del permiso (`listDenies`), como subárboles
   *     (F10). Nunca `all` sin esa lista (juez cruce 5): un deny vivo tiene
   *     que verse.
   *  3. Si no: candidatos = directos ∪ sus descendientes (`descendantsOf`).
   *     Cada candidato se contrasta con `resolveChain` (memoizado por
   *     request, F3): su cadena tiene que contener el scope concedente —si
   *     no, los dos resolutores del consumidor describen árboles distintos y
   *     se lanza 503 `E_AUTHZ_RESOLVER_FAILED`, nunca una lista con cruces—
   *     y no puede contener un scope denegado (es EXACTAMENTE la regla de
   *     `authorize`: deny en la cadena ⇒ false). Se filtran por `scopeType`.
   *  4. Más de `maxScopes` ⇒ 422 `E_AUTHZ_TOO_MANY_SCOPES`, nunca parcial, y
   *     se corta en cuanto se sabe (F8): los directos del tipo antes de bajar
   *     y el conteo del tipo dentro del bucle. `options.maxScopes` solo puede
   *     BAJAR la cota del config.
   * Sin `scopes.descendantsOf` ⇒ 500 `E_AUTHZ_NO_DESCENDANTS_RESOLVER`
   * (antes de mirar nada: un `none` sin árbol sería mentira).
   */
  async authorizedScopes(
    subject: SubjectRef,
    permission: string,
    scopeType: ScopeType,
    options: { maxScopes?: number } = {}
  ): Promise<AuthorizedScopes> {
    assertIdentity({ subject, permission, scopeType })
    const descendantsOf = this.#descendantsResolver('authorizedScopes')
    const { maxScopes, maxNodes } = this.#scopeBounds('authorizedScopes', options)
    // Una vista propia para la llamada: los scopes que se resuelvan se
    // resuelven una vez.
    const view = this.#readResolver ? this : (this.forRequest() as AuthorizationManager)
    const driver = await view.#reader()
    const listDenies = this.#optional(driver, 'listDenies', 'authorizedScopes')
    const key = AuthorizationManager.#scopeKey

    const direct = await driver.listScopes(subject, permission)
    if (direct.length === 0) return { kind: 'none' }
    const denied = (await listDenies(subject)).filter((d) => d.permission === permission).map((d) => d.scope)

    if (direct.some((s) => s.type === APP_SCOPE_TYPE)) {
      if (denied.length > maxScopes) {
        throw new TooManyScopesError(
          `authorizedScopes: ${denied.length} subárboles excluidos superan maxScopes=${maxScopes}; no se devuelve una lista parcial.`
        )
      }
      return { kind: 'all', excludedSubtrees: denied.map((scope) => ({ scope, includesDescendants: true })) }
    }

    const tooMany = (count: number) =>
      new TooManyScopesError(
        `authorizedScopes: más de ${maxScopes} scopes de tipo '${scopeType}' (${count} ya contados, maxScopes); ` +
          `acota la pregunta o sube la cota. No se devuelve una lista parcial.`
      )
    const deniedKeys = new Set(denied.map(key))
    const result = new Map<string, ScopeRef>()
    // Los directos del tipo (ya sin denies por encima: `listScopes`) cuentan
    // antes de bajar a ningún subárbol (F8).
    for (const granted of direct) {
      if (granted.type === scopeType) result.set(key(granted), granted)
    }
    if (result.size > maxScopes) throw tooMany(result.size)

    const resolver = view.#readResolverOrFresh()
    for (const granted of direct) {
      const grantedKey = key(granted)
      for (const candidate of await view.#descendants(descendantsOf, granted, maxNodes)) {
        const candidateKey = key(candidate)
        if (result.has(candidateKey)) continue
        // Pertenencia (F3): la cadena del candidato, según `resolveChain`,
        // tiene que pasar por el scope concedente. Si no (o si el árbol de
        // ancestros no lo conoce), los dos resolutores discrepan: 503.
        const chain = await resolveChain(resolver, candidate, 'authorizedScopes')
        if (!chain || !chain.some((s) => key(s) === grantedKey)) {
          throw new ScopeResolverError(
            'authorizedScopes',
            new Error(
              `descendantsOf(${grantedKey.replace('\u001f', ':')}) devolvió ${candidateKey.replace('\u001f', ':')} pero ` +
                `resolveChain no lo cuelga de ahí: los dos resolutores describen árboles distintos y no se puede responder.`
            )
          )
        }
        // Deny en la cadena ⇒ no concede, como en `authorize`.
        if (chain.some((s) => deniedKeys.has(key(s)))) continue
        if (candidate.type !== scopeType) continue
        result.set(candidateKey, candidate)
        if (result.size > maxScopes) throw tooMany(result.size)
      }
    }
    const scopes = [...result.values()]
    return scopes.length ? { kind: 'some', scopes } : { kind: 'none' }
  }

  /**
   * Los `excludedSubtrees` de un `all` (F10) expandidos: cada scope denegado
   * y todos sus descendientes, con el `descendantsOf` del config. Un scope
   * que `descendantsOf` no conoce (`null`) es 503: restarlo a medias
   * dejaría su subárbol dentro (fail-open). Cotas: `maxDescendants` por
   * subárbol y `maxScopes` (config o por llamada, nunca por encima del
   * config) sobre el total ⇒ 422, nunca parcial.
   */
  async expandExcludedSubtrees(
    excluded: ExcludedSubtree[],
    options: { maxScopes?: number } = {}
  ): Promise<ScopeRef[]> {
    if (!Array.isArray(excluded)) {
      throw new InvalidIdentityError(`expandExcludedSubtrees: se esperaba un array y llegó ${typeof excluded}`)
    }
    for (const item of excluded) assertScope(item?.scope)
    // Es una lectura de la vista como las demás (I2, auditor 10): caduca con ella.
    this.#assertReadable()
    const descendantsOf = this.#descendantsResolver('expandExcludedSubtrees')
    const { maxScopes, maxNodes } = this.#scopeBounds('expandExcludedSubtrees', options)
    const key = AuthorizationManager.#scopeKey
    const result = new Map<string, ScopeRef>()
    for (const { scope } of excluded) {
      result.set(key(scope), scope)
      const below = await this.#descendants(descendantsOf, scope, maxNodes, 'strict')
      for (const d of below) result.set(key(d), d)
      if (result.size > maxScopes) {
        throw new TooManyScopesError(
          `expandExcludedSubtrees: más de ${maxScopes} scopes excluidos (maxScopes); no se devuelve una lista parcial.`
        )
      }
    }
    return [...result.values()]
  }

  /**
   * Clave LAXA de un scope, solo para agrupar/deduplicar candidatos dentro
   * de una operación (`authorizedScopes`, el anti-ciclo de `#assertEdge`).
   * NO es `scopeKey` de `identity.ts` —esa valida la gramática y es la que
   * identifica hechos, owners e ids de binding, y es la que usa
   * `#rolesAlong` (3D · N5)—: aquí los scopes vienen del `descendantsOf` del
   * consumidor y no se les exige gramática para compararlos entre sí.
   */
  static #scopeKey(s: ScopeRef): string {
    return `${s.type}\u001f${s.uuid ?? ''}`
  }

  #descendantsResolver(operation: string): ScopeDescendantsResolver {
    const descendantsOf = this.#config.scopes?.descendantsOf
    if (!descendantsOf) {
      throw new NoDescendantsResolverError(
        `${operation} necesita 'scopes.descendantsOf' en config/authorization.ts (p. ej. sqlDescendantsOf(...)): ` +
          `sin el árbol de descendientes no se puede enumerar sin mentir.`
      )
    }
    return descendantsOf
  }

  /**
   * Cotas de una enumeración: `maxScopes` del config (default 1000), que
   * una llamada solo puede BAJAR (F8: subirla por llamada era una escalada
   * silenciosa de la cota global), y `maxDescendants` del config.
   */
  #scopeBounds(operation: string, options: { maxScopes?: number }): { maxScopes: number; maxNodes: number } {
    const configured = this.#config.scopes?.maxScopes ?? DEFAULT_MAX_SCOPES
    const maxNodes = this.#config.scopes?.maxDescendants ?? DEFAULT_MAX_DESCENDANTS
    for (const [name, value] of [
      ['maxScopes', configured],
      ['maxDescendants', maxNodes],
      ['maxScopes (por llamada)', options.maxScopes ?? configured],
    ] as const) {
      if (!Number.isInteger(value) || value < 1 || value > MAX_SCOPE_BOUND) {
        throw new AuthorizationConfigError(
          `${operation}: ${name} debe ser un entero entre 1 y ${MAX_SCOPE_BOUND} (llegó ${String(value)})`
        )
      }
    }
    return { maxScopes: Math.min(options.maxScopes ?? configured, configured), maxNodes }
  }

  /**
   * El subárbol del consumidor para las dos piezas que lo caminan por
   * SEGURIDAD y no por enumeración —`scopes.detached` y la regla de nivel de
   * `defineScopedRole`/`updateScopedRole`—, DEGRADANDO en vez de tumbar la
   * operación (3F · S2, auditor N3).
   *
   * Regla: *declarar `scopes.descendantsOf` nunca puede dejarte peor que no
   * declararlo*. Hasta 3E, una org con más units que `maxDescendants` —la
   * cota sale del config y una llamada no la puede subir (F8)— dejaba el
   * `detached` entero en 503 **sin purgar ni los roles ni los hechos** y al
   * tenant grande sin poder delegar hacia abajo: la configuración que el
   * invariante 18 recomienda EMPEORABA el caso grande. Ahora, si el subárbol
   * no se puede enumerar (más nodos que la cota, o un `descendantsOf` que
   * falla), se sigue con `enumerated: false`: la purga se acota al scope
   * exacto —lo mismo que sin declararlo, y el resultado lo dice con
   * `truncated`— y la regla de nivel cae a la MÍNIMA (rechazar solo los
   * tipos de un ancestro). Ninguna de las dos degradaciones concede nada:
   * purgar menos deja roles que ya no son visibles en ninguna parte, y la
   * regla mínima es la que corre en todo consumidor con el stub publicado.
   * Pero no es gratis y está escrito donde toca (3G · X1, auditor P4): es un
   * control que el propio vigilado puede apagar creando hijos. Lo que NO
   * degrada nunca es la policy de RANGO: con `below = []` sigue corriendo
   * sobre los roles del scope exacto (3G · X2), y ensombrecer sigue pidiendo
   * rango aunque la regla de nivel haya caído a la mínima (3G · W3).
   *
   * Lo que NO se degrada es un error de CONFIG (`maxDescendants` fuera de
   * rango): eso es un bug del consumidor y sigue siendo 500.
   */
  async #descendantsOrDegrade(
    scope: ScopeRef,
    operation: string
  ): Promise<{ below: ScopeRef[]; declared: boolean; enumerated: boolean }> {
    const descendantsOf = this.#config.scopes?.descendantsOf
    if (!descendantsOf) return { below: [], declared: false, enumerated: false }
    const { maxNodes } = this.#scopeBounds(operation, {})
    try {
      return { below: await this.#descendants(descendantsOf, scope, maxNodes), declared: true, enumerated: true }
    } catch (error) {
      if (error instanceof TooManyScopesError || error instanceof ScopeResolverError) {
        return { below: [], declared: true, enumerated: false }
      }
      throw error
    }
  }

  /**
   * `descendantsOf` del consumidor, clasificado como `resolveChain` clasifica
   * `resolveChain`: lanza ⇒ 503 `E_AUTHZ_RESOLVER_FAILED`; no-array o
   * scope mal formado ⇒ 503; más de `maxNodes` ⇒ 422 `E_AUTHZ_TOO_MANY_SCOPES`;
   * `null` (desconocido para ese árbol) ⇒ nada debajo para un scope
   * CONCEDENTE (conservador: no se lista lo que no se puede enumerar) y 503
   * en modo `strict` (un subárbol EXCLUIDO que no se puede enumerar no se
   * puede restar: fail-open, F3/F10).
   */
  async #descendants(
    descendantsOf: ScopeDescendantsResolver,
    scope: ScopeRef,
    maxNodes: number,
    unknown: 'empty' | 'strict' = 'empty'
  ): Promise<ScopeRef[]> {
    let result: ScopeRef[] | null
    try {
      result = await descendantsOf(scope, { maxNodes })
    } catch (error) {
      if (isAuthzError(error)) throw error
      throw new ScopeResolverError('descendantsOf', error)
    }
    if (result === null || result === undefined) {
      if (unknown === 'strict') {
        throw new ScopeResolverError(
          'descendantsOf',
          new Error(`descendantsOf no conoce ${scope.type}:${scope.uuid ?? ''}: su subárbol no se puede restar.`)
        )
      }
      return []
    }
    if (!Array.isArray(result)) {
      throw new ScopeResolverError(
        'descendantsOf',
        new TypeError(`descendantsOf devolvió ${typeof result} en vez de ScopeRef[] | null`)
      )
    }
    for (const s of result) {
      try {
        assertScope(s)
      } catch (error) {
        throw new ScopeResolverError('descendantsOf', error)
      }
    }
    if (result.length > maxNodes) {
      throw new TooManyScopesError(
        `descendantsOf(${scope.type}:${scope.uuid ?? ''}) devolvió ${result.length} nodos, más que maxDescendants=${maxNodes}.`
      )
    }
    return result
  }

  /**
   * Ejecuta una escritura del driver. Si vence el deadline (503
   * `E_AUTHZ_BACKEND_TIMEOUT`) el resultado es DESCONOCIDO: el SDK o el
   * servidor pueden aplicarla después de que el llamante reciba el error
   * (D2, auditor H1). Antes de propagar se notifica el mismo evento con
   * `indeterminate: true`, para que quien audita registre "puede haber
   * ocurrido" en vez de nada. Cualquier otro fallo (422, conexión rechazada)
   * significa que la escritura no ocurrió y se propaga sin evento.
   */
  async #write<T>(event: AuthzWriteEvent, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn()
    } catch (error) {
      if (error instanceof AuthorizationBackendTimeoutError) {
        await this.#notify({ ...event, indeterminate: true })
      }
      throw error
    }
  }

  /**
   * Notifica al consumidor. El hook es un side-effect (auditar, emitir un
   * evento): cuando falla, la escritura YA está aplicada, así que propagar su
   * error le daría al llamante un fallo por una operación que sí ocurrió —
   * y le invitaría a reintentar algo ya hecho. Se registra y se sigue.
   *
   * El contrato ("el hook no debe lanzar") pasa así de comentario a garantía.
   */
  async #notify(event: AuthzWriteEvent): Promise<void> {
    try {
      await this.#config.hooks?.onWrite?.(event)
    } catch (error) {
      await this.#logHookFailure(event, error)
    }
  }

  async #logHookFailure(event: AuthzWriteEvent, error: unknown): Promise<void> {
    const context = `authz: el hook onWrite falló tras '${event.action}' (la escritura sí se aplicó)`
    try {
      const { default: logger } = await import('@adonisjs/core/services/logger')
      logger.error({ err: error, event }, context)
    } catch {
      // Fuera de una app booteada (tests, scripts sueltos) no hay logger.
      console.error(context, error)
    }
  }
}
