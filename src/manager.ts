import { Exception } from '@adonisjs/core/exceptions'
import type { AuthorizationConfig } from './define_config.js'
import { assertIdentity, assertScope, assertSubject } from './identity.js'
import { expiryChanged } from './expiry.js'
import { assertKnownScope, isAuthzError, resolveChain, rootOnlyResolver } from './drivers/backend_guard.js'
import { CatalogCache } from './catalog_cache.js'
import {
  ActorRequiredError,
  AuthorizationBackendTimeoutError,
  AuthorizationConfigError,
  AuthorizationInternalError,
  InvalidIdentityError,
  NoDescendantsResolverError,
  NotWithinError,
  ScopeCycleError,
  ScopeResolverError,
  TooManyScopesError,
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
  AuthzWriteEvent,
  DenyOptions,
  DenyRef,
  ExcludedSubtree,
  GrantOptions,
  GrantOutcome,
  RoleQuery,
  ScopeAncestorsResolver,
  ScopeDescendantsResolver,
  ScopedWriteOptions,
  ScopeRef,
  ScopeType,
  SubjectRef,
  WriteOptions,
} from './types.js'

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
/** Vida por defecto de una vista de `forRequest()` para LEER (F9): un request, no un módulo. */
export const DEFAULT_VIEW_MAX_AGE_MS = 30_000

export interface ForRequestOptions {
  /**
   * Milisegundos durante los que la vista puede LEER (default 30 000).
   * Después, cualquier lectura es 500 `E_AUTHZ_VIEW_EXPIRED`: el memo de
   * ancestros solo es correcto mientras dura el request y una vista guardada
   * por error serviría la cadena vieja para siempre. `0` = sin límite, a
   * sabiendas. Las escrituras e `isWithin` no caducan (resuelven en fresco).
   */
  maxAgeMs?: number
}

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
  #readResolver: ScopeAncestorsResolver | null = null
  #readDriver: AuthorizationDriver | null = null
  /** Memo del catálogo propio, solo si el driver no expone el suyo (composición sin puerto). */
  #ownCatalog: CatalogCache | null = null
  /** Instante (`Date.now()`) a partir del cual esta vista ya no puede leer; `null` = sin límite / no es vista. */
  #readsUntil: number | null = null

  constructor(config: AuthorizationConfig) {
    this.#config = config
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
   * resuelven ancestros con `memoizeAncestors(config.scopes.resolveAncestors)`
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
   * `config.scopes.resolveAncestors`, o con un driver de terceros sin
   * `withAncestorsResolver`, la vista lee con el driver tal cual (sin memo)
   * y sigue siendo correcta.
   */
  forRequest(options: ForRequestOptions = {}): AuthorizationView {
    const maxAgeMs = options.maxAgeMs ?? DEFAULT_VIEW_MAX_AGE_MS
    if (!Number.isInteger(maxAgeMs) || maxAgeMs < 0) {
      throw new AuthorizationConfigError(
        `forRequest: maxAgeMs debe ser un entero >= 0 (0 = sin límite; llegó ${String(maxAgeMs)})`
      )
    }
    const view = new AuthorizationManager(this.#config)
    view.#parent = this.#parent ?? this
    const resolver = this.#config.scopes?.resolveAncestors
    view.#readResolver = resolver ? memoizeAncestors(resolver) : null
    view.#readsUntil = maxAgeMs === 0 ? null : Date.now() + maxAgeMs
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
    const driver = await factory()
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
  async #reader(): Promise<AuthorizationDriver> {
    // Una vista caducada no lee (F9): su memo de ancestros puede describir
    // un árbol que ya cambió. Ruidoso a propósito.
    if (this.#readsUntil !== null && Date.now() >= this.#readsUntil) {
      throw new ViewExpiredError(
        `La vista de forRequest() superó su maxAgeMs y ya no puede leer: su memo de ancestros puede estar obsoleto. ` +
          `Crea la vista por request (un middleware) o pasa forRequest({ maxAgeMs: 0 }) a sabiendas.`
      )
    }
    const driver = await this.driver()
    if (!this.#readResolver) return driver
    if (this.#readDriver) return this.#readDriver
    this.#readDriver = driver.withAncestorsResolver?.(this.#readResolver) ?? driver
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
    // `within` (2D · F2) se contrasta con el PADRE: colgar o mover algo bajo
    // un scope es escribir en ese scope.
    attached: async (child: ScopeRef, parent: ScopeRef, options?: ScopedWriteOptions): Promise<void> => {
      this.#writeOptions(options, 'scopes.attached')
      const chain = await this.#assertEdge(child, parent, 'scopes.attached')
      this.#assertWithinChain(parent, chain, options, 'scopes.attached')
      await (await this.driver()).onScopeAttached?.(child, parent)
    },
    moved: async (child: ScopeRef, newParent: ScopeRef, options?: ScopedWriteOptions): Promise<void> => {
      this.#writeOptions(options, 'scopes.moved')
      const chain = await this.#assertEdge(child, newParent, 'scopes.moved')
      this.#assertWithinChain(newParent, chain, options, 'scopes.moved')
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
    detached: async (child: ScopeRef, options?: ScopedWriteOptions): Promise<void> => {
      const actor = this.#writeOptions(options, 'scopes.detached')
      this.#resolver('scopes.detached')
      assertScope(child)
      if (child.type === APP_SCOPE_TYPE) {
        throw new InvalidIdentityError('scopes.detached: la raíz `app` no se puede borrar ni purgar')
      }
      await this.#assertWithin(child, options, 'scopes.detached')
      const driver = await this.driver()
      const event: AuthzWriteEvent = { action: 'scope_purged', scope: child, ...actor }
      await this.#write(event, () => driver.purgeScope(child))
      await driver.onScopeDetached?.(child)
      await this.#notify(event)
    },
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
  #readResolverOrFresh(): ScopeAncestorsResolver {
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
    primitive: string
  ): NonNullable<AuthorizationDriver[K]> {
    const fn = driver[method]
    if (typeof fn !== 'function') {
      throw new UnsupportedOperationError(method, primitive, this.#config.default)
    }
    return fn.bind(driver) as NonNullable<AuthorizationDriver[K]>
  }

  /** El resolutor FRESCO del config (o solo-raíz): el de las escrituras y de `isWithin`. */
  #freshResolver(): ScopeAncestorsResolver {
    return this.#config.scopes?.resolveAncestors ?? rootOnlyResolver
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

  #resolver(operation: string): ScopeAncestorsResolver {
    const resolver = this.#config.scopes?.resolveAncestors
    if (!resolver) {
      throw new AuthorizationConfigError(
        `${operation} necesita 'scopes.resolveAncestors' en config/authorization.ts: ` +
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
    const childKey = `${child.type}:${child.uuid}`
    if (chain.some((s) => `${s.type}:${s.uuid}` === childKey)) {
      throw new ScopeCycleError(
        `${operation}: ${parent.type}:${parent.uuid} desciende de ${childKey} (o es él mismo); ` +
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

  async listSubjects(role: string, scope: ScopeRef): Promise<SubjectRef[]> {
    assertIdentity({ roleSlug: role, scope })
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
    const listDenies = this.#optional(driver, 'listDenies', 'effectivePermissions')
    const chain = await resolveChain(this.#readResolverOrFresh(), scope, 'effectivePermissions')
    if (!chain) return []
    const catalog = await this.#catalogFor(driver).view()
    const key = AuthorizationManager.#scopeKey
    const chainKeys = new Set(chain.map(key))
    // Roles de toda la cadena en UNA lectura (`rolesInChain`, G5) o, sin el
    // método opcional, N `listRoles` (misma respuesta).
    const roles: Array<{ scope: ScopeRef; role: string }> =
      typeof driver.rolesInChain === 'function'
        ? await driver.rolesInChain(subject, chain)
        : (
            await Promise.all(
              chain.map(async (level) => (await driver.listRoles(subject, level)).map((role) => ({ scope: level, role })))
            )
          ).flat()
    const granted = new Set<string>()
    for (const { scope: level, role } of roles) {
      if (!chainKeys.has(key(level))) continue
      for (const permission of catalog.rolePermissions(role, level.type)) granted.add(permission)
    }
    // Denies del sujeto en UNA lectura, quedándose con los de la cadena.
    const denied = new Set<string>()
    for (const deny of await listDenies(subject)) {
      if (chainKeys.has(key(deny.scope))) denied.add(deny.permission)
    }
    return [...granted].filter((permission) => !denied.has(permission))
  }

  async grant(
    subject: SubjectRef,
    role: string,
    scope: ScopeRef,
    options?: GrantOptions
  ): Promise<GrantOutcome> {
    const actor = this.#writeOptions(options, 'grant')
    assertIdentity({ subject, roleSlug: role, scope, expiresAt: options?.expiresAt })
    await this.#assertWithin(scope, options, 'grant')
    const outcome: GrantOutcome =
      (await this.#write(
        { action: 'granted', subject, scope, role, expiresAt: options?.expiresAt ?? null, ...actor },
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
        role,
        expiresAt: outcome.expiresAt,
        previousExpiresAt: outcome.previousExpiresAt,
        ...actor,
      })
    } else {
      await this.#notify({
        action: 'granted',
        subject,
        scope,
        role,
        expiresAt: outcome.expiresAt,
        ...actor,
      })
    }
    return outcome
  }

  async revoke(subject: SubjectRef, role: string, scope: ScopeRef, options?: ScopedWriteOptions): Promise<void> {
    const actor = this.#writeOptions(options, 'revoke')
    assertIdentity({ subject, roleSlug: role, scope })
    await this.#assertWithin(scope, options, 'revoke')
    const event: AuthzWriteEvent = { action: 'revoked', subject, scope, role, ...actor }
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
   * `descendantsOf` del consumidor, nunca con N+1 `resolveAncestors` a ciegas.
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
   *     Cada candidato se contrasta con `resolveAncestors` (memoizado por
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
        // Pertenencia (F3): la cadena del candidato, según `resolveAncestors`,
        // tiene que pasar por el scope concedente. Si no (o si el árbol de
        // ancestros no lo conoce), los dos resolutores discrepan: 503.
        const chain = await resolveChain(resolver, candidate, 'authorizedScopes')
        if (!chain || !chain.some((s) => key(s) === grantedKey)) {
          throw new ScopeResolverError(
            'authorizedScopes',
            new Error(
              `descendantsOf(${grantedKey.replace('\u001f', ':')}) devolvió ${candidateKey.replace('\u001f', ':')} pero ` +
                `resolveAncestors no lo cuelga de ahí: los dos resolutores describen árboles distintos y no se puede responder.`
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
      if (!Number.isInteger(value) || value < 1) {
        throw new AuthorizationConfigError(`${operation}: ${name} debe ser un entero >= 1 (llegó ${String(value)})`)
      }
    }
    return { maxScopes: Math.min(options.maxScopes ?? configured, configured), maxNodes }
  }

  /**
   * `descendantsOf` del consumidor, clasificado como `resolveChain` clasifica
   * `resolveAncestors`: lanza ⇒ 503 `E_AUTHZ_RESOLVER_FAILED`; no-array o
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
