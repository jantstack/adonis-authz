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
  InvalidIdentityError,
  NoDescendantsResolverError,
  NotWithinError,
  ScopeCycleError,
  ScopeResolverError,
  TooManyScopesError,
  UnsupportedOperationError,
  WithinRequiredError,
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
>

/** Cotas por defecto de `authorizedScopes` (config `scopes.maxScopes` / `scopes.maxDescendants`). */
export const DEFAULT_MAX_SCOPES = 1_000
export const DEFAULT_MAX_DESCENDANTS = 10_000

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
    const missing = (['requireWithin', 'requireActor'] as const).filter((flag) => config[flag] !== true)
    if (missing.length === 0 || warnedConfigs.has(config)) return
    warnedConfigs.add(config)
    const consequences: Record<(typeof missing)[number], string> = {
      requireWithin: "grant/deny sin 'within' escriben en el scope que les digan, sea de quien sea",
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
  forRequest(): AuthorizationView {
    const view = new AuthorizationManager(this.#config)
    view.#parent = this.#parent ?? this
    const resolver = this.#config.scopes?.resolveAncestors
    view.#readResolver = resolver ? memoizeAncestors(resolver) : null
    return view
  }

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
    attached: async (child: ScopeRef, parent: ScopeRef, options?: WriteOptions): Promise<void> => {
      this.#writeOptions(options, 'scopes.attached')
      await this.#assertEdge(child, parent, 'scopes.attached')
      await (await this.driver()).onScopeAttached?.(child, parent)
    },
    moved: async (child: ScopeRef, newParent: ScopeRef, options?: WriteOptions): Promise<void> => {
      this.#writeOptions(options, 'scopes.moved')
      await this.#assertEdge(child, newParent, 'scopes.moved')
      await (await this.driver()).onScopeMoved?.(child, newParent)
    },
    /**
     * Hechos primero (el driver demuestra cero o lanza), arista después
     * (S6): si la purga muere a medias, el subárbol sigue colgado y los
     * denies heredados siguen valiendo. No comprueba que el scope exista:
     * el consumidor puede haber borrado ya su fila.
     */
    detached: async (child: ScopeRef, options?: WriteOptions): Promise<void> => {
      const actor = this.#writeOptions(options, 'scopes.detached')
      this.#resolver('scopes.detached')
      assertScope(child)
      if (child.type === APP_SCOPE_TYPE) {
        throw new InvalidIdentityError('scopes.detached: la raíz `app` no se puede borrar ni purgar')
      }
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
   * Contención de una escritura (B1). El scope tiene que existir (422
   * `E_AUTHZ_UNKNOWN_SCOPE`, la misma regla que el driver aplicará después) y
   * `within`, si viene, estar en su cadena (422 `E_AUTHZ_NOT_WITHIN`). Con
   * `requireWithin: true`, omitirlo es 422 `E_AUTHZ_WITHIN_REQUIRED`. Todo
   * antes del driver: nada se escribe.
   */
  async #assertWithin(scope: ScopeRef, options: ScopedWriteOptions | undefined, operation: string): Promise<void> {
    const within = options?.within
    if (within === undefined) {
      if (this.#config.requireWithin === true) {
        throw new WithinRequiredError(
          `${operation}: el config exige 'within' (requireWithin: true) y la escritura sobre ` +
            `${scope.type}:${scope.uuid ?? ''} no lo declara.`
        )
      }
      return
    }
    assertScope(within)
    const chain = await assertKnownScope(this.#freshResolver(), scope, operation)
    if (!chain.some((s) => AuthorizationManager.#sameScope(s, within))) {
      throw new NotWithinError(
        `${operation}: ${scope.type}:${scope.uuid ?? ''} no está dentro de ` +
          `${within.type}:${within.uuid ?? ''} (la cadena es ${chain.map((s) => `${s.type}:${s.uuid ?? ''}`).join(' → ')}); ` +
          `no se escribe fuera del scope declarado.`
      )
    }
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

  async #assertEdge(child: ScopeRef, parent: ScopeRef, operation: string): Promise<void> {
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
      return driver.authorizeMany(subject, permission, scopes)
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
    const granted = new Set<string>()
    const denied = new Set<string>()
    for (const level of chain) {
      for (const role of await driver.listRoles(subject, level)) {
        for (const permission of catalog.rolePermissions(role, level.type)) granted.add(permission)
      }
      for (const deny of await listDenies(subject, level)) denied.add(deny.permission)
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

  async revoke(subject: SubjectRef, role: string, scope: ScopeRef, options?: WriteOptions): Promise<void> {
    const actor = this.#writeOptions(options, 'revoke')
    assertIdentity({ subject, roleSlug: role, scope })
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

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef, options?: WriteOptions): Promise<void> {
    const actor = this.#writeOptions(options, 'removeDeny')
    assertIdentity({ subject, permission, scope })
    const event: AuthzWriteEvent = { action: 'deny_removed', subject, scope, permission, ...actor }
    await this.#write(event, async () => (await this.driver()).removeDeny(subject, permission, scope))
    await this.#notify(event)
  }

  /**
   * Scopes de un tipo donde el holder tiene el permiso (2.1, B3). La ÚNICA
   * API del paquete que enumera descendientes — excepción explícita al
   * invariante 7 (`list*` siguen siendo directos) — y lo hace con el
   * `descendantsOf` del consumidor, nunca con N+1 `resolveAncestors`.
   *
   * Regla:
   *  1. `listScopes(subject, permission)`: los scopes DIRECTOS que conceden,
   *     ya sin los bloqueados por un deny en su cadena y sin los que el árbol
   *     no conoce. Vacío ⇒ `none`.
   *  2. Si la raíz está entre ellos ⇒ `all`, con `excludedSubtrees` = todos
   *     los scopes con deny vivo del permiso (`listDenies`). Nunca `all` sin
   *     esa lista (juez cruce 5): un deny vivo tiene que verse.
   *  3. Si no: candidatos = directos ∪ sus descendientes; de ellos se quitan
   *     los denegados y sus subárboles; se filtran por `scopeType`.
   *  4. Más de `maxScopes` ⇒ 422 `E_AUTHZ_TOO_MANY_SCOPES`, nunca parcial.
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
    const descendantsOf = this.#config.scopes?.descendantsOf
    if (!descendantsOf) {
      throw new NoDescendantsResolverError(
        `authorizedScopes necesita 'scopes.descendantsOf' en config/authorization.ts (p. ej. sqlDescendantsOf(...)): ` +
          `sin el árbol de descendientes no se puede enumerar sin mentir.`
      )
    }
    const maxScopes = options.maxScopes ?? this.#config.scopes?.maxScopes ?? DEFAULT_MAX_SCOPES
    const maxNodes = this.#config.scopes?.maxDescendants ?? DEFAULT_MAX_DESCENDANTS
    for (const [name, value] of [['maxScopes', maxScopes], ['maxDescendants', maxNodes]] as const) {
      if (!Number.isInteger(value) || value < 1) {
        throw new AuthorizationConfigError(`authorizedScopes: ${name} debe ser un entero >= 1 (llegó ${String(value)})`)
      }
    }
    // Una vista propia para la llamada: los scopes que se resuelvan se
    // resuelven una vez.
    const view = this.#readResolver ? this : (this.forRequest() as AuthorizationManager)
    const driver = await view.#reader()
    const listDenies = this.#optional(driver, 'listDenies', 'authorizedScopes')
    const key = (s: ScopeRef) => `${s.type}\u001f${s.uuid ?? ''}`

    const direct = await driver.listScopes(subject, permission)
    if (direct.length === 0) return { kind: 'none' }
    const denied = (await listDenies(subject)).filter((d) => d.permission === permission).map((d) => d.scope)

    if (direct.some((s) => s.type === APP_SCOPE_TYPE)) {
      if (denied.length > maxScopes) {
        throw new TooManyScopesError(
          `authorizedScopes: ${denied.length} subárboles excluidos superan maxScopes=${maxScopes}; no se devuelve una lista parcial.`
        )
      }
      return { kind: 'all', excludedSubtrees: denied }
    }

    const candidates = new Map<string, ScopeRef>()
    for (const granted of direct) {
      candidates.set(key(granted), granted)
      for (const d of await view.#descendants(descendantsOf, granted, maxNodes)) candidates.set(key(d), d)
    }
    const excluded = new Set<string>()
    for (const deny of denied) {
      // Un deny fuera de los candidatos no toca nada de lo concedido (un
      // deny por ENCIMA de un grant ya lo quitó `listScopes`).
      if (!candidates.has(key(deny))) continue
      excluded.add(key(deny))
      for (const d of await view.#descendants(descendantsOf, deny, maxNodes)) excluded.add(key(d))
    }
    const scopes = [...candidates.values()].filter((s) => s.type === scopeType && !excluded.has(key(s)))
    if (scopes.length > maxScopes) {
      throw new TooManyScopesError(
        `authorizedScopes: más de ${maxScopes} scopes de tipo '${scopeType}' (maxScopes); acota la pregunta o sube la cota. ` +
          `No se devuelve una lista parcial.`
      )
    }
    return scopes.length ? { kind: 'some', scopes } : { kind: 'none' }
  }

  /**
   * `descendantsOf` del consumidor, clasificado como `resolveChain` clasifica
   * `resolveAncestors`: lanza ⇒ 503 `E_AUTHZ_RESOLVER_FAILED`; no-array o
   * scope mal formado ⇒ 503; más de `maxNodes` ⇒ 422 `E_AUTHZ_TOO_MANY_SCOPES`;
   * `null` (desconocido para ese árbol) ⇒ nada debajo.
   */
  async #descendants(
    descendantsOf: ScopeDescendantsResolver,
    scope: ScopeRef,
    maxNodes: number
  ): Promise<ScopeRef[]> {
    let result: ScopeRef[] | null
    try {
      result = await descendantsOf(scope, { maxNodes })
    } catch (error) {
      if (isAuthzError(error)) throw error
      throw new ScopeResolverError('descendantsOf', error)
    }
    if (result === null || result === undefined) return []
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
        `authorizedScopes: descendantsOf(${scope.type}:${scope.uuid ?? ''}) devolvió ${result.length} nodos, más que maxDescendants=${maxNodes}.`
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
