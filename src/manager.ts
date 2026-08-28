import { Exception } from '@adonisjs/core/exceptions'
import type { AuthorizationConfig } from './define_config.js'
import { assertIdentity, assertScope } from './identity.js'
import { expiryChanged } from './expiry.js'
import { assertKnownScope } from './drivers/backend_guard.js'
import {
  AuthorizationBackendTimeoutError,
  AuthorizationConfigError,
  InvalidIdentityError,
  ScopeCycleError,
} from './errors.js'
import { APP_SCOPE_TYPE } from './types.js'
import { memoizeAncestors } from './memoize_ancestors.js'
import type {
  AuthorizationDriver,
  AuthorizationDriverFactory,
  AuthzWriteEvent,
  GrantOptions,
  GrantOutcome,
  RoleQuery,
  ScopeAncestorsResolver,
  ScopeRef,
  ScopeType,
  SubjectRef,
} from './types.js'

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
>

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

  constructor(config: AuthorizationConfig) {
    this.#config = config
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
    attached: async (child: ScopeRef, parent: ScopeRef): Promise<void> => {
      await this.#assertEdge(child, parent, 'scopes.attached')
      await (await this.driver()).onScopeAttached?.(child, parent)
    },
    moved: async (child: ScopeRef, newParent: ScopeRef): Promise<void> => {
      await this.#assertEdge(child, newParent, 'scopes.moved')
      await (await this.driver()).onScopeMoved?.(child, newParent)
    },
    /**
     * Hechos primero (el driver demuestra cero o lanza), arista después
     * (S6): si la purga muere a medias, el subárbol sigue colgado y los
     * denies heredados siguen valiendo. No comprueba que el scope exista:
     * el consumidor puede haber borrado ya su fila.
     */
    detached: async (child: ScopeRef): Promise<void> => {
      this.#resolver('scopes.detached')
      assertScope(child)
      if (child.type === APP_SCOPE_TYPE) {
        throw new InvalidIdentityError('scopes.detached: la raíz `app` no se puede borrar ni purgar')
      }
      const driver = await this.driver()
      await this.#write({ action: 'scope_purged', scope: child }, () => driver.purgeScope(child))
      await driver.onScopeDetached?.(child)
      await this.#notify({ action: 'scope_purged', scope: child })
    },
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

  async grant(
    subject: SubjectRef,
    role: string,
    scope: ScopeRef,
    options?: GrantOptions
  ): Promise<GrantOutcome> {
    assertIdentity({ subject, roleSlug: role, scope, expiresAt: options?.expiresAt })
    const outcome: GrantOutcome =
      (await this.#write(
        { action: 'granted', subject, scope, role, expiresAt: options?.expiresAt ?? null },
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
      })
    } else {
      await this.#notify({
        action: 'granted',
        subject,
        scope,
        role,
        expiresAt: outcome.expiresAt,
      })
    }
    return outcome
  }

  async revoke(subject: SubjectRef, role: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, roleSlug: role, scope })
    const event: AuthzWriteEvent = { action: 'revoked', subject, scope, role }
    await this.#write(event, async () => (await this.driver()).revoke(subject, role, scope))
    await this.#notify(event)
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    const event: AuthzWriteEvent = { action: 'denied', subject, scope, permission }
    await this.#write(event, async () => (await this.driver()).deny(subject, permission, scope))
    await this.#notify(event)
  }

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    const event: AuthzWriteEvent = { action: 'deny_removed', subject, scope, permission }
    await this.#write(event, async () => (await this.driver()).removeDeny(subject, permission, scope))
    await this.#notify(event)
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
