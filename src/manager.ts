import { Exception } from '@adonisjs/core/exceptions'
import type { AuthorizationConfig } from './define_config.js'
import { assertIdentity } from './identity.js'
import type {
  AuthorizationDriver,
  AuthorizationDriverFactory,
  AuthzWriteEvent,
  GrantOptions,
  ScopeRef,
  ScopeType,
  SubjectRef,
} from './types.js'

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

  constructor(config: AuthorizationConfig) {
    this.#config = config
  }

  async driver(): Promise<AuthorizationDriver> {
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
  }

  // La identidad se valida AQUÍ, antes de resolver siquiera el driver: una
  // pregunta mal formada (uuid ausente, `{app, uuid}`, slug con `~`) es 422
  // sin tocar catálogo, árbol ni backend, y sin que el hook `onWrite` audite
  // una escritura que no ocurrió. Los drivers repiten la misma función por
  // defensa en profundidad (el juez y un driver suelto no pasan por aquí).

  async authorize(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, permission, scope })
    return (await this.driver()).authorize(subject, permission, scope)
  }

  async hasRole(subject: SubjectRef, role: string, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, role, scope })
    return (await this.driver()).hasRole(subject, role, scope)
  }

  async listSubjects(role: string, scope: ScopeRef): Promise<SubjectRef[]> {
    assertIdentity({ role, scope })
    return (await this.driver()).listSubjects(role, scope)
  }

  async listScopes(subject: SubjectRef, permission: string): Promise<ScopeRef[]> {
    assertIdentity({ subject, permission })
    return (await this.driver()).listScopes(subject, permission)
  }

  async listRoles(subject: SubjectRef, scope: ScopeRef): Promise<string[]> {
    assertIdentity({ subject, scope })
    return (await this.driver()).listRoles(subject, scope)
  }

  async listRoleScopes(subject: SubjectRef, scopeType: ScopeType): Promise<ScopeRef[]> {
    assertIdentity({ subject, scopeType })
    return (await this.driver()).listRoleScopes(subject, scopeType)
  }

  async grant(
    subject: SubjectRef,
    role: string,
    scope: ScopeRef,
    options?: GrantOptions
  ): Promise<void> {
    assertIdentity({ subject, role, scope })
    await (await this.driver()).grant(subject, role, scope, options)
    await this.#notify({
      action: 'granted',
      subject,
      scope,
      role,
      expiresAt: options?.expiresAt ?? null,
    })
  }

  async revoke(subject: SubjectRef, role: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, role, scope })
    await (await this.driver()).revoke(subject, role, scope)
    await this.#notify({ action: 'revoked', subject, scope, role })
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    await (await this.driver()).deny(subject, permission, scope)
    await this.#notify({ action: 'denied', subject, scope, permission })
  }

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    await (await this.driver()).removeDeny(subject, permission, scope)
    await this.#notify({ action: 'deny_removed', subject, scope, permission })
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
