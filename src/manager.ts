import { Exception } from '@adonisjs/core/exceptions'
import type { AuthorizationConfig } from './define_config.js'
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

  async authorize(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<boolean> {
    return (await this.driver()).authorize(subject, permission, scope)
  }

  async hasRole(subject: SubjectRef, role: string, scope: ScopeRef): Promise<boolean> {
    return (await this.driver()).hasRole(subject, role, scope)
  }

  async listSubjects(role: string, scope: ScopeRef): Promise<SubjectRef[]> {
    return (await this.driver()).listSubjects(role, scope)
  }

  async listScopes(subject: SubjectRef, permission: string): Promise<ScopeRef[]> {
    return (await this.driver()).listScopes(subject, permission)
  }

  async listRoles(subject: SubjectRef, scope: ScopeRef): Promise<string[]> {
    return (await this.driver()).listRoles(subject, scope)
  }

  async listRoleScopes(subject: SubjectRef, scopeType: ScopeType): Promise<ScopeRef[]> {
    return (await this.driver()).listRoleScopes(subject, scopeType)
  }

  async grant(
    subject: SubjectRef,
    role: string,
    scope: ScopeRef,
    options?: GrantOptions
  ): Promise<void> {
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
    await (await this.driver()).revoke(subject, role, scope)
    await this.#notify({ action: 'revoked', subject, scope, role })
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    await (await this.driver()).deny(subject, permission, scope)
    await this.#notify({ action: 'denied', subject, scope, permission })
  }

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    await (await this.driver()).removeDeny(subject, permission, scope)
    await this.#notify({ action: 'deny_removed', subject, scope, permission })
  }

  /** El hook es responsabilidad del consumidor; no debe lanzar. */
  async #notify(event: AuthzWriteEvent): Promise<void> {
    await this.#config.hooks?.onWrite?.(event)
  }
}
