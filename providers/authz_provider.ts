import type { ApplicationService } from '@adonisjs/core/types'
import { AuthorizationManager } from '../src/manager.js'

declare module '@adonisjs/core/types' {
  export interface ContainerBindings {
    'authz.manager': AuthorizationManager
  }
}

/**
 * Registra el manager de autorización como singleton del contenedor,
 * construido desde `config/authorization.ts` de la aplicación.
 */
export default class AuthzProvider {
  constructor(protected app: ApplicationService) {}

  register() {
    this.app.container.singleton('authz.manager', async () => {
      const config = this.app.config.get('authorization') as any
      if (!config) {
        throw new Error(
          'Falta config/authorization.ts — ejecuta: node ace configure @jantstack/adonis-authz'
        )
      }
      return new AuthorizationManager(config)
    })
  }
}
