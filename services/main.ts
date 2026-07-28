import app from '@adonisjs/core/services/app'
import type { AuthorizationManager } from '../src/manager.js'

/**
 * Singleton del manager, resuelto del contenedor cuando la app ha booteado.
 *
 *   import authorization from '@jantstack/adonis-authz/services/main'
 *   await authorization.authorize(subject, 'audit:read', APP_SCOPE)
 */
let authorization: AuthorizationManager

await app.booted(async () => {
  authorization = await app.container.make('authz.manager')
})

export { authorization as default }
