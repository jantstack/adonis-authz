import app from '@adonisjs/core/services/app'
import type { RelationsManager } from '../src/relations/manager.js'

/**
 * Singleton del motor de relaciones (ReBAC), resuelto del contenedor cuando la
 * app ha booteado — el análogo de `services/main` para el puerto
 * `RelationsDriver`. Solo existe si el consumidor declaró `relations.config` en
 * `config/authorization.ts`; si no, resolverlo lanza con la receta.
 *
 *   import relations from '@jantstack/adonis-authz/services/relations'
 *   await relations.relate(user, 'viewer', { type: 'document', id }, APP_SCOPE)
 *   await relations.check(user, 'viewer', { type: 'document', id }, APP_SCOPE)
 */
let relations: RelationsManager

await app.booted(async () => {
  relations = await app.container.make('authz.relations')
})

export { relations as default }
