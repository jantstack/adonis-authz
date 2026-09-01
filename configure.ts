import type Configure from '@adonisjs/core/commands/configure'
import { stubsRoot } from './stubs/main.js'

/**
 * `node ace configure @jantstack/adonis-authz`
 *
 * Registra el provider, los comandos y el middleware, define las variables
 * de entorno y PUBLICA en el proyecto lo que es suyo: la migración de las
 * tablas `authz_*` y los dos configs (drivers + catálogo del nivel app).
 */
export async function configure(command: Configure) {
  const codemods = await command.createCodemods()

  await codemods.updateRcFile((rcFile: any) => {
    rcFile
      .addProvider('@jantstack/adonis-authz/authz_provider')
      .addCommand('@jantstack/adonis-authz/commands')
  })

  await codemods.registerMiddleware('named', [
    {
      name: 'appAccess',
      path: '@jantstack/adonis-authz/app_access_middleware',
    },
    {
      name: 'resourceAccess',
      path: '@jantstack/adonis-authz/resource_access_middleware',
    },
  ])

  await codemods.defineEnvVariables({ AUTHZ_DRIVER: 'database' })
  await codemods.defineEnvValidations({
    variables: {
      AUTHZ_DRIVER: `Env.schema.string.optional()`,
      OPENFGA_URL: `Env.schema.string.optional({ format: 'url', tld: false })`,
      OPENFGA_STORE_ID: `Env.schema.string.optional()`,
      OPENFGA_MODEL_ID: `Env.schema.string.optional()`,
    },
    leadingComment: 'Variables de @jantstack/adonis-authz',
  })

  await codemods.makeUsingStub(stubsRoot, 'config/authorization.stub', {})
  await codemods.makeUsingStub(stubsRoot, 'config/app_acl.stub', {})

  await codemods.makeUsingStub(stubsRoot, 'migration.stub', {
    migration: {
      folder: 'database/migrations',
      fileName: `${new Date().getTime()}_create_authz_tables.ts`,
    },
  })

  command.logger.success('Autorización configurada.')
  command.logger.info('Siguiente paso: node ace migration:run')
}
