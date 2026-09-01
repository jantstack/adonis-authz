import type Configure from '@adonisjs/core/commands/configure'
import { stubsRoot } from './stubs/main.js'

/**
 * `node ace configure @jantstack/adonis-authz`
 *
 * Registra el provider, los comandos y el middleware, define las variables
 * de entorno y PUBLICA en el proyecto lo que es suyo: la migración de las
 * tablas `authz_*` y los dos configs (drivers + catálogo del nivel app).
 *
 * Es INTERACTIVO: pregunta lo MÍNIMO que cambia lo publicado —el driver por
 * defecto y si publicar la migración de la outbox del árbol (opt-in, ver
 * README)— con `command.prompt`. Lo que NO cambia según la respuesta no se
 * pregunta: los dos configs siempre se publican con las dos costuras cableadas
 * (el stub arranca en cualquier driver leyendo `AUTHZ_DRIVER`), así que la
 * elección solo fija el DEFAULT de esa variable, no ramifica el stub —el que
 * `configure.spec` compila sigue siendo el mismo—. Y las relaciones (Fase 4)
 * NO se preguntan: sus tablas ya están en la migración del motor y su config
 * es `defineRelationsConfig` en el propio proyecto; un prompt ahí no publicaría
 * nada distinto.
 */
export async function configure(command: Configure) {
  const codemods = await command.createCodemods()

  // ── Preguntas (las únicas que cambian lo que se publica) ──────────────────
  const defaultDriver = await command.prompt.choice(
    '¿Qué driver de autorización por defecto? (AUTHZ_DRIVER; puedes cambiarlo por entorno)',
    [
      { name: 'database', message: 'database — SQL propio, sin infraestructura extra (recomendado)' },
      { name: 'openfga', message: 'openfga — los hechos viven en un servidor OpenFGA (necesita @openfga/sdk)' },
    ],
    { default: 'database' }
  )

  // La outbox del árbol de scopes es OPT-IN (README: «configure no la publica,
  // porque la outbox es opcional»). Se ofrece porque, sin ella, el consumidor
  // tenía que copiar el stub a mano; sigue siendo suya y hay que registrar
  // `sqlScopeOutbox()` en el config para usarla.
  const withOutbox = await command.prompt.confirm(
    '¿Publicar la migración de la outbox del árbol de scopes? (opt-in; propaga los cambios de árbol en tu misma transacción)',
    { default: false }
  )

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

  await codemods.defineEnvVariables({ AUTHZ_DRIVER: defaultDriver })
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

  if (withOutbox) {
    // El stub trae su propio destino fijo (`exports({ to: ... })`), sin plantilla.
    await codemods.makeUsingStub(stubsRoot, 'scopes_outbox_migration.stub', {})
  }

  command.logger.success('Autorización configurada.')
  if (defaultDriver === 'openfga') {
    command.logger.info('Driver por defecto: openfga. Instala su peer: npm i @openfga/sdk')
    command.logger.info('Y aprovisiona el store: node ace openfga:provision')
  }
  if (withOutbox) {
    command.logger.info(
      'Outbox publicada. Registra `sqlScopeOutbox()` en config/authorization.ts (scopes.outbox y en el driver).'
    )
  }
  command.logger.info('Siguiente paso: node ace migration:run')
}
