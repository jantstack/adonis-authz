/**
 * Arranque autónomo de AdonisJS + Lucid para los tests del PAQUETE.
 *
 * El motor depende de `@adonisjs/lucid/services/db` (un singleton del
 * contenedor), así que necesita una app booteada — pero no un proyecto Adonis
 * completo. Aquí se monta lo mínimo sobre SQLite en memoria, de modo que la
 * suite de contrato corra en CI sin Postgres y sin la app anfitriona.
 *
 * Orden importante: `setApp()` ANTES de que se importe `services/db.js` — ese
 * módulo hace `await app.booted(...)` en su top-level.
 */

import { AppFactory } from '@adonisjs/core/factories/app'
import { setApp } from '@adonisjs/core/services/app'
import { LoggerFactory } from '@adonisjs/core/factories/logger'
import { Emitter } from '@adonisjs/core/events'
import { Database } from '@adonisjs/lucid/database'
import { BaseModel } from '@adonisjs/lucid/orm'

export async function bootApp(): Promise<Database> {
  const app = new AppFactory().create(new URL('../../', import.meta.url), () => {}) as any
  await app.init()
  setApp(app)

  const db = new Database(
    {
      connection: 'primary',
      connections: {
        primary: {
          client: 'better-sqlite3',
          connection: { filename: ':memory:' },
          useNullAsDefault: true,
          // SQLite en memoria vive dentro de UNA conexión: con pool > 1 cada
          // conexión vería su propia base vacía.
          pool: { min: 1, max: 1 },
        },
      },
    } as any,
    new LoggerFactory().create(),
    new Emitter(app) as any
  )

  app.container.singleton(Database, () => db)

  // El middleware resuelve el manager del contenedor (services/main.ts), así
  // que el binding tiene que existir antes de que se importe.
  app.container.singleton('authz.manager', async () => {
    const { AuthorizationManager } = await import('../../src/manager.js')
    const { DatabaseAuthorizationDriver } = await import('../../src/drivers/database_driver.js')
    return new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver() },
      warnOnOptInSecurity: false,
    } as any)
  })

  await app.boot()

  BaseModel.useAdapter(db.modelAdapter())

  return db
}
