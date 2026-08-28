/**
 * Entrypoint de la suite del paquete. Corre sin proyecto Adonis y sin
 * Postgres: SQLite en memoria (ver tests/helpers/app.ts). El driver `openfga`
 * se suma automáticamente si hay un servidor disponible:
 *
 *   npm test
 *   OPENFGA_TEST_URL=http://localhost:8090 npm test
 */

import { assert } from '@japa/assert'
import { configure, processCLIArgs, run } from '@japa/runner'
import type { Database } from '@adonisjs/lucid/database'
import { bootApp } from '../tests/helpers/app.js'
import { createAuthzSchema, createDemoScopesTable } from '../tests/helpers/schema.js'

processCLIArgs(process.argv.slice(2))

let db: Database

configure({
  files: ['tests/**/*.spec.ts'],
  plugins: [assert()],
  setup: [
    async () => {
      db = await bootApp()
      await createAuthzSchema(db)
      await createDemoScopesTable(db)
    },
  ],
  // Sin esto el pool de SQLite mantiene vivo el event loop y el proceso no
  // termina nunca (la suite pasa, pero el job de CI se queda colgado).
  teardown: [async () => db?.manager.closeAll()],
})

// El teardown de Japa no llega a correr si un .spec.ts falla al importarse.
run().finally(async () => {
  await db?.manager.closeAll()
})
