/**
 * Entrypoint de la suite del paquete. Corre sin proyecto Adonis; el motor SQL
 * lo elige `TEST_DB` (ver tests/helpers/app.ts): SQLite en memoria por
 * defecto, `sqlite-file` (pool ≥ 2), `pg` o `mysql` (base aislada por
 * ejecución, borrada al final). El driver `openfga` se suma automáticamente
 * si hay un servidor disponible:
 *
 *   npm test
 *   npm run test:pg  ·  npm run test:mysql  ·  npm run test:sqlite-file
 *   OPENFGA_TEST_URL=http://localhost:8090 npm test
 */

import { assert } from '@japa/assert'
import { configure, processCLIArgs, run } from '@japa/runner'
import { bootApp } from '../tests/helpers/app.js'
import type { TestApp } from '../tests/helpers/app.js'
import { armOpenFgaStoreGuard } from '../tests/helpers/openfga_stores.js'
import type { OpenFgaStoreGuard } from '../tests/helpers/openfga_stores.js'
import { createAuthzSchema, createDemoScopesTable, createScopeOutboxTable } from '../tests/helpers/schema.js'

processCLIArgs(process.argv.slice(2))

let app: TestApp | undefined
let stores: OpenFgaStoreGuard | undefined

configure({
  files: ['tests/**/*.spec.ts'],
  plugins: [assert()],
  setup: [
    async () => {
      app = await bootApp()
      // La MISMA red que la base SQL, para los stores de OpenFGA (3b-4 · C5):
      // una corrida que TERMINA no gotea, pero una interrumpida sí, y así se
      // llegó a 60 stores en el servidor de desarrollo.
      if (process.env.OPENFGA_TEST_URL) {
        stores = await armOpenFgaStoreGuard(process.env.OPENFGA_TEST_URL)
      }
      console.log(`[suite] motor SQL: ${app.engine} (${app.database})`)
      await createAuthzSchema(app.db)
      await createDemoScopesTable(app.db)
      await createScopeOutboxTable(app.db)
    },
  ],
  // Sin esto el pool mantiene vivo el event loop y el proceso no termina
  // nunca (la suite pasa, pero el job de CI se queda colgado). Y la base de
  // esta ejecución (PG/MySQL/fichero) se destruye aquí.
  teardown: [
    async () => {
      await stores?.sweep()
      await app?.teardown()
      console.log(`[suite] base destruida: ${app?.database}`)
    },
  ],
})

// El teardown de Japa no llega a correr si un .spec.ts falla al importarse.
run().finally(async () => {
  await stores?.sweep()
  await app?.teardown()
})
