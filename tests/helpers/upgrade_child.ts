/**
 * Proceso HIJO de `upgrade_recipe.spec` (2.5-B · K14, tester G5): sobre una
 * base de trabajo vacía (la `connection` que le llega por `AUTHZ_TEST_REUSE`)
 * ejecuta la migración de 1.1.0 (`tests/fixtures/migration-1.1.0.stub`),
 * aplica LITERALMENTE las sentencias SQL de la receta del README (llegan por
 * `AUTHZ_UPGRADE_SQL`, una por elemento) y encima corre el motor 2.x:
 * identidad que no es UUID, caducidad al milisegundo, comparación byte a
 * byte, versión del catálogo. Imprime UNA línea JSON con lo observado y la
 * descripción del esquema resultante (para compararla con la publicada).
 *
 * Es un hijo porque el driver `database` habla con el `db` global de Lucid:
 * la única forma de apuntarlo a otra base es otro proceso.
 */

import { readFile } from 'node:fs/promises'
import { bootApp } from './app.js'
import { describeAuthzSchema, runMigrationSource } from './schema.js'

const reuse = JSON.parse(process.env.AUTHZ_TEST_REUSE ?? 'null')
const statements: string[] = JSON.parse(process.env.AUTHZ_UPGRADE_SQL ?? '[]')
if (!reuse || statements.length === 0) {
  console.error('uso: AUTHZ_TEST_REUSE=<json> AUTHZ_UPGRADE_SQL=<json string[]> upgrade_child.ts')
  process.exit(2)
}

const app = await bootApp({ reuse })
try {
  const old = await readFile(new URL('../fixtures/migration-1.1.0.stub', import.meta.url), 'utf8')
  await runMigrationSource(app.db, old)
  // Un rol que YA existía en 1.x (3B · B1, tester §4): tras la receta tiene que
  // quedar global (`owner_scope_key = 'global'`) y el unique nuevo no puede
  // reventar; el sync 2.x lo reconoce como el mismo rol (mismo uuid).
  const legacyUuid = '0192a000-0000-7000-8000-00000000abcd'
  await app.db.table('authz_roles').insert({ uuid: legacyUuid, slug: 'legacy', name: 'legacy', scope_type: 'app', rank: 7, created_at: new Date(), updated_at: new Date() })
  for (const sql of statements) await app.db.rawQuery(sql)
  const legacyRow: any = (await app.db.from('authz_roles').where('uuid', legacyUuid).select('owner_scope_key'))[0]

  const { DatabaseAuthorizationDriver } = await import('../../src/drivers/database_driver.js')
  const { syncAuthzCatalog } = await import('../../src/catalog/catalog.js')
  const { APP_SCOPE } = await import('../../src/types.js')
  const { v7: uuidv7 } = await import('uuid')
  await syncAuthzCatalog({
    permissions: [{ slug: 'docs:read' }],
    roles: [
      { slug: 'editor', scopeType: 'app', permissions: ['docs:read'] },
      { slug: 'legacy', scopeType: 'app', permissions: ['docs:read'] },
    ],
  })
  const legacyAfterSync: any[] = await app.db.from('authz_roles').where('slug', 'legacy').select('uuid', 'owner_scope_key')
  const T0 = new Date('2030-01-01T00:00:00.000Z')
  const soon = new Date(T0.getTime() + 600)
  const clocked = new DatabaseAuthorizationDriver({ now: () => T0 })
  const alice = { type: 'users', uuid: 'user-42' } // no es un UUID: en 1.x (uuid) era un 503 en PG
  const bob = { type: 'users', uuid: 'x'.repeat(36) }
  await clocked.grant(alice, 'editor', APP_SCOPE, { expiresAt: soon })
  await clocked.grant(bob, 'editor', APP_SCOPE, { expiresAt: new Date('2040-01-01T00:00:00.000Z') })
  const reread = await clocked.grant(alice, 'editor', APP_SCOPE)
  const at = (ms: number) => new DatabaseAuthorizationDriver({ now: () => new Date(T0.getTime() + ms) })
  // Comparación byte a byte: una fila con el id en minúsculas no casa con el mismo id en MAYÚSCULAS.
  const count = async (uuid: string) => {
    const rows: any = await app.db.from('authz_assignments').where('holder_uuid', uuid).count('* as n')
    return Number(rows[0].n ?? Object.values(rows[0])[0])
  }
  const { readAuthzCatalogVersion } = await import('../../src/catalog/catalog_cache.js')
  console.log(
    JSON.stringify({
      nonUuidGranted: await at(0).authorize(alice, 'docs:read', APP_SCOPE),
      msExact: reread.previousExpiresAt?.toISOString() ?? null,
      beforeSoon: await at(599).authorize(alice, 'docs:read', APP_SCOPE),
      atSoon: await at(600).authorize(alice, 'docs:read', APP_SCOPE),
      beyond2038: await at(0).authorize(bob, 'docs:read', APP_SCOPE),
      lowerRows: await count('user-42'),
      upperRows: await count('USER-42'),
      version: await readAuthzCatalogVersion(),
      legacyOwner: legacyRow?.owner_scope_key ?? null,
      legacyAfterSync: legacyAfterSync.map((r) => ({ uuid: r.uuid, owner: r.owner_scope_key })),
      schema: await describeAuthzSchema(app.db),
    })
  )
} finally {
  await app.teardown()
}
