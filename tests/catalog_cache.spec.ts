/**
 * Memo del catálogo (Fase 2, lote 2A · A1).
 *
 * Lo que se fija aquí es el CONTRATO del memo, no la semántica de
 * autorización (esa la juzga el contrato y no cambia): cuántas veces se lee
 * `authz_*`, qué lo invalida (sync, `invalidateAuthzCatalog`, TTL) y, sobre
 * todo, qué NO lo invalida —un cambio en las tablas por fuera del sync— para
 * que el precio del memo esté escrito y no se descubra en producción.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { OpenFgaAuthorizationDriver } from '../src/openfga.js'
import { CatalogCache, invalidateAuthzCatalog } from '../src/catalog_cache.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { APP_SCOPE } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { countQueries } from './helpers/spies.js'
import { withTableMissing } from './database_driver.spec.js'

const CATALOG = {
  permissions: [{ slug: 'docs:read' }],
  roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
}

/** Consultas que LEEN el catálogo (`from authz_permissions|roles|role_permissions`); el join de hechos no cuenta. */
function catalogReads(queries: Array<{ sql: string }>): number {
  return queries.filter((q) => /from\s+[`"]?authz_(permissions|roles|role_permissions)[`"]?/i.test(q.sql)).length
}

/** Escribe un permiso nuevo y su vínculo con `editor` POR FUERA del sync. */
async function linkNewPermissionByHand(slug: string): Promise<void> {
  const role: any = (await db.from('authz_roles').where('slug', 'editor').select('uuid'))[0]
  const permissionUuid = uuidv7()
  await db.table('authz_permissions').insert({
    uuid: permissionUuid,
    slug,
    description: null,
    created_at: new Date(),
    updated_at: new Date(),
  })
  await db.table('authz_role_permissions').insert({
    uuid: uuidv7(),
    role_uuid: role.uuid,
    permission_uuid: permissionUuid,
    created_at: new Date(),
  })
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

test.group('memo del catálogo (2A · A1)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog(CATALOG)
  })

  test('100 authorize seguidos leen el catálogo UNA vez (3 consultas), no una por pregunta', async ({
    assert,
  }) => {
    // Antes: `findPermission` en cada `authorize` (100 lecturas del catálogo).
    // Ahora: una carga (permisos, roles, vínculos) y el resto son hechos.
    const alice = { type: 'users', uuid: uuidv7() }
    await new DatabaseAuthorizationDriver().grant(alice, 'editor', APP_SCOPE)

    // Driver nuevo (memo vacío): la primera pregunta carga, las 99 restantes no.
    const driver = new DatabaseAuthorizationDriver()
    const { queries } = await countQueries(async () => {
      for (let i = 0; i < 100; i++) assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })
    assert.equal(catalogReads(queries), 3)
    // Los hechos se consultan SIEMPRE: denies + asignaciones por pregunta.
    assert.equal(queries.length - catalogReads(queries), 200)
  })

  test('openfga: 100 authorize ⇒ 3 lecturas del catálogo y un batchCheck por pregunta (A1 + A2)', async ({
    assert,
  }) => {
    // Antes: `findPermission` + `rolesGranting` por `authorize` (200 lecturas)
    // y dos batchCheck por pregunta.
    const driver = new OpenFgaAuthorizationDriver({
      apiUrl: 'http://127.0.0.1:9',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      holderTypes: { users: 'user' },
    })
    let batches = 0
    ;(driver as any).client.batchCheck = async (body: any) => {
      batches += 1
      return {
        result: body.checks.map((c: any) => ({
          allowed: c.relation === 'assignee',
          correlationId: c.correlationId,
          request: c,
        })),
      }
    }
    const alice = { type: 'users', uuid: uuidv7() }
    const { queries } = await countQueries(async () => {
      for (let i = 0; i < 100; i++) assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })
    assert.equal(queries.length, 3)
    assert.equal(catalogReads(queries), 3)
    assert.equal(batches, 100)
  })

  test('el memo nunca cachea hechos ni decisiones: grant/deny/revoke se ven en la pregunta siguiente', async ({
    assert,
  }) => {
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    const { queries } = await countQueries(async () => {
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      await driver.deny(alice, 'docs:read', APP_SCOPE)
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      await driver.removeDeny(alice, 'docs:read', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      await driver.revoke(alice, 'editor', APP_SCOPE)
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })
    assert.equal(catalogReads(queries), 3)
  })

  test('syncAuthzCatalog invalida el memo: lo que el sync añade se ve en la pregunta siguiente', async ({
    assert,
  }) => {
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    // `docs:write` no existe: false, y el memo queda cargado.
    assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    assert.isTrue(driver.catalog.loaded)

    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'docs:write'] }],
    })
    assert.isFalse(driver.catalog.loaded)

    const { queries } = await countQueries(async () => {
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })
    // Una recarga (3) y ninguna más.
    assert.equal(catalogReads(queries), 3)
  })

  test('caso negativo: un cambio en authz_* por fuera del sync NO se ve hasta invalidateAuthzCatalog()', async ({
    assert,
  }) => {
    // Es el contrato del memo (README, "Performance"): quien escribe las
    // tablas a mano invalida a mano. Sin TTL, la respuesta vieja se mantiene.
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))

    await linkNewPermissionByHand('docs:write')
    // La base ya lo tiene; el memo, no.
    assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))

    invalidateAuthzCatalog()
    assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
  })

  test('driver.catalog.invalidate() recarga solo ESE memo', async ({ assert }) => {
    const a = new DatabaseAuthorizationDriver()
    const b = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await a.grant(alice, 'editor', APP_SCOPE)
    assert.isFalse(await a.authorize(alice, 'docs:write', APP_SCOPE))
    assert.isFalse(await b.authorize(alice, 'docs:write', APP_SCOPE))

    await linkNewPermissionByHand('docs:write')
    a.catalog.invalidate()
    assert.isTrue(await a.authorize(alice, 'docs:write', APP_SCOPE))
    // `b` sigue con su foto: la invalidación por instancia no es global.
    assert.isFalse(await b.authorize(alice, 'docs:write', APP_SCOPE))
  })

  test('con catalogTtlMs el memo caduca solo (cinturón para multi-proceso)', async ({ assert }) => {
    const driver = new DatabaseAuthorizationDriver({ catalogTtlMs: 40 })
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))

    await linkNewPermissionByHand('docs:write')
    assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    await sleep(60)
    assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
  })

  test('dos drivers pueden compartir un memo (opción catalog): una sola carga para ambos', async ({
    assert,
  }) => {
    const shared = new CatalogCache()
    const a = new DatabaseAuthorizationDriver({ catalog: shared })
    const b = new DatabaseAuthorizationDriver({ catalog: shared })
    assert.strictEqual(a.catalog, shared)
    assert.strictEqual(b.catalog, shared)
    const alice = { type: 'users', uuid: uuidv7() }
    const { queries } = await countQueries(async () => {
      assert.isFalse(await a.authorize(alice, 'docs:read', APP_SCOPE))
      assert.isFalse(await b.authorize(alice, 'docs:read', APP_SCOPE))
    })
    assert.equal(catalogReads(queries), 3)
  })

  test('las cargas concurrentes comparten una sola lectura', async ({ assert }) => {
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    const { queries } = await countQueries(async () => {
      const answers = await Promise.all(
        Array.from({ length: 20 }, () => driver.authorize(alice, 'docs:read', APP_SCOPE))
      )
      assert.deepEqual(answers, Array(20).fill(false))
    })
    assert.equal(catalogReads(queries), 3)
  })

  test('una carga que falla es 503 y no deja nada cacheado: con la base de vuelta, recarga', async ({
    assert,
  }) => {
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    let caught: any
    await withTableMissing('authz_roles', async () => {
      try {
        await driver.authorize(alice, 'docs:read', APP_SCOPE)
        assert.fail('debería haber lanzado')
      } catch (error) {
        caught = error
      }
    })
    assert.equal(caught.status, 503)
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    assert.isFalse(driver.catalog.loaded)

    await driver.grant(alice, 'editor', APP_SCOPE)
    assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    assert.isTrue(driver.catalog.loaded)
  })

  test('toda consulta de carga lleva el deadline del driver', async ({ assert }) => {
    const driver = new DatabaseAuthorizationDriver({ timeoutMs: 250 })
    const { queries } = await countQueries(() =>
      driver.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
    )
    assert.equal(catalogReads(queries), 3)
    assert.deepEqual(
      queries.map((q) => q.timeout),
      queries.map(() => 250)
    )
  })

  test('un ttlMs que no es un número > 0 se rechaza al construir', ({ assert }) => {
    for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.throws(() => new CatalogCache({ ttlMs: bad }), /ttlMs/)
    }
  })
})
