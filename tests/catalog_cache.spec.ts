/**
 * Memo del catálogo (Fase 2, lote 2A · A1; versión compartida en 2D · F1).
 *
 * Lo que se fija aquí es el CONTRATO del memo, no la semántica de
 * autorización (esa la juzga el contrato y no cambia): cuántas veces se lee
 * `authz_*`, cuántas se revalida contra `authz_catalog_version` (una por
 * `view()` con el default `'always'`), qué lo invalida (sync en cualquier
 * proceso, `bumpAuthzCatalogVersion`, `invalidateAuthzCatalog`) y, sobre
 * todo, qué NO lo invalida —un cambio en las tablas sin subir la versión—
 * para que el precio del memo esté escrito y no se descubra en producción.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { OpenFgaAuthorizationDriver } from '../src/openfga.js'
import { CatalogCache, bumpAuthzCatalogVersion, invalidateAuthzCatalog, readAuthzCatalogVersion } from '../src/catalog_cache.js'
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

/** Revalidaciones contra la versión compartida (2D · F1): `SELECT version FROM authz_catalog_version WHERE id = 1`. */
function versionChecks(queries: Array<{ sql: string }>): number {
  return queries.filter((q) => /from\s+[`"]?authz_catalog_version[`"]?/i.test(q.sql)).length
}

/** Consultas de HECHOS: ni catálogo ni revalidación. */
function factsQueries(queries: Array<{ sql: string }>): number {
  return queries.length - catalogReads(queries) - versionChecks(queries)
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

  test('100 authorize seguidos leen el catálogo UNA vez (3 consultas) y lo revalidan una vez por pregunta, no lo recargan', async ({
    assert,
  }) => {
    // Antes: `findPermission` en cada `authorize` (100 lecturas del catálogo).
    // Ahora: una carga (permisos, roles, vínculos), una revalidación por
    // pregunta (SELECT por clave primaria, 2D · F1) y el resto son hechos.
    const alice = { type: 'users', uuid: uuidv7() }
    await new DatabaseAuthorizationDriver().grant(alice, 'editor', APP_SCOPE)

    // Driver nuevo (memo vacío): la primera pregunta carga, las 99 restantes no.
    const driver = new DatabaseAuthorizationDriver()
    const { queries } = await countQueries(async () => {
      for (let i = 0; i < 100; i++) assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })
    assert.equal(catalogReads(queries), 3)
    // Los hechos se consultan SIEMPRE: denies + asignaciones por pregunta.
    assert.equal(queries.length - catalogReads(queries) - versionChecks(queries), 200)
    // F1: cada pregunta revalida la versión compartida (1 SELECT por clave primaria).
    assert.equal(versionChecks(queries), 100)
  })

  test('openfga: 100 authorize ⇒ 3 lecturas del catálogo, 100 revalidaciones y un batchCheck por pregunta (A1 + A2 + F1)', async ({
    assert,
  }) => {
    // Antes: `findPermission` + `rolesGranting` por `authorize` (200 lecturas)
    // y dos batchCheck por pregunta. La revalidación es UNA por pregunta
    // aunque la pregunta lea permiso y roles: una foto por operación.
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
    // 3 de catálogo + 1 revalidación de la versión por pregunta (F1).
    assert.equal(queries.length, 3 + 100)
    assert.equal(catalogReads(queries), 3)
    assert.equal(versionChecks(queries), 100)
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

  test('caso negativo: un cambio en authz_* SIN subir la versión NO se ve hasta invalidateAuthzCatalog() o bumpAuthzCatalogVersion()', async ({
    assert,
  }) => {
    // Es el contrato del memo (README, "Performance"): quien escribe las
    // tablas a mano sube la versión a mano. Sin eso, la revalidación ve la
    // misma versión y la respuesta vieja se mantiene.
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))

    await linkNewPermissionByHand('docs:write')
    // La base ya lo tiene; el memo, no (y cada pregunta revalidó: misma versión).
    const { queries } = await countQueries(async () => {
      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })
    assert.equal(versionChecks(queries), 2)
    assert.equal(catalogReads(queries), 0)

    invalidateAuthzCatalog()
    assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
  })

  test('bumpAuthzCatalogVersion() sin invalidateAuthzCatalog(): el canal entre procesos basta (2D · F1)', async ({
    assert,
  }) => {
    // Lo que deja un sync de OTRO proceso es esto: filas nuevas y la versión
    // subida. Este proceso no recibe ninguna señal en memoria; lo ve porque
    // cada `view()` contrasta la fila y recarga si difiere.
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    const before = await readAuthzCatalogVersion()

    await linkNewPermissionByHand('docs:write')
    await bumpAuthzCatalogVersion()
    assert.equal(await readAuthzCatalogVersion(), before + 1)
    assert.isTrue(driver.catalog.loaded, 'el contador del proceso no se tocó')

    const { queries } = await countQueries(async () => {
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })
    // Una recarga (versión + 3 tablas) y luego solo revalidaciones.
    assert.equal(catalogReads(queries), 3)
    assert.equal(versionChecks(queries), 2)
  })

  test('syncAuthzCatalog sube la versión compartida DENTRO de su transacción: un sync que falla no la sube', async ({
    assert,
  }) => {
    const before = await readAuthzCatalogVersion()
    await syncAuthzCatalog(CATALOG)
    assert.equal(await readAuthzCatalogVersion(), before + 1, 'un sync sin cambios también sube (recargar de más es gratis)')

    // Rol que concede un permiso inexistente: 422 a mitad de la transacción.
    let caught: any
    try {
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }],
        roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'no:existe'] }],
      })
    } catch (error) {
      caught = error
    }
    assert.equal(caught?.code, 'E_AUTHZ_UNKNOWN_PERMISSION')
    assert.equal(await readAuthzCatalogVersion(), before + 1, 'la versión no sube con el sync que no confirmó')
  })

  test('dos memos sobre la misma base: lo que sube la versión en uno lo ve el otro en su siguiente pregunta, sin señal en memoria', async ({
    assert,
  }) => {
    // Dos instancias son dos procesos a efectos del memo: no comparten nada
    // en memoria. `a` escribe y sube la versión; `b` no recibe llamada
    // alguna y aun así responde con el catálogo nuevo (revalidación).
    const a = new DatabaseAuthorizationDriver()
    const b = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await a.grant(alice, 'editor', APP_SCOPE)
    assert.isTrue(await a.authorize(alice, 'docs:read', APP_SCOPE))
    assert.isTrue(await b.authorize(alice, 'docs:read', APP_SCOPE))

    // "Otro proceso" retira el vínculo: solo la base cambia.
    const perm: any = (await db.from('authz_permissions').where('slug', 'docs:read').select('uuid'))[0]
    await db.from('authz_role_permissions').where('permission_uuid', perm.uuid).delete()
    await bumpAuthzCatalogVersion()
    assert.isFalse(await b.authorize(alice, 'docs:read', APP_SCOPE), 'b recarga por la versión, no por el contador')
    assert.isFalse(await a.authorize(alice, 'docs:read', APP_SCOPE))
  })

  test('las revalidaciones concurrentes comparten UNA lectura de la versión; la misma versión no recarga', async ({
    assert,
  }) => {
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.authorize(alice, 'docs:read', APP_SCOPE) // carga
    const { queries } = await countQueries(async () => {
      const answers = await Promise.all(
        Array.from({ length: 20 }, () => driver.authorize(alice, 'docs:read', APP_SCOPE))
      )
      assert.deepEqual(answers, Array(20).fill(false))
    })
    assert.equal(versionChecks(queries), 1)
    assert.equal(catalogReads(queries), 0)
  })

  test('si la revalidación no puede leer la versión es 503 y NO se sirve la foto vieja', async ({ assert }) => {
    // "No sé si el catálogo que tengo es el vigente" no es una respuesta:
    // un `true` con un catálogo que puede haber retirado el permiso sería
    // fail-open; un `false` silencioso, el defecto que el invariante 5 prohíbe.
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    let caught: any
    await withTableMissing('authz_catalog_version', async () => {
      try {
        await driver.authorize(alice, 'docs:read', APP_SCOPE)
        assert.fail('debería haber lanzado')
      } catch (error) {
        caught = error
      }
    })
    assert.equal(caught.status, 503)
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
  })

  test('F4: invalidate() durante una carga en vuelo no se pierde: la foto que aterriza después ya está vieja y la siguiente pregunta recarga', async ({
    assert,
  }) => {
    // Antes `invalidate()` ponía `#view = null` y la carga en curso lo
    // volvía a poner al terminar: la invalidación se perdía. Ahora es una
    // generación de instancia capturada ANTES de leer, como la global.
    const cache = new CatalogCache()
    const inFlight = cache.view()
    cache.invalidate()
    await inFlight
    assert.isFalse(cache.loaded, 'la foto cargada durante la invalidación no vale')
    const { queries } = await countQueries(() => cache.view())
    assert.equal(catalogReads(queries), 3, 'recarga')
    assert.isTrue(cache.loaded)
    // Lo mismo con la global.
    const other = new CatalogCache()
    const pending = other.view()
    invalidateAuthzCatalog()
    await pending
    assert.isFalse(other.loaded)
    // Y una invalidación con la foto ya cargada sigue funcionando.
    await cache.view()
    cache.invalidate()
    assert.isFalse(cache.loaded)
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

  test("catalogRevalidate: { everyMs } revalida como mucho una vez por ventana: un sync de OTRO proceso tarda hasta everyMs en verse (opt-in, documentado); el de ESTE se ve al instante", async ({
    assert,
  }) => {
    const driver = new DatabaseAuthorizationDriver({ catalogRevalidate: { everyMs: 40 } })
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))

    await linkNewPermissionByHand('docs:write')
    await bumpAuthzCatalogVersion()
    // Dentro de la ventana: ni revalida ni ve el cambio (la ventana acotada).
    const { queries } = await countQueries(async () => {
      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })
    assert.equal(versionChecks(queries), 0)
    await sleep(60)
    assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))

    // Un sync de este proceso no espera la ventana: invalida en memoria.
    await syncAuthzCatalog(CATALOG) // sin docs:write en editor: el vínculo a mano se poda
    assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
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
    assert.equal(versionChecks(queries), 2)
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

  test('toda consulta de carga y de revalidación lleva el deadline del driver', async ({ assert }) => {
    const driver = new DatabaseAuthorizationDriver({ timeoutMs: 250 })
    const { queries } = await countQueries(async () => {
      await driver.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
      await driver.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
    })
    assert.equal(catalogReads(queries), 3)
    assert.equal(versionChecks(queries), 2)
    assert.deepEqual(
      queries.map((q) => q.timeout),
      queries.map(() => 250)
    )
  })

  test("un revalidate que no es 'always' ni { everyMs: número > 0 } se rechaza al construir", ({ assert }) => {
    for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 'x']) {
      assert.throws(() => new CatalogCache({ revalidate: { everyMs: bad as any } }), /revalidate/)
    }
    assert.throws(() => new CatalogCache({ revalidate: 'sometimes' as any }), /revalidate/)
    assert.throws(() => new CatalogCache({ revalidate: {} as any }), /revalidate/)
  })
})
