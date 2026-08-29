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
import { CatalogCache, bumpAuthzCatalogVersion, invalidateAuthzCatalog, readAuthzCatalogVersion, withAuthzCatalogWrite } from '../src/catalog_cache.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { APP_SCOPE } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { countQueries } from './helpers/spies.js'
import { withTableMissing } from './database_driver.spec.js'
import { testEngine } from './helpers/app.js'

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

/** Escribe un permiso nuevo y su vínculo con `editor` POR FUERA del sync, con el cliente que le den (el `db` global o un trx). */
async function linkNewPermissionByHand(slug: string, client: { table(t: string): any; from(t: string): any } = db): Promise<void> {
  const role: any = (await client.from('authz_roles').where('slug', 'editor').select('uuid'))[0]
  const permissionUuid = uuidv7()
  await client.table('authz_permissions').insert({
    uuid: permissionUuid,
    slug,
    description: null,
    created_at: new Date(),
    updated_at: new Date(),
  })
  await client.table('authz_role_permissions').insert({
    uuid: uuidv7(),
    role_uuid: role.uuid,
    permission_uuid: permissionUuid,
    created_at: new Date(),
  })
}

/** Lo que deja un proceso ajeno que escribe `authz_*` bien (2E · H2): escritura y bump en UNA transacción, bump al final. */
function linkNewPermissionElsewhere(slug: string): Promise<void> {
  return withAuthzCatalogWrite((trx) => linkNewPermissionByHand(slug, trx))
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

  test('caso negativo: un cambio en authz_* SIN subir la versión NO se ve hasta invalidateAuthzCatalog() o withAuthzCatalogWrite()', async ({
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

  test('withAuthzCatalogWrite() sin invalidateAuthzCatalog(): el canal entre procesos basta (2D · F1, 2E · H2)', async ({
    assert,
  }) => {
    // Lo que deja un sync de OTRO proceso es esto: filas nuevas y la versión
    // subida en la misma transacción. Este proceso no recibe ninguna señal en
    // memoria; lo ve porque cada `view()` contrasta la fila y recarga si difiere.
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    const before = await readAuthzCatalogVersion()

    await linkNewPermissionElsewhere('docs:write')
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

  test('dos memos sobre la misma base: lo que withAuthzCatalogWrite() escribe en uno lo ve el otro en su siguiente pregunta, sin señal en memoria', async ({
    assert,
  }) => {
    // Dos instancias son dos procesos a efectos del memo: no comparten nada
    // en memoria. `a` escribe con el helper (escritura + versión en UNA
    // transacción, bump al final); `b` no recibe llamada alguna y aun así
    // responde con el catálogo nuevo (revalidación por la fila).
    const a = new DatabaseAuthorizationDriver()
    const b = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await a.grant(alice, 'editor', APP_SCOPE)
    assert.isTrue(await a.authorize(alice, 'docs:read', APP_SCOPE))
    assert.isTrue(await b.authorize(alice, 'docs:read', APP_SCOPE))
    const before = await readAuthzCatalogVersion()

    // "Otro proceso" retira el vínculo: solo la base cambia (datos + versión, juntos).
    const deleted = await withAuthzCatalogWrite(async (trx) => {
      const perm: any = (await trx.from('authz_permissions').where('slug', 'docs:read').select('uuid'))[0]
      return trx.from('authz_role_permissions').where('permission_uuid', perm.uuid).delete()
    })
    assert.equal(Number(deleted), 1, 'el helper devuelve lo que devuelve la escritura')
    assert.equal(await readAuthzCatalogVersion(), before + 1, 'una subida por escritura')
    assert.isTrue(a.catalog.loaded && b.catalog.loaded, 'ninguna señal en memoria: el contador del proceso no se tocó')
    assert.isFalse(await b.authorize(alice, 'docs:read', APP_SCOPE), 'b recarga por la versión, no por el contador')
    assert.isFalse(await a.authorize(alice, 'docs:read', APP_SCOPE))
  })

  test('H2: bumpAuthzCatalogVersion exige el trx de la transacción que escribe: sin cliente, con el db global o con un objeto cualquiera ⇒ 500 E_AUTHZ_CONFIG y la versión no cambia', async ({
    assert,
  }) => {
    // Auditor 2 (2E). Un bump con el `db` global desde dentro de una
    // transacción del consumidor se confirmaba ANTES que la escritura: otro
    // proceso recargaba los datos viejos con la versión nueva y no volvía a
    // revalidar jamás (fail-open permanente, verificado con dos procesos).
    const before = await readAuthzCatalogVersion()
    for (const [label, client] of [
      ['sin cliente', undefined],
      ['null', null],
      ['db global', db],
      ['objeto sin isTransaction', { from: () => {}, table: () => {} }],
      ['isTransaction: false', { from: () => {}, table: () => {}, isTransaction: false }],
      ['un string', 'trx'],
    ] as Array<[string, unknown]>) {
      try {
        await bumpAuthzCatalogVersion(client as any)
        assert.fail(`${label}: debería haber rechazado`)
      } catch (error: any) {
        assert.equal(error.status, 500, label)
        assert.equal(error.code, 'E_AUTHZ_CONFIG', label)
        assert.include(error.message, 'withAuthzCatalogWrite', label)
      }
    }
    assert.equal(await readAuthzCatalogVersion(), before, 'nada subió')
    // Con el trx de verdad, sube.
    await db.transaction((trx) => bumpAuthzCatalogVersion(trx))
    assert.equal(await readAuthzCatalogVersion(), before + 1)
  })

  test('H2: withAuthzCatalogWrite sube la versión como ÚLTIMA sentencia de la MISMA transacción; si la escritura lanza no se confirma nada, la versión no sube y el error sale tal cual', async ({
    assert,
  }) => {
    const before = await readAuthzCatalogVersion()
    const { queries } = await countQueries(() => linkNewPermissionElsewhere('docs:write'))
    const at = (pattern: RegExp) => queries.findIndex((q) => pattern.test(q.sql))
    const insertLink = at(/insert into [`"]?authz_role_permissions/i)
    const bump = at(/update [`"]?authz_catalog_version/i)
    const commit = queries.reduce((last, q, i) => (/^\s*commit/i.test(q.sql) ? i : last), -1)
    assert.isAbove(insertLink, -1, 'la escritura del consumidor pasó por la transacción')
    assert.isAbove(bump, insertLink, 'el bump va DESPUÉS de la escritura')
    if (commit !== -1) assert.isAbove(commit, bump, 'y ANTES del commit')
    assert.equal(await readAuthzCatalogVersion(), before + 1)

    // La escritura del consumidor lanza: se revierte todo y su error es el suyo.
    const mine = new Error('mi seeder falló')
    let caught: any
    try {
      await withAuthzCatalogWrite(async (trx) => {
        await linkNewPermissionByHand('docs:zzz', trx)
        throw mine
      })
    } catch (error) {
      caught = error
    }
    assert.strictEqual(caught, mine)
    assert.equal(await readAuthzCatalogVersion(), before + 1, 'la versión no sube con la transacción revertida')
    assert.lengthOf(await db.from('authz_permissions').where('slug', 'docs:zzz'), 0, 'nada se confirmó')
    // Y quien no es función es 500 E_AUTHZ_CONFIG.
    let bad: any
    try {
      await withAuthzCatalogWrite('nope' as any)
    } catch (error) {
      bad = error
    }
    assert.equal(bad?.code, 'E_AUTHZ_CONFIG')
  })

  test('K12: un error SQL tragado dentro de fn envenena la transacción en PostgreSQL ⇒ 503 E_AUTHZ_BACKEND_UNAVAILABLE con status (nunca el error crudo de pg); en MySQL y SQLite la transacción sigue y se confirma', async ({
    assert,
  }) => {
    // 2.5-B · K12 (auditor 🟡 3). Un seeder que se come con `try/catch` un
    // error de SQL dentro de `withAuthzCatalogWrite` y sigue escribiendo:
    // en PostgreSQL la transacción está abortada (`25P02`) y el UPDATE
    // siguiente lanza el error CRUDO de `pg` —sin `status`, con el SQL
    // dentro— que cruzaba la frontera del paquete; en MySQL y SQLite el
    // motor no aborta la transacción y la escritura se confirma. Lo que se
    // fija: PG lo clasifica (503 con la causa), y la divergencia queda
    // escrita aquí y en el README (no la tapa nadie).
    const before = await readAuthzCatalogVersion()
    const role: any = (await db.from('authz_roles').where('slug', 'editor').select('uuid', 'rank'))[0]
    let caught: any
    let resolved = false
    try {
      await withAuthzCatalogWrite(async (trx) => {
        try {
          await trx.from('authz_no_existe').select('*')
        } catch {
          // El consumidor se traga el fallo de SQL y sigue.
        }
        await trx.from('authz_roles').where('uuid', role.uuid).update({ rank: 7 })
      })
      resolved = true
    } catch (error) {
      caught = error
    }
    const after: any = (await db.from('authz_roles').where('uuid', role.uuid).select('rank'))[0]
    if (testEngine() === 'pg') {
      assert.isFalse(resolved, 'PostgreSQL: la transacción abortada no se confirma')
      assert.equal(caught?.status, 503, `PG: ${caught?.message}`)
      assert.equal(caught?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
      assert.equal(String(caught?.cause?.code), '25P02', 'la causa es el error de pg (transacción abortada)')
      assert.notInclude(String(caught?.message), 'authz_roles', 'el SQL del consumidor no cruza en el mensaje')
      assert.equal(Number(after.rank), Number(role.rank), 'revertido')
      assert.equal(await readAuthzCatalogVersion(), before, 'la versión no sube')
    } else {
      assert.isTrue(resolved, `${testEngine()}: la transacción sigue viva y se confirma (${caught?.message ?? ''})`)
      assert.equal(Number(after.rank), 7, 'confirmado')
      assert.equal(await readAuthzCatalogVersion(), before + 1, 'y la versión sube')
    }
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

  test('I1: sin la fila de authz_catalog_version (id = 1) toda pregunta es 503 E_AUTHZ_BACKEND_UNAVAILABLE («migración 2.0 no aplicada»): ni versión 0, ni el memo viejo, ni una carga en frío', async ({
    assert,
  }) => {
    // Auditor ⚪7 (2E). El invariante 14 decía «sin fila de versión legible ⇒
    // 503» y el código devolvía 0: fail-closed de verdad, con el mensaje que
    // dice qué falta.
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    const row: any = (await db.from('authz_catalog_version').where('id', 1))[0]
    await db.from('authz_catalog_version').where('id', 1).delete()
    try {
      const expected = { status: 503, code: 'E_AUTHZ_BACKEND_UNAVAILABLE' }
      for (const [label, call] of [
        ['memo caliente', () => driver.authorize(alice, 'docs:read', APP_SCOPE)],
        ['memo frío', () => new DatabaseAuthorizationDriver().authorize(alice, 'docs:read', APP_SCOPE)],
        ['readAuthzCatalogVersion', () => readAuthzCatalogVersion()],
      ] as Array<[string, () => Promise<unknown>]>) {
        try {
          await call()
          assert.fail(`${label}: debería haber lanzado`)
        } catch (error: any) {
          assert.equal(error.status, expected.status, `${label}: ${error.message}`)
          assert.equal(error.code, expected.code, label)
          assert.include(error.message, 'migración', label)
        }
      }
    } finally {
      await db.table('authz_catalog_version').insert(row)
    }
    assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE), 'con la fila de vuelta, responde')
  })

  test('I3: catalog compartido junto a catalogRevalidate es 500 E_AUTHZ_CONFIG al construir, en ambos drivers (la política es la del memo compartido; no se ignora en silencio)', ({
    assert,
  }) => {
    // Auditor ⚪11 (2E). `new Driver({ catalog: sharedEveryMs, catalogRevalidate: 'always' })`
    // usaba la ventana del compartido y el `'always'` del config no se aplicaba ni avisaba.
    const shared = new CatalogCache({ revalidate: { everyMs: 40 } })
    const builds: Array<[string, () => unknown]> = [
      ['database', () => new DatabaseAuthorizationDriver({ catalog: shared, catalogRevalidate: 'always' })],
      [
        'openfga',
        () =>
          new OpenFgaAuthorizationDriver({
            apiUrl: 'http://127.0.0.1:9',
            storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
            holderTypes: { users: 'user' },
            catalog: shared,
            catalogRevalidate: { everyMs: 10 },
          }),
      ],
    ]
    for (const [label, build] of builds) {
      try {
        build()
        assert.fail(`${label}: debería haber lanzado`)
      } catch (error: any) {
        assert.equal(error.status, 500, `${label}: ${error.message}`)
        assert.equal(error.code, 'E_AUTHZ_CONFIG', label)
        assert.include(error.message, 'catalogRevalidate', label)
      }
    }
    // Compartir sin la otra opción sigue valiendo, y la política es la del memo.
    const a = new DatabaseAuthorizationDriver({ catalog: shared })
    assert.strictEqual(a.catalog, shared)
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

    await linkNewPermissionElsewhere('docs:write')
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

  test('H3: la ventana de { everyMs } se mide con reloj MONÓTONO: un Date.now que retrocede una hora no la alarga; con `now` inyectado la frontera es exacta', async ({
    assert,
  }) => {
    // Auditor 3 (2E). Con `Date.now()`, un salto del reloj de pared hacia
    // atrás (NTP, restauración de snapshot) dejaba la ventana abierta: tras
    // dos ventanas completas el proceso seguía sirviendo el permiso retirado.
    const driver = new DatabaseAuthorizationDriver({ catalogRevalidate: { everyMs: 40 } })
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    await linkNewPermissionElsewhere('docs:write')
    const wall = Date.now
    try {
      Date.now = () => wall() - 3_600_000
      await sleep(60)
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE), 'la ventana venció aunque el reloj de pared retrocediera')
    } finally {
      Date.now = wall
    }

    // Frontera exacta con el reloj inyectado (solo tests): 39 ms no revalida, 40 sí.
    let tick = 0
    const cache = new CatalogCache({ revalidate: { everyMs: 40 }, now: () => tick })
    const clocked = new DatabaseAuthorizationDriver({ catalog: cache })
    const bob = { type: 'users', uuid: uuidv7() }
    await clocked.grant(bob, 'editor', APP_SCOPE)
    assert.isFalse(await clocked.authorize(bob, 'docs:zzz', APP_SCOPE)) // carga (checkedAt = 0)
    await linkNewPermissionElsewhere('docs:zzz')
    tick = 39
    const { queries: inside } = await countQueries(async () => assert.isFalse(await clocked.authorize(bob, 'docs:zzz', APP_SCOPE)))
    assert.equal(versionChecks(inside), 0)
    tick = 40
    const { queries: outside } = await countQueries(async () => assert.isTrue(await clocked.authorize(bob, 'docs:zzz', APP_SCOPE)))
    assert.equal(versionChecks(outside), 1)
    assert.throws(() => new CatalogCache({ now: 'reloj' as any }), /now/)
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
