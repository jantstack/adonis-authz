/**
 * El juez, aplicado al driver que el paquete trae de serie.
 *
 * `runAuthorizationDriverContract` es la misma suite que se publica para que
 * un driver de terceros se pruebe a sí mismo — aquí la corre el paquete
 * contra `database`, sobre SQLite, sin app anfitriona.
 *
 * Si hay un OpenFGA a mano (`OPENFGA_TEST_URL`), el mismo juez se aplica
 * también a ese driver. En CI no hace falta: el contrato del driver por
 * defecto es lo que garantiza que la semántica no se rompe.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { runAuthorizationDriverContract } from '../src/testing/main.js'
import { resolveChainFrom } from '../src/testing/main.js'
import type { DriverCapabilities } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import { AuthorizationBackendError } from '../src/errors.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import {
  OpenFgaAuthorizationDriver,
  importAuthzFactsToOpenFga,
  openFgaAuthorizationModel,
  provisionOpenFgaStore,
} from '../src/openfga.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { invalidateAuthzCatalog } from '../src/catalog_cache.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { countCalls, withFailing } from './helpers/spies.js'
import { testEngine } from './helpers/app.js'
import { cleanSqlScopeTree, sqlScopeTree } from './helpers/sql_scope_tree.js'

/**
 * Lo que ambos drivers pueden hacer HOY. `exhaustiveLists: true` en los dos:
 * SQLite no tiene tope y el driver openfga enumera con `Read` paginado
 * (L0.7), que tampoco lo tiene. `truncationSignal: false` sigue siendo la
 * verdad: ningún driver del paquete trunca, así que ninguno tiene nada que
 * señalar.
 */
const CAPABILITIES_TODAY: DriverCapabilities = {
  hierarchyFacts: false,
  transactions: false,
  truncationSignal: false,
  singleCheckAuthorize: false,
  // 2.5 · J1: ambos drivers aceptan `withClock(now)`; el juez fija el instante.
  injectableClock: true,
  exhaustiveLists: true,
  listDenies: true,
  // 3B · B4: `database` purga un rol en una transacción; `openfga` lo dice con 500 hasta 3b.
  purgeRole: true,
}

runAuthorizationDriverContract({
  name: 'database',
  level: '2.2',
  capabilities: CAPABILITIES_TODAY,
  makeDriver: (tree) => new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) }),
  seedCatalog: (catalog) => syncAuthzCatalog(catalog),
  cleanup: cleanAuthzTables,
})

/**
 * El mismo juez sobre un driver que SOLO trae el puerto 2.0 (sin `listDenies`),
 * en `'2.1'` con `listDenies: false` (2E · I5): la cara `whenFalse` del par
 * —las primitivas que restan denies lo dicen con 500 `E_AUTHZ_UNSUPPORTED`—
 * se ejecuta de verdad, no solo se registra. Es lo que un driver de terceros
 * escrito para 2.0 vería al subir de nivel.
 */
runAuthorizationDriverContract({
  name: 'database (sin listDenies)',
  level: '2.2',
  capabilities: { ...CAPABILITIES_TODAY, listDenies: false },
  makeDriver: (tree) => {
    const view = Object.create(new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) }))
    Object.defineProperty(view, 'listDenies', { value: undefined, enumerable: false })
    return view
  },
  seedCatalog: (catalog) => syncAuthzCatalog(catalog),
  cleanup: cleanAuthzTables,
})

/**
 * El mismo juez con el árbol en SQL (2.5-B · K1): `demo_scopes` en el motor de
 * `TEST_DB`, leída con `hierarchicalScopeResolver` + `sqlDescendantsOf`. Solo
 * en los motores de servidor: es donde el tipo `uuid` (PG) y la collation por
 * defecto (MySQL) funden un alias del uuid con la fila real, lo que el árbol
 * en memoria no puede mostrar. Con `OPENFGA_TEST_URL`, también para `openfga`.
 */
const SQL_TREE_ENGINE = testEngine() === 'pg' || testEngine() === 'mysql'
if (SQL_TREE_ENGINE) {
  runAuthorizationDriverContract({
    name: 'database (árbol SQL)',
    level: '2.2',
    capabilities: CAPABILITIES_TODAY,
    makeTree: async () => sqlScopeTree(db),
    makeDriver: (tree) => new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) }),
    seedCatalog: (catalog) => syncAuthzCatalog(catalog),
    cleanup: async () => {
      await cleanAuthzTables()
      await cleanSqlScopeTree(db)
    },
  })
}

/**
 * Los holders son del consumidor, no del motor: el harness declara los suyos
 * y con ellos se genera el modelo FGA.
 */
const TEST_HOLDER_TYPES = { users: 'user', admins: 'admin' }

/**
 * Con el driver openfga hay una SEGUNDA dependencia en cada check. Que su
 * caída se note es una decisión, no un descuido: denegar en silencio durante
 * una caída deja a todo el mundo sin permisos sin decir por qué, y manda a
 * buscar un rol mal configurado que no existe. Se deniega igual; lo que
 * cambia es el diagnóstico.
 *
 * No necesita servidor: apunta a un puerto donde no hay nada escuchando.
 */
test.group('openfga — un backend inalcanzable se nota', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  function unreachableDriver() {
    return new OpenFgaAuthorizationDriver({
      apiUrl: 'http://127.0.0.1:9',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      holderTypes: { users: 'user' },
    })
  }

  test('authorize lanza un error del PAQUETE, no del SDK, con status 503', async ({ assert }) => {
    let caught: any
    try {
      await unreachableDriver().authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }

    // Tipo propio: el call-site nunca importa nada de @openfga/sdk para
    // distinguir "el backend no responde".
    assert.instanceOf(caught, AuthorizationBackendError)
    // 503 y no 500: la aplicación no está rota, falta una dependencia. Con el
    // status puesto, el manejador de excepciones responde solo — por eso el
    // consumidor no necesita escribir try/catch para estar a salvo.
    assert.equal(caught.status, 503)
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    // El error original no se pierde: queda como causa para el log.
    assert.exists(caught.cause)
  }).timeout(30_000)

  test('las escrituras también lo clasifican, no solo las lecturas', async ({ assert }) => {
    let caught: any
    try {
      await unreachableDriver().grant({ type: 'users', uuid: uuidv7() }, 'editor', APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.instanceOf(caught, AuthorizationBackendError)
    assert.equal(caught.status, 503)
  }).timeout(30_000)

  test('un error SEMÁNTICO sigue siendo 422, no se disfraza de caída', async ({ assert }) => {
    // El rol no existe en el catálogo: eso se resuelve en la base local, sin
    // tocar FGA. Confundirlo con "backend caído" mandaría a revisar la
    // infraestructura por un error de programación.
    let caught: any
    try {
      await unreachableDriver().grant({ type: 'users', uuid: uuidv7() }, 'no-existe', APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.notInstanceOf(caught, AuthorizationBackendError)
    assert.equal(caught.status, 422)
  })
})

/**
 * `holderTypes` es el mapa morph name → tipo FGA. Si dos morph names caen en
 * el MISMO tipo FGA, dos holders distintos son uno para el store: un grant a
 * `users:U` autoriza a `integrations:U`, `listSubjects` devuelve el morph
 * equivocado y un revoke borra al otro (invariante 4, L0.2). No hay servidor
 * al que preguntar: es contradicción de config y se rechaza al construir.
 */
test.group('openfga — holderTypes tiene que ser inyectivo', () => {
  const collapsed = { users: 'user', integrations: 'user' }

  test('el constructor del driver lanza 500 E_AUTHZ_CONFIG', ({ assert }) => {
    let caught: any
    try {
      new OpenFgaAuthorizationDriver({
        apiUrl: 'http://127.0.0.1:9',
        storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
        holderTypes: collapsed,
      })
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_CONFIG')
    assert.include(caught.message, "'user'")
  })

  test('el generador del modelo también, no solo el driver', ({ assert }) => {
    // Es el generador quien "sabe" del colapso (deduplica con un Set): que
    // publique el modelo sin quejarse era el silencio del defecto.
    let caught: any
    try {
      openFgaAuthorizationModel(collapsed)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_CONFIG')
  })

  test('un mapa vacío o con un tipo FGA mal formado también es config rota', ({ assert }) => {
    for (const bad of [{}, { users: '' }, { users: 'us er' }, { users: 'user#x' }]) {
      let caught: any
      try {
        new OpenFgaAuthorizationDriver({
          apiUrl: 'http://127.0.0.1:9',
          storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
          holderTypes: bad as any,
        })
        assert.fail(`${JSON.stringify(bad)}: debería haber lanzado`)
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 500, JSON.stringify(bad))
      assert.equal(caught.code, 'E_AUTHZ_CONFIG', JSON.stringify(bad))
    }
  })
})

const openFgaTestUrl = process.env.OPENFGA_TEST_URL
if (openFgaTestUrl) {
  // Alias con tipo `string`: el estrechamiento del `if` no llega a las
  // funciones declaradas (hoisted) de abajo.
  const apiUrl: string = openFgaTestUrl
  let storeCounter = 0

  /**
   * Cada test crea su store (aislamiento total de hechos) y hay que borrarlo:
   * antes de la Fase 0 nunca se hacía y el servidor local acumuló cientos.
   * El harness recuerda los ids y los borra en el siguiente `cleanup` y en el
   * teardown del grupo.
   */
  const createdStores: string[] = []
  async function deleteCreatedStores(): Promise<void> {
    const { OpenFgaClient } = await import('@openfga/sdk')
    while (createdStores.length) {
      const storeId = createdStores.pop()!
      await new OpenFgaClient({ apiUrl, storeId }).deleteStore()
    }
  }

  /** El id del binding de `editor` a nivel app como lo escribe 2.2: con el UUID del rol, no el slug (3A · A1). */
  async function editorBinding(): Promise<string> {
    const role: any = await db.from('authz_roles').where('slug', 'editor').where('scope_type', 'app').first()
    return `role_binding:app|${role.uuid}`
  }

  async function provisionTestStore(prefix: string): Promise<{ storeId: string; modelId: string }> {
    storeCounter += 1
    const store = await provisionOpenFgaStore(apiUrl, `${prefix}-${storeCounter}`, TEST_HOLDER_TYPES)
    createdStores.push(store.storeId)
    return store
  }

  /**
   * Promesa del README ("Operational"): si el rol desaparece del catálogo, el
   * binding que quedó en el store es una tupla HUÉRFANA y no puede conceder
   * nada. El catálogo es local y es la única fuente del mapa permiso→roles:
   * sin fila de rol no hay roles que consultar, así que `authorize` deniega
   * aunque la tupla siga viva en FGA. Y desde D5 tampoco es membresía:
   * `hasRole`/`listRoles` filtran por el catálogo, igual que `database`, así
   * que los dos drivers responden lo mismo. La tupla sigue en el store (lo
   * comprueba un cliente crudo): recogerla es trabajo de `authz:reconcile`
   * (3b), y es lo que acota la promesa de `purgeScope` al catálogo.
   */
  test.group('openfga — un rol retirado del catálogo deja una tupla huérfana', (group) => {
    let driver: OpenFgaAuthorizationDriver
    let alice: { type: string; uuid: string }

    group.each.setup(async () => {
      await cleanAuthzTables()
      await deleteCreatedStores()
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }],
        roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
      })
      const { storeId, modelId } = await provisionTestStore('orphan')
      driver = new OpenFgaAuthorizationDriver({
        apiUrl: openFgaTestUrl,
        storeId,
        modelId,
        holderTypes: TEST_HOLDER_TYPES,
      })
      alice = { type: 'users', uuid: uuidv7() }
    })

    group.teardown(deleteCreatedStores)

    test('rol borrado del catálogo: la tupla sigue en el store pero authorize deniega', async ({
      assert,
    }) => {
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      // El id del binding lleva el uuid del rol (3A): se toma ANTES de retirarlo.
      const binding = await editorBinding()

      // El consumidor retira el rol de su catálogo (los vínculos caen con él;
      // la tupla del binding NO: nadie la borra).
      const role: any = await db.from('authz_roles').where('slug', 'editor').first()
      await db.from('authz_role_permissions').where('role_uuid', role.uuid).delete()
      await db.from('authz_roles').where('uuid', role.uuid).delete()
      // Escribió `authz_*` por fuera del sync: es SU deber invalidar el memo
      // del catálogo (2A); sin esto la respuesta no cambia hasta el TTL, y
      // así lo fija `catalog_cache.spec`.
      invalidateAuthzCatalog()

      // La tupla huérfana sigue en el store...
      const { OpenFgaClient } = await import('@openfga/sdk')
      const raw = new OpenFgaClient({ apiUrl, storeId: (driver as any).client.configuration.storeId })
      const stored = await raw.read({ user: `user:${alice.uuid}`, relation: 'assignee', object: binding })
      assert.lengthOf(stored.tuples ?? [], 1)
      // ...pero no concede acceso ni es membresía: el catálogo manda en los dos drivers.
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      assert.isFalse(await driver.hasRole(alice, 'editor', APP_SCOPE))
      assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), [])
      assert.deepEqual(await driver.listRoleScopes(alice, 'app'), [])
      assert.deepEqual(await driver.listSubjects('editor', APP_SCOPE), [])
    })
  })

  /**
   * Refrescar una asignación en FGA obliga a delete+write (el servidor no
   * admite ambas sobre la misma tuple key en una transacción), y entre las dos
   * llamadas `authorize()` responde false. El driver evita esa ventana cuando
   * no hay nada que cambiar; estos casos fijan ese comportamiento.
   */
  test.group('openfga — re-grant sin ventana innecesaria', (group) => {
    let driver: OpenFgaAuthorizationDriver
    let alice: { type: string; uuid: string }

    group.each.setup(async () => {
      await cleanAuthzTables()
      await deleteCreatedStores()
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }],
        roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
      })
      const { storeId, modelId } = await provisionTestStore('regrant')
      driver = new OpenFgaAuthorizationDriver({
        apiUrl: openFgaTestUrl,
        storeId,
        modelId,
        holderTypes: TEST_HOLDER_TYPES,
      })
      alice = { type: 'users', uuid: uuidv7() }
    })

    group.teardown(deleteCreatedStores)
    test('re-grant idéntico deja el permiso intacto', async ({ assert }) => {
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('re-grant con la MISMA expiración deja el permiso intacto', async ({ assert }) => {
      const expiresAt = new Date(Date.now() + 3_600_000)
      await driver.grant(alice, 'editor', APP_SCOPE, { expiresAt })
      await driver.grant(alice, 'editor', APP_SCOPE, { expiresAt: new Date(expiresAt.getTime()) })
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('cambiar la expiración sí la actualiza', async ({ assert }) => {
      await driver.grant(alice, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() + 3_600_000),
      })
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))

      // A una ya vencida: el permiso desaparece.
      await driver.grant(alice, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() - 3_600_000),
      })
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))

      // Y de vuelta a una futura: reaparece.
      await driver.grant(alice, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() + 3_600_000),
      })
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('quitar la expiración es explícito (expiresAt: null); omitirla no la toca ni escribe nada', async ({
      assert,
    }) => {
      // L0.4. Antes "grant sin opciones" era "quitar la caducidad" y pagaba
      // el delete+write (con su ventana de denegación) cada vez. Ahora sobre
      // una asignación vigente es un no-op: cero escrituras.
      const expiresAt = new Date(Date.now() + 60_000)
      await driver.grant(alice, 'editor', APP_SCOPE, { expiresAt })

      const writes = countCalls((driver as any).client, ['writeTuples', 'deleteTuples', 'write'])
      try {
        const outcome = await driver.grant(alice, 'editor', APP_SCOPE)
        assert.isTrue(outcome.existed)
        assert.equal(outcome.expiresAt?.getTime(), expiresAt.getTime())
        assert.deepEqual(Object.values(writes.counts), [0, 0, 0])
      } finally {
        writes.restore()
      }

      const lifted = await driver.grant(alice, 'editor', APP_SCOPE, { expiresAt: null })
      assert.isNull(lifted.expiresAt)
      assert.equal(lifted.previousExpiresAt?.getTime(), expiresAt.getTime())
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    /**
     * El borde de la optimización: con un estado OBJETIVO conocido (`Date` o
     * `null`) la lectura es un atajo y si falla se escribe igual por el camino
     * largo. Sin `expiresAt` no hay objetivo sin leer: "preservar lo vigente"
     * exige saber qué hay, y asumir "permanente" sería exactamente L0.4 en
     * modo degradado. Ahí la caída del backend se reporta (503), no se tapa.
     */
    function withFailingRead<T>(fn: () => Promise<T>): Promise<T> {
      return withFailing((driver as any).client, 'read', fn)
    }

    test('si falla la lectura, un grant con objetivo explícito (null) se escribe igual', async ({
      assert,
    }) => {
      await withFailingRead(() => driver.grant(alice, 'editor', APP_SCOPE, { expiresAt: null }))
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('si falla la lectura, un grant CON expiración se escribe igual', async ({ assert }) => {
      await withFailingRead(() =>
        driver.grant(alice, 'editor', APP_SCOPE, { expiresAt: new Date(Date.now() + 3_600_000) })
      )
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('si falla la lectura, un grant SIN expiresAt es 503: no se puede preservar lo que no se pudo leer', async ({
      assert,
    }) => {
      await driver.grant(alice, 'editor', APP_SCOPE, { expiresAt: new Date(Date.now() + 3_600_000) })
      let caught: any
      try {
        await withFailingRead(() => driver.grant(alice, 'editor', APP_SCOPE))
        assert.fail('debería haber rechazado')
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 503)
      // Y la caducidad sigue donde estaba.
      const outcome = await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isNotNull(outcome.expiresAt)
    })

    test('una escritura concurrente no hace que se pierda esta expiración', async ({ assert }) => {
      // Simula la carrera: el read dice "no hay nada" y alguien escribe justo
      // después. El write directo choca y hay que caer al delete+write, o esta
      // expiración se descartaría en silencio y ganaría la del otro.
      const client = (driver as any).client
      const original = client.read.bind(client)
      client.read = async () => {
        client.read = original
        await driver.grant(alice, 'editor', APP_SCOPE, {
          expiresAt: new Date(Date.now() - 3_600_000),
        })
        return { tuples: [] }
      }

      try {
        await driver.grant(alice, 'editor', APP_SCOPE, {
          expiresAt: new Date(Date.now() + 3_600_000),
        })
      } finally {
        // Si el grant lanza antes de que el espía se auto-restaure, el
        // cliente quedaría roto para el resto del grupo.
        client.read = original
      }
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })
  })

  /**
   * S7. El importador escribía con `onDuplicateWrites: Ignore`, y en FGA la
   * condición NO es parte de la clave: una tupla permanente de una era
   * anterior se quedaba permanente aunque SQL dijera que caduca, y el conteo
   * decía "importado". Ahora un store con tuplas se rechaza salvo
   * `reconcile`, y reconcile hace delete+write cuando la condición difiere.
   */
  test.group('openfga:import — sin Ignore, con reconcile (S7)', (group) => {
    let storeId: string
    let modelId: string
    let alice: { type: string; uuid: string }

    group.each.setup(async () => {
      await cleanAuthzTables()
      await deleteCreatedStores()
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }],
        roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
      })
      ;({ storeId, modelId } = await provisionTestStore('import'))
      alice = { type: 'users', uuid: uuidv7() }
    })
    group.teardown(deleteCreatedStores)

    const importOptions = () => ({ apiUrl, storeId, modelId, holderTypes: TEST_HOLDER_TYPES })

    async function rawClient() {
      const { OpenFgaClient } = await import('@openfga/sdk')
      return new OpenFgaClient({ apiUrl, storeId, authorizationModelId: modelId })
    }

    test('store vacío: escribe todo sin Ignore y lo reporta como written', async ({ assert }) => {
      const sql = new DatabaseAuthorizationDriver()
      await sql.grant(alice, 'editor', APP_SCOPE, { expiresAt: new Date(Date.now() + 3_600_000) })
      await sql.grant({ type: 'users', uuid: uuidv7() }, 'editor', APP_SCOPE)
      await sql.grant({ type: 'users', uuid: uuidv7() }, 'editor', APP_SCOPE, { expiresAt: new Date(Date.now() - 1) })
      await sql.deny(alice, 'docs:read', APP_SCOPE)

      const report = await importAuthzFactsToOpenFga(importOptions())
      assert.deepEqual(report, { written: 3, updated: 0, unchanged: 0, extra: 0, deleted: 0, skippedExpired: 1, dryRun: false })

      const again = await importAuthzFactsToOpenFga({ ...importOptions(), reconcile: true })
      assert.deepEqual(again, { written: 0, updated: 0, unchanged: 3, extra: 0, deleted: 0, skippedExpired: 1, dryRun: false })
    })

    test('store con tuplas sin reconcile ⇒ E_AUTHZ_STORE_NOT_EMPTY y nada cambia', async ({ assert }) => {
      const client = await rawClient()
      const key = { user: `user:${alice.uuid}`, relation: 'assignee', object: await editorBinding() }
      await client.writeTuples([key])
      const sql = new DatabaseAuthorizationDriver()
      await sql.grant(alice, 'editor', APP_SCOPE, { expiresAt: new Date(Date.now() + 3_600_000) })

      let caught: any
      try {
        await importAuthzFactsToOpenFga(importOptions())
        assert.fail('debería haber rechazado')
      } catch (error) {
        caught = error
      }
      assert.equal(caught.code, 'E_AUTHZ_STORE_NOT_EMPTY')
      const stored = await client.read(key)
      assert.notExists((stored.tuples?.[0]?.key as any)?.condition)
    })

    test('reconcile: la tupla permanente pasa a llevar la caducidad de SQL (delete+write, updated)', async ({
      assert,
    }) => {
      const client = await rawClient()
      const key = { user: `user:${alice.uuid}`, relation: 'assignee', object: await editorBinding() }
      await client.writeTuples([key])
      const sql = new DatabaseAuthorizationDriver()
      const expiresAt = new Date(Date.now() + 3_600_000)
      await sql.grant(alice, 'editor', APP_SCOPE, { expiresAt })

      const dry = await importAuthzFactsToOpenFga({ ...importOptions(), reconcile: true, dryRun: true })
      assert.deepEqual(dry, { written: 0, updated: 1, unchanged: 0, extra: 0, deleted: 0, skippedExpired: 0, dryRun: true })
      assert.notExists(((await client.read(key)).tuples?.[0]?.key as any)?.condition)

      const report = await importAuthzFactsToOpenFga({ ...importOptions(), reconcile: true })
      assert.deepEqual(report, { written: 0, updated: 1, unchanged: 0, extra: 0, deleted: 0, skippedExpired: 0, dryRun: false })

      const stored = await client.read(key)
      assert.equal(
        Date.parse((stored.tuples?.[0]?.key as any)?.condition?.context?.valid_until),
        expiresAt.getTime()
      )
      const now = await client.check({ ...key, context: { current_time: new Date().toISOString() } })
      assert.isTrue(now.allowed)
      const later = await client.check({
        ...key,
        context: { current_time: new Date(Date.now() + 7_200_000).toISOString() },
      })
      assert.isFalse(later.allowed)
    })
    test('3A: un store con ids 1.x (slug en el id) no es leído por 2.2: reconcile --dry-run los cuenta como extra, --prune los borra, y el driver los registra como no parseables', async ({
      assert,
    }) => {
      // Decisión del dueño (2026-08-28 §2): el binding id lleva el uuid del
      // rol y NO hay comando de migración (no hay stores en producción). Un
      // store escrito por 1.x/2.0–2.1 tiene `role_binding:app|editor`; 2.2
      // escribe `role_binding:app|<uuid>`. Lo viejo no concede, no es
      // membresía, y el reconcile lo cuenta (`extra`) y con `prune` lo borra.
      const client = await rawClient()
      const legacy = { user: `user:${alice.uuid}`, relation: 'assignee', object: 'role_binding:app|editor' }
      const legacyDeny = { user: `user:${alice.uuid}`, relation: 'denied', object: 'deny_binding:app|docs~read' }
      await client.writeTuples([legacy, legacyDeny])
      const sql = new DatabaseAuthorizationDriver()
      await sql.grant(alice, 'editor', APP_SCOPE)

      const dry = await importAuthzFactsToOpenFga({ ...importOptions(), reconcile: true, dryRun: true })
      assert.deepEqual(dry, { written: 1, updated: 0, unchanged: 0, extra: 2, deleted: 0, skippedExpired: 0, dryRun: true })

      const fga = new OpenFgaAuthorizationDriver({ apiUrl, storeId, modelId, holderTypes: TEST_HOLDER_TYPES, logger: { warn() {} } })
      // Aún sin importar: el hecho de SQL no está en el store y el id viejo no cuenta para nada.
      assert.isFalse(await fga.authorize(alice, 'docs:read', APP_SCOPE))
      assert.isFalse(await fga.hasRole(alice, 'editor', APP_SCOPE))
      assert.deepEqual(await fga.listRoles(alice, APP_SCOPE), [])
      assert.deepEqual(await fga.listSubjects('editor', APP_SCOPE), [])
      assert.deepEqual(await fga.listDenies!(alice), [])
      assert.equal(fga.diagnostics.unparseableBindings, 2)

      const pruned = await importAuthzFactsToOpenFga({ ...importOptions(), reconcile: true, prune: true })
      assert.deepEqual(pruned, { written: 1, updated: 0, unchanged: 0, extra: 2, deleted: 2, skippedExpired: 0, dryRun: false })
      assert.lengthOf((await client.read(legacy)).tuples ?? [], 0)
      assert.lengthOf((await client.read({ ...legacy, object: await editorBinding() })).tuples ?? [], 1)
      assert.isTrue(await fga.authorize(alice, 'docs:read', APP_SCOPE))
      assert.deepEqual(await fga.listRoles(alice, APP_SCOPE), ['editor'])
    })

    test('reconcile converge: las tuplas que SQL no tiene se cuentan como extra y --prune las borra (D14)', async ({
      assert,
    }) => {
      // Auditor H3. Un store poblado (migración anterior, restore) puede tener
      // tuplas que SQL ya no tiene: un grant revocado en SQL, o un holder que
      // nunca estuvo. `--reconcile` solo miraba los hechos de SQL, así que
      // esas tuplas seguían concediendo y el reporte de ceros parecía "en
      // sync". Ahora se lee el store entero (`Read({})` paginado) y lo que
      // sobra se cuenta; con `prune` se borra y se reporta como `deleted`.
      const client = await rawClient()
      const zombie = { type: 'users', uuid: uuidv7() }
      const sql = new DatabaseAuthorizationDriver()
      await sql.grant(alice, 'editor', APP_SCOPE)
      await sql.grant(zombie, 'editor', APP_SCOPE)
      await sql.deny(zombie, 'docs:read', APP_SCOPE)
      assert.deepEqual(
        await importAuthzFactsToOpenFga(importOptions()),
        { written: 3, updated: 0, unchanged: 0, extra: 0, deleted: 0, skippedExpired: 0, dryRun: false }
      )
      // Una tupla que nunca estuvo en SQL, y un revoke + removeDeny en SQL.
      const foreign = { user: `user:${uuidv7()}`, relation: 'assignee', object: await editorBinding() }
      await client.writeTuples([foreign])
      await sql.revoke(zombie, 'editor', APP_SCOPE)
      await sql.removeDeny(zombie, 'docs:read', APP_SCOPE)

      const fga = new OpenFgaAuthorizationDriver({ apiUrl, storeId, modelId, holderTypes: TEST_HOLDER_TYPES })
      assert.isFalse(await fga.authorize(zombie, 'docs:read', APP_SCOPE)) // el deny huérfano sigue ahí

      const counted = await importAuthzFactsToOpenFga({ ...importOptions(), reconcile: true })
      assert.deepEqual(counted, { written: 0, updated: 0, unchanged: 1, extra: 3, deleted: 0, skippedExpired: 0, dryRun: false })
      // Sin prune, lo que sobra sigue concediendo (y denegando).
      assert.lengthOf((await client.read(foreign)).tuples ?? [], 1)

      const dry = await importAuthzFactsToOpenFga({ ...importOptions(), reconcile: true, prune: true, dryRun: true })
      assert.deepEqual(dry, { written: 0, updated: 0, unchanged: 1, extra: 3, deleted: 3, skippedExpired: 0, dryRun: true })
      assert.lengthOf((await client.read(foreign)).tuples ?? [], 1)

      const pruned = await importAuthzFactsToOpenFga({ ...importOptions(), reconcile: true, prune: true })
      assert.deepEqual(pruned, { written: 0, updated: 0, unchanged: 1, extra: 3, deleted: 3, skippedExpired: 0, dryRun: false })
      assert.lengthOf((await client.read(foreign)).tuples ?? [], 0)
      assert.isFalse(await fga.hasRole(zombie, 'editor', APP_SCOPE))
      assert.isFalse(await fga.authorize(zombie, 'docs:read', APP_SCOPE))
      assert.isTrue(await fga.authorize(alice, 'docs:read', APP_SCOPE))
      // Convergido: una segunda pasada no ve nada.
      assert.deepEqual(
        await importAuthzFactsToOpenFga({ ...importOptions(), reconcile: true, prune: true }),
        { written: 0, updated: 0, unchanged: 1, extra: 0, deleted: 0, skippedExpired: 0, dryRun: false }
      )
    })

    test('prune no tiene sentido sin reconcile: 500 E_AUTHZ_CONFIG', async ({ assert }) => {
      let caught: any
      try {
        await importAuthzFactsToOpenFga({ ...importOptions(), prune: true })
        assert.fail('debería haber rechazado')
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 500)
      assert.equal(caught.code, 'E_AUTHZ_CONFIG')
    })
  })

  /**
   * El mismo juez, con las mismas capacidades que `database`: las
   * enumeraciones van por `Read` paginado y no dependen del tope de
   * `ListObjects`/`ListUsers` del servidor. En ci.yml el segundo OpenFGA
   * corre con ese tope en 3 precisamente para demostrarlo: el caso de 1.200
   * y el de los denies de ruido (L0.7) pasan igual contra los dos.
   */
  if (SQL_TREE_ENGINE) {
    runAuthorizationDriverContract({
      name: 'openfga (árbol SQL)',
      level: '2.2',
      capabilities: { ...CAPABILITIES_TODAY, purgeRole: false },
      makeTree: async () => sqlScopeTree(db),
      makeDriver: async (tree) => {
        const { storeId, modelId } = await provisionTestStore('contract-sql')
        return new OpenFgaAuthorizationDriver({
          apiUrl: openFgaTestUrl,
          storeId,
          modelId,
          holderTypes: TEST_HOLDER_TYPES,
          resolveChain: resolveChainFrom(tree),
        })
      },
      seedCatalog: (catalog) => syncAuthzCatalog(catalog),
      cleanup: async () => {
        await cleanAuthzTables()
        await cleanSqlScopeTree(db)
        await deleteCreatedStores()
      },
    })
  }

  runAuthorizationDriverContract({
    name: 'openfga',
    level: '2.2',
    capabilities: { ...CAPABILITIES_TODAY, purgeRole: false },
    // Store NUEVO por test: aislamiento total de los hechos. El catálogo
    // sigue siendo local (split: catálogo en SQL, hechos en FGA).
    makeDriver: async (tree) => {
      const { storeId, modelId } = await provisionTestStore('contract')
      return new OpenFgaAuthorizationDriver({
        apiUrl: openFgaTestUrl,
        storeId,
        modelId,
        holderTypes: TEST_HOLDER_TYPES,
        resolveChain: resolveChainFrom(tree),
      })
    },
    seedCatalog: (catalog) => syncAuthzCatalog(catalog),
    cleanup: async () => {
      await cleanAuthzTables()
      await deleteCreatedStores()
    },
  })
}
