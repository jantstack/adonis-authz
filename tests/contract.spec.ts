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
  openFgaFactsModel,
  provisionOpenFgaStore,
} from '../src/openfga.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { invalidateAuthzCatalog } from '../src/catalog/catalog_cache.js'
import { AuthorizationManager } from '../src/manager.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { countCalls, withFailing } from './helpers/spies.js'
import { spyFgaClient } from './helpers/fga_spy.js'
import { testEngine } from './helpers/app.js'
import { cleanSqlScopeTree, sqlScopeTree } from './helpers/sql_scope_tree.js'

/**
 * Lo que ambos drivers pueden hacer HOY. `exhaustiveLists: true` en los dos:
 * SQLite no tiene tope y el driver openfga enumera con `Read` paginado
 * (L0.7), que tampoco lo tiene. `truncationSignal: false` sigue siendo la
 * verdad: ningún driver del paquete trunca, así que ninguno tiene nada que
 * señalar.
 */
/**
 * L-3 (panel `{trx}`, decisión del dueño «pool ≥ 2 declarado»): `database`
 * escribe en la transacción del llamante, y eso exige que la autoridad
 * (barrera, catálogo, árbol) lea por OTRA conexión mientras el llamante
 * sostiene la suya. En `:memory:` (pool 1/1) no hay otra, así que el harness
 * declara `false` —y el driver también (`transactionalWrites: false` en sus
 * opciones, que es lo que un despliegue con pool 1 hace)— y se juzga la cara
 * `whenFalse` (500 al instante); la cara `true` (rollback por CENSO) corre en
 * `sqlite-file`, PG y MySQL. Lo que `:memory:` haría con `true` (503 por la
 * barrera a `freezeTimeoutMs`) lo fija `database_transaction.spec.ts`.
 */
const TRANSACTIONAL_WRITES = testEngine() !== 'sqlite'

const CAPABILITIES_TODAY: DriverCapabilities = {
  hierarchyFacts: false,
  transactionalWrites: TRANSACTIONAL_WRITES,
  truncationSignal: false,
  singleCheckAuthorize: false,
  // 2.5 · J1: ambos drivers aceptan `withClock(now)`; el juez fija el instante.
  injectableClock: true,
  exhaustiveLists: true,
  listDenies: true,
  // 3B · B4: `database` purga un rol en una transacción; `openfga` no lo trae hasta 3b.
  purgeRole: true,
  // 3b-2j: `database` cuenta sus asignaciones vigentes; `openfga` solo en modo
  // `facts` (en `resolver` los bindings de un rol no se enumeran).
  countRoleAssignments: true,
  // 3E · R2: el cerrojo sobre la fila de `authz_catalog_version` serializa
  // las escrituras del catálogo en PostgreSQL y MySQL (`FOR UPDATE`), y ahí
  // el juez exige exactamente un ganador y 422 para el perdedor. SQLite
  // serializa bloqueando la BASE entera: el segundo escritor puede morir con
  // `SQLITE_BUSY` (503 legítimo), así que se declara `false` y se juzga solo
  // lo innegociable.
  serializedCatalogWrites: testEngine() === 'pg' || testEngine() === 'mysql',
  // 3b-2k · K1 · R2 (c): `database` (y `openfga` en modo `resolver`) resuelven
  // la cadena para decidir, así que un alias del uuid que el árbol funde con la
  // fila real encuentra sus hechos.
  canonicalScopeReads: true,
  // 3b-2e · E2 (panel 2, cruce 6): la membresía la resuelve el paquete con el
  // árbol del consumidor en LOS DOS drivers —también en `facts`—, y ningún
  // `list*` enumera herencia (invariante 7). Las dos son `false` y las dos
  // tienen su caso, que es lo que impide vender lo que no es.
  roleInheritanceNative: false,
  listObjectsInherited: false,
  // 3b-3b: ser el ORIGEN de `authz:reconcile`. `database` no lo trae a
  // propósito (sus hechos son `authz_*`); `openfga` sí (viven en el store).
  enumerateFacts: false,
}

runAuthorizationDriverContract({
  name: 'database',
  level: '2.2',
  capabilities: CAPABILITIES_TODAY,
  makeDriver: (tree) =>
    new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree), transactionalWrites: TRANSACTIONAL_WRITES }),
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
  // `serializedCatalogWrites` se declara `false` aquí porque su par cuelga de
  // la API de delegación, que sin `listDenies` no existe: la regla del juez
  // es declarar lo OBSERVABLE en este harness, no lo que hace el motor.
  capabilities: { ...CAPABILITIES_TODAY, listDenies: false, serializedCatalogWrites: false },
  makeDriver: (tree) => {
    const view = Object.create(
      new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree), transactionalWrites: TRANSACTIONAL_WRITES })
    )
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
    makeDriver: (tree) =>
      new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree), transactionalWrites: TRANSACTIONAL_WRITES }),
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
      // El gate del árbol (3b-2d) es del CONFIG y aquí no hay manager: lo que
      // se juzga es cómo se clasifica un backend que no contesta.
      acceptScopeDriftRisk: true,
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
    // publique el modelo sin quejarse era el silencio del defecto. Desde
    // 3b-2k · K2 el único generador es el de `facts` (c2r).
    let caught: any
    try {
      openFgaFactsModel(collapsed, ['docs:read'])
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

  /**
   * Store nuevo con el modelo **`facts` (c2r)** publicado para los permisos
   * que se le pasen (3b-2k · K2: `provisionOpenFgaStore` ya no puede publicar
   * el modelo del modo `resolver`, que no existe). Sin los permisos del
   * catálogo del caso, `can_<P>` no es una relación del modelo y el `Check`
   * sería un 400.
   */
  async function provisionTestStore(
    prefix: string,
    permissions: readonly string[]
  ): Promise<{ storeId: string; modelId: string }> {
    storeCounter += 1
    const store = await provisionOpenFgaStore(apiUrl, `${prefix}-${storeCounter}`, TEST_HOLDER_TYPES, permissions)
    createdStores.push(store.storeId)
    return store
  }

  /**
   * El driver `openfga` de un caso suelto (no del juez): store recién
   * provisionado, catálogo YA sincronizado en SQL y su proyección —más el
   * marcador de raíz de (c2r)— escrita en el store. `acceptScopeDriftRisk`
   * porque aquí el árbol lo mueve el propio test, no una transacción de
   * consumidor (el gate es del CONFIG, 3b-2e · E3).
   */
  async function factsDriverOver(
    prefix: string,
    catalog: any
  ): Promise<OpenFgaAuthorizationDriver> {
    const { storeId, modelId } = await provisionTestStore(prefix, catalog.permissions.map((p: any) => p.slug))
    const driver = new OpenFgaAuthorizationDriver({
      apiUrl,
      storeId,
      modelId,
      holderTypes: TEST_HOLDER_TYPES,
      acceptScopeDriftRisk: true,
      logger: { warn: () => {} },
    })
    // La proyección del catálogo (y el marcador `scope:app#rooted`): sin ella
    // ningún rol concede nada y el store entero deniega.
    await syncAuthzCatalog(catalog, { projection: driver.catalogProjection() })
    return driver
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
  test.group('openfga — un rol retirado del catálogo a mano deja una tupla huérfana', (group) => {
    let driver: OpenFgaAuthorizationDriver
    let alice: { type: string; uuid: string }

    group.each.setup(async () => {
      await cleanAuthzTables()
      await deleteCreatedStores()
      const catalog = {
        permissions: [{ slug: 'docs:read' }],
        roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
      }
      await syncAuthzCatalog(catalog)
      driver = await factsDriverOver('orphan', catalog)
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

      // ...y aquí los dos drivers **no** responden igual, y es lo que hay que
      // decir (3b-2k · K2). La MEMBRESÍA la filtra el catálogo LOCAL en los
      // dos, así que falla cerrado desde el primer instante:
      assert.isFalse(await driver.hasRole(alice, 'editor', APP_SCOPE))
      assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), [])
      assert.deepEqual(await driver.listRoleScopes(alice, 'app'), [])
      assert.deepEqual(await driver.listSubjects('editor', APP_SCOPE), [])
      // ...pero la DECISIÓN la toma el store, y ahí el mapa permiso→rol es la
      // PROYECCIÓN (`role:<uuid>#permits_<P>`), que este borrado a mano no
      // tocó: sigue concediendo. Es la contrapartida del `Check` único, y el
      // deber está escrito —quien escribe `authz_*` por su cuenta rehace la
      // proyección, igual que sube la versión del catálogo—.
      assert.isTrue(
        await driver.authorize(alice, 'docs:read', APP_SCOPE),
        'en `facts` el catálogo que decide es la proyección del store, no la fila que acabas de borrar'
      )
      // Y en cuanto se cumple ese deber, deniega.
      await driver.projectCatalogRole!(role.uuid)
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      assert.lengthOf(
        (await raw.read({ user: `user:${alice.uuid}`, relation: 'assignee', object: binding })).tuples ?? [],
        1,
        'el hecho sigue ahí: lo que se rehizo es la proyección, no los hechos'
      )
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
      const catalog = {
        permissions: [{ slug: 'docs:read' }],
        roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
      }
      await syncAuthzCatalog(catalog)
      driver = await factsDriverOver('regrant', catalog)
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
   * **El juez contra el driver `openfga`**, que desde 3b-2k · K2 **es** el
   * modo `facts` (3b-2e · E6). Fue el criterio de aceptación del lote 3b-2:
   * los mismos casos, sin tocarlos, contra un driver cuyo ÁRBOL vive en el
   * store. Hasta K2 había DOS harness openfga —el del modo `resolver` y
   * éste, detrás de `AUTHZ_CONTRACT_FACTS=1`—; con el modo viejo borrado
   * queda uno, y corre siempre que haya `OPENFGA_TEST_URL`.
   *
   * Las enumeraciones van por `Read` paginado y no dependen del tope de
   * `ListObjects`/`ListUsers` del servidor. En ci.yml el segundo OpenFGA
   * corre con ese tope en 3 precisamente para demostrarlo: el caso de 1.200
   * y el de los denies de ruido (L0.7) pasan igual contra los dos.
   *
   * Dos piezas que el 2c dejó anotadas y aquí existen:
   *   (a) el árbol del juez se ESPEJA en el driver (`onScopeAttached/Moved/
   *       Detached`) — lo hace el propio contrato cuando el harness declara
   *       `hierarchyFacts: true`;
   *   (b) `seedCatalog` pasa la PROYECCIÓN del driver, y el modelo se publica
   *       con los permisos de ESE catálogo — sin eso, en `facts` un rol
   *       retirado seguiría concediendo (quien filtra ya no es el catálogo
   *       local, es la proyección).
   */
  function factsHarness(name: string, makeTree?: () => Promise<any>) {
    let current: OpenFgaAuthorizationDriver | null = null
    let catalogNow: any = null
    return {
      name,
      level: '2.2' as const,
      capabilities: {
        ...CAPABILITIES_TODAY,
        hierarchyFacts: true,
        singleCheckAuthorize: true,
        purgeRole: true,
        serializedCatalogWrites: testEngine() === 'pg' || testEngine() === 'mysql',
        // 3b-2k · K1 · R2 (c): la decisión no pasa por el árbol, así que el
        // objeto del store lleva la ortografía del LLAMANTE y un alias no
        // encuentra sus hechos (fail-CLOSED). La escritura sí canoniza.
        canonicalScopeReads: false,
        // 3b-3b: en `facts` los hechos viven en el store, así que este driver
        // es el único que sabe entregarlos como hechos del puerto.
        enumerateFacts: true,
        // L-2/L-3 (panel `{trx}`): `openfga` no puede ser otra cosa que `false`
        // — una tupla no entra en una transacción SQL, no hay 2PC —; su cara
        // `whenFalse` (500 por llamada con cero llamadas) es la que se juzga.
        transactionalWrites: false,
      },
      ...(makeTree ? { makeTree } : {}),
      seedCatalog: async (catalog: any) => {
        catalogNow = catalog
        return syncAuthzCatalog(catalog, current ? { projection: current.catalogProjection() } : undefined)
      },
      makeDriver: async (tree: any) => {
        const { OpenFgaClient } = await import('@openfga/sdk')
        storeCounter += 1
        const store = await new OpenFgaClient({ apiUrl }).createStore({
          name: `contract-facts-${storeCounter}`,
        })
        createdStores.push(store.id!)
        // El modelo se publica con los permisos del catálogo de ESTE caso.
        const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
          openFgaFactsModel(TEST_HOLDER_TYPES, (catalogNow?.permissions ?? []).map((p: any) => p.slug))
        )
        const driver = new OpenFgaAuthorizationDriver({
          apiUrl,
          storeId: store.id!,
          modelId: model.authorization_model_id,
          holderTypes: TEST_HOLDER_TYPES,
          resolveChain: resolveChainFrom(tree),
          // El juez juzga el DRIVER; la outbox es del config (3b-2e · E3) y
          // aquí el árbol lo mueve la suite, no una transacción de consumidor.
          acceptScopeDriftRisk: true,
          logger: { warn: () => {} },
        })
        current = driver
        // Y la proyección del catálogo, ya con el store publicado.
        if (catalogNow) await syncAuthzCatalog(catalogNow, { projection: driver.catalogProjection() })
        return driver
      },
      cleanup: async () => {
        current = null
        await cleanAuthzTables()
        if (makeTree) await cleanSqlScopeTree(db)
        await deleteCreatedStores()
      },
    }
  }

  /**
   * **El único harness openfga desde 3b-2k · K2.** Hasta aquí eran dos: éste,
   * detrás de `AUTHZ_CONTRACT_FACTS=1` mientras las divergencias (b) y (c) de
   * R2 seguían rojas, y el del modo `resolver`, que ya no existe. Con K1 el
   * juez quedó verde contra `facts` en SQLite, PostgreSQL y MySQL —las dos
   * divergencias son **pares de capacidad con caso negativo**: el
   * *grant-only* con el resolutor caído (par `hierarchyFacts`) y el alias del
   * uuid que no encuentra sus hechos en lectura (par `canonicalScopeReads`)—,
   * así que corre siempre que haya `OPENFGA_TEST_URL`, sin variable de
   * entorno que lo esconda.
   */
  runAuthorizationDriverContract(
    factsHarness(
      SQL_TREE_ENGINE ? 'openfga (árbol SQL)' : 'openfga',
      SQL_TREE_ENGINE ? async () => sqlScopeTree(db) : undefined
    )
  )

  /* ── L-5 · `openfga` rechaza `{ transaction }` CON DIENTES (puerto de roles), contra el `:8101` ── */

  /**
   * L-5 (panel `{trx}`, veredicto (C); `panel-trx-juez.md` §7 · L-5). **Una
   * tupla de OpenFGA no puede entrar en una transacción SQL**: el store es
   * otro servicio, no hay 2PC, y `transactionalWrites` significa EXACTAMENTE
   * «los dos o ninguno». El driver `openfga` declara `false` y el paquete lo
   * hace cumplir por DOS puertas: la del manager (L-2) y, desde L-5, la del
   * DRIVER mismo (`manager.driver()` es la salida documentada de las
   * barreras y no puede convertirse en la forma de colar un `Write` que
   * finge ir en tu transacción — la misma lección que F-05 en L-0).
   *
   * Lo que el runner publicado (`whenFalse`) no puede hacer y aquí se hace:
   * el espía va sobre el cliente FGA REAL contra el `:8101` (ni un `Write`,
   * ni un `Read`, ni un `Check`), el rechazo se prueba también EN DIRECTO
   * al driver, y el arranque se prueba con el driver REAL.
   *
   * **Mutante M1** (quitar la puerta 1 del manager de roles): el caso «por
   * el manager» sigue VERDE porque el driver re-valida; sin la guarda del
   * driver, ROJO con un `Write` real en el store.
   */
  test.group('L-5 · openfga (roles) rechaza { transaction } con dientes: 500 E_AUTHZ_UNSUPPORTED con CERO llamadas al cliente FGA (espía sobre el cliente real), por el manager Y por el driver; y el arranque', (group) => {
    const L5_CATALOG = {
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    }
    let driver: OpenFgaAuthorizationDriver

    // `--tags=@l5` corre solo este lote (los títulos llevan comas y el filtro de Japa las parte).
    group.tap((t) => t.tags(['@l5']))
    group.each.setup(async () => {
      await cleanAuthzTables()
      await deleteCreatedStores()
      await syncAuthzCatalog(L5_CATALOG)
      driver = await factsDriverOver('l5-roles', L5_CATALOG)
    })
    group.teardown(deleteCreatedStores)

    /** Un manager de roles sobre el driver `openfga` REAL, con `onWrite` capturado. */
    function managerOverOpenFga(extra: Record<string, unknown> = {}, over: OpenFgaAuthorizationDriver = driver) {
      const events: unknown[] = []
      const manager = new AuthorizationManager({
        default: 'openfga',
        drivers: { openfga: () => over },
        holderTypes: TEST_HOLDER_TYPES,
        warnOnOptInSecurity: false,
        scopes: { acceptScopeDriftRisk: true },
        hooks: { onWrite: async (event: unknown) => void events.push(event) },
        ...extra,
      } as any)
      return { manager, events }
    }

    async function rejects(assert: any, run: () => Promise<unknown>, label: string): Promise<any> {
      try {
        await run()
      } catch (error: any) {
        assert.equal(error?.status, 500, `${label}: status de ${error?.message ?? error}`)
        assert.equal(error?.code, 'E_AUTHZ_UNSUPPORTED', `${label}: code de ${error?.message ?? error}`)
        return error
      }
      assert.fail(`ROJO: ${label} con { transaction } NO lanzó sobre openfga (¿escribió una tupla fingiendo ir en la transacción?)`)
    }

    test('por el MANAGER: grant/revoke/deny/removeDeny con { transaction } ⇒ 500 nombrando openfga y la operación, CERO llamadas al cliente FGA, sin onWrite; sin transaction la misma llamada entra (y el cliente sí se llama)', async ({
      assert,
    }) => {
      assert.strictEqual(driver.capabilities.transactionalWrites, false, 'openfga declara false EXPLÍCITO')
      const spy = spyFgaClient(driver)
      const { manager, events } = managerOverOpenFga()
      const alice = { type: 'users', uuid: uuidv7() }
      const trx = { from() {}, table() {}, isTransaction: true, connectionName: 'primary' }
      const writes: Array<[string, () => Promise<unknown>]> = [
        ['grant', () => manager.grant(alice, 'editor', APP_SCOPE, { transaction: trx })],
        ['revoke', () => manager.revoke(alice, 'editor', APP_SCOPE, { transaction: trx })],
        ['deny', () => manager.deny(alice, 'docs:read', APP_SCOPE, { transaction: trx })],
        ['removeDeny', () => manager.removeDeny(alice, 'docs:read', APP_SCOPE, { transaction: trx })],
      ]
      for (const [operation, run] of writes) {
        const error = await rejects(assert, run, `manager.${operation}`)
        assert.include(error.message, `'openfga'`, `${operation}: nombra el driver`)
        assert.include(error.message, operation, `${operation}: nombra la operación`)
        assert.include(error.message, 'transacción SQL', `${operation}: dice el porqué`)
      }
      assert.deepEqual(spy.calls, [], 'CERO llamadas al cliente FGA: ni un Write, ni un Read, ni un Check')
      assert.deepEqual(events, [], 'nada que auditar: no se llegó al driver')
      // Sin `{ transaction }` la MISMA llamada entra, y ahora SÍ se habla con el store.
      await manager.grant(alice, 'editor', APP_SCOPE)
      assert.isAbove(spy.total(), 0, 'sin transaction el driver escribe en el store')
      assert.isTrue(await manager.authorize(alice, 'docs:read', APP_SCOPE))
      assert.lengthOf(events, 1)
    })

    test('por el DRIVER en directo (manager.driver()): las cuatro con { transaction } ⇒ el MISMO 500 con CERO llamadas al cliente FGA (defensa en profundidad: el driver re-valida)', async ({
      assert,
    }) => {
      const spy = spyFgaClient(driver)
      const alice = { type: 'users', uuid: uuidv7() }
      const trx = { from() {}, table() {}, isTransaction: true, connectionName: 'primary' }
      const writes: Array<[string, () => Promise<unknown>]> = [
        ['grant', () => driver.grant(alice, 'editor', APP_SCOPE, { transaction: trx })],
        ['revoke', () => driver.revoke(alice, 'editor', APP_SCOPE, { transaction: trx })],
        ['deny', () => driver.deny(alice, 'docs:read', APP_SCOPE, { transaction: trx })],
        ['removeDeny', () => driver.removeDeny(alice, 'docs:read', APP_SCOPE, { transaction: trx })],
      ]
      for (const [operation, run] of writes) {
        const error = await rejects(assert, run, `driver.${operation}`)
        assert.include(error.message, operation, `${operation}: nombra la operación`)
        assert.include(error.message, 'transacción SQL', `${operation}: dice el porqué`)
      }
      assert.deepEqual(spy.calls, [], 'CERO llamadas al cliente FGA por el camino del driver')
      // El store no tiene la tupla: la escritura NO ocurrió «fuera de la transacción» en silencio.
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      spy.reset()
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isAbove(spy.total(), 0)
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('ARRANQUE: requireTransactionalWrites: true + default openfga (driver REAL) ⇒ 500 E_AUTHZ_CONFIG al RESOLVER (driver(), authorize, grant sin transaction) y cero llamadas al cliente; default database (capaz) + openfga solo REGISTRADO ⇒ arranca y la factory de openfga no se invoca', async ({
      assert,
    }) => {
      const spy = spyFgaClient(driver)
      const alice = { type: 'users', uuid: uuidv7() }
      const strict = managerOverOpenFga({ requireTransactionalWrites: true }).manager
      for (const [label, run] of [
        ['driver()', () => strict.driver()],
        ['authorize', () => strict.authorize(alice, 'docs:read', APP_SCOPE)],
        ['grant sin transaction', () => strict.grant(alice, 'editor', APP_SCOPE)],
      ] as Array<[string, () => Promise<unknown>]>) {
        let caught: any
        try {
          await run()
          assert.fail(`ROJO: ${label} resolvió el driver openfga con requireTransactionalWrites: true`)
        } catch (error) {
          caught = error
        }
        assert.equal(caught?.status, 500, `${label}: ${caught?.message}`)
        assert.equal(caught?.code, 'E_AUTHZ_CONFIG', label)
        assert.include(caught.message, `'openfga'`, `${label}: nombra el driver`)
        assert.include(caught.message, 'transactionalWrites', `${label}: nombra la capacidad`)
      }
      assert.deepEqual(spy.calls, [], 'no arrancar es no hablar con el store')

      // La puerta 2 no inutiliza un driver que solo está REGISTRADO: con
      // `default: 'database'` (capaz) el despliegue arranca y la factory de
      // `openfga` ni se invoca (lo que tumbó el «falla al construirse» del roadmap).
      let openFgaFactoryCalls = 0
      const mixed = new AuthorizationManager({
        default: 'database',
        drivers: {
          database: () => new DatabaseAuthorizationDriver({}),
          openfga: () => {
            openFgaFactoryCalls += 1
            return driver
          },
        },
        holderTypes: TEST_HOLDER_TYPES,
        warnOnOptInSecurity: false,
        requireTransactionalWrites: true,
      } as any)
      const resolved = await mixed.driver()
      assert.strictEqual(resolved.capabilities?.transactionalWrites, true, 'database declara true (default)')
      await mixed.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await mixed.authorize(alice, 'docs:read', APP_SCOPE))
      assert.equal(openFgaFactoryCalls, 0, 'un driver solo registrado no se construye ni se juzga')
    })
  })
}
