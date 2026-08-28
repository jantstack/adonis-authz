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
import { runAuthorizationDriverContract } from '../src/testing/main.js'
import { resolveAncestorsFrom } from '../src/testing/main.js'
import type { DriverCapabilities } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import { AuthorizationBackendError } from '../src/errors.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import {
  OpenFgaAuthorizationDriver,
  openFgaAuthorizationModel,
  provisionOpenFgaStore,
} from '../src/drivers/openfga_driver.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { withFailing } from './helpers/spies.js'

/**
 * Lo que ambos drivers pueden hacer HOY. `truncationSignal: false` en openfga
 * es la verdad actual (L0.7): el par rojo→verde que lo cambia es de Fase 1.
 */
const CAPABILITIES_TODAY: DriverCapabilities = {
  hierarchyFacts: false,
  transactions: false,
  truncationSignal: false,
  singleCheckAuthorize: false,
  injectableClock: false,
  exhaustiveLists: false,
}

runAuthorizationDriverContract({
  name: 'database',
  level: '2.0',
  // SQLite no tiene tope de resultados: las listas grandes son exhaustivas.
  capabilities: { ...CAPABILITIES_TODAY, exhaustiveLists: true },
  makeDriver: (tree) => new DatabaseAuthorizationDriver({ resolveAncestors: resolveAncestorsFrom(tree) }),
  seedCatalog: (catalog) => syncAuthzCatalog(catalog),
  cleanup: cleanAuthzTables,
})

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

  async function provisionTestStore(prefix: string): Promise<{ storeId: string; modelId: string }> {
    storeCounter += 1
    const store = await provisionOpenFgaStore(apiUrl, `${prefix}-${storeCounter}`, TEST_HOLDER_TYPES)
    createdStores.push(store.storeId)
    return store
  }

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

    test('quitar la expiración de una asignación que la tenía', async ({ assert }) => {
      await driver.grant(alice, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() + 60_000),
      })
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    /**
     * El borde que importa de la optimización: la lectura es un ATAJO, nunca
     * una condición para escribir. Si no se puede leer hay que escribir igual
     * — el manager ya habrá notificado 'granted' al hook de auditoría, así que
     * un no-op silencioso aquí deja el log diciendo lo contrario que FGA.
     */
    function withFailingRead(fn: () => Promise<void>): Promise<void> {
      return withFailing((driver as any).client, 'read', fn)
    }

    test('si falla la lectura, un grant SIN expiración se escribe igual', async ({ assert }) => {
      await withFailingRead(() => driver.grant(alice, 'editor', APP_SCOPE))
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('si falla la lectura, un grant CON expiración se escribe igual', async ({ assert }) => {
      await withFailingRead(() =>
        driver.grant(alice, 'editor', APP_SCOPE, { expiresAt: new Date(Date.now() + 3_600_000) })
      )
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('si falla la lectura sobre una asignación existente, la refresca', async ({ assert }) => {
      await driver.grant(alice, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() - 3_600_000),
      })
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))

      await withFailingRead(() => driver.grant(alice, 'editor', APP_SCOPE))
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
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
   * Tope de resultados del servidor de test (`OPENFGA_LIST_MAX_RESULTS`; en
   * ci.yml el segundo OpenFGA corre con 3). Sin la variable, el default del
   * servidor: 1.000. El juez prueba la frontera exacta con ese número de
   * tuplas; Fase 1 (L0.7) probará el "una más".
   */
  const listMaxResults = process.env.OPENFGA_LIST_MAX_RESULTS
    ? Number(process.env.OPENFGA_LIST_MAX_RESULTS)
    : 1_000

  runAuthorizationDriverContract({
    name: 'openfga',
    level: '2.0',
    capabilities: CAPABILITIES_TODAY,
    limits: { listMaxResults },
    // Store NUEVO por test: aislamiento total de los hechos. El catálogo
    // sigue siendo local (split: catálogo en SQL, hechos en FGA).
    makeDriver: async (tree) => {
      const { storeId, modelId } = await provisionTestStore('contract')
      return new OpenFgaAuthorizationDriver({
        apiUrl: openFgaTestUrl,
        storeId,
        modelId,
        holderTypes: TEST_HOLDER_TYPES,
        resolveAncestors: resolveAncestorsFrom(tree),
      })
    },
    seedCatalog: (catalog) => syncAuthzCatalog(catalog),
    cleanup: async () => {
      await cleanAuthzTables()
      await deleteCreatedStores()
    },
  })
}
