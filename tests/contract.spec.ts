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
import { APP_SCOPE } from '../src/types.js'
import { AuthorizationBackendError } from '../src/errors.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import {
  OpenFgaAuthorizationDriver,
  provisionOpenFgaStore,
} from '../src/drivers/openfga_driver.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'

runAuthorizationDriverContract({
  name: 'database',
  makeDriver: () => new DatabaseAuthorizationDriver(),
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

const openFgaTestUrl = process.env.OPENFGA_TEST_URL
if (openFgaTestUrl) {
  let fgaDriver: OpenFgaAuthorizationDriver
  let storeCounter = 0

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
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }],
        roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
      })
      storeCounter += 1
      const { storeId, modelId } = await provisionOpenFgaStore(
        openFgaTestUrl,
        `regrant-${storeCounter}`,
        TEST_HOLDER_TYPES
      )
      driver = new OpenFgaAuthorizationDriver({
        apiUrl: openFgaTestUrl,
        storeId,
        modelId,
        holderTypes: TEST_HOLDER_TYPES,
      })
      alice = { type: 'users', uuid: uuidv7() }
    })

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
    async function withFailingRead(fn: () => Promise<void>): Promise<void> {
      const client = (driver as any).client
      const original = client.read.bind(client)
      client.read = async () => {
        throw new Error('read caído')
      }
      try {
        await fn()
      } finally {
        client.read = original
      }
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

      await driver.grant(alice, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() + 3_600_000),
      })
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })
  })

  runAuthorizationDriverContract({
    name: 'openfga',
    makeDriver: () => fgaDriver,
    seedCatalog: (catalog) => syncAuthzCatalog(catalog),
    // Store NUEVO por test: aislamiento total de los hechos. El catálogo
    // sigue siendo local (split: catálogo en SQL, hechos en FGA).
    cleanup: async () => {
      await cleanAuthzTables()
      storeCounter += 1
      const { storeId, modelId } = await provisionOpenFgaStore(
        openFgaTestUrl,
        `contract-${storeCounter}`,
        TEST_HOLDER_TYPES
      )
      fgaDriver = new OpenFgaAuthorizationDriver({
        apiUrl: openFgaTestUrl,
        storeId,
        modelId,
        holderTypes: TEST_HOLDER_TYPES,
      })
    },
  })
}
