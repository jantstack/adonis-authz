/**
 * Unitarios del driver openfga que NO necesitan servidor: el cliente FGA se
 * sustituye por espías (sus propiedades son asignables a través del Proxy).
 * Lo que se juzga aquí es cómo el driver trata lo que el backend le devuelve,
 * no la semántica (eso es del contrato).
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import {
  OpenFgaAuthorizationDriver,
  correlateBatchResults,
  parseBindingId,
} from '../src/drivers/openfga_driver.js'
import { AuthorizationBackendError } from '../src/errors.js'
import { APP_SCOPE } from '../src/types.js'
import { withTableMissing } from './database_driver.spec.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'

function unreachableDriver() {
  return new OpenFgaAuthorizationDriver({
    apiUrl: 'http://127.0.0.1:9',
    storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    holderTypes: { users: 'user' },
  })
}

async function captureWarnings(fn: () => Promise<void>): Promise<string[]> {
  const lines: string[] = []
  const original = console.warn
  console.warn = (...args: unknown[]) => void lines.push(args.map(String).join(' '))
  try {
    await fn()
  } finally {
    console.warn = original
  }
  return lines
}

test.group('openfga — ids de binding que no se entienden', () => {
  test('parseBindingId rechaza lo que no tiene 2 o 3 partes válidas', ({ assert }) => {
    assert.deepEqual(parseBindingId('app|editor'), {
      scope: { type: 'app', uuid: null },
      slug: 'editor',
    })
    assert.deepEqual(parseBindingId('organization|0192-abc|org~editor'), {
      scope: { type: 'organization', uuid: '0192-abc' },
      slug: 'org:editor',
    })
    assert.isNull(parseBindingId('a|b|c|d'))
    assert.isNull(parseBindingId('editor'))
    // Partes con formato inválido tampoco son un binding del motor.
    assert.isNull(parseBindingId('organization|x#y|editor'))
    assert.isNull(parseBindingId('app|Editor'))
  })

  test('un id no parseable se registra y se cuenta, nunca se descarta en silencio (L0.16)', async ({
    assert,
  }) => {
    // Un binding que el driver no entiende es un hecho que EXISTE en el store
    // y que las enumeraciones no van a mostrar: alguien tiene que enterarse.
    const driver = unreachableDriver()
    const client = (driver as any).client
    client.listObjects = async () => ({
      objects: ['role_binding:a|b|c|d', 'role_binding:app|editor', 'role_binding:organization|x#y|editor'],
    })

    const warnings = await captureWarnings(async () => {
      assert.deepEqual(await driver.listRoles({ type: 'users', uuid: uuidv7() }, APP_SCOPE), ['editor'])
    })

    assert.equal(driver.diagnostics.unparseableBindings, 2)
    assert.lengthOf(warnings, 2)
    assert.include(warnings[0], 'a|b|c|d')
  })
})

test.group('openfga — el catálogo SQL caído también es un 503 (L0.11)', () => {
  test('grant con la tabla de roles inaccesible ⇒ AuthorizationBackendError, causa SQL', async ({
    assert,
  }) => {
    // El catálogo vive en SQL también con openfga: es una dependencia dura de
    // cada pregunta, y su caída se presentaba como error crudo de Lucid.
    const driver = unreachableDriver()
    let caught: any
    await withTableMissing('authz_roles', async () => {
      try {
        await driver.grant({ type: 'users', uuid: uuidv7() }, 'editor', APP_SCOPE)
        assert.fail('debería haber lanzado')
      } catch (error) {
        caught = error
      }
    })
    assert.instanceOf(caught, AuthorizationBackendError)
    assert.equal(caught.status, 503)
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    // La causa es el error SQL, no uno del SDK de FGA: el store ni se tocó.
    assert.notInclude(String(caught.cause?.message), 'ECONNREFUSED')
    assert.include(String(caught.cause?.message), 'authz_roles')
  })

  test('authorize con la tabla de permisos inaccesible ⇒ 503', async ({ assert }) => {
    const driver = unreachableDriver()
    let caught: any
    await withTableMissing('authz_permissions', async () => {
      try {
        await driver.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
        assert.fail('debería haber lanzado')
      } catch (error) {
        caught = error
      }
    })
    assert.equal(caught.status, 503)
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
  })
})

/**
 * Un backend que ACEPTA la conexión y nunca contesta es peor que uno caído:
 * `ECONNREFUSED` llega en milisegundos, pero un socket abierto y mudo retiene
 * la request hasta que alguien la mate (N6). El deadline cierra ese tercer
 * estado de verdad: vencido ⇒ 503 con código propio, en tiempo acotado.
 */
test.group('openfga — deadline (L0.13)', (group) => {
  let server: import('node:net').Server
  let port: number
  const sockets = new Set<import('node:net').Socket>()

  group.setup(async () => {
    const net = await import('node:net')
    server = net.createServer((socket) => {
      // Acepta y calla. El cliente se queda esperando la respuesta HTTP.
      sockets.add(socket)
      socket.on('error', () => {})
      socket.on('close', () => sockets.delete(socket))
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    port = (server.address() as import('node:net').AddressInfo).port
  })

  group.teardown(async () => {
    // `server.close()` espera a que los sockets abiertos terminen — y estos
    // no terminan nunca por diseño: hay que destruirlos primero.
    for (const socket of sockets) socket.destroy()
    await new Promise<void>((resolve) => server.close(() => resolve()))
  })

  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  test('authorize contra un servidor mudo ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT en menos de 1 s', async ({
    assert,
  }) => {
    const driver = new OpenFgaAuthorizationDriver({
      apiUrl: `http://127.0.0.1:${port}`,
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      holderTypes: { users: 'user' },
      timeoutMs: 200,
    })
    const started = Date.now()
    let caught: any
    try {
      await driver.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    const elapsed = Date.now() - started
    assert.instanceOf(caught, AuthorizationBackendError)
    assert.equal(caught.status, 503)
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_TIMEOUT')
    assert.isBelow(elapsed, 1_000, `tardó ${elapsed} ms`)
  }).timeout(30_000)

  test('las escrituras también tienen deadline', async ({ assert }) => {
    const driver = new OpenFgaAuthorizationDriver({
      apiUrl: `http://127.0.0.1:${port}`,
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      holderTypes: { users: 'user' },
      timeoutMs: 200,
    })
    const started = Date.now()
    let caught: any
    try {
      await driver.deny({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_TIMEOUT')
    assert.isBelow(Date.now() - started, 1_000)
  }).timeout(30_000)
})

/**
 * Lo que cada llamada al store DEBE llevar, fijado con un cliente falso:
 *  - `context.current_time` en TODOS los checks, denies incluidos (S17): en
 *    cuanto una tupla del camino tenga condición, un check sin `context`
 *    falla entero (400 → 503), y el modo facts (3b) mezcla deny y grant en un
 *    solo check.
 *  - `consistency: HIGHER_CONSISTENCY` por defecto en check/batchCheck/read/
 *    listObjects/listUsers (S11): con la caché de Check activada en el
 *    servidor, un revoke o un deny recién escritos tardan hasta 10 s en
 *    verse. El paquete promete "quitar el deny restaura": lo garantiza él.
 */
test.group('openfga — context y consistency en cada llamada (S17, S11)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  /** Cliente falso que anota cada llamada y contesta "nada". */
  function recordingDriver(options: { consistency?: 'higher_consistency' | 'minimize_latency' } = {}) {
    const driver = new OpenFgaAuthorizationDriver({
      apiUrl: 'http://127.0.0.1:9',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      holderTypes: { users: 'user' },
      ...options,
    })
    const calls: Array<{ method: string; body: any; options: any }> = []
    const client = (driver as any).client
    client.batchCheck = async (body: any, opts: any) => {
      calls.push({ method: 'batchCheck', body, options: opts })
      return {
        result: body.checks.map((c: any) => ({ allowed: false, correlationId: c.correlationId, request: c })),
      }
    }
    client.read = async (body: any, opts: any) => {
      calls.push({ method: 'read', body, options: opts })
      return { tuples: [] }
    }
    client.writeTuples = async (body: any, opts: any) => {
      calls.push({ method: 'writeTuples', body, options: opts })
      return {}
    }
    client.listObjects = async (body: any, opts: any) => {
      calls.push({ method: 'listObjects', body, options: opts })
      return { objects: [] }
    }
    client.listUsers = async (body: any, opts: any) => {
      calls.push({ method: 'listUsers', body, options: opts })
      return { users: [] }
    }
    return { driver, calls }
  }

  test('todo check (denies incluidos) lleva context.current_time; toda llamada HIGHER_CONSISTENCY', async ({
    assert,
  }) => {
    const { driver, calls } = recordingDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.authorize(alice, 'docs:read', APP_SCOPE)
    await driver.hasRole(alice, 'editor', APP_SCOPE)
    await driver.grant(alice, 'editor', APP_SCOPE)
    await driver.listRoles(alice, APP_SCOPE)
    await driver.listScopes(alice, 'docs:read')
    await driver.listSubjects('editor', APP_SCOPE)

    const batches = calls.filter((c) => c.method === 'batchCheck')
    // authorize = denies + roles; hasRole = 1 → al menos 3 lotes con checks.
    assert.isAtLeast(batches.length, 3)
    for (const batch of batches) {
      assert.isNotEmpty(batch.body.checks)
      for (const check of batch.body.checks) {
        assert.match(String(check.context?.current_time), /^\d{4}-\d{2}-\d{2}T/, JSON.stringify(check))
      }
    }
    // Y el de denies en concreto: es el que hoy iba sin context.
    const denyBatch = batches.find((b) => b.body.checks.some((c: any) => c.relation === 'denied'))
    assert.exists(denyBatch)

    for (const method of ['batchCheck', 'read', 'listObjects', 'listUsers']) {
      const ofMethod = calls.filter((c) => c.method === method)
      assert.isNotEmpty(ofMethod, method)
      for (const call of ofMethod) {
        assert.equal(call.options?.consistency, 'HIGHER_CONSISTENCY', `${method}: ${JSON.stringify(call.options)}`)
      }
    }
    // Las enumeraciones condicionadas también llevan el reloj.
    for (const call of calls.filter((c) => c.method === 'listObjects' || c.method === 'listUsers')) {
      assert.exists(call.body.context?.current_time, call.method)
    }
  })

  test("opt-out explícito: consistency 'minimize_latency' se envía tal cual", async ({ assert }) => {
    const { driver, calls } = recordingDriver({ consistency: 'minimize_latency' })
    await driver.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
    const batches = calls.filter((c) => c.method === 'batchCheck')
    assert.isNotEmpty(batches)
    for (const batch of batches) assert.equal(batch.options?.consistency, 'MINIMIZE_LATENCY')
  })

  test('cada check del lote lleva un correlationId propio, único dentro del lote (L0.14)', async ({
    assert,
  }) => {
    const { driver, calls } = recordingDriver()
    await driver.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
    for (const batch of calls.filter((c) => c.method === 'batchCheck')) {
      const ids = batch.body.checks.map((c: any) => c.correlationId)
      for (const id of ids) {
        // `typeof` primero: `String(undefined)` casaría con la regex.
        assert.typeOf(id, 'string')
        assert.match(id, /^[A-Za-z0-9-]{1,36}$/)
      }
      assert.lengthOf(new Set(ids), ids.length)
    }
  })
})

/**
 * L0.14: el SDK devuelve los resultados por lotes y en el orden en que llegan
 * las respuestas, no en el de los checks. Hoy los consumidores usan `.some()`
 * y no lo notan; `authorizeMany` (Fase 2) atribuiría un `true` al scope
 * equivocado. Se correlaciona por `correlationId` ANTES de que exista.
 */
test.group('openfga — correlateBatchResults (L0.14)', () => {
  const checks = [
    { user: 'user:a', relation: 'assignee', object: 'role_binding:app|editor', correlationId: '0' },
    { user: 'user:a', relation: 'assignee', object: 'role_binding:org|1|x', correlationId: '1' },
    { user: 'user:a', relation: 'assignee', object: 'role_binding:org|2|x', correlationId: '2' },
  ]

  test('una respuesta desordenada se alinea con los checks por correlationId', ({ assert }) => {
    const results = [
      { allowed: true, correlationId: '2', request: checks[2] },
      { allowed: false, correlationId: '0', request: checks[0] },
      { allowed: true, correlationId: '1', request: checks[1] },
    ]
    const aligned = correlateBatchResults(checks, results as any)
    assert.deepEqual(
      aligned.map((r: any) => [r.correlationId, r.allowed]),
      [
        ['0', false],
        ['1', true],
        ['2', true],
      ]
    )
  })

  test('misma cardinalidad pero un id duplicado y otro ausente ⇒ 500 E_AUTHZ_INTERNAL', ({ assert }) => {
    // El conteo por posición lo daba por bueno: tres pedidos, tres recibidos.
    const results = [
      { allowed: true, correlationId: '2', request: checks[2] },
      { allowed: true, correlationId: '2', request: checks[2] },
      { allowed: false, correlationId: '0', request: checks[0] },
    ]
    let caught: any
    try {
      correlateBatchResults(checks, results as any)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_INTERNAL')
  })

  test('un resultado con un id que nadie pidió ⇒ 500', ({ assert }) => {
    const results = [
      { allowed: false, correlationId: '0', request: checks[0] },
      { allowed: false, correlationId: '1', request: checks[1] },
      { allowed: false, correlationId: '2', request: checks[2] },
      { allowed: true, correlationId: 'ajeno', request: checks[2] },
    ]
    assert.throws(() => correlateBatchResults(checks, results as any), /ajeno/)
  })
})
