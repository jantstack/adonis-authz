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
} from '../src/openfga.js'
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

test.group('openfga — ids de binding que no se entienden', (group) => {
  // `listRoles` filtra por el catálogo (D5): el rol tiene que existir.
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

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
    client.read = async () => ({
      tuples: ['role_binding:a|b|c|d', 'role_binding:app|editor', 'role_binding:organization|x#y|editor'].map(
        (object) => ({ key: { user: 'user:u', relation: 'assignee', object } })
      ),
      continuation_token: '',
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
 *  - `consistency: HIGHER_CONSISTENCY` por defecto en check/batchCheck/read
 *    (S11): con la caché de Check activada en el
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

    for (const method of ['batchCheck', 'read']) {
      const ofMethod = calls.filter((c) => c.method === method)
      assert.isNotEmpty(ofMethod, method)
      for (const call of ofMethod) {
        assert.equal(call.options?.consistency, 'HIGHER_CONSISTENCY', `${method}: ${JSON.stringify(call.options)}`)
      }
    }
    // Las enumeraciones son `Read` (L0.7): ninguna llamada a ListObjects/ListUsers.
    assert.deepEqual(calls.filter((c) => c.method === 'listObjects' || c.method === 'listUsers'), [])
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

/**
 * `purgeScope` en openfga (N7, S6, B2): FGA no tiene FK ni "borrar todo lo de
 * este objeto". El driver lee por objeto EXACTO cada rol del nivel y cada
 * permiso (nada de ListObjects), borra en lotes ≤ 100 (límite del Write) y
 * al terminar demuestra que quedó a cero: si no puede, lanza. Un número
 * parcial que no lanza era el defecto (B2 del auditor).
 */
test.group('openfga — purgeScope demuestra cero o lanza', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [
        { slug: 'editor', scopeType: 'app', permissions: ['docs:read'] },
        { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read', 'docs:write'] },
        { slug: 'org-viewer', scopeType: 'organization', permissions: ['docs:read'] },
      ],
    })
  })

  /** Cliente falso con un store en memoria por objeto, paginado de 100 en 100. */
  function fakeStore(initial: Record<string, number>, options: { residue?: boolean } = {}) {
    const tuples = new Map<string, any[]>()
    for (const [object, count] of Object.entries(initial)) {
      tuples.set(
        object,
        Array.from({ length: count }, (_, i) => ({
          key: { user: `user:u${i}`, relation: object.startsWith('deny_') ? 'denied' : 'assignee', object },
        }))
      )
    }
    const reads: string[] = []
    const deletes: number[] = []
    const driver = unreachableDriver()
    const client = (driver as any).client
    client.read = async (body: any, opts: any) => {
      reads.push(body.object)
      const all = tuples.get(body.object) ?? []
      const from = Number(opts?.continuationToken ?? 0)
      const page = all.slice(from, from + 100)
      const next = from + 100 < all.length ? String(from + 100) : ''
      return { tuples: page, continuation_token: next }
    }
    client.deleteTuples = async (keys: any[]) => {
      deletes.push(keys.length)
      for (const key of keys) {
        const list = tuples.get(key.object) ?? []
        const idx = list.findIndex((t) => t.key.user === key.user)
        if (idx >= 0 && !options.residue) list.splice(idx, 1)
      }
      return {}
    }
    return { driver, reads, deletes }
  }

  test('lee por objeto exacto cada rol del nivel y cada permiso; borra en lotes ≤ 100; verifica cero', async ({
    assert,
  }) => {
    const orgUuid = uuidv7()
    const { driver, reads, deletes } = fakeStore({
      [`role_binding:organization|${orgUuid}|org-editor`]: 250,
      [`deny_binding:organization|${orgUuid}|docs~write`]: 5,
    })

    await driver.purgeScope({ type: 'organization', uuid: orgUuid })

    // Los cuatro objetos del nivel (2 roles de organization + 2 permisos), y
    // NUNCA el rol de app ni ningún ListObjects.
    const objects = new Set(reads)
    assert.deepEqual(
      [...objects].sort(),
      [
        `deny_binding:organization|${orgUuid}|docs~read`,
        `deny_binding:organization|${orgUuid}|docs~write`,
        `role_binding:organization|${orgUuid}|org-editor`,
        `role_binding:organization|${orgUuid}|org-viewer`,
      ]
    )
    assert.equal(deletes.reduce((a, b) => a + b, 0), 255)
    for (const size of deletes) assert.isAtMost(size, 100)
  })

  test('si tras borrar queda alguna tupla ⇒ 500 E_AUTHZ_PURGE_INCOMPLETE', async ({ assert }) => {
    const orgUuid = uuidv7()
    const { driver } = fakeStore({ [`role_binding:organization|${orgUuid}|org-editor`]: 3 }, { residue: true })
    let caught: any
    try {
      await driver.purgeScope({ type: 'organization', uuid: orgUuid })
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_PURGE_INCOMPLETE')
  })

  test('la raíz no se purga: 422', async ({ assert }) => {
    const { driver, reads } = fakeStore({})
    let caught: any
    try {
      await driver.purgeScope(APP_SCOPE)
    } catch (error) {
      caught = error
    }
    assert.equal(caught?.status, 422)
    assert.deepEqual(reads, [])
  })
})

/**
 * L0.7. Las tres enumeraciones (`listBindings` para listRoles/listRoleScopes/
 * listScopes, los denies de `listScopes` y `listSubjects`) van por `Read`
 * paginado: se consumen TODAS las páginas y la caducidad se filtra en cliente
 * por `condition.context.valid_until`. `ListObjects`/`ListUsers` cortan al
 * tope del servidor sin señal, y con los denies eso era fail-open. Aquí se
 * fija con un cliente falso lo que el contrato fija contra el servidor real.
 */
test.group('openfga — enumeraciones por Read paginado (L0.7)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [
        { slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'docs:write'] },
        { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read', 'docs:write'] },
      ],
    })
  })

  /**
   * Store falso: filtra por user/relation/prefijo de objeto como hace `Read`
   * y pagina de `pageSize` en `pageSize` con un token opaco.
   */
  function fakeReadStore(tuples: Array<{ user: string; relation: string; object: string; validUntil?: Date }>) {
    const driver = unreachableDriver()
    // Las enumeraciones consultan el árbol (D8): aquí todo cuelga de app.
    ;(driver as any).resolveAncestors = async () => [APP_SCOPE]
    const client = (driver as any).client
    const reads: Array<{ filter: any; options: any }> = []
    client.read = async (filter: any, opts: any) => {
      reads.push({ filter, options: opts })
      const all = tuples.filter(
        (t) =>
          (!filter.user || t.user === filter.user) &&
          (!filter.relation || t.relation === filter.relation) &&
          (filter.object.endsWith(':') ? t.object.startsWith(filter.object) : t.object === filter.object)
      )
      const from = Number(opts?.continuationToken ?? 0)
      const size = opts?.pageSize ?? all.length
      const page = all.slice(from, from + size).map((t) => ({
        key: {
          user: t.user,
          relation: t.relation,
          object: t.object,
          ...(t.validUntil
            ? { condition: { name: 'not_expired', context: { valid_until: t.validUntil.toISOString() } } }
            : {}),
        },
      }))
      return { tuples: page, continuation_token: from + size < all.length ? String(from + size) : '' }
    }
    client.listObjects = async () => {
      throw new Error('ListObjects no debe usarse en las enumeraciones')
    }
    client.listUsers = async () => {
      throw new Error('ListUsers no debe usarse en las enumeraciones')
    }
    return { driver, reads }
  }

  test('listRoleScopes consume todas las páginas: 250 bindings ⇒ 3 lecturas de 100 y 250 scopes', async ({
    assert,
  }) => {
    const alice = { type: 'users', uuid: uuidv7() }
    const orgs = Array.from({ length: 250 }, () => uuidv7())
    const { driver, reads } = fakeReadStore(
      orgs.map((uuid) => ({
        user: `user:${alice.uuid}`,
        relation: 'assignee',
        object: `role_binding:organization|${uuid}|org-editor`,
      }))
    )

    const scopes = await driver.listRoleScopes(alice, 'organization')

    assert.lengthOf(scopes, 250)
    assert.deepEqual(scopes.map((s) => s.uuid).sort(), [...orgs].sort())
    assert.lengthOf(reads, 3)
    for (const read of reads) {
      assert.equal(read.options.pageSize, 100)
      assert.equal(read.options.consistency, 'HIGHER_CONSISTENCY')
      assert.deepEqual(read.filter, { user: `user:${alice.uuid}`, relation: 'assignee', object: 'role_binding:' })
    }
    assert.deepEqual(
      reads.map((r) => r.options.continuationToken),
      [undefined, '100', '200']
    )
  })

  test('la caducidad se filtra en cliente: una tupla con valid_until pasado no se lista; una futura sí', async ({
    assert,
  }) => {
    const alice = { type: 'users', uuid: uuidv7() }
    const live = uuidv7()
    const dead = uuidv7()
    const { driver } = fakeReadStore([
      {
        user: `user:${alice.uuid}`,
        relation: 'assignee',
        object: `role_binding:organization|${live}|org-editor`,
        validUntil: new Date(Date.now() + 60_000),
      },
      {
        user: `user:${alice.uuid}`,
        relation: 'assignee',
        object: `role_binding:organization|${dead}|org-editor`,
        validUntil: new Date(Date.now() - 60_000),
      },
      { user: `user:${alice.uuid}`, relation: 'assignee', object: 'role_binding:app|editor' },
      {
        user: `user:${dead}`,
        relation: 'assignee',
        object: 'role_binding:app|editor',
        validUntil: new Date(Date.now() - 1),
      },
    ])

    assert.deepEqual((await driver.listRoleScopes(alice, 'organization')).map((s) => s.uuid), [live])
    assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), ['editor'])
    // listSubjects: el holder caducado tampoco aparece.
    assert.deepEqual(await driver.listSubjects('editor', APP_SCOPE), [alice])
  })

  test('los denies de listScopes se leen enteros: 205 denies de ruido no esconden el relevante', async ({
    assert,
  }) => {
    // Es el mecanismo exacto del fail-open: el filtro por permiso es en
    // cliente, así que la lista de denies tiene que ser completa.
    const alice = { type: 'users', uuid: uuidv7() }
    const orgA = uuidv7()
    const orgB = uuidv7()
    const noise = Array.from({ length: 205 }, () => ({
      user: `user:${alice.uuid}`,
      relation: 'denied',
      object: `deny_binding:organization|${uuidv7()}|docs~read`,
    }))
    const { driver, reads } = fakeReadStore([
      ...noise,
      { user: `user:${alice.uuid}`, relation: 'denied', object: `deny_binding:organization|${orgB}|docs~write` },
      { user: `user:${alice.uuid}`, relation: 'assignee', object: `role_binding:organization|${orgA}|org-editor` },
      { user: `user:${alice.uuid}`, relation: 'assignee', object: `role_binding:organization|${orgB}|org-editor` },
    ])

    const scopes = await driver.listScopes(alice, 'docs:write')

    assert.deepEqual(scopes.map((s) => s.uuid), [orgA])
    // 206 denies ⇒ 3 páginas; los bindings, 1.
    assert.lengthOf(reads.filter((r) => r.filter.relation === 'denied'), 3)
    assert.lengthOf(reads.filter((r) => r.filter.relation === 'assignee'), 1)
  })

  test('listSubjects lee por objeto exacto y traduce el tipo FGA al morph name; lo que no es un holder se cuenta', async ({
    assert,
  }) => {
    const driver = unreachableDriver()
    const client = (driver as any).client
    const a = uuidv7()
    const b = uuidv7()
    const filters: any[] = []
    client.read = async (filter: any) => {
      filters.push(filter)
      return {
        tuples: [
          { key: { user: `user:${a}`, relation: 'assignee', object: 'role_binding:app|editor' } },
          { key: { user: `user:${b}`, relation: 'assignee', object: 'role_binding:app|editor' } },
          // Un userset y un tipo fuera del mapa: no son holders del motor.
          { key: { user: `group:g#member`, relation: 'assignee', object: 'role_binding:app|editor' } },
          { key: { user: `robot:${a}`, relation: 'assignee', object: 'role_binding:app|editor' } },
        ],
        continuation_token: '',
      }
    }

    const warnings = await captureWarnings(async () => {
      const holders = await driver.listSubjects('editor', APP_SCOPE)
      assert.deepEqual(holders, [
        { type: 'users', uuid: a },
        { type: 'users', uuid: b },
      ])
    })

    assert.deepEqual(filters, [{ relation: 'assignee', object: 'role_binding:app|editor' }])
    assert.equal(driver.diagnostics.unparseableBindings, 2)
    assert.lengthOf(warnings, 2)
  })

  test('el driver no contiene ninguna llamada a listObjects ni listUsers (guardia de fuente)', async ({
    assert,
  }) => {
    // El plan lo fija como `grep -c listObjects … = 0`. Aquí, ejecutable: un
    // call-site nuevo que vuelva a ListObjects/ListUsers reabre L0.7.
    const { readFile } = await import('node:fs/promises')
    const source = await readFile(new URL('../src/drivers/openfga_driver.ts', import.meta.url), 'utf8')
    assert.notMatch(source, /\.listObjects\s*\(/)
    assert.notMatch(source, /\.listUsers\s*\(/)
    assert.notMatch(source, /streamedListObjects/)
  })
})

/**
 * D1 (invariante 5). Un `batchCheck` puede devolver 200 con un `error` por
 * check (`input_error`, `internal_error`…). En la fase de roles de `authorize`
 * y en `hasRole` ese error se colapsaba en `false`: una caída parcial del
 * backend disfrazada de "sin permiso". Los denies ya fallaban cerrado; ahora
 * las dos fases lo tratan igual: error ⇒ 503 con el error del servidor como
 * causa, nunca un `false`.
 */
test.group('openfga — un error por check en batchCheck es 503, nunca false (D1)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  /** Cliente falso: los denies responden limpio; los checks de rol, con error. */
  function driverWithCheckErrors(failing: (check: any) => boolean) {
    const driver = unreachableDriver()
    const client = (driver as any).client
    client.batchCheck = async (body: any) => ({
      result: body.checks.map((c: any) =>
        failing(c)
          ? { allowed: false, correlationId: c.correlationId, request: c, error: { input_error: 'validation_error', message: 'relation not found' } }
          : { allowed: false, correlationId: c.correlationId, request: c }
      ),
    })
    return driver
  }

  test('authorize: error en un check de rol ⇒ 503 E_AUTHZ_BACKEND_UNAVAILABLE con causa', async ({
    assert,
  }) => {
    const driver = driverWithCheckErrors((c) => c.relation === 'assignee')
    let caught: any
    try {
      await driver.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.instanceOf(caught, AuthorizationBackendError)
    assert.equal(caught.status, 503)
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    assert.include(JSON.stringify(caught.cause), 'relation not found')
  })

  test('authorize: error en un check de deny ⇒ 503 (no un false silencioso)', async ({ assert }) => {
    const driver = driverWithCheckErrors((c) => c.relation === 'denied')
    let caught: any
    try {
      await driver.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught?.status, 503)
    assert.equal(caught?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
  })

  test('hasRole: error en el check ⇒ 503', async ({ assert }) => {
    const driver = driverWithCheckErrors(() => true)
    let caught: any
    try {
      await driver.hasRole({ type: 'users', uuid: uuidv7() }, 'editor', APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught?.status, 503)
    assert.equal(caught?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
  })
})

/**
 * D2 (auditor H1). Con el deadline del paquete el llamante recibe 503 y sigue
 * con su vida, pero el SDK reintentaba en segundo plano (`maxRetry: 3`) y la
 * escritura aterrizaba DESPUÉS del error, sin evento `onWrite`: un privilegio
 * vivo sin rastro en la auditoría. Sin reintentos del SDK, lo que el paquete
 * dio por fallido no se reintenta a escondidas; el reintento es del llamante.
 */
test.group('openfga — el SDK no reintenta por su cuenta (D2)', () => {
  test('retryParams.maxRetry es 0 por defecto', ({ assert }) => {
    const driver = unreachableDriver()
    const config = (driver as any).client.configuration
    assert.equal(config.retryParams.maxRetry, 0)
  })

  test('los reintentos son opt-in explícito (retryParams en las opciones del driver)', ({ assert }) => {
    const driver = new OpenFgaAuthorizationDriver({
      apiUrl: 'http://127.0.0.1:9',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      holderTypes: { users: 'user' },
      retryParams: { maxRetry: 2, minWaitInMs: 10 },
    })
    const config = (driver as any).client.configuration
    assert.equal(config.retryParams.maxRetry, 2)
    assert.equal(config.retryParams.minWaitInMs, 10)
  })
})

/**
 * D5 (auditor H2, CR5). El catálogo es la única fuente de verdad de qué roles
 * existen: `database` no puede devolver un rol que no está en `authz_roles`
 * (el join lo excluye) y `openfga` respondía desde las tuplas, así que un rol
 * retirado del catálogo seguía apareciendo en `hasRole`/`listRoles`/
 * `listRoleScopes`/`listSubjects` en un driver y no en el otro. Ahora las
 * cuatro filtran por el catálogo (slug existente para ese `scope_type`): la
 * tupla huérfana queda en el store hasta `authz:reconcile` (3b), pero ya no
 * es una membresía.
 */
test.group('openfga — las lecturas de membresía filtran por el catálogo (D5)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [
        { slug: 'editor', scopeType: 'app', permissions: ['docs:read'] },
        { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] },
      ],
    })
  })

  function fakeStore(tuples: Array<{ user: string; relation: string; object: string }>) {
    const driver = unreachableDriver()
    const client = (driver as any).client
    const reads: any[] = []
    const checks: any[] = []
    client.read = async (filter: any) => {
      reads.push(filter)
      const all = tuples.filter(
        (t) =>
          (!filter.user || t.user === filter.user) &&
          (!filter.relation || t.relation === filter.relation) &&
          (filter.object.endsWith(':') ? t.object.startsWith(filter.object) : t.object === filter.object)
      )
      return { tuples: all.map((t) => ({ key: t })), continuation_token: '' }
    }
    client.batchCheck = async (body: any) => {
      checks.push(...body.checks)
      return {
        result: body.checks.map((c: any) => ({
          allowed: tuples.some((t) => t.user === c.user && t.relation === c.relation && t.object === c.object),
          correlationId: c.correlationId,
          request: c,
        })),
      }
    }
    return { driver, reads, checks }
  }

  test('un binding de un rol que no está en el catálogo no es membresía: hasRole false, listRoles/listRoleScopes sin él', async ({
    assert,
  }) => {
    const alice = { type: 'users', uuid: uuidv7() }
    const org = uuidv7()
    const { driver, checks } = fakeStore([
      { user: `user:${alice.uuid}`, relation: 'assignee', object: 'role_binding:app|editor' },
      { user: `user:${alice.uuid}`, relation: 'assignee', object: 'role_binding:app|fantasma' },
      { user: `user:${alice.uuid}`, relation: 'assignee', object: `role_binding:organization|${org}|fantasma` },
      // `editor` existe a nivel app, no a nivel organization: en la org no cuenta.
      { user: `user:${alice.uuid}`, relation: 'assignee', object: `role_binding:organization|${org}|editor` },
    ])
    ;(driver as any).resolveAncestors = async () => [APP_SCOPE]

    assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), ['editor'])
    assert.deepEqual(await driver.listRoles(alice, { type: 'organization', uuid: org }), [])
    assert.deepEqual(await driver.listRoleScopes(alice, 'organization'), [])
    assert.deepEqual((await driver.listRoleScopes(alice, 'app')).map((s) => s.uuid), [null])

    assert.isTrue(await driver.hasRole(alice, 'editor', APP_SCOPE))
    // La tupla existe (el check diría true): el catálogo manda.
    assert.isFalse(await driver.hasRole(alice, 'fantasma', APP_SCOPE))
    assert.isFalse(await driver.hasRole(alice, { slug: 'fantasma', scopeType: 'app' }, APP_SCOPE))
    assert.isFalse(await driver.hasRole(alice, 'fantasma', { type: 'organization', uuid: org }))
    // Y no se pregunta al backend por un rol que el catálogo no conoce.
    assert.deepEqual(checks.filter((c) => c.object.endsWith('|fantasma')), [])
  })

  test('listSubjects de un rol que no existe para ese nivel es [] sin leer el store', async ({ assert }) => {
    const a = uuidv7()
    const { driver, reads } = fakeStore([
      { user: `user:${a}`, relation: 'assignee', object: 'role_binding:app|fantasma' },
      { user: `user:${a}`, relation: 'assignee', object: `role_binding:organization|${uuidv7()}|editor` },
    ])
    assert.deepEqual(await driver.listSubjects('fantasma', APP_SCOPE), [])
    assert.deepEqual(await driver.listSubjects('editor', { type: 'organization', uuid: uuidv7() }), [])
    assert.deepEqual(reads, [])
  })
})

/**
 * D6 (CR6, tester H5). La rama de carrera de `grant` hacía `catch {` a secas:
 * cualquier fallo del write (un 400 de validación, un 5xx) se trataba como
 * "alguien escribió antes" y se reintentaba a ciegas, con la causa perdida.
 * Solo un 409 (duplicado) es una carrera; lo demás se propaga clasificado con
 * el error del SDK como `cause`. Y si tras la carrera la relectura no ve la
 * tupla y no hay objetivo explícito, es 503 con la receta — nunca una
 * escritura permanente a ciegas (sería L0.4 en una ventana estrecha).
 */
test.group('openfga — la carrera de grant solo es carrera con un duplicado (D6)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  /**
   * Errores con la forma del SDK. El duplicado real de OpenFGA v1.19 NO es un
   * 409: es un 400 con `apiErrorCode: 'write_failed_due_to_invalid_input'` y
   * "cannot write a tuple which already exists" (medido contra el servidor);
   * un 400 `validation_error` es otra cosa y no puede pasar por carrera.
   */
  function sdkError(kind: 'duplicate' | 409 | 400 | 503) {
    if (kind === 'duplicate') {
      return Object.assign(new Error('FGA API Validation Error: post write : cannot write a tuple which already exists'), {
        name: 'FgaApiValidationError',
        statusCode: 400,
        apiErrorCode: 'write_failed_due_to_invalid_input',
        apiErrorMessage: 'cannot write a tuple which already exists: user: user:x relation: assignee object: role_binding:app|editor',
      })
    }
    return Object.assign(new Error(`Request failed with status code ${kind}`), {
      name: kind === 400 ? 'FgaApiValidationError' : 'FgaApiError',
      statusCode: kind,
      ...(kind === 400 ? { apiErrorCode: 'validation_error', apiErrorMessage: 'relation not found' } : {}),
    })
  }

  /** Cliente falso: `read` vacío siempre; `writeTuples` falla como se le diga. */
  function racingDriver(writeFailures: Array<'duplicate' | 409 | 400 | null>) {
    const driver = unreachableDriver()
    const client = (driver as any).client
    const calls: string[] = []
    client.read = async () => {
      calls.push('read')
      return { tuples: [] }
    }
    client.writeTuples = async () => {
      calls.push('writeTuples')
      const failure = writeFailures.shift()
      if (failure) throw sdkError(failure)
      return {}
    }
    client.deleteTuples = async () => {
      calls.push('deleteTuples')
      return {}
    }
    return { driver, calls }
  }

  const alice = () => ({ type: 'users', uuid: uuidv7() })

  test('un write que falla con 400 no es una carrera: 503 con el FgaApiError como causa, sin reintento', async ({
    assert,
  }) => {
    const { driver, calls } = racingDriver([400])
    let caught: any
    try {
      await driver.grant(alice(), 'editor', APP_SCOPE, { expiresAt: null })
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.instanceOf(caught, AuthorizationBackendError)
    assert.equal(caught.status, 503)
    assert.equal(caught.cause?.statusCode, 400)
    assert.equal(caught.cause?.name, 'FgaApiValidationError')
    assert.equal(caught.cause?.apiErrorCode, 'validation_error')
    // read inicial + el write que falló: ni relectura ni segunda escritura.
    assert.deepEqual(calls, ['read', 'writeTuples'])
  })

  test('duplicado + relectura vacía + expiresAt omitido ⇒ 503 con la receta { expiresAt: null } y ninguna escritura', async ({
    assert,
  }) => {
    const { driver, calls } = racingDriver(['duplicate'])
    let caught: any
    try {
      await driver.grant(alice(), 'editor', APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 503)
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    assert.include(caught.message, '{ expiresAt: null }')
    assert.deepEqual(calls, ['read', 'writeTuples', 'read'])
  })

  test('duplicado (400 write_failed_due_to_invalid_input, o 409) + relectura vacía + expiresAt: null ⇒ camino largo (delete + write)', async ({
    assert,
  }) => {
    const { driver, calls } = racingDriver(['duplicate', 409])
    const outcome = await driver.grant(alice(), 'editor', APP_SCOPE, { expiresAt: null })
    assert.isTrue(outcome.existed)
    assert.isNull(outcome.expiresAt)
    assert.deepEqual(calls, ['read', 'writeTuples', 'read', 'writeTuples', 'deleteTuples', 'writeTuples'])
  })

  test('grant sin expiresAt con la lectura caída: el 503 trae la receta', async ({ assert }) => {
    const driver = unreachableDriver()
    const client = (driver as any).client
    client.read = async () => {
      throw sdkError(503)
    }
    let caught: any
    try {
      await driver.grant(alice(), 'editor', APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 503)
    assert.include(caught.message, '{ expiresAt: null }')
    assert.equal(caught.cause?.statusCode, 503)
  })
})

/**
 * D12 (auditor H7). `readAllTuples` seguía el `continuation_token` sin cota:
 * un servidor (o un proxy/caché delante) que devuelva siempre el mismo token
 * era un bucle infinito que ningún deadline cortaba (el deadline es por
 * llamada). Token repetido o más de 10.000 páginas ⇒ 500 `E_AUTHZ_INTERNAL`.
 * Y las tuplas malformadas (sin user/relation/object) se cuentan en
 * `diagnostics`, como los ids que no se entienden (L0.16, auditor H16).
 */
test.group('openfga — la paginación de Read está acotada (D12)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  test('un continuation_token que no avanza ⇒ 500 E_AUTHZ_INTERNAL en menos de 1 s', async ({ assert }) => {
    const driver = unreachableDriver()
    let reads = 0
    ;(driver as any).client.read = async () => {
      reads += 1
      return {
        tuples: [{ key: { user: 'user:u', relation: 'assignee', object: 'role_binding:app|editor' } }],
        continuation_token: 'siempre-el-mismo',
      }
    }
    const started = Date.now()
    let caught: any
    try {
      await driver.listRoles({ type: 'users', uuid: uuidv7() }, APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_INTERNAL')
    assert.isBelow(Date.now() - started, 1_000)
    assert.isBelow(reads, 10)
  })

  test('una tupla sin user/relation/object se cuenta en diagnostics y se registra, no se descarta en silencio', async ({
    assert,
  }) => {
    const driver = unreachableDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    ;(driver as any).client.read = async () => ({
      tuples: [
        { key: { user: `user:${alice.uuid}`, relation: 'assignee', object: 'role_binding:app|editor' } },
        { key: { user: `user:${alice.uuid}`, relation: 'assignee' } },
        { key: null },
      ],
      continuation_token: '',
    })
    const warnings = await captureWarnings(async () => {
      assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), ['editor'])
    })
    assert.equal(driver.diagnostics.unparseableBindings, 2)
    assert.lengthOf(warnings, 2)
  })
})

/**
 * D15 (auditor H15). Un holder cuyo morph name no está en `holderTypes` es
 * una contradicción de config (el modelo FGA no tiene ese tipo): 500 con
 * código propio, no un 500 mudo.
 */
test.group('openfga — holder type no declarado es E_AUTHZ_CONFIG (D15)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  test('authorize y grant con un morph fuera del mapa ⇒ 500 E_AUTHZ_CONFIG sin tocar el store', async ({
    assert,
  }) => {
    const driver = unreachableDriver()
    const calls: string[] = []
    const client = (driver as any).client
    for (const method of ['batchCheck', 'read', 'writeTuples', 'deleteTuples']) {
      client[method] = async () => void calls.push(method)
    }
    const robot = { type: 'robots', uuid: uuidv7() }
    for (const [label, call] of [
      ['authorize', () => driver.authorize(robot, 'docs:read', APP_SCOPE)],
      ['grant', () => driver.grant(robot, 'editor', APP_SCOPE)],
      ['deny', () => driver.deny(robot, 'docs:read', APP_SCOPE)],
      ['listRoles', () => driver.listRoles(robot, APP_SCOPE)],
    ] as Array<[string, () => Promise<unknown>]>) {
      let caught: any
      try {
        await call()
        assert.fail(`${label}: debería haber lanzado`)
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 500, `${label}: ${caught.message}`)
      assert.equal(caught.code, 'E_AUTHZ_CONFIG', label)
      assert.include(caught.message, 'robots')
    }
    assert.deepEqual(calls, [])
  })
})
