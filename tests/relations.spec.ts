/**
 * Unidad de `relations/` (Fase 4, lote 4-2): `defineRelationsConfig` y la
 * fachada `RelationsManager` (F-05, `assertWrite` puro, `actor`, `membersOf`).
 * Corre sin servidor ni base: es puerto + config + doble en memoria.
 */
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { RelationsManager } from '../src/relations/manager.js'
import { makeRelationsDriver, contractRelationsConfig } from '../src/testing/relations_contract.js'
import {
  AuthorizationBackendError,
  AuthorizationBackendTimeoutError,
  AuthorizationConfigError,
  PurgeIncompleteError,
  markPartialWrite,
} from '../src/errors.js'
import { AuthorizationManager } from '../src/manager.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import type { RelationsDriverCapabilities } from '../src/types.js'

/**
 * Recoge lo que el motor manda a `console.error` mientras corre `fn` (el
 * helper de `tests/manager.spec.ts:33`, duplicado a propósito: fuera de una
 * app con logger el registro del fallo del hook cae a `console.error`, y
 * capturarlo afirma que el fallo SE REPORTA —tragárselo no es ocultarlo—).
 */
async function captureErrorLog(fn: () => Promise<void>): Promise<string[]> {
  const lines: string[] = []
  const original = console.error
  console.error = (...args: unknown[]) => void lines.push(args.map(String).join(' '))
  try {
    await fn()
  } finally {
    console.error = original
  }
  return lines
}

const CAPS: RelationsDriverCapabilities = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: false,
  injectableClock: true,
  // Doble en memoria (L-2/L-4): no escribe en ninguna transacción, así que declara `false` y se le juzga esa cara; la `true` la juzga el driver `database` REAL en pool ≥ 2 (`relations_database.spec.ts`).
  transactionalWrites: false,
}

function managerWith(options?: ConstructorParameters<typeof RelationsManager>[2]) {
  const config = contractRelationsConfig()
  const driver = makeRelationsDriver({ config, capabilities: CAPS })
  return new RelationsManager(driver, config, options)
}

function catch422(fn: () => unknown): any {
  try {
    fn()
    throw new Error('no lanzó')
  } catch (e) {
    return e
  }
}

test.group('defineRelationsConfig — validación', () => {
  test('config válida devuelve un objeto congelado con isDeclared/hasType', ({ assert }) => {
    const config = defineRelationsConfig({
      objectTypes: [{ type: 'document', relations: [{ name: 'owner' }, { name: 'viewer', includes: ['owner'] }] }],
      holderTypes: ['user'],
    })
    assert.isTrue(config.hasType('document'))
    assert.isTrue(config.isDeclared('document', 'viewer'))
    assert.isFalse(config.isDeclared('document', 'assignee'))
    assert.isFalse(config.hasType('folder'))
  })

  test('⚪4 · objectType que duplica un tipo reservado (role_binding/scope/role/group) ⇒ 422', ({ assert }) => {
    for (const type of ['role_binding', 'scope', 'role', 'group', 'deny_binding']) {
      const e = catch422(() => defineRelationsConfig({ objectTypes: [{ type, relations: [{ name: 'x' }] }] }))
      assert.equal(e.status, 422, type)
      assert.equal(e.code, 'E_AUTHZ_RELATION_CONFIG', type)
    }
  })

  test('⚪4 · objectType que colisiona con un holder type ⇒ 422', ({ assert }) => {
    const e = catch422(() =>
      defineRelationsConfig({ objectTypes: [{ type: 'user', relations: [{ name: 'x' }] }], holderTypes: ['user'] })
    )
    assert.equal(e.code, 'E_AUTHZ_RELATION_CONFIG')
  })

  test('⚪4 · relación con nombre reservado (parent/assignee) o prefijo (can_) ⇒ 422', ({ assert }) => {
    for (const name of ['parent', 'assignee', 'rooted', 'can_read', 'permits_x', 'denied_y']) {
      const e = catch422(() => defineRelationsConfig({ objectTypes: [{ type: 'document', relations: [{ name }] }] }))
      assert.equal(e.code, 'E_AUTHZ_RELATION_CONFIG', name)
    }
  })

  test('includes tiene que referir una relación del MISMO tipo (sin from) ⇒ 422', ({ assert }) => {
    const e = catch422(() =>
      defineRelationsConfig({ objectTypes: [{ type: 'document', relations: [{ name: 'viewer', includes: ['owner'] }] }] })
    )
    assert.equal(e.code, 'E_AUTHZ_RELATION_CONFIG')
    const e2 = catch422(() =>
      defineRelationsConfig({
        objectTypes: [{ type: 'document', relations: [{ name: 'viewer', includes: ['parent:owner'] }] }],
      })
    )
    assert.equal(e2.code, 'E_AUTHZ_RELATION_CONFIG')
    assert.include(e2.message, 'from')
  })

  test('membersOf solo vive en las opciones de database ⇒ 422 en la raíz', ({ assert }) => {
    const e = catch422(() =>
      defineRelationsConfig({ objectTypes: [{ type: 'document', relations: [{ name: 'owner' }] }], membersOf: true } as any)
    )
    assert.equal(e.code, 'E_AUTHZ_RELATION_CONFIG')
    assert.include(e.message, 'database.membersOf')
    // En database.membersOf sí vale.
    const ok = defineRelationsConfig({
      objectTypes: [{ type: 'document', relations: [{ name: 'owner' }] }],
      database: { membersOf: true },
    })
    assert.isTrue(ok.membersOf)
  })

  test('tipo duplicado / objectTypes vacío / tipo sin relaciones ⇒ 422', ({ assert }) => {
    assert.equal(
      catch422(() =>
        defineRelationsConfig({
          objectTypes: [
            { type: 'document', relations: [{ name: 'a' }] },
            { type: 'document', relations: [{ name: 'b' }] },
          ],
        })
      ).code,
      'E_AUTHZ_RELATION_CONFIG'
    )
    assert.equal(catch422(() => defineRelationsConfig({ objectTypes: [] })).code, 'E_AUTHZ_RELATION_CONFIG')
    assert.equal(
      catch422(() => defineRelationsConfig({ objectTypes: [{ type: 'document', relations: [] }] })).code,
      'E_AUTHZ_RELATION_CONFIG'
    )
  })
})

test.group('RelationsManager — F-05 (cierre del 🔴)', () => {
  test('F-05 · relate a un tipo NO declarado (role_binding) ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN antes del driver', async ({
    assert,
  }) => {
    let relateCalls = 0
    const config = contractRelationsConfig()
    const base = makeRelationsDriver({ config, capabilities: CAPS })
    const spied = { ...base, relate: async (...a: Parameters<typeof base.relate>) => { relateCalls++; return base.relate(...a) } }
    const manager = new RelationsManager(spied, config)
    let caught: any
    try {
      await manager.relate({ type: 'user', uuid: uuidv7() }, 'assignee', { type: 'role_binding', id: uuidv7() }, {
        type: 'unit',
        uuid: uuidv7(),
      })
    } catch (e) {
      caught = e
    }
    assert.equal(caught.status, 422)
    assert.equal(caught.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN')
    assert.equal(relateCalls, 0)
  })

  test('F-05 · relación no declarada para un tipo declarado ⇒ 422 E_AUTHZ_RELATION_UNKNOWN', async ({ assert }) => {
    const manager = managerWith()
    let caught: any
    try {
      await manager.relate({ type: 'user', uuid: uuidv7() }, 'assignee', { type: 'document', id: uuidv7() }, {
        type: 'unit',
        uuid: uuidv7(),
      })
    } catch (e) {
      caught = e
    }
    assert.equal(caught.code, 'E_AUTHZ_RELATION_UNKNOWN')
  })
})

test.group('RelationsManager — R-16 (validación de object.id, antes del driver)', () => {
  const S = { type: 'unit', uuid: uuidv7() }

  // El hallazgo del auditor: el manager solo validaba tipo+relación (F-05), no
  // el `object.id`. Un `|`/`#`/`:`/espacio/`*` se colaba al driver.
  for (const bad of ['a|b', 'a:b', 'a#viewer', 'a b', '*', 'A-B']) {
    test(`relate con object.id ${JSON.stringify(bad)} ⇒ 422 E_AUTHZ_INVALID_IDENTITY antes del driver`, async ({
      assert,
    }) => {
      let relateCalls = 0
      const config = contractRelationsConfig()
      const base = makeRelationsDriver({ config, capabilities: CAPS })
      const spied = {
        ...base,
        relate: async (...a: Parameters<typeof base.relate>) => {
          relateCalls++
          return base.relate(...a)
        },
      }
      const manager = new RelationsManager(spied, config)
      let caught: any
      try {
        await manager.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: bad }, S)
      } catch (e) {
        caught = e
      }
      assert.equal(caught?.status, 422, bad)
      assert.equal(caught?.code, 'E_AUTHZ_INVALID_IDENTITY', bad)
      assert.equal(relateCalls, 0, `${bad}: nada tocó el driver`)
    })
  }

  test('un object.id VÁLIDO (uuid) pasa; el userset con object.id inválido ⇒ 422', async ({ assert }) => {
    const manager = managerWith()
    // Válido: no lanza.
    await manager.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, S)
    // Userset con object.id con `|` ⇒ 422 (R-16 cubre también subject.object.id).
    let caught: any
    try {
      await manager.relate(
        { object: { type: 'group', id: 'g|evil' }, relation: 'member' },
        'viewer',
        { type: 'document', id: uuidv7() },
        S
      )
    } catch (e) {
      caught = e
    }
    assert.equal(caught?.status, 422)
    assert.equal(caught?.code, 'E_AUTHZ_INVALID_IDENTITY')
  })

  test('check/listSubjects/purgeObject con object.id inválido ⇒ 422 (no llega al driver)', async ({ assert }) => {
    const manager = managerWith()
    const bad = { type: 'document', id: 'a|b' }
    for (const op of [
      () => manager.check({ type: 'user', uuid: uuidv7() }, 'viewer', bad, S),
      () => manager.listSubjects('viewer', bad, S),
      () => manager.purgeObject(bad, S),
    ]) {
      let caught: any
      try {
        await op()
      } catch (e) {
        caught = e
      }
      assert.equal(caught?.code, 'E_AUTHZ_INVALID_IDENTITY')
    }
  })
})

test.group('RelationsManager — R-13 y membersOf', () => {
  test('assertWrite puro rechaza ⇒ nada toca el driver; actor viaja en onRelationWrite', async ({ assert }) => {
    const events: any[] = []
    const manager = managerWith({
      assertWrite: (ref) => {
        if (ref.relation === 'owner') throw new Error('prohibido owner')
      },
      onRelationWrite: (e) => events.push(e),
    })
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit' as const, uuid: uuidv7() }
    const actor = { type: 'admin', uuid: uuidv7() }
    let threw = false
    try {
      await manager.relate(u, 'owner', doc, p, { actor })
    } catch {
      threw = true
    }
    assert.isTrue(threw)
    assert.lengthOf(events, 0)
    await manager.relate(u, 'viewer', doc, p, { actor })
    assert.lengthOf(events, 1)
    assert.deepEqual(events[0].actor, actor)
  })

  test('membersOf con el driver que NO lo trae ⇒ 500 E_AUTHZ_UNSUPPORTED', async ({ assert }) => {
    const config = contractRelationsConfig()
    const driver = makeRelationsDriver({ config, capabilities: { ...CAPS, membersOfNative: false } })
    const manager = new RelationsManager(driver, config)
    let caught: any
    try {
      await manager.membersOf({ type: 'group', id: uuidv7() }, 'member', { type: 'unit', uuid: uuidv7() })
    } catch (e) {
      caught = e
    }
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_UNSUPPORTED')
    assert.include(caught.message, 'membersOf')
  })
})

/* ── L-2 · `{ transaction }`: la capacidad `transactionalWrites` y las dos puertas (relations) ── */

test.group('L-2 · {transaction} — la capacidad transactionalWrites y las dos puertas (puerto de relaciones)', () => {
  /** Lo que un `TransactionClientContract` de Lucid le enseña al paquete (la forma, no un motor). */
  const fakeTrx = () => ({ from() {}, table() {}, isTransaction: true as const, connectionName: 'sqlite' })
  const user = () => ({ type: 'user', uuid: uuidv7() })
  const partition = () => ({ type: 'unit', uuid: uuidv7() })

  /** El doble con la capacidad a elección, envuelto en un espía que anota las CUATRO escrituras y sus opciones. */
  function spiedDouble(capabilities: Record<string, boolean>) {
    const config = contractRelationsConfig()
    const base = makeRelationsDriver({ config, capabilities: capabilities as any })
    const calls: Array<{ method: string; options?: unknown }> = []
    const driver = new Proxy(base, {
      get(target, prop, receiver) {
        if (prop === 'relate' || prop === 'unrelate' || prop === 'purgeObject' || prop === 'purgeSubject') {
          return async (...args: unknown[]) => {
            calls.push({ method: prop, options: args.at(-1) })
            return (target as any)[prop](...args)
          }
        }
        const value = Reflect.get(target, prop, receiver)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    return { config, driver, calls }
  }

  async function rejects(assert: any, fn: () => Promise<unknown>, expected: { status: number; code: string }, label: string): Promise<any> {
    try {
      await fn()
    } catch (error: any) {
      assert.equal(error.status, expected.status, `${label}: ${error.message}`)
      assert.equal(error.code, expected.code, `${label}: ${error.message}`)
      return error
    }
    assert.fail(`ROJO: ${label} aceptó { transaction } sin que el driver declare transactionalWrites (debería haber lanzado)`)
  }

  test('puerta 1 · transactionalWrites: false + { transaction } en relate/unrelate/purgeObject/purgeSubject ⇒ 500 E_AUTHZ_UNSUPPORTED nombrando driver y operación, CERO llamadas al driver y sin onRelationWrite', async ({
    assert,
  }) => {
    const { config, driver, calls } = spiedDouble({ ...CAPS, transactionalWrites: false })
    const events: unknown[] = []
    const manager = new RelationsManager(driver, config, { driverName: 'openfga', onRelationWrite: (e: unknown) => void events.push(e) } as any)
    const u = user()
    const doc = { type: 'document', id: uuidv7() }
    const p = partition()
    const ops: Array<[string, () => Promise<unknown>]> = [
      ['relate', () => manager.relate(u, 'viewer', doc, p, { transaction: fakeTrx() } as any)],
      ['unrelate', () => manager.unrelate(u, 'viewer', doc, p, { transaction: fakeTrx() } as any)],
      ['purgeObject', () => (manager as any).purgeObject(doc, p, { transaction: fakeTrx() })],
      ['purgeSubject', () => (manager as any).purgeSubject(u, p, { transaction: fakeTrx() })],
    ]
    for (const [op, run] of ops) {
      const error = await rejects(assert, run, { status: 500, code: 'E_AUTHZ_UNSUPPORTED' }, op)
      assert.include(error.message, `'openfga'`, `${op}: nombra el driver`)
      assert.include(error.message, op, `${op}: nombra la operación`)
      assert.include(error.message, 'requireTransactionalWrites', `${op}: la letra lleva la salida`)
    }
    assert.deepEqual(calls, [], 'cero llamadas al driver')
    assert.deepEqual(events, [], 'una escritura que no ocurre no notifica')
    // Sin `transaction` la misma llamada entra: la puerta es del parámetro.
    await manager.relate(u, 'viewer', doc, p)
    assert.deepEqual(calls.map((c) => c.method), ['relate'])
  })

  test('puerta 1 · con transactionalWrites: true la puerta se abre: { transaction } llega al driver tal cual en las cuatro (lo que haga con ella es L-4)', async ({
    assert,
  }) => {
    const { config, driver, calls } = spiedDouble({ ...CAPS, transactionalWrites: true })
    const manager = new RelationsManager(driver, config)
    const u = user()
    const doc = { type: 'document', id: uuidv7() }
    const p = partition()
    const trx = fakeTrx()
    await manager.relate(u, 'viewer', doc, p, { transaction: trx } as any)
    await manager.unrelate(u, 'viewer', doc, p, { transaction: trx } as any)
    await (manager as any).purgeObject(doc, p, { transaction: trx })
    await (manager as any).purgeSubject(u, p, { transaction: trx })
    assert.deepEqual(calls.map((c) => c.method), ['relate', 'unrelate', 'purgeObject', 'purgeSubject'])
    for (const call of calls) assert.strictEqual((call.options as any)?.transaction, trx, `${call.method}: el driver recibe la transacción del llamante`)
  })

  /**
   * **alpha.3 · B1 (criterio (b) de COGNITIV, paridad con L-3).** El evento de
   * una escritura inscrita en la trx del llamante lleva `transactional: true`
   * (roles: `#transactional`, `manager.ts:442`); sin `{ transaction }` la marca
   * está AUSENTE (no `false`: la letra de `types.ts`, «Ausente en el resto»), y
   * `{ transaction: undefined }` / `{ transaction: null }` cuentan como SIN
   * transacción (lo que ya hace `#assertTransactional`). Las purgas se suman
   * en el bloque E (E1/E4). **Mutantes**: `options?.transaction !== undefined`
   * (sin el `null`) ⇒ el borde rojo; emitir `transactional: false` sin trx ⇒
   * `notProperty` rojo.
   */
  test('alpha.3 · B1 · con transactionalWrites: true, relate/unrelate con { transaction } marcan el evento con transactional: true; sin ella la marca está AUSENTE (no false), también con { transaction: undefined } y { transaction: null }', async ({
    assert,
  }) => {
    const { config, driver } = spiedDouble({ ...CAPS, transactionalWrites: true })
    const events: any[] = []
    const manager = new RelationsManager(driver, config, { onRelationWrite: (e: any) => void events.push(e) })
    const u = user()
    const doc = { type: 'document', id: uuidv7() }
    const p = partition()
    const trx = fakeTrx()
    await manager.relate(u, 'viewer', doc, p, { transaction: trx } as any)
    await manager.unrelate(u, 'viewer', doc, p, { transaction: trx } as any)
    assert.deepEqual(
      events.map((e) => [e.operation, e.transactional]),
      [
        ['relate', true],
        ['unrelate', true],
      ],
      'ROJO: el evento de relaciones no lleva transactional: true con { transaction }'
    )
    events.length = 0
    await manager.relate(u, 'viewer', doc, p)
    await manager.unrelate(u, 'viewer', doc, p)
    await manager.relate(u, 'viewer', doc, p, { transaction: undefined } as any)
    await manager.unrelate(u, 'viewer', doc, p, { transaction: null } as any)
    assert.lengthOf(events, 4)
    for (const event of events) {
      assert.notProperty(event, 'transactional', `${event.operation}: sin transacción la marca está AUSENTE, no false`)
    }
  })

  test('puerta 2 · requireTransactionalWrites: true + un driver que declara false (o nada) ⇒ 500 E_AUTHZ_CONFIG al construir el RelationsManager (= al resolver el driver), nombrando el driver; con uno capaz construye; sin el flag, el incapaz construye (opt-in)', ({
    assert,
  }) => {
    const config = contractRelationsConfig()
    const incapable = makeRelationsDriver({ config, capabilities: { ...CAPS, transactionalWrites: false } as any })
    const mute = { ...incapable, capabilities: undefined } as any
    for (const [label, driver] of [['false', incapable], ['sin capabilities', mute]] as const) {
      let caught: any
      try {
        new RelationsManager(driver, config, { requireTransactionalWrites: true, driverName: 'openfga' } as any)
        assert.fail(`ROJO (${label}): el RelationsManager se construyó con requireTransactionalWrites: true sobre un driver que no la declara`)
      } catch (e) {
        caught = e
      }
      assert.equal(caught.status, 500, `${label}: ${caught.message}`)
      assert.equal(caught.code, 'E_AUTHZ_CONFIG', label)
      assert.include(caught.message, `'openfga'`, `${label}: nombra el driver`)
      assert.include(caught.message, 'transactionalWrites', label)
      // Sin el flag, opt-in: construye.
      assert.strictEqual(new RelationsManager(driver, config).driver(), driver)
    }
    const capable = makeRelationsDriver({ config, capabilities: { ...CAPS, transactionalWrites: true } as any })
    assert.strictEqual(new RelationsManager(capable, config, { requireTransactionalWrites: true } as any).driver(), capable)
  })
})

/* ── alpha.3 · bloque C · Invariante 13 en relaciones (`indeterminate`) ── */

/**
 * **alpha.3 · C1 (hallazgo #3 del encargo).** Hasta alpha.2 `grep -c
 * indeterminate src/relations/manager.ts` = 0: no existía el envoltorio
 * `#write` de roles (`manager.ts:3257`) y las cuatro llamadas al driver iban
 * desnudas. Y SÍ hay deadline que vencer en los dos drivers (`guardSql` en
 * `database`, `isTimeoutLike` + `maxRetry: 0` en `openfga`). Harness: driver
 * FALSO cuyas escrituras lanzan `AuthorizationBackendTimeoutError` (copia del
 * patrón de roles, `tests/manager.spec.ts:139-195`). El ORDEN se observa con
 * una secuencia compartida entre el hook y el `catch`: el hook va ANTES de que
 * el llamante vea el 503 (un `finally` posterior pasaría el resto del caso).
 * **Mutantes**: notificar en cualquier `catch` ⇒ C2 (i) rojo; notificar sin
 * la marca ⇒ este caso rojo; notificar DESPUÉS de propagar ⇒ la secuencia rojo.
 */
test.group('alpha.3 · Invariante 13 · el deadline en relaciones (indeterminate)', () => {
  const timeout = (op: string) => new AuthorizationBackendTimeoutError('fake-relations', op, 5)

  /** Un driver falso: las escrituras fallan como se pida; las lecturas responden `false`/vacío. */
  function fakeDriver(fail: Record<string, () => Error>) {
    const calls: string[] = []
    const driver: any = {
      capabilities: { transactionalWrites: false },
      check: async () => false,
      listObjects: async () => ({ objects: [] }),
      listSubjects: async () => ({ subjects: [] }),
    }
    for (const op of ['relate', 'unrelate', 'purgeObject', 'purgeSubject']) {
      driver[op] = async () => {
        calls.push(op)
        const make = fail[op]
        if (make) throw make()
      }
    }
    return { driver, calls }
  }

  test('C1 · relate/unrelate que vencen el deadline notifican indeterminate: true con el resto del evento intacto (subject/object/partition/actor/expiresAt), ANTES de propagar el 503 E_AUTHZ_BACKEND_TIMEOUT', async ({
    assert,
  }) => {
    const { driver, calls } = fakeDriver({ relate: () => timeout('relate'), unrelate: () => timeout('unrelate') })
    const sequence: string[] = []
    const events: any[] = []
    const manager = new RelationsManager(driver, contractRelationsConfig(), {
      onRelationWrite: (e: any) => {
        events.push(e)
        sequence.push(`hook:${e.operation}`)
      },
    })
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    const actor = { type: 'admin', uuid: uuidv7() }
    const expiresAt = new Date(Date.now() + 3_600_000)
    for (const [op, run] of [
      ['relate', () => manager.relate(u, 'viewer', doc, p, { actor, expiresAt })],
      ['unrelate', () => manager.unrelate(u, 'viewer', doc, p, { actor })],
    ] as Array<[string, () => Promise<unknown>]>) {
      let caught: any
      try {
        await run()
        assert.fail(`${op}: debería haber rechazado`)
      } catch (error) {
        caught = error
      }
      sequence.push(`catch:${op}`)
      assert.equal(caught.status, 503, `${op}: ${caught.message}`)
      assert.equal(caught.code, 'E_AUTHZ_BACKEND_TIMEOUT', op)
    }
    assert.deepEqual(calls, ['relate', 'unrelate'], 'el driver se llamó (el deadline venció DENTRO)')
    assert.deepEqual(
      events.map((e) => [e.operation, e.indeterminate]),
      [
        ['relate', true],
        ['unrelate', true],
      ],
      'ROJO: una escritura de relación que vence el deadline no notifica indeterminate: true'
    )
    assert.deepEqual(sequence, ['hook:relate', 'catch:relate', 'hook:unrelate', 'catch:unrelate'], 'el hook se llama ANTES de que el llamante vea el 503')
    // El resto del evento, intacto.
    assert.deepEqual(events[0].subject, u)
    assert.deepEqual(events[0].object, doc)
    assert.deepEqual(events[0].partition, p)
    assert.deepEqual(events[0].actor, actor)
    assert.equal(events[0].relation, 'viewer')
    assert.equal(events[0].expiresAt?.getTime(), expiresAt.getTime())
    assert.notProperty(events[0], 'transactional', 'sin { transaction } no lleva la marca')
    assert.deepEqual(events[1].subject, u)
    assert.deepEqual(events[1].actor, actor)
  })
})

/**
 * **alpha.3 · C2 · inverso: lo que NO produce evento.** Nace verde por
 * ausencia de todo, así que por sí solo no prueba nada: es la no-regresión de
 * C1 (escrito DESPUÉS de C1, como exige el tester) y el que mata al mutante
 * «notificar en cualquier `catch`». Cuatro negativos: (i) un 503 que NO es
 * timeout (`ECONNREFUSED`: «esa escritura no ocurrió»), (ii) un 422 de
 * F-05 / R-16 / `expiresAt` inválido, (iii) `assertWrite` que lanza, (iv) el
 * freeze (503 `E_AUTHZ_FROZEN`). En los cuatro modos y SIN transacción (hasta
 * alpha.3 (iii)/(iv) solo estaban medidos dentro del grupo de `{ transaction }`
 * de `relations_database.spec.ts`, que no corre en `mem`).
 */
test.group('alpha.3 · Invariante 13 · lo que NO produce evento (C2, no-regresión de C1)', () => {
  test('C2 · (i) 503 no-timeout, (ii) 422 F-05/R-16/expiresAt, (iii) assertWrite que lanza, (iv) freeze ⇒ CERO eventos (y en ii/iii/iv cero llamadas al driver)', async ({
    assert,
  }) => {
    const calls: string[] = []
    const driver: any = {
      capabilities: { transactionalWrites: false },
      check: async () => false,
      relate: async () => {
        calls.push('relate')
        throw new AuthorizationBackendError('fake-relations', 'relate', new Error('ECONNREFUSED'))
      },
      unrelate: async () => {
        calls.push('unrelate')
        throw new AuthorizationBackendError('fake-relations', 'unrelate', new Error('ECONNREFUSED'))
      },
      purgeObject: async () => void calls.push('purgeObject'),
      purgeSubject: async () => void calls.push('purgeSubject'),
    }
    const events: any[] = []
    const manager = new RelationsManager(driver, contractRelationsConfig(), {
      assertWrite: (ref) => {
        if (ref.relation === 'owner') throw new Error('prohibido owner')
      },
      onRelationWrite: (e: any) => void events.push(e),
    })
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }

    // (i) un 503 que NO es timeout: el driver se llamó, la escritura no ocurrió, sin evento.
    for (const run of [() => manager.relate(u, 'viewer', doc, p), () => manager.unrelate(u, 'viewer', doc, p)]) {
      const caught = await run().then(() => null, (e) => e)
      assert.equal(caught?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    }
    assert.deepEqual(calls, ['relate', 'unrelate'])
    assert.deepEqual(events, [], '(i) un 503 que no es timeout no notifica')
    calls.length = 0

    // (ii) 422: F-05 (tipo), F-05 (relación), R-16 (object.id), expiresAt inválido.
    for (const [label, run, code] of [
      ['F-05 tipo', () => manager.relate(u, 'assignee', { type: 'role_binding', id: uuidv7() }, p), 'E_AUTHZ_RELATION_TYPE_UNKNOWN'],
      ['F-05 relación', () => manager.unrelate(u, 'assignee', doc, p), 'E_AUTHZ_RELATION_UNKNOWN'],
      ['R-16', () => manager.relate(u, 'viewer', { type: 'document', id: 'a|b' }, p), 'E_AUTHZ_INVALID_IDENTITY'],
      ['expiresAt', () => manager.relate(u, 'viewer', doc, p, { expiresAt: 'mañana' as any }), 'E_AUTHZ_INVALID_IDENTITY'],
    ] as Array<[string, () => Promise<unknown>, string]>) {
      const caught = await run().then(() => null, (e) => e)
      assert.equal(caught?.status, 422, `${label}: ${caught?.message}`)
      assert.equal(caught?.code, code, label)
    }
    // (iii) assertWrite que lanza.
    const rejected = await manager.relate(u, 'owner', doc, p).then(() => null, (e) => e)
    assert.equal(rejected?.message, 'prohibido owner')
    assert.deepEqual(calls, [], '(ii)/(iii) cero llamadas al driver')
    assert.deepEqual(events, [], '(ii)/(iii) cero eventos')

    // (iv) el freeze: 503 E_AUTHZ_FROZEN en las cuatro, cero llamadas, cero eventos.
    const roles = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver({}) },
      holderTypes: { users: 'user' },
      warnOnOptInSecurity: false,
    } as any)
    const token = await roles.freeze('cutover alpha.3 · C2')
    try {
      for (const [op, run] of [
        ['relate', () => manager.relate(u, 'viewer', doc, p)],
        ['unrelate', () => manager.unrelate(u, 'viewer', doc, p)],
        ['purgeObject', () => manager.purgeObject(doc, p)],
        ['purgeSubject', () => manager.purgeSubject(u, p)],
      ] as Array<[string, () => Promise<unknown>]>) {
        const caught = await run().then(() => null, (e) => e)
        assert.equal(caught?.code, 'E_AUTHZ_FROZEN', `${op}: ${caught?.message}`)
        assert.equal(caught?.status, 503, op)
      }
    } finally {
      await roles.unfreeze(token)
    }
    assert.deepEqual(calls, [], '(iv) el freeze corta ANTES del driver')
    assert.deepEqual(events, [], '(iv) cero eventos')
  })
})

/* ── alpha.3 · bloque D · paridad del despacho: el hook que lanza, el hook async, assertWrite async, el actor validado ── */

/**
 * **alpha.3 · D1/D2 (hallazgo 🔴 H1 del tester).** Hasta alpha.2 el manager
 * llamaba a `onRelationWrite` sin `await` ni `try/catch`: un sink de auditoría
 * caído convertía un `relate` YA ESCRITO en un error para el llamante (que
 * reintentaría algo hecho), y un hook `async` que rechazaba era un unhandled
 * rejection — ni tumbaba ni se registraba. Roles lo tiene como garantía
 * (`#notify`/`#logHookFailure`, `manager.ts:3276-3293`; casos
 * `manager.spec.ts:197`/`:214`). Se replica, no se reinventa: se traga, se
 * REGISTRA (el log tiene que nombrar la operación), y la escritura queda.
 * **Mutantes**: quitar el `try/catch` ⇒ D1 rojo; tragarlo sin registrar ⇒
 * rojo por `isNotEmpty(logged)`; llamar al hook sin `await` ⇒ D2 rojo.
 */
test.group('alpha.3 · D · paridad de #notify: un onRelationWrite que lanza NO tumba la escritura', () => {
  test('D1 · un onRelationWrite SÍNCRONO que lanza no propaga al llamante: la tupla está (check true) y el fallo queda REGISTRADO nombrando la operación', async ({
    assert,
  }) => {
    const manager = managerWith({
      onRelationWrite: () => {
        throw new Error('el sistema de auditoría está caído')
      },
    })
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    let caught: any = null
    const logged = await captureErrorLog(async () => {
      try {
        await manager.relate(u, 'viewer', doc, p)
      } catch (error) {
        caught = error
      }
    })
    assert.isNull(caught, `ROJO: el error del hook tumbó un relate ya escrito: ${caught?.message}`)
    assert.isTrue(await manager.check(u, 'viewer', doc, p), 'la escritura sí se aplicó')
    // Tragarse el fallo NO es lo mismo que ocultarlo: tiene que quedar registro, con la operación.
    assert.isNotEmpty(logged, 'el fallo del hook tiene que quedar registrado')
    assert.include(logged.join(' '), 'relate')
    assert.include(logged.join(' '), 'el sistema de auditoría está caído')
  })

  test('D2 · un onRelationWrite ASYNC que rechaza tampoco propaga, y SE ESPERA (queda registrado, no es un unhandled rejection)', async ({
    assert,
  }) => {
    const manager = managerWith({
      onRelationWrite: async (event) => {
        await new Promise((resolve) => setTimeout(resolve, 5))
        if (event.operation === 'unrelate') throw new Error('timeout escribiendo el log')
      },
    })
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    await manager.relate(u, 'viewer', doc, p)
    let caught: any = null
    const logged = await captureErrorLog(async () => {
      try {
        await manager.unrelate(u, 'viewer', doc, p)
      } catch (error) {
        caught = error
      }
    })
    assert.isNull(caught, `el rechazo del hook async tumbó el unrelate: ${caught?.message}`)
    assert.isFalse(await manager.check(u, 'viewer', doc, p), 'la escritura sí se aplicó')
    assert.isNotEmpty(logged, 'ROJO: nadie registró nada (el hook no se esperó: el rechazo se perdió como unhandled rejection)')
    assert.include(logged.join(' '), 'unrelate')
  })
})

/**
 * **alpha.3 · D3 (hallazgo 🔴 H2 del tester, y justo lo que COGNITIV asumió al
 * revés).** `assertWrite?(ref): void` es síncrono a propósito (R-13), pero
 * TypeScript no lo defiende: `assertWrite: async (ref) => { throw … }` compila,
 * la promesa se descartaba y LA ESCRITURA ENTRABA. Se cierra fail-closed: si
 * `assertWrite` devuelve un thenable ⇒ 500 `E_AUTHZ_CONFIG` ANTES de escribir,
 * nombrando la causa (precedente: `clock` que no es `() => Date` ⇒ 500 al
 * construir). También cuando la promesa RESUELVE: el problema es el thenable,
 * no el rechazo. **Mutante**: quitar la detección ⇒ rojo (el espía cuenta 1).
 */
test.group('alpha.3 · D3 · un assertWrite ASYNC no es un assertWrite: 500 E_AUTHZ_CONFIG, cero escrituras (H2, fail-closed)', () => {
  test('D3 · assertWrite: async (rechace o resuelva) ⇒ 500 E_AUTHZ_CONFIG nombrando assertWrite, «síncrono» y la receta; CERO llamadas al driver y CERO eventos; la promesa descartada no queda como unhandled rejection', async ({
    assert,
  }) => {
    const config = contractRelationsConfig()
    const base = makeRelationsDriver({ config, capabilities: CAPS })
    const calls: string[] = []
    const driver = new Proxy(base, {
      get(target, prop, receiver) {
        if (prop === 'relate' || prop === 'unrelate') {
          return async (...args: unknown[]) => {
            calls.push(prop)
            return (target as any)[prop](...args)
          }
        }
        const value = Reflect.get(target, prop, receiver)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const events: any[] = []
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    const unhandled: unknown[] = []
    const onUnhandled = (reason: unknown) => void unhandled.push(reason)
    process.on('unhandledRejection', onUnhandled)
    try {
      for (const [label, assertWrite] of [
        ['que rechaza', async () => { throw new Error('prohibido (async, se habría ignorado)') }],
        ['que resuelve', async () => {}],
      ] as Array<[string, any]>) {
        const manager = new RelationsManager(driver, config, { assertWrite, onRelationWrite: (e: any) => void events.push(e) })
        for (const [op, run] of [
          ['relate', () => manager.relate(u, 'viewer', doc, p)],
          ['unrelate', () => manager.unrelate(u, 'viewer', doc, p)],
        ] as Array<[string, () => Promise<unknown>]>) {
          const caught = await run().then(() => null, (e) => e)
          assert.isNotNull(caught, `ROJO (${label}/${op}): la escritura ENTRÓ con un assertWrite async (la promesa se descartó: fail-open)`)
          assert.instanceOf(caught, AuthorizationConfigError, `${label}/${op}: ${caught?.message}`)
          assert.equal(caught.status, 500)
          assert.equal(caught.code, 'E_AUTHZ_CONFIG')
          assert.include(caught.message, 'assertWrite')
          assert.include(caught.message, 'síncrono')
          assert.include(caught.message, `relations.${op}`)
          assert.include(caught.message, 'servicio', 'la receta: la policy con actor/BD va en el servicio del consumidor')
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 20))
    } finally {
      process.off('unhandledRejection', onUnhandled)
    }
    assert.deepEqual(calls, [], 'CERO llamadas al driver')
    assert.deepEqual(events, [], 'CERO eventos')
    assert.deepEqual(unhandled, [], 'la promesa descartada del assertWrite que rechaza no se filtra como unhandled rejection')
    // Un assertWrite SÍNCRONO que no lanza sigue entrando (el diente es el thenable, no el hook).
    const sync = new RelationsManager(driver, config, { assertWrite: () => {} })
    await sync.relate(u, 'viewer', doc, p)
    assert.deepEqual(calls, ['relate'])
  })
})

/**
 * **alpha.3 · D4 (hallazgo 🟠 H3 del tester).** `#assertActor` solo comprobaba
 * PRESENCIA (`!options?.actor`): un `actor: { type: 'user', uuid: 'ACTOR
 * MAL#FORMADO' }` pasaba y viajaba al evento (envenena el rastro), y un
 * `actor: {}` truthy satisfacía `requireActor`. Roles valida la identidad
 * ANTES de nada (`#writeOptions`, `manager.ts:1512`: `assertSubject`). Paridad:
 * validar-si-viene y después exigir-si-falta, en las CUATRO escrituras.
 * **Mutantes**: validar solo en `relate` ⇒ rojo en unrelate/purgas; comprobar
 * `requireActor` con truthiness antes de validar ⇒ `actor: {}` pasa ⇒ rojo.
 */
test.group('alpha.3 · D4 · el actor se valida como identidad en las CUATRO escrituras (422 antes del driver, cero eventos)', () => {
  function spiedManager(options?: ConstructorParameters<typeof RelationsManager>[2]) {
    const config = contractRelationsConfig()
    const base = makeRelationsDriver({ config, capabilities: CAPS })
    const calls: string[] = []
    const events: any[] = []
    const driver = new Proxy(base, {
      get(target, prop, receiver) {
        if (prop === 'relate' || prop === 'unrelate' || prop === 'purgeObject' || prop === 'purgeSubject') {
          return async (...args: unknown[]) => {
            calls.push(prop)
            return (target as any)[prop](...args)
          }
        }
        const value = Reflect.get(target, prop, receiver)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const manager = new RelationsManager(driver, config, { onRelationWrite: (e: any) => void events.push(e), ...options })
    return { manager, calls, events }
  }

  const BAD_ACTORS: Array<[string, unknown]> = [
    ['uuid con #', { type: 'user', uuid: 'a#b' }],
    ['uuid en MAYÚSCULAS', { type: 'user', uuid: uuidv7().toUpperCase() }],
    ['uuid undefined', { type: 'user', uuid: undefined }],
    ['actor: {}', {}],
    ['tipo con espacio', { type: 'us er', uuid: uuidv7() }],
  ]

  test('D4 · un actor mal formado (uuid con #, MAYÚSCULAS, undefined, {}, tipo inválido) ⇒ 422 E_AUTHZ_INVALID_IDENTITY en relate/unrelate/purgeObject/purgeSubject, cero llamadas, cero eventos; uno bien formado entra y viaja al evento', async ({
    assert,
  }) => {
    const { manager, calls, events } = spiedManager()
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    for (const [label, actor] of BAD_ACTORS) {
      for (const [op, run] of [
        ['relate', () => manager.relate(u, 'viewer', doc, p, { actor } as any)],
        ['unrelate', () => manager.unrelate(u, 'viewer', doc, p, { actor } as any)],
        ['purgeObject', () => manager.purgeObject(doc, p, { actor } as any)],
        ['purgeSubject', () => manager.purgeSubject(u, p, { actor } as any)],
      ] as Array<[string, () => Promise<unknown>]>) {
        const caught = await run().then(() => null, (e) => e)
        assert.isNotNull(caught, `ROJO (${label}/${op}): el actor mal formado ENTRÓ`)
        assert.equal(caught?.status, 422, `${label}/${op}: ${caught?.message}`)
        assert.equal(caught?.code, 'E_AUTHZ_INVALID_IDENTITY', `${label}/${op}: ${caught?.message}`)
      }
    }
    assert.deepEqual(calls, [], 'cero llamadas al driver')
    assert.deepEqual(events, [], 'cero eventos: un actor basura no viaja al rastro')
    // Bien formado: entra y viaja.
    const actor = { type: 'admin', uuid: uuidv7() }
    await manager.relate(u, 'viewer', doc, p, { actor })
    await manager.unrelate(u, 'viewer', doc, p, { actor })
    assert.deepEqual(calls, ['relate', 'unrelate'])
    assert.deepEqual(events.map((e) => e.actor), [actor, actor])
  })

  test('D4 · borde: requireActor: true + actor: {} es 422 de IDENTIDAD, no «actor requerido» (validar-si-viene, después exigir-si-falta); sin actor sigue siendo E_AUTHZ_ACTOR_REQUIRED', async ({ assert }) => {
    const { manager, calls } = spiedManager({ requireActor: true })
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    const empty = await manager.relate(u, 'viewer', doc, p, { actor: {} as any }).then(() => null, (e) => e)
    assert.equal(empty?.code, 'E_AUTHZ_INVALID_IDENTITY', `ROJO: actor: {} satisface requireActor (truthiness antes de validar): ${empty?.message}`)
    const missing = await manager.relate(u, 'viewer', doc, p).then(() => null, (e) => e)
    assert.equal(missing?.code, 'E_AUTHZ_ACTOR_REQUIRED', missing?.message)
    assert.deepEqual(calls, [])
  })
})

/* ── alpha.3 · bloque E · la purga (hallazgo #4 + D-1/D-2/D-3) ── */

/**
 * **alpha.3 · E (hallazgo #4 del encargo).** Hasta alpha.2 `purgeObject`/
 * `purgeSubject` hacían `return this.#driver.purge*(...)` sin evento alguno.
 * Forma decidida (D-1/D-2, espejo de `scope_purged` de roles): UN evento por
 * llamada, `operation: 'purgeObject' | 'purgeSubject'`, el objetivo y la
 * partición, sin `relation`, SIN conteo; con `actor`, `transactional` e
 * `indeterminate` como las otras dos. `requireActor` alcanza a las purgas
 * (D-3, breaking). La purga NO pasa por `assertWrite` (D-1, E9).
 * **Mutantes**: emitir `operation: 'unrelate'` ⇒ E1 rojo; un evento por tupla
 * borrada ⇒ `lengthOf(events, 1)` rojo; condicionar al «borró algo» ⇒ E2 rojo;
 * exigir el actor DESPUÉS del driver ⇒ E3 «cero llamadas» rojo.
 */
test.group('alpha.3 · E · las purgas notifican UN evento con la forma decidida, respetan requireActor y no pasan por assertWrite', () => {
  function spiedManager(options?: ConstructorParameters<typeof RelationsManager>[2]) {
    const config = contractRelationsConfig()
    const base = makeRelationsDriver({ config, capabilities: CAPS })
    const calls: string[] = []
    const events: any[] = []
    const driver = new Proxy(base, {
      get(target, prop, receiver) {
        if (prop === 'relate' || prop === 'unrelate' || prop === 'purgeObject' || prop === 'purgeSubject') {
          return async (...args: unknown[]) => {
            calls.push(prop)
            return (target as any)[prop](...args)
          }
        }
        const value = Reflect.get(target, prop, receiver)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const manager = new RelationsManager(driver, config, { onRelationWrite: (e: any) => void events.push(e), ...options })
    return { manager, calls, events }
  }

  test('E1 · purgeObject ⇒ UN evento { operation: purgeObject, object, partition, actor } sin subject ni relation; purgeSubject ⇒ { operation: purgeSubject, subject, partition, actor } sin object ni relation — aunque borren VARIAS tuplas', async ({
    assert,
  }) => {
    const { manager, events } = spiedManager()
    const u = { type: 'user', uuid: uuidv7() }
    const v = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const other = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    const actor = { type: 'admin', uuid: uuidv7() }
    await manager.relate(u, 'viewer', doc, p)
    await manager.relate(v, 'editor', doc, p)
    await manager.relate(u, 'owner', other, p)
    events.length = 0

    await manager.purgeObject(doc, p, { actor })
    assert.lengthOf(events, 1, 'ROJO: la purga no notifica (o notifica una vez por tupla borrada)')
    assert.equal(events[0].operation, 'purgeObject', 'una purga no es un unrelate: un sink que cuenta desasociaciones no la contaría como una')
    assert.deepEqual(events[0].object, doc)
    assert.deepEqual(events[0].partition, p)
    assert.deepEqual(events[0].actor, actor)
    assert.notProperty(events[0], 'subject')
    assert.notProperty(events[0], 'relation')
    assert.notProperty(events[0], 'transactional')
    assert.notProperty(events[0], 'indeterminate')
    assert.isFalse(await manager.check(u, 'viewer', doc, p))
    assert.isFalse(await manager.check(v, 'viewer', doc, p))

    events.length = 0
    await manager.relate(u, 'viewer', doc, p)
    events.length = 0
    await manager.purgeSubject(u, p, { actor })
    assert.lengthOf(events, 1)
    assert.equal(events[0].operation, 'purgeSubject')
    assert.deepEqual(events[0].subject, u)
    assert.deepEqual(events[0].partition, p)
    assert.deepEqual(events[0].actor, actor)
    assert.notProperty(events[0], 'object')
    assert.notProperty(events[0], 'relation')
    assert.isFalse(await manager.check(u, 'owner', other, p))
    assert.isFalse(await manager.check(u, 'viewer', doc, p))
  })

  test('E2 · una purga que no borra NADA notifica igual (el hecho auditable es «alguien pidió borrar las llaves de X»); sin actor, el evento no lo inventa', async ({ assert }) => {
    const { manager, events } = spiedManager()
    const p = { type: 'unit', uuid: uuidv7() }
    await manager.purgeObject({ type: 'document', id: uuidv7() }, p)
    await manager.purgeSubject({ type: 'user', uuid: uuidv7() }, p)
    assert.deepEqual(
      events.map((e) => e.operation),
      ['purgeObject', 'purgeSubject'],
      'ROJO: la purga vacía no notifica (condicionar el evento a «borró algo» exigiría romper el puerto: purge* devuelve void)'
    )
    for (const e of events) assert.notProperty(e, 'actor')
  })

  test('E3 · inverso · requireActor: true alcanza a las purgas: 422 E_AUTHZ_ACTOR_REQUIRED sin tocar el driver ni notificar; con actor, entran (breaking D-3)', async ({ assert }) => {
    const { manager, calls, events } = spiedManager({ requireActor: true })
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    for (const [op, run] of [
      ['purgeObject', () => manager.purgeObject(doc, p)],
      ['purgeSubject', () => manager.purgeSubject(u, p)],
    ] as Array<[string, () => Promise<unknown>]>) {
      const caught = await run().then(() => null, (e) => e)
      assert.equal(caught?.code, 'E_AUTHZ_ACTOR_REQUIRED', `ROJO (${op}): la purga ENTRÓ sin actor con requireActor: true: ${caught?.message}`)
      assert.equal(caught?.status, 422)
      assert.include(caught.message, op)
    }
    assert.deepEqual(calls, [], 'cero llamadas al driver (el actor se exige ANTES)')
    assert.deepEqual(events, [])
    const actor = { type: 'admin', uuid: uuidv7() }
    await manager.purgeObject(doc, p, { actor })
    await manager.purgeSubject(u, p, { actor })
    assert.deepEqual(calls, ['purgeObject', 'purgeSubject'])
    assert.deepEqual(events.map((e) => [e.operation, e.actor]), [['purgeObject', actor], ['purgeSubject', actor]])
  })

  test('E5 · purgeObject/purgeSubject que vencen el deadline notifican indeterminate: true (con la forma de la purga) ANTES del 503', async ({ assert }) => {
    const timeout = (op: string) => new AuthorizationBackendTimeoutError('fake-relations', op, 5)
    const driver: any = {
      capabilities: { transactionalWrites: false },
      check: async () => false,
      relate: async () => {},
      unrelate: async () => {},
      purgeObject: async () => {
        throw timeout('purgeObject')
      },
      purgeSubject: async () => {
        throw timeout('purgeSubject')
      },
    }
    const events: any[] = []
    const sequence: string[] = []
    const manager = new RelationsManager(driver, contractRelationsConfig(), {
      onRelationWrite: (e: any) => {
        events.push(e)
        sequence.push(`hook:${e.operation}`)
      },
    })
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    const actor = { type: 'admin', uuid: uuidv7() }
    for (const [op, run] of [
      ['purgeObject', () => manager.purgeObject(doc, p, { actor })],
      ['purgeSubject', () => manager.purgeSubject(u, p, { actor })],
    ] as Array<[string, () => Promise<unknown>]>) {
      const caught = await run().then(() => null, (e) => e)
      sequence.push(`catch:${op}`)
      assert.equal(caught?.code, 'E_AUTHZ_BACKEND_TIMEOUT', `${op}: ${caught?.message}`)
      assert.equal(caught?.status, 503)
    }
    assert.deepEqual(
      events.map((e) => [e.operation, e.indeterminate]),
      [
        ['purgeObject', true],
        ['purgeSubject', true],
      ],
      'ROJO: una purga que vence el deadline (una purga a MEDIAS: openfga borra en lotes) no notifica indeterminate: true'
    )
    assert.deepEqual(sequence, ['hook:purgeObject', 'catch:purgeObject', 'hook:purgeSubject', 'catch:purgeSubject'])
    assert.deepEqual(events[0].object, doc)
    assert.notProperty(events[0], 'subject')
    assert.deepEqual(events[1].subject, u)
    assert.notProperty(events[1], 'object')
    for (const e of events) {
      assert.deepEqual(e.actor, actor)
      assert.deepEqual(e.partition, p)
      assert.notProperty(e, 'transactional')
    }
  })

  test('E9 · negativo declarado (D-1) · la purga NO pasa por assertWrite: el contador queda a 0, la purga se hace y el evento se emite (un relate sí lo llama)', async ({ assert }) => {
    let assertWriteCalls = 0
    const { manager, calls, events } = spiedManager({ assertWrite: () => void (assertWriteCalls += 1) })
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    await manager.relate(u, 'viewer', doc, p)
    assert.equal(assertWriteCalls, 1, 'un relate SÍ pasa por assertWrite (la aserción positiva)')
    await manager.purgeObject(doc, p)
    await manager.purgeSubject(u, p)
    assert.equal(assertWriteCalls, 1, 'las purgas NO pasan por assertWrite: RelationRef.operation es relate | unrelate (tipo publicado de R-13)')
    assert.deepEqual(calls, ['relate', 'purgeObject', 'purgeSubject'])
    assert.deepEqual(events.map((e) => e.operation), ['relate', 'purgeObject', 'purgeSubject'])
  })
})

/* ── CIERRE de alpha.3 (auditor NO APTA, decisiones 2026-09-02 (2c)) ──────── */

/** Un manager sobre el doble cuyo driver cuenta las SIETE operaciones (escrituras Y lecturas). */
function sevenWaySpiedManager(options?: ConstructorParameters<typeof RelationsManager>[2]) {
  const config = contractRelationsConfig()
  const base = makeRelationsDriver({ config, capabilities: CAPS })
  const calls: string[] = []
  const events: any[] = []
  const SEVEN = ['relate', 'unrelate', 'purgeObject', 'purgeSubject', 'check', 'listObjects', 'listSubjects']
  const driver = new Proxy(base, {
    get(target, prop, receiver) {
      if (typeof prop === 'string' && SEVEN.includes(prop)) {
        return async (...args: unknown[]) => {
          calls.push(prop)
          return (target as any)[prop](...args)
        }
      }
      const value = Reflect.get(target, prop, receiver)
      return typeof value === 'function' ? value.bind(target) : value
    },
  })
  const manager = new RelationsManager(driver, config, { onRelationWrite: (e: any) => void events.push(e), ...options })
  return { manager, calls, events }
}

/**
 * **🔴 1 + 🟠 2 del auditor · F-05 cubre las CUATRO escrituras y las TRES
 * lecturas.** Hasta el cierre `#assertDeclared` solo corría en `relate`/
 * `unrelate` (`manager.ts:313`/`:338`): `purgeObject({ type: 'role_binding',
 * id: R }, S)` atravesaba el manager, componía en `openfga` el id EXACTO del
 * binding real y lo borraba (reproducido contra el `:8101`: `authorize` de
 * `true` a `false`, 0 tuplas, evento limpio); `listSubjects('assignee',
 * role_binding)` enumeraba sus asignados. Aquí, con el doble: 422 con cero
 * llamadas (ni una lectura) y cero eventos. **Mutante**: quitar
 * `#assertDeclared` de `purgeObject` ⇒ rojo («entró»).
 */
test.group('cierre alpha.3 · 🔴 1 / 🟠 2 · F-05 en purgeObject/purgeSubject y en check/listObjects/listSubjects (manager, dobles)', () => {
  const S = { type: 'organization', uuid: uuidv7() }

  test('purgeObject(role_binding) y purgeSubject(userset role_binding#role) ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN ANTES del driver: cero llamadas, cero eventos (D3/D4 del auditor)', async ({
    assert,
  }) => {
    const { manager, calls, events } = sevenWaySpiedManager()
    const binding = { type: 'role_binding', id: uuidv7() }
    const actor = { type: 'user', uuid: uuidv7() }
    for (const [label, run] of [
      ['purgeObject', () => manager.purgeObject(binding, S, { actor })],
      ['purgeSubject(userset)', () => manager.purgeSubject({ object: binding, relation: 'role' }, S, { actor })],
    ] as Array<[string, () => Promise<unknown>]>) {
      const caught = await run().then(() => null, (e) => e)
      assert.isNotNull(caught, `ROJO (${label}): la purga de un tipo NO declarado ENTRÓ (el 🔴 1 del auditor)`)
      assert.equal(caught.status, 422, `${label}: ${caught.message}`)
      assert.equal(caught.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN', label)
      assert.include(caught.message, 'purgeObject', 'el mensaje de F-05 nombra ya las purgas y las lecturas')
    }
    assert.deepEqual(calls, [], 'cero llamadas al driver')
    assert.deepEqual(events, [], 'cero eventos: no hay purga que auditar')
  })

  test('check/listObjects/listSubjects contra role_binding ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN; con una relación no declarada del tipo ⇒ 422 E_AUTHZ_RELATION_UNKNOWN; el userset del sujeto de check/listObjects también; cero llamadas (D-lecturas del auditor)', async ({
    assert,
  }) => {
    const { manager, calls } = sevenWaySpiedManager()
    const u = { type: 'user', uuid: uuidv7() }
    const binding = { type: 'role_binding', id: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const expect = async (label: string, code: string, run: () => Promise<unknown>) => {
      const caught = await run().then(() => null, (e) => e)
      assert.isNotNull(caught, `ROJO (${label}): la lectura ENTRÓ`)
      assert.equal(caught.status, 422, `${label}: ${caught.message}`)
      assert.equal(caught.code, code, label)
    }
    await expect('check', 'E_AUTHZ_RELATION_TYPE_UNKNOWN', () => manager.check(u, 'assignee', binding, S))
    await expect('listObjects', 'E_AUTHZ_RELATION_TYPE_UNKNOWN', () => manager.listObjects(u, 'assignee', 'role_binding', S))
    await expect('listSubjects', 'E_AUTHZ_RELATION_TYPE_UNKNOWN', () => manager.listSubjects('assignee', binding, S))
    await expect('check(rel)', 'E_AUTHZ_RELATION_UNKNOWN', () => manager.check(u, 'assignee', doc, S))
    await expect('listObjects(rel)', 'E_AUTHZ_RELATION_UNKNOWN', () => manager.listObjects(u, 'assignee', 'document', S))
    await expect('listSubjects(rel)', 'E_AUTHZ_RELATION_UNKNOWN', () => manager.listSubjects('assignee', doc, S))
    // El USERSET del sujeto de una lectura también pasa por F-05.
    const evilUserset = { object: binding, relation: 'assignee' }
    await expect('check(userset)', 'E_AUTHZ_RELATION_TYPE_UNKNOWN', () => manager.check(evilUserset, 'viewer', doc, S))
    await expect('listObjects(userset)', 'E_AUTHZ_RELATION_TYPE_UNKNOWN', () => manager.listObjects(evilUserset, 'viewer', 'document', S))
    assert.deepEqual(calls, [], 'cero llamadas al driver: F-05 corta ANTES en las tres lecturas')
    // CONTROL: lo declarado sigue leyendo (y el `group` built-in como userset).
    await manager.relate({ object: { type: 'group', id: uuidv7() }, relation: 'member' }, 'viewer', doc, S)
    assert.isFalse(await manager.check(u, 'viewer', doc, S))
    assert.lengthOf((await manager.listSubjects('viewer', doc, S)).subjects, 1)
    assert.deepEqual(calls, ['relate', 'check', 'listSubjects'])
  })

  test('⚪ 7 · purgeSubject valida su SUJETO en el manager (paridad con H3): holder mal formado o {} ⇒ 422 E_AUTHZ_INVALID_IDENTITY, cero llamadas, cero eventos (D1/D2 del auditor)', async ({
    assert,
  }) => {
    const { manager, calls, events } = sevenWaySpiedManager()
    for (const subject of [{ type: 'user', uuid: 'A#B|evil' }, {}, { type: 'user' }, { uuid: uuidv7() }, null]) {
      const caught = await manager.purgeSubject(subject as any, S).then(() => null, (e) => e)
      assert.isNotNull(caught, `ROJO: purgeSubject(${JSON.stringify(subject)}) ENTRÓ sin validar el sujeto`)
      assert.equal(caught.status, 422, JSON.stringify(subject))
      assert.equal(caught.code, 'E_AUTHZ_INVALID_IDENTITY', JSON.stringify(subject))
    }
    assert.deepEqual(calls, [])
    assert.deepEqual(events, [], 'el sujeto envenenado no llega al evento')
    // CONTROL: uno bien formado entra y notifica.
    const u = { type: 'user', uuid: uuidv7() }
    await manager.purgeSubject(u, S)
    assert.deepEqual(calls, ['purgeSubject'])
    assert.deepEqual(events[0]?.subject, u)
  })
})

/**
 * **🟠 3 + 🟡 4 del auditor · `assertWrite` rechaza TODO retorno ≠
 * `undefined`.** H2 cerró el thenable-objeto y dejó abierto el gate que
 * DEVUELVE un veredicto: `assertWrite: (ref) => allowed.has(ref.object.type)`
 * compila bajo `--strict` y la escritura entraba con `false` (A1 del auditor:
 * «llamado=1 ESCRITURA ENTRÓ=true»); y una FUNCIÓN con `.then` esquivaba
 * `typeof result === 'object'` (A2). `assertWrite` no devuelve veredictos:
 * lanza o no lanza. **Mutante**: quitar la condición ⇒ la escritura entra ⇒
 * rojo.
 */
test.group('cierre alpha.3 · 🟠 3 / 🟡 4 · assertWrite que DEVUELVE algo (false, true, thenable-función, null) es 500 E_AUTHZ_CONFIG antes del driver', () => {
  const S = { type: 'unit', uuid: uuidv7() }

  test('(ref) => false y (ref) => true ⇒ 500 E_AUTHZ_CONFIG nombrando «no devuelve veredictos», CERO llamadas y CERO eventos en relate/unrelate; el sink que dice false NO deniega nada por sí mismo', async ({
    assert,
  }) => {
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    for (const [label, assertWrite] of [
      ['false', () => false],
      ['true', () => true],
      ['null', () => null],
      ['string', () => 'deny'],
      ['objeto', () => ({ allowed: false })],
    ] as Array<[string, any]>) {
      const { manager, calls, events } = sevenWaySpiedManager({ assertWrite })
      for (const [op, run] of [
        ['relate', () => manager.relate(u, 'viewer', doc, S)],
        ['unrelate', () => manager.unrelate(u, 'viewer', doc, S)],
      ] as Array<[string, () => Promise<unknown>]>) {
        const caught = await run().then(() => null, (e) => e)
        assert.isNotNull(caught, `ROJO (${label}/${op}): la escritura ENTRÓ con un assertWrite que devuelve ${label} (A1 del auditor: fail-open)`)
        assert.instanceOf(caught, AuthorizationConfigError, `${label}/${op}: ${caught?.message}`)
        assert.equal(caught.status, 500)
        assert.equal(caught.code, 'E_AUTHZ_CONFIG')
        assert.include(caught.message, `relations.${op}`)
        assert.include(caught.message, 'no devuelve veredictos')
        assert.include(caught.message, 'servicio del consumidor')
      }
      assert.deepEqual(calls, [], `${label}: cero llamadas al driver`)
      assert.deepEqual(events, [], `${label}: cero eventos`)
      assert.isFalse(await manager.check(u, 'viewer', doc, S), `${label}: la escritura NO entró`)
    }
  })

  test('un thenable que es FUNCIÓN (lazy promise con .then) ⇒ 500 con la letra del async (H2), CERO llamadas; y la escritura NO entra (A2 del auditor)', async ({ assert }) => {
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    let rejected = false
    const lazy: any = () => {}
    lazy.then = (_res: any, rej: any) => {
      rejected = true
      rej(new Error('policy: denegado'))
    }
    const { manager, calls, events } = sevenWaySpiedManager({ assertWrite: () => lazy })
    const caught = await manager.relate(u, 'viewer', doc, S).then(() => null, (e) => e)
    assert.isNotNull(caught, 'ROJO: el thenable-función esquivó la guarda y la escritura ENTRÓ')
    assert.equal(caught.code, 'E_AUTHZ_CONFIG')
    assert.equal(caught.message, AuthorizationConfigError.asyncAssertWrite('relations.relate').message, 'la MISMA letra que el async de H2')
    assert.isTrue(rejected, 'el rechazo se ha descartado a sabiendas (no queda como unhandled rejection)')
    assert.deepEqual(calls, [])
    assert.deepEqual(events, [])
    assert.isFalse(await manager.check(u, 'viewer', doc, S))
  })

  test('CONTROL: un assertWrite que vuelve sin valor (undefined) entra; uno que LANZA propaga su error tal cual y no toca el driver', async ({ assert }) => {
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const ok = sevenWaySpiedManager({ assertWrite: () => {} })
    await ok.manager.relate(u, 'viewer', doc, S)
    assert.deepEqual(ok.calls, ['relate'])
    const denies = sevenWaySpiedManager({ assertWrite: () => { throw new Error('prohibido') } })
    const caught = await denies.manager.relate(u, 'owner', doc, S).then(() => null, (e) => e)
    assert.equal(caught?.message, 'prohibido')
    assert.deepEqual(denies.calls, [])
  })
})

/**
 * **🟡 6 del auditor · una purga a MEDIAS es indeterminada.** La purga de
 * `openfga` es multi-request; un 503 no-timeout (o el 500 de la demostración
 * de cero) puede llegar después de haber borrado parte, y el manager solo
 * notificaba con `AuthorizationBackendTimeoutError` (F del auditor: «borró=1
 * … EVENTOS=0»). Mecanismo: el driver marca el error con `markPartialWrite`
 * (`src/errors.ts`; una propiedad, la clase y el `code` no cambian) y
 * `#write` notifica `indeterminate: true` para timeout O parcial. Aquí con
 * un driver que falla marcado; contra el `:8101` en `relations_openfga.spec`.
 * **Mutante**: quitar `isPartialWrite` de `#write` ⇒ rojo (cero eventos).
 */
test.group('cierre alpha.3 · 🟡 6 · una purga que falla DESPUÉS de haber borrado (marcada parcial) notifica indeterminate: true ANTES de propagar; sin la marca, nada', () => {
  const S = { type: 'unit', uuid: uuidv7() }

  function partialDriver(purgeObjectError: () => unknown, purgeSubjectError: () => unknown) {
    const config = contractRelationsConfig()
    const base = makeRelationsDriver({ config, capabilities: CAPS })
    const driver: any = Object.create(base)
    driver.purgeObject = async () => {
      throw purgeObjectError()
    }
    driver.purgeSubject = async () => {
      throw purgeSubjectError()
    }
    const events: any[] = []
    const sequence: string[] = []
    const manager = new RelationsManager(driver, config, {
      onRelationWrite: (e: any) => {
        events.push(e)
        sequence.push(`hook:${e.operation}`)
      },
    })
    return { manager, events, sequence }
  }

  test('503 E_AUTHZ_BACKEND_UNAVAILABLE marcado parcial (purgeObject) y 500 E_AUTHZ_PURGE_INCOMPLETE marcado parcial (purgeSubject) ⇒ UN evento con indeterminate: true y la forma de la purga, ANTES del error; el error propagado conserva clase y code', async ({
    assert,
  }) => {
    const { manager, events, sequence } = partialDriver(
      () => markPartialWrite(new AuthorizationBackendError('fake-relations', 'purgeObject', new Error('caído a mitad'))),
      () => markPartialWrite(new PurgeIncompleteError('purgeSubject: quedan 1 tuplas'))
    )
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const actor = { type: 'admin', uuid: uuidv7() }
    const caughtObject = await manager.purgeObject(doc, S, { actor }).then(() => null, (e) => e)
    sequence.push('catch:purgeObject')
    assert.instanceOf(caughtObject, AuthorizationBackendError, 'la clase se conserva')
    assert.equal(caughtObject.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    assert.equal(caughtObject.status, 503)
    const caughtSubject = await manager.purgeSubject(u, S, { actor }).then(() => null, (e) => e)
    sequence.push('catch:purgeSubject')
    assert.instanceOf(caughtSubject, PurgeIncompleteError)
    assert.equal(caughtSubject.status, 500)
    assert.deepEqual(
      events.map((e) => [e.operation, e.indeterminate]),
      [
        ['purgeObject', true],
        ['purgeSubject', true],
      ],
      'ROJO: una purga que falló DESPUÉS de borrar no notifica indeterminate: true (F del auditor: «borró=1 … EVENTOS=0»)'
    )
    assert.deepEqual(sequence, ['hook:purgeObject', 'catch:purgeObject', 'hook:purgeSubject', 'catch:purgeSubject'], 'el evento sale ANTES de propagar')
    assert.deepEqual(events[0].object, doc)
    assert.notProperty(events[0], 'subject')
    assert.deepEqual(events[1].subject, u)
    assert.notProperty(events[1], 'object')
    for (const e of events) {
      assert.deepEqual(e.actor, actor)
      assert.notProperty(e, 'transactional')
    }
  })

  test('CONTROL (la cara C2): el MISMO 503 no-timeout SIN la marca (no se había borrado nada) ⇒ cero eventos — «esa escritura no ocurrió» sigue siendo verdad ahí', async ({ assert }) => {
    const { manager, events } = partialDriver(
      () => new AuthorizationBackendError('fake-relations', 'purgeObject', new Error('caído antes de borrar')),
      () => new PurgeIncompleteError('purgeSubject: quedan 1 tuplas')
    )
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    assert.equal((await manager.purgeObject(doc, S).then(() => null, (e) => e))?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    assert.equal((await manager.purgeSubject(u, S).then(() => null, (e) => e))?.code, 'E_AUTHZ_PURGE_INCOMPLETE')
    assert.deepEqual(events, [])
  })
})

/**
 * **⚪ del auditor**: el evento es una COPIA (G: «el evento guardado dice
 * object.id=MUTADO-DESPUES»), y `actor: null` es 422 de identidad (E1),
 * anunciado como BREAKING en el CHANGELOG.
 */
test.group('cierre alpha.3 · ⚪ · el evento es una copia (no alias) y actor: null es 422 E_AUTHZ_INVALID_IDENTITY', () => {
  test('mutar object/partition/subject/actor DESPUÉS de la escritura no cambia el evento guardado; y un sink que muta el evento no toca las constantes del llamante; el actor conserva sus campos de más (documentado, sin poda)', async ({
    assert,
  }) => {
    const { manager, events } = sevenWaySpiedManager()
    const doc: any = { type: 'document', id: uuidv7() }
    const S: any = { type: 'unit', uuid: uuidv7() }
    const u: any = { type: 'user', uuid: uuidv7() }
    const group: any = { object: { type: 'group', id: uuidv7() }, relation: 'member' }
    const actor: any = { type: 'admin', uuid: uuidv7(), admin: true }
    const original = { doc: doc.id, S: S.uuid, u: u.uuid, group: group.object.id, actor: actor.uuid }
    await manager.relate(u, 'viewer', doc, S, { actor })
    await manager.relate(group, 'viewer', doc, S, { actor })
    await manager.purgeObject(doc, S, { actor })
    await manager.purgeSubject(u, S, { actor })
    doc.id = 'MUTADO-DESPUES'
    S.uuid = 'MUTADO-DESPUES'
    u.uuid = 'MUTADO-DESPUES'
    group.object.id = 'MUTADO-DESPUES'
    actor.uuid = 'MUTADO-DESPUES'
    assert.lengthOf(events, 4)
    for (const e of events) {
      assert.equal(e.partition.uuid, original.S, `ROJO (${e.operation}): el evento es un ALIAS de la partición del llamante (G del auditor)`)
      assert.equal(e.actor.uuid, original.actor, `${e.operation}: alias del actor`)
      assert.isTrue(e.actor.admin, `${e.operation}: el actor viaja con sus campos de más (⚪ 9: por referencia lógica, sin poda)`)
    }
    assert.equal(events[0].object.id, original.doc, 'ROJO: el evento guardado dice object.id=MUTADO-DESPUES')
    assert.equal(events[0].subject.uuid, original.u)
    assert.equal(events[1].subject.object.id, original.group, 'el objeto del userset también se copia')
    assert.equal(events[2].object.id, original.doc)
    assert.equal(events[3].subject.uuid, original.u)
    // Un sink hostil que muta el evento no cambia las constantes del llamante.
    const hostile = sevenWaySpiedManager({
      onRelationWrite: (e: any) => {
        e.partition.uuid = 'ENVENENADO'
        e.object.id = 'ENVENENADO'
      },
    })
    const doc2 = { type: 'document', id: uuidv7() }
    const S2 = { type: 'unit', uuid: uuidv7() }
    const ids = { doc: doc2.id, S: S2.uuid }
    await hostile.manager.relate({ type: 'user', uuid: uuidv7() }, 'viewer', doc2, S2)
    assert.equal(doc2.id, ids.doc, 'el sink no alcanza el objeto del llamante')
    assert.equal(S2.uuid, ids.S, 'ni su partición')
  })

  test('actor: null ⇒ 422 E_AUTHZ_INVALID_IDENTITY en las CUATRO escrituras (con requireActor: false), cero llamadas, cero eventos — BREAKING respecto a alpha.2, donde null pasaba por «sin actor»', async ({
    assert,
  }) => {
    const { manager, calls, events } = sevenWaySpiedManager({ requireActor: false })
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const S = { type: 'unit', uuid: uuidv7() }
    for (const [op, run] of [
      ['relate', () => manager.relate(u, 'viewer', doc, S, { actor: null } as any)],
      ['unrelate', () => manager.unrelate(u, 'viewer', doc, S, { actor: null } as any)],
      ['purgeObject', () => manager.purgeObject(doc, S, { actor: null } as any)],
      ['purgeSubject', () => manager.purgeSubject(u, S, { actor: null } as any)],
    ] as Array<[string, () => Promise<unknown>]>) {
      const caught = await run().then(() => null, (e) => e)
      assert.equal(caught?.code, 'E_AUTHZ_INVALID_IDENTITY', `${op}: ${caught?.message ?? 'ENTRÓ'}`)
      assert.equal(caught?.status, 422)
    }
    assert.deepEqual(calls, [])
    assert.deepEqual(events, [])
    // `undefined` (o la clave ausente) sigue siendo «sin actor».
    await manager.relate(u, 'viewer', doc, S, { actor: undefined })
    assert.deepEqual(calls, ['relate'])
    assert.notProperty(events[0], 'actor')
  })
})

/* ── CIERRE-2 de alpha.3 (re-ataque del auditor, decisiones 2026-09-02 (2d)) ── */

/**
 * **🟠 1 · REGRESIÓN del cierre**: `assertRelationDeclared(config, object,
 * relation?)` con `if (relation === undefined) return` compartido por las
 * siete operaciones apagó F-05 en `relate`/`unrelate` sin relación
 * (`request.input('relation')` ausente): antes `isDeclared('document',
 * undefined)` era `false` ⇒ 422 con cero llamadas; con el opcional los dobles
 * ESCRIBÍAN la tupla (2e/2f del auditor: «NINGUNO»), `openfga` devolvía 503
 * del servidor y `database` lo salvaba su driver (paridad rota). **🟡 2**:
 * `listSubjects(undefined)` devolvía la UNIÓN de relaciones del objeto. Ahora
 * son DOS funciones: la ESTRICTA (relación obligatoria) y la de TIPO
 * (`purgeObject`). **Mutante**: volver a aceptar `undefined` en la estricta ⇒
 * rojo («la escritura ENTRÓ sin relación»).
 */
test.group('cierre-2 alpha.3 · 🟠 1 / 🟡 2 · relate/unrelate/check/listSubjects/listObjects/membersOf SIN relación ⇒ 422 E_AUTHZ_RELATION_UNKNOWN antes del driver (dos funciones, no un opcional)', () => {
  const S = { type: 'organization', uuid: uuidv7() }

  test('relation: undefined (y "", null, un número) ⇒ 422 E_AUTHZ_RELATION_UNKNOWN en las seis operaciones que nombran relación, cero llamadas, cero eventos; purgeObject (tipo solo) sigue entrando', async ({
    assert,
  }) => {
    const { manager, calls, events } = sevenWaySpiedManager()
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    for (const missing of [undefined, '', null, 7] as any[]) {
      const label = JSON.stringify(missing) ?? 'undefined'
      for (const [op, run] of [
        ['relate', () => manager.relate(u, missing, doc, S)],
        ['unrelate', () => manager.unrelate(u, missing, doc, S)],
        ['check', () => manager.check(u, missing, doc, S)],
        ['listSubjects', () => manager.listSubjects(missing, doc, S)],
        ['listObjects', () => manager.listObjects(u, missing, 'document', S)],
        ['membersOf', () => manager.membersOf({ type: 'group', id: uuidv7() }, missing, S)],
      ] as Array<[string, () => Promise<unknown>]>) {
        const caught = await run().then(() => null, (e) => e)
        assert.isNotNull(caught, `ROJO (${op}/${label}): ENTRÓ sin relación (la regresión 🟠 1 del cierre)`)
        assert.equal(caught.status, 422, `${op}/${label}: ${caught.message}`)
        assert.equal(caught.code, 'E_AUTHZ_RELATION_UNKNOWN', `${op}/${label}`)
      }
    }
    assert.deepEqual(calls, [], 'cero llamadas al driver: ni una tupla escrita, ni una lectura')
    assert.deepEqual(events, [], 'cero eventos')
    assert.isFalse(await manager.check(u, 'viewer', doc, S), 'nada se escribió')
    // La de TIPO: una purga no nombra relación y entra.
    await manager.purgeObject(doc, S)
    assert.deepEqual(calls, ['check', 'purgeObject'])
  })

  test('🟡 2 · listSubjects(undefined) ya NO es la unión de todas las relaciones del objeto: 422; con la relación, solo esa', async ({ assert }) => {
    const { manager } = sevenWaySpiedManager()
    const u = { type: 'user', uuid: uuidv7() }
    const v = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    await manager.relate(u, 'viewer', doc, S)
    await manager.relate(v, 'owner', doc, S)
    const caught = await manager.listSubjects(undefined as any, doc, S).then(() => null, (e) => e)
    assert.equal(caught?.code, 'E_AUTHZ_RELATION_UNKNOWN', 'ROJO: sin relación devolvió la UNIÓN (u y v)')
    assert.deepEqual((await manager.listSubjects('owner', doc, S)).subjects, [v])
    assert.deepEqual((await manager.listSubjects('viewer', doc, S)).subjects, [u])
  })

  test('el userset del sujeto sin relación ({ object, relation: undefined }) ⇒ 422 E_AUTHZ_RELATION_UNKNOWN en relate/check/listObjects/purgeSubject (2g del auditor), cero llamadas', async ({ assert }) => {
    const { manager, calls } = sevenWaySpiedManager()
    const doc = { type: 'document', id: uuidv7() }
    const evil = { object: { type: 'group', id: uuidv7() }, relation: undefined } as any
    for (const [op, run] of [
      ['relate', () => manager.relate(evil, 'viewer', doc, S)],
      ['check', () => manager.check(evil, 'viewer', doc, S)],
      ['listObjects', () => manager.listObjects(evil, 'viewer', 'document', S)],
      ['purgeSubject', () => manager.purgeSubject(evil, S)],
    ] as Array<[string, () => Promise<unknown>]>) {
      const caught = await run().then(() => null, (e) => e)
      assert.equal(caught?.code, 'E_AUTHZ_RELATION_UNKNOWN', `ROJO (${op}): ${caught?.message ?? 'ENTRÓ'}`)
      assert.equal(caught?.status, 422)
    }
    assert.deepEqual(calls, [])
  })

  test('🟡 3 · membersOf pasa por F-05 (par) ANTES de la capacidad: role_binding ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN, relación no declarada ⇒ 422 E_AUTHZ_RELATION_UNKNOWN, cero llamadas (1a/1b del auditor); también donde membersOf sería 500 UNSUPPORTED', async ({
    assert,
  }) => {
    const { manager, calls } = sevenWaySpiedManager()
    const doc = { type: 'document', id: uuidv7() }
    const binding = { type: 'role_binding', id: uuidv7() }
    const a = await manager.membersOf(binding, 'assignee', S).then(() => null, (e) => e)
    assert.equal(a?.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN', `ROJO (1a): membersOf(role_binding) ${a ? a.message : 'respondió {subjects: []}'}`)
    const b = await manager.membersOf(doc, 'relacion-no-declarada', S).then(() => null, (e) => e)
    assert.equal(b?.code, 'E_AUTHZ_RELATION_UNKNOWN', `ROJO (1b): ${b ? b.message : 'respondió'}`)
    assert.deepEqual(calls, [], 'cero llamadas al driver')
    // CONTROL: lo declarado sigue respondiendo (el doble trae membersOf).
    assert.deepEqual((await manager.membersOf({ type: 'group', id: uuidv7() }, 'member', S)).subjects, [])
    // Sin la capacidad, F-05 sigue yendo primero: 422, no 500.
    const config = contractRelationsConfig()
    const noMembers = new RelationsManager(makeRelationsDriver({ config, capabilities: { ...CAPS, membersOfNative: false } }), config)
    const c = await noMembers.membersOf(binding, 'assignee', S).then(() => null, (e) => e)
    assert.equal(c?.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN', 'F-05 antes del 500 de capacidad')
    const d = await noMembers.membersOf({ type: 'group', id: uuidv7() }, 'member', S).then(() => null, (e) => e)
    assert.equal(d?.code, 'E_AUTHZ_UNSUPPORTED', 'lo declarado sin capacidad sigue siendo el 500 de siempre')
  })

  test('⚪ 4 · markPartialWrite sobre un error CONGELADO no lanza TypeError: devuelve el original sin marca, y por el manager el 503 original se propaga tal cual (sin evento: no pudo marcarse)', async ({ assert }) => {
    const frozen = Object.freeze(new AuthorizationBackendError('fake-relations', 'purgeObject', new Error('congelado')))
    const returned = markPartialWrite(frozen)
    assert.strictEqual(returned, frozen, 'devuelve el MISMO objeto')
    assert.isFalse(Object.prototype.hasOwnProperty.call(frozen, 'partialWrite'), 'no pudo marcar')
    const config = contractRelationsConfig()
    const driver: any = Object.create(makeRelationsDriver({ config, capabilities: CAPS }))
    driver.purgeObject = async () => {
      throw markPartialWrite(frozen)
    }
    const events: any[] = []
    const manager = new RelationsManager(driver, config, { onRelationWrite: (e: any) => void events.push(e) })
    const caught = await manager.purgeObject({ type: 'document', id: uuidv7() }, S).then(() => null, (e) => e)
    assert.strictEqual(caught, frozen, 'ROJO (3a): el TypeError de defineProperty SUSTITUYÓ al 503 real')
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    assert.equal(caught.status, 503)
    assert.deepEqual(events, [])
  })
})
