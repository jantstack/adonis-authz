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
import type { RelationsDriverCapabilities } from '../src/types.js'

const CAPS: RelationsDriverCapabilities = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: false,
  injectableClock: true,
  // L-2: `false` hasta L-4 (la escritura real en la transacción del llamante); la cara `whenFalse` es la que se juzga hoy.
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
