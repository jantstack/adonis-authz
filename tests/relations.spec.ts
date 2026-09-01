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
