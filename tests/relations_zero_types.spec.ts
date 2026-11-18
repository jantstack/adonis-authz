/**
 * **`objectTypes: []` — cero tipos de dominio (2.5.1)**. SQL puro (todos los motores); no toca ningún OpenFGA.
 *
 * Una app que solo necesita el tipo built-in `group` (relación `member`, el portador de los usersets) activa el bloque
 * `relations` con la lista VACÍA: hasta 2.5.0 `defineRelationsConfig` exigía al menos un tipo y obligaba a inventar uno.
 * Lo que este fichero fija:
 *
 *  (a) `[]` se acepta y la config resultante declara `group#member` y NADA más;
 *  (b) con cero tipos, `group#member` funciona de punta a punta en `database` (driver y manager): relate, check
 *      (directo y transitivo), listObjects, listSubjects, membersOf, enumerateRelations, unrelate, purgeObject y
 *      purgeSubject;
 *  (c) **la frontera de seguridad**: cero tipos NO es «cualquier tipo vale» — toda operación sobre un tipo no declarado
 *      (también los del modelo `facts`: `role_binding`, `scope`) sigue siendo el 422 `E_AUTHZ_RELATION_TYPE_UNKNOWN` de
 *      siempre, ANTES de tocar la conexión; `group#<otra>` sigue siendo `E_AUTHZ_RELATION_UNKNOWN`;
 *  (d) `saveRelationsConfig` persiste la spec vacía, se relee validada, y la guarda del alcance de los denies sigue
 *      negando el guardado que deja huérfano un deny vivo;
 *  (e) lo que NO es un array (omitido, `null`, cadena, objeto) sigue siendo 422 `E_AUTHZ_RELATION_CONFIG`.
 */
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import type { RelationsConfigSpec } from '../src/relations/define_relations_config.js'
import { RelationsManager } from '../src/relations/manager.js'
import {
  checkRelationsConfigDenyReach,
  readRelationsConfig,
  readRelationsConfigSpec,
  saveRelationsConfig,
} from '../src/relations_config_store.js'
import type { ScopeRef } from '../src/types.js'

/** La spec del chasis: cero tipos de dominio, solo `group#member` con sus holders. */
const ZERO: RelationsConfigSpec = { objectTypes: [], holderTypes: ['user', 'admin'], database: { membersOf: true } }

const catching = async (fn: () => unknown): Promise<any> => {
  try {
    await fn()
    return null
  } catch (error) {
    return error
  }
}

const uuidsOf = (subjects: any[]) => subjects.map((s) => s.uuid ?? `${s.object.id}#${s.relation}`).sort()

/* ── (a) y (e): el validador ──────────────────────────────────────────────── */

test.group('relaciones · objectTypes: [] — defineRelationsConfig (2.5.1)', () => {
  test('(a) objectTypes: [] se ACEPTA: la config declara group#member y nada más', ({ assert }) => {
    const config = defineRelationsConfig(ZERO)
    assert.deepEqual([...config.objectTypes], [])
    assert.isTrue(Object.isFrozen(config.objectTypes))
    assert.isTrue(config.membersOf)
    assert.isTrue(config.hasType('group'))
    assert.isTrue(config.isDeclared('group', 'member'))
    // Y NADA más: ni un tipo de dominio, ni los del modelo facts, ni otra relación de `group`.
    for (const type of ['document', 'space', 'role_binding', 'scope', 'role', 'user', '', '*']) {
      assert.isFalse(config.hasType(type), `hasType('${type}')`)
      assert.isFalse(config.isDeclared(type, 'member'), `isDeclared('${type}', 'member')`)
    }
    assert.isFalse(config.isDeclared('group', 'viewer'))
    // Sin holderTypes ni opciones también vale (la forma mínima).
    const bare = defineRelationsConfig({ objectTypes: [] })
    assert.deepEqual([...bare.objectTypes], [])
    assert.isFalse(bare.membersOf)
    assert.isTrue(bare.isDeclared('group', 'member'))
  })

  test('(e) lo que NO es un array (omitido, null, cadena, objeto, array-like) sigue siendo 422 E_AUTHZ_RELATION_CONFIG', async ({ assert }) => {
    const notArrays: unknown[] = [undefined, null, 'document', '', {}, { length: 0 }, { 0: { type: 'document', relations: [{ name: 'a' }] }, length: 1 }, 0, true, new Set()]
    for (const objectTypes of notArrays) {
      const error = await catching(() => defineRelationsConfig({ objectTypes, holderTypes: ['user'] } as any))
      assert.isNotNull(error, `objectTypes: ${JSON.stringify(objectTypes) ?? String(objectTypes)} se ACEPTÓ`)
      assert.equal(error.status, 422, String(error?.message))
      assert.equal(error.code, 'E_AUTHZ_RELATION_CONFIG', String(error?.message))
      assert.include(error.message, `'objectTypes' tiene que ser un array`)
    }
    // Omitir la clave entera es lo mismo que `undefined`.
    const omitted = await catching(() => defineRelationsConfig({ holderTypes: ['user'] } as any))
    assert.equal(omitted?.code, 'E_AUTHZ_RELATION_CONFIG', String(omitted?.message))
    assert.include(omitted.message, `'objectTypes' tiene que ser un array`)
  })

  test('las demás validaciones no se relajan con la lista vacía: holderTypes mal formado y clave desconocida siguen siendo 422', async ({ assert }) => {
    const badHolders = await catching(() => defineRelationsConfig({ objectTypes: [], holderTypes: 'user' } as any))
    assert.equal(badHolders?.code, 'E_AUTHZ_RELATION_CONFIG', String(badHolders?.message))
    const unknownKey = await catching(() => defineRelationsConfig({ objectTypes: [], deny: true } as any))
    assert.equal(unknownKey?.status, 422, String(unknownKey?.message))
    assert.equal(unknownKey?.code, 'E_AUTHZ_RELATION_CONFIG_UNKNOWN_KEY', String(unknownKey?.message))
    // Y `group` sigue sin poder DECLARARSE (es built-in y reservado): vacío no abre esa puerta.
    const group = await catching(() => defineRelationsConfig({ objectTypes: [{ type: 'group', relations: [{ name: 'member' }] }] }))
    assert.equal(group?.code, 'E_AUTHZ_RELATION_CONFIG', String(group?.message))
  })
})

/* ── (b) y (c): el driver `database` y el manager ─────────────────────────── */

test.group('relaciones · objectTypes: [] — database de punta a punta (2.5.1)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
    return async () => {
      await db.from('authz_relations').delete()
    }
  })

  const P: ScopeRef = { type: 'unit', uuid: uuidv7() }
  const OTHER: ScopeRef = { type: 'unit', uuid: uuidv7() }

  /** Un driver cuya conexión CUENTA cada acceso: cero accesos = la guarda cortó antes del backend. */
  function spied() {
    let connections = 0
    const config = defineRelationsConfig(ZERO)
    const driver = new DatabaseRelationsDriver(config, { transactionalWrites: false }, {
      connection: (name?: string) => {
        connections += 1
        return db.connection(name)
      },
    })
    return { config, driver, manager: new RelationsManager(driver, config), connections: () => connections }
  }

  for (const via of ['driver', 'manager'] as const) {
    test(`(b) ${via}: group#member funciona entero con cero tipos — relate, check, listObjects, listSubjects, membersOf, enumerate, unrelate, purge`, async ({ assert }) => {
      const made = spied()
      const rel: any = made[via]
      const alice = { type: 'user', uuid: uuidv7() }
      const bob = { type: 'admin', uuid: uuidv7() }
      const carol = { type: 'user', uuid: uuidv7() }
      const team = { type: 'group', id: uuidv7() }
      const org = { type: 'group', id: uuidv7() }

      // relate: dos miembros directos del equipo, y el equipo entero (userset) dentro de la organización.
      await rel.relate(alice, 'member', team, P)
      await rel.relate(bob, 'member', team, P)
      await rel.relate({ object: team, relation: 'member' }, 'member', org, P)
      assert.lengthOf(await db.from('authz_relations'), 3)

      // check: directo, transitivo por el userset, y los negativos (no miembro; otra partición).
      assert.isTrue(await rel.check(alice, 'member', team, P))
      assert.isTrue(await rel.check(bob, 'member', team, P))
      assert.isTrue(await rel.check(alice, 'member', org, P), 'transitivo: alice ∈ team ⊂ org')
      assert.isFalse(await rel.check(carol, 'member', team, P), 'carol no es miembro')
      assert.isFalse(await rel.check(alice, 'member', team, OTHER), 'otra partición no ve nada')
      assert.deepEqual(await rel.checkMany(carol, 'member', [team, org], P), [false, false])
      assert.deepEqual(await rel.checkMany(alice, 'member', [team, org], P), [true, true])

      // listObjects: los grupos de alice (directo + heredado por el userset).
      const groups = await rel.listObjects(alice, 'member', 'group', P)
      assert.deepEqual(groups.objects.map((o: any) => o.id).sort(), [team.id, org.id].sort())
      assert.deepEqual((await rel.listObjects(carol, 'member', 'group', P)).objects, [])

      // listSubjects: los sujetos DIRECTOS (el userset tal cual); membersOf: la membresía transitiva.
      assert.deepEqual(uuidsOf((await rel.listSubjects('member', team, P)).subjects), [alice.uuid, bob.uuid].sort())
      assert.deepEqual(uuidsOf((await rel.listSubjects('member', org, P)).subjects), [`${team.id}#member`])
      assert.deepEqual(uuidsOf((await rel.membersOf(team, 'member', P)).subjects), [alice.uuid, bob.uuid].sort())
      assert.deepEqual(uuidsOf((await rel.membersOf(org, 'member', P)).subjects), [alice.uuid, bob.uuid].sort(), 'membersOf(org) trae a los del equipo')

      // enumerateRelations (el origen de reconcile): las tres tuplas, todas de `group`.
      const page = await rel.enumerateRelations(P)
      assert.lengthOf(page.tuples, 3)
      assert.isTrue(page.tuples.every((t: any) => t.object.type === 'group' && t.relation === 'member'))

      // unrelate: bob sale del equipo y deja de ser miembro de los dos.
      await rel.unrelate(bob, 'member', team, P)
      assert.isFalse(await rel.check(bob, 'member', team, P))
      assert.isFalse(await rel.check(bob, 'member', org, P))
      assert.isTrue(await rel.check(alice, 'member', org, P))
      assert.lengthOf(await db.from('authz_relations'), 2)

      // purgeSubject: todo lo de alice en la partición.
      await rel.relate(alice, 'member', org, P)
      await rel.purgeSubject(alice, P)
      assert.isFalse(await rel.check(alice, 'member', team, P))
      assert.isFalse(await rel.check(alice, 'member', org, P))
      assert.lengthOf(await db.from('authz_relations'), 1, 'queda el userset team#member ⊂ org')

      // purgeObject: el grupo `org` desaparece con sus tuplas.
      await rel.relate(carol, 'member', org, P)
      await rel.purgeObject(org, P)
      assert.lengthOf(await db.from('authz_relations'), 0)
      assert.isAbove(made.connections(), 0, 'CONTROL del espía: el camino legal SÍ pide la conexión')
    })

    test(`(c) ${via}: cero tipos NO es «cualquier tipo vale» — toda operación sobre un tipo no declarado ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN, cero accesos, cero filas`, async ({ assert }) => {
      const made = spied()
      const rel: any = made[via]
      const u = { type: 'user', uuid: uuidv7() }
      for (const type of ['document', 'space', 'tenancy_node', 'role_binding', 'scope', 'role', 'user']) {
        const object = { type, id: uuidv7() }
        const operations: Array<[string, () => Promise<unknown>]> = [
          ['relate', () => rel.relate(u, 'member', object, P)],
          ['relate(assignee)', () => rel.relate(u, 'assignee', object, P)],
          ['unrelate', () => rel.unrelate(u, 'member', object, P)],
          ['check', () => rel.check(u, 'member', object, P)],
          ['checkMany', () => rel.checkMany(u, 'member', [object], P)],
          ['listObjects', () => rel.listObjects(u, 'member', type, P)],
          ['listSubjects', () => rel.listSubjects('member', object, P)],
          ['membersOf', () => rel.membersOf(object, 'member', P)],
          ['purgeObject', () => rel.purgeObject(object, P)],
          // Un userset de un tipo no declarado como SUJETO de una membresía (legal en el objeto, ilegal en el sujeto).
          ['relate(userset ajeno)', () => rel.relate({ object, relation: 'member' }, 'member', { type: 'group', id: uuidv7() }, P)],
          ['purgeSubject(userset ajeno)', () => rel.purgeSubject({ object, relation: 'member' }, P)],
        ]
        for (const [name, run] of operations) {
          const error = await catching(run)
          assert.isNotNull(error, `${name} ACEPTÓ el tipo no declarado '${type}' con objectTypes: []`)
          assert.equal(error.status, 422, `${name} · ${type}: ${error?.message}`)
          assert.equal(error.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN', `${name} · ${type}: ${error?.message}`)
        }
      }
      // `group` solo tiene `member`: otra relación es el 422 de relación de siempre.
      const g = { type: 'group', id: uuidv7() }
      for (const [name, run] of [
        ['relate', () => rel.relate(u, 'viewer', g, P)],
        ['unrelate', () => rel.unrelate(u, 'viewer', g, P)],
        ['check', () => rel.check(u, 'viewer', g, P)],
        ['listObjects', () => rel.listObjects(u, 'viewer', 'group', P)],
      ] as Array<[string, () => Promise<unknown>]>) {
        const error = await catching(run)
        assert.isNotNull(error, `${name} ACEPTÓ group#viewer`)
        assert.equal(error.status, 422, `${name} · group#viewer: ${error?.message}`)
        assert.equal(error.code, 'E_AUTHZ_RELATION_UNKNOWN', `${name} · group#viewer: ${error?.message}`)
      }
      assert.equal(made.connections(), 0, 'la guarda corta ANTES de pedir la conexión')
      assert.lengthOf(await db.from('authz_relations'), 0)
    })
  }

  test('(c) el MISMO error que con tipos declarados: código, status y letra de un tipo ajeno no cambian con la lista vacía', async ({ assert }) => {
    const u = { type: 'user', uuid: uuidv7() }
    const folder = { type: 'folder', id: uuidv7() }
    const some = new DatabaseRelationsDriver(
      defineRelationsConfig({ objectTypes: [{ type: 'document', relations: [{ name: 'viewer' }] }], holderTypes: ['user'] }),
      { transactionalWrites: false }
    )
    const zero = spied().driver
    const before = await catching(() => some.relate(u, 'viewer', folder, P))
    const after = await catching(() => zero.relate(u, 'viewer', folder, P))
    assert.equal(before?.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN')
    assert.equal(after?.code, before.code)
    assert.equal(after?.status, before.status)
    assert.equal(after?.message, before.message)
  })

  test('(c) deny sobre group#member sigue rechazado y enumerateRelations no emite una fila de un tipo no declarado escrita a mano', async ({ assert }) => {
    const { driver } = spied()
    const u = { type: 'user', uuid: uuidv7() }
    const g = { type: 'group', id: uuidv7() }
    const denied = await catching(() => driver.deny!(u, 'member', g, P))
    assert.isNotNull(denied, 'deny(group#member) se ACEPTÓ')
    assert.equal(denied.status, 422, String(denied?.message))
    assert.lengthOf(await db.from('authz_relations'), 0)

    await driver.relate(u, 'member', g, P)
    const row: any = await db.from('authz_relations').first()
    await db.table('authz_relations').insert({ ...row, uuid: uuidv7(), object_type: 'document', object_uuid: uuidv7(), relation: 'viewer' })
    const page = await driver.enumerateRelations(P)
    assert.deepEqual(page.tuples.map((t) => `${t.object.type}#${t.relation}`), ['group#member'])
  })
})

/* ── (d): la config persistida ────────────────────────────────────────────── */

test.group('relaciones · objectTypes: [] — saveRelationsConfig (2.5.1)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
    await db.from('authz_relations_config').delete()
    return async () => {
      await db.from('authz_relations').delete()
      await db.from('authz_relations_config').delete()
    }
  })

  test('(d) saveRelationsConfig persiste la spec vacía, se relee VALIDADA y el detector del alcance de los denies la da por buena', async ({ assert }) => {
    const saved = await saveRelationsConfig(ZERO)
    assert.deepEqual([...saved.objectTypes], [])
    const row: any = await db.from('authz_relations_config').where('id', 1).first()
    assert.deepEqual(JSON.parse(String(row.spec)).objectTypes, [], 'la fila lleva objectTypes: [] (no se omite ni se rellena)')

    const spec = await readRelationsConfigSpec()
    assert.deepEqual(spec!.objectTypes, [])
    const config = await readRelationsConfig()
    assert.isNotNull(config)
    assert.isTrue(config!.isDeclared('group', 'member'))
    assert.isFalse(config!.hasType('document'))
    assert.isTrue(config!.membersOf)

    const reach = await checkRelationsConfigDenyReach(saved)
    assert.isTrue(reach.ok, reach.lines.join(' '))
    // Re-guardar la misma spec es idempotente, y crecer desde cero tipos entra sin forzar nada.
    await saveRelationsConfig(ZERO)
    await saveRelationsConfig({ ...ZERO, objectTypes: [{ type: 'document', relations: [{ name: 'viewer' }] }] })
    assert.isTrue((await readRelationsConfig())!.hasType('document'))
  })

  test('(d) la guarda del alcance de los denies NO se apaga con la lista vacía: vaciar los tipos con un deny vivo ⇒ 500 E_AUTHZ_DENY_REACH_REFUSED, cero escrituras', async ({ assert }) => {
    const P: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const withDeny: RelationsConfigSpec = {
      objectTypes: [{ type: 'note', deny: 'write', relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }] }],
      holderTypes: ['user'],
    }
    await saveRelationsConfig(withDeny)
    const driver = new DatabaseRelationsDriver(defineRelationsConfig(withDeny), { transactionalWrites: false })
    await driver.deny!({ type: 'user', uuid: uuidv7() }, 'editor', { type: 'note', id: uuidv7() }, P)
    const before = String(((await db.from('authz_relations_config').where('id', 1).first()) as any).spec)

    const refused = await catching(() => saveRelationsConfig({ objectTypes: [], holderTypes: ['user'] }))
    assert.isNotNull(refused, 'saveRelationsConfig GUARDÓ objectTypes: [] dejando huérfano un deny vivo')
    assert.equal(refused.status, 500, String(refused?.message))
    assert.equal(refused.code, 'E_AUTHZ_DENY_REACH_REFUSED', String(refused?.message))
    assert.deepEqual(refused.findings.map((f: any) => [f.objectType, f.relation, f.reason, f.count]), [['note', 'editor', 'orphan', 1]])
    assert.equal(String(((await db.from('authz_relations_config').where('id', 1).first()) as any).spec), before, 'la fila no cambió')

    // Y el detector lo ve igual si un proceso SIRVE la lista vacía contra esa fila.
    const reach = await checkRelationsConfigDenyReach(defineRelationsConfig({ objectTypes: [], holderTypes: ['user'] }))
    assert.isFalse(reach.ok, 'el detector dio por buena una config vacía con un deny vivo')
  })
})
