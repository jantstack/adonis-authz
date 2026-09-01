/**
 * El driver `database` de relaciones (Fase 4, lote 4-3) contra el contrato del
 * puerto (`runRelationsDriverContract`) en el motor de `TEST_DB` —SQLite, PG 18
 * o MySQL 8.4—, más los casos de SOLO-DRIVER que el contrato no expresa: el
 * TRIGGER de partición (INSERT y UPDATE), el dialecto ajeno y el barrido de las
 * dos ortografías del uuid de partición en `purge*`.
 *
 * Es SQL puro: no toca el `:8101`.
 */
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { runRelationsDriverContract, contractRelationsConfig } from '../src/testing/relations_contract.js'
import {
  DatabaseRelationsDriver,
  relationPartitionTrigger,
} from '../src/drivers/database_relations_driver.js'
import { UnsupportedDialectError } from '../src/errors.js'
import { sqlExpiryCodec } from '../src/shared/sql_expiry.js'
import type { ScopeRef } from '../src/types.js'

/* ── El contrato del puerto contra el driver REAL ────────────────────────── */

runRelationsDriverContract({
  name: `database (${process.env.TEST_DB ?? 'sqlite'})`,
  capabilities: {
    singleCheckRelations: true,
    listObjectsInherited: false,
    usersetSubjects: true,
    membersOfNative: true,
    enumerateRelations: true,
    listObjectsTruncation: false,
    injectableClock: true,
  },
  makeDriver: async (config) => {
    // La tabla es COMPARTIDA: aislamiento por caso vaciándola (las particiones
    // son uuids frescos, pero la limpieza mantiene los conteos deterministas).
    await db.from('authz_relations').delete()
    return new DatabaseRelationsDriver(config)
  },
})

/* ── El TRIGGER de partición: caso de DRIVER, INSERT y UPDATE ─────────────── */

test.group('database relations — el trigger de partición defiende al escritor a mano', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  const partitionA = `unit|${uuidv7()}`
  const partitionB = `unit|${uuidv7()}`

  function baseRow(overrides: Record<string, unknown> = {}) {
    return {
      uuid: uuidv7(),
      partition_key: partitionA,
      object_type: 'document',
      object_uuid: uuidv7(),
      relation: 'viewer',
      subject_type: 'group',
      subject_uuid: uuidv7(),
      subject_relation: 'member',
      subject_partition: partitionA,
      created_at: new Date(),
      ...overrides,
    }
  }

  test('un userset de la MISMA partición se inserta', async ({ assert }) => {
    await db.table('authz_relations').insert(baseRow())
    const rows = await db.from('authz_relations').where('partition_key', partitionA)
    assert.lengthOf(rows, 1)
  })

  test('un HOLDER (sin subject_relation) NO lo mira el trigger, aunque subject_partition difiera', async ({
    assert,
  }) => {
    // El trigger solo actúa sobre usersets; un holder no lleva partición de sujeto.
    await db.table('authz_relations').insert(
      baseRow({ subject_type: 'user', subject_uuid: uuidv7(), subject_relation: null, subject_partition: null })
    )
    const rows = await db.from('authz_relations').where('partition_key', partitionA)
    assert.lengthOf(rows, 1)
  })

  test('INSERT de un userset de OTRA partición ⇒ el motor lo RECHAZA', async ({ assert }) => {
    await assert.rejects(() =>
      db.table('authz_relations').insert(baseRow({ subject_partition: partitionB }))
    )
    const rows = await db.from('authz_relations')
    assert.lengthOf(rows, 0)
  })

  test('UPDATE que MUEVE el userset a otra partición ⇒ el motor lo RECHAZA', async ({ assert }) => {
    const row = baseRow()
    await db.table('authz_relations').insert(row)
    await assert.rejects(() =>
      db.from('authz_relations').where('uuid', row.uuid).update({ subject_partition: partitionB })
    )
    // La fila sigue en su partición original: el UPDATE no pasó.
    const [after] = await db.from('authz_relations').where('uuid', row.uuid).select('subject_partition')
    assert.equal(after.subject_partition, partitionA)
  })
})

/* ── Dialecto ajeno ⇒ throw ───────────────────────────────────────────────── */

test.group('database relations — dialecto no medido', () => {
  test('relationPartitionTrigger(dialecto ajeno) ⇒ 500 E_AUTHZ_UNSUPPORTED_DIALECT', ({ assert }) => {
    let caught: any
    try {
      relationPartitionTrigger('oracledb')
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.instanceOf(caught, UnsupportedDialectError)
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_UNSUPPORTED_DIALECT')
  })

  test('la CTE del check con un dialecto ajeno ⇒ 500 E_AUTHZ_UNSUPPORTED_DIALECT', async ({ assert }) => {
    // Conexión FALSA con un dialecto que la suite no mide: la CTE recursiva no
    // se declara igual en dos motores, así que se niega antes de construirla.
    const fakeDatabase = { connection: () => ({ dialect: { name: 'oracledb' } }) }
    const driver = new DatabaseRelationsDriver(contractRelationsConfig(), {}, fakeDatabase)
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    let caught: any
    try {
      await driver.check({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, p)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.instanceOf(caught, UnsupportedDialectError)
    assert.equal(caught.code, 'E_AUTHZ_UNSUPPORTED_DIALECT')
  })
})

/* ── 🟡2: purge* barre AMBAS ortografías del uuid de partición ─────────────── */

test.group('database relations — purge barre las dos ortografías del uuid de partición', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  const config = contractRelationsConfig()
  const driver = () => new DatabaseRelationsDriver(config)

  test('purgeObject borra la fila escrita con el uuid CON guiones aunque se purgue el SIN guiones', async ({
    assert,
  }) => {
    // 32 hex sin guiones: `scopeSpellings` lo expande a la forma 8-4-4-4-12.
    const dashless = uuidv7().replace(/-/g, '')
    const dashed = `${dashless.slice(0, 8)}-${dashless.slice(8, 12)}-${dashless.slice(12, 16)}-${dashless.slice(16, 20)}-${dashless.slice(20)}`
    const withDashes: ScopeRef = { type: 'unit', uuid: dashed }
    const withoutDashes: ScopeRef = { type: 'unit', uuid: dashless }
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }

    // Se escribe la relación en la partición CON guiones (la ortografía canónica).
    await driver().relate(u, 'viewer', doc, withDashes)
    assert.isTrue(await driver().check(u, 'viewer', doc, withDashes))

    // Se purga con la ortografía SIN guiones (la del llamante): el barrido de
    // ambas ortografías tiene que alcanzar la fila canónica igualmente.
    await driver().purgeObject(doc, withoutDashes)
    assert.isFalse(await driver().check(u, 'viewer', doc, withDashes))
    const rows = await db.from('authz_relations')
    assert.lengthOf(rows, 0)
  })

  test('purgeSubject barre las dos ortografías igual', async ({ assert }) => {
    const dashless = uuidv7().replace(/-/g, '')
    const dashed = `${dashless.slice(0, 8)}-${dashless.slice(8, 12)}-${dashless.slice(12, 16)}-${dashless.slice(16, 20)}-${dashless.slice(20)}`
    const withDashes: ScopeRef = { type: 'unit', uuid: dashed }
    const withoutDashes: ScopeRef = { type: 'unit', uuid: dashless }
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }

    await driver().relate(u, 'owner', doc, withDashes)
    await driver().purgeSubject(u, withoutDashes)
    assert.isFalse(await driver().check(u, 'owner', doc, withDashes))
    const rows = await db.from('authz_relations')
    assert.lengthOf(rows, 0)
  })
})

/* ── F-01/F-02 en `database`: DECORATIVOS, degradados a documentación ─────── */

/**
 * La frontera roles↔relations (F-01/F-02) NO tiene dientes en `database`: los
 * hechos de roles viven en `authz_assignments`/`authz_denies` y los de
 * relaciones en `authz_relations` —tablas DISJUNTAS—, así que una tupla de
 * relación es estructuralmente incapaz de aparecer en una lectura de roles y
 * viceversa. Un caso «relate ⇒ authorize sigue false» pasaría SIN implementar
 * ninguna frontera (falso-verde). Por eso F-01/F-02 se ANCLAN CON DIENTES en
 * `openfga` (store COMPARTIDO, `relations_bridge.spec.ts`) y aquí se degradan a
 * esta documentación EXPLÍCITA: se afirma la separación ESTRUCTURAL (un
 * `relate` no escribe una sola fila en la tabla de roles), que es lo único que
 * `database` puede demostrar y lo que hace la conflación imposible.
 */
test.group('database relations — F-01/F-02 son decorativos (tablas disjuntas): documentación', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  test('un relate() de relaciones NO toca la tabla de roles (authz_assignments)', async ({ assert }) => {
    const driver = new DatabaseRelationsDriver(contractRelationsConfig())
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const asgBefore = await db.from('authz_assignments').count('* as c').first()
    await driver.relate(u, 'viewer', doc, p)
    const asgAfter = await db.from('authz_assignments').count('* as c').first()
    // La escritura de relaciones dejó su fila en authz_relations…
    assert.lengthOf(await db.from('authz_relations'), 1)
    // …y CERO en la tabla de roles: la conflación es estructuralmente imposible.
    assert.equal(Number((asgAfter as any).c), Number((asgBefore as any).c))
  })
})

/* ── ⚪3 · enumerateRelations FILTRA por tipos declarados (paridad openfga) ── */

/**
 * El driver `openfga` de relaciones descarta de su enumeración todo
 * `object_type` que no sea `group` ni un tipo de `defineRelationsConfig`; el de
 * `database` NO lo hacía (auditor ⚪3). Como `reconcileRelations` escribe
 * `to.relate(...)` DIRECTO (salta el manager/F-05), una fila raw
 * `object_type='role_binding'` habría migrado al store compartido y reabierto
 * la escalada. Aquí se planta la fila a mano (el residuo del chokepoint) y se
 * exige que `enumerateRelations` NO la emita, y sí las de tipos declarados.
 */
test.group('database relations — ⚪3 · enumerateRelations filtra por tipos declarados', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  const APP: ScopeRef = { type: 'app', uuid: null }

  function rawRow(objectType: string): Record<string, unknown> {
    return {
      uuid: uuidv7(),
      partition_key: 'app',
      object_type: objectType,
      object_uuid: uuidv7(),
      relation: objectType === 'role_binding' ? 'assignee' : 'viewer',
      subject_type: 'user',
      subject_uuid: uuidv7(),
      subject_relation: null,
      subject_partition: null,
      created_at: new Date(),
    }
  }

  test('una fila raw role_binding NO se emite; la declarada (document) sí', async ({ assert }) => {
    // Fila envenenada (tipo reservado, a mano) + fila legítima (tipo declarado).
    await db.table('authz_relations').insert(rawRow('role_binding'))
    await db.table('authz_relations').insert(rawRow('document'))

    const driver = new DatabaseRelationsDriver(contractRelationsConfig())
    const page = await driver.enumerateRelations(APP)
    const types = page.tuples.map((t) => t.object.type)
    assert.notInclude(types, 'role_binding', 'el residuo del chokepoint NO se enumera')
    assert.include(types, 'document', 'el tipo declarado sí se enumera')
    assert.lengthOf(page.tuples, 1)
  })

  test('un userset (subject group#member) sobre un document declarado SÍ se emite', async ({ assert }) => {
    const row = rawRow('document')
    row.subject_type = 'group'
    row.subject_relation = 'member'
    row.subject_partition = 'app'
    await db.table('authz_relations').insert(row)
    const driver = new DatabaseRelationsDriver(contractRelationsConfig())
    const page = await driver.enumerateRelations(APP)
    assert.lengthOf(page.tuples, 1)
    assert.equal(page.tuples[0].object.type, 'document')
  })
})

/* ── R-15 · renovar la caducidad es DELETE+INSERT, nunca UPDATE (decisión (c)) ── */

/**
 * La decisión (c) del juez (INSERT/DELETE-ONLY) exigía, si R-15 entraba, un
 * caso que la OBSERVE: renovar la caducidad de una relación en `database` es
 * borrar la fila e insertar otra. Lo observable es el `uuid` (PK) de la fila:
 * un UPDATE lo conserva; delete+insert produce uno NUEVO, con UNA sola fila
 * al final. Y lo que no cambia no reescribe nada (idempotente): la misma
 * caducidad, u omitida, deja el MISMO uuid.
 */
test.group('database relations — R-15 · renovar la caducidad es delete+insert (INSERT/DELETE-ONLY)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  test('renovar cambia el uuid de la fila (fila NUEVA, una sola); la misma caducidad u omitida conservan el uuid', async ({
    assert,
  }) => {
    const driver = new DatabaseRelationsDriver(contractRelationsConfig())
    const codec = sqlExpiryCodec(db.connection())
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const T1 = new Date(Date.now() + 3_600_000)
    const T2 = new Date(Date.now() + 7_200_000)
    const rows = async () =>
      db.from('authz_relations').select('uuid', codec.select('expires_at') as any).orderBy('uuid')

    await driver.relate(u, 'viewer', doc, p, { expiresAt: T1 })
    const [first] = await rows()
    assert.equal(codec.fromDb(first.expires_at)!.getTime(), T1.getTime())

    // RENOVAR: otra caducidad ⇒ delete + insert ⇒ OTRO uuid, y sigue habiendo UNA fila.
    await driver.relate(u, 'viewer', doc, p, { expiresAt: T2 })
    const afterRenew = await rows()
    assert.lengthOf(afterRenew, 1, 'una sola fila tras renovar')
    assert.notEqual(afterRenew[0].uuid, first.uuid, 'renovar es delete+insert: la fila es NUEVA (no un UPDATE)')
    assert.equal(codec.fromDb(afterRenew[0].expires_at)!.getTime(), T2.getTime())
    assert.isTrue(await driver.check(u, 'viewer', doc, p))

    // La MISMA caducidad no reescribe (idempotente): mismo uuid.
    await driver.relate(u, 'viewer', doc, p, { expiresAt: T2 })
    const same = await rows()
    assert.equal(same[0].uuid, afterRenew[0].uuid, 'misma caducidad ⇒ no se toca la fila')
    // Omitida preserva la vigente sin reescribir: mismo uuid, misma caducidad.
    await driver.relate(u, 'viewer', doc, p)
    const kept = await rows()
    assert.equal(kept[0].uuid, afterRenew[0].uuid, 'omitida ⇒ no se toca la fila')
    assert.equal(codec.fromDb(kept[0].expires_at)!.getTime(), T2.getTime())
    // `null` la quita: otra fila (delete+insert), sin caducidad.
    await driver.relate(u, 'viewer', doc, p, { expiresAt: null })
    const lifted = await rows()
    assert.lengthOf(lifted, 1)
    assert.notEqual(lifted[0].uuid, afterRenew[0].uuid, 'quitar la caducidad también es delete+insert')
    assert.isNull(codec.fromDb(lifted[0].expires_at))
  })
})

/* ── R-16 · el driver database rechaza un object.id inválido (defensa) ────── */

test.group('database relations — R-16 · object.id inválido ⇒ 422 (defensa en profundidad)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  const P: ScopeRef = { type: 'unit', uuid: uuidv7() }

  test('relate con object.id "a|b" ⇒ 422 E_AUTHZ_INVALID_IDENTITY, sin fila', async ({ assert }) => {
    const driver = new DatabaseRelationsDriver(contractRelationsConfig())
    let caught: any
    try {
      await driver.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: 'a|b' }, P)
    } catch (e) {
      caught = e
    }
    assert.equal(caught?.status, 422)
    assert.equal(caught?.code, 'E_AUTHZ_INVALID_IDENTITY')
    assert.lengthOf(await db.from('authz_relations'), 0)
  })
})
