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
import type { ScopeRef } from '../src/types.js'

/* ── El contrato del puerto contra el driver REAL ────────────────────────── */

runRelationsDriverContract({
  name: `database (${process.env.TEST_DB ?? 'sqlite'})`,
  capabilities: {
    singleCheckRelations: true,
    listObjectsInherited: false,
    usersetSubjects: true,
    membersOfNative: true,
    enumerateRelations: false,
    listObjectsTruncation: false,
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
