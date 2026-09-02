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
import { testEngine } from './helpers/app.js'

/**
 * L-4: `{ transaction }` exige pool ≥ 2 (la barrera del freeze lee por la
 * conexión del motor mientras el llamante sostiene la suya), así que el
 * harness `database` declara la cara `true` en `sqlite-file`/PG/MySQL y la
 * `false` en `:memory:` (pool 1/1) — lo que un despliegue con pool 1 declara
 * (`transactionalWrites: false` en las opciones del driver), mismo criterio que
 * el harness de roles desde L-3.
 */
const TRANSACTIONAL_WRITES = testEngine() !== 'sqlite'

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
    transactionalWrites: TRANSACTIONAL_WRITES,
  },
  makeDriver: async (config) => {
    // La tabla es COMPARTIDA: aislamiento por caso vaciándola (las particiones
    // son uuids frescos, pero la limpieza mantiene los conteos deterministas).
    await db.from('authz_relations').delete()
    return new DatabaseRelationsDriver(config, { transactionalWrites: TRANSACTIONAL_WRITES })
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

/* ── L-0 · F-05 vive TAMBIÉN en el driver (la red de manager.driver() y reconcile) ── */

/**
 * Panel `{trx}`, 🔴 2 del auditor: F-05 («solo tipos/relaciones declarados en
 * `defineRelationsConfig`») vivía SOLO en el `RelationsManager`, y el docblock
 * del puerto publicaba que el driver la re-validaba — era falso. Como
 * `reconcileRelations` y `manager.driver()` entran por el driver, la premisa
 * «una sola validación por la que embudan TODOS los caminos» no se cumplía.
 * Aquí el driver `database` la aplica ANTES de tocar la conexión: el espía es
 * la propia `database` inyectada —si la guarda no corta, `connection()` se
 * llama y el caso lo ve—. En `database` la tabla es propia (inocuo), pero la
 * paridad con `openfga` (donde el store es COMPARTIDO) exige el MISMO 422.
 */
test.group('database relations — L-0 · F-05 en el driver: 422 ANTES de tocar la conexión (espía)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  const P: ScopeRef = { type: 'unit', uuid: uuidv7() }

  /** Un driver cuya conexión CUENTA cada acceso: cero accesos = la guarda cortó antes del backend. */
  function spiedDriver(): { driver: DatabaseRelationsDriver; connections: () => number } {
    let connections = 0
    const driver = new DatabaseRelationsDriver(contractRelationsConfig(), {}, {
      connection: (name?: string) => {
        connections += 1
        return db.connection(name)
      },
    })
    return { driver, connections: () => connections }
  }

  test('relate/unrelate con object.type NO declarado (role_binding, scope) ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN, cero accesos a la conexión, cero filas', async ({
    assert,
  }) => {
    const { driver, connections } = spiedDriver()
    const u = { type: 'user', uuid: uuidv7() }
    for (const object of [
      { type: 'role_binding', id: uuidv7() },
      { type: 'scope', id: uuidv7() },
      { type: 'folder', id: uuidv7() },
    ]) {
      for (const op of ['relate', 'unrelate'] as const) {
        let caught: any
        try {
          await driver[op](u, 'assignee', object, P)
          assert.fail(`${op} aceptó el tipo no declarado '${object.type}'`)
        } catch (e) {
          caught = e
        }
        assert.equal(caught?.status, 422, `${op} · ${object.type}: ${caught?.message}`)
        assert.equal(caught?.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN', `${op} · ${object.type}`)
      }
    }
    assert.equal(connections(), 0, 'la guarda corta ANTES de pedir la conexión')
    assert.lengthOf(await db.from('authz_relations'), 0)
  })

  test('relate/unrelate con una relación NO declarada del tipo (document#assignee, group#viewer) ⇒ 422 E_AUTHZ_RELATION_UNKNOWN, cero accesos', async ({
    assert,
  }) => {
    const { driver, connections } = spiedDriver()
    const u = { type: 'user', uuid: uuidv7() }
    for (const [relation, object] of [
      ['assignee', { type: 'document', id: uuidv7() }],
      ['viewer', { type: 'group', id: uuidv7() }],
    ] as const) {
      for (const op of ['relate', 'unrelate'] as const) {
        let caught: any
        try {
          await driver[op](u, relation, object, P)
          assert.fail(`${op} aceptó la relación no declarada '${object.type}#${relation}'`)
        } catch (e) {
          caught = e
        }
        assert.equal(caught?.status, 422, `${op} · ${object.type}#${relation}`)
        assert.equal(caught?.code, 'E_AUTHZ_RELATION_UNKNOWN', `${op} · ${object.type}#${relation}`)
      }
    }
    assert.equal(connections(), 0)
    assert.lengthOf(await db.from('authz_relations'), 0)
  })

  test('CONTROL: lo declarado (document#viewer) y el built-in (group#member) SÍ entran y escriben', async ({ assert }) => {
    const { driver, connections } = spiedDriver()
    const u = { type: 'user', uuid: uuidv7() }
    await driver.relate(u, 'viewer', { type: 'document', id: uuidv7() }, P)
    await driver.relate(u, 'member', { type: 'group', id: uuidv7() }, P)
    assert.isAbove(connections(), 0)
    assert.lengthOf(await db.from('authz_relations'), 2)
  })
})

/* ── L-4 · `{ transaction }` REAL en el driver `database` de relaciones, medido por motor ── */

/**
 * L-4 (panel `{trx}`, veredicto (C); `panel-trx-juez.md` §7 · L-4). La
 * regla: **la ESCRITURA va por tu transacción; la AUTORIDAD (barrera del
 * freeze, F-05, `assertWrite`, partición) NUNCA.** El runner publicado ya
 * juzga la cara `true` (rollback ⇒ CERO tuplas por censo para las cuatro,
 * commit, trx ajena ⇒ 500 sin sentencia). Aquí va lo que el runner no puede
 * montar: el trigger de partición disparando DENTRO de la trx del llamante,
 * la autoridad que lanza sin una sola sentencia por la trx, la caducidad ×
 * trx (renovar = delete+insert dentro de la trx y el rollback devuelve la
 * caducidad anterior), el choque del UNIQUE y el **deadlock A→B/B→A** de dos
 * trx externas (🟡 12 del auditor), y la cara de pool 1. `{ transaction }`
 * exige pool ≥ 2 (decisión del dueño): el grupo grande corre en
 * `sqlite-file`/PG/MySQL; la cara honesta de `:memory:` corre en los cuatro.
 */

/** Espía sobre una transacción REAL de Lucid: cuenta las sentencias que el paquete construye por ella. */
function spyTransaction<T extends object>(trx: T): { transaction: T; statements: () => number } {
  let statements = 0
  const counted = new Set(['from', 'table', 'query', 'insertQuery', 'rawQuery', 'raw', 'knexQuery', 'knexRawQuery', 'modelQuery', 'transaction'])
  const transaction = new Proxy(trx, {
    get(target, prop) {
      const value = Reflect.get(target, prop)
      if (typeof value !== 'function') return value
      if (typeof prop === 'string' && counted.has(prop)) {
        return (...args: unknown[]) => {
          statements += 1
          return value.apply(target, args)
        }
      }
      return value.bind(target)
    },
  })
  return { transaction, statements: () => statements }
}

async function rejects(assert: any, run: () => unknown, code: string, status: number, note?: string): Promise<any> {
  try {
    await run()
  } catch (error: any) {
    assert.equal(error?.code, code, `${note ?? ''} code de ${error?.message ?? error}`)
    assert.equal(error?.status, status, `${note ?? ''} status de ${error?.message ?? error}`)
    return error
  }
  assert.fail(`${note ?? ''}: se esperaba ${code} y no lanzó`)
}

/** ¿Sigue viva la transacción del llamante? (PG la aborta tras un error; MySQL y SQLite no.) */
async function transactionAlive(trx: any): Promise<{ alive: boolean; error?: any }> {
  try {
    await trx.from('authz_catalog_version').where('id', 1).select('id')
    return { alive: true }
  } catch (error) {
    return { alive: false, error }
  }
}

/** El censo de una partición por la conexión del motor: filas con `uuid` y `expires_at` (por el codec). */
async function partitionRows(p: ScopeRef): Promise<Array<{ uuid: string; expires_at: Date | null; object_uuid: string }>> {
  const codec = sqlExpiryCodec(db.connection())
  const rows: any[] = await db
    .from('authz_relations')
    .where('partition_key', `${p.type}|${p.uuid}`)
    .select('uuid', 'object_uuid', codec.select('expires_at') as any)
    .orderBy('uuid')
  return rows.map((r) => ({ uuid: String(r.uuid), object_uuid: String(r.object_uuid), expires_at: codec.fromDb(r.expires_at) }))
}

const L4_ENGINE = testEngine()
const L4_TRIGGER_MESSAGE = /userset no puede pertenecer a otra partici/

/** Un `RelationsManager` sobre el driver `database` REAL (con `onRelationWrite` capturado). */
async function relationsWorker(managerOptions: Record<string, unknown> = {}, driverOptions: Record<string, unknown> = {}) {
  const { RelationsManager } = await import('../src/relations/manager.js')
  const config = contractRelationsConfig()
  const driver = new DatabaseRelationsDriver(config, driverOptions)
  const events: any[] = []
  const manager = new RelationsManager(driver, config, {
    driverName: 'database',
    onRelationWrite: (e: any) => events.push(e),
    ...managerOptions,
  } as any)
  return { manager, driver, events }
}

/** Un manager de ROLES (el que abre y cierra el freeze durable). */
async function rolesWorker() {
  const { AuthorizationManager } = await import('../src/manager.js')
  const { DatabaseAuthorizationDriver } = await import('../src/drivers/database_driver.js')
  return new AuthorizationManager({
    default: 'database',
    drivers: { database: () => new DatabaseAuthorizationDriver({}) },
    holderTypes: { users: 'user' },
    warnOnOptInSecurity: false,
  } as any)
}

if (L4_ENGINE !== 'sqlite') {
  test.group(`L-4 · { transaction } real en database (relations) — motor ${L4_ENGINE}, pool ≥ 2`, (group) => {
    group.each.setup(async () => {
      await db.from('authz_relations').delete()
      await db.from('authz_catalog_version').where('id', 2).update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null })
      return async () => {
        await db.from('authz_relations').delete()
        await db.from('authz_catalog_version').where('id', 2).update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null })
      }
    })

    /**
     * El trigger de partición sigue disparando DENTRO de la trx del llamante:
     * un `relate` legítimo entra POR la trx (el trigger lo deja pasar en ESE
     * INSERT) y una fila con userset de OTRA partición insertada a mano por
     * la MISMA trx la rechaza el motor con el mensaje del trigger (la
     * sentencia es del consumidor: su error es crudo, del motor). Lo que
     * queda de la trx después es del motor y se mide: PG la deja ABORTADA
     * —el siguiente `relate` del paquete por esa trx es un 503 CLASIFICADO
     * (`25P02`), nunca el error crudo—; MySQL y SQLite la dejan viva y el
     * siguiente `relate` entra. Tras el rollback: CERO filas (ni la legítima
     * ni la envenenada).
     */
    test('el trigger de partición dispara DENTRO de la trx del llamante: la fila cross-partición insertada por la trx la rechaza el motor; lo que queda de la trx (PG abortada ⇒ 503 clasificado en el siguiente relate; MySQL/SQLite viva) se mide; rollback ⇒ cero filas', async ({
      assert,
    }) => {
      const { manager } = await relationsWorker()
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const other: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const u = { type: 'user', uuid: uuidv7() }
      const v = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      let triggerError: any
      let afterPoison: { ok?: true; error?: any } = {}
      let insideRows = -1
      let caught: any
      try {
        await db.transaction(async (trx) => {
          await manager.relate(u, 'viewer', doc, p, { transaction: trx })
          insideRows = (await trx.from('authz_relations').where('partition_key', `${p.type}|${p.uuid}`)).length
          try {
            await trx.table('authz_relations').insert({
              uuid: uuidv7(),
              partition_key: `${p.type}|${p.uuid}`,
              object_type: 'document',
              object_uuid: doc.id,
              relation: 'viewer',
              subject_type: 'group',
              subject_uuid: uuidv7(),
              subject_relation: 'member',
              subject_partition: `${other.type}|${other.uuid}`,
              created_at: new Date(),
            })
            assert.fail('ROJO: el trigger de partición NO disparó dentro de la trx del llamante')
          } catch (error) {
            triggerError = error
          }
          afterPoison = await manager.relate(v, 'viewer', doc, p, { transaction: trx }).then(
            () => ({ ok: true as const }),
            (error) => ({ error })
          )
          throw new Error('rollback a propósito')
        })
      } catch (error) {
        caught = error
      }
      assert.equal(caught?.message, 'rollback a propósito')
      assert.equal(insideRows, 1, 'el relate legítimo entró POR la trx (visible por ella antes de confirmar)')
      assert.match(String(triggerError?.message ?? ''), L4_TRIGGER_MESSAGE, `el motor rechazó la fila con el mensaje del trigger: ${triggerError?.message}`)
      if (L4_ENGINE === 'pg') {
        assert.isUndefined(afterPoison.ok, 'PostgreSQL: la trx quedó abortada por el trigger y el siguiente relate no entra')
        assert.equal(afterPoison.error?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', `clasificado, no crudo: ${afterPoison.error?.message}`)
        assert.equal(afterPoison.error?.status, 503)
        assert.equal(afterPoison.error?.cause?.code, '25P02')
      } else {
        assert.isTrue(afterPoison.ok, `${L4_ENGINE}: la trx sigue viva tras el rechazo del trigger y el siguiente relate entra: ${afterPoison.error?.message}`)
      }
      assert.lengthOf(await partitionRows(p), 0, 'rollback ⇒ ni la legítima ni la envenenada')
      assert.isFalse(await manager.check(u, 'viewer', doc, p))
    }).timeout(20_000)

    /**
     * La AUTORIDAD que lanza ⇒ CERO sentencias por la trx del llamante: F-05
     * (por el manager y por el driver directo), `assertWrite` del consumidor
     * y la barrera del freeze. Y tras el `unfreeze` la MISMA llamada entra
     * POR la trx.
     */
    test('assertWrite / F-05 / freeze que lanzan ⇒ CERO sentencias por la trx del llamante (espía); tras el unfreeze la misma llamada entra POR la trx', async ({
      assert,
    }) => {
      const { manager, driver, events } = await relationsWorker({
        assertWrite: (ref: any) => {
          if (ref.relation === 'owner') throw new Error('no se permite conceder owner')
        },
      })
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }

      // F-05 y assertWrite, por el manager; F-05 por el driver directo.
      await db.transaction(async (trx) => {
        const spy = spyTransaction(trx)
        const evil = await rejects(assert, () => manager.relate(u, 'assignee', { type: 'role_binding', id: uuidv7() }, p, { transaction: spy.transaction }), 'E_AUTHZ_RELATION_TYPE_UNKNOWN', 422, 'F-05 manager')
        assert.isString(evil.message)
        await rejects(assert, () => driver.relate(u, 'assignee', { type: 'role_binding', id: uuidv7() }, p, { transaction: spy.transaction }), 'E_AUTHZ_RELATION_TYPE_UNKNOWN', 422, 'F-05 driver')
        await rejects(assert, () => manager.unrelate(u, 'assignee', doc, p, { transaction: spy.transaction }), 'E_AUTHZ_RELATION_UNKNOWN', 422, 'F-05 relación')
        let threw = false
        try {
          await manager.relate(u, 'owner', doc, p, { transaction: spy.transaction })
        } catch {
          threw = true
        }
        assert.isTrue(threw, 'assertWrite rechazó')
        assert.equal(spy.statements(), 0, 'ROJO: la autoridad se leyó/escribió por la trx del llamante')
      })
      assert.deepEqual(events, [], 'nada que auditar')

      // El freeze: 503 E_AUTHZ_FROZEN en las cuatro, cero sentencias por la trx.
      const roles = await rolesWorker()
      const token = await roles.freeze('cutover L-4')
      try {
        const trx = await db.transaction()
        const spy = spyTransaction(trx)
        try {
          for (const [op, run] of [
            ['relate', () => manager.relate(u, 'viewer', doc, p, { transaction: spy.transaction })],
            ['unrelate', () => manager.unrelate(u, 'viewer', doc, p, { transaction: spy.transaction })],
            ['purgeObject', () => manager.purgeObject(doc, p, { transaction: spy.transaction })],
            ['purgeSubject', () => manager.purgeSubject(u, p, { transaction: spy.transaction })],
          ] as const) {
            const error = await rejects(assert, run, 'E_AUTHZ_FROZEN', 503, op)
            assert.isTrue(error.retryable, `${op}: reintentable`)
          }
          assert.equal(spy.statements(), 0, 'ROJO: la barrera se leyó por la trx del llamante (o algo entró)')
        } finally {
          await trx.rollback()
        }
      } finally {
        await roles.unfreeze(token)
      }
      assert.lengthOf(await partitionRows(p), 0)

      // Tras el unfreeze, la MISMA llamada entra POR la trx y confirma con ella.
      let statements = -1
      await db.transaction(async (trx) => {
        const spy = spyTransaction(trx)
        await manager.relate(u, 'viewer', doc, p, { transaction: spy.transaction })
        statements = spy.statements()
        assert.isFalse(await manager.check(u, 'viewer', doc, p), 'sin confirmar, la conexión del motor no la ve')
      })
      assert.isAbove(statements, 0, 'la escritura fue por la trx del llamante')
      assert.isTrue(await manager.check(u, 'viewer', doc, p))
      assert.lengthOf(await partitionRows(p), 1)
      assert.lengthOf(events, 1)
    }).timeout(20_000)

    /**
     * Caducidad × trx (R-15 se cruza con L-4): renovar la caducidad es
     * delete+insert DENTRO de la trx del llamante (por ella se ve la fila
     * NUEVA con OTRO uuid y la caducidad nueva; por la conexión del motor
     * sigue la vieja), y el rollback DEVUELVE la caducidad anterior: el censo
     * tiene la fila con el `uuid` y el `expires_at` viejos, no la nueva. Con
     * commit, la nueva.
     */
    test('caducidad × trx: renovar = delete+insert DENTRO de la trx del llamante; rollback ⇒ la fila con el expires_at VIEJO está de vuelta (mismo uuid), no la nueva; commit ⇒ la nueva', async ({
      assert,
    }) => {
      const { manager } = await relationsWorker()
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const T1 = new Date(Date.now() + 3_600_000)
      const T2 = new Date(Date.now() + 7_200_000)
      const codec = sqlExpiryCodec(db.connection())
      await manager.relate(u, 'viewer', doc, p, { expiresAt: T1 })
      const [before] = await partitionRows(p)
      assert.equal(before.expires_at?.getTime(), T1.getTime())

      let inside: any[] = []
      let outsideMeanwhile: any[] = []
      try {
        await db.transaction(async (trx) => {
          await manager.relate(u, 'viewer', doc, p, { transaction: trx, expiresAt: T2 })
          inside = (await trx.from('authz_relations').where('partition_key', `${p.type}|${p.uuid}`).select('uuid', codec.select('expires_at') as any)).map(
            (r: any) => ({ uuid: String(r.uuid), expires_at: codec.fromDb(r.expires_at) })
          )
          outsideMeanwhile = await partitionRows(p)
          throw new Error('rollback a propósito')
        })
      } catch (error: any) {
        if (error?.message !== 'rollback a propósito') throw error
      }
      assert.lengthOf(inside, 1, 'dentro de la trx: UNA fila (delete+insert, no dos)')
      assert.notEqual(inside[0].uuid, before.uuid, 'dentro de la trx: la fila es NUEVA (otro uuid)')
      assert.equal(inside[0].expires_at?.getTime(), T2.getTime(), 'dentro de la trx: la caducidad nueva')
      assert.deepEqual(
        outsideMeanwhile.map((r) => [r.uuid, r.expires_at?.getTime()]),
        [[before.uuid, T1.getTime()]],
        'mientras la trx está abierta la conexión del motor sigue viendo la fila vieja'
      )
      const after = await partitionRows(p)
      assert.deepEqual(
        after.map((r) => [r.uuid, r.expires_at?.getTime()]),
        [[before.uuid, T1.getTime()]],
        'ROJO: el rollback no devolvió la caducidad anterior (la fila vieja con su uuid)'
      )

      await db.transaction(async (trx) => {
        await manager.relate(u, 'viewer', doc, p, { transaction: trx, expiresAt: T2 })
      })
      const committed = await partitionRows(p)
      assert.lengthOf(committed, 1)
      assert.notEqual(committed[0].uuid, before.uuid)
      assert.equal(committed[0].expires_at?.getTime(), T2.getTime(), 'commit ⇒ la caducidad nueva')
    }).timeout(20_000)

    test('transactionalWrites: false declarado en el driver (pool 1) ⇒ { transaction } es 500 E_AUTHZ_UNSUPPORTED de la puerta 1 y también saltándose el manager, cero sentencias; sin transaction la misma escritura entra', async ({
      assert,
    }) => {
      const { manager, driver } = await relationsWorker({}, { transactionalWrites: false })
      assert.equal(driver.capabilities.transactionalWrites, false)
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      await db.transaction(async (trx) => {
        const spy = spyTransaction(trx)
        const error = await rejects(assert, () => manager.relate(u, 'viewer', doc, p, { transaction: spy.transaction }), 'E_AUTHZ_UNSUPPORTED', 500)
        assert.include(error.message, 'transactionalWrites')
        assert.include(error.message, "'database'")
        const direct = await rejects(assert, () => driver.relate(u, 'viewer', doc, p, { transaction: spy.transaction }), 'E_AUTHZ_UNSUPPORTED', 500)
        assert.include(direct.message, 'pool 1')
        await rejects(assert, () => driver.purgeObject(doc, p, { transaction: spy.transaction }), 'E_AUTHZ_UNSUPPORTED', 500)
        assert.equal(spy.statements(), 0)
      })
      assert.lengthOf(await partitionRows(p), 0)
      await manager.relate(u, 'viewer', doc, p)
      assert.isTrue(await manager.check(u, 'viewer', doc, p))
    })

    /**
     * Dos `relate` del MISMO hecho en dos transacciones externas. T1 inserta
     * y no confirma; T2 inserta lo mismo. Medido por motor (la tabla y su
     * UNIQUE son otros que en L-3, así que se mide, no se supone): PG y MySQL
     * hacen esperar al INSERT de T2 en el índice único hasta que T1 confirma
     * y entonces T2 recibe el choque ⇒ 409 `E_AUTHZ_WRITE_CONFLICT` (PG deja
     * la trx abortada; MySQL solo deshace la sentencia); SQLite (fichero, WAL)
     * no espera: T2 ya tiene snapshot de lectura (el «¿ya existe?») y no puede
     * subir a escritora ⇒ `SQLITE_BUSY` inmediato, 503 clasificado.
     */
    test('choque del UNIQUE de authz_relations con dos relate (userset) en dos trx externas ⇒ error CLASIFICADO (409 E_AUTHZ_WRITE_CONFLICT en PG/MySQL; 503 SQLITE_BUSY en sqlite-file); lo que queda de la trx del perdedor, medido por motor', async ({
      assert,
    }) => {
      const { manager, events } = await relationsWorker()
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      // Sujeto USERSET (`subject_relation` NO nulo): es donde el UNIQUE de
      // `authz_relations` muerde de verdad — ver el HALLAZGO del holder abajo.
      const u = { object: { type: 'group', id: uuidv7() }, relation: 'member' }
      const doc = { type: 'document', id: uuidv7() }
      const t1 = await db.transaction()
      const t2 = await db.transaction()
      let t2Result: { ok?: unknown; error?: any } = {}
      let alive: { alive: boolean; error?: any } = { alive: true }
      const started = Date.now()
      try {
        await manager.relate(u, 'viewer', doc, p, { transaction: t1 })
        const second = manager.relate(u, 'viewer', doc, p, { transaction: t2 }).then(
          (ok) => ({ ok: ok ?? true }),
          (error) => ({ error })
        )
        await new Promise((resolve) => setTimeout(resolve, 300))
        await t1.commit()
        t2Result = await second
        alive = await transactionAlive(t2)
      } finally {
        await t2.rollback().catch(() => {})
        if (!t1.isCompleted) await t1.rollback().catch(() => {})
      }
      const elapsed = Date.now() - started
      assert.isUndefined(t2Result.ok, 'ROJO: el segundo relate «entró» sobre una tupla que ya escribió otra transacción')
      const error = t2Result.error
      assert.isString(error?.code, `clasificado: ${error?.message}`)
      assert.isNumber(error?.status)
      if (L4_ENGINE === 'sqlite-file') {
        assert.equal(error.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', `sqlite-file: SQLITE_BUSY clasificado (${error.message})`)
        assert.equal(error.status, 503)
        assert.match(String(error.cause?.code ?? error.cause?.message ?? ''), /SQLITE_BUSY/)
        assert.isTrue(alive.alive, 'sqlite-file: la transacción del perdedor sigue viva tras el BUSY')
      } else {
        assert.equal(error.code, 'E_AUTHZ_WRITE_CONFLICT', `${L4_ENGINE}: el UNIQUE dentro de tu transacción es 409 (${error.message})`)
        assert.equal(error.status, 409)
        assert.include(error.message, 'rollback')
        if (L4_ENGINE === 'pg') {
          assert.isFalse(alive.alive, 'PostgreSQL: la transacción del perdedor queda ABORTADA (25P02) hasta el rollback')
          assert.equal(alive.error?.cause?.code ?? alive.error?.code, '25P02')
        } else {
          assert.isTrue(alive.alive, 'MySQL: solo se deshace la sentencia; la transacción sigue viva')
        }
      }
      assert.isBelow(elapsed, 20_000, `el choque se resolvió en ${elapsed} ms`)
      assert.lengthOf(events, 1, 'un solo evento: el relate de T1; el perdedor no publica nada')
      assert.lengthOf(await partitionRows(p), 1, 'el censo: solo la fila de T1')
      assert.isTrue(await manager.check(u, 'viewer', doc, p))
    }).timeout(30_000)

    /**
     * **HALLAZGO de L-4 (medido, no corregido: decisión del dueño).** El
     * UNIQUE publicado `authz_rel_tuple_uq` incluye `subject_relation`, que es
     * `NULL` para un HOLDER, y en los tres motores dos `NULL` son DISTINTOS en
     * un índice único: el UNIQUE solo defiende las tuplas con USERSET. Dos
     * `relate` concurrentes del MISMO hecho de holder en dos transacciones
     * (el «¿ya existe?» de cada una no ve a la otra) ENTRAN los dos, sin
     * espera, sin choque y sin deadlock, y confirman DOS filas iguales: la
     * idempotencia del invariante 6 vale en secuencia, no bajo concurrencia.
     * No concede de más (`check` es el mismo `true`; `unrelate`/`purge*`
     * borran las dos por su WHERE) pero `listSubjects`/`enumerateRelations`
     * emiten el sujeto DOS veces. Cerrarlo es un cambio de ESQUEMA publicado
     * (`subject_relation NOT NULL DEFAULT ''`, o un índice parcial —que MySQL
     * no tiene—): fuera de L-4, dicho en el informe. En SQLite-file no se
     * observa porque el segundo escritor ya recibe `SQLITE_BUSY`.
     */
    test('HALLAZGO · el UNIQUE de authz_relations NO cubre subject_relation NULL: dos relate concurrentes del MISMO hecho de HOLDER en dos trx entran los dos y confirman DOS filas (PG/MySQL); en sqlite-file el segundo es SQLITE_BUSY', async ({
      assert,
    }) => {
      const { manager } = await relationsWorker()
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const t1 = await db.transaction()
      const t2 = await db.transaction()
      let second: { ok?: true; error?: any } = {}
      try {
        await manager.relate(u, 'viewer', doc, p, { transaction: t1 })
        second = await manager.relate(u, 'viewer', doc, p, { transaction: t2 }).then(
          () => ({ ok: true as const }),
          (error) => ({ error })
        )
        await t1.commit()
        if (second.ok) await t2.commit()
        else await t2.rollback()
      } finally {
        if (!t1.isCompleted) await t1.rollback().catch(() => {})
        if (!t2.isCompleted) await t2.rollback().catch(() => {})
      }
      const rows = await partitionRows(p)
      if (L4_ENGINE === 'sqlite-file') {
        assert.isUndefined(second.ok)
        assert.equal(second.error?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
        assert.match(String(second.error?.cause?.code ?? ''), /SQLITE_BUSY/)
        assert.lengthOf(rows, 1)
      } else {
        assert.isTrue(second.ok, `${L4_ENGINE}: el segundo relate del holder NO esperó ni chocó: ${second.error?.message}`)
        assert.lengthOf(rows, 2, `${L4_ENGINE}: DOS filas iguales del mismo hecho de holder (el UNIQUE no cubre NULL)`)
        const listed = (await manager.listSubjects('viewer', doc, p)).subjects.filter((s: any) => s.uuid === u.uuid)
        assert.lengthOf(listed, 2, 'listSubjects lo emite dos veces')
      }
      assert.isTrue(await manager.check(u, 'viewer', doc, p), 'no concede de más: el mismo true')
      await manager.unrelate(u, 'viewer', doc, p)
      assert.lengthOf(await partitionRows(p), 0, 'unrelate borra las dos por su WHERE')
    }).timeout(30_000)

    /**
     * **Deadlock A→B / B→A** (🟡 12 del auditor, cerrado): T1 escribe la
     * relación sobre `docA` y T2 sobre `docB`; después, a la vez, T1 pide
     * `docB` y T2 pide `docA`. Cada INSERT espera en el índice único al otro:
     * el motor detecta el ciclo y elige una VÍCTIMA (PG tras
     * `deadlock_timeout`, 1 s por defecto, `40P01`; InnoDB al instante,
     * `1213`, y deshace la transacción ENTERA de la víctima). El perdedor
     * sale con **409 `E_AUTHZ_WRITE_CONFLICT`** («haz rollback y reintenta»),
     * jamás un cuelgue ni el error crudo del motor; el ganador —una vez la
     * víctima suelta sus locks— entra y confirma sus DOS filas. En SQLite no
     * hay deadlock posible: el segundo escritor recibe `SQLITE_BUSY` (503) ya
     * en su primera escritura, porque T1 sostiene el lock RESERVED.
     */
    test('deadlock A→B / B→A entre dos trx externas ⇒ el perdedor sale con 409 E_AUTHZ_WRITE_CONFLICT clasificado (PG 40P01 / MySQL 1213), nunca un cuelgue ni un error crudo; el ganador confirma sus dos filas; en sqlite-file el segundo escritor es 503 SQLITE_BUSY en su primera escritura', async ({
      assert,
    }) => {
      const { manager } = await relationsWorker()
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      // Sujeto USERSET: con un holder (`subject_relation` NULL) el UNIQUE no
      // muerde en ningún motor y no hay espera ni deadlock (HALLAZGO, abajo).
      const u = { object: { type: 'group', id: uuidv7() }, relation: 'member' }
      const docA = { type: 'document', id: `a-${uuidv7()}` }
      const docB = { type: 'document', id: `b-${uuidv7()}` }
      const t1 = await db.transaction()
      const t2 = await db.transaction()
      const started = Date.now()
      const settle = (run: Promise<unknown>) => run.then(() => ({ ok: true as const }), (error) => ({ error }))
      try {
        if (L4_ENGINE === 'sqlite-file') {
          await manager.relate(u, 'viewer', docA, p, { transaction: t1 })
          const second = await settle(manager.relate(u, 'viewer', docB, p, { transaction: t2 }))
          assert.isUndefined((second as any).ok, 'ROJO: el segundo escritor entró con T1 sosteniendo el lock')
          const error = (second as any).error
          assert.equal(error?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', `sqlite-file: BUSY clasificado (${error?.message})`)
          assert.equal(error?.status, 503)
          assert.match(String(error?.cause?.code ?? ''), /SQLITE_BUSY/)
          await t2.rollback()
          await t1.commit()
          assert.deepEqual((await partitionRows(p)).map((r) => r.object_uuid), [docA.id])
          return
        }
        // Paso 1: cada una escribe la suya (sin conflicto).
        await manager.relate(u, 'viewer', docA, p, { transaction: t1 })
        await manager.relate(u, 'viewer', docB, p, { transaction: t2 })
        // Paso 2: cruzado y a la vez. El primero en resolverse es la víctima.
        const r1 = settle(manager.relate(u, 'viewer', docB, p, { transaction: t1 })).then((r) => ({ who: 't1' as const, r }))
        const r2 = settle(manager.relate(u, 'viewer', docA, p, { transaction: t2 })).then((r) => ({ who: 't2' as const, r }))
        // Quién se resuelve primero es del motor: en PG la víctima (el ganador
        // sigue esperando sus locks hasta el rollback de la víctima); en MySQL
        // InnoDB deshace a la víctima al instante y el ganador puede resolverse
        // ANTES de que su rechazo llegue al event loop. Se aceptan los dos
        // órdenes; lo que no se acepta es que ENTREN los dos.
        const first = await Promise.race([r1, r2])
        let loser: { who: 't1' | 't2'; r: any }
        let winnerPromise: Promise<{ who: 't1' | 't2'; r: any }>
        if ((first.r as any).ok) {
          const other = await (first.who === 't1' ? r2 : r1)
          assert.isUndefined((other.r as any).ok, `ROJO: ENTRARON los dos (${first.who} y ${other.who}): no hubo deadlock`)
          loser = other
          winnerPromise = Promise.resolve(first)
        } else {
          loser = first
          winnerPromise = first.who === 't1' ? r2 : r1
        }
        const victim = loser.who === 't1' ? t1 : t2
        const error = loser.r.error
        assert.equal(error?.code, 'E_AUTHZ_WRITE_CONFLICT', `${L4_ENGINE}: el deadlock es 409 clasificado (${error?.message})`)
        assert.equal(error?.status, 409)
        assert.include(error?.message, 'DEADLOCK')
        assert.include(error?.message, 'rollback')
        // El código CRUDO del motor viaja en la cadena de causas (409 ← 503 de #sql ← pg/mysql2).
        const rawCodes: unknown[] = []
        for (let c: any = error?.cause; c; c = c.cause) rawCodes.push(L4_ENGINE === 'pg' ? c.code : c.errno)
        assert.include(rawCodes, L4_ENGINE === 'pg' ? '40P01' : 1213, `el motor devolvió ${JSON.stringify(rawCodes)}`)
        // Lo que queda de la víctima, medido: PG abortada; MySQL deshizo la
        // transacción ENTERA (su primera fila ya no está por su propia conexión).
        const victimFirst = loser.who === 't1' ? docA : docB
        const victimSees = await victim
          .from('authz_relations')
          .where('partition_key', `${p.type}|${p.uuid}`)
          .where('object_uuid', victimFirst.id)
          .then((rows: any[]) => ({ rows: rows.length }), (e: any) => ({ error: e }))
        if (L4_ENGINE === 'pg') {
          assert.equal((victimSees as any).error?.code, '25P02', 'PostgreSQL: la víctima queda ABORTADA hasta el rollback')
        } else {
          assert.equal((victimSees as any).rows, 0, 'MySQL: InnoDB deshizo la transacción ENTERA de la víctima (su primera fila tampoco está)')
        }
        await victim.rollback()
        // La víctima soltó sus locks: el ganador entra.
        const winner = await winnerPromise
        assert.isTrue((winner.r as any).ok, `el ganador (${winner.who}) entró tras el rollback de la víctima: ${(winner.r as any).error?.message}`)
        await (winner.who === 't1' ? t1 : t2).commit()
        assert.sameMembers((await partitionRows(p)).map((r) => r.object_uuid), [docA.id, docB.id], 'el censo: las DOS filas del ganador')
        assert.isTrue(await manager.check(u, 'viewer', docA, p))
        assert.isTrue(await manager.check(u, 'viewer', docB, p))
      } finally {
        if (!t1.isCompleted) await t1.rollback().catch(() => {})
        if (!t2.isCompleted) await t2.rollback().catch(() => {})
      }
      assert.isBelow(Date.now() - started, 20_000, 'jamás un cuelgue')
    }).timeout(30_000)
  })
}

test.group('L-4 · { transaction } en database (relations) con pool 1 (`:memory:`): la cara honesta', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
    return async () => {
      await db.from('authz_relations').delete()
    }
  })

  test('el driver declara transactionalWrites: true por defecto, false con la opción, y la vista withClock declara lo MISMO', ({ assert }) => {
    const config = contractRelationsConfig()
    const driver = new DatabaseRelationsDriver(config)
    assert.equal(driver.capabilities.transactionalWrites, true)
    assert.deepEqual(driver.withClock(() => new Date()).capabilities, driver.capabilities)
    const pool1 = new DatabaseRelationsDriver(config, { transactionalWrites: false })
    assert.equal(pool1.capabilities.transactionalWrites, false)
    assert.deepEqual(pool1.withClock(() => new Date()).capabilities, pool1.capabilities)
  })

  test('pool 1 + { transaction: trx } con el driver declarando true ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT por la barrera (SU deadline, jamás un cuelgue), cero sentencias por la trx y cero filas; con pool ≥ 2 la misma escritura entra y confirma con la trx', async ({
    assert,
  }) => {
    const { manager, events } = await relationsWorker({ freezeTimeoutMs: 400 })
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    let caught: any = null
    let statements = -1
    const started = Date.now()
    await db.transaction(async (trx) => {
      // El llamante sostiene su transacción (en `:memory:`, la ÚNICA conexión).
      await trx.from('authz_catalog_version').where('id', 1).select('id')
      const spy = spyTransaction(trx)
      try {
        await manager.relate(u, 'viewer', doc, p, { transaction: spy.transaction })
      } catch (error) {
        caught = error
      }
      statements = spy.statements()
    })
    const elapsed = Date.now() - started
    if (L4_ENGINE === 'sqlite') {
      assert.isNotNull(caught, 'ROJO: con pool 1 la autoridad se leyó por la transacción del llamante (la escritura entró)')
      assert.equal(caught.code, 'E_AUTHZ_BACKEND_TIMEOUT')
      assert.equal(caught.status, 503)
      assert.isBelow(elapsed, 5_000, `por el deadline de la barrera (400 ms), no por el del pool (${elapsed} ms)`)
      assert.equal(statements, 0, 'la barrera cortó ANTES de la primera sentencia por la trx')
      assert.lengthOf(await partitionRows(p), 0)
      assert.deepEqual(events, [], 'nada que auditar: no se llegó al driver')
    } else {
      assert.isNull(caught, `con pool ≥ 2 (${L4_ENGINE}) la barrera lee por otra conexión y la escritura entra: ${caught?.message}`)
      assert.isAbove(statements, 0, 'la escritura fue por la transacción del llamante')
      assert.lengthOf(await partitionRows(p), 1)
      assert.isTrue(await manager.check(u, 'viewer', doc, p))
      assert.lengthOf(events, 1)
    }
  }).timeout(20_000)
})
