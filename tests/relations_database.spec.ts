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
import { assertPartition, isNonCanonicalUuid, pgFusedSpellings, scopeSpellings } from '../src/identity.js'
import { testEngine } from './helpers/app.js'
import { countQueries } from './helpers/spies.js'
import { RelationsManager } from '../src/relations/manager.js'

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
    // Lote D · D1: el driver honra y escribe el deny (cara `true` del par: T1, D9, D-13…).
    relationDenies: true,
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

  test("un HOLDER (subject_relation = '' desde L-4b, o la columna OMITIDA: el DEFAULT del motor) NO lo mira el trigger, aunque subject_partition difiera", async ({
    assert,
  }) => {
    // El trigger solo actúa sobre usersets (`subject_relation <> ''`); un
    // holder no lleva partición de sujeto. L-4b: con `IS NOT NULL` en el
    // trigger, un holder con `''` y `subject_partition` NULL DISPARARÍA
    // (NULL ≠ partition_key): este caso es el mutante de esa condición.
    await db.table('authz_relations').insert(
      baseRow({ subject_type: 'user', subject_uuid: uuidv7(), subject_relation: '', subject_partition: null })
    )
    // Y con la columna OMITIDA: el DEFAULT '' lo pone el MOTOR (mismo holder ⇒ '').
    const { subject_relation: _omitted, ...withoutColumn } = baseRow({
      subject_type: 'user',
      subject_uuid: uuidv7(),
      subject_partition: null,
    })
    await db.table('authz_relations').insert(withoutColumn)
    const rows = await db.from('authz_relations').where('partition_key', partitionA).select('subject_relation')
    assert.lengthOf(rows, 2)
    assert.deepEqual(
      rows.map((r: any) => r.subject_relation),
      ['', ''],
      "el motor guarda '' (explícito y por DEFAULT), nunca NULL"
    )
  })

  test('L-4b · un HOLDER con subject_relation NULL explícito lo RECHAZA el motor (NOT NULL): el driver nunca lo escribe y un escritor a mano tampoco puede', async ({
    assert,
  }) => {
    await assert.rejects(() =>
      db.table('authz_relations').insert(
        baseRow({ subject_type: 'user', subject_uuid: uuidv7(), subject_relation: null, subject_partition: null })
      )
    )
    assert.lengthOf(await db.from('authz_relations').where('partition_key', partitionA), 0)
  })

  test("L-4b · el UNIQUE authz_rel_tuple_uq DEFIENDE al holder: el MISMO hecho de holder dos veces (subject_relation '') ⇒ el segundo INSERT lo rechaza el motor (con NULL entraban los dos)", async ({
    assert,
  }) => {
    // El rojo→verde del ESQUEMA en los tres motores, también en `:memory:`
    // (donde la carrera de dos transacciones no es observable): dos filas
    // iguales de holder chocan en el índice único porque '' = ''.
    const holder = baseRow({ subject_type: 'user', subject_uuid: uuidv7(), subject_relation: '', subject_partition: null })
    await db.table('authz_relations').insert(holder)
    const second = await db
      .table('authz_relations')
      .insert({ ...holder, uuid: uuidv7() })
      .then(() => ({ ok: true as const }), (error: any) => ({ error }))
    assert.isUndefined((second as any).ok, 'ROJO: el segundo INSERT del mismo hecho de holder ENTRÓ (el UNIQUE no cubre al holder)')
    assert.lengthOf(await db.from('authz_relations').where('partition_key', partitionA), 1)
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

/* ── ⚪ A8 (cierre del lote A): el hint de recursión de MySQL va ANTES de DISTINCT también en checkMany ── */

/**
 * `cte_max_recursion_depth` es 1000 por defecto en MySQL; el driver lo sube con
 * el hint `SET_VAR` en cada consulta recursiva. En `checkMany` el hint iba
 * DETRÁS de `DISTINCT` y el optimizador lo ignoraba: con una cadena de grupos
 * anidados de más de 1000 niveles `check` respondía y `checkMany` era
 * `ERROR 3636` ⇒ 503 — rompía «≡ N check». Solo MySQL (PG y SQLite no tienen
 * tope); el caso siembra la cadena con inserts directos (1 002 grupos).
 */
test.group('database relations — A8 · hint de recursión de MySQL en checkMany (> 1000 niveles)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  test('A8 · con 1 002 grupos anidados check y checkMany responden lo MISMO (true) en MySQL: el hint va delante de DISTINCT', async ({ assert }) => {
    const config = contractRelationsConfig()
    const driver = new DatabaseRelationsDriver(config)
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const key = `unit|${p.uuid}`
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const depth = 1002
    const groups = Array.from({ length: depth }, () => uuidv7())
    const rows: any[] = [
      { uuid: uuidv7(), partition_key: key, object_type: 'group', object_uuid: groups[0], relation: 'member', subject_type: 'user', subject_uuid: u.uuid, subject_relation: '', subject_partition: null, expires_at: null, created_at: new Date() },
    ]
    for (let i = 1; i < depth; i++) {
      rows.push({ uuid: uuidv7(), partition_key: key, object_type: 'group', object_uuid: groups[i], relation: 'member', subject_type: 'group', subject_uuid: groups[i - 1], subject_relation: 'member', subject_partition: key, expires_at: null, created_at: new Date() })
    }
    rows.push({ uuid: uuidv7(), partition_key: key, object_type: 'document', object_uuid: doc.id, relation: 'viewer', subject_type: 'group', subject_uuid: groups[depth - 1], subject_relation: 'member', subject_partition: key, expires_at: null, created_at: new Date() })
    for (let i = 0; i < rows.length; i += 200) await db.table('authz_relations').multiInsert(rows.slice(i, i + 200))
    assert.isTrue(await driver.check(u, 'viewer', doc, p), 'check sube 1 002 niveles')
    const many = await driver.checkMany(u, 'viewer', [doc, { type: 'document', id: uuidv7() }], p).then((a) => a, (e) => e)
    assert.isFalse(many instanceof Error, `ROJO (A8): checkMany no responde donde check sí: ${many?.message}`)
    assert.deepEqual(many, [true, false], 'checkMany ≡ N check')
    const { queries } = await countQueries(() => driver.checkMany(u, 'viewer', [doc], p))
    const sql = queries.find((q) => /WITH RECURSIVE/i.test(q.sql))!.sql
    assert.match(sql, /SELECT \/\*\+ SET_VAR\(cte_max_recursion_depth = 50000\) \*\/ DISTINCT/, 'el hint va ANTES de DISTINCT')
  })
    .skip(testEngine() !== 'mysql', 'solo MySQL tiene cte_max_recursion_depth (PG y SQLite no truncan)')
    .timeout(120_000)
})

/* ── D4 (plan 2.5 · lote A): la ortografía SIN guiones de la partición es 422, no un alias que se barre ── */

/**
 * Hasta 2.5.0 `purge*`/`enumerateRelations` barrían las DOS ortografías del
 * uuid de partición (🟡2) porque la clave era un string comparado byte a byte
 * y nadie canonizaba. Desde D4 (decisión del dueño 2026-10-14) la ortografía
 * sin guiones no ENTRA en ninguna operación con partición: 422
 * `E_AUTHZ_INVALID_IDENTITY` con CERO sentencias (el `partition_key` nunca se
 * compone), la canónica sigue intacta, y las filas viejas escritas sin
 * guiones las canoniza la receta del README (`upgrade_recipe.spec.ts`). Los
 * ids de OBJETO y de SUJETO no se rechazan: se comparan byte a byte (README).
 */
test.group('database relations — D4 · la partición sin guiones es 422 (antes: barrido de dos ortografías)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  const config = contractRelationsConfig()
  const driver = () => new DatabaseRelationsDriver(config)
  const spellings = () => {
    const dashless = uuidv7().replace(/-/g, '')
    const dashed = `${dashless.slice(0, 8)}-${dashless.slice(8, 12)}-${dashless.slice(12, 16)}-${dashless.slice(16, 20)}-${dashless.slice(20)}`
    return { withDashes: { type: 'unit', uuid: dashed } as ScopeRef, withoutDashes: { type: 'unit', uuid: dashless } as ScopeRef }
  }

  /**
   * **Tabla de verdad de formas (🟠 A2, cierre del lote A; cierre-3, 🟡 C2-1)**
   * con DOS columnas: `422` = `assertPartition`/`isNonCanonicalUuid` (la regla
   * ANCHA: «32 hex sin los guiones y NO exactamente 8-4-4-4-12 ⇒ 422»), y
   * `funde` = `pgFusedSpellings` (la regla ESTRECHA del fan-out de roles: solo
   * lo que el tipo `uuid` de PostgreSQL funde de verdad — guiones únicamente
   * detrás de grupos de cuatro, MEDIDO contra PG 18 con `::uuid`). Son dos
   * propósitos: rechazar de más es inocuo, purgar de más no (la canónica
   * añadida puede ser un scope VIVO ajeno). Mutante «usar la ancha en roles»
   * (`scopeSpellings` sobre `isNonCanonicalUuid`) ⇒ las filas `-<hex>`,
   * `<hex>-`, `a0e-…` y `8--24` se ponen rojas en la columna `funde`.
   */
  test('A2/C2-1 · tabla de verdad de formas: columna 422 (`assertPartition`, ancha) × columna funde (`pgFusedSpellings`, lo que PG funde): canónica ⇒ entra/no; sin guiones, 8-4-4-16, 8-8-8-8, 12-4-4-12, 8-24 ⇒ 422/funde; guion inicial/final, tras tres, dos seguidos ⇒ 422/NO funde; 4×8 (39) ⇒ 422 y funde pero `scopeSpellings` es 422 por longitud; 31/33 hex, no-hex, `_`, corto ⇒ entran/no', ({ assert }) => {
    const dashed = uuidv7()
    const h = dashed.replace(/-/g, '')
    const rows: Array<[string, string, 'entra' | 422, boolean]> = [
      ['canónica 8-4-4-4-12', dashed, 'entra', false],
      ['sin guiones (D4)', h, 422, true],
      ['8-4-4-16', `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16)}`, 422, true],
      ['8-8-8-8', `${h.slice(0, 8)}-${h.slice(8, 16)}-${h.slice(16, 24)}-${h.slice(24)}`, 422, true],
      ['12-4-4-12 (sin el primer guion)', dashed.slice(0, 8) + dashed.slice(9), 422, true],
      ['8-4-4-16 (sin el último guion)', dashed.slice(0, 23) + dashed.slice(24), 422, true],
      ['8-24 (un solo guion tras ocho)', `${h.slice(0, 8)}-${h.slice(8)}`, 422, true],
      ['4-4-4-4-4-4-4-4 (39 chars: PG la funde, assertScope la corta por longitud)', h.match(/.{4}/g)!.join('-'), 422, true],
      ['guion inicial (PG no la funde)', `-${h.slice(0, 31)}` + h.slice(31), 422, false],
      ['guion final (PG no la funde)', `${h.slice(0, 31)}-${h.slice(31)}`, 422, false],
      ['guion tras TRES hex, a0e-… (PG no la funde)', `${h.slice(0, 3)}-${h.slice(3, 31)}` + h.slice(31), 422, false],
      ['dos guiones seguidos (PG no la funde)', `${h.slice(0, 8)}--${h.slice(8)}`, 422, false],
      ['33 hex', `${h}0`, 'entra', false],
      ['31 hex', h.slice(1), 'entra', false],
      ['32 caracteres no todos hex', `${h.slice(0, 31)}z`, 'entra', false],
      ['md5 con `_` (32 chars)', `${h.slice(0, 31)}_`, 'entra', false],
      ['un id corto', 'tenant-7', 'entra', false],
    ]
    for (const [label, uuid, verdict, fused] of rows) {
      assert.isAtMost(uuid.replace(/-/g, '').length, 33)
      // Columna `funde` (cierre-3 · C2-1): la ortografía canónica que PG fundiría, o nada.
      assert.deepEqual(pgFusedSpellings(uuid), fused ? [dashed] : [], `${label}: columna funde (pgFusedSpellings)`)
      if (uuid.length <= 36) {
        assert.deepEqual(
          scopeSpellings({ type: 'unit', uuid }).map((s) => s.uuid),
          fused ? [uuid, dashed] : [uuid],
          `${label}: el fan-out de roles sigue exactamente la columna funde`
        )
      } else {
        // ⚪ C2-4: lo que PG funde pero no cabe en 36 muere ANTES, en assertScope (ruidoso, visible).
        assert.equal((() => { try { scopeSpellings({ type: 'unit', uuid }); return null } catch (e: any) { return e.code } })(), 'E_AUTHZ_INVALID_IDENTITY', `${label}: 422 por longitud`)
      }
      const caught = (() => {
        try {
          assertPartition({ type: 'unit', uuid })
          return null
        } catch (e) {
          return e as any
        }
      })()
      if (verdict === 'entra') assert.isNull(caught, `${label} ('${uuid}') tiene que ENTRAR: ${caught?.message}`)
      else {
        assert.isNotNull(caught, `ROJO (A2 · ${label}): '${uuid}' ENTRÓ como partición`)
        assert.equal(caught.code, 'E_AUTHZ_INVALID_IDENTITY', label)
        if (uuid.length <= 36) assert.include(caught.message, dashed, `${label}: el 422 nombra la forma canónica`)
      }
      assert.equal(isNonCanonicalUuid(uuid), verdict === 422, `${label}: isNonCanonicalUuid es la misma regla`)
    }
  })

  /**
   * **🟠 A2 invertido (auditor del lote A)**: el alias `8-4-4-16` (y las demás
   * colocaciones de guiones que PG funde) entraba en `assertPartition`, era OTRA
   * partición, la purga canónica no lo tocaba y `check` por el alias seguía
   * `true` tras el offboarding. Ahora: 422 en las once operaciones del driver,
   * CERO sentencias, el manager también, y una fila alias plantada a mano es
   * inalcanzable (ni concede ni se purga por el alias: la receta la borra).
   */
  test('A2 · un alias con otra colocación de guiones (8-4-4-16, 8-8-8-8, 12-4-4-12) ⇒ 422 en las once operaciones del driver con CERO sentencias y en el manager; una fila alias plantada no concede por el alias (422) ni por la canónica', async ({
    assert,
  }) => {
    const { withDashes } = spellings()
    const h = withDashes.uuid!.replace(/-/g, '')
    const aliases: ScopeRef[] = [
      { type: 'unit', uuid: `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16)}` },
      { type: 'unit', uuid: `${h.slice(0, 8)}-${h.slice(8, 16)}-${h.slice(16, 24)}-${h.slice(24)}` },
      { type: 'unit', uuid: withDashes.uuid!.slice(0, 8) + withDashes.uuid!.slice(9) },
    ]
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const manager = new RelationsManager(driver(), config)
    for (const alias of aliases) {
      const attempts: Array<[string, () => Promise<unknown>]> = [
        ['purgeObject', () => driver().purgeObject(doc, alias)],
        ['purgeSubject', () => driver().purgeSubject(u, alias)],
        ['relate', () => driver().relate(u, 'viewer', doc, alias)],
        ['unrelate', () => driver().unrelate(u, 'viewer', doc, alias)],
        ['check', () => driver().check(u, 'viewer', doc, alias)],
        ['checkMany', () => driver().checkMany(u, 'viewer', [doc], alias)],
        ['listObjects', () => driver().listObjects(u, 'viewer', 'document', alias)],
        ['listSubjects', () => driver().listSubjects('viewer', doc, alias)],
        ['membersOf', () => driver().membersOf(doc, 'viewer', alias)],
        ['enumerateRelations', () => driver().enumerateRelations(alias)],
        ['enumerateRelationsMany', () => driver().enumerateRelationsMany([withDashes, alias])],
        ['manager.check', () => manager.check(u, 'viewer', doc, alias)],
        ['manager.relate', () => manager.relate(u, 'viewer', doc, alias)],
      ]
      for (const [label, run] of attempts) {
        const { result: caught, queries } = await countQueries(() => run().then(() => null, (e) => e))
        assert.isNotNull(caught, `ROJO (A2 · ${label} · ${alias.uuid}): el alias ENTRÓ`)
        assert.equal(caught.code, 'E_AUTHZ_INVALID_IDENTITY', `${label}: ${caught.message}`)
        assert.include(caught.message, withDashes.uuid!, `${label}: nombra la canónica`)
        // La barrera del freeze del manager lee ANTES de la gramática (otra tabla); sobre `authz_relations`, ninguna.
        assert.deepEqual(queries.filter((q) => /authz_relations/i.test(q.sql)), [], `${label}: CERO sentencias sobre authz_relations`)
      }
    }
    // Una fila escrita por el alias (el insider de 2.4) es inalcanzable: la purga canónica no la ve (la receta la borra), y el alias ya no la lee.
    await db.table('authz_relations').insert({
      uuid: uuidv7(),
      partition_key: `unit|${aliases[0].uuid}`,
      object_type: 'document',
      object_uuid: doc.id,
      relation: 'viewer',
      subject_type: 'user',
      subject_uuid: u.uuid,
      subject_relation: '',
      subject_partition: null,
      expires_at: null,
      created_at: new Date(),
    })
    await manager.purgeSubject(u, withDashes)
    assert.isFalse(await manager.check(u, 'viewer', doc, withDashes))
    assert.equal((await manager.check(u, 'viewer', doc, aliases[0]).then(() => null, (e) => e))?.code, 'E_AUTHZ_INVALID_IDENTITY', 'ROJO (A2): por el alias la compartición ya no se lee')
    assert.lengthOf(await db.from('authz_relations').where('partition_key', `unit|${aliases[0].uuid}`), 1, 'la fila alias sigue ahí hasta la receta (DELETE por defecto)')
  })

  test('purgeObject/purgeSubject/relate/check/enumerateRelations con el uuid SIN guiones ⇒ 422 E_AUTHZ_INVALID_IDENTITY nombrando la forma con guiones, CERO sentencias, y la fila canónica sigue concediendo', async ({
    assert,
  }) => {
    const { withDashes, withoutDashes } = spellings()
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    await driver().relate(u, 'viewer', doc, withDashes)
    assert.isTrue(await driver().check(u, 'viewer', doc, withDashes))
    const attempts: Array<[string, () => Promise<unknown>]> = [
      ['purgeObject', () => driver().purgeObject(doc, withoutDashes)],
      ['purgeSubject', () => driver().purgeSubject(u, withoutDashes)],
      ['relate', () => driver().relate(u, 'viewer', doc, withoutDashes)],
      ['unrelate', () => driver().unrelate(u, 'viewer', doc, withoutDashes)],
      ['check', () => driver().check(u, 'viewer', doc, withoutDashes)],
      ['checkMany', () => driver().checkMany(u, 'viewer', [doc], withoutDashes)],
      ['listObjects', () => driver().listObjects(u, 'viewer', 'document', withoutDashes)],
      ['listSubjects', () => driver().listSubjects('viewer', doc, withoutDashes)],
      ['membersOf', () => driver().membersOf(doc, 'viewer', withoutDashes)],
      ['enumerateRelations', () => driver().enumerateRelations(withoutDashes)],
      ['enumerateRelationsMany', () => driver().enumerateRelationsMany([withDashes, withoutDashes])],
    ]
    for (const [label, run] of attempts) {
      const { result: caught, queries } = await countQueries(() => run().then(() => null, (e) => e))
      assert.isNotNull(caught, `ROJO (${label}): la ortografía sin guiones ENTRÓ`)
      assert.equal(caught.status, 422, `${label}: ${caught.message}`)
      assert.equal(caught.code, 'E_AUTHZ_INVALID_IDENTITY', label)
      assert.include(caught.message, withDashes.uuid!, `${label}: el 422 nombra la forma canónica`)
      assert.include(caught.message, 'Upgrading to 2.5.0', `${label}: y la receta`)
      assert.lengthOf(queries, 0, `${label}: CERO sentencias`)
    }
    assert.isTrue(await driver().check(u, 'viewer', doc, withDashes), 'la fila canónica sigue intacta')
    assert.lengthOf(await db.from('authz_relations'), 1)
  })

  test('el manager también: purgeObject/purgeSubject con la ortografía sin guiones ⇒ 422 sin evento ni sentencia; con la canónica, UN evento por purga con la partición del llamante', async ({
    assert,
  }) => {
    const events: any[] = []
    const manager = new RelationsManager(driver(), config, { onRelationWrite: (e: any) => void events.push(e) })
    const { withDashes, withoutDashes } = spellings()
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    await manager.relate(u, 'viewer', doc, withDashes)
    events.length = 0
    for (const run of [() => manager.purgeObject(doc, withoutDashes), () => manager.purgeSubject(u, withoutDashes)]) {
      const { result: caught, queries } = await countQueries(() => run().then(() => null, (e) => e))
      assert.equal(caught?.code, 'E_AUTHZ_INVALID_IDENTITY', String(caught?.message))
      // La barrera del freeze va ANTES de la gramática (una lectura de la fila id=2); de escritura, ninguna.
      assert.deepEqual(queries.filter((q) => /^\s*(insert|update|delete)\b/i.test(q.sql)), [], 'cero sentencias de escritura')
    }
    assert.lengthOf(events, 0, 'una purga rechazada en la puerta no se audita')
    assert.isTrue(await manager.check(u, 'viewer', doc, withDashes))
    await manager.purgeObject(doc, withDashes)
    assert.lengthOf(events, 1)
    assert.equal(events[0].operation, 'purgeObject')
    assert.deepEqual(events[0].partition, withDashes, 'la partición del llamante, tal cual')
    assert.isFalse(await manager.check(u, 'viewer', doc, withDashes))
  })

  /**
   * **Ids de OBJETO y de SUJETO: se comparan byte a byte, no se rechazan** (D4,
   * juez §5): rechazar los 32 hex rompería ids legítimos que no son uuid. Un
   * documento escrito con el id sin guiones y preguntado con guiones es OTRO
   * documento (y al revés) — en las DOS direcciones, como dice el README.
   */
  test('D4 · ids de objeto y de sujeto NO se rechazan: dos ortografías del mismo uuid son dos ids (byte a byte, en las dos direcciones)', async ({ assert }) => {
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const u = { type: 'user', uuid: uuidv7() }
    const dashed = uuidv7()
    const dashless = dashed.replace(/-/g, '')
    await driver().relate(u, 'viewer', { type: 'document', id: dashless }, p)
    assert.isTrue(await driver().check(u, 'viewer', { type: 'document', id: dashless }, p), 'escrito sin guiones, preguntado sin guiones')
    assert.isFalse(await driver().check(u, 'viewer', { type: 'document', id: dashed }, p), 'preguntado CON guiones: otro id')
    const other = { type: 'document', id: uuidv7() }
    await driver().relate(u, 'viewer', other, p)
    assert.isFalse(await driver().check(u, 'viewer', { type: 'document', id: other.id.replace(/-/g, '') }, p), 'escrito con guiones, preguntado sin: otro id')
    // Y el sujeto igual: el holder `uuid` sin guiones es otro holder.
    const holderDashless = { type: 'user', uuid: u.uuid.replace(/-/g, '') }
    assert.isFalse(await driver().check(holderDashless, 'viewer', { type: 'document', id: dashless }, p))
    await driver().relate(holderDashless, 'viewer', other, p)
    assert.isTrue(await driver().check(holderDashless, 'viewer', other, p))
    assert.isTrue(await driver().check(u, 'viewer', other, p), 'y el holder con guiones conserva lo suyo')
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
      subject_relation: '',
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

  /**
   * **Cierre alpha.3 (🔴 1 / 🟠 2 del auditor)**: F-05 también en las purgas y las lecturas DEL DRIVER
   * (`manager.driver()` no es salida). Hasta el lote 0 del plan 2.5 aquí vivía la lista A MANO de «las ocho
   * operaciones» (purgeObject/purgeSubject/check/listObjects/listSubjects/membersOf + relación `undefined`),
   * que era justo lo que L1 (`linajes.md`) señala: cada iteración olvidaba «la operación siguiente». La lista
   * se sustituyó por la **guardia de superficie** (`tests/guard_surface.spec.ts`, filas `database.*`,
   * columna `f05`): el inventario sale por REFLEXIÓN del prototipo del driver y de su vista `withClock`, y
   * un método nuevo sin fila en `tests/fixtures/guard_manifest.ts` nace rojo. Borrado declarado: −1 caso.
   */
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
     * **alpha.3 · B2 — el criterio LITERAL de COGNITIV: «rollback ⇒ ni tupla NI
     * evento contabilizado como definitivo».** Un sink de auditoría de DOS
     * niveles —la receta que el README vende (`trx.after('commit')`)—: todo
     * evento va a `emitidos`; si lleva `transactional: true` el registro
     * FIRME se difiere al commit; si no, se registra firme al momento. Con
     * rollback: `emitidos` = 1 con la marca, `firmes` = 0, censo = 0. Con
     * commit: `firmes` = 1, censo = 1. En las dos mitades (relate y unrelate).
     * **ROJO hoy**: sin la marca el sink NO puede diferir ⇒ un rollback deja
     * un registro firme. **Mutante**: la marca solo en `relate` ⇒ la mitad
     * de `unrelate` rojo.
     */
    test('alpha.3 · B2 · rollback ⇒ ni tupla NI evento contabilizado como definitivo: el sink difiere el registro firme a trx.after(commit) cuando el evento lleva transactional: true; con commit lo registra (relate y unrelate)', async ({
      assert,
    }) => {
      const emitidos: any[] = []
      const firmes: string[] = []
      let currentTrx: any = null
      const { manager } = await relationsWorker({
        onRelationWrite: (e: any) => {
          emitidos.push(e)
          if (e.transactional === true) {
            currentTrx.after('commit', () => firmes.push(e.operation))
          } else {
            firmes.push(e.operation)
          }
        },
      })
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }

      // relate + rollback.
      await db.transaction(async (trx) => {
        currentTrx = trx
        await manager.relate(u, 'viewer', doc, p, { transaction: trx })
        await trx.rollback()
      })
      assert.lengthOf(emitidos, 1)
      assert.equal(emitidos[0].transactional, true, 'ROJO: el evento no lleva transactional: true y el sink no puede diferir')
      assert.deepEqual(firmes, [], 'ROJO: un rollback dejó un registro de auditoría firme')
      assert.lengthOf(await partitionRows(p), 0, 'censo tras el rollback: cero tuplas')

      // relate + commit.
      await db.transaction(async (trx) => {
        currentTrx = trx
        await manager.relate(u, 'viewer', doc, p, { transaction: trx })
      })
      assert.deepEqual(firmes, ['relate'], 'commit ⇒ el registro se firma')
      assert.lengthOf(await partitionRows(p), 1)

      // unrelate + rollback (la segunda mitad: el mutante «solo relate» cae aquí).
      await db.transaction(async (trx) => {
        currentTrx = trx
        await manager.unrelate(u, 'viewer', doc, p, { transaction: trx })
        await trx.rollback()
      })
      assert.lengthOf(emitidos, 3)
      assert.equal(emitidos[2].operation, 'unrelate')
      assert.equal(emitidos[2].transactional, true, 'ROJO: el unrelate no lleva la marca')
      assert.deepEqual(firmes, ['relate'], 'ROJO: un rollback del unrelate dejó un registro firme')
      assert.lengthOf(await partitionRows(p), 1, 'la tupla sigue')

      // unrelate + commit.
      await db.transaction(async (trx) => {
        currentTrx = trx
        await manager.unrelate(u, 'viewer', doc, p, { transaction: trx })
      })
      assert.deepEqual(firmes, ['relate', 'unrelate'])
      assert.lengthOf(await partitionRows(p), 0)
      // Fuera de una transacción, el evento no lleva la marca y el sink registra firme al momento.
      await manager.relate(u, 'viewer', doc, p)
      assert.notProperty(emitidos.at(-1), 'transactional')
      assert.deepEqual(firmes, ['relate', 'unrelate', 'relate'])
    }).timeout(20_000)

    /**
     * **alpha.3 · E4 — purga × `{ transaction }`**: el evento de la purga
     * marca `transactional: true` y el rollback lo deshace (el sink diferido
     * de B2 tiene 0 registros y el censo sigue intacto: las purgas revierten
     * JUNTAS, que el runner ya fija por censo); con commit, 1 registro y censo
     * 0. Las dos purgas.
     */
    test('alpha.3 · E4 · purgeObject/purgeSubject dentro de una trx: el evento lleva transactional: true; rollback ⇒ sink diferido 0 y censo intacto; commit ⇒ 1 registro y censo 0', async ({
      assert,
    }) => {
      const emitidos: any[] = []
      const firmes: string[] = []
      let currentTrx: any = null
      const { manager } = await relationsWorker({
        onRelationWrite: (e: any) => {
          emitidos.push(e)
          if (e.transactional === true) currentTrx.after('commit', () => firmes.push(e.operation))
          else firmes.push(e.operation)
        },
      })
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const u = { type: 'user', uuid: uuidv7() }
      const v = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const other = { type: 'document', id: uuidv7() }
      await manager.relate(u, 'viewer', doc, p)
      await manager.relate(v, 'editor', doc, p)
      await manager.relate(u, 'owner', other, p)
      emitidos.length = 0
      firmes.length = 0

      // purgeObject + rollback.
      await db.transaction(async (trx) => {
        currentTrx = trx
        await manager.purgeObject(doc, p, { transaction: trx })
        await trx.rollback()
      })
      assert.lengthOf(emitidos, 1, 'ROJO: la purga no notifica')
      assert.equal(emitidos[0].operation, 'purgeObject')
      assert.equal(emitidos[0].transactional, true, 'ROJO: el evento de la purga no lleva transactional: true')
      assert.notProperty(emitidos[0], 'subject')
      assert.deepEqual(firmes, [], 'rollback ⇒ ningún registro firme')
      assert.lengthOf(await partitionRows(p), 3, 'rollback ⇒ el censo intacto (las purgas revierten juntas)')
      // purgeObject + commit.
      await db.transaction(async (trx) => {
        currentTrx = trx
        await manager.purgeObject(doc, p, { transaction: trx })
      })
      assert.deepEqual(firmes, ['purgeObject'])
      assert.lengthOf(await partitionRows(p), 1, 'commit ⇒ solo queda la tupla de `other`')

      // purgeSubject + rollback / + commit.
      await db.transaction(async (trx) => {
        currentTrx = trx
        await manager.purgeSubject(u, p, { transaction: trx })
        await trx.rollback()
      })
      assert.equal(emitidos.at(-1).operation, 'purgeSubject')
      assert.equal(emitidos.at(-1).transactional, true)
      assert.notProperty(emitidos.at(-1), 'object')
      assert.deepEqual(firmes, ['purgeObject'])
      assert.lengthOf(await partitionRows(p), 1)
      await db.transaction(async (trx) => {
        currentTrx = trx
        await manager.purgeSubject(u, p, { transaction: trx })
      })
      assert.deepEqual(firmes, ['purgeObject', 'purgeSubject'])
      assert.lengthOf(await partitionRows(p), 0)
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
      // Sujeto USERSET (`subject_relation` con valor). Desde L-4b el UNIQUE
      // muerde igual con un HOLDER (`''`): ver el caso L-4b, abajo.
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
     * **alpha.3 · C3 — el deadline DENTRO de la transacción del llamante ⇒
     * `indeterminate: true` Y `transactional: true`** (invariante 13 en
     * relaciones, calcado del de roles `database_transaction.spec.ts:355`, con
     * el mecanismo del caso L-4b de abajo): T1 escribe la tupla en su trx y no
     * confirma; T2 escribe LA MISMA por otra trx y espera en el UNIQUE hasta
     * que su deadline de 400 ms vence. PG/MySQL: 503 `E_AUTHZ_BACKEND_TIMEOUT`
     * en < 5 s y eventos `[['relate', true, false], ['relate', true, true]]`
     * (transactional, indeterminate); lo que queda de T2, MEDIDO: PG abortada
     * (`25P02`), MySQL viva. `sqlite-file`: NO hay deadline que vencer (SQLite
     * es síncrono) ⇒ `SQLITE_BUSY` ⇒ 503 `E_AUTHZ_BACKEND_UNAVAILABLE` y SIN
     * evento indeterminado — la cara honesta, en el mismo caso. **Mutante**:
     * mantener `indeterminate` pero perder `transactional` dentro de la trx
     * (🟡 12 del auditor `{trx}`) ⇒ rojo.
     */
    test('alpha.3 · C3 · deadline vencido DENTRO de la trx externa ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT (PG/MySQL) y onRelationWrite publica indeterminate: true + transactional: true; la trx del llamante queda abortada en PG y viva en MySQL; en sqlite-file es SQLITE_BUSY sin evento indeterminado', async ({
      assert,
    }) => {
      const { manager, events } = await relationsWorker({}, { timeoutMs: 400 })
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const t1 = await db.transaction()
      const t2 = await db.transaction()
      let t2Result: { ok?: unknown; error?: any } = {}
      let alive: { alive: boolean; error?: any } = { alive: true }
      const started = Date.now()
      try {
        await manager.relate(u, 'viewer', doc, p, { transaction: t1 })
        t2Result = await manager.relate(u, 'viewer', doc, p, { transaction: t2 }).then(
          (ok) => ({ ok: ok ?? true }),
          (error) => ({ error })
        )
        alive = await transactionAlive(t2)
      } finally {
        await t2.rollback().catch(() => {})
        await t1.rollback().catch(() => {})
      }
      const elapsed = Date.now() - started
      assert.isUndefined(t2Result.ok, 'ROJO: el segundo relate del mismo hecho ENTRÓ')
      const error = t2Result.error
      assert.equal(error?.status, 503, error?.message)
      if (L4_ENGINE === 'sqlite-file') {
        assert.equal(error.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', `sqlite-file: no hay deadline que vencer (síncrono): BUSY (${error.message})`)
        assert.isTrue(alive.alive)
        assert.deepEqual(
          events.map((e) => [e.operation, e.transactional === true, e.indeterminate === true]),
          [['relate', true, false]],
          'sin deadline no hay indeterminado (un BUSY no es un timeout: esa escritura no ocurrió)'
        )
      } else {
        assert.equal(error.code, 'E_AUTHZ_BACKEND_TIMEOUT', `${L4_ENGINE}: ${error.message}`)
        assert.isBelow(elapsed, 5_000, `el 503 llega por el deadline del driver (400 ms), no por el lock-wait del motor (${elapsed} ms)`)
        assert.deepEqual(
          events.map((e) => [e.operation, e.transactional === true, e.indeterminate === true]),
          [
            ['relate', true, false],
            ['relate', true, true],
          ],
          'ROJO: el deadline dentro de tu transacción tiene que publicar indeterminate: true Y transactional: true'
        )
        if (L4_ENGINE === 'pg') {
          assert.isFalse(alive.alive, 'PostgreSQL: la consulta cancelada deja la transacción abortada')
          assert.equal(alive.error?.cause?.code ?? alive.error?.code, '25P02')
        } else {
          assert.isTrue(alive.alive, 'MySQL: KILL QUERY mata la sentencia y la transacción sigue')
        }
      }
      // Las dos hicieron rollback: nada queda.
      assert.lengthOf(await partitionRows(p), 0)
    }).timeout(30_000)

    /**
     * **L-4b · el UNIQUE defiende también a los HOLDERS** (cierra el HALLAZGO
     * de L-4, decisión del dueño del 2026-09-02). Hasta L-4b `subject_relation`
     * era `NULL` para un holder y en los tres motores dos `NULL` son DISTINTOS
     * en un índice único: `authz_rel_tuple_uq` solo defendía los USERSETS, y
     * dos `relate` concurrentes del MISMO hecho de holder en dos transacciones
     * (el «¿ya existe?» de cada una no ve a la otra) entraban los dos y
     * confirmaban DOS filas iguales (`listSubjects`/`enumerateRelations` ×2, el
     * censo del reconcile contando doble). Desde L-4b la columna es
     * `NOT NULL DEFAULT ''` —la ÚNICA forma con paridad en los tres motores:
     * el índice parcial no existe en MySQL y `NULLS NOT DISTINCT` es solo
     * PG 15+— y el driver escribe `''` para el holder, así que `'' = ''` y el
     * UNIQUE muerde igual que con un userset: T2 espera en el índice único y
     * al confirmar T1 recibe **409 `E_AUTHZ_WRITE_CONFLICT`** (PG la deja
     * abortada; MySQL deshace la sentencia); en sqlite-file el segundo
     * escritor sigue siendo `SQLITE_BUSY` (503). Exactamente UNA fila y
     * `listSubjects` lo emite UNA vez. **Mutante**: volver la columna a
     * `nullable()` (o escribir NULL) ⇒ dos filas ⇒ ROJO.
     */
    test('L-4b · el UNIQUE de authz_relations cubre también al HOLDER (subject_relation NOT NULL DEFAULT \'\'): dos relate concurrentes del MISMO hecho de holder en dos trx ⇒ exactamente UNA fila; el perdedor 409 E_AUTHZ_WRITE_CONFLICT (PG/MySQL) o 503 SQLITE_BUSY (sqlite-file); listSubjects lo emite UNA vez', async ({
      assert,
    }) => {
      const { manager, events } = await relationsWorker()
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const t1 = await db.transaction()
      const t2 = await db.transaction()
      let second: { ok?: true; error?: any } = {}
      let alive: { alive: boolean; error?: any } = { alive: true }
      const started = Date.now()
      try {
        await manager.relate(u, 'viewer', doc, p, { transaction: t1 })
        // T2 escribe lo mismo. Con el UNIQUE mordiendo, en PG/MySQL ESPERA a
        // que T1 confirme (mismo protocolo que el caso del userset); en
        // sqlite-file es BUSY inmediato. Se resuelve DESPUÉS del commit de T1.
        const pending = manager.relate(u, 'viewer', doc, p, { transaction: t2 }).then(
          () => ({ ok: true as const }),
          (error) => ({ error })
        )
        await new Promise((resolve) => setTimeout(resolve, 300))
        await t1.commit()
        second = await pending
        alive = await transactionAlive(t2)
        if (second.ok) await t2.commit()
        else await t2.rollback().catch(() => {})
      } finally {
        if (!t1.isCompleted) await t1.rollback().catch(() => {})
        if (!t2.isCompleted) await t2.rollback().catch(() => {})
      }
      const elapsed = Date.now() - started
      const rows = await partitionRows(p)
      assert.isUndefined(
        second.ok,
        `ROJO: ${L4_ENGINE}: el segundo relate del MISMO hecho de holder ENTRÓ (el UNIQUE no lo defiende); censo = ${rows.length} filas`
      )
      assert.lengthOf(rows, 1, `${L4_ENGINE}: exactamente UNA fila del hecho de holder (el UNIQUE cubre '' = '')`)
      const error = second.error
      assert.isString(error?.code, `clasificado: ${error?.message}`)
      if (L4_ENGINE === 'sqlite-file') {
        assert.equal(error.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', `sqlite-file: SQLITE_BUSY clasificado (${error.message})`)
        assert.equal(error.status, 503)
        assert.match(String(error.cause?.code ?? error.cause?.message ?? ''), /SQLITE_BUSY/)
      } else {
        assert.equal(error.code, 'E_AUTHZ_WRITE_CONFLICT', `${L4_ENGINE}: el UNIQUE del holder dentro de tu transacción es 409 (${error.message})`)
        assert.equal(error.status, 409)
        assert.include(error.message, 'rollback')
        if (L4_ENGINE === 'pg') assert.isFalse(alive.alive, 'PostgreSQL: la transacción del perdedor queda ABORTADA (25P02)')
        else assert.isTrue(alive.alive, 'MySQL: solo se deshace la sentencia; la transacción sigue viva')
      }
      assert.isBelow(elapsed, 20_000, `el choque se resolvió en ${elapsed} ms`)
      assert.lengthOf(events, 1, 'un solo evento: el relate de T1; el perdedor no publica nada')
      const listed = (await manager.listSubjects('viewer', doc, p)).subjects.filter((s: any) => s.uuid === u.uuid)
      assert.lengthOf(listed, 1, 'listSubjects lo emite UNA vez')
      const enumerated = (await manager.enumerateRelations(p)).tuples.filter((t: any) => t.subject.uuid === u.uuid)
      assert.lengthOf(enumerated, 1, 'enumerateRelations (el censo del reconcile) lo emite UNA vez')
      assert.isTrue(await manager.check(u, 'viewer', doc, p))
      await manager.unrelate(u, 'viewer', doc, p)
      assert.lengthOf(await partitionRows(p), 0)
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
      // Sujeto USERSET (con un holder el resultado es el mismo desde L-4b:
      // el UNIQUE cubre `''`; se conserva el userset por continuidad con L-4).
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

test.group('alpha.8 · una transacción YA CONFIRMADA o REVERTIDA en `{ transaction }` de relaciones ⇒ 500 E_AUTHZ_CONFIG nombrando la operación, cero sentencias por ella y cero filas (antes: 503)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
    await db.from('authz_catalog_version').where('id', 2).update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null })
  })

  test('relate/unrelate/purgeObject/purgeSubject con una trx confirmada y con una revertida ⇒ 500 «confirmada/revertida», nada escrito; sin `transaction` la misma escritura entra', async ({ assert }) => {
    const { manager } = await relationsWorker()
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const committed = await db.transaction()
    await committed.commit()
    const rolled = await db.transaction()
    await rolled.rollback()
    for (const [name, trx] of [['confirmada', committed], ['revertida', rolled]] as const) {
      const spy = spyTransaction(trx as any)
      for (const [op, run] of [
        ['relate', () => manager.relate(u, 'viewer', doc, p, { transaction: spy.transaction })],
        ['unrelate', () => manager.unrelate(u, 'viewer', doc, p, { transaction: spy.transaction })],
        ['purgeObject', () => manager.purgeObject(doc, p, { transaction: spy.transaction })],
        ['purgeSubject', () => manager.purgeSubject(u, p, { transaction: spy.transaction })],
      ] as const) {
        const error = await rejects(assert, run, 'E_AUTHZ_CONFIG', 500, `${op} (${name})`)
        assert.include(error.message, `database-relations.${op}`)
        assert.match(error.message, /confirmada|revertida/)
      }
      assert.equal(spy.statements(), 0, `${name}: ni una sentencia por la trx cerrada`)
    }
    assert.lengthOf(await partitionRows(p), 0)
    await manager.relate(u, 'viewer', doc, p)
    assert.lengthOf(await partitionRows(p), 1)
  })
})

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

/* ── alpha.8 · C1 · `enumerateRelationsMany` NATIVO en `database` ─────────── */

/**
 * **alpha.8 · C1** (panel relay 2, analista §8 / juez 7.1). Hasta alpha.7 el
 * driver `database` no traía `enumerateRelationsMany` y el manager caía al
 * respaldo (K consultas y un cursor que perdía tuplas, C2). Ahora es el mismo
 * SELECT de `enumerateRelations` con `partition_key IN (todas las ortografías
 * de todas las particiones)`, **UNA consulta por página**, orden por `uuid`
 * (cursor estable) y cada tupla con la partición PEDIDA a la que pertenece.
 * Paridad byte a byte con K `enumerateRelations`; reanudación por cursor sin
 * pérdida ni duplicado; `[]` es 500 con cero consultas (paridad `openfga`).
 * Sin capacidad nueva: con los dos drivers publicados nativos y el respaldo
 * ruidoso, «¿estoy en el respaldo?» ya no es una pregunta.
 */
test.group('database relations — alpha.8 · C1 · `enumerateRelationsMany` nativo: UNA consulta, paridad con K llamadas, cursor sin pérdida', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  const APP: ScopeRef = { type: 'app', uuid: null }
  const keyOf = (p: ScopeRef) => (p.type === 'app' ? 'app' : `${p.type}|${p.uuid}`)
  const PER = 7
  const FOREIGN = 5

  async function seeded() {
    const config = contractRelationsConfig()
    const driver = new DatabaseRelationsDriver(config, { transactionalWrites: false })
    const org: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const unit: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const partitions = [APP, org, unit]
    for (const p of partitions) {
      for (let i = 0; i < PER; i++) await driver.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, p)
    }
    const other: ScopeRef = { type: 'organization', uuid: uuidv7() }
    for (let i = 0; i < FOREIGN; i++) await driver.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, other)
    return { driver, config, partitions }
  }

  test('EL CASO (M-2): 3 particiones ⇒ UNA consulta (espía de knex), 7/7/7 sin ajenas, y por partición la salida es IDÉNTICA a la de tres `enumerateRelations`', async ({
    assert,
  }) => {
    const { driver, partitions } = await seeded()
    const baseline = new Map<string, unknown[]>()
    for (const p of partitions) baseline.set(keyOf(p), (await driver.enumerateRelations(p, { limit: 1000 })).tuples)

    const { result: page, queries } = await countQueries(() => driver.enumerateRelationsMany!(partitions, { limit: 1000 }))
    assert.lengthOf(queries, 1, 'UNA consulta para K particiones (el respaldo del manager hacía K)')
    assert.isUndefined(page.cursor)
    assert.lengthOf(page.tuples, 3 * PER, 'las ajenas (otra partición) no vienen')
    for (const p of partitions) {
      const mine = page.tuples.filter((t) => keyOf(t.partition) === keyOf(p))
      assert.lengthOf(mine, PER, `partición ${keyOf(p).slice(0, 12)}: sus ${PER}`)
      assert.deepEqual(mine, baseline.get(keyOf(p))!, 'paridad tupla a tupla, en el mismo orden (uuid)')
    }
    const ids = page.tuples.map((t) => t.object.id)
    assert.deepEqual(ids, [...ids].sort(), 'orden total por uuid: es lo que hace estable al cursor')
  })

  test('reanudar por cursor (a través del MANAGER: nativo, sin respaldo) ve TODAS las tuplas exactamente una vez; `partitions: []` es 500 E_AUTHZ_CONFIG con cero consultas', async ({
    assert,
  }) => {
    const { driver, config, partitions } = await seeded()
    const manager = new RelationsManager(driver, config)
    const expected = new Set<string>()
    for (const p of partitions) for (const t of (await driver.enumerateRelations(p, { limit: 1000 })).tuples) expected.add(t.object.id)

    const seen: string[] = []
    let after: string | undefined
    let pages = 0
    do {
      const page = await manager.enumerateRelationsMany(partitions, { limit: 4, after })
      pages += 1
      for (const t of page.tuples) seen.push(t.object.id)
      after = page.cursor
    } while (after !== undefined && pages < 100)
    assert.equal(pages, Math.ceil((3 * PER) / 4), 'tantas páginas como hacen falta, ni una de más')
    assert.lengthOf(seen, 3 * PER, 'ninguna perdida')
    assert.equal(new Set(seen).size, seen.length, 'ninguna repetida')
    assert.deepEqual(new Set(seen), expected)

    let caught: any
    const { queries } = await countQueries(async () => {
      try {
        await driver.enumerateRelationsMany!([])
      } catch (error) {
        caught = error
      }
    })
    assert.equal(caught?.code, 'E_AUTHZ_CONFIG', 'un barrido para nadie no es un éxito vacío (paridad openfga)')
    assert.lengthOf(queries, 0)
  })
})

/* ── Plan 2.5 · lote D · D8: `database` honra `denied_*` SIEMPRE ───────────── */

test.group('lote D · D8 · database honra las filas denied_* SIEMPRE (también sin opt-in: una fila deny es un hecho)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  test('D8 · retirar el opt-in con denies vivos: con la config SIN deny (y en un tipo que nunca lo tuvo, `note`), check/checkMany/listObjects siguen restando la fila denied_viewer; listDenies la ve y removeDeny la borra (reversible); deny() ⇒ 422', async ({ assert }) => {
    const { contractDenyRelationsConfig } = await import('../src/testing/relations_contract.js')
    const withDeny = new DatabaseRelationsDriver(contractDenyRelationsConfig(), { transactionalWrites: false })
    const u = { type: 'user', uuid: uuidv7() }
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    await withDeny.relate(u, 'viewer', doc, p)
    await withDeny.deny(u, 'viewer', doc, p)
    // El mismo hecho, leído por un proceso con la config SIN deny (opt-in retirado).
    const retired = new RelationsManager(new DatabaseRelationsDriver(contractRelationsConfig(), { transactionalWrites: false }), contractRelationsConfig())
    assert.isFalse(await retired.check(u, 'viewer', doc, p), 'D8: la fila deny sigue denegando sin opt-in')
    assert.deepEqual(await retired.checkMany(u, 'viewer', [doc], p), [false])
    assert.deepEqual((await retired.listObjects(u, 'viewer', 'document', p)).objects, [])
    assert.lengthOf((await retired.listDenies('viewer', doc, p)).subjects, 1)
    const denied = await retired.deny(u, 'viewer', doc, p).then(() => null, (e) => e)
    assert.equal(denied?.code, 'E_AUTHZ_RELATION_NOT_DENYABLE')
    await retired.removeDeny(u, 'viewer', doc, p)
    assert.isTrue(await retired.check(u, 'viewer', doc, p), 'removeDeny sin opt-in: reversible')
    // Un tipo que NUNCA tuvo opt-in (`note`) con una fila deny escrita a mano: también resta.
    const note = { type: 'note', id: uuidv7() }
    await withDeny.relate(u, 'owner', note, p)
    await db.table('authz_relations').insert({
      uuid: uuidv7(),
      partition_key: `${p.type}|${p.uuid}`,
      object_type: 'note',
      object_uuid: note.id,
      relation: 'denied_editor',
      subject_type: 'user',
      subject_uuid: u.uuid,
      subject_relation: '',
      subject_partition: null,
      created_at: new Date(),
    })
    assert.isFalse(await withDeny.check(u, 'viewer', note, p), 'fila 35 en un tipo sin opt-in: database corta igual')
    assert.deepEqual(await withDeny.decideMany(u, 'viewer', [note], p), ['deny'])
  })

  test('sin filas denied_* la respuesta es la de 2.4.0-alpha.10: un tipo sin deny responde igual con la config CON y SIN deny (R-02 y la paridad de listObjects no cambian)', async ({ assert }) => {
    const { contractDenyRelationsConfig } = await import('../src/testing/relations_contract.js')
    const a = new DatabaseRelationsDriver(contractRelationsConfig(), { transactionalWrites: false })
    const b = new DatabaseRelationsDriver(contractDenyRelationsConfig(), { transactionalWrites: false })
    const u = { type: 'user', uuid: uuidv7() }
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const docs = [{ type: 'document', id: uuidv7() }, { type: 'document', id: uuidv7() }, { type: 'document', id: uuidv7() }]
    await a.relate(u, 'owner', docs[0], p)
    await a.relate(u, 'editor', docs[1], p)
    for (const q of ['viewer', 'editor', 'owner']) {
      assert.deepEqual(await a.checkMany(u, q, docs, p), await b.checkMany(u, q, docs, p), q)
      assert.deepEqual((await a.listObjects(u, q, 'document', p)).objects, (await b.listObjects(u, q, 'document', p)).objects, q)
    }
  })
})

/* ── Lote D · cierre 1 de D1 · 🟡 4: `membersOf` con deny, cota DECLARADA y deadline TOTAL ─────────────── */

/**
 * **🟡 4 del auditor de D1**: basta UNA fila `denied_*` vigente en el objeto para que cada candidato de `membersOf` pase
 * por `check` (una CTE por candidato), en serie: sin cota ni deadline total era una amplificación barata para quien puede
 * escribir un deny. Ahora: cota `RELATIONS_MEMBERS_DENY_CHECK_MAX` (1 000) ⇒ 500 `E_AUTHZ_MEMBERS_DENY_LIMIT` ANTES del
 * primer `check` (nunca una lista parcial) y deadline TOTAL del bucle (`timeoutMs`) ⇒ 503 `E_AUTHZ_BACKEND_TIMEOUT`, con
 * el bucle parado. Sin filas deny, nada cambia (cero consultas de más: D-15b).
 */
test.group('lote D · cierre 1 de D1 · 🟡 4 · membersOf de database con deny: cota declarada y deadline total', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  /** `n` miembros directos (`viewer`) de un documento + un deny vivo sobre el primero, sembrados en bloque. */
  async function seed(n: number) {
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const row = (relation: string, subject: string) => ({
      uuid: uuidv7(),
      partition_key: `${p.type}|${p.uuid}`,
      object_type: 'document',
      object_uuid: doc.id,
      relation,
      subject_type: 'user',
      subject_uuid: subject,
      subject_relation: '',
      subject_partition: null,
      created_at: new Date(),
    })
    const subjects = Array.from({ length: n }, () => uuidv7())
    const rows = [...subjects.map((s) => row('viewer', s)), row('denied_viewer', subjects[0])]
    for (let i = 0; i < rows.length; i += 200) await db.table('authz_relations').multiInsert(rows.slice(i, i + 200))
    return { p, doc, subjects }
  }

  test('🟡 4 · con deny, MÁS de RELATIONS_MEMBERS_DENY_CHECK_MAX (1 000) candidatos ⇒ 500 E_AUTHZ_MEMBERS_DENY_LIMIT antes del primer check (nunca una lista parcial); con exactamente 1 000, un check por candidato y la resta', async ({ assert }) => {
    const { RELATIONS_MEMBERS_DENY_CHECK_MAX } = await import('../src/drivers/database_relations_driver.js')
    const { contractDenyRelationsConfig } = await import('../src/testing/relations_contract.js')
    assert.equal(RELATIONS_MEMBERS_DENY_CHECK_MAX, 1_000)
    for (const [n, expectLimit] of [[RELATIONS_MEMBERS_DENY_CHECK_MAX + 1, true], [RELATIONS_MEMBERS_DENY_CHECK_MAX, false]] as const) {
      await db.from('authz_relations').delete()
      const { p, doc, subjects } = await seed(n)
      const driver = new DatabaseRelationsDriver(contractDenyRelationsConfig(), { transactionalWrites: false })
      const original = driver.check.bind(driver)
      let checks = 0
      // Espía barato: el coste de la CTE no es lo que se juzga aquí (lo juzga D-15b), sino la cota.
      ;(driver as any).check = async (subject: any, ...rest: any[]) => {
        checks += 1
        return subject.uuid === subjects[0] ? original(subject, ...(rest as [any, any, any])) : true
      }
      const outcome = await driver.membersOf(doc, 'viewer', p).then((page) => ({ page }), (e) => e)
      if (expectLimit) {
        assert.equal(outcome?.status, 500, `ROJO (🟡 4): ${n} candidatos con deny respondió ${outcome?.page ? `una lista de ${outcome.page.subjects.length}` : outcome?.message}`)
        assert.equal(outcome?.code, 'E_AUTHZ_MEMBERS_DENY_LIMIT')
        assert.include(String(outcome?.message), 'RELATIONS_MEMBERS_DENY_CHECK_MAX')
        assert.equal(checks, 0, 'la cota corta ANTES del primer check')
      } else {
        assert.lengthOf(outcome.page.subjects, n - 1, 'en la cota: un check por candidato y el denegado fuera')
        assert.equal(checks, n)
      }
    }
  }).timeout(60_000)

  test('🟡 4 · con deny, el bucle de check tiene deadline TOTAL (timeoutMs del driver) ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT y el bucle se PARA; sin deny, ningún check', async ({ assert }) => {
    const { contractDenyRelationsConfig } = await import('../src/testing/relations_contract.js')
    const { p, doc } = await seed(3)
    const driver = new DatabaseRelationsDriver(contractDenyRelationsConfig(), { transactionalWrites: false, timeoutMs: 100 })
    let checks = 0
    // Cada check tarda 60 ms (ninguno vence su deadline por sentencia); los tres juntos pasan del total de 100.
    ;(driver as any).check = async () => {
      checks += 1
      await new Promise((resolve) => setTimeout(resolve, 60))
      return true
    }
    const caught = await driver.membersOf(doc, 'viewer', p).then((page) => ({ page }), (e) => e)
    assert.equal(caught?.status, 503, `ROJO (🟡 4): sin deadline total respondió ${JSON.stringify(caught?.page ?? caught?.message)}`)
    assert.equal(caught?.code, 'E_AUTHZ_BACKEND_TIMEOUT')
    await new Promise((resolve) => setTimeout(resolve, 200))
    assert.isBelow(checks, 3, 'vencido el deadline, el bucle no sigue lanzando checks')
    // Sin filas deny: la respuesta de alpha.10, ningún check.
    await db.from('authz_relations').where('relation', 'denied_viewer').delete()
    checks = 0
    assert.lengthOf((await driver.membersOf(doc, 'viewer', p)).subjects, 3)
    assert.equal(checks, 0)
  })
})
