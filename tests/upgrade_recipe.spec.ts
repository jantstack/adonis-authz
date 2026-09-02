/**
 * La receta de subida 1.x → 2.x del README se EJECUTA (2.5-B · K14, tester
 * G5): es la única promesa del README que un consumidor copia y pega en
 * producción, y nunca se había corrido. Aquí se crea el esquema de 1.1.0
 * (`tests/fixtures/migration-1.1.0.stub`) en una base de trabajo del motor,
 * se aplican literalmente las sentencias del bloque ```sql del README para
 * ese motor, y encima corre el motor 2.x: ids que no son UUID, caducidad al
 * milisegundo y más allá de 2038, comparación byte a byte, versión del
 * catálogo. Y el esquema resultante tiene que ser EL MISMO que construye la
 * migración publicada (tipo, longitud, precisión, collation).
 *
 * Solo PG y MySQL: SQLite no tiene ALTER de tipo (y 1.x en SQLite ya
 * guardaba texto), y la receta del README es para esos dos motores.
 */

import { test } from '@japa/runner'
import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { DatabaseRelationsDriver, relationPartitionTrigger } from '../src/drivers/database_relations_driver.js'
import { contractRelationsConfig } from '../src/testing/relations_contract.js'
import type { ScopeRef } from '../src/types.js'
import { openScratchDatabase, testEngine } from './helpers/app.js'
import { AUTHZ_TABLES, describeAuthzSchema } from './helpers/schema.js'

/**
 * La receta 1.x → 2.x NO crea `authz_relations` ni `authz_relations_config`:
 * son tablas NUEVAS de la Fase 4 (ReBAC — tuplas y la config persistida de
 * 🟡3), que un despliegue obtiene con la migración forward publicada, no con el
 * ALTER a mano del salto 2.0. La equivalencia con «la migración publicada» se
 * afirma sobre las tablas que la receta transforma.
 */
const RECIPE_TABLES = AUTHZ_TABLES.filter(
  (table) => table !== 'authz_relations' && table !== 'authz_relations_config'
)

const CHILD = fileURLToPath(new URL('./helpers/upgrade_child.ts', import.meta.url))
const ROOT = fileURLToPath(new URL('..', import.meta.url))

/** Las sentencias del bloque ```sql del README marcado con `-- <engine>: upgrading …`. */
async function readmeRecipe(engine: 'pg' | 'mysql'): Promise<string[]> {
  const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
  const marker = engine === 'pg' ? '-- PostgreSQL' : '-- MySQL'
  const block = [...readme.matchAll(/```sql\n([\s\S]*?)```/g)].map((m) => m[1]).find((b) => b.startsWith(marker))
  if (!block) throw new Error(`el README no tiene el bloque \`\`\`sql que empieza por "${marker}"`)
  return block
    .split('\n')
    .filter((line) => !line.startsWith('--') && line.trim() !== '')
    .join('\n')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean)
}

if (testEngine() === 'pg' || testEngine() === 'mysql') {
  const engine = testEngine() as 'pg' | 'mysql'
  test.group(`receta de subida 1.x → 2.x del README en ${engine} (2.5-B · K14)`, () => {
    test('el esquema 1.1.0 + la receta del README = la migración publicada, y el motor 2.x funciona encima (id no UUID, ms, 2040, byte a byte, versión)', async ({
      assert,
    }) => {
      const statements = await readmeRecipe(engine)
      assert.isAtLeast(statements.length, 3, 'la receta tiene sentencias')
      const scratch = await openScratchDatabase()
      let output = ''
      try {
        const reuse = { engine, connection: structuredClone(scratch.connection), database: scratch.database }
        delete (reuse.connection as any)?.connection?.timezone
        output = execFileSync(process.execPath, ['--import', '@poppinss/ts-exec', CHILD], {
          encoding: 'utf-8',
          cwd: ROOT,
          timeout: 120_000,
          stdio: ['ignore', 'pipe', 'pipe'],
          env: { ...process.env, AUTHZ_TEST_REUSE: JSON.stringify(reuse), AUTHZ_UPGRADE_SQL: JSON.stringify(statements) },
        })
      } finally {
        await scratch.drop()
      }
      const line = output.split('\n').find((l) => l.startsWith('{'))
      assert.isString(line, `el hijo no imprimió JSON:\n${output}`)
      const seen = JSON.parse(line!)
      assert.isTrue(seen.nonUuidGranted, "'user-42' (no UUID) concede tras la receta")
      assert.equal(seen.msExact, '2030-01-01T00:00:00.600Z', 'la caducidad se lee al milisegundo')
      assert.isTrue(seen.beforeSoon, 'T+599 ms concede')
      assert.isFalse(seen.atSoon, 'T+600 ms no concede: sin redondeo al segundo')
      assert.isTrue(seen.beyond2038, '2040 es una caducidad válida')
      assert.equal(seen.lowerRows, 1)
      assert.equal(seen.upperRows, 0, 'byte a byte: USER-42 no es user-42')
      assert.equal(seen.version, 1, 'la fila de versión existe y el sync la subió')
      // 3B · B1: los roles de 1.x quedan globales y el sync los reconoce (mismo uuid, sin duplicar).
      assert.equal(seen.legacyOwner, 'global', 'un rol de 1.x queda con owner_scope_key = global tras la receta')
      assert.deepEqual(seen.legacyAfterSync, [{ uuid: '0192a000-0000-7000-8000-00000000abcd', owner: 'global' }])
      assert.deepEqual(seen.schema, await describeAuthzSchema(db, RECIPE_TABLES), 'el esquema subido es el publicado')
    }).timeout(180_000)
  })
}

/* ── L-4b · la receta alpha.2 → L-4b de `authz_relations.subject_relation`, EJECUTADA en los TRES motores ── */

type L4bEngine = 'pg' | 'mysql' | 'sqlite'
const L4B_ENGINE: L4bEngine = testEngine() === 'pg' ? 'pg' : testEngine() === 'mysql' ? 'mysql' : 'sqlite'

/**
 * Las sentencias del bloque ```sql del README marcado con `-- L-4b · <Motor>`:
 * UNA por línea (los cuerpos de los triggers llevan `;` dentro, así que la
 * receta NO se trocea por `;`: cada línea se ejecuta ENTERA, como el stub).
 */
async function l4bRecipe(engine: L4bEngine): Promise<string[]> {
  const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
  const marker = { pg: '-- L-4b · PostgreSQL', mysql: '-- L-4b · MySQL', sqlite: '-- L-4b · SQLite' }[engine]
  const block = [...readme.matchAll(/```sql\n([\s\S]*?)```/g)].map((m) => m[1]).find((b) => b.startsWith(marker))
  if (!block) throw new Error(`el README no tiene el bloque \`\`\`sql que empieza por "${marker}"`)
  return block
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('--'))
    .map((line) => line.replace(/;$/, ''))
}

/**
 * La forma de `authz_relations` ANTES de L-4b (2.4.0-alpha.1/alpha.2):
 * `subject_relation` NULLABLE (NULL = holder) y el trigger de partición
 * juzgando «es userset» con `IS NOT NULL`. Es exactamente lo que un
 * despliegue que migró la alpha tiene en producción.
 */
async function createPreL4bRelationsTable(scratch: any): Promise<void> {
  await scratch.connection().schema.createTable('authz_relations', (table: any) => {
    table.uuid('uuid').primary().notNullable()
    table.string('partition_key', 64).notNullable().collate('utf8mb4_bin')
    table.string('object_type', 50).notNullable().collate('utf8mb4_bin')
    table.string('object_uuid', 64).notNullable().collate('utf8mb4_bin')
    table.string('relation', 50).notNullable().collate('utf8mb4_bin')
    table.string('subject_type', 50).notNullable().collate('utf8mb4_bin')
    table.string('subject_uuid', 64).notNullable().collate('utf8mb4_bin')
    table.string('subject_relation', 50).nullable().collate('utf8mb4_bin')
    table.string('subject_partition', 64).nullable().collate('utf8mb4_bin')
    table.datetime('expires_at', { precision: 3 }).nullable()
    table.timestamp('created_at').notNullable()
    table.unique(
      ['partition_key', 'object_type', 'object_uuid', 'relation', 'subject_type', 'subject_uuid', 'subject_relation'],
      'authz_rel_tuple_uq'
    )
    table.index(['partition_key', 'object_type', 'object_uuid', 'relation'], 'authz_rel_object_idx')
    table.index(['partition_key', 'subject_type', 'subject_uuid'], 'authz_rel_subject_idx')
  })
  const dialect: string = scratch.connection().dialect.name
  for (const statement of relationPartitionTrigger(dialect).map((s) => s.replace(/<> ''/g, 'IS NOT NULL'))) {
    await scratch.rawQuery(statement)
  }
}

test.group(`L-4b · la receta alpha.2 → L-4b del README (authz_relations.subject_relation) en ${testEngine()}, ejecutada`, () => {
  test("la forma alpha (NULL = holder, con un holder DUPLICADO por el UNIQUE que no lo cubría) + la receta literal del README = la columna publicada (PG/MySQL byte a byte; SQLite solo difiere en la nulabilidad, medido), el trigger nuevo deja pasar al holder, el UNIQUE ya lo defiende; y ANTES de la receta el driver nuevo TOLERA la fila con NULL (check, list, relate no-op, unrelate/purge la borran)", async ({
    assert,
  }) => {
    const statements = await l4bRecipe(L4B_ENGINE)
    assert.isAtLeast(statements.length, L4B_ENGINE === 'pg' ? 4 : 6, 'la receta tiene sentencias (una por línea)')
    const scratch = await openScratchDatabase()
    try {
      await createPreL4bRelationsTable(scratch.db)
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const key = `unit|${p.uuid}`
      const holder = { type: 'user', uuid: uuidv7() }
      const twice = { type: 'user', uuid: uuidv7() }
      const gone = { type: 'user', uuid: uuidv7() }
      const purged = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const row = (over: Record<string, unknown> = {}) => ({
        uuid: uuidv7(),
        partition_key: key,
        object_type: 'document',
        object_uuid: doc.id,
        relation: 'viewer',
        subject_type: 'user',
        subject_uuid: holder.uuid,
        subject_relation: null,
        subject_partition: null,
        expires_at: null,
        created_at: new Date(),
        ...over,
      })
      const settle = (run: Promise<unknown>): Promise<{ ok?: true; error?: any }> =>
        run.then(() => ({ ok: true as const }), (error: any) => ({ error }))
      const insert = (r: Record<string, unknown>) => settle(scratch.db.table('authz_relations').insert(r))
      const rows = (subjectUuid?: string) => {
        const q = scratch.db.from('authz_relations').where('partition_key', key)
        return (subjectUuid ? q.where('subject_uuid', subjectUuid) : q).orderBy('uuid')
      }

      // Estado alpha: holders con NULL (uno normal, uno DOS veces —lo que el
      // UNIQUE dejaba pasar—, uno para unrelate, uno para purgeSubject) y un userset.
      assert.isTrue((await insert(row())).ok)
      const dupA = uuidv7()
      const dupB = uuidv7()
      assert.isTrue((await insert(row({ uuid: dupA, subject_uuid: twice.uuid }))).ok)
      assert.isTrue(
        (await insert(row({ uuid: dupB, subject_uuid: twice.uuid }))).ok,
        'alpha: el MISMO hecho de holder entra dos veces (NULL ≠ NULL en el índice único)'
      )
      assert.isTrue((await insert(row({ subject_uuid: gone.uuid }))).ok)
      assert.isTrue((await insert(row({ subject_uuid: purged.uuid }))).ok)
      assert.isTrue(
        (await insert(row({ subject_type: 'group', subject_uuid: uuidv7(), subject_relation: 'member', subject_partition: key }))).ok
      )
      assert.lengthOf(await rows(), 6)

      // TOLERANCIA en lectura ANTES de la receta: el driver de L-4b sobre la forma vieja.
      const driver = new DatabaseRelationsDriver(contractRelationsConfig(), {}, scratch.db as any)
      assert.isTrue(await driver.check(holder, 'viewer', doc, p), 'una fila vieja con NULL es un holder: check true')
      const listed = (await driver.listSubjects('viewer', doc, p)).subjects
      assert.lengthOf(listed.filter((s: any) => s.uuid === holder.uuid), 1, 'listSubjects: el holder viejo, una vez, como holder')
      assert.lengthOf(listed.filter((s: any) => s.uuid === twice.uuid), 2, 'el duplicado viejo se emite dos veces HASTA la receta')
      assert.lengthOf((await driver.enumerateRelations(p)).tuples.filter((t: any) => t.subject.uuid === holder.uuid), 1)
      assert.include(
        (await driver.membersOf(doc, 'viewer', p)).subjects.map((s: any) => s.uuid),
        holder.uuid,
        'membersOf: el holder viejo (COALESCE) cuenta'
      )
      await driver.relate(holder, 'viewer', doc, p)
      assert.lengthOf(await rows(holder.uuid), 1, 'relate del mismo holder: la fila vieja se ENCUENTRA (no-op, no una segunda fila)')
      // **Medido, y por eso la receta va en el MISMO despliegue**: una ESCRITURA
      // de holder (INSERT con '' y `subject_partition` NULL) la rechaza el
      // trigger VIEJO (`IS NOT NULL` ⇒ dispara) hasta el paso 4 de la receta.
      // Fail-closed y ruidoso (503 clasificado con el mensaje del trigger), la
      // transacción interna del driver lo deshace: la fila vieja sigue ahí.
      const renewed = new Date(Date.now() + 3_600_000)
      const refused = await settle(driver.relate(holder, 'viewer', doc, p, { expiresAt: renewed }))
      assert.isUndefined(refused.ok, 'con el trigger viejo, la escritura de un holder NO entra')
      assert.equal(refused.error?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
      assert.equal(refused.error?.status, 503)
      assert.match(String(refused.error?.cause?.message ?? ''), /userset no puede pertenecer a otra partici/)
      const untouched = await rows(holder.uuid)
      assert.lengthOf(untouched, 1, 'la fila vieja sigue (delete+insert deshechos juntos)')
      assert.isNull(untouched[0].subject_relation)
      const freshBefore = { type: 'user', uuid: uuidv7() }
      assert.isUndefined((await settle(driver.relate(freshBefore, 'viewer', doc, p))).ok, 'ni un holder NUEVO entra con el trigger viejo')
      // Las lecturas y los BORRADOS sí (tolerantes a NULL).
      await driver.unrelate(gone, 'viewer', doc, p)
      assert.lengthOf(await rows(gone.uuid), 0, 'unrelate de un holder viejo con NULL lo BORRA (si no, seguiría concediendo: fail-open)')
      await driver.purgeSubject(purged, p)
      assert.lengthOf(await rows(purged.uuid), 0, 'purgeSubject también')

      // LA RECETA, literal del README: una sentencia por línea, cada una ENTERA.
      for (const statement of statements) await scratch.db.rawQuery(statement)

      // Tras la receta, la misma renovación ENTRA: delete+insert, UNA fila, con ''.
      await driver.relate(holder, 'viewer', doc, p, { expiresAt: renewed })
      const afterRenew = await rows(holder.uuid)
      assert.lengthOf(afterRenew, 1, 'renovar la caducidad es delete+insert: sigue habiendo UNA fila')
      assert.strictEqual(afterRenew[0].subject_relation, '', "y la fila nueva lleva '' (el driver nunca escribe NULL)")

      // (1) de-duplicado: del holder `twice` queda UNA fila, la más antigua (uuid menor).
      const twiceRows = await rows(twice.uuid)
      assert.lengthOf(twiceRows, 1, 'la receta de-duplica el hecho que el índice dejó pasar')
      assert.equal(String(twiceRows[0].uuid), [dupA, dupB].sort()[0], 'sobrevive la fila más antigua (uuid v7 menor)')
      // (2) backfill: ningún NULL.
      assert.lengthOf(await scratch.db.from('authz_relations').whereNull('subject_relation'), 0, "todo holder lleva ''")
      assert.strictEqual((await rows(twice.uuid))[0].subject_relation, '')
      // (3) la columna, según el MOTOR, contra el espejo publicado.
      const fromRecipe = await describeAuthzSchema(scratch.db, ['authz_relations'])
      const mirror = await describeAuthzSchema(db, ['authz_relations'])
      if (L4B_ENGINE === 'sqlite') {
        // SQLite no tiene ALTER COLUMN: la ÚNICA diferencia es la nulabilidad de subject_relation.
        const diff = fromRecipe.filter((c, i) => JSON.stringify(c) !== JSON.stringify(mirror[i]))
        assert.deepEqual(diff.map((c) => c.column), ['subject_relation'], 'SQLite: solo difiere subject_relation')
        assert.isTrue(diff[0].nullable, 'SQLite: la columna sigue nullable (sin ALTER COLUMN)')
        assert.deepEqual({ ...diff[0], nullable: false }, mirror.find((c) => c.column === 'subject_relation'), 'y en todo lo demás es la publicada')
      } else {
        assert.deepEqual(fromRecipe, mirror, 'la columna subida es la publicada (tipo, longitud, nulabilidad, collation)')
        const nullRow = await insert(row({ subject_uuid: uuidv7(), subject_relation: null }))
        assert.isUndefined((nullRow as any).ok, 'NOT NULL: un NULL explícito ya no entra')
      }
      // (4) el trigger nuevo: un holder del driver ENTRA (con el trigger viejo,
      // `IS NOT NULL` sobre '' dispararía en todos); un userset de OTRA partición NO.
      const fresh = { type: 'user', uuid: uuidv7() }
      await driver.relate(fresh, 'viewer', doc, p)
      assert.isTrue(await driver.check(fresh, 'viewer', doc, p), 'tras la receta el holder entra (el trigger nuevo no lo mira)')
      const cross = await insert(row({ subject_type: 'group', subject_uuid: uuidv7(), subject_relation: 'member', subject_partition: 'unit|otra' }))
      assert.isUndefined((cross as any).ok, 'el trigger re-creado sigue defendiendo la partición del userset')
      // Y el UNIQUE defiende al holder: el MISMO hecho de `twice` otra vez ⇒ rechazado.
      const dup = await insert(row({ subject_uuid: twice.uuid, subject_relation: '' }))
      assert.isUndefined((dup as any).ok, "ROJO: el mismo hecho de holder entró dos veces tras la receta ('' = '' debería chocar)")
      assert.lengthOf((await driver.listSubjects('viewer', doc, p)).subjects.filter((s: any) => s.uuid === twice.uuid), 1, 'el censo: una vez')
      // IDEMPOTENTE: la receta corre OTRA vez entera (un despliegue que la
      // repite, o que la corrió a medias) y no cambia nada: mismo esquema,
      // mismo censo, el trigger sigue.
      const before = await rows()
      for (const statement of statements) await scratch.db.rawQuery(statement)
      assert.deepEqual(await describeAuthzSchema(scratch.db, ['authz_relations']), fromRecipe, 'segunda pasada: el mismo esquema')
      assert.deepEqual(
        (await rows()).map((r: any) => [String(r.uuid), r.subject_relation]),
        before.map((r: any) => [String(r.uuid), r.subject_relation]),
        'segunda pasada: el mismo censo'
      )
      assert.isUndefined((await insert(row({ subject_type: 'group', subject_uuid: uuidv7(), subject_relation: 'member', subject_partition: 'unit|otra' }))).ok)
    } finally {
      await scratch.drop()
    }
  }).timeout(120_000)
})
