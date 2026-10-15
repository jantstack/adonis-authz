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
import { randomBytes } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { DatabaseRelationsDriver, relationPartitionTrigger } from '../src/drivers/database_relations_driver.js'
import { contractRelationsConfig } from '../src/testing/relations_contract.js'
import { sqlExpiryCodec } from '../src/shared/sql_expiry.js'
import { sameInstant } from '../src/expiry.js'
import type { ScopeRef } from '../src/types.js'
import { assertPartition, dashedUuid, isNonCanonicalUuid } from '../src/identity.js'
import { openScratchDatabase, testEngine } from './helpers/app.js'
import { AUTHZ_TABLES, createAuthzRelationsTable, describeAuthzSchema } from './helpers/schema.js'

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

/* ── D4 (plan 2.5 · lote A + cierre del auditor) · la receta de las particiones NO canónicas, EJECUTADA en los TRES motores ── */

type D4Engine = 'pg' | 'mysql' | 'sqlite'
const D4_ENGINE: D4Engine = testEngine() === 'pg' ? 'pg' : testEngine() === 'mysql' ? 'mysql' : 'sqlite'
const D4_NAME = { pg: 'PostgreSQL', mysql: 'MySQL', sqlite: 'SQLite' }[D4_ENGINE]

/**
 * Las sentencias del bloque ```sql del README marcado con `-- D4 · <Motor>` (rama por
 * defecto, SOLO lectura: detector, listado, conteos), `-- D4 · <Motor> · --delete`
 * (el DELETE fail-closed) o `-- D4 · <Motor> · --rekey` (borrado del gemelo +
 * re-clavado): UNA por línea, los comentarios fuera. Tres ramas desde el cierre-2
 * del lote A (🟡 R3): la rama por defecto no escribe.
 */
async function d4Recipe(branch: 'default' | 'delete' | 'rekey'): Promise<string[]> {
  const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
  const marker = branch === 'default' ? `-- D4 · ${D4_NAME}\n` : `-- D4 · ${D4_NAME} · --${branch}\n`
  const block = [...readme.matchAll(/```sql\n([\s\S]*?)```/g)].map((m) => m[1]).find((b) => b.startsWith(marker))
  if (!block) throw new Error(`el README no tiene el bloque \`\`\`sql que empieza por "${marker.trim()}"`)
  return block
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('--'))
    .map((line) => line.replace(/;$/, ''))
}

/** Las ortografías NO canónicas de un uuid canónico (las que PG funde con él, 🟠 A2). */
function aliasesOf(dashed: string): Record<string, string> {
  const h = dashed.replace(/-/g, '')
  return {
    dashless: h,
    '8-4-4-16': `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16)}`,
    '8-8-8-8': `${h.slice(0, 8)}-${h.slice(8, 16)}-${h.slice(16, 24)}-${h.slice(24)}`,
    'sin el primer guion': dashed.slice(0, 8) + dashed.slice(9), // 12-4-4-12: PG también lo funde
  }
}


/**
 * **🟠 A1 + 🟠 A2 del auditor del lote A (decisión del dueño 2026-10-15)**: la
 * receta ya no re-clava por defecto. Una fila con una partición NO canónica
 * (sin guiones, `8-4-4-16`, cuatro grupos de ocho, la canónica sin un guion…)
 * era una concesión INVISIBLE a la purga canónica: en 2.4 `purgeSubject(U,
 * <canónica>)` no la tocaba, y re-clavarla en el deploy devolvía el acceso al
 * usuario purgado. Por defecto: detector + listado + DELETE (fail-closed); el
 * re-clavado es la rama `--rekey`, opt-in tras revisar el listado, y nunca
 * alarga una caducidad. El detector usa la MISMA regla que `assertPartition`.
 */
/** El censo de `authz_relations`, byte a byte, para afirmar «cero escrituras» (🟡 R3). */
async function census(scratchDb: any): Promise<string> {
  const rows: any[] = await scratchDb.from('authz_relations').orderBy('uuid')
  return JSON.stringify(rows.map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, v === null ? null : String(v)]))))
}

test.group(`D4 · la receta de particiones no canónicas del README en ${testEngine()}, ejecutada (default de SOLO lectura, --delete fail-closed y --rekey)`, () => {
  test('default (SOLO lectura, 🟡 R3) + --delete (fail-closed) · el escenario del auditor (A1): purga canónica ⇒ false ⇒ receta ⇒ SIGUE false; el detector lista exactamente lo que assertPartition rechaza (las cuatro formas de A2, no el id no-hex), el listado enumera las filas, los CONTEOS separan con gemelo / sin gemelo, la rama por defecto NO ESCRIBE (censo idéntico), el --delete las borra, la canónica queda intacta, idempotente', async ({
    assert,
  }) => {
    const statements = await d4Recipe('default')
    assert.lengthOf(statements, 3, 'detector + listado + conteos, una por línea')
    const [detector, listing, counts] = statements
    assert.match(detector, /^SELECT partition_key, COUNT\(\*\)/i)
    assert.match(listing, /^SELECT uuid, partition_key/i)
    assert.match(counts, /^SELECT CASE WHEN EXISTS/i)
    for (const statement of statements) assert.match(statement, /^SELECT /i, 'ROJO (R3): la rama por defecto solo lee')
    const deleteBranch = await d4Recipe('delete')
    assert.lengthOf(deleteBranch, 1, '--delete: UNA sentencia')
    const [remove] = deleteBranch
    assert.match(remove, /^DELETE FROM authz_relations WHERE/i)
    const scratch = await openScratchDatabase()
    try {
      await createAuthzRelationsTable(scratch.db)
      const driver = new DatabaseRelationsDriver(contractRelationsConfig(), {}, scratch.db as any)
      const dashed = uuidv7()
      const canonical: ScopeRef = { type: 'unit', uuid: dashed }
      const canonicalKey = `unit|${dashed}`
      const aliases = aliasesOf(dashed)
      const nonHex = `unit|${'z'.repeat(32)}`
      const md5ish = `unit|${'a'.repeat(31)}_` // 32 caracteres, no todos hex: id legal
      const u = { type: 'user', uuid: uuidv7() }
      const v = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const row = (over: Record<string, unknown>) => ({
        uuid: uuidv7(),
        partition_key: canonicalKey,
        object_type: 'document',
        object_uuid: doc.id,
        relation: 'viewer',
        subject_type: 'user',
        subject_uuid: u.uuid,
        subject_relation: '',
        subject_partition: null,
        expires_at: null,
        created_at: new Date(),
        ...over,
      })
      const insert = (r: Record<string, unknown>) => scratch.db.table('authz_relations').insert(r)

      // ── El escenario del auditor (A1), tal cual: la misma compartición por las dos ortografías, offboarding canónico ──
      await insert(row({ partition_key: `unit|${aliases.dashless}` })) // el camino del id de la URL (2.4)
      await driver.relate(u, 'viewer', doc, canonical) // el camino de la fila
      assert.isTrue(await driver.check(u, 'viewer', doc, canonical))
      await driver.purgeSubject(u, canonical) // offboarding con la partición canónica
      assert.isFalse(await driver.check(u, 'viewer', doc, canonical), 'tras la purga canónica: revocado')
      // ── Y las otras tres formas que PG funde (A2), para `v`, más dos ids legales de 32 caracteres ──
      for (const alias of ['8-4-4-16', '8-8-8-8', 'sin el primer guion'] as const) {
        await insert(row({ partition_key: `unit|${aliases[alias]}`, subject_uuid: v.uuid }))
      }
      await insert(row({ partition_key: nonHex, subject_uuid: v.uuid }))
      await insert(row({ partition_key: md5ish, subject_uuid: v.uuid }))
      await insert(row({ subject_uuid: v.uuid })) // la canónica de v, que NO se toca
      assert.lengthOf(await scratch.db.from('authz_relations'), 7)

      // ANTES: el driver 2.5 rechaza las cuatro formas con 422 y la canónica no ve esas filas.
      for (const [label, uuid] of Object.entries(aliases)) {
        const refused = await driver.check(u, 'viewer', doc, { type: 'unit', uuid }).then(() => null, (e) => e)
        assert.equal(refused?.code, 'E_AUTHZ_INVALID_IDENTITY', `${label}: ${refused?.message}`)
      }
      // El DETECTOR lista exactamente las particiones que `assertPartition` rechaza, y ninguna otra (misma regla).
      const detected = rowsOf(await scratch.db.rawQuery(detector)).map((r) => String(r.partition_key)).sort()
      const expected = Object.values(aliases).map((uuid) => `unit|${uuid}`).sort()
      assert.deepEqual(detected, expected, 'ROJO (A2): el detector no ve alguna forma que la API rechaza, o ve un id legal')
      for (const key of [canonicalKey, nonHex, md5ish, ...expected]) {
        const uuid = key.slice('unit|'.length)
        const rejected = (() => {
          try {
            assertPartition({ type: 'unit', uuid })
            return false
          } catch {
            return true
          }
        })()
        assert.equal(rejected, detected.includes(key), `assertPartition y el detector discrepan en '${uuid}'`)
      }
      // El LISTADO enumera las filas que se van a borrar (con el sujeto: el purgado está ahí).
      const listed = rowsOf(await scratch.db.rawQuery(listing))
      assert.lengthOf(listed, 4)
      assert.isTrue(listed.some((r) => String(r.subject_uuid) === u.uuid && String(r.partition_key) === `unit|${aliases.dashless}`), 'el listado enseña la fila del usuario purgado')
      // Los CONTEOS (🟡 R3): las tres formas de `v` tienen gemelo canónico (su fila canónica), la de `u` no (la purga se llevó la canónica).
      const counted = Object.fromEntries(rowsOf(await scratch.db.rawQuery(counts)).map((r) => [String(r.twin), Number(r.tuples)]))
      assert.deepEqual(counted, { 'with-canonical-twin': 3, 'without-twin': 1 }, 'con gemelo canónico / sin gemelo')
      // LA RAMA POR DEFECTO NO ESCRIBE: el censo antes y después de correrla entera es idéntico.
      const before = await census(scratch.db)
      for (const statement of statements) await scratch.db.rawQuery(statement)
      assert.equal(await census(scratch.db), before, 'ROJO (R3): la rama por defecto escribió algo')
      assert.isFalse(await driver.check(u, 'viewer', doc, canonical))

      // LA RAMA --delete: borrar.
      await scratch.db.rawQuery(remove)
      assert.lengthOf(rowsOf(await scratch.db.rawQuery(detector)), 0, 'tras la receta el detector da 0')
      assert.isFalse(await driver.check(u, 'viewer', doc, canonical), 'ROJO (A1): la receta por defecto NO puede devolver el acceso al usuario purgado')
      assert.isTrue(await driver.check(v, 'viewer', doc, canonical), 'la fila canónica de v sigue intacta')
      const left: any[] = await scratch.db.from('authz_relations').orderBy('partition_key')
      assert.deepEqual(left.map((r) => String(r.partition_key)).sort(), [canonicalKey, md5ish, nonHex].sort(), 'quedan la canónica y los dos ids legales')

      // IDEMPOTENTE.
      for (const statement of [...statements, ...deleteBranch]) await scratch.db.rawQuery(statement)
      assert.lengthOf(await scratch.db.from('authz_relations'), 3)
      assert.isFalse(await driver.check(u, 'viewer', doc, canonical))
    } finally {
      await scratch.drop()
    }
  }).timeout(120_000)

  /**
   * **🟡 R3 (re-ataque al cierre del lote A)**: la población que 🟡 A6 nombra
   * —ids de tenant que NUNCA fueron uuids: 32 hex por construcción
   * (`randomBytes(16).toString('hex')`, md5)— ve TODAS sus particiones en el
   * detector. Con la receta anterior el DELETE por defecto le vaciaba
   * `authz_relations`. Ahora el default no escribe, el README nombra la
   * población y su rama es `--rekey`: conserva cada relación bajo la forma
   * 8-4-4-4-12 de los mismos 32 hex, y la API responde por ese id.
   */
  test('🟡 R3 · población B (ids 32-hex que nunca fueron uuid): el detector lista TODAS sus particiones, el default no escribe, --rekey conserva todas sus relaciones (userset incluido) bajo la forma 8-4-4-4-12 y la API responde por ella; --delete las vaciaría (pinado)', async ({
    assert,
  }) => {
    const [detector, , counts] = await d4Recipe('default')
    const statements = await d4Recipe('default')
    const [remove] = await d4Recipe('delete')
    const rekey = await d4Recipe('rekey')
    const scratch = await openScratchDatabase()
    try {
      await createAuthzRelationsTable(scratch.db)
      const driver = new DatabaseRelationsDriver(contractRelationsConfig(), {}, scratch.db as any)
      const tenants = [randomBytes(16).toString('hex'), randomBytes(16).toString('hex')]
      for (const hex of tenants) {
        assert.isTrue(isNonCanonicalUuid(hex), 'un id de 32 hex es, para la regla, un uuid sin guiones')
        assert.equal(dashedUuid(hex).replace(/-/g, ''), hex)
      }
      const u = { type: 'user', uuid: uuidv7() }
      const w = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const group = { type: 'group', id: uuidv7() }
      const row = (over: Record<string, unknown>) => ({
        uuid: uuidv7(),
        partition_key: `unit|${tenants[0]}`,
        object_type: 'document',
        object_uuid: doc.id,
        relation: 'viewer',
        subject_type: 'user',
        subject_uuid: u.uuid,
        subject_relation: '',
        subject_partition: null,
        expires_at: null,
        created_at: new Date(),
        ...over,
      })
      const seed = async () => {
        await scratch.db.from('authz_relations').delete()
        await scratch.db.table('authz_relations').insert(row({}))
        await scratch.db.table('authz_relations').insert(row({ subject_type: 'group', subject_uuid: group.id, subject_relation: 'member', subject_partition: `unit|${tenants[0]}` }))
        await scratch.db.table('authz_relations').insert(row({ object_type: 'group', object_uuid: group.id, relation: 'member', subject_uuid: w.uuid }))
        await scratch.db.table('authz_relations').insert(row({ partition_key: `unit|${tenants[1]}`, subject_uuid: w.uuid }))
      }
      await seed()
      // La firma de la población B: el detector lista TODAS sus particiones, y ninguna tiene gemelo.
      const detected = rowsOf(await scratch.db.rawQuery(detector)).map((r) => String(r.partition_key)).sort()
      assert.deepEqual(detected, tenants.map((h) => `unit|${h}`).sort(), 'todas las particiones del consumidor')
      const counted = Object.fromEntries(rowsOf(await scratch.db.rawQuery(counts)).map((r) => [String(r.twin), Number(r.tuples)]))
      assert.deepEqual(counted, { 'without-twin': 4 }, 'nada es alias de nada: sin gemelo')
      const before = await census(scratch.db)
      for (const statement of statements) await scratch.db.rawQuery(statement)
      assert.equal(await census(scratch.db), before, 'el default no escribe')
      // --delete sobre esta población VACÍA la tabla (la frase del README, pinada): por eso ninguna rama escribe sin su sentencia explícita.
      await scratch.db.rawQuery(remove)
      assert.lengthOf(await scratch.db.from('authz_relations'), 0, 'README: «Running --delete on this population empties authz_relations»')
      // Su rama: --rekey conserva TODO.
      await seed()
      for (const statement of rekey) await scratch.db.rawQuery(statement)
      assert.lengthOf(rowsOf(await scratch.db.rawQuery(detector)), 0)
      const all: any[] = await scratch.db.from('authz_relations')
      assert.lengthOf(all, 4, 'ROJO (R3): --rekey perdió relaciones de la población B')
      const keys = new Set(all.map((r) => String(r.partition_key)))
      assert.deepEqual([...keys].sort(), tenants.map((h) => `unit|${dashedUuid(h)}`).sort(), 'cada partición bajo la forma 8-4-4-4-12 de sus 32 hex')
      const userset = all.find((r) => String(r.subject_type) === 'group')
      assert.equal(String(userset.subject_partition), `unit|${dashedUuid(tenants[0])}`, 'el subject_partition del userset va con la fila')
      const p0: ScopeRef = { type: 'unit', uuid: dashedUuid(tenants[0]) }
      const p1: ScopeRef = { type: 'unit', uuid: dashedUuid(tenants[1]) }
      assert.isTrue(await driver.check(u, 'viewer', doc, p0), 'la API responde por el id con guiones')
      assert.isTrue(await driver.check(w, 'viewer', doc, p0), 'y el userset re-clavado concede')
      assert.isTrue(await driver.check(w, 'viewer', doc, p1))
      assert.equal((await driver.check(u, 'viewer', doc, { type: 'unit', uuid: tenants[0] }).then(() => null, (e) => e))?.code, 'E_AUTHZ_INVALID_IDENTITY', 'el id de 32 hex a secas sigue siendo 422: desde 2.5.0 se pasa con guiones')
    } finally {
      await scratch.drop()
    }
  }).timeout(120_000)

  test('--rekey (opt-in) · re-clava las filas sin gemelo canónico (las cuatro formas y el subject_partition del userset), con gemelo las BORRA sin tocar la caducidad del gemelo (nunca se alarga: NULL no gana, la lejana no gana), respeta los ids legales, es idempotente; y el escenario del auditor vuelve a conceder — es la decisión revisada, no el default', async ({
    assert,
  }) => {
    const [detector] = await d4Recipe('default')
    const rekey = await d4Recipe('rekey')
    assert.lengthOf(rekey, 2, 'borrado del gemelo + re-clavado, una por línea')
    assert.match(rekey[0], /^DELETE/i)
    assert.match(rekey[1], /^UPDATE authz_relations SET subject_partition = CASE/i)
    const scratch = await openScratchDatabase()
    try {
      await createAuthzRelationsTable(scratch.db)
      const driver = new DatabaseRelationsDriver(contractRelationsConfig(), {}, scratch.db as any)
      const dashed = uuidv7()
      const canonical: ScopeRef = { type: 'unit', uuid: dashed }
      const canonicalKey = `unit|${dashed}`
      const aliases = aliasesOf(dashed)
      const legacyKey = `unit|${aliases.dashless}`
      const nonHex = `unit|${'z'.repeat(32)}`
      const u1 = { type: 'user', uuid: uuidv7() }
      const u2 = { type: 'user', uuid: uuidv7() }
      const u3 = { type: 'user', uuid: uuidv7() }
      const u4 = { type: 'user', uuid: uuidv7() }
      const u5 = { type: 'user', uuid: uuidv7() }
      const u6 = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const group = { type: 'group', id: uuidv7() }
      const codec = sqlExpiryCodec(scratch.db.connection())
      const row = (over: Record<string, unknown>) => ({
        uuid: uuidv7(),
        partition_key: legacyKey,
        object_type: 'document',
        object_uuid: doc.id,
        relation: 'viewer',
        subject_type: 'user',
        subject_uuid: u1.uuid,
        subject_relation: '',
        subject_partition: null,
        expires_at: null,
        created_at: new Date(),
        ...over,
      })
      const insert = (r: Record<string, unknown>) => scratch.db.table('authz_relations').insert(r)
      const far = new Date('2031-01-01T00:00:00.000Z')
      const near = new Date('2030-01-01T00:00:00.000Z')
      // (1) solo sin guiones: se re-clava (con su propia caducidad: ninguna).
      await insert(row({ subject_uuid: u1.uuid }))
      // (2) sin guiones (caduca LEJOS) + gemelo canónico (caduca CERCA): el gemelo se queda con la CERCANA (nunca se alarga).
      await insert(row({ subject_uuid: u2.uuid, expires_at: codec.toDb(far) }))
      await insert(row({ subject_uuid: u2.uuid, partition_key: canonicalKey, expires_at: codec.toDb(near) }))
      // (3) sin guiones SIN caducidad + gemelo canónico con caducidad: el gemelo conserva su fecha (NULL no gana).
      await insert(row({ subject_uuid: u3.uuid, expires_at: null }))
      await insert(row({ subject_uuid: u3.uuid, partition_key: canonicalKey, expires_at: codec.toDb(near) }))
      // (4) un USERSET sin guiones (subject_partition = la clave vieja): se re-clavan las dos columnas.
      await insert(row({ subject_type: 'group', subject_uuid: group.id, subject_relation: 'member', subject_partition: legacyKey }))
      await insert(row({ object_type: 'group', object_uuid: group.id, relation: 'member', subject_uuid: u4.uuid }))
      // (5) un id de partición de 32 caracteres que NO es hex: legal, se queda tal cual.
      await insert(row({ partition_key: nonHex, subject_uuid: u4.uuid }))
      // (6) las otras formas de A2, solas: se re-clavan igual.
      await insert(row({ partition_key: `unit|${aliases['8-4-4-16']}`, subject_uuid: u5.uuid }))
      await insert(row({ partition_key: `unit|${aliases['sin el primer guion']}`, subject_uuid: u6.uuid }))
      // (7) el escenario del auditor: el sujeto purgado por la canónica sobrevive en la sin guiones.
      const purged = { type: 'user', uuid: uuidv7() }
      await insert(row({ subject_uuid: purged.uuid }))
      await driver.relate(purged, 'viewer', doc, canonical)
      await driver.purgeSubject(purged, canonical)
      assert.isFalse(await driver.check(purged, 'viewer', doc, canonical))
      assert.lengthOf(await scratch.db.from('authz_relations'), 11)
      assert.lengthOf(rowsOf(await scratch.db.rawQuery(detector)), 3, 'tres particiones no canónicas')

      for (const statement of rekey) await scratch.db.rawQuery(statement)

      assert.lengthOf(rowsOf(await scratch.db.rawQuery(detector)), 0, 'tras --rekey el detector da 0')
      const columns: any[] = ['uuid', 'partition_key', 'object_type', 'subject_type', 'subject_uuid', 'subject_relation', 'subject_partition', codec.select('expires_at')]
      const all: any[] = await scratch.db.from('authz_relations').select(...columns).orderBy('subject_uuid')
      assert.lengthOf(all, 9, '11 − 2 gemelos borrados')
      assert.lengthOf(all.filter((r) => String(r.partition_key) !== canonicalKey && String(r.partition_key) !== nonHex), 0, 'todo es canónico o legal')
      const of = (uuid: string) => all.filter((r) => String(r.subject_uuid) === uuid && String(r.partition_key) === canonicalKey)
      assert.lengthOf(of(u1.uuid), 1, 'u1 re-clavada')
      assert.isNull(codec.fromDb(of(u1.uuid)[0].expires_at), 'con su propia caducidad (ninguna)')
      assert.lengthOf(of(u2.uuid), 1, 'u2: una sola fila')
      assert.isTrue(sameInstant(codec.fromDb(of(u2.uuid)[0].expires_at), near), 'u2: el gemelo conserva la CERCANA (la lejana de la sin guiones NO gana)')
      assert.lengthOf(of(u3.uuid), 1)
      assert.isTrue(sameInstant(codec.fromDb(of(u3.uuid)[0].expires_at), near), 'u3: el gemelo conserva su fecha (NULL NO gana)')
      const userset = all.find((r) => String(r.subject_type) === 'group' && String(r.subject_relation) === 'member')
      assert.equal(String(userset.partition_key), canonicalKey)
      assert.equal(String(userset.subject_partition), canonicalKey, 'el subject_partition del userset se re-clava con la fila (el trigger lo exige)')
      assert.lengthOf(of(u5.uuid), 1, '8-4-4-16 re-clavada')
      assert.lengthOf(of(u6.uuid), 1, 'sin el primer guion re-clavada')
      assert.lengthOf(all.filter((r) => String(r.partition_key) === nonHex), 1, 'el id no-hex sigue tal cual')

      // DESPUÉS: concede por la canónica, incluido el userset y las formas de A2 — y el purgado también (opt-in revisado).
      for (const who of [u1, u2, u3, u4, u5, u6]) assert.isTrue(await driver.check(who, 'viewer', doc, canonical), who.uuid)
      assert.isTrue(await driver.check(purged, 'viewer', doc, canonical), 'con --rekey el acceso del purgado VUELVE: por eso es opt-in tras el listado')
      assert.equal((await driver.check(u1, 'viewer', doc, { type: 'unit', uuid: aliases.dashless }).then(() => null, (e) => e))?.code, 'E_AUTHZ_INVALID_IDENTITY')

      // IDEMPOTENTE.
      const snapshot = JSON.stringify(all.map((r) => [String(r.uuid), String(r.partition_key), r.subject_partition === null ? null : String(r.subject_partition), codec.fromDb(r.expires_at)?.toISOString() ?? null]))
      for (const statement of rekey) await scratch.db.rawQuery(statement)
      const again: any[] = await scratch.db.from('authz_relations').select(...columns).orderBy('subject_uuid')
      assert.equal(JSON.stringify(again.map((r) => [String(r.uuid), String(r.partition_key), r.subject_partition === null ? null : String(r.subject_partition), codec.fromDb(r.expires_at)?.toISOString() ?? null])), snapshot, 'segunda pasada: el mismo censo')
    } finally {
      await scratch.drop()
    }
  }).timeout(120_000)

  /**
   * **A2, medido en el motor**: el tipo `uuid` de PostgreSQL FUNDE las cuatro
   * formas con la canónica. Es la razón publicada de la regla («la ortografía
   * que un motor funde»), y por eso la regla no puede ser solo «sin guiones».
   */
  test('A2 · PostgreSQL funde con la canónica las cuatro formas no canónicas (`::uuid`), y rechaza un 33 hex y un 31 hex (que la API acepta como ids)', async ({ assert }) => {
    const dashed = uuidv7()
    const aliases = aliasesOf(dashed)
    for (const [label, alias] of Object.entries(aliases)) {
      const rows = rowsOf(await db.rawQuery(`select ?::uuid = ?::uuid as same`, [alias, dashed]))
      assert.isTrue(rows[0].same === true, `${label}: PG funde '${alias}' con '${dashed}'`)
    }
    for (const notUuid of [dashed.replace(/-/g, '') + '0', dashed.replace(/-/g, '').slice(1)]) {
      const failed = await db.rawQuery(`select ?::uuid as u`, [notUuid]).then(() => null, (e) => e)
      assert.isNotNull(failed, `'${notUuid}' no es un uuid para PG`)
      assert.isFalse(isNonCanonicalUuid(notUuid), 'y tampoco para la regla: es un id legal')
    }
  })
    .skip(testEngine() !== 'pg', 'solo PostgreSQL tiene el tipo uuid que funde ortografías')
})

/** Forma del resultado crudo por cliente (como `rowsOf` del driver): pg `{ rows }`, sqlite `rows[]`, mysql2 `[rows[], fields[]]`. */
function rowsOf(result: any): any[] {
  if (Array.isArray(result)) return result.length === 2 && Array.isArray(result[0]) && Array.isArray(result[1]) ? result[0] : result
  return result?.rows ?? []
}

/* ══════════════════════════════════════════════════════════════════════════
 * ⚪ 12 (cierre 1 del lote B): la receta SQL del residuo pre-2.5 de B3 (userset ≠ `group#member` como sujeto) del
 * README §Upgrading, EJECUTADA (una receta no ejecutada es letra sin efecto, L8): el detector lista EXACTAMENTE
 * las filas que la API ya no admite, el DELETE las quita y deja intactos los holders y los `group#member`, es
 * idempotente, y las sentencias del README son byte a byte las constantes que el comando imprime en la línea
 * del residuo. Corre en los CUATRO modos (`:memory:`, sqlite-file, pg, mysql): los tres motores.
 * ══════════════════════════════════════════════════════════════════════════ */
async function b3Recipe(): Promise<{ select: string; del: string }> {
  const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
  const marker = '-- B3 · userset residue'
  const block = [...readme.matchAll(/```sql\n([\s\S]*?)```/g)].map((m) => m[1]).find((b) => b.startsWith(marker))
  if (!block) throw new Error(`el README no tiene el bloque \`\`\`sql que empieza por "${marker}"`)
  const statements = block
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('--'))
  if (statements.length !== 2) throw new Error(`la receta B3 tiene ${statements.length} sentencias (se esperaban 2: detector y DELETE)`)
  return { select: statements[0], del: statements[1] }
}

test.group(`B3 · la receta del residuo pre-2.5 (userset ≠ group#member) del README en ${testEngine()}, ejecutada (⚪ 12)`, () => {
  test('el detector lista exactamente los residuos (ni holders ni group#member), el DELETE los quita y solo a ellos, es idempotente, y las sentencias son las que imprime el comando', async ({ assert }) => {
    const { RELATION_USERSET_RESIDUE_SELECT, RELATION_USERSET_RESIDUE_DELETE } = await import('../src/relations/define_relations_config.js')
    const { select, del } = await b3Recipe()
    assert.equal(select, RELATION_USERSET_RESIDUE_SELECT, 'el detector del README es la constante del paquete')
    assert.equal(del, RELATION_USERSET_RESIDUE_DELETE, 'el DELETE del README es el que imprime la línea del residuo')
    await db.from('authz_relations').delete()
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const key = `unit|${p.uuid}`
    const driver = new DatabaseRelationsDriver(contractRelationsConfig())
    const holder = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const group = { type: 'group', id: uuidv7() }
    await driver.relate(holder, 'viewer', doc, p)
    await driver.relate(holder, 'member', group, p)
    await driver.relate({ object: group, relation: 'member' }, 'viewer', doc, p)
    const residue = (objectType: string, subjectType: string, subjectRelation: string) =>
      db.table('authz_relations').insert({
        uuid: uuidv7(), partition_key: key, object_type: objectType, object_uuid: uuidv7(), relation: 'viewer',
        subject_type: subjectType, subject_uuid: uuidv7(), subject_relation: subjectRelation, subject_partition: key, expires_at: null, created_at: new Date(),
      })
    await residue('document', 'document', 'viewer')
    await residue('document', 'workspace', 'editor')
    assert.lengthOf(await db.from('authz_relations'), 5)

    const rowsOf = (raw: any): any[] => (Array.isArray(raw) ? (Array.isArray(raw[0]) ? raw[0] : raw) : raw?.rows ?? [])
    const listed = rowsOf(await db.rawQuery(select.replace(/;$/, '')))
    assert.sameMembers(
      listed.map((r: any) => `${r.subject_type}#${r.subject_relation}`),
      ['document#viewer', 'workspace#editor'],
      'el detector lista los DOS residuos y nada más'
    )
    await db.rawQuery(del.replace(/;$/, ''))
    const left: any[] = await db.from('authz_relations').select('subject_type', 'subject_relation')
    assert.sameMembers(
      left.map((r) => `${r.subject_type}#${r.subject_relation}`),
      ['user#', 'user#', 'group#member'],
      'quedan los dos holders y el group#member'
    )
    assert.isTrue(await driver.check(holder, 'viewer', doc, p), 'lo legítimo sigue concediendo')
    assert.isTrue(await driver.check({ object: group, relation: 'member' }, 'viewer', doc, p))
    await db.rawQuery(del.replace(/;$/, ''))
    assert.lengthOf(await db.from('authz_relations'), 3, 'idempotente')
    assert.lengthOf(rowsOf(await db.rawQuery(select.replace(/;$/, ''))), 0, 'el detector queda en cero')
    await db.from('authz_relations').delete()
  })
})
