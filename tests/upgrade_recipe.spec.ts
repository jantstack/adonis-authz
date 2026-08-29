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
import db from '@adonisjs/lucid/services/db'
import { openScratchDatabase, testEngine } from './helpers/app.js'
import { describeAuthzSchema } from './helpers/schema.js'

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
      assert.deepEqual(seen.schema, await describeAuthzSchema(db), 'el esquema subido es el publicado')
    }).timeout(180_000)
  })
}
