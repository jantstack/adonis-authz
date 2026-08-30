/**
 * El harness multi-motor (2.5 · J2) promete —CLAUDE.md §Comandos y README
 * §Compatibility— que «cada ejecución crea `authz_test_<8 hex>` y la borra al
 * terminar; nunca se toca una base existente». Esa promesa vale para el
 * proceso de la suite Y para el proceso HIJO que lanza `purity.spec` (la
 * prueba de carga sin `@openfga/sdk`), que hereda `TEST_DB` y por tanto
 * provisiona SU propia base.
 *
 * Ese hijo fue justo el fallo que se encontró a mano durante la Fase 2.5: 16
 * bases `authz_test_*` huérfanas en PG y MySQL. Se corrigió (`teardown()` en
 * vez de `closeAll()`), pero NADA en la suite lo vigilaba: con el hijo
 * fugando, `npm run test:pg` seguía dando 335/335 en verde y dejando dos
 * bases en el servidor. Un residuo silencioso en el motor de otra persona no
 * es un detalle de limpieza: es la suite escribiendo fuera de su caja.
 *
 * Cómo se observa sin depender de quién más esté usando el servidor (otra
 * suite en paralelo crea y borra las suyas): el hijo IMPRIME el nombre de lo
 * que provisionó (`db:<nombre>`), y aquí se comprueba que ESE nombre concreto
 * ya no existe cuando el hijo ha terminado. Nada de contar bases.
 */

import { test } from '@japa/runner'
import { execFileSync, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import db from '@adonisjs/lucid/services/db'
import { testEngine } from './helpers/app.js'

const HELPER = fileURLToPath(new URL('./helpers/load_without_sdk.ts', import.meta.url))
const EXIT_HELPER = fileURLToPath(new URL('./helpers/exit_without_teardown.ts', import.meta.url))
const ROOT = fileURLToPath(new URL('..', import.meta.url))

/** Lanza el hijo tal y como lo lanza `purity.spec` y devuelve su salida. */
function loadInChild(target: string): string {
  return execFileSync(process.execPath, ['--import', '@poppinss/ts-exec', HELPER, target], {
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 60_000,
    cwd: ROOT,
  })
}

/**
 * ¿Existe esa base en el servidor? `pg_database` e `information_schema` son
 * catálogos compartidos: se leen desde la conexión de la suite, sin abrir una
 * administrativa. `mysql2` devuelve `[rows, fields]` (2.5 · J3).
 */
async function databaseExists(name: string): Promise<boolean> {
  const engine = testEngine()
  const sql =
    engine === 'pg'
      ? 'select datname as name from pg_database where datname = ?'
      : 'select schema_name as name from information_schema.schemata where schema_name = ?'
  const result: any = await db.rawQuery(sql, [name])
  const rows = Array.isArray(result) ? result[0] : (result?.rows ?? result)
  return Array.isArray(rows) && rows.length > 0
}

test.group('el harness no deja residuos fuera de su caja (2.5 · J2)', () => {
  test('el proceso hijo de la prueba de carga destruye la base (o el fichero) que provisionó', async ({
    assert,
  }) => {
    const engine = testEngine()
    const output = loadInChild('../../index.ts')
    assert.include(output, 'loaded:../../index.ts', output)

    const provisioned = /^db:(.+)$/m.exec(output)?.[1]
    assert.isString(
      provisioned,
      `el hijo tiene que decir qué provisionó (línea "db:<nombre>"); salida:\n${output}`
    )

    if (engine === 'sqlite') {
      // Nada que fugar: la base vive dentro de la conexión del hijo.
      assert.equal(provisioned, ':memory:')
      return
    }

    if (engine === 'sqlite-file') {
      // `mkdtemp` + fichero: lo que no debe quedar es el directorio temporal.
      assert.isFalse(
        fs.existsSync(path.dirname(provisioned!)),
        `el hijo dejó el directorio temporal ${path.dirname(provisioned!)}`
      )
      return
    }

    assert.match(provisioned!, /^authz_test_[0-9a-f]{8}$/)
    assert.isFalse(
      await databaseExists(provisioned!),
      `el hijo dejó la base '${provisioned}' en el servidor ${engine}: la suite escribe fuera de su caja`
    )
  }).timeout(90_000)

  test('también cuando el módulo que carga FALLA (el control: src/openfga.ts con el SDK bloqueado)', async ({
    assert,
  }) => {
    // El caso de control de `purity.spec` termina con código ≠ 0. Si la
    // limpieza viviera en el camino feliz y no en un `finally`, este es el
    // que dejaría el residuo — y es el que más veces se dará en la vida real
    // (un test de carga que revienta).
    const engine = testEngine()
    let output = ''
    try {
      output = loadInChild('../../src/openfga.ts')
      assert.fail('el control tenía que fallar: el SDK está bloqueado')
    } catch (error: any) {
      output = `${error.stdout ?? ''}${error.stderr ?? ''}`
    }

    const provisioned = /^db:(.+)$/m.exec(output)?.[1]
    assert.isString(provisioned, `el hijo tiene que decir qué provisionó; salida:\n${output}`)

    if (engine === 'sqlite') {
      assert.equal(provisioned, ':memory:')
      return
    }
    if (engine === 'sqlite-file') {
      assert.isFalse(fs.existsSync(path.dirname(provisioned!)), `quedó ${path.dirname(provisioned!)}`)
      return
    }
    assert.isFalse(
      await databaseExists(provisioned!),
      `el hijo que falla dejó la base '${provisioned}' en el servidor ${engine}`
    )
  }).timeout(90_000)

  test('3b-1 (⚪ 4 de 3b-0b): un proceso que sale con process.exit() SIN teardown() tampoco deja residuo — el guard de salida lo destruye y AVISA', async ({
    assert,
  }) => {
    // La fuga «no determinista» de bases en PostgreSQL no estaba en la suite
    // (que cierra a cero, medido) sino en los scripts de reproducción, que
    // hacen `bootApp()` … `process.exit(0)`: `process.exit` no espera a
    // ninguna promesa, así que `teardown()` no corre y queda UNA base
    // huérfana por ejecución (medido: 3 scripts ⇒ 3 bases). Por eso dos
    // re-ejecuciones aisladas de la suite nunca lo reproducían.
    const engine = testEngine()
    const done = spawnSync(process.execPath, ['--import', '@poppinss/ts-exec', EXIT_HELPER], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60_000,
      cwd: ROOT,
    })
    const output = `${done.stdout ?? ''}${done.stderr ?? ''}`
    assert.equal(done.status, 0, output)
    const provisioned = /^db:(.+)$/m.exec(output)?.[1]
    assert.isString(provisioned, `el hijo tiene que decir qué provisionó; salida:\n${output}`)

    if (engine === 'sqlite') {
      assert.equal(provisioned, ':memory:', 'nada que fugar: la base vive en la conexión')
      return
    }
    // Y no es silencioso: quien fuga se entera por stderr.
    assert.include(output, 'guard de salida', output)
    if (engine === 'sqlite-file') {
      assert.isFalse(fs.existsSync(path.dirname(provisioned!)), `quedó ${path.dirname(provisioned!)}`)
      return
    }
    assert.match(provisioned!, /^authz_test_[0-9a-f]{8}$/)
    assert.isFalse(
      await databaseExists(provisioned!),
      `process.exit() sin teardown dejó '${provisioned}' en el servidor ${engine}: el guard de salida no la destruyó`
    )
  }).timeout(90_000)
})
