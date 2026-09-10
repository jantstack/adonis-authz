/**
 * **2.4.0-alpha.5 · R6 — el relay es escritor ÚNICO entre PROCESOS de verdad**
 * (tester del panel relay, 🔴: «la garantía no está observada donde importa»).
 *
 * `scope_outbox.spec.ts` («dos pasadas a la vez: la segunda no aplica NADA y
 * lo dice») hace `Promise.all` de dos pasadas EN EL MISMO PROCESO. En
 * `:memory:` eso pasa por `localLeases` —un `Set` de módulo— y en pg/mysql,
 * aunque se toma el cerrojo del servidor, las dos pasadas comparten proceso y
 * el `Set` también las excluiría. Conclusión medida: el mutante «sustituir el
 * advisory lock por `localLeases` en todos los dialectos» deja ese caso VERDE
 * en los cuatro motores. Y el escenario que motiva el lease —dos réplicas, un
 * `CronJob` con `concurrencyPolicy: Allow`— es multiproceso por definición.
 *
 * Patrón de `freeze_multiprocess.spec.ts` + `helpers/relay_child.ts`:
 * `execFileSync` de un hijo con `bootApp({ reuse })`, determinista (el padre
 * toma el lease ANTES de lanzar al hijo: sin sleep, sin carrera).
 *
 * **Gate por motor, declarado**: corre en `pg`, `mysql` y `sqlite-file` —los
 * motores que otro proceso puede abrir—. En `:memory:` la base ES del proceso
 * y esta garantía NO es observable en `npm test` a secas: ahí el mutante queda
 * verde, y por eso los jobs de CI de los otros motores no son opcionales.
 * Y en `sqlite-file` el «verde» es el comportamiento MALO a propósito (5-4):
 * el cerrojo es de PROCESO, el hijo aplica por encima del padre, y el README
 * lo dice con esas palabras — SQLite no es el motor de dos réplicas del relay.
 */

import { test } from '@japa/runner'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { readFile } from 'node:fs/promises'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { sqlScopeOutbox } from '../src/scope_outbox.js'
import { APP_SCOPE } from '../src/types.js'
import { cleanScopeOutbox } from './helpers/schema.js'
import { testEngine } from './helpers/app.js'
import type { TestApp } from './helpers/app.js'

const CHILD = fileURLToPath(new URL('./helpers/relay_child.ts', import.meta.url))
const ROOT = fileURLToPath(new URL('..', import.meta.url))

/** La config de conexión de ESTA suite (la base que el hijo reabre). */
async function suiteApp(): Promise<Pick<TestApp, 'engine' | 'connection' | 'database'>> {
  const raw: any = structuredClone(db.manager.get('primary')?.config)
  return { engine: testEngine(), connection: raw, database: String(raw?.connection?.database ?? raw?.connection?.filename ?? '') }
}

function inChild(reuse: unknown): { busy: boolean; applied: string[]; calls: string[] } {
  const output = execFileSync(process.execPath, ['--import', '@poppinss/ts-exec', CHILD], {
    encoding: 'utf-8',
    cwd: ROOT,
    timeout: 60_000,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, AUTHZ_TEST_REUSE: JSON.stringify(reuse) },
  })
  const line = output.split('\n').find((l) => l.startsWith('{'))
  if (!line) throw new Error(`el hijo del relay no imprimió JSON:\n${output}`)
  return JSON.parse(line)
}

const engine = testEngine()

if (engine === 'pg' || engine === 'mysql' || engine === 'sqlite-file') {
  test.group('alpha.5 · R6 · el relay es escritor ÚNICO entre PROCESOS (mata al mutante «advisory lock → Set de proceso»)', (group) => {
    group.each.setup(async () => {
      await cleanScopeOutbox(db)
    })

    async function enqueueOne() {
      const outbox = sqlScopeOutbox()
      const org = { type: 'organization', uuid: uuidv7() }
      const unit = { type: 'unit', uuid: uuidv7() }
      const receipt = (await outbox.enqueue({ op: 'attached', child: unit, parent: org }, {})) as { id: string | number }
      return { outbox, id: String(receipt.id), org, unit }
    }

    test('5-1 · control: sin lease tomado, el OTRO proceso releva y aplica', async ({ assert }) => {
      const reuse = await suiteApp()
      const { id, outbox } = await enqueueOne()
      const seen = inChild(reuse)
      assert.isFalse(seen.busy)
      assert.deepEqual(seen.applied, [id], 'el hijo aplicó la entrada')
      assert.lengthOf(seen.calls, 1)
      assert.deepEqual(await outbox.pending(10), [], 'y la marcó')
      void APP_SCOPE
    }).timeout(120_000)

    if (engine === 'sqlite-file') {
      test('5-4 · en sqlite-file el cerrojo es de PROCESO: el OTRO proceso aplica pese al lease del padre — y el README lo dice con esas palabras', async ({
        assert,
      }) => {
        const reuse = await suiteApp()
        const { id, outbox } = await enqueueOne()
        const lease = await outbox.acquire!()
        assert.isNotNull(lease, 'el padre tiene el lease (de su proceso)')
        try {
          const seen = inChild(reuse)
          assert.isFalse(seen.busy, 'el hijo NO ve el lease: es un Set de este proceso')
          assert.deepEqual(seen.applied, [id], 'y aplica por encima del padre: por eso SQLite no vale para dos réplicas')
        } finally {
          await lease!.release()
        }
        const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
        assert.include(readme, 'a process-wide one on SQLite')
        assert.include(readme, 'SQLite is not the engine for two replicas of the relay')
      }).timeout(120_000)
    } else {
      test('5-2/5-3 · con el lease del padre SOSTENIDO, el OTRO proceso no aplica NADA y lo dice (`busy`); soltado, entra', async ({ assert }) => {
        const reuse = await suiteApp()
        const { id, outbox } = await enqueueOne()
        // El padre toma el lease a mano y DESPUÉS lanza al hijo: determinista.
        const lease = await outbox.acquire!()
        assert.isNotNull(lease, 'el padre tiene el lease')
        try {
          const blocked = inChild(reuse)
          assert.isTrue(blocked.busy, 'el lease es del SERVIDOR: alcanza al otro proceso')
          assert.deepEqual(blocked.applied, [], 'cero escrituras')
          assert.deepEqual(blocked.calls, [], 'el driver del hijo no vio nada')
          assert.deepEqual((await outbox.pending(10)).map((p) => String(p.id)), [id], 'la entrada sigue pendiente')
        } finally {
          await lease!.release()
        }
        const after = inChild(reuse)
        assert.isFalse(after.busy, 'soltado el lease, el hijo entra')
        assert.deepEqual(after.applied, [id])
        assert.deepEqual(await outbox.pending(10), [])
      }).timeout(120_000)
    }
  })
}
