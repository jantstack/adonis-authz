/**
 * 3b-7 — el freeze durable entre **PROCESOS de verdad** (hallazgo del tester
 * del panel 3: el caso en proceso NO basta).
 *
 * Dos managers del mismo proceso comparten los módulos cargados, así que el
 * mutante `modulo` —guardar el «durable» en una global de módulo en vez de
 * en la fila, exactamente el defecto que este lote arregla— deja VERDE todo
 * `freeze.spec.ts`. Solo un segundo proceso, que no comparte nada más que la
 * base, lo mata. Patrón de `expiry_timezone.spec.ts` + `expiry_child.ts`:
 * `execFileSync` de un hijo con `bootApp({ reuse })`, determinista (el padre
 * congela ANTES de lanzar al hijo: sin sleep, sin carrera), ~1 s.
 *
 * **Gate por motor, declarado**: corre en `pg`, `mysql` y `sqlite-file` —los
 * motores que otro proceso puede abrir—. En SQLite `:memory:` la base ES del
 * proceso (un hijo no puede abrirla), así que esta garantía NO es observable
 * en `npm test` a secas: ahí el mutante `modulo` queda verde, y por eso los
 * jobs de CI de los otros motores no son opcionales para este lote.
 */

import { test } from '@japa/runner'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { v7 as uuidv7 } from 'uuid'
import { AuthorizationManager } from '../src/manager.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { testEngine } from './helpers/app.js'
import type { TestApp } from './helpers/app.js'

const CHILD = fileURLToPath(new URL('./helpers/freeze_child.ts', import.meta.url))
const ROOT = fileURLToPath(new URL('..', import.meta.url))

/** La config de conexión de ESTA suite (la base que el hijo reabre). */
async function suiteApp(): Promise<Pick<TestApp, 'engine' | 'connection' | 'database'>> {
  const { default: db } = await import('@adonisjs/lucid/services/db')
  const raw: any = structuredClone(db.manager.get('primary')?.config)
  return { engine: testEngine(), connection: raw, database: String(raw?.connection?.database ?? raw?.connection?.filename ?? '') }
}

function inChild(reuse: unknown): any {
  const output = execFileSync(process.execPath, ['--import', '@poppinss/ts-exec', CHILD], {
    encoding: 'utf-8',
    cwd: ROOT,
    timeout: 60_000,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, AUTHZ_TEST_REUSE: JSON.stringify(reuse) },
  })
  const line = output.split('\n').find((l) => l.startsWith('{'))
  if (!line) throw new Error(`el hijo del freeze no imprimió JSON:\n${output}`)
  return JSON.parse(line)
}

function parentManager() {
  return new AuthorizationManager({
    default: 'spy',
    drivers: { spy: () => ({ async grant() {} }) as any },
    holderTypes: { users: 'user' },
    scopes: { resolveChain: resolveChainFrom(memoryScopeTree()) },
    warnOnOptInSecurity: false,
  })
}

if (testEngine() === 'pg' || testEngine() === 'mysql' || testEngine() === 'sqlite-file') {
  test.group('3b-7 · freeze durable entre PROCESOS (mata al mutante `modulo`)', (group) => {
    group.each.setup(async () => {
      // Teardown explícito (tester C1): un freeze que se escapa envenena todo lo que siga.
      return async () => {
        const { default: db } = await import('@adonisjs/lucid/services/db')
        await db
          .from('authz_catalog_version')
          .where('id', 2)
          .update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null })
      }
    })

    test('control: sin freeze, la escritura del OTRO proceso entra', async ({ assert }) => {
      const reuse = await suiteApp()
      const seen = inChild(reuse)
      assert.equal(seen.attempted, 'accepted', 'sin freeze el hijo escribe con normalidad')
      assert.isTrue(seen.driverSawGrant)
    }).timeout(120_000)

    test('congelado por el padre: la escritura del OTRO proceso es 503 E_AUTHZ_FROZEN, su lectura sigue, y unfreeze lo devuelve', async ({
      assert,
    }) => {
      const reuse = await suiteApp()
      const manager = parentManager()
      // leaseMs: null — execFileSync bloquea el event loop del padre y un
      // renovador no podría correr; la ventana del operador no lo necesita.
      const token = await manager.freeze('cutover multiproceso', { leaseMs: null, kind: 'operator' })
      try {
        const frozen = inChild(reuse)
        assert.equal(frozen.attempted, 'E_AUTHZ_FROZEN/503', 'el freeze ALCANZA al otro proceso: eso es «durable»')
        assert.isFalse(frozen.driverSawGrant, 'la escritura no llegó a su driver')
        assert.isFalse(frozen.frozenGetter, 'el hijo no SOSTIENE el freeze: lo ve por la fila')
        assert.isTrue(frozen.readOk, 'las lecturas del otro proceso siguen (la asimetría, entre procesos)')
      } finally {
        await manager.unfreeze(token)
      }
      const after = inChild(reuse)
      assert.equal(after.attempted, 'accepted', 'levantada la ventana, la flota vuelve a escribir')
    }).timeout(120_000)
  })
}
