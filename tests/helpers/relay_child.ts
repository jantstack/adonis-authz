/**
 * Proceso HIJO de `scope_outbox_multiprocess.spec` (2.4.0-alpha.5 · R6; tester
 * del panel relay, 5-1/5-2/5-4): abre la MISMA base que la suite
 * (`bootApp({ reuse })`), construye SU PROPIA `sqlScopeOutbox` y SU PROPIO
 * manager —otro proceso, otra memoria, otro módulo cargado: exactamente una
 * segunda réplica del relay— y hace UNA pasada `relayScopeChanges()` sobre la
 * cola que el padre dejó. Imprime UNA línea JSON con lo observado:
 *
 *   { busy, applied: ids[], calls: string[] }
 *
 * Es el ÚNICO caso que mata al mutante «advisory lock → `Set` de proceso»:
 * dos pasadas del mismo proceso comparten `localLeases` (`scope_outbox.ts`),
 * así que el caso en proceso (`scope_outbox.spec.ts`, «dos pasadas a la vez»)
 * queda verde con el defecto puesto en los cuatro motores. Un segundo PROCESO
 * no comparte nada más que la base — si el lease no está en el SERVIDOR, aquí
 * se ve: el hijo aplica por encima del padre.
 *
 *   AUTHZ_TEST_REUSE='{…}' node --import @poppinss/ts-exec tests/helpers/relay_child.ts
 */

import { bootApp } from './app.js'

const reuse = JSON.parse(process.env.AUTHZ_TEST_REUSE ?? 'null')
if (!reuse) {
  console.error('uso: AUTHZ_TEST_REUSE=<json> relay_child.ts')
  process.exit(2)
}

const app = await bootApp({ reuse })
try {
  const { AuthorizationManager } = await import('../../src/manager.js')
  const { sqlScopeOutbox } = await import('../../src/scope_outbox.js')
  const { resolveChainFrom, memoryScopeTree } = await import('../../src/testing/main.js')

  const keyOf = (s: any) => `${s.type}:${s.uuid ?? ''}`
  const calls: string[] = []
  const driver: any = {
    authorize: async () => false,
    onScopeAttached: async (c: any, p: any) => void calls.push(`attached ${keyOf(c)} → ${keyOf(p)}`),
    onScopeMoved: async (c: any, p: any) => void calls.push(`moved ${keyOf(c)} → ${keyOf(p)}`),
    onScopeDetached: async (c: any) => void calls.push(`detached ${keyOf(c)}`),
    purgeScope: async () => {},
  }
  const manager = new AuthorizationManager({
    default: 'spy',
    drivers: { spy: () => driver },
    scopes: { resolveChain: resolveChainFrom(memoryScopeTree()), outbox: sqlScopeOutbox() },
    warnOnOptInSecurity: false,
  } as any)

  const report = await manager.relayScopeChanges()
  console.log(JSON.stringify({ busy: report.busy, applied: report.applied.map((a) => String(a.id)), calls }))
} finally {
  await app.teardown()
}
