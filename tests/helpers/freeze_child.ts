/**
 * Proceso HIJO de `freeze_multiprocess.spec` (3b-7): abre la MISMA base que
 * la suite (`bootApp({ reuse })`), construye SU PROPIO manager —otro proceso,
 * otra memoria, otro módulo cargado: exactamente un worker de la flota— e
 * intenta un `grant`. Imprime UNA línea JSON con lo observado:
 *
 *   { attempted: 'accepted' | '<code>/<status>', frozenGetter, readOk }
 *
 * Es el ÚNICO caso que mata al mutante `modulo` (el «durable» como global de
 * módulo): dos managers del mismo proceso comparten los módulos, así que
 * cualquier estado en memoria los congela a los dos y el caso en proceso
 * queda verde con el defecto puesto. Un segundo PROCESO no comparte nada más
 * que la base — si el freeze no está en la fila, aquí se ve.
 *
 *   AUTHZ_TEST_REUSE='{…}' node --import @poppinss/ts-exec tests/helpers/freeze_child.ts
 */

import { bootApp } from './app.js'

const reuse = JSON.parse(process.env.AUTHZ_TEST_REUSE ?? 'null')
if (!reuse) {
  console.error('uso: AUTHZ_TEST_REUSE=<json> freeze_child.ts')
  process.exit(2)
}

const app = await bootApp({ reuse })
try {
  const { AuthorizationManager } = await import('../../src/manager.js')
  const { APP_SCOPE } = await import('../../src/types.js')
  const { resolveChainFrom, memoryScopeTree } = await import('../../src/testing/main.js')
  const { v7: uuidv7 } = await import('uuid')

  const driverCalls: string[] = []
  const manager = new AuthorizationManager({
    default: 'spy',
    drivers: {
      spy: () =>
        ({
          async grant() {
            driverCalls.push('grant')
            return { existed: false, expiresAt: null }
          },
          async authorize() {
            return true
          },
        }) as any,
    },
    holderTypes: { users: 'user' },
    scopes: { resolveChain: resolveChainFrom(memoryScopeTree()) },
    warnOnOptInSecurity: false,
  })

  const subject = { type: 'users', uuid: uuidv7() }
  let attempted: string
  try {
    await manager.grant(subject, 'org-editor', APP_SCOPE)
    attempted = 'accepted'
  } catch (error: any) {
    attempted = `${error.code}/${error.status}`
  }
  // La asimetría también entre procesos: la lectura responde congelado o no.
  const readOk = await manager.authorize(subject, 'docs:read', APP_SCOPE)
  console.log(
    JSON.stringify({
      attempted,
      driverSawGrant: driverCalls.includes('grant'),
      frozenGetter: manager.frozen,
      readOk,
    })
  )
} finally {
  await app.teardown()
}
