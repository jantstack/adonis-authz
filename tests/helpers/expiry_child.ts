/**
 * Proceso HIJO de `expiry_timezone.spec` (2.5-B · K2/K17): abre la MISMA base
 * que la suite —con la config de conexión que le llega por `AUTHZ_TEST_REUSE`,
 * SIN `timezone: 'Z'`: la conexión por defecto de un consumidor— y, con el
 * `TZ` con el que lo lanzaron, escribe o lee caducidades. Imprime UNA línea
 * JSON con lo observado. Lo que la suite compara es que todos los procesos,
 * sea cual sea su zona, vean el MISMO instante.
 *
 *   TZ=Asia/Tokyo AUTHZ_TEST_REUSE='{…}' node --import @poppinss/ts-exec tests/helpers/expiry_child.ts write|read <holder uuid> <ISO>
 */

import { bootApp } from './app.js'

const [phase, holderUuid, iso] = process.argv.slice(2)
const reuse = JSON.parse(process.env.AUTHZ_TEST_REUSE ?? 'null')
if (!reuse || !phase || !holderUuid || !iso) {
  console.error('uso: AUTHZ_TEST_REUSE=<json> expiry_child.ts write|read <holder uuid> <ISO>')
  process.exit(2)
}

const app = await bootApp({ reuse })
try {
  const { DatabaseAuthorizationDriver } = await import('../../src/drivers/database_driver.js')
  const { APP_SCOPE } = await import('../../src/types.js')
  const holder = { type: 'users', uuid: holderUuid }
  const T = new Date(iso)
  const driver = new DatabaseAuthorizationDriver()
  if (phase === 'write') {
    const outcome = await driver.grant(holder, 'editor', APP_SCOPE, { expiresAt: T })
    console.log(JSON.stringify({ tz: process.env.TZ ?? null, wrote: outcome.expiresAt?.toISOString() ?? null }))
  } else {
    const at = (ms: number) => driver.withClock(() => new Date(T.getTime() + ms))
    const stored = await driver.withClock(() => new Date(T.getTime() - 60_000)).grant(holder, 'editor', APP_SCOPE)
    console.log(
      JSON.stringify({
        tz: process.env.TZ ?? null,
        before: await at(-1000).authorize(holder, 'docs:read', APP_SCOPE),
        atT: await at(0).authorize(holder, 'docs:read', APP_SCOPE),
        after: await at(1000).authorize(holder, 'docs:read', APP_SCOPE),
        stored: stored.previousExpiresAt?.toISOString() ?? null,
      })
    )
  }
} finally {
  await app.teardown()
}
