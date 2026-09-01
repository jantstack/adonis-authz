/**
 * La caducidad es un INSTANTE, no una hora de pared (2.5-B · K2, auditor 🟠 2;
 * K17/G6 del tester). En MySQL `DATETIME(3)` no guarda zona y `mysql2`
 * serializa los `Date` con el `TZ` del proceso (`timezone: 'local'`): un
 * proceso en UTC escribía `12:00` y uno en Caracas leía ese `12:00` como
 * `16:00Z` — la asignación caducaba 4 h tarde para él, y 9 h antes para uno
 * en Tokio. Dentro de un solo proceso el ida y vuelta era exacto, que es lo
 * único que el juez podía ver. Aquí hay procesos de verdad, con `TZ`
 * distinta, sobre la MISMA base, y con la conexión por defecto (sin
 * `timezone: 'Z'`): el driver tiene que dar la misma respuesta en todos.
 *
 * Solo en los motores de servidor (PG y MySQL): son los que otro proceso
 * puede abrir. En SQLite la caducidad se guarda como número (sin zona).
 */

import { test } from '@japa/runner'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { v7 as uuidv7 } from 'uuid'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { APP_SCOPE } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { testEngine } from './helpers/app.js'
import type { TestApp } from './helpers/app.js'

const CHILD = fileURLToPath(new URL('./helpers/expiry_child.ts', import.meta.url))
const ROOT = fileURLToPath(new URL('..', import.meta.url))
const ZONES = ['UTC', 'Asia/Tokyo', 'America/Caracas']

/** La app de ESTA suite (la base que los hijos reabren). */
async function suiteApp(): Promise<Pick<TestApp, 'engine' | 'connection' | 'database'>> {
  const { default: db } = await import('@adonisjs/lucid/services/db')
  const raw: any = structuredClone(db.manager.get('primary')?.config)
  // La conexión por defecto de un consumidor: SIN `timezone: 'Z'` (el hijo no
  // hereda la opción con la que la suite se protege; el driver no la necesita).
  delete raw?.connection?.timezone
  return { engine: testEngine(), connection: raw, database: String(raw?.connection?.database) }
}

function inChild(tz: string, phase: 'write' | 'read', holderUuid: string, iso: string, reuse: unknown): any {
  const output = execFileSync(process.execPath, ['--import', '@poppinss/ts-exec', CHILD, phase, holderUuid, iso], {
    encoding: 'utf-8',
    cwd: ROOT,
    timeout: 60_000,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, TZ: tz, AUTHZ_TEST_REUSE: JSON.stringify(reuse) },
  })
  const line = output.split('\n').find((l) => l.startsWith('{'))
  if (!line) throw new Error(`el hijo (TZ=${tz}, ${phase}) no imprimió JSON:\n${output}`)
  return JSON.parse(line)
}

if (testEngine() === 'pg' || testEngine() === 'mysql') {
  test.group('expires_at es un instante: procesos con TZ distinta sobre la misma base ven la misma caducidad (2.5-B · K2)', (group) => {
    group.each.setup(async () => {
      await cleanAuthzTables()
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }],
        roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
      })
    })

    test('escrito por la suite, leído por hijos en UTC, Tokio y Caracas (sin timezone en su conexión): T−1 s concede, T no, T+1 s no, y lo leído es T', async ({
      assert,
    }) => {
      const reuse = await suiteApp()
      const T = new Date('2030-06-15T12:00:00.000Z')
      const alice = { type: 'users', uuid: uuidv7() }
      await new DatabaseAuthorizationDriver().grant(alice, 'editor', APP_SCOPE, { expiresAt: T })
      for (const tz of ZONES) {
        const seen = inChild(tz, 'read', alice.uuid, T.toISOString(), reuse)
        assert.deepEqual(seen, { tz, before: true, atT: false, after: false, stored: T.toISOString() }, `leído desde TZ=${tz}`)
      }
    }).timeout(120_000)

    test('escrito por hijos en Tokio y Caracas, leído por la suite y por los otros hijos: el instante no se mueve en ninguna dirección', async ({
      assert,
    }) => {
      const reuse = await suiteApp()
      const T = new Date('2031-01-20T03:30:00.500Z')
      const driver = new DatabaseAuthorizationDriver()
      for (const writer of ['Asia/Tokyo', 'America/Caracas']) {
        const holder = { type: 'users', uuid: uuidv7() }
        const wrote = inChild(writer, 'write', holder.uuid, T.toISOString(), reuse)
        assert.equal(wrote.wrote, T.toISOString(), `escrito desde TZ=${writer}`)
        // La suite (este proceso) lo lee con su reloj inyectado.
        const at = (ms: number) => driver.withClock(() => new Date(T.getTime() + ms))
        assert.isTrue(await at(-1).authorize(holder, 'docs:read', APP_SCOPE), `escrito en ${writer}: T−1 ms concede aquí`)
        assert.isFalse(await at(0).authorize(holder, 'docs:read', APP_SCOPE), `escrito en ${writer}: T no concede aquí`)
        const reread = await at(-60_000).grant(holder, 'editor', APP_SCOPE)
        assert.equal(reread.previousExpiresAt?.toISOString(), T.toISOString(), `escrito en ${writer}: lo leído aquí es T`)
        // Y los demás procesos ven lo mismo.
        for (const tz of ZONES) {
          const seen = inChild(tz, 'read', holder.uuid, T.toISOString(), reuse)
          assert.deepEqual(seen, { tz, before: true, atT: false, after: false, stored: T.toISOString() }, `escrito en ${writer}, leído desde TZ=${tz}`)
        }
      }
    }).timeout(180_000)
  })
}
