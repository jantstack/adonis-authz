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
import { parseUtcDatetime, sqlExpiryCodec } from '../src/shared/sql_expiry.js'
import { OpenFgaAuthorizationDriver } from '../src/drivers/openfga_driver.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/scope_tree.js'
import { OPENFGA_OPT_IN } from './helpers/openfga_opt_in.js'
import { FgaMemoryStore, installMemoryClient } from './helpers/fga_memory_client.js'
import { generatedModel, TEST_MODEL_ID } from './helpers/fga_model.js'
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

/**
 * Rotación 3 · cierre 2 · RR-2 (🟡, re-ataque): una caducidad PRESENTE que no se puede leer es un error (500
 * `E_AUTHZ_INTERNAL`), nunca `null` = «sin caducidad». Hasta aquí `parseUtcDatetime('0000-00-00 00:00:00.000000')` (lo
 * que `DATE_FORMAT` devuelve para la fecha cero que MySQL deja con un `sql_mode` no estricto) y el codec identidad con un
 * `-infinity` de PostgreSQL o un texto devolvían `null`: el re-grant la conservaba como permanente y `reconcile
 * --to=openfga` / el export de `relations:reconcile` escribían una tupla PERMANENTE para una fila que en SQL ya no
 * concede. El código compartido (`src/shared/sql_expiry.ts`) lanza; cada consumidor lo propaga antes de escribir.
 */
test.group('RR-2 · una caducidad presente e ilegible es un error, nunca «sin caducidad» (código compartido SQL)', () => {
  async function thrown(fn: () => unknown): Promise<any> {
    try {
      await fn()
    } catch (error) {
      return error
    }
    return undefined
  }

  test('parseUtcDatetime lee una fecha real al milisegundo y LANZA 500 con la fecha cero, un mes 13, un 31 de febrero, un 24:00 o basura', async ({ assert }) => {
    assert.equal(parseUtcDatetime('2030-06-15 12:00:00.123456').toISOString(), '2030-06-15T12:00:00.123Z')
    assert.equal(parseUtcDatetime('2030-06-15T12:00:00').toISOString(), '2030-06-15T12:00:00.000Z')
    assert.equal(parseUtcDatetime('2028-02-29 23:59:59.999').toISOString(), '2028-02-29T23:59:59.999Z')
    for (const bad of ['0000-00-00 00:00:00.000000', '2030-00-10 00:00:00', '2030-13-01 00:00:00', '2030-02-31 00:00:00', '2031-02-29 00:00:00', '2030-01-01 24:00:00', '2030-01-01 23:60:00', 'garbage', '']) {
      const error = await thrown(() => parseUtcDatetime(bad))
      assert.equal(error?.status, 500, `${JSON.stringify(bad)}: ${error?.message ?? 'no lanzó (devolvió una fecha o null)'}`)
      assert.equal(error?.code, 'E_AUTHZ_INTERNAL', JSON.stringify(bad))
      assert.include(String(error?.message), 'nunca «sin caducidad»')
    }
  })

  test('los dos codecs: NULL es «sin caducidad»; lo presente e ilegible (fecha cero de MySQL, ±infinity de PostgreSQL, texto, Date inválido) LANZA', async ({ assert }) => {
    const mysql = sqlExpiryCodec({ dialect: { name: 'mysql2' } })
    const identity = sqlExpiryCodec({ dialect: { name: 'postgres' } })
    for (const codec of [mysql, identity]) {
      assert.isNull(codec.fromDb(null))
      assert.isNull(codec.fromDb(undefined))
    }
    assert.equal(mysql.fromDb('2030-01-01 00:00:00.500000')?.toISOString(), '2030-01-01T00:00:00.500Z')
    assert.equal(identity.fromDb(Date.UTC(2030, 0, 1))?.toISOString(), '2030-01-01T00:00:00.000Z')
    assert.equal(identity.fromDb(new Date('2030-01-01T00:00:00Z'))?.toISOString(), '2030-01-01T00:00:00.000Z')
    const cases: Array<[string, () => unknown]> = [
      ['mysql · fecha cero', () => mysql.fromDb('0000-00-00 00:00:00.000000')],
      ['mysql · 31 de febrero', () => mysql.fromDb('2030-02-31 00:00:00.000000')],
      ['identidad · -infinity (pg)', () => identity.fromDb(-Infinity)],
      ['identidad · infinity (pg)', () => identity.fromDb(Infinity)],
      ['identidad · texto (sqlite)', () => identity.fromDb('not a date')],
      ['identidad · Date inválido', () => identity.fromDb(new Date(Number.NaN))],
    ]
    for (const [name, read] of cases) {
      const error = await thrown(read)
      assert.equal(error?.code, 'E_AUTHZ_INTERNAL', `${name}: ${error?.message ?? 'no lanzó'}`)
    }
  })

  test('mysql · una fila con la fecha cero (sql_mode no estricto): authorize no concede y el re-grant es 500 sin tocar la fila (antes: «existed, sin caducidad»)', async ({ assert }) => {
    const { default: db } = await import('@adonisjs/lucid/services/db')
    await cleanAuthzTables()
    await syncAuthzCatalog({ permissions: [{ slug: 'docs:read' }], roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }] })
    const holder = { type: 'users', uuid: uuidv7() }
    const T = new Date('2030-01-01T00:00:00.000Z')
    const driver = new DatabaseAuthorizationDriver({ now: () => T })
    await driver.grant(holder, 'editor', APP_SCOPE, { expiresAt: new Date('2031-01-01T00:00:00.000Z') })
    // La fecha cero, escrita como la deja un `sql_mode` no estricto (p. ej. el centinela de una receta vieja).
    const knex: any = (db.connection() as any).getWriteClient()
    const conn: any = await knex.client.acquireConnection()
    const q = (sql: string, bindings: unknown[] = []) =>
      new Promise<any>((resolve, reject) => conn.query(sql, bindings, (e: any, r: any) => (e ? reject(e) : resolve(r))))
    try {
      await q('SET @rr2_mode = @@SESSION.sql_mode')
      await q("SET SESSION sql_mode = ''")
      await q("UPDATE authz_assignments SET expires_at = '0000-00-00 00:00:00' WHERE holder_uuid = ?", [holder.uuid])
    } finally {
      await q('SET SESSION sql_mode = @rr2_mode').catch(() => {})
      await knex.client.releaseConnection(conn)
    }
    const stored = async () =>
      (await db.from('authz_assignments').where('holder_uuid', holder.uuid).select(db.raw("DATE_FORMAT(expires_at, '%Y-%m-%d %H:%i:%s.%f') as e")))[0]?.e
    assert.equal(await stored(), '0000-00-00 00:00:00.000000', 'control: la fila tiene la fecha cero')
    assert.isFalse(await driver.authorize(holder, 'docs:read', APP_SCOPE), 'la decisión de SQL no concede')
    const error = await thrown(() => driver.grant(holder, 'editor', APP_SCOPE))
    assert.equal(error?.code, 'E_AUTHZ_INTERNAL', `re-grant: ${error?.message ?? 'no lanzó: leyó la fecha cero como «sin caducidad»'}`)
    assert.equal(await stored(), '0000-00-00 00:00:00.000000', 'la fila no se tocó')
    // La salida declarada: revoke (no lee la caducidad) + grant.
    await driver.revoke(holder, 'editor', APP_SCOPE)
    await driver.grant(holder, 'editor', APP_SCOPE, { expiresAt: new Date('2031-01-01T00:00:00.000Z') })
    assert.isTrue(await driver.authorize(holder, 'docs:read', APP_SCOPE))
  }).skip(testEngine() !== 'mysql', 'solo MySQL (la fecha cero solo existe ahí)')

  test('mysql · reconcile --to=openfga (consumidor del codec compartido, código de openfga sin tocar) con una fila de fecha cero: 500 antes de escribir NADA en el store (antes: escribía la asignación como tupla PERMANENTE)', async ({ assert }) => {
    const { default: db } = await import('@adonisjs/lucid/services/db')
    await cleanAuthzTables()
    await syncAuthzCatalog({ permissions: [{ slug: 'docs:read' }], roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }] })
    const holder = { type: 'users', uuid: uuidv7() }
    await new DatabaseAuthorizationDriver().grant(holder, 'editor', APP_SCOPE, { expiresAt: new Date('2031-01-01T00:00:00.000Z') })
    const knex: any = (db.connection() as any).getWriteClient()
    const conn: any = await knex.client.acquireConnection()
    const q = (sql: string, bindings: unknown[] = []) =>
      new Promise<any>((resolve, reject) => conn.query(sql, bindings, (e: any, r: any) => (e ? reject(e) : resolve(r))))
    try {
      await q('SET @rr2_mode = @@SESSION.sql_mode')
      await q("SET SESSION sql_mode = ''")
      await q("UPDATE authz_assignments SET expires_at = '0000-00-00 00:00:00' WHERE holder_uuid = ?", [holder.uuid])
    } finally {
      await q('SET SESSION sql_mode = @rr2_mode').catch(() => {})
      await knex.client.releaseConnection(conn)
    }
    const fga = new FgaMemoryStore({ model: generatedModel({ users: 'user' }, ['docs:read']), initial: [], trace: false } as any)
    const tree = memoryScopeTree()
    const target: any = new OpenFgaAuthorizationDriver({
      ...OPENFGA_OPT_IN,
      apiUrl: 'http://127.0.0.1:1',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      modelId: TEST_MODEL_ID,
      holderTypes: { users: 'user' },
      resolveChain: resolveChainFrom(tree),
      acceptScopeDriftRisk: true,
      logger: { warn: () => {} },
    } as any)
    installMemoryClient(target, fga.client('reconcile'))
    const error = await thrown(() => target.reconcile({ enumerateEdges: async () => ({ edges: [] }), resolveChain: resolveChainFrom(tree) }, {}))
    assert.equal(error?.code, 'E_AUTHZ_INTERNAL', `reconcile: ${error?.message ?? 'no lanzó'}`)
    assert.deepEqual(fga.tuples(), [], 'ni una tupla escrita (antes: role_binding#assignee del holder, sin condición = permanente)')
  }).skip(testEngine() !== 'mysql', 'solo MySQL (la fecha cero solo existe ahí)')

  /**
   * Re-ataque 2 · C1 (🟡, preexistente, DECLARADO en «Limits»; arreglo de fondo en 2.6, `backlog-2.6.md`): la decisión de
   * SQL (`expires_at > now`) no pasa por el codec. Con la fecha cero de MySQL y `-infinity` no concede; con un TEXTO en
   * SQLite (`TEXT > INTEGER` es siempre verdadero) o `+infinity` en PostgreSQL CONCEDE para siempre, mientras el codec
   * la lee caducada (texto) o lanza (`+infinity`). El paquete nunca escribe esos valores. Caracterización: hoy concede;
   * cuando 2.6 filtre por tipo/finitud, este caso se pone rojo y la fila de Limits se reescribe con él.
   */
  test('límite declarado rotación 3 · C1: una caducidad PASADA en texto (SQLite) o +infinity (PostgreSQL) concede en la decisión de SQL; se voltea en 2.6', async ({ assert }) => {
    const { default: db } = await import('@adonisjs/lucid/services/db')
    await cleanAuthzTables()
    await syncAuthzCatalog({ permissions: [{ slug: 'docs:read' }], roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }] })
    const holder = { type: 'users', uuid: uuidv7() }
    const driver = new DatabaseAuthorizationDriver()
    await driver.grant(holder, 'editor', APP_SCOPE, { expiresAt: new Date('2020-01-01T00:00:00.000Z') })
    assert.isFalse(await driver.authorize(holder, 'docs:read', APP_SCOPE), 'control: caducada no concede')
    const engine = String(testEngine())
    const value = engine === 'pg' ? 'infinity' : '2020-01-01T00:00:00.000Z'
    await db.from('authz_assignments').where('holder_uuid', holder.uuid).update({ expires_at: value })
    assert.isTrue(await driver.authorize(holder, 'docs:read', APP_SCOPE), `HOY: ${value} concede (límite declarado C1)`)
    const error = await thrown(() => driver.grant(holder, 'editor', APP_SCOPE))
    if (engine === 'pg') assert.equal(error?.code, 'E_AUTHZ_INTERNAL', 'el lector (re-grant) lo dice: 500')
    // La receta declarada: revoke + grant con la caducidad buena.
    await driver.revoke(holder, 'editor', APP_SCOPE)
    await driver.grant(holder, 'editor', APP_SCOPE, { expiresAt: new Date('2020-01-01T00:00:00.000Z') })
    assert.isFalse(await driver.authorize(holder, 'docs:read', APP_SCOPE), 'revoke + grant lo repara')
  }).skip(testEngine() === 'mysql', 'MySQL: DATETIME no admite ni texto ni +infinity (su fecha cero no concede: caso de arriba)')
})
