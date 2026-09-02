/**
 * L-3 (panel `{trx}`, veredicto (C), §1.2 y §6.2) — **`{ transaction }` REAL en
 * el driver `database`, puerto de roles**, medido motor a motor.
 *
 * La regla: **la ESCRITURA va por tu transacción; la AUTORIDAD (barrera del
 * freeze, catálogo, `resolveChain`) NUNCA.** Y el precio, decidido por el
 * dueño: `{ transaction }` exige **pool ≥ 2** — la autoridad lee por OTRA
 * conexión mientras el llamante sostiene la suya. Por eso el grupo grande
 * corre solo en `sqlite-file`/PG/MySQL (precedente `freeze_multiprocess`), y
 * en `:memory:` (pool 1/1) lo que se fija es la cara de pool 1: 503 por la
 * barrera, con cero sentencias por la transacción del llamante.
 *
 * Lo que el runner publicado ya juzga (`runAuthorizationDriverContract`, cara
 * `whenTrue`): rollback ⇒ CERO filas por CENSO para las cuatro escrituras, y
 * una transacción ajena ⇒ 500 sin una sentencia. Aquí va lo que el runner no
 * puede montar: una tabla del CONSUMIDOR en la misma transacción (los dos o
 * ninguno), una segunda conexión REAL, dos `grant` concurrentes en dos
 * transacciones externas (el UNIQUE, y qué queda de la transacción después,
 * que es DISTINTO por motor), el deadline vencido dentro de la transacción
 * (y qué publica `onWrite`), y la cara de pool 1.
 */

import { test } from '@japa/runner'
import db from '@adonisjs/lucid/services/db'
import { v7 as uuidv7 } from 'uuid'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { AuthorizationManager } from '../src/manager.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import type { AuthzWriteEvent, CatalogSpec, ScopeRef, SubjectRef } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { testEngine } from './helpers/app.js'

const HOLDERS = { users: 'user' }
const CATALOG: CatalogSpec = {
  permissions: [{ slug: 'docs:read' }],
  roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] }],
}
const CONSUMER_TABLE = 'l3_consumer_rows'

/** Un manager sobre el driver `database` REAL, con el hook `onWrite` capturado. */
function worker(extra: Record<string, unknown> = {}, driverOptions: Record<string, unknown> = {}) {
  const tree = memoryScopeTree()
  const driver = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree), ...driverOptions })
  const events: AuthzWriteEvent[] = []
  const manager = new AuthorizationManager({
    default: 'database',
    drivers: { database: () => driver },
    holderTypes: HOLDERS,
    scopes: { resolveChain: resolveChainFrom(tree) },
    warnOnOptInSecurity: false,
    hooks: {
      onWrite: async (event: AuthzWriteEvent) => {
        events.push(event)
      },
    },
    ...extra,
  } as any)
  return { manager, driver, tree, events }
}

/** El censo: las filas de ESE holder en las tablas de hechos, por la conexión del motor. */
async function census(subject: SubjectRef): Promise<{ assignments: number; denies: number }> {
  const count = async (table: string) => {
    const rows: any[] = await db.from(table).where('holder_type', subject.type).where('holder_uuid', subject.uuid).count('* as n')
    return Number(rows[0]?.n ?? 0)
  }
  return { assignments: await count('authz_assignments'), denies: await count('authz_denies') }
}

/**
 * Espía sobre una transacción REAL de Lucid: cuenta las sentencias que el
 * paquete construye por ella (`from`/`table`/`query`/`raw`…). Las propiedades
 * (`isTransaction`, `connectionName`) pasan tal cual: son lo que
 * `assertCallerTransaction` mira, y mirar no es escribir.
 */
function spyTransaction<T extends object>(trx: T): { transaction: T; statements: () => number } {
  let statements = 0
  const counted = new Set(['from', 'table', 'query', 'insertQuery', 'rawQuery', 'raw', 'knexQuery', 'knexRawQuery', 'modelQuery'])
  const transaction = new Proxy(trx, {
    get(target, prop) {
      const value = Reflect.get(target, prop)
      if (typeof value !== 'function') return value
      if (typeof prop === 'string' && counted.has(prop)) {
        return (...args: unknown[]) => {
          statements += 1
          return value.apply(target, args)
        }
      }
      return value.bind(target)
    },
  })
  return { transaction, statements: () => statements }
}

async function rejects(assert: any, run: () => unknown, code: string, status: number, note?: string) {
  try {
    await run()
  } catch (error: any) {
    assert.equal(error?.code, code, `${note ?? ''} code de ${error?.message ?? error}`)
    assert.equal(error?.status, status, `${note ?? ''} status de ${error?.message ?? error}`)
    return error
  }
  assert.fail(`${note ?? ''}: se esperaba ${code} y no lanzó`)
}

/** ¿Sigue viva la transacción del llamante? (PG la aborta tras un error; MySQL y SQLite no.) */
async function transactionAlive(trx: any): Promise<{ alive: boolean; error?: any }> {
  try {
    await trx.from('authz_catalog_version').where('id', 1).select('id')
    return { alive: true }
  } catch (error) {
    return { alive: false, error }
  }
}

const engine = testEngine()

if (engine !== 'sqlite') {
  test.group(`L-3 · { transaction } real en database (roles) — motor ${engine}, pool ≥ 2`, (group) => {
    let org: ScopeRef
    group.each.setup(async () => {
      await cleanAuthzTables()
      await syncAuthzCatalog(CATALOG)
      org = { type: 'organization', uuid: uuidv7() }
      return cleanAuthzTables
    })
    group.setup(async () => {
      await db.connection().schema.createTable(CONSUMER_TABLE, (table) => {
        table.integer('id').primary()
        table.string('note', 40).notNullable()
      })
      return async () => {
        await db.connection().schema.dropTable(CONSUMER_TABLE)
      }
    })

    test('COMPOSICIÓN: revoke + un UPDATE de una tabla del CONSUMIDOR en la MISMA transacción + rollback ⇒ ni lo uno ni lo otro (la asignación sigue, la fila sin tocar); + commit ⇒ los dos; y el evento lleva transactional: true', async ({
      assert,
    }) => {
      const { manager, tree, events } = worker()
      await tree.attach(org, APP_SCOPE)
      const alice = { type: 'users', uuid: uuidv7() }
      const id = 1
      await db.table(CONSUMER_TABLE).insert({ id, note: 'con acceso' })
      const note = async () => (await db.from(CONSUMER_TABLE).where('id', id).select('note'))[0]?.note
      await manager.grant(alice, 'org-editor', org)
      assert.isTrue(await manager.authorize(alice, 'docs:read', org))
      assert.notProperty(events[0], 'transactional', 'sin { transaction } el evento no lleva la marca')

      // Los dos o ninguno — ninguno.
      let caught: any = null
      try {
        await db.transaction(async (trx) => {
          await manager.revoke(alice, 'org-editor', org, { transaction: trx })
          await trx.from(CONSUMER_TABLE).where('id', id).update({ note: 'revocado' })
          // Dentro de la transacción las dos escrituras ya son visibles POR ELLA…
          assert.equal((await trx.from(CONSUMER_TABLE).where('id', id).select('note'))[0]?.note, 'revocado')
          // …y la autoridad, por la conexión del motor, todavía no ve ninguna.
          assert.isTrue(await manager.authorize(alice, 'docs:read', org), 'el revoke sin confirmar no se ve desde fuera')
          throw new Error('rollback a propósito')
        })
      } catch (error) {
        caught = error
      }
      assert.equal(caught?.message, 'rollback a propósito')
      assert.isTrue(await manager.authorize(alice, 'docs:read', org), 'ROJO: el revoke sobrevivió al rollback del consumidor')
      assert.deepEqual(await census(alice), { assignments: 1, denies: 0 }, 'censo: la asignación sigue')
      assert.equal(await note(), 'con acceso', 'la fila del consumidor sin tocar')
      const revokedEvent = events.find((e) => e.action === 'revoked')
      assert.equal(revokedEvent?.transactional, true, 'el evento de una escritura inscrita en tu transacción lleva transactional: true')
      assert.notProperty(revokedEvent, 'indeterminate')

      // Los dos o ninguno — los dos.
      await db.transaction(async (trx) => {
        await manager.revoke(alice, 'org-editor', org, { transaction: trx })
        await trx.from(CONSUMER_TABLE).where('id', id).update({ note: 'revocado' })
      })
      assert.isFalse(await manager.authorize(alice, 'docs:read', org))
      assert.deepEqual(await census(alice), { assignments: 0, denies: 0 })
      assert.equal(await note(), 'revocado')
    })

    test('grant/deny y su re-escritura DENTRO de la misma transacción se ven entre sí (un grant y su re-grant con caducidad en la misma trx ⇒ existed: true, una sola fila); rollback ⇒ cero', async ({
      assert,
    }) => {
      const { manager, tree } = worker()
      await tree.attach(org, APP_SCOPE)
      const alice = { type: 'users', uuid: uuidv7() }
      const until = new Date(Date.now() + 3_600_000)
      let outcomes: any[] = []
      try {
        await db.transaction(async (trx) => {
          outcomes.push(await manager.grant(alice, 'org-editor', org, { transaction: trx }))
          outcomes.push(await manager.grant(alice, 'org-editor', org, { transaction: trx, expiresAt: until }))
          await manager.deny(alice, 'docs:read', org, { transaction: trx })
          await manager.deny(alice, 'docs:read', org, { transaction: trx })
          const rows: any[] = await trx.from('authz_assignments').where('holder_uuid', alice.uuid).select('uuid')
          const denies: any[] = await trx.from('authz_denies').where('holder_uuid', alice.uuid).select('uuid')
          assert.lengthOf(rows, 1, 'el re-grant dentro de la trx VIO el grant de la misma trx: una fila')
          assert.lengthOf(denies, 1, 'el re-deny dentro de la trx VIO el deny de la misma trx: una fila')
          throw new Error('rollback a propósito')
        })
      } catch (error: any) {
        if (error?.message !== 'rollback a propósito') throw error
      }
      assert.deepEqual(outcomes[0], { existed: false, expiresAt: null })
      assert.equal(outcomes[1].existed, true)
      assert.equal(outcomes[1].expiresAt?.getTime(), until.getTime())
      assert.deepEqual(await census(alice), { assignments: 0, denies: 0 }, 'rollback ⇒ nada de lo escrito en la trx')
    })

    test('una transacción de OTRA conexión (real) ⇒ 500 E_AUTHZ_CONFIG nombrando las dos conexiones, cero sentencias por ella y cero filas', async ({
      assert,
    }) => {
      const { manager, tree } = worker()
      await tree.attach(org, APP_SCOPE)
      const alice = { type: 'users', uuid: uuidv7() }
      const primary = db.primaryConnectionName
      const other = `l3_otra_${Date.now().toString(36)}`
      const node: any = db.manager.get(primary)
      db.manager.add(other, { ...node.config })
      try {
        const trx = await db.connection(other).transaction()
        const spy = spyTransaction(trx)
        try {
          for (const [op, run] of [
            ['grant', () => manager.grant(alice, 'org-editor', org, { transaction: spy.transaction })],
            ['revoke', () => manager.revoke(alice, 'org-editor', org, { transaction: spy.transaction })],
            ['deny', () => manager.deny(alice, 'docs:read', org, { transaction: spy.transaction })],
            ['removeDeny', () => manager.removeDeny(alice, 'docs:read', org, { transaction: spy.transaction })],
          ] as const) {
            const error = await rejects(assert, run, 'E_AUTHZ_CONFIG', 500, op)
            assert.include(error.message, `'${other}'`, `${op}: nombra la conexión del trx`)
            assert.include(error.message, `'${primary}'`, `${op}: nombra la conexión del driver`)
            assert.include(error.message, `database.${op}`)
          }
          assert.equal(spy.statements(), 0, 'ni una sentencia por la transacción ajena')
        } finally {
          await trx.rollback()
        }
        assert.deepEqual(await census(alice), { assignments: 0, denies: 0 })
        assert.isFalse(await manager.authorize(alice, 'docs:read', org))
      } finally {
        await db.manager.close(other, true)
      }
    })

    test('transactionalWrites: false declarado en el driver (pool 1) ⇒ { transaction } es 500 E_AUTHZ_UNSUPPORTED de la puerta 1, cero sentencias; sin transaction la misma escritura entra', async ({
      assert,
    }) => {
      const { manager, driver, tree } = worker({}, { transactionalWrites: false })
      assert.equal(driver.capabilities.transactionalWrites, false)
      await tree.attach(org, APP_SCOPE)
      const alice = { type: 'users', uuid: uuidv7() }
      await db.transaction(async (trx) => {
        const spy = spyTransaction(trx)
        const error = await rejects(assert, () => manager.grant(alice, 'org-editor', org, { transaction: spy.transaction }), 'E_AUTHZ_UNSUPPORTED', 500)
        assert.include(error.message, 'transactionalWrites')
        assert.equal(spy.statements(), 0)
        // Y saltándose el manager (`manager.driver()` es la salida documentada): el driver también lo rechaza.
        const direct = await rejects(assert, () => driver.grant(alice, 'org-editor', org, { transaction: spy.transaction }), 'E_AUTHZ_UNSUPPORTED', 500)
        assert.include(direct.message, 'pool 1')
        assert.equal(spy.statements(), 0)
      })
      assert.deepEqual(await census(alice), { assignments: 0, denies: 0 })
      await manager.grant(alice, 'org-editor', org)
      assert.isTrue(await manager.authorize(alice, 'docs:read', org))
    })

    /**
     * Dos `grant` del MISMO hecho en dos transacciones externas. T1 inserta y
     * no confirma; T2 inserta lo mismo. En PG y MySQL el INSERT de T2 ESPERA en
     * el índice único a que T1 termine (es el comportamiento del motor); cuando
     * T1 confirma, T2 recibe el choque del UNIQUE — y el driver NO lo absorbe
     * como fuera de una transacción (K4): 409 `E_AUTHZ_WRITE_CONFLICT`, «haz
     * rollback y reintenta». Qué queda de T2 después es DISTINTO por motor y
     * se mide, no se supone: PG la deja ABORTADA (toda sentencia posterior es
     * `25P02` hasta el rollback); MySQL solo deshace la sentencia y T2 sigue
     * viva. SQLite (fichero, WAL) ni siquiera espera: el segundo escritor
     * muere con `SQLITE_BUSY` tras el busy-timeout SIN que T1 haya confirmado
     * (better-sqlite3 es síncrono: bloquea el event loop mientras espera, así
     * que T1 no puede confirmar), y eso es un 503 clasificado, no un 409.
     */
    test('choque del UNIQUE de dos grant concurrentes en dos transacciones externas ⇒ error CLASIFICADO (409 E_AUTHZ_WRITE_CONFLICT en PG/MySQL; 503 SQLITE_BUSY en sqlite-file) que envenena la transacción del perdedor; lo que queda de ella, medido por motor', async ({
      assert,
    }) => {
      const { manager, tree, events } = worker()
      await tree.attach(org, APP_SCOPE)
      const alice = { type: 'users', uuid: uuidv7() }
      const t1 = await db.transaction()
      const t2 = await db.transaction()
      let t2Result: { ok?: unknown; error?: any } = {}
      let alive: { alive: boolean; error?: any } = { alive: true }
      const started = Date.now()
      try {
        await manager.grant(alice, 'org-editor', org, { transaction: t1 })
        const second = manager.grant(alice, 'org-editor', org, { transaction: t2 }).then(
          (ok) => ({ ok }),
          (error) => ({ error })
        )
        // T2 está esperando en el índice único (PG/MySQL); T1 confirma.
        await new Promise((resolve) => setTimeout(resolve, 300))
        await t1.commit()
        t2Result = await second
        alive = await transactionAlive(t2)
      } finally {
        await t2.rollback().catch(() => {})
        if (!t1.isCompleted) await t1.rollback().catch(() => {})
      }
      const elapsed = Date.now() - started
      assert.isUndefined(t2Result.ok, 'ROJO: el segundo grant «entró» sobre un hecho que ya escribió otra transacción')
      const error = t2Result.error
      assert.isString(error?.code, `el error está clasificado: ${error?.message}`)
      assert.isNumber(error?.status)
      if (engine === 'sqlite-file') {
        assert.equal(error.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', `sqlite-file: SQLITE_BUSY clasificado (${error.message})`)
        assert.equal(error.status, 503)
        assert.match(String(error.cause?.code ?? error.cause?.message ?? ''), /SQLITE_BUSY/)
        assert.isTrue(alive.alive, 'sqlite-file: la transacción del perdedor sigue viva tras el BUSY')
      } else {
        assert.equal(error.code, 'E_AUTHZ_WRITE_CONFLICT', `${engine}: el UNIQUE dentro de tu transacción es 409 (${error.message})`)
        assert.equal(error.status, 409)
        assert.include(error.message, 'rollback')
        if (engine === 'pg') {
          assert.isFalse(alive.alive, 'PostgreSQL: la transacción del perdedor queda ABORTADA (25P02) hasta el rollback')
          assert.equal(alive.error?.cause?.code ?? alive.error?.code, '25P02')
        } else {
          assert.isTrue(alive.alive, 'MySQL: solo se deshace la sentencia; la transacción sigue viva')
        }
      }
      assert.isBelow(elapsed, 20_000, `el choque se resolvió en ${elapsed} ms`)
      // No es un deadline: `onWrite` NO publica un indeterminado por el perdedor.
      assert.deepEqual(
        events.map((e) => [e.action, e.transactional === true, e.indeterminate === true]),
        [['granted', true, false]],
        'un solo evento: el grant de T1 (transactional); el perdedor no publica nada'
      )
      assert.deepEqual(await census(alice), { assignments: 1, denies: 0 }, 'el censo: solo la fila de T1')
      assert.isTrue(await manager.authorize(alice, 'docs:read', org))
    }).timeout(30_000)

    /**
     * El deadline del driver vence DENTRO de la transacción del llamante (T2
     * espera en el índice único y su `timeoutMs` es de 400 ms). Lo que se
     * publica en `onWrite` (invariante 13 vs 🟡 12 del auditor): el mismo
     * `indeterminate: true` de siempre, con `transactional: true` — el
     * paquete no sabe si la sentencia aterrizó en la transacción, y confirmar
     * o no es del llamante. Y lo que queda de T2, medido: PG cancela la
     * consulta (`pg_cancel_backend`) y la transacción queda abortada; MySQL
     * la mata (`KILL QUERY`) y la transacción sigue viva; SQLite no puede
     * vencer un deadline (síncrono) y lo que sale es el BUSY de arriba.
     */
    test('deadline vencido DENTRO de la transacción externa ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT (PG/MySQL) y onWrite publica indeterminate: true + transactional: true; la transacción del llamante queda abortada en PG y viva en MySQL', async ({
      assert,
    }) => {
      const { manager, tree, events } = worker({}, { timeoutMs: 400 })
      await tree.attach(org, APP_SCOPE)
      const alice = { type: 'users', uuid: uuidv7() }
      const t1 = await db.transaction()
      const t2 = await db.transaction()
      let t2Result: { ok?: unknown; error?: any } = {}
      let alive: { alive: boolean; error?: any } = { alive: true }
      const started = Date.now()
      try {
        await manager.grant(alice, 'org-editor', org, { transaction: t1 })
        t2Result = await manager.grant(alice, 'org-editor', org, { transaction: t2 }).then(
          (ok) => ({ ok }),
          (error) => ({ error })
        )
        alive = await transactionAlive(t2)
      } finally {
        await t2.rollback().catch(() => {})
        await t1.rollback().catch(() => {})
      }
      const elapsed = Date.now() - started
      assert.isUndefined(t2Result.ok)
      const error = t2Result.error
      assert.equal(error?.status, 503, error?.message)
      if (engine === 'sqlite-file') {
        assert.equal(error.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', `sqlite-file: no hay deadline que vencer (síncrono): BUSY (${error.message})`)
        assert.isTrue(alive.alive)
        assert.deepEqual(
          events.map((e) => [e.action, e.transactional === true, e.indeterminate === true]),
          [['granted', true, false]],
          'sin deadline no hay indeterminado'
        )
      } else {
        assert.equal(error.code, 'E_AUTHZ_BACKEND_TIMEOUT', `${engine}: ${error.message}`)
        assert.isBelow(elapsed, 5_000, `el 503 llega por el deadline del driver (400 ms), no por el lock-wait del motor (${elapsed} ms)`)
        assert.deepEqual(
          events.map((e) => [e.action, e.transactional === true, e.indeterminate === true]),
          [
            ['granted', true, false],
            ['granted', true, true],
          ],
          'el deadline dentro de tu transacción publica indeterminate: true Y transactional: true'
        )
        if (engine === 'pg') {
          assert.isFalse(alive.alive, 'PostgreSQL: la consulta cancelada deja la transacción abortada')
          assert.equal(alive.error?.cause?.code ?? alive.error?.code, '25P02')
        } else {
          assert.isTrue(alive.alive, 'MySQL: KILL QUERY mata la sentencia y la transacción sigue')
        }
      }
      // Las dos hicieron rollback: nada queda.
      assert.deepEqual(await census(alice), { assignments: 0, denies: 0 })
    }).timeout(30_000)
  })
}

test.group('L-3 · { transaction } en database con pool 1 (`:memory:`): la cara honesta', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog(CATALOG)
    return cleanAuthzTables
  })

  test('pool 1 + { transaction: trx } ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT por la barrera (SU deadline, jamás un cuelgue), cero sentencias por la trx y cero filas; con pool ≥ 2 la misma escritura entra y confirma con la trx', async ({
    assert,
  }) => {
    const { manager, tree, events } = worker({ freezeTimeoutMs: 400 })
    const org = { type: 'organization', uuid: uuidv7() }
    await tree.attach(org, APP_SCOPE)
    const alice = { type: 'users', uuid: uuidv7() }
    let caught: any = null
    let statements = -1
    const started = Date.now()
    await db.transaction(async (trx) => {
      // El llamante sostiene su transacción (en `:memory:`, la ÚNICA conexión).
      await trx.from('authz_catalog_version').where('id', 1).select('id')
      const spy = spyTransaction(trx)
      try {
        await manager.grant(alice, 'org-editor', org, { transaction: spy.transaction })
      } catch (error) {
        caught = error
      }
      statements = spy.statements()
    })
    const elapsed = Date.now() - started
    if (engine === 'sqlite') {
      assert.isNotNull(caught, 'ROJO: con pool 1 la autoridad se leyó por la transacción del llamante (la escritura entró)')
      assert.equal(caught.code, 'E_AUTHZ_BACKEND_TIMEOUT')
      assert.equal(caught.status, 503)
      assert.isBelow(elapsed, 5_000, `por el deadline de la barrera (400 ms), no por el del pool (${elapsed} ms)`)
      assert.equal(statements, 0, 'la barrera cortó ANTES de la primera sentencia por la trx')
      assert.deepEqual(await census(alice), { assignments: 0, denies: 0 })
      assert.deepEqual(events, [], 'nada que auditar: no se llegó al driver')
    } else {
      assert.isNull(caught, `con pool ≥ 2 (${engine}) la barrera lee por otra conexión y la escritura entra: ${caught?.message}`)
      assert.isAbove(statements, 0, 'la escritura fue por la transacción del llamante')
      assert.deepEqual(await census(alice), { assignments: 1, denies: 0 })
      assert.isTrue(await manager.authorize(alice, 'docs:read', org))
    }
  }).timeout(20_000)
})
