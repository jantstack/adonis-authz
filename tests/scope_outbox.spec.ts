/**
 * 3b-2d — **Outbox del árbol y gate de construcción**.
 *
 * El problema está medido (panel 2, cruce 4 · S5): el paquete escribe el
 * árbol en FGA dentro de la transacción del consumidor, y un simple
 * `rollback` posterior NO deshace esa escritura. SQL dice una cosa y FGA
 * otra; en modo `facts` FGA es el PDP, así que lo que queda es una
 * **escalada persistente e invisible** (la aplicación lista y audita contra
 * SQL). No hace falta un crash ni un mal uso: el uso correcto fuga.
 *
 * La mitigación es el puerto `scopes.outbox`: el cambio de árbol se ENCOLA
 * en la misma transacción del consumidor y lo aplica después
 * `authz:scopes:relay`. Y como un puerto opcional que nadie declara no
 * mitiga nada, el driver `facts` se NIEGA a construirse sin outbox y sin
 * `acceptScopeDriftRisk: true`.
 */

import { test } from '@japa/runner'
import { OpenFgaAuthorizationDriver } from '../src/openfga.js'
import { AuthorizationManager } from '../src/manager.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import { v7 as uuidv7 } from 'uuid'
import { sqlScopeOutbox } from '../src/scope_outbox.js'
import { cleanScopeOutbox } from './helpers/schema.js'
import db from '@adonisjs/lucid/services/db'
import { readFile } from 'node:fs/promises'
import { openFgaFactsModel } from '../src/openfga.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { cleanSqlScopeTree, sqlScopeTree } from './helpers/sql_scope_tree.js'

const orgScope = () => ({ type: 'organization', uuid: uuidv7() })
const unitScope = () => ({ type: 'unit', uuid: uuidv7() })

const HOLDERS = { users: 'user' }

/** Un driver de laboratorio: la url no se usa (nada de esto llega a la red). */
function build(options: any = {}) {
  return new OpenFgaAuthorizationDriver({
    apiUrl: 'http://127.0.0.1:9',
    storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    holderTypes: HOLDERS,
    logger: { warn: () => {} },
    ...options,
  })
}

/** Una outbox de mentira: para el gate solo cuenta que ESTÉ. */
const someOutbox: any = {
  enqueue: async () => {},
  pending: async () => [],
  markApplied: async () => {},
  markFailed: async () => {},
}

async function rejects(
  assert: any,
  run: () => unknown,
  expected: { status: number; code: string },
  message?: string
): Promise<any> {
  let caught: any = null
  try {
    await run()
  } catch (error) {
    caught = error
  }
  assert.isNotNull(caught, `${message ?? 'la operación'}: debería haber lanzado`)
  assert.equal(caught.status, expected.status, message)
  assert.equal(caught.code, expected.code, message)
  return caught
}

test.group('3b-2d · el gate de construcción del driver `facts`', () => {
  test('sin outbox y sin `acceptScopeDriftRisk` el driver `facts` NO se construye: 500 E_AUTHZ_SCOPE_DRIFT_UNGUARDED', async ({
    assert,
  }) => {
    const error = await rejects(
      assert,
      () => build({ hierarchy: 'facts' }),
      { status: 500, code: 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED' },
      'facts a pelo'
    )
    assert.include(error.message, 'outbox')
    assert.include(error.message, 'acceptScopeDriftRisk')
  })

  test('con `outbox` declarada, se construye', async ({ assert }) => {
    const driver = build({ hierarchy: 'facts', outbox: someOutbox })
    assert.instanceOf(driver, OpenFgaAuthorizationDriver)
  })

  test('sin outbox pero con `acceptScopeDriftRisk: true`, se construye (el riesgo es del dueño)', async ({
    assert,
  }) => {
    const driver = build({ hierarchy: 'facts', acceptScopeDriftRisk: true })
    assert.instanceOf(driver, OpenFgaAuthorizationDriver)
  })

  test('`acceptScopeDriftRisk` tiene que ser el booleano `true` literal: nada de valores «truthy»', async ({
    assert,
  }) => {
    await rejects(
      assert,
      () => build({ hierarchy: 'facts', acceptScopeDriftRisk: 'sí' as any }),
      { status: 500, code: 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED' },
      'una cadena no es una aceptación'
    )
  })

  test('en modo `resolver` (el default) el gate no aplica: el árbol no está en el store', async ({
    assert,
  }) => {
    assert.instanceOf(build({}), OpenFgaAuthorizationDriver)
    assert.instanceOf(build({ hierarchy: 'resolver' }), OpenFgaAuthorizationDriver)
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * 3b-2e · E3 — el AGUJERO que el 2d declaró, cerrado.
 *
 * El gate del driver mira SU opción `outbox`. Pero quien encola es el
 * MANAGER, que lee `config.scopes.outbox`. Declarar la outbox solo en el
 * driver deja el gate contento y la mitigación APAGADA: `manager.scopes.*`
 * escribe en el backend dentro de la transacción del consumidor, que es
 * exactamente lo que S5 describe. El manager tiene que saber la `hierarchy`
 * del driver — que es la pieza de CAPACIDADES de este lote — y negarse.
 * ════════════════════════════════════════════════════════════════════════ */

/** El manager sobre un driver openfga real (sin red: nada de esto llega a llamar). */
function managerOverDriver(driver: any, scopes: any = {}) {
  const tree = memoryScopeTree()
  return new AuthorizationManager({
    default: 'openfga',
    drivers: { openfga: () => driver },
    holderTypes: HOLDERS,
    scopes: { resolveChain: resolveChainFrom(tree), ...scopes },
    warnOnOptInSecurity: false,
  } as any)
}

test.group('3b-2e · E3 — el gate también en el MANAGER (la outbox del driver no basta)', () => {
  test('outbox SOLO en el driver ⇒ el manager lanza 500 E_AUTHZ_SCOPE_DRIFT_UNGUARDED', async ({
    assert,
  }) => {
    // El montaje que el gate del 2d dejaba pasar: el driver se construye tan
    // contento y el manager encola… en ningún sitio.
    const driver = build({ hierarchy: 'facts', outbox: someOutbox })
    const authz = managerOverDriver(driver)
    const error = await rejects(
      assert,
      () => authz.driver(),
      { status: 500, code: 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED' },
      'la outbox del driver no es la del manager'
    )
    assert.include(error.message, 'scopes.outbox')
    // Y no es solo `driver()`: la escritura del árbol tampoco pasa.
    const org = orgScope()
    await rejects(
      assert,
      () => authz.scopes.attached(org, APP_SCOPE),
      { status: 500, code: 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED' },
      'scopes.attached'
    )
  })

  test('con la MISMA outbox en el config, el manager sí construye (y es quien encola)', async ({
    assert,
  }) => {
    const driver = build({ hierarchy: 'facts', outbox: someOutbox })
    const authz = managerOverDriver(driver, { outbox: someOutbox })
    assert.strictEqual(await authz.driver(), driver)
  })

  test('la salida explícita también existe en el config: `scopes.acceptScopeDriftRisk: true`', async ({
    assert,
  }) => {
    const driver = build({ hierarchy: 'facts', acceptScopeDriftRisk: true })
    await rejects(
      assert,
      () => managerOverDriver(driver).driver(),
      { status: 500, code: 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED' },
      'la firma del driver no firma por el manager'
    )
    const firmado = managerOverDriver(driver, { acceptScopeDriftRisk: true })
    assert.strictEqual(await firmado.driver(), driver)
  })

  test('CASO NEGATIVO: con un driver que NO declara `hierarchyFacts` el gate no aplica', async ({
    assert,
  }) => {
    // `database`, o cualquier driver de terceros cuyo árbol no viva en el
    // backend: no hay dos árboles, no hay deriva que mitigar.
    const resolver = build({ hierarchy: 'resolver' })
    assert.isFalse(resolver.capabilities.hierarchyFacts)
    assert.strictEqual(await managerOverDriver(resolver).driver(), resolver)
    const { driver: sinCapacidades } = spyDriver()
    assert.strictEqual(await managerOverDriver(sinCapacidades).driver(), sinCapacidades)
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * El PUERTO: con `scopes.outbox` declarada, `manager.scopes.*` no toca el
 * driver — ENCOLA. Es lo que hace que el cambio del árbol del consumidor y
 * su propagación al backend confirmen (o se vayan) JUNTOS.
 * ════════════════════════════════════════════════════════════════════════ */

const keyOf = (s: any) => `${s.type}:${s.uuid ?? ''}`

/** Un driver espía: registra lo que el manager le pide del árbol. */
function spyDriver() {
  const calls: string[] = []
  const driver: any = {
    authorize: async () => false,
    onScopeAttached: async (c: any, p: any) => void calls.push(`attached ${keyOf(c)} → ${keyOf(p)}`),
    onScopeMoved: async (c: any, p: any) => void calls.push(`moved ${keyOf(c)} → ${keyOf(p)}`),
    onScopeDetached: async (c: any) => void calls.push(`detached ${keyOf(c)}`),
    purgeScope: async (c: any) => void calls.push(`purgeScope ${keyOf(c)}`),
  }
  return { driver, calls }
}

/** Una outbox que solo apunta lo que le encolan. */
function recordingOutbox() {
  const enqueued: Array<{ change: any; context: any }> = []
  const outbox: any = {
    enqueue: async (change: any, context: any) => void enqueued.push({ change, context }),
    pending: async () => [],
    markApplied: async () => {},
    markFailed: async () => {},
  }
  return { outbox, enqueued }
}

/**
 * Convierte la outbox que solo APUNTA (`recordingOutbox`) en una cola de
 * verdad: `pending` lee lo encolado, `markApplied` lo saca y `markFailed` lo
 * deja donde está. Es la implementación mínima del puerto, en memoria, para
 * juzgar el relay sin base.
 */
function queueFrom(enqueued: Array<{ change: any; context: any }>, base: any) {
  const applied = new Set<number>()
  const attempts = new Map<number, number>()
  return {
    enqueue: base.enqueue,
    pending: async (limit: number) =>
      enqueued
        .map((e, index) => ({ id: index, change: e.change, actor: e.context?.actor, attempts: attempts.get(index) ?? 0 }))
        .filter((e) => !applied.has(e.id))
        .slice(0, limit),
    markApplied: async (id: number) => void applied.add(id),
    markFailed: async (id: number) => void attempts.set(id, (attempts.get(id) ?? 0) + 1),
  }
}

function managerWith(options: { tree: any; driver: any; outbox?: any; requireWithin?: any }) {
  return new AuthorizationManager({
    default: 'spy',
    drivers: { spy: () => options.driver },
    scopes: { resolveChain: resolveChainFrom(options.tree), outbox: options.outbox },
    requireWithin: options.requireWithin,
    warnOnOptInSecurity: false,
  } as any)
}

test.group('3b-2d · con outbox, `manager.scopes.*` encola en vez de escribir', () => {
  test('`attached` encola el cambio y NO toca el driver', async ({ assert }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const { driver, calls } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const manager = managerWith({ tree, driver, outbox })
    const unit = unitScope()
    await tree.attach(unit, org)

    await manager.scopes.attached(unit, org)

    assert.deepEqual(calls, [], 'el driver no se toca: la arista la aplicará el relay')
    assert.lengthOf(enqueued, 1)
    assert.deepEqual(enqueued[0].change, { op: 'attached', child: unit, parent: org })
  })

  test('`moved` encola, y con la identidad CANÓNICA del árbol (invariante 17)', async ({
    assert,
  }) => {
    const org = orgScope()
    const orgB = orgScope()
    const unit = unitScope()
    // El árbol del consumidor funde el alias sin guiones con su fila (el tipo
    // `uuid` de PG lo hace solo) y responde canónico. Lo que se encola es la
    // fila, no lo que escribió el llamante: si no, el relay abriría una rama
    // nueva en el store días después.
    const rows = new Map<string, { self: any; parent: any }>([
      [`organization|${org.uuid.replaceAll('-', '')}`, { self: org, parent: APP_SCOPE }],
      [`organization|${orgB.uuid.replaceAll('-', '')}`, { self: orgB, parent: APP_SCOPE }],
      [`unit|${unit.uuid.replaceAll('-', '')}`, { self: unit, parent: org }],
    ])
    const resolveChain = async (scope: any): Promise<any[] | null> => {
      const chain: any[] = []
      let current = scope
      for (let depth = 0; depth < 10; depth++) {
        if (current.type === 'app') return [...chain, APP_SCOPE]
        const row = rows.get(`${current.type}|${String(current.uuid).replaceAll('-', '')}`)
        if (!row) return null
        chain.push(row.self)
        current = row.parent
      }
      return null
    }
    const { driver, calls } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const manager = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => driver },
      scopes: { resolveChain, outbox },
      warnOnOptInSecurity: false,
    } as any)

    await manager.scopes.moved(
      { type: 'unit', uuid: unit.uuid.replaceAll('-', '') } as any,
      { type: 'organization', uuid: orgB.uuid.replaceAll('-', '') } as any
    )

    assert.deepEqual(calls, [])
    assert.deepEqual(enqueued[0].change, { op: 'moved', child: unit, parent: orgB })
  })

  test('`detached` encola: NO purga, NO borra la arista y NO audita todavía', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const written: any[] = []
    const manager = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => driver },
      scopes: { resolveChain: resolveChainFrom(tree), outbox },
      hooks: { onWrite: async (e: any) => void written.push(e.action) },
      warnOnOptInSecurity: false,
    } as any)

    await manager.scopes.detached(unit)

    assert.deepEqual(calls, [], 'la purga la hace el relay, no la transacción del tenant')
    assert.deepEqual(written, [], 'no se audita un `scope_purged` que todavía no ha pasado')
    assert.deepEqual(enqueued[0].change, { op: 'detached', child: unit })
  })

  test('la transacción del consumidor y el actor viajan en el contexto del encolado', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const { driver } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const manager = managerWith({ tree, driver, outbox })
    const unit = unitScope()
    await tree.attach(unit, org)
    const trx = { fake: 'transaction' }
    const actor = { type: 'users', uuid: '0192f000-0000-7000-8000-0000000000aa' }

    await manager.scopes.attached(unit, org, { actor, transaction: trx } as any)

    assert.strictEqual(enqueued[0].context.transaction, trx, 'la MISMA instancia, sin copiar')
    assert.deepEqual(enqueued[0].context.actor, actor)
  })

  test('sin outbox declarada nada cambia: el driver sigue recibiendo las tres', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const manager = managerWith({ tree, driver })

    await manager.scopes.attached(unit, org)
    await manager.scopes.moved(unit, org)
    await manager.scopes.detached(unit)

    assert.deepEqual(calls, [
      `attached ${keyOf(unit)} → ${keyOf(org)}`,
      `moved ${keyOf(unit)} → ${keyOf(org)}`,
      `purgeScope ${keyOf(unit)}`,
      `detached ${keyOf(unit)}`,
    ])
  })

  test('las validaciones van PRIMERO: un ciclo, un padre fantasma o un `within` de fuera no encolan nada', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const unit = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(unit, orgA)
    const { driver, calls } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const manager = managerWith({ tree, driver, outbox })

    await rejects(assert, () => manager.scopes.moved(orgA, unit), {
      status: 422,
      code: 'E_AUTHZ_SCOPE_CYCLE',
    })
    await rejects(assert, () => manager.scopes.moved(unit, orgScope()), {
      status: 422,
      code: 'E_AUTHZ_UNKNOWN_SCOPE',
    })
    await rejects(
      assert,
      () => manager.scopes.moved(unit, orgB, { within: orgB } as any),
      { status: 422, code: 'E_AUTHZ_NOT_WITHIN' },
      'el origen (orgA) queda fuera del within'
    )
    await rejects(assert, () => manager.scopes.attached(APP_SCOPE, orgA), {
      status: 422,
      code: 'E_AUTHZ_INVALID_IDENTITY',
    })

    assert.deepEqual(enqueued, [], 'una escritura rechazada no deja intención encolada')
    assert.deepEqual(calls, [])
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * `sqlScopeOutbox`: la implementación del puerto sobre Lucid, y el stub de
 * migración que la respalda. El paquete NO impone tabla —el puerto es el
 * contrato—, pero publicar una implementación y su migración es lo que hace
 * que la mitigación se pueda usar el mismo día.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('3b-2d · sqlScopeOutbox — el puerto sobre Lucid', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  test('encolar y relevar: los pendientes salen en ORDEN de encolado, con la identidad intacta', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox()
    const org = orgScope()
    const unit = unitScope()

    await outbox.enqueue({ op: 'attached', child: org, parent: APP_SCOPE }, {})
    await outbox.enqueue({ op: 'moved', child: unit, parent: org }, {})
    await outbox.enqueue({ op: 'detached', child: unit }, {})

    const pending = await outbox.pending(10)
    assert.deepEqual(
      pending.map((p) => p.change),
      [
        { op: 'attached', child: org, parent: APP_SCOPE },
        { op: 'moved', child: unit, parent: org },
        { op: 'detached', child: unit },
      ]
    )
    assert.deepEqual(
      pending.map((p) => p.attempts),
      [0, 0, 0]
    )
  })

  test('`markApplied` lo saca de pendientes; `markFailed` lo DEJA, con el intento y la causa a la vista', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox()
    const org = orgScope()
    await outbox.enqueue({ op: 'attached', child: org, parent: APP_SCOPE }, {})
    await outbox.enqueue({ op: 'detached', child: org }, {})
    const [first, second] = await outbox.pending(10)

    await outbox.markApplied(first.id)
    await outbox.markFailed(second.id, 'el servidor no responde')

    const left = await outbox.pending(10)
    assert.lengthOf(left, 1, 'lo aplicado no se vuelve a relevar; lo fallido sigue pendiente')
    assert.deepEqual(left[0].change, { op: 'detached', child: org })
    assert.equal(left[0].attempts, 1)
    const row: any = await db.from('authz_scope_outbox').where('id', second.id).first()
    assert.equal(row.last_error, 'el servidor no responde')
  })

  test('`pending(limit)` respeta la cota (el relay drena por lotes)', async ({ assert }) => {
    const outbox = sqlScopeOutbox()
    for (let i = 0; i < 5; i++) await outbox.enqueue({ op: 'detached', child: unitScope() }, {})
    assert.lengthOf(await outbox.pending(2), 2)
  })

  test('EL CASO: encolar en la transacción del consumidor y hacer ROLLBACK no deja intención ninguna', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox()
    const org = orgScope()
    const unit = unitScope()

    let caught: any = null
    try {
      await db.transaction(async (trx) => {
        await outbox.enqueue({ op: 'moved', child: unit, parent: org }, { transaction: trx })
        // Cualquier statement posterior que falle: una constraint, una
        // validación, un timeout de pool. No hace falta un crash.
        throw new Error('la transacción del consumidor se cae después de notificar')
      })
    } catch (error) {
      caught = error
    }

    assert.isNotNull(caught)
    assert.deepEqual(await outbox.pending(10), [], 'el encolado se fue con el rollback')
  })

  test('…y con COMMIT sí queda: la intención confirma con el cambio del árbol', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox()
    const org = orgScope()
    const unit = unitScope()

    await db.transaction(async (trx) => {
      await outbox.enqueue({ op: 'moved', child: unit, parent: org }, { transaction: trx })
    })

    const pending = await outbox.pending(10)
    assert.lengthOf(pending, 1)
    assert.deepEqual(pending[0].change, { op: 'moved', child: unit, parent: org })
  })

  test('el actor se guarda cuando llega, y sin él la fila no inventa autor', async ({ assert }) => {
    const outbox = sqlScopeOutbox()
    const actor = { type: 'users', uuid: '0192f000-0000-7000-8000-0000000000aa' }
    await outbox.enqueue({ op: 'detached', child: unitScope() }, { actor })
    await outbox.enqueue({ op: 'detached', child: unitScope() }, {})
    const rows: any[] = await db.from('authz_scope_outbox').orderBy('id', 'asc')
    assert.deepEqual([rows[0].actor_type, rows[0].actor_uuid], ['users', actor.uuid])
    assert.deepEqual([rows[1].actor_type, rows[1].actor_uuid], [null, null])
  })

  test('una identidad mal formada no entra en la cola: 422 antes del INSERT', async ({ assert }) => {
    const outbox = sqlScopeOutbox()
    await rejects(
      assert,
      () => outbox.enqueue({ op: 'detached', child: { type: 'unit', uuid: null } } as any, {}),
      { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
    )
    await rejects(
      assert,
      () => outbox.enqueue({ op: 'attached', child: unitScope(), parent: { type: 'ORG', uuid: 'x' } } as any, {}),
      { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
    )
    assert.deepEqual(await outbox.pending(10), [])
  })
})

test.group('3b-2d · el stub de la outbox y la tabla con la que se prueba coinciden', () => {
  test('la migración publicada declara `authz_scope_outbox` con las columnas que lee `sqlScopeOutbox`', async ({
    assert,
  }) => {
    const source = await readFile(new URL('../stubs/scopes_outbox_migration.stub', import.meta.url), 'utf8')
    const tableRe = /createTable\('(\w+)',\s*\(table\)\s*=>\s*\{([\s\S]*?)\n {4}\}\)/g
    const tables = new Map<string, string[]>()
    for (const [, name, body] of source.matchAll(tableRe)) {
      const columns: string[] = []
      const columnRe = /^\s*table\s*(?:\r?\n\s*)?\.(?!unique|index|primary)\w+\('(\w+)'/gm
      for (const [, column] of body.matchAll(columnRe)) columns.push(column)
      tables.set(name, columns)
    }
    assert.deepEqual([...tables.keys()], ['authz_scope_outbox'])

    const info = await db.connection().columnsInfo('authz_scope_outbox')
    for (const column of tables.get('authz_scope_outbox')!) {
      assert.property(info, column, `la columna ${column} del stub no está en la tabla del harness`)
    }
    assert.deepEqual(
      [...tables.get('authz_scope_outbox')!].sort(),
      Object.keys(info).sort(),
      'el stub y el harness declaran EXACTAMENTE las mismas columnas'
    )
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * El RELAY: quien drena la cola y aplica las aristas al driver. Reanudable
 * (si una falla, para: el orden del árbol importa) y nunca silencioso (dice
 * QUÉ aplicó, no un contador).
 * ════════════════════════════════════════════════════════════════════════ */

test.group('3b-2d · `authz:scopes:relay` — drenar la outbox contra el driver', () => {
  test('aplica en ORDEN y marca lo aplicado: attached, moved y detached (hechos primero, arista al final)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const unit = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(unit, orgA)
    const { driver, calls } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const manager = managerWith({ tree, driver, outbox: queueFrom(enqueued, outbox) })

    await manager.scopes.attached(unit, orgA)
    await tree.attach(unit, orgB)
    await manager.scopes.moved(unit, orgB)
    await manager.scopes.detached(unit)
    assert.deepEqual(calls, [], 'nada ha llegado al driver todavía')

    const report = await manager.relayScopeChanges()

    assert.deepEqual(calls, [
      `attached ${keyOf(unit)} → ${keyOf(orgA)}`,
      `moved ${keyOf(unit)} → ${keyOf(orgB)}`,
      `purgeScope ${keyOf(unit)}`,
      `detached ${keyOf(unit)}`,
    ])
    assert.deepEqual(
      report.applied.map((a) => a.change.op),
      ['attached', 'moved', 'detached']
    )
    assert.isNull(report.failed)
    assert.isFalse(report.remaining)
  })

  test('el `detached` que releva SÍ audita `scope_purged`, con el actor que lo ordenó', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const written: any[] = []
    const actor = { type: 'users', uuid: '0192f000-0000-7000-8000-0000000000aa' }
    const manager = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => driver },
      scopes: { resolveChain: resolveChainFrom(tree), outbox: queueFrom(enqueued, outbox) },
      hooks: { onWrite: async (e: any) => void written.push(e) },
      warnOnOptInSecurity: false,
    } as any)

    await manager.scopes.detached(unit, { actor } as any)
    assert.deepEqual(written, [])

    await manager.relayScopeChanges()

    assert.lengthOf(written, 1)
    assert.equal(written[0].action, 'scope_purged')
    assert.deepEqual(written[0].scope, unit)
    assert.deepEqual(written[0].actor, actor)
  })

  test('REANUDABLE: si una falla, se marca, se PARA y las siguientes siguen pendientes; la próxima pasada retoma', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const unit = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(unit, orgA)
    const { driver, calls } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const queue = queueFrom(enqueued, outbox)
    const manager = managerWith({ tree, driver, outbox: queue })

    await manager.scopes.attached(unit, orgA)
    await tree.attach(unit, orgB)
    await manager.scopes.moved(unit, orgB)
    await manager.scopes.detached(unit)

    // El servidor se cae justo en el `moved`.
    let caido = true
    driver.onScopeMoved = async (c: any, p: any) => {
      if (caido) throw new Error('el store no responde')
      calls.push(`moved ${keyOf(c)} → ${keyOf(p)}`)
    }

    const first = await manager.relayScopeChanges()
    assert.deepEqual(first.applied.map((a) => a.change.op), ['attached'])
    assert.equal(first.failed?.change.op, 'moved')
    assert.include(first.failed?.error, 'el store no responde')
    assert.isTrue(first.remaining, 'el detached NO se adelanta al moved: el orden del árbol importa')
    assert.deepEqual(calls, [`attached ${keyOf(unit)} → ${keyOf(orgA)}`])

    caido = false
    const second = await manager.relayScopeChanges()
    assert.deepEqual(second.applied.map((a) => a.change.op), ['moved', 'detached'])
    assert.isNull(second.failed)
    assert.isFalse(second.remaining)
  })

  test('`dryRun`: dice lo que aplicaría y no toca ni el driver ni la cola', async ({ assert }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const queue = queueFrom(enqueued, outbox)
    const manager = managerWith({ tree, driver, outbox: queue })
    await manager.scopes.attached(unit, org)

    const report = await manager.relayScopeChanges({ dryRun: true })

    assert.isTrue(report.dryRun)
    assert.deepEqual(report.wouldApply.map((w) => w.change.op), ['attached'])
    assert.deepEqual(report.applied, [])
    assert.deepEqual(calls, [])
    assert.isTrue(report.remaining)
  })

  test('sin `scopes.outbox` declarada, relevar es 500 E_AUTHZ_CONFIG: no hay cola que drenar', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const { driver } = spyDriver()
    const manager = managerWith({ tree, driver })
    await rejects(assert, () => manager.relayScopeChanges(), { status: 500, code: 'E_AUTHZ_CONFIG' })
  })

  test('una outbox que no marca lo aplicado NO deja al relay dando vueltas: 500 E_AUTHZ_CONFIG', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const { driver } = spyDriver()
    const rota: any = {
      enqueue: async () => {},
      // Devuelve SIEMPRE lo mismo, aplique lo que aplique el relay.
      pending: async () => [{ id: 1, change: { op: 'attached', child: org, parent: APP_SCOPE } }],
      markApplied: async () => {},
      markFailed: async () => {},
    }
    const manager = managerWith({ tree, driver, outbox: rota })
    await rejects(assert, () => manager.relayScopeChanges(), { status: 500, code: 'E_AUTHZ_CONFIG' })
  })

  test('`limit` corta la pasada y lo que queda sigue pendiente (drenar es reanudable por diseño)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const { driver } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const queue = queueFrom(enqueued, outbox)
    const manager = managerWith({ tree, driver, outbox: queue })
    for (let i = 0; i < 4; i++) {
      const unit = unitScope()
      await tree.attach(unit, org)
      await manager.scopes.attached(unit, org)
    }

    const report = await manager.relayScopeChanges({ limit: 2 })

    assert.lengthOf(report.applied, 2)
    assert.isTrue(report.remaining)
    assert.lengthOf((await manager.relayScopeChanges()).applied, 2)
  })
})

test.group('3b-2d · el comando `authz:scopes:relay` está registrado y llama al manager', () => {
  test('`commands/main.ts` lo exporta con su nombre, descripción y `startApp`', async ({ assert }) => {
    const commands: any = await import('../commands/main.js')
    const Relay = commands.AuthzScopesRelay
    assert.isFunction(Relay, 'sin esto `node ace configure` no lo registra y el comando no existe')
    assert.equal(Relay.commandName, 'authz:scopes:relay')
    assert.isString(Relay.description)
    assert.isTrue(Relay.options.startApp, 'necesita la app: el manager sale del config')
  })

  test('declara las banderas que el operador usa: --dry-run, --limit y --batch-size', async ({
    assert,
  }) => {
    const commands: any = await import('../commands/main.js')
    const nombres = (commands.AuthzScopesRelay.flags ?? []).map((f: any) => f.name ?? f.flagName)
    assert.includeMembers(nombres, ['dry-run', 'limit', 'batch-size'])
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * **LA DEMOSTRACIÓN** (panel 2, cruce 4 · S5), contra el servidor REAL y con
 * el árbol del consumidor en SQL.
 *
 * Sin outbox: una transacción del consumidor notifica el `moved`, el paquete
 * escribe la arista en FGA, la transacción hace `rollback` — y la escalada
 * se queda. SQL dice que la unit es del tenant A; FGA dice que es del B; FGA
 * es quien decide. Con outbox: el mismo guion, y no queda nada.
 * ════════════════════════════════════════════════════════════════════════ */

const openFgaTestUrl = process.env.OPENFGA_TEST_URL

if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('3b-2d · el rollback del consumidor, contra el servidor real', (group) => {
    const stores: string[] = []
    group.each.setup(async () => {
      await cleanSqlScopeTree(db)
      await cleanScopeOutbox(db)
      await cleanAuthzTables()
    })
    group.each.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) {
        await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
      }
    })

    /** El cliente por el que lee el árbol del consumidor: `db`, o la trx viva. */
    let activeClient: any = null
    const treeClient = () => activeClient ?? db
    /** Corre el cuerpo con el árbol leyendo POR la transacción (ver `chainOf`). */
    async function inTransaction(body: (trx: any) => Promise<void>): Promise<unknown> {
      try {
        await db.transaction(async (trx) => {
          activeClient = trx
          try {
            await body(trx)
          } finally {
            activeClient = null
          }
        })
        return null
      } catch (error) {
        activeClient = null
        return error
      }
    }

    const HOLDERS_FGA = { users: 'user', admins: 'admin', integrations: 'integration' }
    const PERMS = ['docs:read', 'docs:write']

    /**
     * Un mundo completo: store real con el modelo (c2), catálogo
     * sincronizado con su proyección, árbol del consumidor en `demo_scopes`
     * (orgA, orgB y una unit bajo orgA) y sus aristas ya en el store.
     */
    async function world(options: { outbox?: any } = {}) {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({
        name: `outbox-rollback-${Date.now()}-${stores.length}`,
      })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS_FGA, PERMS)
      )
      const tree = sqlScopeTree(db)
      // El resolutor del consumidor lee por el cliente ACTIVO. En un proyecto
      // real eso es `db`; aquí hace falta poder apuntarlo a la transacción
      // porque la suite por defecto corre SQLite en memoria con pool 1/1 y
      // una lectura por fuera mientras la transacción tiene la conexión se
      // queda esperando para siempre. La semántica no cambia: el consumidor
      // notifica ANTES de recolgar su fila, así que dentro de la transacción
      // el árbol todavía dice lo mismo que dice el commit.
      const chainOf = (scope: any) => sqlScopeTree(treeClient()).chainOf(scope)
      const driver = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id,
        holderTypes: HOLDERS_FGA,
        resolveChain: chainOf,
        hierarchy: 'facts',
        // Sin outbox el driver `facts` NO se construye (el gate de esta
        // misma pieza): este montaje es EXACTAMENTE el que el gate rechaza,
        // y aquí se firma a propósito para poder enseñar lo que pasa.
        outbox: options.outbox,
        acceptScopeDriftRisk: options.outbox ? undefined : true,
        // Desde 3b-2e · E1, `scopes.moved` en `facts` CONSULTA EL CATÁLOGO
        // (para saber qué roles son locales y barrer sus aristas). Sin
        // outbox eso pasa DENTRO de la transacción del consumidor, y este
        // montaje corre por defecto sobre SQLite en memoria con pool 1/1:
        // una lectura por fuera mientras la transacción tiene la única
        // conexión se queda esperando para siempre. Con la ventana, el memo
        // ya cargado responde sin SQL. Es una razón MÁS para la outbox, que
        // es el camino soportado: con ella el driver no se toca dentro de la
        // transacción.
        catalogRevalidate: { everyMs: 60_000 },
        logger: { warn: () => {} },
      })
      await syncAuthzCatalog(
        {
          permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
          roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] }],
        },
        { projection: driver.catalogProjection() }
      )
      const orgA = orgScope()
      const orgB = orgScope()
      const unit = unitScope()
      await tree.attach(orgA, APP_SCOPE)
      await tree.attach(orgB, APP_SCOPE)
      await tree.attach(unit, orgA)
      await driver.onScopeAttached(orgA, APP_SCOPE)
      await driver.onScopeAttached(orgB, APP_SCOPE)
      await driver.onScopeAttached(unit, orgA)

      const manager = new AuthorizationManager({
        default: 'openfga',
        drivers: { openfga: () => driver },
        holderTypes: HOLDERS_FGA,
        // 3b-2e · E3: el gate del MANAGER pide la outbox (o la firma) en el
        // CONFIG, no en el driver. Este montaje es justo el que se rechaza, y
        // aquí se firma a propósito para poder enseñar lo que pasa sin ella.
        scopes: {
          resolveChain: chainOf,
          outbox: options.outbox,
          ...(options.outbox ? {} : { acceptScopeDriftRisk: true }),
        },
        warnOnOptInSecurity: false,
      } as any)

      // Un holder del tenant B, con docs:read en SU organización y en ningún
      // sitio más.
      const holderB = { type: 'users', uuid: '0192f000-0000-7000-8000-00000000000b' }
      await manager.grant(holderB, 'org-editor', orgB, { expiresAt: null })

      return { driver, manager, tree, orgA, orgB, unit, holderB }
    }

    /** El padre de la unit según la BASE del consumidor. */
    const parentInSql = async (unit: any) => {
      const row: any = await db.from('demo_scopes').where('uuid', unit.uuid).first()
      return row?.parent_uuid ?? null
    }

    test('SIN outbox: el rollback deja una escalada PERSISTENTE que la base del consumidor no puede ver', async ({
      assert,
    }) => {
      const { manager, orgA, orgB, unit, holderB } = await world()

      assert.isFalse(
        await manager.authorize(holderB, 'docs:read', unit),
        'de partida: el editor de la org B no alcanza una unit de la org A'
      )

      const caught = await inTransaction(async (trx) => {
        // El consumidor notifica ANTES de recolgar su fila (es lo que el
        // paquete documenta para poder contrastar el `within` de origen).
        await manager.scopes.moved(unit, orgB)
        await trx.from('demo_scopes').where('uuid', unit.uuid).update({ parent_uuid: orgB.uuid })
        // Y algo posterior falla: una constraint, una validación, un timeout
        // de pool. No hace falta un crash.
        throw new Error('la transacción del consumidor se cae después de notificar')
      })
      assert.isNotNull(caught)

      // La base del consumidor está INTACTA: la unit sigue siendo del tenant A.
      assert.equal(await parentInSql(unit), orgA.uuid, 'el rollback deshizo el movimiento en SQL')

      // FGA no. Y FGA es el PDP.
      assert.isTrue(
        await manager.authorize(holderB, 'docs:read', unit),
        'ESCALADA: el editor del tenant B autoriza sobre una unit que en SQL es del tenant A, ' +
          'y ninguna consulta a la base del consumidor puede enseñarlo'
      )
    }).timeout(30_000)

    test('CON outbox: el mismo guion, y del rollback no queda ni la intención', async ({ assert }) => {
      const outbox = sqlScopeOutbox()
      const { manager, orgA, orgB, unit, holderB } = await world({ outbox })

      assert.isFalse(await manager.authorize(holderB, 'docs:read', unit), 'de partida')

      const caught = await inTransaction(async (trx) => {
        await manager.scopes.moved(unit, orgB, { transaction: trx } as any)
        await trx.from('demo_scopes').where('uuid', unit.uuid).update({ parent_uuid: orgB.uuid })
        throw new Error('la transacción del consumidor se cae después de notificar')
      })
      assert.isNotNull(caught)

      assert.equal(await parentInSql(unit), orgA.uuid, 'SQL sigue diciendo tenant A')
      assert.deepEqual(await outbox.pending(10), [], 'el encolado se fue con el rollback')

      const report = await manager.relayScopeChanges()
      assert.deepEqual(report.applied, [], 'no hay nada que propagar')

      assert.isFalse(
        await manager.authorize(holderB, 'docs:read', unit),
        'SIN ESCALADA: el árbol de FGA sigue siendo el que la base del consumidor confirma'
      )
    }).timeout(30_000)

    test('CON outbox y COMMIT: el relay propaga y las dos versiones del árbol vuelven a coincidir', async ({
      assert,
    }) => {
      const outbox = sqlScopeOutbox()
      const { manager, orgB, unit, holderB } = await world({ outbox })

      assert.isNull(
        await inTransaction(async (trx) => {
          await manager.scopes.moved(unit, orgB, { transaction: trx } as any)
          await trx.from('demo_scopes').where('uuid', unit.uuid).update({ parent_uuid: orgB.uuid })
        })
      )

      assert.equal(await parentInSql(unit), orgB.uuid, 'SQL ya dice tenant B')
      // **El lag del relay, medido aquí**: entre el commit y la pasada, FGA
      // decide con el árbol VIEJO. Para `moved` eso es fail-open del lado
      // del tenant ANTIGUO (aquí, todavía denegando al nuevo). Es el riesgo
      // 🟠 aceptado, y esto es su forma exacta.
      assert.isFalse(
        await manager.authorize(holderB, 'docs:read', unit),
        'durante el lag del relay FGA todavía responde con el árbol viejo'
      )

      const report = await manager.relayScopeChanges()
      assert.deepEqual(
        report.applied.map((a: any) => a.change.op),
        ['moved']
      )
      assert.isTrue(
        await manager.authorize(holderB, 'docs:read', unit),
        'aplicado el relay, FGA y SQL dicen lo mismo'
      )
    }).timeout(30_000)
  })
}

test.group('3b-2d · el README dice el riesgo con SUS palabras', () => {
  /**
   * El dueño lo pidió literal, y con razón: el documento que este paquete
   * sustituye vendía esto como «cambios del árbol fuera del servicio», es
   * decir, mal uso. El hallazgo es que el USO CORRECTO fuga. Un test es lo
   * único que impide que la frase se suavice en la próxima pasada de estilo.
   */
  test('el lag del relay va escrito como fail-open TEMPORAL, con las dos direcciones nombradas', async ({
    assert,
  }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, 'seconds during which FGA decides with the old tree')
    assert.include(readme, 'temporary fail-open')
    assert.include(readme, 'old tenant keeps access')
    assert.include(readme, 'inherited denies do not apply')
    assert.include(readme, 'persistent escalation your own database cannot show you')
    assert.include(readme, 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED')
  })
})
