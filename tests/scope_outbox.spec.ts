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
/*
 * Plan 2.5 · lote B · B6: `sqlScopeOutbox` exige `{ transaction }` POR DEFECTO desde 2.5.0. Este spec juzga la
 * mecánica de la cola (aparcado, requeue, lease, sondas, edad…), no la unidad de trabajo del llamante, así que
 * construye sus outboxes con el opt-out EXPLÍCITO (`requireTransaction: false`) — la medida del flip, documentada en
 * el informe del lote: 56 de 148 casos de este spec encolaban sin transacción. Los casos que juzgan la opción
 * (`alpha.8 · T`) usan el default o `true` a propósito.
 */
import { OpenFgaAuthorizationDriver } from '../src/openfga.js'
import { AuthorizationManager, RELAY_LEASE_POLL_MS } from '../src/manager.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import { v7 as uuidv7 } from 'uuid'
import { scopeOutboxLockNames, sqlScopeOutbox } from '../src/scope_outbox.js'
import { AuthorizationBackendError } from '../src/errors.js'
import { isNonCanonicalUuid, pgFusedSpellings } from '../src/identity.js'
import { cleanScopeOutbox } from './helpers/schema.js'
import db from '@adonisjs/lucid/services/db'
import { readFile } from 'node:fs/promises'
import { openFgaFactsModel } from '../src/openfga.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { cleanSqlScopeTree, sqlScopeTree } from './helpers/sql_scope_tree.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { testEngine } from './helpers/app.js'
import { TEST_MODEL_ID, generatedModel, serveGeneratedModel, serveModel } from './helpers/fga_model.js'

/**
 * Las banderas PÚBLICAS de un comando (`--dry-run`, `--batch-size`…). Es
 * `flagName`, nunca `name`: en ace `name` es el nombre de la **propiedad** del
 * comando y `flagName` el de la bandera (2.4.0-alpha.9 · lote A). Hasta alpha.8
 * estos casos leían `name` y pasaban en verde porque el paquete pasaba
 * `name: 'dry-run'` en las opciones —que era justo el defecto: la propiedad
 * tipada nunca recibía el valor y la bandera era INERTE—.
 */
const flagNamesOf = (Command: any): string[] => (Command.flags ?? []).map((f: any) => f.flagName)

const orgScope = () => ({ type: 'organization', uuid: uuidv7() })
const unitScope = () => ({ type: 'unit', uuid: uuidv7() })

const HOLDERS = { users: 'user' }

/** Un driver de laboratorio: la url no se usa (nada de esto llega a la red). */
function build(options: any = {}) {
  return serveGeneratedModel(new OpenFgaAuthorizationDriver({
    apiUrl: 'http://127.0.0.1:9',
    storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    modelId: TEST_MODEL_ID,
    holderTypes: HOLDERS,
    logger: { warn: () => {} },
    ...options,
  }), HOLDERS)
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
      () => build({}),
      { status: 500, code: 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED' },
      'facts a pelo'
    )
    assert.include(error.message, 'outbox')
    assert.include(error.message, 'acceptScopeDriftRisk')
  })

  test('con `outbox` declarada, se construye', async ({ assert }) => {
    const driver = build({ outbox: someOutbox })
    assert.instanceOf(driver, OpenFgaAuthorizationDriver)
  })

  test('sin outbox pero con `acceptScopeDriftRisk: true`, se construye (el riesgo es del dueño)', async ({
    assert,
  }) => {
    const driver = build({ acceptScopeDriftRisk: true })
    assert.instanceOf(driver, OpenFgaAuthorizationDriver)
  })

  test('`acceptScopeDriftRisk` tiene que ser el booleano `true` literal: nada de valores «truthy»', async ({
    assert,
  }) => {
    await rejects(
      assert,
      () => build({ acceptScopeDriftRisk: 'sí' as any }),
      { status: 500, code: 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED' },
      'una cadena no es una aceptación'
    )
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
    const driver = build({ outbox: someOutbox })
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
    const driver = build({ outbox: someOutbox })
    const authz = managerOverDriver(driver, { outbox: someOutbox })
    assert.strictEqual(await authz.driver(), driver)
  })

  test('la salida explícita también existe en el config: `scopes.acceptScopeDriftRisk: true`', async ({
    assert,
  }) => {
    const driver = build({ acceptScopeDriftRisk: true })
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
    // backend: no hay dos árboles, no hay deriva que mitigar. (Hasta 3b-2k
    // esta cara la daba también `openfga` en modo `resolver`; ese modo ya no
    // existe y el driver declara SIEMPRE `hierarchyFacts: true`.)
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

function managerWith(options: { tree: any; driver: any; outbox?: any; requireWithin?: any; clock?: () => Date }) {
  return new AuthorizationManager({
    default: 'spy',
    drivers: { spy: () => options.driver },
    scopes: { resolveChain: resolveChainFrom(options.tree), outbox: options.outbox },
    requireWithin: options.requireWithin,
    warnOnOptInSecurity: false,
    ...(options.clock === undefined ? {} : { clock: options.clock }),
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
    const outbox = sqlScopeOutbox({ requireTransaction: false })
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
    const outbox = sqlScopeOutbox({ requireTransaction: false })
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
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    for (let i = 0; i < 5; i++) await outbox.enqueue({ op: 'detached', child: unitScope() }, {})
    assert.lengthOf(await outbox.pending(2), 2)
  })

  test('EL CASO: encolar en la transacción del consumidor y hacer ROLLBACK no deja intención ninguna', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox({ requireTransaction: false })
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
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const org = orgScope()
    const unit = unitScope()

    await db.transaction(async (trx) => {
      await outbox.enqueue({ op: 'moved', child: unit, parent: org }, { transaction: trx })
    })

    const pending = await outbox.pending(10)
    assert.lengthOf(pending, 1)
    assert.deepEqual(pending[0].change, { op: 'moved', child: unit, parent: org })
  })

  /**
   * L-1 · 🟠 9 (auditor del panel `{trx}`): con un `trx` la conexión con
   * nombre se IGNORABA en silencio (`on()` devolvía el `trx` tal cual), así
   * que el encolado caía en la base del llamante — si allí existe la tabla
   * (una migración copiada, un entorno clonado), la fila queda donde NINGÚN
   * relay lee y ni siquiera sale en `dead()`. Y `db` entero pasaba el
   * duck-check (`.from`/`.table`) y escribía FUERA de toda transacción, en
   * silencio: la mitigación entera desactivada sin un solo aviso.
   */
  test('L-1 · 🟠 9 · un `trx` de OTRA conexión ⇒ 500 E_AUTHZ_CONFIG nombrando las dos conexiones, y no encola en ninguna', async ({
    assert,
  }) => {
    const primary = db.primaryConnectionName
    const other = `l1_otra_${Date.now().toString(36)}`
    const node: any = db.manager.get(primary)
    db.manager.add(other, { ...node.config })
    const org = orgScope()
    const unit = unitScope()
    try {
      // La cola vive en la conexión primaria; el llamante pasa la trx de OTRA.
      const outbox = sqlScopeOutbox({ requireTransaction: false })
      const trx = await db.connection(other).transaction()
      try {
        const error = await rejects(
          assert,
          () => outbox.enqueue({ op: 'moved', child: unit, parent: org }, { transaction: trx }),
          { status: 500, code: 'E_AUTHZ_CONFIG' },
          'ROJO: el trx de otra conexión se aceptó y el encolado se fue a la base equivocada'
        )
        assert.include(error.message, `'${other}'`, 'nombra la conexión del trx')
        assert.include(error.message, `'${primary}'`, 'nombra la conexión de la cola')
      } finally {
        await trx.rollback()
      }
      assert.deepEqual(await outbox.pending(10), [], 'nada encolado en la primaria')

      // Y al revés: la cola declara la conexión con nombre y el llamante pasa
      // la trx de la primaria (el montaje exacto del auditor).
      const named = sqlScopeOutbox({ requireTransaction: false, connection: other })
      await db.transaction(async (primaryTrx) => {
        const error = await rejects(
          assert,
          () => named.enqueue({ op: 'moved', child: unit, parent: org }, { transaction: primaryTrx }),
          { status: 500, code: 'E_AUTHZ_CONFIG' },
          'ROJO: la conexión con nombre se ignoró y el encolado cayó en la base del llamante'
        )
        assert.include(error.message, `'${other}'`)
        assert.include(error.message, `'${primary}'`)
      })
      assert.deepEqual(await outbox.pending(10), [], 'la primaria sigue sin filas: no se escribió «donde ningún relay lee»')
    } finally {
      await db.manager.close(other, true)
    }
  })

  test('L-1 · 🟠 9 · pasar `db` entero (o un cliente que no es transacción) como `transaction` ⇒ 500 E_AUTHZ_CONFIG, y NADA se escribe', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const org = orgScope()
    const unit = unitScope()
    // `db` tiene `.from()`/`.table()`: hasta L-1 pasaba el duck-check y el
    // INSERT se confirmaba solo, fuera de la transacción del consumidor.
    const whole = await rejects(
      assert,
      () => outbox.enqueue({ op: 'moved', child: unit, parent: org }, { transaction: db }),
      { status: 500, code: 'E_AUTHZ_CONFIG' },
      'ROJO: `db` entero pasó por transacción y el encolado se escribió fuera de toda transacción, en silencio'
    )
    assert.include(whole.message, 'db.transaction()')
    // Un QueryClient (`db.connection()`) tampoco es una transacción abierta.
    await rejects(
      assert,
      () => outbox.enqueue({ op: 'moved', child: unit, parent: org }, { transaction: db.connection() }),
      { status: 500, code: 'E_AUTHZ_CONFIG' },
      'un cliente de consulta no es una transacción'
    )
    assert.deepEqual(await outbox.pending(10), [], 'ninguna de las dos escribió')
    // El control: la transacción de la conexión de la cola sí encola.
    await db.transaction(async (trx) => {
      await outbox.enqueue({ op: 'moved', child: unit, parent: org }, { transaction: trx })
    })
    assert.lengthOf(await outbox.pending(10), 1)
  })

  test('el actor se guarda cuando llega, y sin él la fila no inventa autor', async ({ assert }) => {
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const actor = { type: 'users', uuid: '0192f000-0000-7000-8000-0000000000aa' }
    await outbox.enqueue({ op: 'detached', child: unitScope() }, { actor })
    await outbox.enqueue({ op: 'detached', child: unitScope() }, {})
    const rows: any[] = await db.from('authz_scope_outbox').orderBy('id', 'asc')
    assert.deepEqual([rows[0].actor_type, rows[0].actor_uuid], ['users', actor.uuid])
    assert.deepEqual([rows[1].actor_type, rows[1].actor_uuid], [null, null])
  })

  test('una identidad mal formada no entra en la cola: 422 antes del INSERT', async ({ assert }) => {
    const outbox = sqlScopeOutbox({ requireTransaction: false })
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
 * (lo que falla APLAZA lo que depende de ello —el orden del árbol importa— y
 * deja pasar el resto, 3b-2h · 🔴 2) y nunca silencioso (dice QUÉ aplicó, no
 * un contador).
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
    const nombres = flagNamesOf(commands.AuthzScopesRelay)
    assert.includeMembers(nombres, ['dry-run', 'limit', 'batch-size'])
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * **3b-2h** — las tres correcciones del auditor R2 sobre la COMPOSICIÓN de
 * la outbox (`fase-3b-auditor-r2.md`, hallazgos 🔴 2, 🟠 3 y 🟠 4). Cada una
 * está derivada de SU reproducción, y las tres se vuelven a medir contra el
 * servidor real más abajo.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('3b-2h · 🔴 2 — una entrada envenenada ya no congela la cola de todos', () => {
  /**
   * La reproducción del auditor, pieza a pieza: `attached(C, P)` encolado y
   * `P` borrado del árbol del consumidor ANTES del relevo. Al relevar, la
   * entrada no se puede validar (en el driver de verdad es 422
   * `E_AUTHZ_UNKNOWN_SCOPE`; aquí el espía lo simula, y el caso contra el
   * `:8101` lo enseña de verdad). Hasta 3b-2h eso PARABA la pasada, y como
   * `pending()` ordena por id, la envenenada era la cabecera de la cola en
   * todas las pasadas siguientes: ningún cambio del árbol, de NINGÚN tenant,
   * volvía a llegar al store.
   */
  test('EL CASO: la entrada irreparable falla, APLAZA lo que depende de ella y el resto de la cola avanza', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const padre = orgScope()
    const hijo = unitScope()
    const otra = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(padre, orgA)
    await tree.attach(hijo, padre)
    const { driver, calls } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const manager = managerWith({ tree, driver, outbox: queueFrom(enqueued, outbox) })

    await manager.scopes.attached(padre, orgA)
    await manager.scopes.attached(hijo, padre)
    await manager.scopes.detached(padre)
    await tree.detach(padre)
    // Otro tenant, detrás en la cola y sin nada que ver con el tapón.
    await tree.attach(otra, orgB)
    await manager.scopes.attached(otra, orgB)

    // Al relevar, la arista del hijo ya no se puede validar: su padre no existe.
    const attachedOk = driver.onScopeAttached
    driver.onScopeAttached = async (c: any, p: any) => {
      if (keyOf(p) === keyOf(padre)) throw new Error(`El scope ${keyOf(p)} no existe para el resolutor de la cadena`)
      await attachedOk(c, p)
    }

    const report = await manager.relayScopeChanges()

    assert.deepEqual(
      report.applied.map((a: any) => `${a.change.op} ${keyOf(a.change.child)}`),
      [`attached ${keyOf(padre)}`, `attached ${keyOf(otra)}`],
      'el tenant de al lado NO se queda sin propagar por el tapón del otro'
    )
    assert.lengthOf(report.failures, 1)
    assert.equal(keyOf(report.failures[0].change.child), keyOf(hijo))
    assert.deepEqual(report.failed, report.failures[0], '`failed` sigue siendo el primero que falló')
    assert.deepEqual(
      report.deferred.map((d: any) => `${d.change.op} ${keyOf(d.change.child)}`),
      [`detached ${keyOf(padre)}`],
      'lo que TOCA el scope del fallo no se adelanta: el orden del árbol importa'
    )
    assert.include(calls, `attached ${keyOf(otra)} → ${keyOf(orgB)}`)
    assert.notInclude(calls.join(' | '), `purgeScope ${keyOf(padre)}`)
    assert.isTrue(report.remaining)
  })

  /**
   * La contaminación es TRANSITIVA: lo aplazado contamina a su vez, así que
   * un cambio que depende de otro aplazado tampoco se adelanta.
   */
  test('la dependencia es transitiva: lo que depende de un APLAZADO también se aplaza', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const padre = orgScope()
    const hijo = unitScope()
    const nieto = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(padre, org)
    await tree.attach(hijo, padre)
    await tree.attach(nieto, hijo)
    const { driver } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const manager = managerWith({ tree, driver, outbox: queueFrom(enqueued, outbox) })

    await manager.scopes.attached(padre, org)
    await manager.scopes.attached(hijo, padre)
    await manager.scopes.attached(nieto, hijo)

    driver.onScopeAttached = async (_c: any, p: any) => {
      if (keyOf(p) === keyOf(padre)) throw new Error('el padre ya no existe')
    }

    const report = await manager.relayScopeChanges()

    assert.deepEqual(report.applied.map((a: any) => keyOf(a.change.child)), [keyOf(padre)])
    assert.deepEqual(report.failures.map((f: any) => keyOf(f.change.child)), [keyOf(hijo)])
    assert.deepEqual(
      report.deferred.map((d: any) => keyOf(d.change.child)),
      [keyOf(nieto)],
      'el nieto cuelga del hijo, que quedó sin aplicar: no se adelanta'
    )
  })

  /**
   * **La transitividad de VERDAD** (tester Fase 3b · M9). El caso de arriba
   * llega hasta el primer eslabón: el nieto se aplaza porque toca al `hijo`,
   * que **FALLÓ**, y las claves de un fallo las contamina la rama del `catch`.
   * Lo que CLAUDE.md afirma —«la contaminación va por clave de scope y es
   * TRANSITIVA»— es que **lo APLAZADO contamina a su vez**, y eso lo decide
   * otra rama (la del `collision`). Con un eslabón más se separan:
   *
   *   attached(padre,org)      → aplica
   *   attached(hijo,padre)     → FALLA        (contamina `hijo` y `padre`)
   *   attached(nieto,hijo)     → aplazado     (toca `hijo`)
   *   attached(bisnieto,nieto) → **aplazado** (toca `nieto`, que quedó APLAZADO)
   *
   * Sin la línea `for (const key of keys) blocked.add(key)` de la rama de
   * colisión, el bisnieto se ADELANTA: se cuelga en el store de un `nieto`
   * que nunca se escribió, y el orden del árbol —lo único que la contaminación
   * defiende— se rompe. La suite entera pasaba con esa línea borrada.
   */
  test('la transitividad llega al SEGUNDO eslabón: lo que depende de un APLAZADO (no de un fallo) también se aplaza', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const padre = orgScope()
    const hijo = unitScope()
    const nieto = unitScope()
    const bisnieto = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(padre, org)
    await tree.attach(hijo, padre)
    await tree.attach(nieto, hijo)
    await tree.attach(bisnieto, nieto)
    const { driver, calls } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const manager = managerWith({ tree, driver, outbox: queueFrom(enqueued, outbox) })

    await manager.scopes.attached(padre, org)
    await manager.scopes.attached(hijo, padre)
    await manager.scopes.attached(nieto, hijo)
    await manager.scopes.attached(bisnieto, nieto)

    driver.onScopeAttached = async (_c: any, p: any) => {
      if (keyOf(p) === keyOf(padre)) throw new Error('el padre ya no existe')
    }

    const report = await manager.relayScopeChanges()

    assert.deepEqual(report.applied.map((a: any) => keyOf(a.change.child)), [keyOf(padre)])
    assert.deepEqual(report.failures.map((f: any) => keyOf(f.change.child)), [keyOf(hijo)])
    assert.deepEqual(
      report.deferred.map((d: any) => keyOf(d.change.child)),
      [keyOf(nieto), keyOf(bisnieto)],
      'el bisnieto depende del nieto, que quedó APLAZADO: tampoco se adelanta'
    )
    assert.notInclude(
      calls.join(' | '),
      `attached ${keyOf(bisnieto)}`,
      'y no llegó al driver: colgarlo de un nieto que no se escribió es el desorden que la contaminación evita'
    )
    assert.isTrue(report.remaining)
  })

  test('un fallo NO contamina a quien no comparte ningún scope con él', async ({ assert }) => {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const uA = unitScope()
    const uB = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(uA, orgA)
    await tree.attach(uB, orgB)
    const { driver } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const manager = managerWith({ tree, driver, outbox: queueFrom(enqueued, outbox) })
    await manager.scopes.attached(uA, orgA)
    await manager.scopes.attached(uB, orgB)
    await manager.scopes.detached(uB)

    driver.onScopeAttached = async (c: any) => {
      if (keyOf(c) === keyOf(uA)) throw new Error('el store no responde para esta unit')
    }

    const report = await manager.relayScopeChanges()

    assert.deepEqual(report.failures.map((f: any) => keyOf(f.change.child)), [keyOf(uA)])
    assert.deepEqual(report.deferred, [])
    assert.deepEqual(
      report.applied.map((a: any) => `${a.change.op} ${keyOf(a.change.child)}`),
      [`attached ${keyOf(uB)}`, `detached ${keyOf(uB)}`]
    )
  })
})

test.group('3b-2h · 🔴 2 — la cola convergiendo: paginación, aparcado y desbloqueo', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  test('`pending(limit, after)` continúa DESPUÉS de un id: sin eso, lo saltado volvería a salir el primero', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const uno = unitScope()
    const dos = unitScope()
    await outbox.enqueue({ op: 'detached', child: uno }, {})
    await outbox.enqueue({ op: 'detached', child: dos }, {})
    const [first] = await outbox.pending(10)

    const rest = await outbox.pending(10, first.id)

    assert.deepEqual(rest.map((r) => r.change), [{ op: 'detached', child: dos }])
    assert.lengthOf(await outbox.pending(10), 2, 'sin `after` sigue saliendo la cola entera')
  })

  test('una entrada que agota `maxAttempts` sale de `pending()` y aparece en `dead()`, con su causa', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 2 })
    const unit = unitScope()
    await outbox.enqueue({ op: 'detached', child: unit }, {})
    const [item] = await outbox.pending(10)

    await outbox.markFailed(item.id, 'el padre ya no existe')
    assert.lengthOf(await outbox.pending(10), 1, 'con un intento todavía se reintenta')
    await outbox.markFailed(item.id, 'el padre ya no existe')

    assert.deepEqual(await outbox.pending(10), [], 'agotados los intentos, deja de ofrecerse')
    const dead = await outbox.dead!(10)
    assert.lengthOf(dead, 1)
    assert.deepEqual(dead[0].change, { op: 'detached', child: unit })
    assert.equal(dead[0].attempts, 2)
    assert.equal(dead[0].lastError, 'el padre ya no existe')
  })

  test('`maxAttempts` tiene que ser un entero >= 1 (config rota ⇒ 500)', async ({ assert }) => {
    await rejects(assert, () => sqlScopeOutbox({ requireTransaction: false, maxAttempts: 0 }) as any, {
      status: 500,
      code: 'E_AUTHZ_CONFIG',
    })
  })

  /**
   * **El caso 1136, DESDOBLADO** (2.4.0-alpha.5 · R2a; decisión del dueño del
   * 2026-09-09 (2)). Hasta alpha.4 este caso fijaba «aparcada la irreparable,
   * lo que dependía de ella avanza» SIN distinguir qué avanzaba. El auditor del
   * panel relay lo midió (`relay-auditor-1.ts`): con la aparcada siendo un
   * `moved` y la dependiente un `attached`, el hijo se colgaba del padre VIEJO
   * de forma PERMANENTE —la escalada que la outbox existe para evitar—. Y el
   * juez leyó la composición de ESTE caso: lo que avanzaba era una PURGA.
   *
   * Regla que queda: **lo aparcado tapona por CLAVE lo que concede o recuelga
   * (`attached`/`moved`) y deja pasar lo que retira (`detached`)** —invariante
   * 11: una purga nunca queda bloqueada, dejar denies de MÁS y no de menos—.
   * Lo aparcado sigue sin volver a `pending()` y sigue reportándose (converge).
   *
   * (a) es el caso de siempre: la purga avanza.
   */
  test('(a) aparcada la irreparable, el relay la reporta en cada pasada y el `detached` de su clave SÍ avanza (una purga nunca queda bloqueada)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const padre = orgScope()
    const hijo = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(padre, org)
    await tree.attach(hijo, padre)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 2 })
    const manager = managerWith({ tree, driver, outbox })

    await manager.scopes.attached(hijo, padre)
    await manager.scopes.detached(padre)
    await tree.detach(padre)
    driver.onScopeAttached = async (_c: any, p: any) => {
      if (keyOf(p) === keyOf(padre)) throw new Error('el padre ya no existe')
    }

    const first = await manager.relayScopeChanges()
    assert.lengthOf(first.failures, 1)
    assert.lengthOf(first.deferred, 1)
    assert.deepEqual(first.dead, [])

    const second = await manager.relayScopeChanges()
    assert.lengthOf(second.failures, 1, 'segundo intento: se agota el tope')
    assert.deepEqual(second.dead, [], 'el reporte de una pasada enseña lo aparcado ANTES de ella')

    const third = await manager.relayScopeChanges()
    assert.deepEqual(third.failures, [], 'la aparcada ya no se reintenta')
    assert.deepEqual(
      third.dead.map((d: any) => `${d.change.op} ${keyOf(d.change.child)}`),
      [`attached ${keyOf(hijo)}`],
      'pero se REPORTA: el árbol del backend queda divergente en ese nodo'
    )
    assert.deepEqual(
      third.applied.map((a: any) => `${a.change.op} ${keyOf(a.change.child)}`),
      [`detached ${keyOf(padre)}`],
      'la PURGA del padre no queda bloqueada por la aparcada que lo nombra (invariante 11)'
    )
    assert.deepEqual(third.deferred, [], 'un `detached` no se aplaza por aparcado')
    assert.include(calls, `purgeScope ${keyOf(padre)}`)
    assert.deepEqual(
      third.entries.map((e: any) => `${e.status} ${e.change.op} ${keyOf(e.change.child)}`),
      [`applied detached ${keyOf(padre)}`, `dead attached ${keyOf(hijo)}`],
      'el resultado por entrada nombra la purga aplicada y la aparcada'
    )

    const fourth = await manager.relayScopeChanges()
    assert.lengthOf(fourth.dead, 1, 'lo aparcado se dice en TODAS las pasadas, no una vez')
    assert.deepEqual(fourth.applied, [])
  })

  /**
   * (b) es el 🟠 4 del auditor, subido a 🔴 por el juez: la aparcada es un
   * `moved(unit → orgV2)` y detrás viene `attached(child, unit)`. Hasta alpha.4
   * el `attached` se aplicaba SIN su `moved` y el store se quedaba con
   * `child → unit → orgV1` (el padre viejo) para siempre. Ahora se APLAZA, con
   * el motivo `parked:<id>`, y sigue aplazado pasada tras pasada hasta que
   * alguien mire la aparcada.
   */
  test('(b) aparcado un `moved`, el `attached` que depende de él se APLAZA con motivo `parked:<id>` y NO se aplica con el padre viejo', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgV1 = orgScope()
    const orgV2 = orgScope()
    const unit = unitScope()
    const child = unitScope()
    await tree.attach(orgV1, APP_SCOPE)
    await tree.attach(orgV2, APP_SCOPE)
    await tree.attach(unit, orgV2)
    await tree.attach(child, unit)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 2 })
    const manager = managerWith({ tree, driver, outbox })

    const { queued: [movedId] } = await manager.scopes.moved(unit, orgV2)
    await manager.scopes.attached(child, unit)
    driver.onScopeMoved = async () => {
      throw new Error('E_AUTHZ_SCOPE_TREE_DRIFT: la unit tiene dos padres en el store')
    }

    await manager.relayScopeChanges()
    await manager.relayScopeChanges()
    const third = await manager.relayScopeChanges()

    assert.deepEqual(third.dead.map((d: any) => d.id), [movedId], 'el `moved` está aparcado')
    assert.deepEqual(third.applied, [], 'el `attached` NO se aplica: se colgaría del padre viejo')
    assert.lengthOf(third.deferred, 1)
    assert.equal(keyOf(third.deferred[0].change.child), keyOf(child))
    assert.include(third.deferred[0].error!, `parked:${movedId}`, 'el motivo nombra la entrada aparcada')
    assert.include(third.deferred[0].error!, keyOf(unit).replace(':', '|'), 'y la clave compartida')
    assert.deepEqual(
      third.entries.map((e: any) => [e.status, e.reason ?? null]),
      [['deferred', `parked:${movedId}`], ['dead', third.dead[0].error ?? null]],
      'el resultado por entrada: el attached aplazado por aparcado, y la aparcada'
    )
    assert.notInclude(calls.join(' | '), `attached ${keyOf(child)}`, 'cero llamadas al driver con el hijo')
    assert.isTrue(third.remaining, 'la cola no está vacía: el attached sigue pendiente')

    const fourth = await manager.relayScopeChanges()
    assert.lengthOf(fourth.deferred, 1, 'y sigue aplazado mientras la aparcada exista: no es un incidente pasado')
    assert.deepEqual(fourth.applied, [])
  })

  test('(c) CASO NEGATIVO: una aparcada NO tapona a quien no comparte clave con ella', async ({ assert }) => {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const uA = unitScope()
    const uB = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(uA, orgA)
    await tree.attach(uB, orgB)
    const { driver } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 1 })
    const manager = managerWith({ tree, driver, outbox })
    await manager.scopes.attached(uA, orgA)
    driver.onScopeAttached = async (c: any) => {
      if (keyOf(c) === keyOf(uA)) throw new Error('irreparable')
    }
    await manager.relayScopeChanges()
    await manager.scopes.attached(uB, orgB)

    const report = await manager.relayScopeChanges()

    assert.lengthOf(report.dead, 1)
    assert.deepEqual(report.applied.map((a: any) => keyOf(a.change.child)), [keyOf(uB)], 'el otro tenant avanza')
    assert.deepEqual(report.deferred, [])
  })

  test('(d) el tapón del aparcado es TRANSITIVO: lo que depende de lo aplazado por aparcado también se aplaza', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgV1 = orgScope()
    const orgV2 = orgScope()
    const unit = unitScope()
    const child = unitScope()
    const grandchild = unitScope()
    await tree.attach(orgV1, APP_SCOPE)
    await tree.attach(orgV2, APP_SCOPE)
    await tree.attach(unit, orgV2)
    await tree.attach(child, unit)
    await tree.attach(grandchild, child)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 1 })
    const manager = managerWith({ tree, driver, outbox })
    const { queued: [movedId] } = await manager.scopes.moved(unit, orgV2)
    driver.onScopeMoved = async () => {
      throw new Error('irreparable')
    }
    await manager.relayScopeChanges()
    await manager.scopes.attached(child, unit)
    await manager.scopes.attached(grandchild, child)

    const report = await manager.relayScopeChanges()

    assert.deepEqual(report.applied, [])
    assert.deepEqual(
      report.deferred.map((d: any) => keyOf(d.change.child)),
      [keyOf(child), keyOf(grandchild)],
      'el nieto no comparte clave con la aparcada, pero sí con el hijo APLAZADO por ella'
    )
    assert.include(report.deferred[0].error!, `parked:${movedId}`)
    assert.notInclude(calls.join(' | '), 'attached', 'cero escrituras de árbol')
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * **2.4.0-alpha.5 · R2a — un 503 del backend NO consume intento** (panel
 * relay, cuestión 2; decidido por la NATURALEZA del error, no por flag).
 *
 * El auditor lo midió (`relay-auditor-1.ts`): con el store caído, CINCO
 * peticiones de otro tenant con relay inline gastaban los cinco intentos de
 * una entrada ajena y la aparcaban — y aparcar era dejar de ordenar (🟠 4).
 * `maxAttempts` existe para converger sobre lo IRREPARABLE (el padre borrado
 * no vuelve); una caída del store es común a todas las entradas y no dice
 * nada de ninguna. Forma: `markFailed(id, error, { transient })`, opcional en
 * el puerto; un tercero que lo ignore cuenta el intento = lo de hoy.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('alpha.5 · R2a — un 503 del backend no consume intento', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  /** Lo que lanza el driver `openfga` de verdad cuando el store no responde. */
  const storeDown = () => new AuthorizationBackendError('spy', 'onScopeMoved', new Error('ECONNREFUSED'))

  /**
   * La reproducción del auditor, como caso: la víctima encola `moved` (+ un
   * `attached` que depende de él); el store cae; el tenant ruidoso hace 5
   * escrituras de árbol con relay inline. Antes: `attempts` 1,2,3,4,5 ⇒
   * aparcada por tráfico ajeno. Ahora: 0 en las cinco, `last_error` escrito,
   * y al volver el store se aplica EN ORDEN (`moved` antes que `attached`).
   */
  test('EL CASO (auditor 🟠 4): cinco peticiones ajenas con el store caído NO aparcan la entrada de otro; al volver, se aplica en orden', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgV1 = orgScope()
    const orgV2 = orgScope()
    const orgA = orgScope()
    const unitV = unitScope()
    const childV = unitScope()
    await tree.attach(orgV1, APP_SCOPE)
    await tree.attach(orgV2, APP_SCOPE)
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(unitV, orgV2)
    await tree.attach(childV, unitV)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const manager = managerWith({ tree, driver, outbox })
    const { queued: [movedId] } = await manager.scopes.moved(unitV, orgV2)
    await manager.scopes.attached(childV, unitV)
    const movedOk = driver.onScopeMoved
    driver.onScopeMoved = async () => {
      throw storeDown()
    }

    const attemptsSeen: number[] = []
    for (let i = 0; i < 5; i++) {
      const u = unitScope()
      await tree.attach(u, orgA)
      await manager.scopes.attached(u, orgA)
      const report = await manager.relayScopeChanges()
      const row: any = await db.from('authz_scope_outbox').where('id', movedId).first()
      attemptsSeen.push(Number(row.attempts))
      assert.lengthOf(report.failures, 1, `petición ${i + 1}: el moved falla`)
      assert.isTrue(report.failures[0].transient, 'y el fallo se reporta como TRANSITORIO')
      assert.equal(report.entries.find((e: any) => String(e.id) === String(movedId))?.status, 'failed')
      assert.deepEqual(report.dead, [], `petición ${i + 1}: nada aparcado`)
      assert.deepEqual(report.applied.map((a: any) => keyOf(a.change.child)), [keyOf(u)], 'lo del tenant ruidoso sí avanza')
      assert.isString(row.last_error, 'nada se vuelve silencioso: la causa queda escrita')
      assert.include(row.last_error, 'no respondió')
    }
    assert.deepEqual(attemptsSeen, [0, 0, 0, 0, 0], 'un 503 no consume intento: cero en las cinco peticiones')
    assert.lengthOf(await outbox.dead!(10), 0)
    assert.lengthOf(await outbox.pending(10), 2, 'el moved y su attached siguen pendientes')

    driver.onScopeMoved = movedOk
    const after = await manager.relayScopeChanges()
    assert.deepEqual(after.applied.map((a: any) => a.change.op), ['moved', 'attached'], 'al volver el store: EN ORDEN')
    assert.deepEqual(
      calls.filter((c) => c.includes(keyOf(unitV)) || c.includes(keyOf(childV))),
      [`moved ${keyOf(unitV)} → ${keyOf(orgV2)}`, `attached ${keyOf(childV)} → ${keyOf(unitV)}`],
      'el driver ve el padre NUEVO antes que el hijo'
    )
  })

  /**
   * Con el driver `openfga` DE VERDAD contra un puerto muerto: lo que lanza
   * es `AuthorizationBackendError` (503, `maxRetry: 0`), y eso es lo que el
   * manager clasifica como transitorio. Sin espía por medio.
   */
  test('con el driver `openfga` real y el store caído (puerto muerto): el fallo es 503, `transient`, y `attempts` se queda en 0', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const tree = memoryScopeTree()
    const driver = build({ outbox, apiUrl: 'http://127.0.0.1:9', timeoutMs: 2_000, resolveChain: resolveChainFrom(tree) })
    const manager = new AuthorizationManager({
      default: 'openfga',
      drivers: { openfga: () => driver },
      holderTypes: HOLDERS,
      scopes: { resolveChain: resolveChainFrom(tree), outbox },
      warnOnOptInSecurity: false,
    } as any)
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const { queued: [id] } = await manager.scopes.attached(org, APP_SCOPE)

    const report = await manager.relayScopeChanges()

    assert.lengthOf(report.failures, 1)
    assert.isTrue(report.failures[0].transient, report.failures[0].error)
    assert.include(report.failures[0].error, 'no respondió')
    const row: any = await db.from('authz_scope_outbox').where('id', id).first()
    assert.equal(Number(row.attempts), 0)
    assert.include(String(row.last_error), 'no respondió')
    assert.deepEqual(report.dead, [])
  }).timeout(30_000)

  test('CASO NEGATIVO: un fallo de la ENTRADA (422/500, un error sin status) sí consume intento, como siempre', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 2 })
    const manager = managerWith({ tree, driver, outbox })
    const { queued: [id] } = await manager.scopes.attached(unit, org)
    driver.onScopeAttached = async () => {
      throw new Error('El scope organization:… no existe para el resolutor de la cadena')
    }

    const report = await manager.relayScopeChanges()

    assert.isFalse(report.failures[0].transient)
    const row: any = await db.from('authz_scope_outbox').where('id', id).first()
    assert.equal(Number(row.attempts), 1, 'lo irreparable sigue convergiendo hacia el aparcado')
  })

  /**
   * **Cierre de L11 · 🟠 A1 del auditor (= H1)**: adelanta de la decisión del dueño 2026-10-17 (3) SOLO esta pieza — el
   * 500 de la puerta del modelo (despliegue a medias: el modelo fijado no es el que genera la config) es TRANSITORIO para
   * el relay. Con el driver `openfga` REAL y su puerta: cinco relevos con el modelo cambiado ⇒ el `moved` y el `detached`
   * fallan con 500 `E_AUTHZ_CONFIG` (la letra de L11), `transient: true`, `attempts` 0 y `dead()` VACÍO; arreglado el
   * despliegue, la siguiente pasada los aplica. Antes del cierre se aparcaban a la quinta y el padre VIEJO seguía en el
   * store (los admins de la org vieja conservaban el acceso: fail-open PERSISTENTE hasta un `requeue` manual).
   */
  test('cierre L11 · A1: cinco relevos con el modelo CAMBIADO (puerta L11 del driver openfga real) ⇒ moved y detached fallan transitorios, `dead()` vacío; con el modelo bueno la pasada siguiente los aplica', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 5 })
    const tree = memoryScopeTree()
    const orgOld = orgScope()
    const orgNew = orgScope()
    const unit = unitScope()
    const gone = unitScope()
    await tree.attach(orgOld, APP_SCOPE)
    await tree.attach(orgNew, APP_SCOPE)
    await tree.attach(unit, orgNew)
    // Un holder con una relación de más: lo que deja un despliegue cuya config cambió antes de re-provisionar.
    const drifted = generatedModel(HOLDERS)
    drifted.type_definitions.find((t: any) => t.type === 'user').relations = { nickname: { this: {} } }
    const driver = serveModel(
      new OpenFgaAuthorizationDriver({
        apiUrl: 'http://127.0.0.1:9',
        storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
        modelId: TEST_MODEL_ID,
        holderTypes: HOLDERS,
        resolveChain: resolveChainFrom(tree),
        outbox,
        logger: { warn: () => {} },
      } as any),
      drifted
    )
    const manager = new AuthorizationManager({
      default: 'openfga',
      drivers: { openfga: () => driver },
      holderTypes: HOLDERS,
      scopes: { resolveChain: resolveChainFrom(tree), outbox },
      warnOnOptInSecurity: false,
    } as any)
    const { queued: [movedId] } = await manager.scopes.moved(unit, orgNew)
    const { queued: [detachedId] } = await manager.scopes.detached(gone)

    for (let i = 0; i < 5; i++) {
      const report = await manager.relayScopeChanges()
      assert.lengthOf(report.failures, 2, `relevo ${i + 1}: los dos fallan por la puerta`)
      for (const failure of report.failures) {
        assert.isTrue(failure.transient, `relevo ${i + 1}: la puerta del modelo es TRANSITORIA para el relay (${failure.error})`)
        // Cierre-2 de L11 (⚪ C2): el reporte dice que es DESPLIEGUE (el comando no puede imprimir «el backend no respondió»).
        assert.isTrue(failure.deployment, `relevo ${i + 1}: el fallo va marcado como DESPLIEGUE en el reporte`)
        assert.include(failure.error, 'NO es el que genera la config')
        assert.include(failure.error, 'user#nickname (relación de más)')
      }
      assert.deepEqual(report.dead, [], `relevo ${i + 1}: nada aparcado`)
    }
    for (const id of [movedId, detachedId]) {
      const row: any = await db.from('authz_scope_outbox').where('id', id).first()
      assert.equal(Number(row.attempts), 0, `#${id}: la puerta no consume intento`)
      assert.include(String(row.last_error), 'NO es el que genera la config', 'la causa queda escrita')
    }
    assert.lengthOf(await outbox.dead!(10), 0, 'dead() VACÍO tras cinco relevos')

    // Arreglado el despliegue (proceso con el modelo bueno): la pasada siguiente aplica las dos, en orden.
    const { driver: fixed, calls } = spyDriver()
    const healthy = managerWith({ tree, driver: fixed, outbox })
    const after = await healthy.relayScopeChanges()
    assert.deepEqual(after.applied.map((a: any) => a.change.op), ['moved', 'detached'])
    assert.deepEqual(calls, [`moved ${keyOf(unit)} → ${keyOf(orgNew)}`, `purgeScope ${keyOf(gone)}`, `detached ${keyOf(gone)}`])
    assert.deepEqual(after.dead, [])
  })

  test('el puerto: `markFailed(id, error, { transient: true })` escribe `last_error` y NO incrementa `attempts`', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 1 })
    const unit = unitScope()
    await outbox.enqueue({ op: 'detached', child: unit }, {})
    const [item] = await outbox.pending(10)

    await outbox.markFailed(item.id, 'el store no responde', { transient: true })

    const [again] = await outbox.pending(10)
    assert.equal(again.attempts, 0)
    assert.equal(again.lastError, 'el store no responde')
    assert.deepEqual(await outbox.dead!(10), [], 'con maxAttempts 1 un fallo contado la habría aparcado')
    await outbox.markFailed(item.id, 'el padre ya no existe')
    assert.deepEqual(await outbox.pending(10), [], 'el fallo contado sí la aparca')
  })

  test('un `ScopeOutbox` de terceros que ignora el tercer parámetro cuenta el intento (degrada hacia lo de hoy, nunca hacia lo peligroso)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const { driver } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const queue = queueFrom(enqueued, outbox)
    const manager = managerWith({ tree, driver, outbox: queue })
    await manager.scopes.attached(org, APP_SCOPE)
    driver.onScopeAttached = async () => {
      throw storeDown()
    }

    const report = await manager.relayScopeChanges()

    assert.isTrue(report.failures[0].transient, 'el manager lo clasifica igual')
    assert.equal((await queue.pending(10))[0].attempts, 1, 'pero la outbox que no sabe de transitorios lo cuenta')
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * **2.4.0-alpha.5 · R1 — el recibo del encolado y `relayScopeChanges({ only })`**
 * (panel relay, cuestión 1; veredicto D del juez, 92,5/100).
 *
 * Lo que COGNITIV pidió: saber si SU cambio aterrizó, y no pagar la cola de
 * los demás para relevarlo (medido: 4 507 ms y 2 004 llamadas a FGA con 500
 * entradas ajenas por delante; 19 ms con `only`). Lo que el auditor midió
 * (`relay-auditor-2.ts`, 🔴 1): un `only` que filtra `pending()` sin más
 * aplica `attached(child, unit)` ANTES que el `moved(unit → orgB)` del que
 * depende, y el editor de la org VIEJA autoriza sobre el hijo. La síntesis:
 * el filtro va al PUERTO (no en memoria: eso deja los 50 casos verdes sin
 * arreglar nada, tester 1b-3) **y** antes de aplicar cada entrada pedida se
 * sondea la cola ENTERA — una pendiente anterior que comparta clave ⇒
 * `deferred`, nunca fuera de orden. Un nivel basta: el último eslabón de
 * cualquier cadena de dependencias comparte clave conmigo por definición.
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * La implementación mínima del puerto de alpha.5, en memoria: recibo, filtro
 * por ids, `transient`, `dead` y —opcional— la sonda `earlierPending`. Con
 * `probe: false` es una outbox de terceros que solo sabe filtrar.
 */
function memoryQueue(options: { probe?: boolean; maxAttempts?: number; honourFilter?: boolean } = {}) {
  const rows: Array<{ change: any; actor: any }> = []
  const applied = new Set<number>()
  const attempts = new Map<number, number>()
  const max = options.maxAttempts ?? 5
  const keysOf = (change: any) =>
    change.op === 'detached' ? [keyOf(change.child)] : [keyOf(change.child), keyOf(change.parent)]
  const view = (index: number) => ({
    id: index,
    change: rows[index].change,
    actor: rows[index].actor,
    attempts: attempts.get(index) ?? 0,
    ...((attempts.get(index) ?? 0) >= max ? { lastError: 'irreparable' } : {}),
  })
  const isPending = (index: number) => !applied.has(index) && (attempts.get(index) ?? 0) < max
  const outbox: any = {
    enqueue: async (change: any, context: any) => {
      rows.push({ change, actor: context?.actor })
      return { id: rows.length - 1 }
    },
    pending: async (limit: number, after?: number, filter?: { ids: number[] }) =>
      rows
        .map((_, index) => index)
        .filter(isPending)
        .filter((index) => after === undefined || index > after)
        .filter((index) => options.honourFilter === false || filter === undefined || filter.ids.map(String).includes(String(index)))
        .slice(0, limit)
        .map(view),
    dead: async (limit: number) =>
      rows
        .map((_, index) => index)
        .filter((index) => !applied.has(index) && (attempts.get(index) ?? 0) >= max)
        .slice(0, limit)
        .map(view),
    markApplied: async (id: number) => void applied.add(id),
    markFailed: async (id: number, _error: string, o?: { transient?: boolean }) => {
      if (o?.transient !== true) attempts.set(id, (attempts.get(id) ?? 0) + 1)
    },
  }
  if (options.probe !== false) {
    outbox.earlierPending = async (id: number, scopes: any[]) => {
      const wanted = scopes.map(keyOf)
      const hit = rows
        .map((_, index) => index)
        .filter((index) => index < id && isPending(index))
        .find((index) => keysOf(rows[index].change).some((k) => wanted.includes(k)))
      return hit === undefined ? null : view(hit)
    }
  }
  return { outbox, rows, applied, attempts }
}

test.group('alpha.5 · R1 — el recibo del encolado: `scopes.*` devuelve los ids de lo que encoló', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  test('`attached`/`moved` devuelven `{ queued: [id] }` y ese id es el de la fila: el MISMO que devuelve `pending()`', async ({
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
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const manager = managerWith({ tree, driver, outbox })

    const first = await manager.scopes.attached(unit, orgA)
    const second = await manager.scopes.moved(unit, orgB)

    assert.lengthOf(first.queued, 1)
    assert.lengthOf(second.queued, 1)
    assert.notEqual(String(first.queued[0]), String(second.queued[0]))
    const row: any = await db.from('authz_scope_outbox').where('id', first.queued[0]).first()
    assert.equal(row.op, 'attached')
    assert.equal(row.child_uuid, unit.uuid)
    const pending = await outbox.pending(10)
    assert.deepEqual(pending.map((p) => String(p.id)), [String(first.queued[0]), String(second.queued[0])], 'intercambiables como clave de `only`')
    assert.deepEqual(calls, [], 'encolar sigue sin tocar el driver')
  })

  test('`detached` sin cadena y con el alias sin guiones encola DOS filas y el recibo trae los dos ids (invariante 17: plural)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const unit = unitScope()
    const { driver } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const manager = managerWith({ tree, driver, outbox })

    const receipt = await manager.scopes.detached({ type: 'unit', uuid: unit.uuid!.replaceAll('-', '') })

    assert.lengthOf(receipt.queued, 2)
    const rows = await db.from('authz_scope_outbox').whereIn('id', receipt.queued).orderBy('id', 'asc')
    assert.deepEqual(
      rows.map((r: any) => r.child_uuid),
      [unit.uuid!.replaceAll('-', ''), unit.uuid],
      'una fila por ortografía, en el orden de encolado'
    )
  })

  test('sin outbox el recibo es `{ queued: [] }`: el cambio ya se aplicó en línea, no hay nada que relevar', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const { driver, calls } = spyDriver()
    const manager = managerWith({ tree, driver })

    assert.deepEqual(await manager.scopes.attached(org, APP_SCOPE), { queued: [] })
    assert.deepEqual(await manager.scopes.detached(org), { queued: [] })
    assert.lengthOf(calls, 3, 'attached + purgeScope + detached: aplicado en línea')
  })

  test('TERCEROS: una outbox cuyo `enqueue` devuelve `void` sigue valiendo, el recibo sale vacío y con él no hay `only` (500 nombrando el porqué)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const { driver, calls } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const queue = queueFrom(enqueued, outbox)
    const manager = managerWith({ tree, driver, outbox: queue })

    const receipt = await manager.scopes.attached(org, APP_SCOPE)

    assert.deepEqual(receipt, { queued: [] }, 'nunca un id inventado')
    assert.lengthOf(enqueued, 1, 'y la cola tiene la entrada')
    const error = await rejects(assert, () => manager.relayScopeChanges({ only: receipt.queued }), {
      status: 500,
      code: 'E_AUTHZ_CONFIG',
    })
    assert.include(error.message, 'sin recibo')
    assert.deepEqual(calls, [], 'y no drenó la cola entera en silencio')
    assert.lengthOf((await manager.relayScopeChanges()).applied, 1, 'sin `only` todo sigue como hasta ahora')
  })
})

test.group('alpha.5 · R1 — `only`: solo lo mío, y nunca fuera de orden', () => {
  /** El mundo del 🔴 1: la unit pasa de A a B (`moved`) y B le cuelga un hijo (`attached`). */
  async function transfer(options: Parameters<typeof memoryQueue>[0] = {}) {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const unit = unitScope()
    const child = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(unit, orgA)
    const { driver, calls } = spyDriver()
    const q = memoryQueue(options)
    const manager = managerWith({ tree, driver, outbox: q.outbox })
    const { queued: [movedId] } = await manager.scopes.moved(unit, orgB)
    await tree.attach(unit, orgB)
    await tree.attach(child, unit)
    const { queued: [attachedId] } = await manager.scopes.attached(child, unit)
    return { tree, manager, driver, calls, q, orgA, orgB, unit, child, movedId, attachedId }
  }

  test('EL CASO (auditor 🔴 1, 1c-1): `only: [attached]` con su `moved` pendiente y no pedido ⇒ `deferred` con `depends-on:<id>`, CERO llamadas al driver', async ({
    assert,
  }) => {
    const w = await transfer()

    const report = await w.manager.relayScopeChanges({ only: [w.attachedId] })

    assert.deepEqual(report.applied, [], 'no se aplica fuera de orden')
    assert.deepEqual(w.calls, [], 'cero llamadas al driver')
    assert.lengthOf(report.deferred, 1)
    assert.equal(report.deferred[0].id, w.attachedId)
    assert.include(report.deferred[0].error!, keyOf(w.unit).replace(':', '|'), 'nombra la clave compartida')
    assert.include(report.deferred[0].error!, `#${w.movedId}`, 'y la entrada bloqueante')
    assert.deepEqual(
      report.entries.map((e: any) => [e.id, e.status, e.reason]),
      [[w.attachedId, 'deferred', `depends-on:${w.movedId}`]],
      'el resultado por entrada responde a la pregunta «¿se aplicó lo mío?»: no, y por qué'
    )
    assert.deepEqual(report.missing, [])
    assert.isTrue(report.remaining, '`remaining` es GLOBAL: la cola no está vacía')
    assert.isFalse(report.busy)
  })

  test('1c-2: `only: [moved, attached]` aplica los dos EN ORDEN de id (no en el orden del array)', async ({ assert }) => {
    const w = await transfer()

    const report = await w.manager.relayScopeChanges({ only: [w.attachedId, w.movedId] })

    assert.deepEqual(report.applied.map((a: any) => a.change.op), ['moved', 'attached'])
    assert.deepEqual(w.calls, [
      `moved ${keyOf(w.unit)} → ${keyOf(w.orgB)}`,
      `attached ${keyOf(w.child)} → ${keyOf(w.unit)}`,
    ])
    assert.deepEqual(report.deferred, [])
    assert.deepEqual(report.entries.map((e: any) => e.status), ['applied', 'applied'])
    assert.isFalse(report.remaining)
  })

  test('1c-3 (inverso): una pendiente anterior SIN clave compartida no aplaza: `only: [mío]` aplica lo mío y deja la ajena donde está', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const uA = unitScope()
    const uB = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(uA, orgA)
    await tree.attach(uB, orgB)
    const { driver, calls } = spyDriver()
    const q = memoryQueue()
    const manager = managerWith({ tree, driver, outbox: q.outbox })
    const { queued: [foreign] } = await manager.scopes.attached(uA, orgA)
    const { queued: [mine] } = await manager.scopes.attached(uB, orgB)

    const report = await manager.relayScopeChanges({ only: [mine] })

    assert.deepEqual(report.applied.map((a: any) => a.id), [mine])
    assert.deepEqual(calls, [`attached ${keyOf(uB)} → ${keyOf(orgB)}`], 'el driver solo vio lo mío')
    assert.isTrue(report.remaining, 'la ajena sigue pendiente y el reporte lo dice')
    assert.deepEqual((await q.outbox.pending(10)).map((p: any) => p.id), [foreign])
  })

  test('1c-4: `only: []` es 500 E_AUTHZ_CONFIG (nunca «drena todo»); un id que no está ni pendiente ni aparcado sale en `missing`, jamás un reporte vacío en verde', async ({
    assert,
  }) => {
    const w = await transfer()

    const error = await rejects(assert, () => w.manager.relayScopeChanges({ only: [] }), { status: 500, code: 'E_AUTHZ_CONFIG' })
    assert.include(error.message, "'only' está vacío")
    assert.deepEqual(w.calls, [], 'y no drenó nada')

    const report = await w.manager.relayScopeChanges({ only: [999] })
    assert.deepEqual(report.applied, [])
    assert.deepEqual(report.entries, [])
    assert.deepEqual(report.missing, [999], 'el id que no era se nombra')
    assert.isTrue(report.remaining)

    // Y un id ya aplicado por una pasada anterior (la receta inline con un
    // cron detrás) NO es un error: sale en `missing` también.
    await w.manager.relayScopeChanges()
    const again = await w.manager.relayScopeChanges({ only: [w.attachedId] })
    assert.deepEqual(again.missing, [w.attachedId])
    assert.deepEqual(again.applied, [])
  })

  test('1d-3 (TERCEROS): una outbox que IGNORA `filter.ids` no aplica el backlog ajeno en silencio: 500 E_AUTHZ_CONFIG nombrando el puerto, cero llamadas', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const uA = unitScope()
    const uB = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(uA, orgA)
    await tree.attach(uB, orgB)
    const { driver, calls } = spyDriver()
    const q = memoryQueue({ honourFilter: false })
    const manager = managerWith({ tree, driver, outbox: q.outbox })
    await manager.scopes.attached(uA, orgA)
    const { queued: [mine] } = await manager.scopes.attached(uB, orgB)

    const error = await rejects(assert, () => manager.relayScopeChanges({ only: [mine] }), { status: 500, code: 'E_AUTHZ_CONFIG' })

    assert.include(error.message, 'pending(limit, after, { ids })')
    assert.include(error.message, 'no honra')
    assert.deepEqual(calls, [])
    assert.lengthOf((await manager.relayScopeChanges()).applied, 2, 'sin `only` esa outbox sigue valiendo')
  })

  test('TERCEROS sin `earlierPending`: el manager sondea paginando `pending()` y el veredicto es el MISMO (aplaza lo dependiente, aplica lo independiente)', async ({
    assert,
  }) => {
    const w = await transfer({ probe: false })
    assert.isUndefined(w.q.outbox.earlierPending)

    const report = await w.manager.relayScopeChanges({ only: [w.attachedId] })
    assert.deepEqual(report.applied, [])
    assert.deepEqual(report.entries.map((e: any) => e.reason), [`depends-on:${w.movedId}`])
    assert.deepEqual(w.calls, [])

    const both = await w.manager.relayScopeChanges({ only: [w.movedId, w.attachedId] })
    assert.deepEqual(both.applied.map((a: any) => a.change.op), ['moved', 'attached'])
  })

  test('`only` sobre una entrada APARCADA la reporta como `dead` en `entries`; sobre una que falla, `failed` con la causa', async ({
    assert,
  }) => {
    const w = await transfer({ maxAttempts: 1 })
    w.driver.onScopeMoved = async () => {
      throw new Error('E_AUTHZ_SCOPE_TREE_DRIFT')
    }
    const first = await w.manager.relayScopeChanges({ only: [w.movedId] })
    assert.deepEqual(first.entries.map((e: any) => [e.status, e.reason]), [['failed', 'E_AUTHZ_SCOPE_TREE_DRIFT']])
    assert.isFalse(first.failures[0].transient)

    const second = await w.manager.relayScopeChanges({ only: [w.movedId] })
    assert.deepEqual(second.entries.map((e: any) => [e.id, e.status]), [[w.movedId, 'dead']])
    assert.deepEqual(second.missing, [], 'aparcada ≠ desaparecida')
    assert.lengthOf(second.dead, 1, '`dead` es global, con o sin `only`')

    // Y el attached que depende de la aparcada: `parked:<id>` (R2a), también con `only`.
    const third = await w.manager.relayScopeChanges({ only: [w.attachedId] })
    assert.deepEqual(third.entries.map((e: any) => [e.status, e.reason]), [['deferred', `parked:${w.movedId}`]])
  })

  test('`dryRun` + `only` lista SOLO lo pedido en `wouldApply` y no toca nada', async ({ assert }) => {
    const w = await transfer()

    const report = await w.manager.relayScopeChanges({ dryRun: true, only: [w.attachedId] })

    assert.deepEqual(report.wouldApply.map((x: any) => x.id), [w.attachedId])
    assert.deepEqual(report.missing, [])
    assert.deepEqual(w.calls, [])
    assert.isTrue(report.remaining)
  })

  test('sin `only`, `entries` también existe: una pasada con aplicado, fallo, aplazado y aparcado los nombra a todos con su motivo', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    // La aparcada vive bajo OTRA org: una aparcada tapona su clave para
    // `attached`/`moved` (R2a), y aquí lo que se juzga es la forma de `entries`.
    const orgX = orgScope()
    const padre = orgScope()
    const hijo = unitScope()
    const otra = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(orgX, APP_SCOPE)
    await tree.attach(padre, org)
    await tree.attach(hijo, padre)
    await tree.attach(otra, orgX)
    const { driver } = spyDriver()
    const q = memoryQueue({ maxAttempts: 1 })
    const manager = managerWith({ tree, driver, outbox: q.outbox })
    const { queued: [parkedId] } = await manager.scopes.attached(otra, orgX)
    driver.onScopeAttached = async (c: any) => {
      if (keyOf(c) === keyOf(otra)) throw new Error('irreparable')
      if (keyOf(c) === keyOf(padre)) throw new Error('el store no tiene ese nodo')
    }
    await manager.relayScopeChanges()
    const { queued: [padreId] } = await manager.scopes.attached(padre, org)
    const { queued: [hijoId] } = await manager.scopes.attached(hijo, padre)
    const { queued: [detachedId] } = await manager.scopes.detached(otra)

    const report = await manager.relayScopeChanges()

    assert.deepEqual(
      report.entries.map((e: any) => [e.id, e.status, e.reason ?? null]),
      [
        [padreId, 'failed', 'el store no tiene ese nodo'],
        [hijoId, 'deferred', `depends-on:${padreId}`],
        [detachedId, 'applied', null],
        [parkedId, 'dead', 'irreparable'],
      ],
      'en orden de proceso, las aparcadas al final; la purga de la clave aparcada pasa (R2a)'
    )
    assert.deepEqual(report.missing, [])
  })

  /**
   * **1b-3, el caso decisivo del tester**: con 500 entradas ajenas por delante
   * y `limit: 50`, sin `only` la propia no aparece en NINGUNA lista (correcto e
   * inútil); con `only` se aplica, y el espía sobre `pending` demuestra que
   * NO se leyó la cola ajena — que es lo que distingue el filtro en el puerto
   * del filtro en memoria. Contra la outbox SQL real, en los cuatro motores,
   * y con el tiempo medido en el log.
   */
  test('1b-3: 500 ajenas + `limit 50` — sin `only` la mía no aparece en ninguna lista; con `only` se aplica y la pasada NO lee las 500 (espía sobre `pending`)', async ({
    assert,
  }) => {
    await cleanScopeOutbox(db)
    const tree = memoryScopeTree()
    const otro = orgScope()
    const miOrg = orgScope()
    const mia = unitScope()
    await tree.attach(otro, APP_SCOPE)
    await tree.attach(miOrg, APP_SCOPE)
    await tree.attach(mia, miOrg)
    const { driver, calls } = spyDriver()
    const base = sqlScopeOutbox({ requireTransaction: false })
    let rowsRead = 0
    const outbox: any = {
      ...base,
      pending: async (...args: any[]) => {
        const rows = await (base.pending as any)(...args)
        rowsRead += rows.length
        return rows
      },
    }
    const manager = managerWith({ tree, driver, outbox })
    for (let i = 0; i < 500; i++) {
      await base.enqueue({ op: 'attached', child: unitScope(), parent: otro }, {})
    }
    const { queued } = await manager.scopes.attached(mia, miOrg)

    // Sin `only`: la receta de hoy. Correcta, e inútil para «¿se aplicó lo mío?».
    const t0 = performance.now()
    const blind = await manager.relayScopeChanges({ limit: 50 })
    const blindMs = performance.now() - t0
    assert.lengthOf(blind.applied, 50)
    assert.isTrue(blind.remaining)
    const listed = [...blind.applied, ...blind.deferred, ...blind.failures, ...blind.dead, ...blind.entries]
    assert.isFalse(listed.some((x: any) => String(x.id) === String(queued[0])), 'la mía no está en ninguna lista')
    assert.isFalse(calls.some((c) => c.includes(keyOf(mia))))

    // Con `only`: lo mío, sin leer lo de los demás.
    rowsRead = 0
    const t1 = performance.now()
    const report = await manager.relayScopeChanges({ only: queued, limit: 50 })
    const onlyMs = performance.now() - t1
    assert.deepEqual(report.applied.map((a: any) => String(a.id)), [String(queued[0])])
    assert.deepEqual(report.entries.map((e: any) => e.status), ['applied'])
    assert.isTrue(calls.some((c) => c.includes(keyOf(mia))))
    assert.isTrue(report.remaining, 'y sigue gritando que la cola no está vacía (450 ajenas)')
    assert.isAtMost(rowsRead, 3, `con only la pasada no lee la cola ajena (leyó ${rowsRead} filas)`)
    console.log(`[1b-3 · ${testEngine()}] pasada ciega (50 de 501): ${blindMs.toFixed(1)} ms · pasada only (1 de 501): ${onlyMs.toFixed(1)} ms · filas leídas con only: ${rowsRead}`)
    assert.isBelow(onlyMs, blindMs, 'y es más barata que relevar a ciegas')
  }).timeout(120_000)

  test('el puerto SQL: `pending(limit, after, { ids })` honra los ids y `after`; `earlierPending` encuentra la anterior por hijo o por padre (la raíz incluida) e ignora aplicadas y aparcadas; `ids: []` es 500', async ({
    assert,
  }) => {
    await cleanScopeOutbox(db)
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 1 })
    const org = orgScope()
    const unit = unitScope()
    const child = unitScope()
    const other = unitScope()
    const a = (await outbox.enqueue({ op: 'attached', child: org, parent: APP_SCOPE }, {}))!.id
    const b = (await outbox.enqueue({ op: 'attached', child: unit, parent: org }, {}))!.id
    const c = (await outbox.enqueue({ op: 'attached', child: child, parent: unit }, {}))!.id
    const d = (await outbox.enqueue({ op: 'detached', child: other }, {}))!.id

    assert.deepEqual((await outbox.pending(10, undefined, { ids: [c, a] })).map((p) => String(p.id)), [String(a), String(c)], 'en orden de id')
    assert.deepEqual((await outbox.pending(10, a, { ids: [c, a] })).map((p) => String(p.id)), [String(c)], '`after` sigue valiendo')
    await rejects(assert, () => outbox.pending(10, undefined, { ids: [] }), { status: 500, code: 'E_AUTHZ_CONFIG' })

    assert.equal(String((await outbox.earlierPending!(c, [child, unit]))!.id), String(b), 'la anterior que nombra `unit` (como hijo)')
    assert.equal(String((await outbox.earlierPending!(b, [unit, org]))!.id), String(a), 'la anterior que nombra `org` (como hijo de la raíz)')
    assert.equal(String((await outbox.earlierPending!(d, [APP_SCOPE]))!.id), String(a), 'la raíz se busca como padre con uuid nulo')
    assert.isNull(await outbox.earlierPending!(d, [other]), 'nada anterior nombra `other`')
    assert.isNull(await outbox.earlierPending!(a, [org, APP_SCOPE]), 'la primera no tiene anterior')

    await outbox.markApplied(a)
    assert.isNull(await outbox.earlierPending!(b, [unit, org]), 'una APLICADA ya no bloquea')
    await outbox.markFailed(b, 'irreparable')
    assert.isNull(await outbox.earlierPending!(c, [child, unit]), 'una APARCADA no sale por aquí: la siembra de `dead()` es quien la ve (R2a)')
    await outbox.markFailed(c, 'el store no responde', { transient: true })
    assert.equal(String((await outbox.earlierPending!(d, [child]))!.id), String(c), 'un fallo transitorio sigue pendiente y sigue bloqueando')
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * **alpha.5 · R2b — `authz:scopes:requeue --id`** (panel relay, cuestión 2;
 * decisiones del dueño del 2026-09-09 (2)). Una entrada APARCADA vuelve a
 * `pending()` con `attempts = maxAttempts − 1` (ni 0 ni conservado: vuelve a
 * `dead()` en UNA pasada si la causa sigue rota, entra a la primera si el
 * operador la arregló, sin columna nueva). Y la SONDA ANTI-REVERSIÓN vive en
 * el MANAGER: reencolar una entrada anterior a otra YA APLICADA que comparta
 * clave de scope reescribe el árbol del store en un orden que nunca existió
 * (auditor 🔴 2, `relay-auditor-5.ts`: el `moved` viejo re-aplicado tras el
 * nuevo deja el store con el padre VIEJO y UN solo padre: `assertOneParent`
 * no lo delata). `--force` existe solo en el comando ace, con el diff impreso.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('alpha.5 · R2b — `requeue`: una aparcada vuelve a la cola, y nunca por encima de lo ya aplicado', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  /** Aparca `id` a mano: `maxAttempts` fallos de la ENTRADA (no transitorios). */
  async function park(outbox: any, id: any, times: number, error = 'irreparable') {
    for (let i = 0; i < times; i++) await outbox.markFailed(id, error)
  }

  test('2-1/2-2 · una aparcada reencolada vuelve a `pending()` con `attempts = maxAttempts − 1`, sale de `dead()` y la pasada siguiente la aplica', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 3 })
    const manager = managerWith({ tree, driver, outbox })
    const { queued: [id] } = await manager.scopes.attached(unit, org)
    driver.onScopeAttached = async () => {
      throw new Error('el padre todavía no está en el store')
    }
    for (let i = 0; i < 3; i++) await manager.relayScopeChanges()
    assert.deepEqual((await outbox.dead!(10)).map((d) => String(d.id)), [String(id)], 'aparcada')
    assert.deepEqual(await outbox.pending(10), [])

    // El operador arregla la causa y reencola.
    driver.onScopeAttached = async (c: any, p: any) => void calls.push(`attached ${keyOf(c)} → ${keyOf(p)}`)
    const report = await manager.requeueScopeChanges([id])

    assert.deepEqual(report.requeued.map((r) => String(r.id)), [String(id)])
    assert.deepEqual(report.overrides, [], 'nada aplicado después comparte clave: sin diff')
    assert.isFalse(report.forced)
    assert.deepEqual(await outbox.dead!(10), [], 'ya no está aparcada')
    const [again] = await outbox.pending(10)
    assert.equal(String(again.id), String(id), 'vuelve con su id VIEJO')
    assert.equal(again.attempts, 2, 'maxAttempts − 1: le queda UN intento, ni cero ni los tres')
    assert.include(again.lastError!, 'todavía no está en el store', 'la causa no se borra: nada se vuelve silencioso')

    const pass = await manager.relayScopeChanges()
    assert.deepEqual(pass.applied.map((a) => String(a.id)), [String(id)])
    assert.deepEqual(calls, [`attached ${keyOf(unit)} → ${keyOf(org)}`])
    assert.deepEqual(pass.dead, [])
  })

  /**
   * **EL CASO** (auditor 🔴 2, `relay-auditor-5.ts`). El estado que deja una
   * cola de alpha.4 (o un `detached` que pasa el tapón): `#1 moved(unit → orgB)`
   * APARCADA y `#2 moved(unit → orgC)` APLICADA después. Reencolar #1 la
   * aplicaría tras #2 ⇒ el store vuelve a orgB con UN solo padre, SQL sigue en
   * orgC, el tenant de orgB recupera el acceso y nada lo delata.
   */
  test('EL CASO (auditor 🔴 2): reencolar una aparcada con una entrada APLICADA posterior que comparte clave se NIEGA (500 E_AUTHZ_REQUEUE_REFUSED) nombrándola, y no toca nada', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const orgC = orgScope()
    const unit = unitScope()
    for (const o of [orgA, orgB, orgC]) await tree.attach(o, APP_SCOPE)
    await tree.attach(unit, orgC)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 2 })
    const manager = managerWith({ tree, driver, outbox })
    const old = (await outbox.enqueue({ op: 'moved', child: unit, parent: orgB }, {}))!.id
    await park(outbox, old, 2, 'el store no respondía')
    const current = (await outbox.enqueue({ op: 'moved', child: unit, parent: orgC }, {}))!.id
    await outbox.markApplied(current)

    const error = await rejects(assert, () => manager.requeueScopeChanges([old]), {
      status: 500,
      code: 'E_AUTHZ_REQUEUE_REFUSED',
    })
    assert.include(error.message, `#${current}`, 'nombra la entrada aplicada que se revertiría')
    assert.include(error.message, keyOf(unit).replace(':', '|'), 'y la clave compartida')
    assert.include(error.message, 'authz:reconcile', 'y el remedio correcto: recalcular con el árbol de HOY')
    assert.lengthOf(error.conflicts, 1)
    assert.equal(String(error.conflicts[0].parked.id), String(old))
    assert.deepEqual(error.conflicts[0].applied.map((a: any) => String(a.id)), [String(current)])

    assert.deepEqual((await outbox.dead!(10)).map((d) => String(d.id)), [String(old)], 'sigue aparcada')
    assert.deepEqual(await outbox.pending(10), [], 'no volvió a la cola')
    assert.deepEqual((await manager.relayScopeChanges()).applied, [])
    assert.deepEqual(calls, [], 'el driver no vio NADA: el store sigue en orgC')
  })

  test('2-9b (inverso): una aplicada posterior que NO comparte clave no impide el requeue, y no hay diff', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    const other = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    await tree.attach(other, org)
    const { driver } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 2 })
    const manager = managerWith({ tree, driver, outbox })
    const parked = (await outbox.enqueue({ op: 'detached', child: unit }, {}))!.id
    await park(outbox, parked, 2)
    const later = (await outbox.enqueue({ op: 'detached', child: other }, {}))!.id
    await outbox.markApplied(later)

    const report = await manager.requeueScopeChanges([parked])
    assert.deepEqual(report.requeued.map((r) => String(r.id)), [String(parked)])
    assert.deepEqual(report.overrides, [])
    assert.deepEqual((await outbox.pending(10)).map((p) => String(p.id)), [String(parked)])
  })

  test('`force: true` (lo que hace el comando con --force): entra, y el reporte trae el DIFF —qué aplicada posterior se revierte—', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgB = orgScope()
    const orgC = orgScope()
    const unit = unitScope()
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(orgC, APP_SCOPE)
    await tree.attach(unit, orgC)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 2 })
    const manager = managerWith({ tree, driver, outbox })
    const old = (await outbox.enqueue({ op: 'moved', child: unit, parent: orgB }, {}))!.id
    await park(outbox, old, 2)
    const current = (await outbox.enqueue({ op: 'moved', child: unit, parent: orgC }, {}))!.id
    await outbox.markApplied(current)

    const report = await manager.requeueScopeChanges([old], { force: true })
    assert.isTrue(report.forced)
    assert.deepEqual(report.requeued.map((r) => String(r.id)), [String(old)])
    assert.lengthOf(report.overrides, 1)
    assert.equal(String(report.overrides[0].parked.id), String(old))
    assert.deepEqual(report.overrides[0].applied.map((a) => String(a.id)), [String(current)])
    assert.deepEqual(report.overrides[0].applied.map((a) => a.change.op), ['moved'])

    // Y la pasada hace exactamente lo que el operador pidió con el diff delante: la reversión.
    const pass = await manager.relayScopeChanges()
    assert.deepEqual(pass.applied.map((a) => String(a.id)), [String(old)])
    assert.deepEqual(calls, [`moved ${keyOf(unit)} → ${keyOf(orgB)}`])
  })

  /**
   * El «grifo» del auditor (🔴 2, segunda mitad): un requeue automatizado de
   * lo irreparable aplazaría una y otra vez los cambios nuevos de ese scope.
   * Con `attempts = maxAttempts − 1` la entrada vuelve a `dead()` en UNA
   * pasada y su fallo contamina la clave SOLO en esa pasada: la purga del
   * padre (que pasa el tapón de lo aparcado) se aplaza una vez y entra en la
   * siguiente. Y no hay bucle: la aparcada no vuelve sola a `pending()`.
   */
  test('el requeue de una entrada cuyo padre ya no existe vuelve a aparcarse en UNA pasada, sin bucle, y contamina su clave solo esa pasada', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const parent = unitScope()
    const child = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(parent, org)
    await tree.attach(child, parent)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 2 })
    const manager = managerWith({ tree, driver, outbox })
    const { queued: [attachedId] } = await manager.scopes.attached(child, parent)
    // El padre se borró antes del relevo y no va a volver.
    await tree.detach(parent)
    driver.onScopeAttached = async () => {
      throw new Error('E_AUTHZ_UNKNOWN_SCOPE: el padre no existe en el store')
    }
    await manager.relayScopeChanges()
    await manager.relayScopeChanges()
    assert.deepEqual((await outbox.dead!(10)).map((d) => String(d.id)), [String(attachedId)], 'aparcada tras 2')
    const attempts = () => calls.filter((c) => c.startsWith('attached')).length

    await manager.requeueScopeChanges([attachedId])
    const detachedId = (await outbox.enqueue({ op: 'detached', child: parent }, {}))!.id

    const first = await manager.relayScopeChanges()
    assert.deepEqual(first.failures.map((f) => String(f.id)), [String(attachedId)], 'se intenta UNA vez más')
    assert.isFalse(first.failures[0].transient)
    assert.deepEqual(first.deferred.map((d) => String(d.id)), [String(detachedId)], 'la purga se aplaza SOLO por el fallo de esta pasada')
    assert.deepEqual(
      first.entries.filter((e) => e.status === 'deferred').map((e) => e.reason),
      [`depends-on:${attachedId}`],
      'por el FALLO (depends-on), no por el aparcado (parked): todavía no lo está'
    )
    assert.deepEqual(first.dead, [], 'todavía no: el aparcado se decide en la outbox al contar el intento')

    const second = await manager.relayScopeChanges()
    assert.deepEqual(second.dead.map((d) => String(d.id)), [String(attachedId)], 'vuelve a estar aparcada: UNA pasada, no cinco')
    assert.deepEqual(second.applied.map((a) => String(a.id)), [String(detachedId)], 'la purga entra en la pasada siguiente (invariante 11): la clave no queda contaminada')
    assert.deepEqual(second.failures, [])

    const third = await manager.relayScopeChanges()
    assert.deepEqual(third.applied, [])
    assert.deepEqual(third.failures, [], 'sin bucle: la aparcada no vuelve sola')
    assert.deepEqual(third.dead.map((d) => String(d.id)), [String(attachedId)], 'y se sigue reportando')
    assert.equal(attempts(), 0, 'el driver nunca vio el attached aplicado')
  })

  test('2-3/2-4/2-6 · un id inexistente, uno todavía PENDIENTE o uno YA APLICADO ⇒ 500 nombrándolo, todo o nada (cero filas tocadas); `ids: []` ⇒ 500', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 2 })
    const manager = managerWith({ tree, driver, outbox })
    const parked = (await outbox.enqueue({ op: 'attached', child: unit, parent: org }, {}))!.id
    await park(outbox, parked, 2)
    const live = (await outbox.enqueue({ op: 'detached', child: unit }, {}))!.id
    const applied = (await outbox.enqueue({ op: 'detached', child: org }, {}))!.id
    await outbox.markApplied(applied)
    const snapshot = async () => JSON.stringify(await db.from('authz_scope_outbox').orderBy('id', 'asc'))
    const before = await snapshot()

    for (const [label, ids] of [
      ['inexistente', [999_999]],
      ['pendiente viva', [live]],
      ['ya aplicada', [applied]],
      ['lote mixto', [parked, applied]],
    ] as Array<[string, any[]]>) {
      const error = await rejects(assert, () => manager.requeueScopeChanges(ids), { status: 500, code: 'E_AUTHZ_CONFIG' }, label)
      const culprit = ids[ids.length - 1]
      assert.include(error.message, String(culprit), `${label}: nombra el id`)
      assert.equal(await snapshot(), before, `${label}: cero filas tocadas`)
    }
    await rejects(assert, () => manager.requeueScopeChanges([]), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'vacío')
    await rejects(assert, () => manager.requeueScopeChanges('7' as any), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'no es lista')
    assert.deepEqual(calls, [])
    // 2-6: reencolar un `detached` APLICADO volvería a purgar; el puerto también se niega solo.
    await rejects(assert, () => outbox.requeue!([applied]), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'el puerto')
    assert.equal(await snapshot(), before)
  })

  test('TERCEROS: una outbox sin `requeue` ⇒ 500 E_AUTHZ_UNSUPPORTED nombrándolo; con `requeue` pero sin `laterApplied` ⇒ 500 nombrando la sonda (sin sonda no hay requeue)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const { driver, calls } = spyDriver()
    const { outbox } = memoryQueue({ maxAttempts: 1 })
    const manager = managerWith({ tree, driver, outbox })
    const { queued: [id] } = await manager.scopes.attached(org, APP_SCOPE)
    driver.onScopeAttached = async () => {
      throw new Error('irreparable')
    }
    await manager.relayScopeChanges()
    assert.lengthOf(await outbox.dead(10), 1)

    const sinRequeue = await rejects(assert, () => manager.requeueScopeChanges([id]), { status: 500, code: 'E_AUTHZ_UNSUPPORTED' })
    assert.include(sinRequeue.message, 'requeue')

    let touched = 0
    outbox.requeue = async () => void touched++
    const sinSonda = await rejects(assert, () => manager.requeueScopeChanges([id]), { status: 500, code: 'E_AUTHZ_UNSUPPORTED' })
    assert.include(sinSonda.message, 'laterApplied')
    assert.equal(touched, 0, 'sin sonda no se reencola nada')
    assert.deepEqual(calls.filter((c) => c.startsWith('attached')), [], 'y el driver no vio nada tras el aparcado')
  })

  test('sin `scopes.outbox` el requeue es 500 E_AUTHZ_CONFIG: no hay cola', async ({ assert }) => {
    const tree = memoryScopeTree()
    const { driver } = spyDriver()
    const manager = managerWith({ tree, driver })
    await rejects(assert, () => manager.requeueScopeChanges([1]), { status: 500, code: 'E_AUTHZ_CONFIG' })
  })

  test('el puerto SQL: `laterApplied(id, scopes, limit)` devuelve las APLICADAS posteriores que nombran el hijo o el padre (la raíz incluida), ignora pendientes, aparcadas y anteriores; `requeue` deja `attempts = maxAttempts − 1`', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 3 })
    const org = orgScope()
    const unit = unitScope()
    const other = unitScope()
    const a = (await outbox.enqueue({ op: 'attached', child: unit, parent: org }, {}))!.id
    await outbox.markApplied(a) // anterior y aplicada: no cuenta
    const b = (await outbox.enqueue({ op: 'moved', child: unit, parent: org }, {}))!.id
    await park(outbox, b, 3)
    const c = (await outbox.enqueue({ op: 'detached', child: unit }, {}))!.id // posterior, aplicada, comparte `unit` como hijo
    await outbox.markApplied(c)
    const d = (await outbox.enqueue({ op: 'attached', child: other, parent: org }, {}))!.id // posterior, aplicada, comparte `org` como padre
    await outbox.markApplied(d)
    const e = (await outbox.enqueue({ op: 'attached', child: other, parent: APP_SCOPE }, {}))!.id // posterior, aplicada, la raíz
    await outbox.markApplied(e)
    const f = (await outbox.enqueue({ op: 'moved', child: unit, parent: other }, {}))!.id // posterior, PENDIENTE: no cuenta aquí
    void f

    const byUnit = await outbox.laterApplied!(b, [unit], 10)
    assert.deepEqual(byUnit.map((x) => String(x.id)), [String(c)], 'por hijo')
    const byOrg = await outbox.laterApplied!(b, [org], 10)
    assert.deepEqual(byOrg.map((x) => String(x.id)), [String(d)], 'por padre')
    const both = await outbox.laterApplied!(b, [unit, org], 10)
    assert.deepEqual(both.map((x) => String(x.id)), [String(c), String(d)], 'en orden de id')
    assert.deepEqual((await outbox.laterApplied!(b, [APP_SCOPE], 10)).map((x) => String(x.id)), [String(e)], 'la raíz como padre con uuid nulo')
    assert.deepEqual(await outbox.laterApplied!(b, [other], 1), [(await outbox.laterApplied!(b, [other], 10))[0]], '`limit` acota')
    assert.deepEqual(await outbox.laterApplied!(e, [org, unit, other], 10), [], 'nada posterior a la última aplicada')
    assert.deepEqual(await outbox.laterApplied!(b, [], 10), [])

    await outbox.requeue!([b])
    const [row] = await outbox.pending(10)
    assert.equal(String(row.id), String(b))
    assert.equal(row.attempts, 2)
    assert.deepEqual(await outbox.dead!(10), [])
    await outbox.markFailed(b, 'sigue rota')
    assert.deepEqual((await outbox.dead!(10)).map((x) => String(x.id)), [String(b)], 'un fallo más y vuelve a estar aparcada')
    await rejects(assert, () => outbox.requeue!([]), { status: 500, code: 'E_AUTHZ_CONFIG' })
  })
})

test.group('alpha.5 · R2b — el comando `authz:scopes:requeue` está registrado y decide en una función pura', () => {
  test('`commands/main.ts` lo exporta con su nombre, `--id` (repetible) y `--force`; sin `--id` no reencola nada', async ({ assert }) => {
    const commands: any = await import('../commands/main.js')
    const Requeue = commands.AuthzScopesRequeue
    assert.isFunction(Requeue)
    assert.equal(Requeue.commandName, 'authz:scopes:requeue')
    assert.isTrue(Requeue.options.startApp)
    const nombres = flagNamesOf(Requeue)
    assert.includeMembers(nombres, ['id', 'force'])
    assert.isUndefined(Requeue.parseIds(undefined), 'sin --id no hay lista: el comando para con error, nunca «reencola todo»')
    assert.deepEqual(Requeue.parseIds(['12,13', ' 14 ', 'abc']), [12, 13, 14, 'abc'])
    assert.deepEqual(Requeue.parseIds(['']), [])
    const source = await readFile(new URL('../commands/authz_scopes_requeue.ts', import.meta.url), 'utf8')
    assert.include(source, 'E_AUTHZ_REQUEUE_REFUSED')
    assert.include(source, 'force: this.force === true')
  })

  test('`requeueLines`: la negativa imprime el DIFF (la aparcada y cada aplicada posterior que revertiría) y sale 1; con --force imprime el diff, lo dice y sale 0', async ({
    assert,
  }) => {
    const { requeueLines } = await import('../commands/authz_scopes_requeue.js')
    const unit = unitScope()
    const orgB = orgScope()
    const orgC = orgScope()
    const parked: any = { id: 1, change: { op: 'moved', child: unit, parent: orgB }, attempts: 5, lastError: 'el store no respondía' }
    const applied: any = { id: 2, change: { op: 'moved', child: unit, parent: orgC } }
    const conflicts: any = [{ parked, applied: [applied] }]

    const refused = requeueLines({ refused: conflicts })
    assert.isFalse(refused.clean)
    const texto = refused.lines.map((l) => l.message).join('\n')
    assert.include(texto, `#1 moved ${keyOf(unit)} → ${keyOf(orgB)}`)
    assert.include(texto, `#2 moved ${keyOf(unit)} → ${keyOf(orgC)}`)
    assert.include(texto, '--force')
    assert.include(texto, 'authz:reconcile')
    assert.isTrue(refused.lines.some((l) => l.level === 'error'))

    const forced = requeueLines({ report: { requeued: [parked], overrides: conflicts, forced: true } as any })
    assert.isTrue(forced.clean)
    const forzado = forced.lines.map((l) => l.message).join('\n')
    assert.include(forzado, `#2 moved ${keyOf(unit)} → ${keyOf(orgC)}`, 'el diff también con --force')
    assert.include(forzado, 'maxAttempts')
    assert.isTrue(forced.lines.some((l) => l.level === 'warning'), 'forzar se dice como aviso, no como éxito mudo')

    const plain = requeueLines({ report: { requeued: [parked], overrides: [], forced: false } as any })
    assert.isTrue(plain.clean)
    assert.include(plain.lines.map((l) => l.message).join('\n'), `#1 moved ${keyOf(unit)} → ${keyOf(orgB)}`)
  })
})

test.group('3b-2h · 🟠 3 — el alias del uuid en la ESCRITURA (fila ya borrada)', () => {
  const dashless = (uuid: string) => uuid.replaceAll('-', '')
  /** La canónica sin su ÚLTIMO guion: `8-4-4-16`, que PG funde con ella (la sonda `misdashed` de la guardia). */
  const misdashed = (uuid: string) => uuid.slice(0, 23) + uuid.slice(24)

  /**
   * El auditor lo midió contra PostgreSQL: el tipo `uuid` funde el alias sin
   * guiones con la fila real, así que el `DELETE` del controlador acierta y
   * el `scopes.detached` llega con el alias y SIN cadena. La purga se hacía
   * entonces con la ortografía del llamante: cero demostrado sobre un objeto
   * que no existe, y el scope real conservando `parent` y `binding` — en
   * `facts`, concediendo para siempre. Aquí se juzga la consecuencia sin
   * depender del motor (la fila ya no está, sea cual sea la razón).
   */
  test('EL CASO: sin cadena, un `detached` con el uuid SIN guiones purga TAMBIÉN la forma canónica', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const manager = managerWith({ tree, driver })

    // El consumidor borra su fila primero (el orden soportado, 3F · S1) y
    // notifica con el alias.
    await tree.detach(unit)
    await manager.scopes.detached({ type: 'unit', uuid: dashless(unit.uuid!) })

    assert.deepEqual(calls, [
      `purgeScope unit:${dashless(unit.uuid!)}`,
      `detached unit:${dashless(unit.uuid!)}`,
      `purgeScope ${keyOf(unit)}`,
      `detached ${keyOf(unit)}`,
    ])
  })

  /**
   * **🟠 R1 del re-ataque al cierre del lote A** (decisión del dueño
   * 2026-10-15 (2)): el cierre dijo «Roles: no aplica» y SÍ aplicaba justo en
   * esta rama, la que NO tiene cadena. `scopeSpellings` expandía SOLO la forma
   * sin guiones; con `8-4-4-16` —que PG funde igual (A2, medido con `::uuid`)—
   * `isNonCanonicalUuid` ya decía `true` y aun así se purgaba una clave sin
   * hechos: la canónica sobrevivía (en `facts`, concediendo para siempre; en
   * `database`, resucitando si la fila volvía — «nada resucita», invariante 11).
   * El cierre-2 puso la regla de relaciones (`isNonCanonicalUuid`) y el
   * re-ataque (🟡 C2-1) midió que es MÁS ANCHA que lo que PG funde: `-<hex>`,
   * `<hex>-`, `a0e-…` o `8--24` son ids legales que PG rechaza, y expandirlos a
   * la canónica era alcance de más sin beneficio. **Cierre-3**: la regla del
   * fan-out es `pgFusedSpellings` (solo lo que PG funde, medido); las formas
   * que PG no funde son UNA purga (el repro C2-1 del auditor, invertido: filas
   * con `purges === 1`). Mutante «usar la ancha en roles» ⇒ esas filas rojas.
   */
  test('🟠 R1 / 🟡 C2-1 · sin cadena, un `detached` con una forma que PG funde (8-4-4-16, 8-8-8-8, 12-4-4-12, sin guiones) purga TAMBIÉN la canónica; una forma que PG NO funde (-<hex>, <hex>-, a0e-…, 8--24) o un id legal purga SOLO la del llamante', async ({
    assert,
  }) => {
    const forms: Array<[string, (uuid: string) => string, number]> = [
      ['8-4-4-16 (la sonda misdashed)', misdashed, 2],
      ['8-8-8-8', (u) => u.replaceAll('-', '').replace(/^(.{8})(.{8})(.{8})(.{8})$/, '$1-$2-$3-$4'), 2],
      ['12-4-4-12 (sin el primer guion)', (u) => u.slice(0, 8) + u.slice(9), 2],
      ['sin guiones (3b-2h, control)', dashless, 2],
      ['32 caracteres NO hex (id legal, no es alias de nada)', () => 'z'.repeat(32), 1],
      ['-<32 hex> (PG no la funde; cierre-3 · C2-1)', (u) => `-${dashless(u)}`, 1],
      ['<32 hex>- (PG no la funde)', (u) => `${dashless(u)}-`, 1],
      ['a0e-… guion tras tres (PG no la funde)', (u) => `${dashless(u).slice(0, 3)}-${dashless(u).slice(3)}`, 1],
      ['8--24 dos guiones seguidos (PG no la funde)', (u) => `${dashless(u).slice(0, 8)}--${dashless(u).slice(8)}`, 1],
    ]
    for (const [label, form, purges] of forms) {
      const tree = memoryScopeTree()
      const org = orgScope()
      const unit = unitScope()
      await tree.attach(org, APP_SCOPE)
      await tree.attach(unit, org)
      const { driver, calls } = spyDriver()
      const manager = managerWith({ tree, driver })
      const alias = form(unit.uuid!)
      assert.lengthOf(pgFusedSpellings(alias), purges - 1, `${label}: la regla del fan-out es lo que PG funde (pgFusedSpellings)`)

      await tree.detach(unit) // la fila ya no está (3F · S1); no hay cadena con la que canonizar
      await manager.scopes.detached({ type: 'unit', uuid: alias })

      const expected = [`purgeScope unit:${alias}`, `detached unit:${alias}`]
      if (purges === 2) expected.push(`purgeScope ${keyOf(unit)}`, `detached ${keyOf(unit)}`)
      assert.deepEqual(calls, expected, `${label}: ROJO (R1) si falta la purga de la canónica`)
    }
  })

  test('con la fila VIVA nada cambia: la identidad es la CANÓNICA del árbol y se purga UNA vez', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const manager = managerWith({ tree, driver })

    await manager.scopes.detached(unit)

    assert.deepEqual(calls, [`purgeScope ${keyOf(unit)}`, `detached ${keyOf(unit)}`])
  })

  /**
   * **🟡 C2-2 del re-ataque al cierre-2 (cierre-3 del lote A, decisión del
   * dueño 2026-10-15 (3), estructural)**: en un consumidor con ids de scope de
   * TEXTO elegibles por el usuario, un tenant crea `<32 hex de la víctima>`
   * (u otra forma que PG funde), la borra y llama `detached` SIN `within`: sin
   * cadena, el fan-out añadía la canónica — que ES la unit VIVA de otro
   * tenant — y `purgeScope` + `onScopeDetached` caían sobre ella (en
   * `database` se iban sus denies con la herencia intacta: fail-open
   * cross-tenant; en `facts`, su arista `parent`: DoS). Clase PREEXISTENTE
   * desde 3b-2h con el 32 hex; el cierre-2 la ampliaba. Ahora
   * `canonicalScopeTargets` DESCARTA toda ortografía que el resolutor
   * reconozca como scope vivo distinto del pedido: nunca se purga un scope
   * vivo que no es el que se pidió. Repro C2-2 del auditor, invertido.
   * Mutante (quitar el contraste con el resolutor) ⇒ rojo en las dos formas
   * que PG funde.
   */
  test('🟡 C2-2 · sin cadena para el alias, la canónica que está VIVA en el árbol (otro scope, otro tenant) NO se purga ni se desengancha: solo la ortografía del llamante', async ({
    assert,
  }) => {
    const forms: Array<[string, (uuid: string) => string]> = [
      ['32 hex sin guiones (clase preexistente, 3b-2h)', dashless],
      ['8-4-4-16 (cierre-2)', misdashed],
      ['a0e-… (PG no la funde: ya la descarta la regla 1)', (u) => `${dashless(u).slice(0, 3)}-${dashless(u).slice(3)}`],
    ]
    for (const [label, form] of forms) {
      const tree = memoryScopeTree()
      const orgVictim = orgScope()
      const victim = unitScope()
      await tree.attach(orgVictim, APP_SCOPE)
      await tree.attach(victim, orgVictim) // VIVA, de otro tenant
      const { driver, calls } = spyDriver()
      const manager = managerWith({ tree, driver })

      // El atacante ya borró su fila `unit:<alias>` (o nunca la tuvo): no resuelve.
      const alias = { type: 'unit', uuid: form(victim.uuid!) }
      assert.isNull(await resolveChainFrom(tree)(alias), `${label}: el alias no resuelve`)
      await manager.scopes.detached(alias)

      assert.deepEqual(
        calls,
        [`purgeScope ${keyOf(alias)}`, `detached ${keyOf(alias)}`],
        `${label}: ROJO (C2-2) si se purga/desengancha la víctima VIVA ${keyOf(victim)}`
      )
      assert.isNotNull(await resolveChainFrom(tree)(victim), 'la víctima sigue en el árbol')
    }
  })

  test('🟡 C2-2 · si el resolutor FALLA al contrastar la canónica, el `detached` es 503 E_AUTHZ_RESOLVER_FAILED y el driver no recibe NADA (nunca se purga «por si acaso»)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const base = resolveChainFrom(tree)
    const flaky = async (scope: any) => {
      if (scope.uuid === unit.uuid) throw new Error('árbol caído justo para la canónica')
      return base(scope)
    }
    const { driver, calls } = spyDriver()
    const manager = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => driver },
      scopes: { resolveChain: flaky },
      warnOnOptInSecurity: false,
    } as any)

    const caught = await manager.scopes.detached({ type: 'unit', uuid: dashless(unit.uuid!) }).then(() => null, (e) => e)
    assert.equal(caught?.status, 503)
    assert.equal(caught?.code, 'E_AUTHZ_RESOLVER_FAILED')
    assert.deepEqual(calls, [], 'cero purgas con el árbol caído')
  })

  test('un uuid que no es un alias de nada (ni 32 hex) sigue siendo UNA purga: el caso normal no paga', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const { driver, calls } = spyDriver()
    const manager = managerWith({ tree, driver })
    const unit = unitScope()

    await manager.scopes.detached(unit)

    assert.deepEqual(calls, [`purgeScope ${keyOf(unit)}`, `detached ${keyOf(unit)}`])
  })

  test('por la OUTBOX viajan las dos ortografías: el relevo no puede canonizar nada', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const unit = unitScope()
    const { driver } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const manager = managerWith({ tree, driver, outbox })

    await manager.scopes.detached({ type: 'unit', uuid: dashless(unit.uuid!) })
    const other = unitScope()
    await manager.scopes.detached({ type: 'unit', uuid: misdashed(other.uuid!) }) // 🟠 R1: también la 8-4-4-16

    assert.deepEqual(
      enqueued.map((e) => e.change.child.uuid),
      [dashless(unit.uuid!), unit.uuid, misdashed(other.uuid!), other.uuid],
      'la decisión se toma donde está la información: al encolar'
    )
  })
})

test.group('3b-2h · 🟠 4 — el relay es escritor ÚNICO (lease de la outbox)', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  /**
   * `pending()` no reserva nada y el lote no se relee, así que dos pasadas a
   * la vez trabajan sobre el MISMO lote: medido, la rezagada re-aplica un
   * `attached` viejo DESPUÉS de que la otra aplicara el `moved` nuevo y deja
   * el árbol del store revertido —con UN solo padre, así que nada lo delata—
   * mientras el tenant antiguo conserva el acceso. Con lease, la segunda
   * pasada no hace nada y lo dice.
   */
  test('dos pasadas a la vez: la segunda no aplica NADA y lo dice (`busy`)', async ({ assert }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const manager = managerWith({ tree, driver, outbox })
    // Una pasada que tarda: es lo que hace un lote grande o un servidor lento.
    driver.onScopeAttached = async (c: any, p: any) => {
      await new Promise((r) => setTimeout(r, 60))
      calls.push(`attached ${keyOf(c)} → ${keyOf(p)}`)
    }
    await manager.scopes.attached(unit, org)

    const [primera, segunda] = await Promise.all([
      manager.relayScopeChanges(),
      new Promise((r) => setTimeout(r, 10)).then(() => manager.relayScopeChanges()),
    ])

    assert.isFalse(primera.busy)
    assert.lengthOf(primera.applied, 1)
    assert.isTrue((segunda as any).busy, 'la segunda pasada ve el lease tomado')
    assert.deepEqual((segunda as any).applied, [])
    assert.deepEqual(calls, [`attached ${keyOf(unit)} → ${keyOf(org)}`], 'el cambio se aplicó UNA vez')
  })

  test('el lease se suelta aunque la pasada falle: la siguiente pasada entra', async ({ assert }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const manager = managerWith({ tree, driver, outbox })
    await manager.scopes.attached(unit, org)
    const roto: any = manager
    const original = roto.driver.bind(roto)
    roto.driver = async () => {
      roto.driver = original
      throw new Error('el driver no se pudo resolver')
    }

    await assert.rejects(() => manager.relayScopeChanges())

    const report = await manager.relayScopeChanges()
    assert.isFalse(report.busy, 'el lease no se quedó tomado')
    assert.lengthOf(report.applied, 1)
  })

  test('una outbox SIN lease se comporta como siempre (el puerto no lo exige)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const { driver } = spyDriver()
    const { outbox, enqueued } = recordingOutbox()
    const manager = managerWith({ tree, driver, outbox: queueFrom(enqueued, outbox) })
    await manager.scopes.attached(org, APP_SCOPE)

    const report = await manager.relayScopeChanges()

    assert.isFalse(report.busy)
    assert.lengthOf(report.applied, 1)
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * **alpha.5 · CIERRE** (auditor del lote, `alpha5-auditor.md`; repros
 * `relay-auditor-7.ts` y `relay-auditor-9.ts`). Dos 🟠 en el tapón por clave
 * de R2a y tres 🟡 baratos.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('alpha.5 · CIERRE · 🟠 1 — el tapón por APARCADO no congela las purgas, ni a un salto ni a dos', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  /**
   * La repro G del auditor, con un nieto de más: `#1 moved(unit → o2)` APARCADA,
   * `#2 attached(child, unit)` aplazado `parked:#1` (correcto), `#2b
   * attached(grandchild, child)` aplazado por `#2` (transitivo), y el tenant
   * BORRA la unit: `#3 detached(unit)` y `#4 detached(child)`. Hasta el cierre,
   * `defer()` contaminaba la clave para TODAS las operaciones y las dos purgas
   * salían `depends-on:#2` en todas las pasadas: el scope borrado conservaba
   * sus hechos y su arista, y seguía concediendo (invariante 11 roto, y el
   * README prometiendo lo contrario). El ORIGEN del bloqueo decide: un
   * aplazamiento cuya causa raíz es un aparcado solo tapona `attached`/`moved`.
   */
  test('EL CASO (repro G): con un `attached` aplazado por aparcado entre medias, el `detached` de esa clave SE APLICA y purga — también el del nieto (dos saltos)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const o = orgScope()
    const o2 = orgScope()
    const unit = unitScope()
    const child = unitScope()
    const grandchild = unitScope()
    for (const x of [o, o2]) await tree.attach(x, APP_SCOPE)
    await tree.attach(unit, o)
    await tree.attach(child, unit)
    await tree.attach(grandchild, child)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 1 })
    const manager = managerWith({ tree, driver, outbox })

    const { queued: [movedId] } = await manager.scopes.moved(unit, o2)
    const { queued: [attachedId] } = await manager.scopes.attached(child, unit)
    const { queued: [grandId] } = await manager.scopes.attached(grandchild, child)
    driver.onScopeMoved = async () => {
      throw new Error('el padre ya no existe')
    }
    await manager.relayScopeChanges() // #1 falla ⇒ APARCADA (maxAttempts 1)
    assert.deepEqual((await outbox.dead!(10)).map((d) => String(d.id)), [String(movedId)])

    const { queued: [detachedUnit] } = await manager.scopes.detached(unit)
    const { queued: [detachedChild] } = await manager.scopes.detached(child)
    const report = await manager.relayScopeChanges()

    assert.deepEqual(
      report.entries.map((e: any) => [String(e.id), e.status, e.reason ?? null]),
      [
        [String(attachedId), 'deferred', `parked:${movedId}`],
        [String(grandId), 'deferred', `depends-on:${attachedId}`],
        [String(detachedUnit), 'applied', null],
        [String(detachedChild), 'applied', null],
        [String(movedId), 'dead', 'el padre ya no existe'],
      ],
      'los attached siguen aplazados (orden), las DOS purgas entran'
    )
    assert.deepEqual(
      calls.filter((c) => c.startsWith('purgeScope')),
      [`purgeScope ${keyOf(unit)}`, `purgeScope ${keyOf(child)}`],
      'el scope borrado NO conserva sus hechos'
    )
    assert.notInclude(calls.join(' | '), 'attached', 'y ningún attached se coló fuera de orden')
    const second = await manager.relayScopeChanges()
    assert.deepEqual(second.applied, [])
    assert.deepEqual(second.deferred.map((d) => String(d.id)), [String(attachedId), String(grandId)], 'lo que sigue aplazado es lo que concede')
  })

  test('control (repro G sin hijo): sin `attached` entre medias, el `detached` de la clave aparcada se aplica (como en R2a)', async ({ assert }) => {
    const tree = memoryScopeTree()
    const o = orgScope()
    const o2 = orgScope()
    const unit = unitScope()
    for (const x of [o, o2]) await tree.attach(x, APP_SCOPE)
    await tree.attach(unit, o)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 1 })
    const manager = managerWith({ tree, driver, outbox })
    await manager.scopes.moved(unit, o2)
    driver.onScopeMoved = async () => {
      throw new Error('el padre ya no existe')
    }
    await manager.relayScopeChanges()
    await manager.scopes.detached(unit)
    const report = await manager.relayScopeChanges()
    assert.deepEqual(report.applied.map((a) => a.change.op), ['detached'])
    assert.include(calls.join(' | '), `purgeScope ${keyOf(unit)}`)
  })

  /**
   * El bloqueo cuyo origen es un FALLO REAL de la pasada sigue afectando a
   * todo, `detached` incluido (3b-2h: el orden entre un `attached` que falló y
   * la purga de ese mismo nodo importa —purgar un nodo cuya arista no está
   * es purgar en el sitio equivocado—). Solo el aparcado exime a la purga.
   */
  test('CASO NEGATIVO: un `detached` detrás de un `attached` que FALLÓ (no aparcado) sigue aplazado `depends-on:` como hasta ahora; en la pasada siguiente, si el fallo se arregla, entra en orden', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 5 })
    const manager = managerWith({ tree, driver, outbox })
    const { queued: [attachedId] } = await manager.scopes.attached(unit, org)
    const { queued: [detachedId] } = await manager.scopes.detached(unit)
    const original = driver.onScopeAttached
    driver.onScopeAttached = async () => {
      throw new Error('el store no acepta la arista todavía')
    }
    const report = await manager.relayScopeChanges()
    assert.deepEqual(report.failures.map((f) => String(f.id)), [String(attachedId)])
    assert.deepEqual(
      report.entries.filter((e: any) => String(e.id) === String(detachedId)).map((e: any) => [e.status, e.reason]),
      [['deferred', `depends-on:${attachedId}`]],
      'un fallo real contamina también la purga: el orden manda'
    )
    assert.notInclude(calls.join(' | '), 'purgeScope')
    driver.onScopeAttached = original
    const next = await manager.relayScopeChanges()
    assert.deepEqual(next.applied.map((a) => a.change.op), ['attached', 'detached'], 'en orden')
  })
})

test.group('alpha.5 · CIERRE · 🟠 2 — el censo de claves aparcadas es COMPLETO, sea cual sea `limit`/`batchSize`', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  /** Repro I del auditor: 100 aparcadas de ruido y la 101 es la que importa. */
  async function parkedBacklog() {
    const tree = memoryScopeTree()
    const orgOld = orgScope()
    const orgNew = orgScope()
    const unit = unitScope()
    const child = unitScope()
    for (const o of [orgOld, orgNew]) await tree.attach(o, APP_SCOPE)
    await tree.attach(unit, orgNew)
    await tree.attach(child, unit)
    const now = new Date()
    const rows = []
    for (let i = 0; i < 100; i++) {
      rows.push({ op: 'moved', child_type: 'unit', child_uuid: uuidv7(), parent_type: 'organization', parent_uuid: uuidv7(), attempts: 5, last_error: 'irreparable', created_at: now, applied_at: null })
    }
    await db.table('authz_scope_outbox').multiInsert(rows)
    const [parkedId] = await db.table('authz_scope_outbox').returning('id').insert({
      op: 'moved', child_type: 'unit', child_uuid: unit.uuid, parent_type: 'organization', parent_uuid: orgNew.uuid,
      attempts: 5, last_error: 'irreparable', created_at: now, applied_at: null,
    })
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const manager = managerWith({ tree, driver, outbox })
    const { queued: [attachedId] } = await manager.scopes.attached(child, unit)
    const id101 = typeof parkedId === 'object' ? parkedId.id : parkedId
    return { manager, calls, attachedId, id101 }
  }

  test('EL CASO (repro I): 101 aparcadas + `relay({ only, limit: 1 })` ⇒ el attached se APLAZA `parked:<#101>`, cero llamadas; también `relay({ limit: 50 })` sin `only`', async ({
    assert,
  }) => {
    const { manager, calls, attachedId, id101 } = await parkedBacklog()
    const small = await manager.relayScopeChanges({ only: [attachedId], limit: 1 })
    assert.deepEqual(
      small.entries.filter((e: any) => String(e.id) === String(attachedId)).map((e: any) => [e.status, e.reason]),
      [['deferred', `parked:${id101}`]],
      'la aparcada 101 tapona su clave aunque la pasada solo lea 1'
    )
    assert.deepEqual(calls, [], 'el attached NO cuelga del padre viejo')
    const cmd = await manager.relayScopeChanges({ limit: 50 })
    assert.deepEqual(cmd.applied, [])
    assert.deepEqual(cmd.deferred.map((d) => String(d.id)), [String(attachedId)])
    assert.deepEqual(calls, [])
    assert.lengthOf(cmd.dead, 100, 'el reporte sigue enseñando `batchSize` aparcadas; el CENSO es aparte')
  })

  test('el censo tiene cota PROPIA: una outbox con más aparcadas que `PARKED_CENSUS_MAX` ⇒ 500 E_AUTHZ_CONFIG antes de aplicar nada (un tapón incompleto no se usa)', async ({
    assert,
  }) => {
    const { PARKED_CENSUS_MAX } = await import('../src/manager.js')
    const tree = memoryScopeTree()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const { driver, calls } = spyDriver()
    const { outbox, rows } = memoryQueue({ maxAttempts: 1 })
    // Un `dead()` que siempre llena lo que se le pide: el censo nunca cabe.
    outbox.dead = async (limit: number) =>
      Array.from({ length: limit }, (_, i) => ({ id: 1_000_000 + i, change: { op: 'moved', child: unitScope(), parent: orgScope() }, attempts: 1, lastError: 'irreparable' }))
    const manager = managerWith({ tree, driver, outbox })
    await manager.scopes.attached(org, APP_SCOPE)
    assert.lengthOf(rows, 1)
    const error = await rejects(assert, () => manager.relayScopeChanges(), { status: 500, code: 'E_AUTHZ_CONFIG' })
    assert.include(error.message, String(PARKED_CENSUS_MAX))
    assert.deepEqual(calls, [])
  })
})

test.group('alpha.5 · CIERRE · 🟡 baratos — el diff de `--force` dice cuando está cortado; `laterApplied` no ve a `reconcile`; `pending()` no esconde filas', () => {
  test('⚪ 6 · más de 100 aplicadas posteriores ⇒ `conflicts[].truncated` y `requeueLines` lo dice («y más»)', async ({ assert }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver } = spyDriver()
    const { outbox } = memoryQueue({ maxAttempts: 1 })
    const parked = { id: 7, change: { op: 'moved', child: unit, parent: org }, attempts: 1, lastError: 'irreparable' }
    outbox.dead = async () => [parked]
    outbox.laterApplied = async (_id: any, _scopes: any, limit: number) =>
      Array.from({ length: limit }, (_, i) => ({ id: 100 + i, change: { op: 'moved', child: unit, parent: orgScope() }, attempts: 0 }))
    outbox.requeue = async () => {}
    const manager = managerWith({ tree, driver, outbox })
    const error = await rejects(assert, () => manager.requeueScopeChanges([7]), { status: 500, code: 'E_AUTHZ_REQUEUE_REFUSED' })
    assert.lengthOf(error.conflicts[0].applied, 100, 'se listan 100')
    assert.isTrue(error.conflicts[0].truncated, 'y se DICE que hay más')
    const { requeueLines } = await import('../commands/authz_scopes_requeue.js')
    const texto = requeueLines({ refused: error.conflicts }).lines.map((l) => l.message).join('\n')
    assert.include(texto, 'y más')
    assert.include(texto, '100')
    // Y con exactamente 100 no se marca.
    outbox.laterApplied = async () => Array.from({ length: 100 }, (_, i) => ({ id: 100 + i, change: { op: 'moved', child: unit, parent: orgScope() }, attempts: 0 }))
    const exact = await rejects(assert, () => manager.requeueScopeChanges([7]), { status: 500, code: 'E_AUTHZ_REQUEUE_REFUSED' })
    assert.isNotOk(exact.conflicts[0].truncated)
  })

  test('🟡 4 / 🟡 3 · el README dice que `laterApplied` solo ve la outbox (no reencoles tras reconciliar) y que `pending()` no puede esconder filas; el docblock del puerto también', async ({
    assert,
  }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, 'only sees the outbox')
    assert.include(readme, 'do not requeue after reconciling')
    assert.include(readme, 'reconcile again')
    assert.include(readme, 'must return the whole unapplied queue, oldest first')
    const types = await readFile(new URL('../src/types.ts', import.meta.url), 'utf8')
    assert.include(types, 'puede ESCONDER una entrada sin aplicar')
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * **alpha.5 · R6 — el nombre del lease de MySQL** (tester del panel relay;
 * juez, cuestión 6 · 4). `GET_LOCK` admite 64 caracteres y el nombre se
 * recortaba: dos despliegues que coincidieran en los primeros 64 compartían
 * lease y se excluían PARA SIEMPRE, con `busy: true` —que no lanza— como único
 * síntoma. Desde alpha.5 el nombre es un hash estable del completo, y durante
 * la transición se toman los DOS (un rolling deploy con alpha.4 y alpha.5 no
 * se pisa). El viejo se retira en 2.5.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('alpha.6 · bajo `only` la sonda hereda el ORIGEN del bloqueo: la purga pasa si la anterior espera a un APARCADO, y sigue aplazada si la anterior está pendiente de verdad o bloqueada por un FALLO', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  /**
   * El 🟡 A del auditor de alpha.5 (`alpha5-auditor-final.md`): aparcada `#1
   * moved(unit → o2)`, pendiente `#2 attached(child, unit)` (que en una pasada
   * completa saldría `parked:#1`), y el consumidor releva su borrado con la
   * receta inline: `relayScopeChanges({ only: [#3 detached(unit)] })`. Hasta
   * alpha.6 la rama de la sonda marcaba origen FALLO (`defer(…, false)`) porque
   * desde ahí no sabía si `#2` esperaba a un aparcado ⇒ `deferred/depends-on:#2`
   * y la purga esperaba a una pasada COMPLETA — que un despliegue solo-inline
   * nunca corre. Ahora la sonda hereda el ORIGEN de `#2`: sus claves nombran la
   * aparcada ⇒ origen APARCADO ⇒ el `detached` PASA (invariante 11), y a dos
   * saltos igual (`#2b attached(grandchild, child)` ⇒ `#2` ⇒ `#1`).
   */
  test('EL CASO (auditor 🟡 A): aparcado `moved` → `attached` pendiente (no pedido) → `relay({ only: [detached] })` ⇒ `applied` y purga, a un salto y a dos; un `attached` pedido detrás de esa cadena sigue `deferred` (con origen aparcado)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const o = orgScope()
    const o2 = orgScope()
    const unit = unitScope()
    const child = unitScope()
    const grandchild = unitScope()
    const cousin = unitScope()
    for (const x of [o, o2]) await tree.attach(x, APP_SCOPE)
    await tree.attach(unit, o)
    await tree.attach(child, unit)
    await tree.attach(grandchild, child)
    await tree.attach(cousin, child)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 1 })
    const manager = managerWith({ tree, driver, outbox })

    const { queued: [movedId] } = await manager.scopes.moved(unit, o2)
    driver.onScopeMoved = async () => {
      throw new Error('el padre ya no existe')
    }
    await manager.relayScopeChanges() // #1 ⇒ APARCADA
    assert.deepEqual((await outbox.dead!(10)).map((d) => String(d.id)), [String(movedId)])

    const { queued: [attachedId] } = await manager.scopes.attached(child, unit) // #2, NO se pide
    const { queued: [grandId] } = await manager.scopes.attached(grandchild, child) // #2b, NO se pide
    const { queued: [detachedUnit] } = await manager.scopes.detached(unit) // #3: un salto (#2 ⇒ #1)
    const { queued: [detachedGrand] } = await manager.scopes.detached(grandchild) // #4: dos saltos (#2b ⇒ #2 ⇒ #1)
    const { queued: [cousinId] } = await manager.scopes.attached(cousin, child) // #5: concede ⇒ sigue aplazado

    const report = await manager.relayScopeChanges({ only: [detachedUnit, detachedGrand, cousinId] })
    // La sonda nombra la pendiente MÁS ANTIGUA que comparte clave (`child` ⇒ #2,
    // alpha.5), y bajo `only` las aparcadas no pedidas van en `dead`, no en `entries`.
    assert.deepEqual(
      report.entries.map((e: any) => [String(e.id), e.status, e.reason ?? null]),
      [
        [String(detachedUnit), 'applied', null],
        [String(detachedGrand), 'applied', null],
        [String(cousinId), 'deferred', `depends-on:${attachedId}`],
      ],
      'las DOS purgas pasan bajo only; lo que concede sigue aplazado'
    )
    assert.deepEqual(report.dead.map((d) => String(d.id)), [String(movedId)], '`dead` sigue siendo global')
    assert.deepEqual(
      calls.filter((c) => c.startsWith('purgeScope')),
      [`purgeScope ${keyOf(unit)}`, `purgeScope ${keyOf(grandchild)}`]
    )
    assert.notInclude(calls.join(' | '), 'attached', 'ningún attached se coló fuera de orden')
    assert.deepEqual(report.missing, [])
    // Las no pedidas siguen pendientes, intactas (sin intento consumido).
    const still = await outbox.pending(10)
    assert.deepEqual(still.map((p) => [String(p.id), p.attempts]), [
      [String(attachedId), 0],
      [String(grandId), 0],
      [String(cousinId), 0],
    ])
    // Y la pasada completa sigue diciendo lo mismo: los attached esperan al aparcado.
    const full = await manager.relayScopeChanges()
    assert.deepEqual(full.applied, [])
    assert.deepEqual(full.deferred.map((d) => String(d.id)), [String(attachedId), String(grandId), String(cousinId)])
  })

  test('NEGATIVO 1: la anterior está pendiente DE VERDAD (ni aparcada ni bloqueada) ⇒ el `detached` pedido sigue `deferred/depends-on:` sin purgar; la pasada completa los aplica en orden', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    const child = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    await tree.attach(child, unit)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 5 })
    const manager = managerWith({ tree, driver, outbox })
    const { queued: [attachedId] } = await manager.scopes.attached(child, unit) // #1 pendiente, no pedida
    const { queued: [detachedId] } = await manager.scopes.detached(child) // #2 pedida
    const report = await manager.relayScopeChanges({ only: [detachedId] })
    assert.deepEqual(
      report.entries.map((e: any) => [String(e.id), e.status, e.reason ?? null]),
      [[String(detachedId), 'deferred', `depends-on:${attachedId}`]],
      'una anterior aplicable no es un aparcado: la purga espera su turno'
    )
    assert.notInclude(calls.join(' | '), 'purgeScope')
    const full = await manager.relayScopeChanges()
    assert.deepEqual(full.applied.map((a) => a.change.op), ['attached', 'detached'], 'en orden')
  })

  test('NEGATIVO 2: la anterior está bloqueada por un FALLO real de la pasada (transitivo) ⇒ el `detached` pedido sigue `deferred/depends-on:` sin purgar (3b-2h: el orden entre un attached fallido y la purga manda)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    const child = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    await tree.attach(child, unit)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 5 })
    const manager = managerWith({ tree, driver, outbox })
    const { queued: [unitId] } = await manager.scopes.attached(unit, org) // #1 pedida: FALLA
    const { queued: [childId] } = await manager.scopes.attached(child, unit) // #2 NO pedida: comparte `unit` con #1
    const { queued: [detachedId] } = await manager.scopes.detached(child) // #3 pedida: comparte `child` con #2
    driver.onScopeAttached = async () => {
      throw new Error('el store no acepta la arista todavía')
    }
    const report = await manager.relayScopeChanges({ only: [unitId, detachedId] })
    assert.deepEqual(report.failures.map((f) => String(f.id)), [String(unitId)])
    assert.deepEqual(
      report.entries.filter((e: any) => String(e.id) === String(detachedId)).map((e: any) => [e.status, e.reason]),
      [['deferred', `depends-on:${childId}`]],
      'el origen heredado es un FALLO: contamina también la purga'
    )
    assert.notInclude(calls.join(' | '), 'purgeScope')
  })

  test('README: el párrafo «does not apply yet» desaparece y la regla queda escrita con SUS palabras', async ({ assert }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.notInclude(readme, 'Under `only` the purge exemption does not apply yet')
    assert.include(readme, 'Under `only` the purge exemption holds too')
    assert.include(readme, 'inherits the origin of the block')
  })
})

/**
 * Comparador mínimo de versiones `x.y.z[-alpha.N]` (sin dependencia): estable > prerelease
 * de la misma base; entre prereleases, por el número final. Suficiente para el paquete.
 */
function isVersionAfter(a: string, b: string): boolean {
  const parse = (v: string) => {
    const [base, pre] = v.split('-')
    const nums = base.split('.').map(Number)
    const preNum = pre ? Number(pre.replace(/^[a-z]+\./, '')) : Number.POSITIVE_INFINITY
    return [...nums, preNum]
  }
  const [x, y] = [parse(a), parse(b)]
  for (let i = 0; i < 4; i++) if (x[i] !== y[i]) return x[i] > y[i]
  return false
}

/* ════════════════════════════════════════════════════════════════════════
 * 2.4.0-alpha.8 (panel relay 2; decisiones del dueño 2026-09-10 (4)).
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * **X-1 · una opción desconocida es 500, nunca silencio** (tester §10-d;
 * juez, prerrequisito de `apply` y `waitForLeaseMs`). Medido: hasta alpha.7
 * `requeueScopeChanges(ids, { apply: true })` y `relayScopeChanges({
 * waitForLeaseMs })` se IGNORABAN (objeto literal sin validar): un consumidor
 * en JS —o con `as any`— creía que aplicaba o esperaba cuando no.
 */
test.group('alpha.8 · X-1 — una opción desconocida en `relayScopeChanges`/`requeueScopeChanges` es 500 E_AUTHZ_CONFIG nombrándola (nunca se ignora en silencio)', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  test('relay: `{ waitForLeaseMss: 5 }` (una letra de más) ⇒ 500 nombrando la clave, CERO llamadas al driver y la cola intacta; las conocidas siguen entrando; `null` o una lista tampoco valen', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const manager = managerWith({ tree, driver, outbox })
    await manager.scopes.attached(unit, org)

    for (const bad of [{ waitForLeaseMss: 5 }, { apply: true }, { limit: 1, dryrun: true }]) {
      const error = await rejects(assert, () => manager.relayScopeChanges(bad as any), { status: 500, code: 'E_AUTHZ_CONFIG' }, JSON.stringify(bad))
      const key = Object.keys(bad).find((k) => !['limit', 'batchSize', 'dryRun', 'only'].includes(k))!
      assert.include(error.message, key, 'nombra la clave que no existe')
      assert.include(error.message, 'relayScopeChanges')
    }
    for (const bad of [null, [1], 'x']) {
      await rejects(assert, () => manager.relayScopeChanges(bad as any), { status: 500, code: 'E_AUTHZ_CONFIG' }, String(bad))
    }
    assert.deepEqual(calls, [], 'nada se aplicó con una opción rota')
    assert.lengthOf(await outbox.pending(10), 1, 'la cola sigue intacta')

    const ok = await manager.relayScopeChanges({ dryRun: true, limit: 1, batchSize: 1, only: undefined })
    assert.isTrue(ok.dryRun, 'las conocidas (aun con valor undefined) entran')
  })

  test('requeue: `{ appply: true }` ⇒ 500 nombrando la clave, y la aparcada SIGUE aparcada (cero filas, cero llamadas)', async ({ assert }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 2 })
    const manager = managerWith({ tree, driver, outbox })
    const { queued: [id] } = await manager.scopes.attached(unit, org)
    await outbox.markFailed(id, 'irreparable')
    await outbox.markFailed(id, 'irreparable')
    assert.lengthOf(await outbox.dead!(10), 1)

    const error = await rejects(assert, () => manager.requeueScopeChanges([id], { appply: true } as any), { status: 500, code: 'E_AUTHZ_CONFIG' })
    assert.include(error.message, 'appply')
    assert.include(error.message, 'requeueScopeChanges')
    assert.lengthOf(await outbox.dead!(10), 1, 'sigue aparcada: nada se reencoló')
    assert.deepEqual(await outbox.pending(10), [])
    assert.deepEqual(calls, [])
  })
})

/**
 * **A · la raíz `app` NO es clave de bloqueo** (panel relay 2, cuestión 1;
 * decisión del dueño 2026-09-10 (4)). Medido por los tres panelistas y por
 * COGNITIV: `#changeKeys` devolvía `[hijo, padre]` y el padre de toda alta de
 * tenant es `app`, así que (I) una aparcada `attached(orgA, app)` dejaba el
 * alta de orgB `deferred · parked:` en TODAS las pasadas (5 pasadas con
 * `applied = []`), (II) **sin nada aparcado** dos altas concurrentes con la
 * receta inline dejaban la segunda `deferred · depends-on:` (la raíz era un
 * serializador global del registro), y (III) `requeue` de la aparcada se
 * negaba con un conflicto FALSO (`laterApplied` con la raíz). La raíz no se
 * mueve, no se purga y nunca es hijo (los tres 422 de `manager.spec.ts`
 * —`attached(APP_SCOPE)`, `moved(APP_SCOPE)`, `detached(APP_SCOPE)`—): ningún
 * par de cambios cuyo ÚNICO cruce sea `app` necesita orden (el auditor lo
 * buscó y no lo encontró; `m2-orden.ts`). Por eso se exime, por REF
 * (`isRootRef`, jamás la cadena `'app'`), en los TRES sitios —`#changeKeys`,
 * la lista de `#dependencyOf` (`earlierPending`) y la de `requeueScopeChanges`
 * (`laterApplied`)—, en el MANAGER (el puerto sigue sabiendo buscar por la
 * raíz), también para el bloqueo por FALLO. **Hoy exentarla deja la suite
 * verde en los 4 motores** (tester §0): estos casos son la única red.
 */
test.group('alpha.8 · A — la raíz `app` no es clave de bloqueo, por REF y en los TRES sitios (aparcado, sonda de `only`, anti-reversión del requeue); la clave del HIJO sigue ordenando', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  /** El mundo de COGNITIV: `attached(orgA, app)` APARCADA (el store la rechaza, 422) y el alta de orgB detrás. */
  async function parkedRoot(outboxOf: () => any = () => memoryQueue({ maxAttempts: 2 }).outbox) {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    const { driver, calls } = spyDriver()
    const outbox = outboxOf()
    const manager = managerWith({ tree, driver, outbox })
    const ok = driver.onScopeAttached
    driver.onScopeAttached = async (c: any, p: any) => {
      if (keyOf(c) === keyOf(orgA)) throw Object.assign(new Error('el store rechaza a orgA'), { status: 422 })
      await ok(c, p)
    }
    const { queued: [idA] } = await manager.scopes.attached(orgA, APP_SCOPE)
    await manager.relayScopeChanges()
    await manager.relayScopeChanges()
    precondition(String((await outbox.dead(10))[0]?.id) === String(idA), 'precondición: orgA aparcada')
    const { queued: [idB] } = await manager.scopes.attached(orgB, APP_SCOPE)
    return { tree, manager, driver, calls, outbox, orgA, orgB, idA, idB }
  }
  const precondition = (cond: boolean, msg: string) => {
    if (!cond) throw new Error(msg)
  }
  const statusOf = (report: any, id: any) => {
    const e = report.entries.find((x: any) => String(x.id) === String(id))
    return e ? [e.status, e.reason] : undefined
  }

  test('A-1 (S1 · el síntoma medido): aparcada `attached(orgA, app)` ⇒ el alta de orgB SE APLICA en la primera pasada (hasta alpha.7: `deferred · parked:` en las 5 pasadas)', async ({
    assert,
  }) => {
    const w = await parkedRoot()
    const report = await w.manager.relayScopeChanges()
    assert.deepEqual(report.applied.map((a) => a.id), [w.idB])
    assert.deepEqual(statusOf(report, w.idB), ['applied', undefined])
    assert.include(w.calls, `attached ${keyOf(w.orgB)} → ${keyOf(APP_SCOPE)}`)
    assert.deepEqual(report.dead.map((d) => d.id), [w.idA], 'la aparcada se sigue reportando: exentar la raíz no la olvida')
  })

  test('A-2 (S2 · la receta inline): `only: [idB]` con orgA aparcada ⇒ `applied`, cero `deferred` — contra `memoryQueue` y contra `sqlScopeOutbox` (donde la sonda es SQL); y el array de scopes que va a `earlierPending` NO lleva la raíz (espía)', async ({
    assert,
  }) => {
    const m = await parkedRoot()
    const inline = await m.manager.relayScopeChanges({ only: [m.idB] })
    assert.deepEqual(inline.applied.map((a) => a.id), [m.idB])
    assert.deepEqual(inline.deferred, [])

    const probes: any[][] = []
    const s = await parkedRoot(() => {
      const outbox: any = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 2 })
      const real = outbox.earlierPending.bind(outbox)
      outbox.earlierPending = async (id: any, scopes: any[]) => {
        probes.push(scopes)
        return real(id, scopes)
      }
      return outbox
    })
    const sql = await s.manager.relayScopeChanges({ only: [s.idB] })
    assert.deepEqual(sql.applied.map((a) => String(a.id)), [String(s.idB)], 'el SQL de la sonda casa parent_type=app: la exención tiene que llegar ANTES de la consulta')
    assert.deepEqual(sql.deferred, [])
    assert.include(s.calls, `attached ${keyOf(s.orgB)} → ${keyOf(APP_SCOPE)}`)
    assert.isAtLeast(probes.length, 1, 'la sonda se consultó')
    for (const scopes of probes) {
      assert.isFalse(scopes.some((x) => x.type === 'app'), 'A-8 del tester: la raíz no viaja a earlierPending')
      assert.isAtLeast(scopes.length, 1, 'la lista nunca queda vacía: siempre va el hijo')
    }
  })

  test('A-3 (sin NADA aparcado): dos altas de tenant concurrentes bajo la raíz — la de orgA pendiente y no pedida, la de orgB con `only` ⇒ orgB SE APLICA (hasta alpha.7: `deferred · depends-on:` — la raíz serializaba el registro); con `earlierPending` SQL, con la de memoria y con el respaldo que pagina `pending()`', async ({
    assert,
  }) => {
    for (const outboxOf of [
      () => sqlScopeOutbox({ requireTransaction: false }),
      () => memoryQueue().outbox,
      () => memoryQueue({ probe: false }).outbox,
    ]) {
      await cleanScopeOutbox(db)
      const tree = memoryScopeTree()
      const orgA = orgScope()
      const orgB = orgScope()
      await tree.attach(orgA, APP_SCOPE)
      await tree.attach(orgB, APP_SCOPE)
      const { driver, calls } = spyDriver()
      const manager = managerWith({ tree, driver, outbox: outboxOf() })
      const { queued: [idA] } = await manager.scopes.attached(orgA, APP_SCOPE)
      const { queued: [idB] } = await manager.scopes.attached(orgB, APP_SCOPE)
      const report = await manager.relayScopeChanges({ only: [idB] })
      assert.deepEqual(report.applied.map((a) => String(a.id)), [String(idB)], 'el alta de B no espera al alta de A')
      assert.deepEqual(calls, [`attached ${keyOf(orgB)} → ${keyOf(APP_SCOPE)}`])
      assert.deepEqual((await manager.relayScopeChanges({ dryRun: true })).wouldApply.map((w) => String(w.id)), [String(idA)], 'la de A sigue donde estaba')
    }
  })

  test('A-8 (S3 · la salida del incidente): aparcada `attached(orgA, app)` con `attached(orgB, app)` APLICADA después ⇒ `requeueScopeChanges([idA])` ENTRA sin conflicto (hasta alpha.7: 500 E_AUTHZ_REQUEUE_REFUSED falso, que empujaba a --force); `laterApplied` no recibe la raíz (espía)', async ({
    assert,
  }) => {
    const probes: any[][] = []
    const w = await parkedRoot(() => {
      const outbox: any = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 2 })
      const real = outbox.laterApplied.bind(outbox)
      outbox.laterApplied = async (id: any, scopes: any[], limit: number) => {
        probes.push(scopes)
        return real(id, scopes, limit)
      }
      return outbox
    })
    await w.manager.relayScopeChanges()
    assert.include(w.calls, `attached ${keyOf(w.orgB)} → ${keyOf(APP_SCOPE)}`, 'orgB aplicada DESPUÉS de la aparcada')
    // El operador arregla la causa de orgA y reencola.
    w.driver.onScopeAttached = async (c: any, p: any) => void w.calls.push(`attached ${keyOf(c)} → ${keyOf(p)}`)
    const report = await w.manager.requeueScopeChanges([w.idA])
    assert.deepEqual(report.requeued.map((r) => String(r.id)), [String(w.idA)])
    assert.deepEqual(report.overrides, [], 'ningún conflicto: la única clave común con orgB era la raíz')
    assert.isFalse(report.forced)
    assert.lengthOf(probes, 1)
    assert.isFalse(probes[0].some((x) => x.type === 'app'), 'la raíz no viaja a laterApplied')
    const pass = await w.manager.relayScopeChanges()
    assert.deepEqual(pass.applied.map((a) => String(a.id)), [String(w.idA)], 'y entra a la primera')
  })

  test('A-4 (negativo · la clave del HIJO sigue ordenando): `detached(orgA)` que FALLA + `attached(orgA, app)` con el MISMO uuid ⇒ el attached sigue `deferred · depends-on:<detached>`, cero llamadas de attached', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    await tree.attach(orgA, APP_SCOPE)
    const { driver, calls } = spyDriver()
    const q = memoryQueue()
    const manager = managerWith({ tree, driver, outbox: q.outbox })
    driver.onScopeDetached = async () => {
      throw new Error('la purga falla')
    }
    const { queued: [d] } = await manager.scopes.detached(orgA)
    const { queued: [a] } = await manager.scopes.attached(orgA, APP_SCOPE)
    const report = await manager.relayScopeChanges()
    assert.deepEqual(statusOf(report, d)?.[0], 'failed')
    assert.deepEqual(statusOf(report, a), ['deferred', `depends-on:${d}`], 'restaurar el MISMO uuid espera a su purga: la exención no se lleva por delante la clave del hijo')
    assert.deepEqual(calls.filter((c) => c.startsWith('attached')), [])
  })

  test('A-6 (borde, también para el bloqueo por FALLO): `moved(unit1 → app)` + `attached(unit2, app)` ⇒ los dos se aplican en orden; y si el `moved` FALLA, el `attached` de unit2 se aplica igual (el único cruce era la raíz)', async ({
    assert,
  }) => {
    const build = async () => {
      const tree = memoryScopeTree()
      const org = orgScope()
      const unit1 = unitScope()
      const unit2 = unitScope()
      await tree.attach(org, APP_SCOPE)
      await tree.attach(unit1, org)
      await tree.attach(unit2, APP_SCOPE)
      const { driver, calls } = spyDriver()
      const q = memoryQueue()
      const manager = managerWith({ tree, driver, outbox: q.outbox })
      const { queued: [m] } = await manager.scopes.moved(unit1, APP_SCOPE)
      const { queued: [a] } = await manager.scopes.attached(unit2, APP_SCOPE)
      return { manager, driver, calls, unit1, unit2, m, a }
    }
    const ok = await build()
    const both = await ok.manager.relayScopeChanges()
    assert.deepEqual(both.applied.map((x) => x.id), [ok.m, ok.a])
    assert.deepEqual(ok.calls, [`moved ${keyOf(ok.unit1)} → ${keyOf(APP_SCOPE)}`, `attached ${keyOf(ok.unit2)} → ${keyOf(APP_SCOPE)}`])

    const bad = await build()
    bad.driver.onScopeMoved = async () => {
      throw new Error('el store rechaza el moved')
    }
    const report = await bad.manager.relayScopeChanges()
    assert.deepEqual(statusOf(report, bad.m)?.[0], 'failed')
    assert.deepEqual(statusOf(report, bad.a), ['applied', undefined], 'un fallo bajo la raíz no contamina a otra arista bajo la raíz (decidido: una sola regla, también para el fallo)')
    assert.deepEqual(bad.calls, [`attached ${keyOf(bad.unit2)} → ${keyOf(APP_SCOPE)}`])
  })

  test('A-7 (negativo · mata al mutante «exención por op» o «vaciar las claves»): `moved(unit1 → app)` que FALLA + `moved(unit1 → orgB)` ⇒ la segunda sigue `deferred · depends-on:` por la clave `unit|1`', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const unit1 = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(unit1, orgA)
    const { driver, calls } = spyDriver()
    const q = memoryQueue()
    const manager = managerWith({ tree, driver, outbox: q.outbox })
    driver.onScopeMoved = async () => {
      throw new Error('el store rechaza el moved')
    }
    const { queued: [m1] } = await manager.scopes.moved(unit1, APP_SCOPE)
    await tree.attach(unit1, APP_SCOPE)
    const { queued: [m2] } = await manager.scopes.moved(unit1, orgB)
    const report = await manager.relayScopeChanges()
    assert.deepEqual(statusOf(report, m1)?.[0], 'failed')
    assert.deepEqual(statusOf(report, m2), ['deferred', `depends-on:${m1}`])
    assert.deepEqual(calls, [])
  })

  test('A-9 (letra): el README y `CLAUDE.md` dicen POR QUÉ la raíz no es clave —no se mueve, no se purga, nunca es hijo— y la frase vieja del contrato («dos attached bajo app se contaminan») ya no existe', async ({
    assert,
  }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, 'The root `app` is not a scope key')
    assert.include(readme, 'never moves, is never purged and is never a child')
    const guide = await readFile(new URL('../CLAUDE.md', import.meta.url), 'utf8')
    assert.notInclude(guide, 'la raíz `app` también es clave')
    assert.include(guide, 'la raíz `app` NO es clave')
  })
})

/**
 * **Variante B · el censo de aparcadas siembra SOLO la clave del HIJO** (juez,
 * cuestión 2; dueño: SÍ). Principio: una entrada aparcada dice que la
 * POSICIÓN DE SU HIJO en el store es incorrecta; no dice nada de su padre
 * nuevo. Medido (`m7-tapon.ts`): con `moved(unit → orgA)` aparcada, un
 * `attached(otraUnit, orgA)` quedaba `deferred · parked:` sin motivo (orgA no
 * está tocada por el fallo: las dos aristas conmutan) y el store conservaba
 * el padre VIEJO de todo lo que colgara de orgA. Vive SOLO en la siembra
 * (`#parkedKeys`), jamás en `#changeKeys`: al COMPARAR van siempre las dos
 * claves (si no, el respaldo de la sonda pierde el caso 1136 — trampa
 * medida por el juez).
 */
test.group('alpha.8 · variante B — el censo de aparcadas siembra solo la clave del HIJO (solo en `#parkedKeys`; al comparar van las dos claves)', () => {
  /** Aparca `moved(unit → orgA)`: el store rechaza el moved de `unit`. */
  async function parkedMove() {
    const tree = memoryScopeTree()
    const orgV = orgScope()
    const orgA = orgScope()
    const unit = unitScope()
    await tree.attach(orgV, APP_SCOPE)
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(unit, orgV)
    const { driver, calls } = spyDriver()
    const q = memoryQueue({ maxAttempts: 2 })
    const manager = managerWith({ tree, driver, outbox: q.outbox })
    const ok = driver.onScopeMoved
    driver.onScopeMoved = async (c: any, p: any) => {
      if (keyOf(c) === keyOf(unit)) throw Object.assign(new Error('el store rechaza el moved de unit'), { status: 422 })
      await ok(c, p)
    }
    const { queued: [parkedId] } = await manager.scopes.moved(unit, orgA)
    await tree.attach(unit, orgA)
    await manager.relayScopeChanges()
    await manager.relayScopeChanges()
    if (String((await q.outbox.dead(10))[0]?.id) !== String(parkedId)) throw new Error('precondición: el moved aparcado')
    calls.length = 0
    return { tree, manager, driver, calls, q, orgA, orgV, unit, parkedId }
  }
  const statusOf = (report: any, id: any) => {
    const e = report.entries.find((x: any) => String(x.id) === String(id))
    return e ? [e.status, e.reason] : undefined
  }

  test('EL CASO (m7): con `moved(unit → orgA)` aparcada, `moved(otraUnit → orgA)` SE APLICA (hasta alpha.7: `parked:`); `attached(child, unit)` y `moved(unit → orgC)` siguen `deferred · parked:<id>` (la posición de unit es incorrecta); `detached(unit)` se aplica (invariante 11)', async ({
    assert,
  }) => {
    const w = await parkedMove()
    const otra = unitScope()
    const child = unitScope()
    const orgC = orgScope()
    await w.tree.attach(otra, w.orgV)
    await w.tree.attach(child, w.unit)
    await w.tree.attach(orgC, APP_SCOPE)
    const { queued: [m] } = await w.manager.scopes.moved(otra, w.orgA)
    const { queued: [a] } = await w.manager.scopes.attached(child, w.unit)
    const { queued: [c] } = await w.manager.scopes.moved(w.unit, orgC)
    const { queued: [d] } = await w.manager.scopes.detached(w.unit)
    const report = await w.manager.relayScopeChanges()
    assert.deepEqual(statusOf(report, m), ['applied', undefined], 'orgA no está tocada por el fallo: las dos aristas conmutan')
    assert.deepEqual(statusOf(report, a), ['deferred', `parked:${w.parkedId}`], 'colgar de unit sería colgar del padre VIEJO (caso 1136)')
    assert.deepEqual(statusOf(report, c), ['deferred', `depends-on:${a}`], 'recolgar unit espera a que alguien mire la aparcada (transitivo: detrás del attached que ya espera por `unit`)')
    assert.deepEqual(statusOf(report, d), ['applied', undefined], 'una purga nunca espera a un aparcado')
    assert.deepEqual(w.calls.filter((c) => !c.startsWith('purgeScope')), [`moved ${keyOf(otra)} → ${keyOf(w.orgA)}`, `detached ${keyOf(w.unit)}`])
  })

  test('NEGATIVO (el 🔴 1 del auditor, sobre supersede, sigue cubierto): `#1 moved(unit → orgA)` APARCADA, `#2 attached(child, unit)`, `#3 moved(unit → orgB)` ⇒ #2 `deferred · parked:1` y #3 `deferred · depends-on:2` en todas las pasadas; el store no ve a child', async ({
    assert,
  }) => {
    const w = await parkedMove()
    const child = unitScope()
    const orgB = orgScope()
    await w.tree.attach(child, w.unit)
    await w.tree.attach(orgB, APP_SCOPE)
    const { queued: [a] } = await w.manager.scopes.attached(child, w.unit)
    const { queued: [b] } = await w.manager.scopes.moved(w.unit, orgB)
    for (let i = 0; i < 3; i++) {
      const report = await w.manager.relayScopeChanges()
      assert.deepEqual(statusOf(report, a), ['deferred', `parked:${w.parkedId}`], '#2 espera a la aparcada por la clave `unit` (su hijo)')
      assert.deepEqual(statusOf(report, b), ['deferred', `depends-on:${a}`], '#3 espera detrás de #2 (transitivo; el origen sigue siendo el aparcado)')
      assert.deepEqual(report.dead.map((x) => x.id), [w.parkedId])
    }
    assert.deepEqual(w.calls, [], 'fail-CLOSED: child no existe en el store, en vez de colgar de unit → orgV')
  })

  test('mata al mutante «variante B metida en `#changeKeys`»: al COMPARAR van las dos claves — `attached(org, app)` pendiente de verdad (no pedida) retiene `only: [attached(unit, org)]` también con el respaldo que pagina `pending()`; y si `attached(org, app)` FALLA, `attached(unit, org)` sigue `deferred` en la pasada completa (caso 1136)', async ({
    assert,
  }) => {
    for (const probe of [false, true]) {
      const tree = memoryScopeTree()
      const org = orgScope()
      const unit = unitScope()
      await tree.attach(org, APP_SCOPE)
      await tree.attach(unit, org)
      const { driver, calls } = spyDriver()
      const q = memoryQueue({ probe })
      const manager = managerWith({ tree, driver, outbox: q.outbox })
      const { queued: [o] } = await manager.scopes.attached(org, APP_SCOPE)
      const { queued: [u] } = await manager.scopes.attached(unit, org)
      const inline = await manager.relayScopeChanges({ only: [u] })
      assert.deepEqual(statusOf(inline, u), ['deferred', `depends-on:${o}`], `probe=${probe}: el hijo no cuelga de un padre que no está en el store`)
      assert.deepEqual(calls, [])
    }
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const q = memoryQueue()
    const manager = managerWith({ tree, driver, outbox: q.outbox })
    driver.onScopeAttached = async (c: any) => {
      if (keyOf(c) === keyOf(org)) throw new Error('el store rechaza a org')
      calls.push(`attached ${keyOf(c)}`)
    }
    const { queued: [o] } = await manager.scopes.attached(org, APP_SCOPE)
    const { queued: [u] } = await manager.scopes.attached(unit, org)
    const full = await manager.relayScopeChanges()
    assert.deepEqual(statusOf(full, o)?.[0], 'failed')
    assert.deepEqual(statusOf(full, u), ['deferred', `depends-on:${o}`])
    assert.deepEqual(calls, [])
  })
})

/**
 * **B · `requeueScopeChanges(ids, { apply: true })`** (panel relay 2, cuestión
 * 4; decisión del dueño 2026-09-10 (4)). Medido (tester P14): tras `requeue`
 * la reencolada vuelve con su id ORIGINAL (menor) y la siguiente pasada
 * `only` del tenant sale `deferred · depends-on:` — el incidente no se cerraba
 * con un comando; hacía falta una pasada completa detrás. Con `apply` se
 * reencola y se releva SOLO eso en la MISMA llamada, con cuatro condiciones
 * bloqueantes: (1) sin lease propio —el lease se toma UNA vez para toda la
 * llamada; tomarlo dos veces era `busy` en verde (auditor 🟠 5)—; (2) PASA la
 * barrera del freeze (con `apply` escribe el árbol); (3) excluyente con
 * `force` (500 juntos: con las dos, revertir el árbol era una sola llamada,
 * auditor 🟠 6); (4) el `only` lo construye el método = exactamente los ids
 * reencolados (los dependientes quedan `deferred` y se dice). Lease tomado
 * ⇒ `relay.busy`, CERO filas reencoladas, el comando sale ≠ 0 (todo o nada:
 * «reencolo y digo busy» dejaba una entrada con `attempts = max − 1` que se
 * volvía a aparcar y contaminaba su clave otra vez).
 */
test.group('alpha.8 · B — `requeueScopeChanges(ids, { apply: true })`: reencola y releva SOLO eso en la misma llamada, bajo UN lease, pasando el freeze, sin `force`', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  /** Espía sobre `acquire` de una `sqlScopeOutbox` real: cuenta las adquisiciones. */
  function spiedOutbox(options: { maxAttempts?: number } = {}) {
    const outbox: any = sqlScopeOutbox({ requireTransaction: false, ...options })
    let acquisitions = 0
    const real = outbox.acquire.bind(outbox)
    outbox.acquire = async () => {
      acquisitions += 1
      return real()
    }
    return { outbox, acquisitions: () => acquisitions }
  }

  /** El mundo de P14: `attached(unit, org)` APARCADA (2 fallos de entrada) y `attached(child, unit)` pendiente detrás. */
  async function p14() {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    const child = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    await tree.attach(child, unit)
    const { driver, calls } = spyDriver()
    const { outbox, acquisitions } = spiedOutbox({ maxAttempts: 2 })
    const manager = managerWith({ tree, driver, outbox })
    const ok = driver.onScopeAttached
    let broken = true
    driver.onScopeAttached = async (c: any, p: any) => {
      if (broken && keyOf(c) === keyOf(unit)) throw Object.assign(new Error('el padre no existía'), { status: 422 })
      await ok(c, p)
    }
    const { queued: [idUnit] } = await manager.scopes.attached(unit, org)
    const { queued: [idChild] } = await manager.scopes.attached(child, unit)
    await manager.relayScopeChanges()
    await manager.relayScopeChanges()
    if (String((await outbox.dead(10))[0]?.id) !== String(idUnit)) throw new Error('precondición: la unit aparcada')
    calls.length = 0
    return { tree, manager, driver, calls, outbox, acquisitions, org, unit, child, idUnit, idChild, fix: () => void (broken = false) }
  }
  const statusOf = (report: any, id: any) => {
    const e = report.entries.find((x: any) => String(x.id) === String(id))
    return e ? [e.status, e.reason] : undefined
  }

  test('R-1/R-2 (P14): el operador arregla la causa y `{ apply: true }` cierra el incidente en UNA llamada: la aparcada se aplica ahí mismo (`report.relay.applied`), con EXACTAMENTE UNA adquisición del lease; el `only` del tenant sale después `applied`; el dependiente NO se arrastra (queda pendiente, y se dice)', async ({
    assert,
  }) => {
    const w = await p14()
    w.fix()
    const before = w.acquisitions()
    const report = await w.manager.requeueScopeChanges([w.idUnit], { apply: true })
    assert.equal(w.acquisitions() - before, 1, 'R-2: un solo lease para toda la llamada (dos = busy en verde, auditor 🟠 5)')
    assert.deepEqual(report.requeued.map((r) => String(r.id)), [String(w.idUnit)])
    assert.deepEqual(report.overrides, [])
    assert.isFalse(report.forced)
    assert.isDefined(report.relay, 'el reporte del relay interno viaja en `relay`')
    assert.isFalse(report.relay!.busy)
    assert.deepEqual(report.relay!.applied.map((a) => String(a.id)), [String(w.idUnit)], 'aplicada en la misma llamada')
    assert.deepEqual(w.calls, [`attached ${keyOf(w.unit)} → ${keyOf(w.org)}`])
    assert.deepEqual(report.relay!.missing, [])
    assert.deepEqual(await w.outbox.dead(10), [], 'ya no está aparcada')
    assert.deepEqual((await w.outbox.pending(10)).map((p: any) => String(p.id)), [String(w.idChild)], 'R-3 reescrito: el dependiente NO se arrastra (`only` = los ids reencolados, nunca más)')
    assert.isTrue(report.relay!.remaining, 'y el reporte lo dice')

    // La llamada `only` del tenant (su recibo) ya no ve nada delante.
    const inline = await w.manager.relayScopeChanges({ only: [w.idChild] })
    assert.deepEqual(inline.applied.map((a) => String(a.id)), [String(w.idChild)])
    assert.deepEqual(w.calls, [`attached ${keyOf(w.unit)} → ${keyOf(w.org)}`, `attached ${keyOf(w.child)} → ${keyOf(w.unit)}`])
  })

  test('R-4 (anti-reversión, por la razón correcta): una aparcada con una APLICADA posterior de su clave + `{ apply: true }` ⇒ 500 E_AUTHZ_REQUEUE_REFUSED, CERO filas tocadas, CERO llamadas al driver — y el lease se suelta (la pasada siguiente no es `busy`)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgB = orgScope()
    const orgC = orgScope()
    const unit = unitScope()
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(orgC, APP_SCOPE)
    await tree.attach(unit, orgC)
    const { driver, calls } = spyDriver()
    const { outbox } = spiedOutbox({ maxAttempts: 2 })
    const manager = managerWith({ tree, driver, outbox })
    const viejo = (await outbox.enqueue({ op: 'moved', child: unit, parent: orgB }, {})).id
    await outbox.markFailed(viejo, 'x')
    await outbox.markFailed(viejo, 'x')
    const nuevo = (await outbox.enqueue({ op: 'moved', child: unit, parent: orgC }, {})).id
    await outbox.markApplied(nuevo)

    await rejects(assert, () => manager.requeueScopeChanges([viejo], { apply: true }), { status: 500, code: 'E_AUTHZ_REQUEUE_REFUSED' })
    assert.deepEqual(calls, [], 'la sonda corre ANTES de reencolar y de aplicar')
    assert.deepEqual((await outbox.dead(10)).map((d: any) => String(d.id)), [String(viejo)], 'sigue aparcada: cero filas')
    const next = await manager.relayScopeChanges()
    assert.isFalse(next.busy, 'el lease se soltó al negarse')
  })

  test('R-5: `{ apply: true, force: true }` ⇒ 500 E_AUTHZ_CONFIG nombrando las dos, sin tomar el lease, cero filas (con las dos, revertir el árbol sería UNA llamada)', async ({
    assert,
  }) => {
    const w = await p14()
    const before = w.acquisitions()
    const error = await rejects(assert, () => w.manager.requeueScopeChanges([w.idUnit], { apply: true, force: true }), { status: 500, code: 'E_AUTHZ_CONFIG' })
    assert.include(error.message, 'apply')
    assert.include(error.message, 'force')
    assert.equal(w.acquisitions() - before, 0)
    assert.deepEqual((await w.outbox.dead(10)).map((d: any) => String(d.id)), [String(w.idUnit)])
    assert.deepEqual(w.calls, [])
  })

  test('R-8 (freeze): con el freeze durable vivo, `{ apply: true }` ⇒ 503 E_AUTHZ_FROZEN ANTES de tocar nada: nada reencolado, cero leases, cero llamadas; sin `apply`, `requeue` sigue sin pasar por la barrera (no escribe en el backend)', async ({
    assert,
  }) => {
    const w = await p14()
    w.fix()
    const token = await w.manager.freeze('cutover a openfga')
    try {
      const before = w.acquisitions()
      await rejects(assert, () => w.manager.requeueScopeChanges([w.idUnit], { apply: true }), { status: 503, code: 'E_AUTHZ_FROZEN' })
      assert.equal(w.acquisitions() - before, 0)
      assert.deepEqual((await w.outbox.dead(10)).map((d: any) => String(d.id)), [String(w.idUnit)], 'sigue aparcada')
      assert.deepEqual(w.calls, [])
      // Sin apply no se escribe el árbol: la barrera no aplica (como hasta ahora).
      const plain = await w.manager.requeueScopeChanges([w.idUnit])
      assert.deepEqual(plain.requeued.map((r) => String(r.id)), [String(w.idUnit)])
      assert.isUndefined(plain.relay)
    } finally {
      await w.manager.unfreeze(token)
    }
  })

  test('R-2b (lease tomado por otra pasada): `{ apply: true }` ⇒ `relay.busy`, `requeued: []`, la aparcada SIGUE aparcada (cero filas) y cero llamadas; soltado el lease, entra', async ({
    assert,
  }) => {
    const w = await p14()
    w.fix()
    const lease = await w.outbox.acquire()
    assert.isNotNull(lease)
    try {
      const report = await w.manager.requeueScopeChanges([w.idUnit], { apply: true })
      assert.isTrue(report.relay?.busy)
      assert.deepEqual(report.requeued, [], 'todo o nada: reencolar y decir busy dejaría attempts = max − 1 y se volvería a aparcar contaminando su clave')
      assert.deepEqual((await w.outbox.dead(10)).map((d: any) => String(d.id)), [String(w.idUnit)])
      assert.deepEqual(w.calls, [])
    } finally {
      await lease!.release()
    }
    const report = await w.manager.requeueScopeChanges([w.idUnit], { apply: true })
    assert.isFalse(report.relay!.busy)
    assert.deepEqual(report.relay!.applied.map((a) => String(a.id)), [String(w.idUnit)])
  })

  test('R-6/R-7: si la causa sigue rota, la misma llamada la vuelve a APARCAR (fallo de entrada: `attempts` max − 1 → max) y el reporte lo dice; un 503 del store la deja PENDIENTE con `attempts = max − 1` (transitorio, no consume intento)', async ({
    assert,
  }) => {
    const w = await p14()
    const report = await w.manager.requeueScopeChanges([w.idUnit], { apply: true })
    assert.deepEqual(statusOf(report.relay, w.idUnit)?.[0], 'failed')
    assert.deepEqual((await w.outbox.dead(10)).map((d: any) => String(d.id)), [String(w.idUnit)], 'vuelve a dead() en la misma llamada')

    await cleanScopeOutbox(db)
    const v = await p14()
    v.driver.onScopeAttached = async () => {
      throw new AuthorizationBackendError('spy', 'onScopeAttached', new Error('ECONNREFUSED'))
    }
    const transient = await v.manager.requeueScopeChanges([v.idUnit], { apply: true })
    assert.deepEqual(statusOf(transient.relay, v.idUnit)?.[0], 'failed')
    assert.isTrue(transient.relay!.failures[0]?.transient)
    assert.deepEqual(await v.outbox.dead(10), [], 'no vuelve a aparcarse por un 503')
    const [again] = await v.outbox.pending(10)
    assert.equal(String(again.id), String(v.idUnit))
    assert.equal(again.attempts, 1, 'max − 1: el 503 no consumió el intento')
  })

  test('R-10 (comando): `authz:scopes:requeue` declara `--apply` (explícito, jamás por defecto) y `--wait-lease-ms`; `requeueLines` con `relay`: aplicada ⇒ limpio, `busy` ⇒ error y exit ≠ 0, fallida ⇒ exit ≠ 0', async ({ assert }) => {
    const commands: any = await import('../commands/main.js')
    const Requeue = commands.AuthzScopesRequeue
    const nombres = flagNamesOf(Requeue)
    assert.includeMembers(nombres, ['id', 'force', 'apply', 'wait-lease-ms'])
    const source = await readFile(new URL('../commands/authz_scopes_requeue.ts', import.meta.url), 'utf8')
    assert.include(source, 'apply: this.apply === true', 'explícito: el default del comando no escribe en el backend')

    const { requeueLines } = await import('../commands/authz_scopes_requeue.js')
    const unit = unitScope()
    const org = orgScope()
    const parked: any = { id: 1, change: { op: 'attached', child: unit, parent: org }, attempts: 5, lastError: 'el padre no existía' }
    const base = (relay: any) => ({ requeued: [parked], overrides: [], forced: false, relay })
    const relay = (over: any) => ({ applied: [], failed: null, failures: [], deferred: [], dead: [], busy: false, remaining: false, dryRun: false, wouldApply: [], entries: [], missing: [], ...over })

    const ok = requeueLines({ report: base(relay({ applied: [{ id: 1, change: parked.change }], entries: [{ id: 1, change: parked.change, status: 'applied' }] })) as any })
    assert.isTrue(ok.clean)
    assert.include(ok.lines.map((l) => l.message).join('\n'), 'aplicada')

    const busy = requeueLines({ report: { requeued: [], overrides: [], forced: false, relay: relay({ busy: true }) } as any })
    assert.isFalse(busy.clean, 'busy no es verde')
    assert.include(busy.lines.map((l) => l.message).join('\n'), 'lease')
    assert.include(busy.lines.map((l) => l.message).join('\n'), '--apply')
    assert.isTrue(busy.lines.some((l) => l.level === 'error'))

    const failed = requeueLines({
      report: base(relay({ failed: { id: 1, change: parked.change, error: 'sigue rota', transient: false }, failures: [{ id: 1, change: parked.change, error: 'sigue rota', transient: false }], entries: [{ id: 1, change: parked.change, status: 'failed', reason: 'sigue rota' }] })) as any,
    })
    assert.isFalse(failed.clean, 'la causa sigue rota: el comando lo dice y sale ≠ 0')
    assert.include(failed.lines.map((l) => l.message).join('\n'), 'sigue rota')
  })
})

/**
 * **B · `waitForLeaseMs`** (panel relay 2, cuestión 7; default 0 obligatorio:
 * `scope_outbox.spec.ts` «dos pasadas a la vez ⇒ busy» no puede cambiar).
 * Espera acotada reintentando `acquire()` cada `RELAY_LEASE_POLL_MS` hasta el
 * tope; `busy` al vencer, jamás un cuelgue. Exige pool ≥ 2 (README): con pool 1
 * el que espera puede estar reteniendo la conexión del que tiene el lease.
 */
test.group('alpha.8 · B — `relayScopeChanges({ waitForLeaseMs })`: espera acotada por el lease (default 0 = el `busy` inmediato de siempre)', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  function spiedOutbox() {
    const outbox: any = sqlScopeOutbox({ requireTransaction: false })
    let acquisitions = 0
    const real = outbox.acquire.bind(outbox)
    outbox.acquire = async () => {
      acquisitions += 1
      return real()
    }
    return { outbox, acquisitions: () => acquisitions }
  }

  test('W-1: dos pasadas a la vez con `waitForLeaseMs: 5000` en la segunda ⇒ la segunda ESPERA, entra al soltar la primera y aplica lo que quedó (`busy: false`, ≥ 2 adquisiciones)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit1 = unitScope()
    const unit2 = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit1, org)
    await tree.attach(unit2, org)
    const { driver, calls } = spyDriver()
    const { outbox, acquisitions } = spiedOutbox()
    const manager = managerWith({ tree, driver, outbox })
    driver.onScopeAttached = async (c: any, p: any) => {
      await new Promise((r) => setTimeout(r, 120))
      calls.push(`attached ${keyOf(c)} → ${keyOf(p)}`)
    }
    const { queued: [id1] } = await manager.scopes.attached(unit1, org)
    const { queued: [id2] } = await manager.scopes.attached(unit2, org)

    const [primera, segunda] = await Promise.all([
      manager.relayScopeChanges({ limit: 1 }),
      new Promise((r) => setTimeout(r, 10)).then(() => manager.relayScopeChanges({ waitForLeaseMs: 5000 })),
    ])
    assert.isFalse(primera.busy)
    assert.deepEqual(primera.applied.map((a) => String(a.id)), [String(id1)])
    assert.isFalse((segunda as any).busy, 'la segunda no se rinde: espera')
    assert.deepEqual((segunda as any).applied.map((a: any) => String(a.id)), [String(id2)], 'y aplica lo que la primera dejó')
    assert.isAtLeast(acquisitions(), 3, 'la primera + al menos dos intentos de la segunda')
    assert.deepEqual(calls, [`attached ${keyOf(unit1)} → ${keyOf(org)}`, `attached ${keyOf(unit2)} → ${keyOf(org)}`], 'cada cambio UNA vez, en orden')
  })

  test('W-2 (el default): sin `waitForLeaseMs` —o con 0— y el lease tomado ⇒ `busy` INMEDIATO con exactamente UNA adquisición (el caso «dos pasadas a la vez ⇒ busy» no cambia)', async ({ assert }) => {
    const tree = memoryScopeTree()
    const { driver } = spyDriver()
    const { outbox, acquisitions } = spiedOutbox()
    const manager = managerWith({ tree, driver, outbox })
    const lease = await outbox.acquire()
    try {
      for (const options of [{}, { waitForLeaseMs: 0 }]) {
        const before = acquisitions()
        const report = await manager.relayScopeChanges(options)
        assert.isTrue(report.busy)
        assert.equal(acquisitions() - before, 1, `${JSON.stringify(options)}: un intento y busy`)
      }
    } finally {
      await lease.release()
    }
  })

  test('W-3 (vencimiento): un lease que nunca cede + `waitForLeaseMs: 120` ⇒ `busy` tras esperar, con los intentos acotados (nunca un cuelgue); valores inválidos (negativo, no entero, cadena) ⇒ 500 E_AUTHZ_CONFIG sin tocar el lease', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const { driver } = spyDriver()
    const { outbox, acquisitions } = spiedOutbox()
    const manager = managerWith({ tree, driver, outbox })
    const lease = await outbox.acquire()
    try {
      const before = acquisitions()
      const started = Date.now()
      const report = await manager.relayScopeChanges({ waitForLeaseMs: 120 })
      const elapsed = Date.now() - started
      assert.isTrue(report.busy)
      const attempts = acquisitions() - before
      assert.isAtLeast(attempts, 2, 'reintentó')
      assert.isAtMost(attempts, 120 / RELAY_LEASE_POLL_MS + 2, 'acotado por el sondeo')
      assert.isAtLeast(elapsed, 100, 'esperó (casi) el tope')
      assert.isBelow(elapsed, 2000, 'y no se colgó')
      for (const bad of [-1, 1.5, 'x', Number.NaN]) {
        const b = acquisitions()
        await rejects(assert, () => manager.relayScopeChanges({ waitForLeaseMs: bad as any }), { status: 500, code: 'E_AUTHZ_CONFIG' }, String(bad))
        assert.equal(acquisitions() - b, 0)
      }
    } finally {
      await lease.release()
    }
  })

  test('letra: el README dice que `waitForLeaseMs` es opt-in (default 0), que sondea y vence en `busy`, y que exige pool ≥ 2; el comando `authz:scopes:relay` declara `--wait-lease-ms`', async ({ assert }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, 'waitForLeaseMs')
    assert.include(readme, 'pool of at least 2')
    const commands: any = await import('../commands/main.js')
    const nombres = flagNamesOf(commands.AuthzScopesRelay)
    assert.includeMembers(nombres, ['wait-lease-ms'])
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * **alpha.8 · E — la EDAD de la cola** (panel relay 2, cuestión 5; decisión
 * del dueño 2026-09-10 (4)). El rojo es el B2 del auditor de COGNITIV: con
 * el store caído, diez pasadas seguidas dicen `attempts = 0` (un 503 no
 * consume intento, alpha.5), `dead = 0` y NADA de tiempo — el cron está en
 * rojo por `failures`, pero nadie sabe desde cuándo. La alarma es la edad de
 * la CABEZA global de la cola (`pending(1)`, que la pasada ya hacía al final),
 * medida con el reloj INYECTABLE del manager (`tests/clock.spec.ts` caza
 * cualquier `Date.now()` en `src/`), y `--max-age` en el comando.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('alpha.8 · E — la edad de la cola: `report.queue.{oldestPendingAt, pendingAgeMs}` global (también bajo `only`), con el reloj inyectable; terceros sin `createdAt` ⇒ null', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  /** Un reloj de pared que solo avanza cuando el caso lo dice (segundos enteros: MySQL `TIMESTAMP(0)`). */
  function clockAt(iso: string) {
    let nowMs = new Date(iso).getTime()
    return { now: () => new Date(nowMs), advance: (ms: number) => void (nowMs += ms), ms: () => nowMs }
  }
  /** El driver espía con `withClock` (el manager lo exige cuando `config.clock` está declarado). */
  function clockedSpy() {
    const spy = spyDriver()
    spy.driver.withClock = function () {
      return this
    }
    return spy
  }

  test('EL ROJO (B2 de COGNITIV): diez pasadas con el store caído ⇒ `attempts` 0, `dead` 0, `deadCount` 0… y la EDAD crece entre pasadas con el reloj inyectado (`oldestPendingAt` = el `created_at` de la cabeza, `pendingAgeMs` = ahora − ese instante)', async ({
    assert,
  }) => {
    const clock = clockAt('2026-09-10T10:00:00Z')
    const t0 = clock.ms()
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver } = clockedSpy()
    const outbox = sqlScopeOutbox({ requireTransaction: false, now: clock.now })
    const manager = managerWith({ tree, driver, outbox, clock: clock.now })
    await manager.scopes.attached(unit, org)
    driver.onScopeAttached = async () => {
      throw new AuthorizationBackendError('openfga', 'write', new Error('ECONNREFUSED'))
    }
    for (let pass = 1; pass <= 10; pass++) {
      clock.advance(60_000)
      const report = await manager.relayScopeChanges()
      assert.lengthOf(report.failures, 1, `pasada ${pass}`)
      assert.isTrue(report.failures[0].transient)
      assert.deepEqual(report.dead, [])
      assert.equal(report.deadCount, 0, 'el contador GLOBAL de aparcadas, siempre presente')
      assert.deepEqual((await outbox.pending(1)).map((p) => p.attempts), [0], 'un 503 no consume intento (alpha.5)')
      assert.instanceOf(report.queue.oldestPendingAt, Date, `pasada ${pass}: la cabeza de la cola tiene fecha`)
      assert.equal(report.queue.oldestPendingAt!.getTime(), t0, 'es el `created_at` de la entrada, sellado con el reloj de quien encoló')
      assert.equal(report.queue.pendingAgeMs, pass * 60_000, `pasada ${pass}: la edad crece con el reloj del manager, sin dormir`)
    }
  })

  test('bajo `only` la edad sigue siendo GLOBAL: la cabeza es la pendiente más antigua de OTRO tenant, no la pedida', async ({ assert }) => {
    const clock = clockAt('2026-09-10T10:00:00Z')
    const t0 = clock.ms()
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const unitA = unitScope()
    const unitB = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(unitA, orgA)
    await tree.attach(unitB, orgB)
    const { driver } = clockedSpy()
    const outbox = sqlScopeOutbox({ requireTransaction: false, now: clock.now })
    const manager = managerWith({ tree, driver, outbox, clock: clock.now })
    await manager.scopes.attached(unitA, orgA) // el backlog ajeno, en t0
    clock.advance(30_000)
    const { queued: [mine] } = await manager.scopes.attached(unitB, orgB) // lo mío, en t0 + 30 s
    clock.advance(10_000)
    const report = await manager.relayScopeChanges({ only: [mine] })
    assert.deepEqual(report.entries.map((e) => e.status), ['applied'])
    assert.equal(report.queue.oldestPendingAt!.getTime(), t0, 'la cabeza global sigue siendo la de orgA')
    assert.equal(report.queue.pendingAgeMs, 40_000)
    assert.isTrue(report.remaining)
  })

  test('bordes: cola vacía ⇒ `{ null, null }`; solo APARCADAS ⇒ `{ null, null }` (lo aparcado tiene su propia alarma, `deadCount`); un `created_at` en el FUTURO (skew entre réplicas) ⇒ edad 0, nunca negativa', async ({
    assert,
  }) => {
    const clock = clockAt('2026-09-10T10:00:00Z')
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver } = clockedSpy()
    const outbox = sqlScopeOutbox({ requireTransaction: false, now: clock.now, maxAttempts: 1 })
    const manager = managerWith({ tree, driver, outbox, clock: clock.now })

    const empty = await manager.relayScopeChanges()
    assert.deepEqual(empty.queue, { oldestPendingAt: null, pendingAgeMs: null })
    assert.equal(empty.deadCount, 0)

    await manager.scopes.attached(unit, org)
    driver.onScopeAttached = async () => {
      throw new Error('irreparable')
    }
    clock.advance(5_000)
    const parkedPass = await manager.relayScopeChanges() // aparca (maxAttempts 1)
    assert.lengthOf(parkedPass.failures, 1)
    const onlyParked = await manager.relayScopeChanges()
    assert.equal(onlyParked.deadCount, 1)
    assert.deepEqual(onlyParked.queue, { oldestPendingAt: null, pendingAgeMs: null }, 'solo aparcadas: nada PENDIENTE que envejezca')

    // Skew: otra réplica encoló con su reloj adelantado 1 h.
    const ahead = sqlScopeOutbox({ requireTransaction: false, now: () => new Date(clock.ms() + 3_600_000) })
    const other = unitScope()
    await tree.attach(other, org)
    await ahead.enqueue({ op: 'attached', child: other, parent: org }, {})
    driver.onScopeAttached = async () => {
      throw new AuthorizationBackendError('openfga', 'write', new Error('caído'))
    }
    const skewed = await manager.relayScopeChanges()
    assert.equal(skewed.queue.oldestPendingAt!.getTime(), clock.ms() + 3_600_000)
    assert.equal(skewed.queue.pendingAgeMs, 0, 'Math.max(0, …): la edad nunca es negativa')
  })

  test('una `ScopeOutbox` de terceros SIN `createdAt` ⇒ `{ null, null }` (jamás 0 ni «ahora») y la pasada sigue en verde', async ({ assert }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const q = memoryQueue()
    const manager = managerWith({ tree, driver, outbox: q.outbox })
    await manager.scopes.attached(unit, org)
    await manager.scopes.attached(unitScope(), org)
    const report = await manager.relayScopeChanges({ limit: 1 })
    assert.lengthOf(calls, 1)
    assert.isTrue(report.remaining, 'queda una pendiente… sin fecha')
    assert.deepEqual(report.queue, { oldestPendingAt: null, pendingAgeMs: null })
    assert.isUndefined((await q.outbox.pending(1))[0].createdAt)
  })

  test('el reporte `busy` y el `dryRun` (también con `only`) llevan la MISMA edad global: el cron que no entra tampoco se queda ciego', async ({ assert }) => {
    const clock = clockAt('2026-09-10T10:00:00Z')
    const t0 = clock.ms()
    const tree = memoryScopeTree()
    const org = orgScope()
    const unitA = unitScope()
    const unitB = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unitA, org)
    await tree.attach(unitB, org)
    const { driver } = clockedSpy()
    const outbox = sqlScopeOutbox({ requireTransaction: false, now: clock.now })
    const manager = managerWith({ tree, driver, outbox, clock: clock.now })
    await manager.scopes.attached(unitA, org)
    clock.advance(20_000)
    const { queued: [mine] } = await manager.scopes.attached(unitB, org)
    clock.advance(5_000)
    const dry = await manager.relayScopeChanges({ dryRun: true, only: [mine] })
    assert.deepEqual(dry.wouldApply.map((w) => String(w.id)), [String(mine)])
    assert.equal(dry.queue.oldestPendingAt!.getTime(), t0, 'dryRun + only: la cabeza GLOBAL, no la pedida')
    assert.equal(dry.queue.pendingAgeMs, 25_000)
    const lease = await outbox.acquire!()
    try {
      const busy = await manager.relayScopeChanges()
      assert.isTrue(busy.busy)
      assert.equal(busy.queue.pendingAgeMs, 25_000)
      assert.equal(busy.deadCount, 0)
    } finally {
      await lease!.release()
    }
  })

  test('el puerto sobre Lucid devuelve `createdAt` como `Date` (el sello de `created_at`, con el reloj inyectado) en `pending()`, `dead()` y `earlierPending()`', async ({ assert }) => {
    const clock = clockAt('2026-09-10T10:00:00Z')
    const outbox = sqlScopeOutbox({ requireTransaction: false, now: clock.now, maxAttempts: 1 })
    const org = orgScope()
    const unit = unitScope()
    await outbox.enqueue({ op: 'attached', child: unit, parent: org }, {})
    clock.advance(1_000)
    await outbox.enqueue({ op: 'detached', child: unit }, {})
    const [first, second] = await outbox.pending(10)
    assert.instanceOf(first.createdAt, Date)
    assert.equal(first.createdAt!.getTime(), clock.ms() - 1_000)
    assert.equal(second.createdAt!.getTime(), clock.ms())
    assert.equal((await outbox.earlierPending!(second.id, [unit]))!.createdAt!.getTime(), first.createdAt!.getTime())
    await outbox.markFailed(first.id, 'irreparable')
    assert.equal((await outbox.dead!(10))[0].createdAt!.getTime(), first.createdAt!.getTime())
  })

  test('cierre alpha.8 · `waitForLeaseMs` termina con un reloj FIJO (sondeos contados) y tiene tope (RELAY_WAIT_LEASE_MAX_MS ⇒ 500)', async ({ assert }) => {
    const { RELAY_WAIT_LEASE_MAX_MS, RELAY_LEASE_POLL_MS } = await import('../src/manager.js')
    const clock = clockAt('2030-01-01T00:00:00Z') // reloj FIJO: nunca avanza
    const tree = memoryScopeTree()
    const { driver } = clockedSpy()
    const outbox = sqlScopeOutbox({ requireTransaction: false, now: clock.now })
    const manager = managerWith({ tree, driver, outbox, clock: clock.now })
    const held = await outbox.acquire!()
    assert.isNotNull(held)
    const t0 = Date.now()
    try {
      const report = await manager.relayScopeChanges({ waitForLeaseMs: 200 })
      assert.isTrue(report.busy, 'con el lease tomado y reloj fijo: busy, no cuelgue')
    } finally {
      await held!.release()
    }
    const elapsed = Date.now() - t0
    assert.isBelow(elapsed, 200 + RELAY_LEASE_POLL_MS * 8, `terminó por número de sondeos, no por el reloj fijo (${elapsed} ms)`)
    let caught: any
    try {
      await manager.relayScopeChanges({ waitForLeaseMs: RELAY_WAIT_LEASE_MAX_MS + 1 })
    } catch (error) {
      caught = error
    }
    assert.equal(caught?.code, 'E_AUTHZ_CONFIG', `por encima del tope es 500: ${caught?.message}`)
    assert.match(caught?.message ?? '', /RELAY_WAIT_LEASE_MAX_MS/)
  })

  test('cierre alpha.8 · `--max-age` con entradas pendientes y edad DESCONOCIDA (outbox sin createdAt) es ruidoso: aviso sin umbral, error y exit ≠ 0 con umbral', async ({ assert }) => {
    const { queueAgeLines } = await import('../commands/authz_scopes_relay.js')
    const unknown = { oldestPendingAt: null, pendingAgeMs: null }
    assert.deepEqual(queueAgeLines(unknown, 60_000, false), { lines: [], exceeded: false }, 'cola vacía: calla')
    const warn = queueAgeLines(unknown, undefined, true)
    assert.isFalse(warn.exceeded); assert.equal(warn.lines[0]?.level, 'warning'); assert.match(warn.lines[0]!.message, /DESCONOCIDA/)
    const err = queueAgeLines(unknown, 60_000, true)
    assert.isTrue(err.exceeded, 'con umbral y edad desconocida: exit ≠ 0, nunca silencio'); assert.equal(err.lines[0]?.level, 'error')
  })

  test('`authz:scopes:relay --max-age=<ms>`: declara la bandera; `queueAgeLines` (pura) sale ≠ 0 SOLO con umbral y edad por encima; sin umbral informa; sin edad (null) calla', async ({ assert }) => {
    const commands: any = await import('../commands/main.js')
    const nombres = flagNamesOf(commands.AuthzScopesRelay)
    assert.includeMembers(nombres, ['max-age'])
    const { queueAgeLines } = await import('../commands/authz_scopes_relay.js')
    const at = new Date('2026-09-10T10:00:00Z')
    const aged = { oldestPendingAt: at, pendingAgeMs: 90_000 }
    const over = queueAgeLines(aged, 60_000)
    assert.isTrue(over.exceeded)
    assert.isTrue(over.lines.some((l) => l.level === 'error' && l.message.includes('90000') && l.message.includes('60000')))
    const under = queueAgeLines(aged, 120_000)
    assert.isFalse(under.exceeded)
    assert.isTrue(under.lines.some((l) => l.level !== 'error' && l.message.includes('90000')))
    const noThreshold = queueAgeLines(aged, undefined)
    assert.isFalse(noThreshold.exceeded, 'sin umbral NUNCA sale ≠ 0 por edad (un cron en rojo para siempre)')
    assert.isTrue(noThreshold.lines.some((l) => l.message.includes('90000')))
    const none = queueAgeLines({ oldestPendingAt: null, pendingAgeMs: null }, 60_000)
    assert.isFalse(none.exceeded)
    assert.deepEqual(none.lines, [], 'sin edad no hay nada que decir ni que alarmar')
    for (const bad of [-1, 1.5, Number.NaN]) {
      assert.throws(() => queueAgeLines(aged, bad), /max-age/)
    }
  })

  test('letra: el README dice la edad, `--max-age`, que la mide el reloj de quien encoló y que terceros sin `createdAt` la dejan a null; y `clock.spec` sigue vigilando `src/`', async ({ assert }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, 'pendingAgeMs')
    assert.include(readme, 'oldestPendingAt')
    assert.include(readme, '--max-age')
    assert.include(readme, 'the clock of whoever enqueued')
    assert.include(readme, 'createdAt')
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * **alpha.8 · T — `enqueue` sin `{ transaction }`** (panel relay 2, cuestión
 * 6; P13 del tester; decisión del dueño 2026-09-10 (4)). Hoy `enqueue(change,
 * {})` ESCRIBE: la fila confirma sola, fuera de la unidad de trabajo del
 * consumidor, y si su transacción revierte después el relay aplica al store
 * un cambio que en SU base no ocurrió — la fuga S5 por el camino de uso
 * «correcto». Opt-in en alpha.8 (`requireTransaction: true` ⇒ 500 ANTES del
 * INSERT); el default pasa a `true` en 2.5 (anunciado), cuando el contrato
 * publicado pase la transacción en `ctx()`.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('alpha.8 · T — `sqlScopeOutbox({ requireTransaction: true })`: encolar sin `{ transaction }` es 500 E_AUTHZ_CONFIG ANTES del INSERT (la fuga S5, nombrada); default `false` en alpha.8, `true` desde 2.5.0 (lote B · B6)', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  const rows = async () => Number(((await db.from('authz_scope_outbox').count('* as n')) as any[])[0]?.n ?? 0)

  test('P13 (EL ROJO): con `requireTransaction: true`, `enqueue(change, {})` ⇒ 500 E_AUTHZ_CONFIG que nombra la fuga (rollback tuyo ⇒ el relay aplica igual) y CERO filas; el mismo `enqueue` con la trx abierta entra', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox({ requireTransaction: true })
    const org = orgScope()
    const unit = unitScope()
    const error = await rejects(assert, () => outbox.enqueue({ op: 'attached', child: unit, parent: org }, {}), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'sin transacción')
    assert.include(error.message, 'requireTransaction')
    assert.include(error.message, 'rollback', 'nombra la fuga S5: un rollback tuyo deja el cambio en la cola')
    assert.include(error.message, 'relay', '…y el relay lo aplica')
    assert.equal(await rows(), 0, 'ANTES del INSERT')
    await rejects(assert, () => outbox.enqueue({ op: 'attached', child: unit, parent: org }, { actor: { type: 'user', uuid: uuidv7() } }), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'con actor y sin transacción, igual')
    assert.equal(await rows(), 0)
    await db.transaction(async (trx) => {
      await outbox.enqueue({ op: 'attached', child: unit, parent: org }, { transaction: trx })
    })
    assert.equal(await rows(), 1, 'con la transacción abierta del llamante, entra')
  })

  test('por el MANAGER: `scopes.attached/moved/detached` sin `transaction` ⇒ el mismo 500 y cero filas; con `{ transaction }` encolan (y el recibo llega)', async ({ assert }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: true })
    const manager = managerWith({ tree, driver, outbox })
    await rejects(assert, () => manager.scopes.attached(unit, org), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'attached')
    await rejects(assert, () => manager.scopes.moved(unit, org), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'moved')
    await rejects(assert, () => manager.scopes.detached(unit), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'detached')
    assert.equal(await rows(), 0)
    assert.deepEqual(calls, [], 'y tampoco escribió en línea en el driver')
    // `{ transaction }` por el manager exige pool ≥ 2 (la barrera del freeze lee por OTRA conexión): en `:memory:` no se monta.
    if (testEngine() === 'sqlite') return
    let queued: Array<string | number> = []
    await db.transaction(async (trx) => {
      ;({ queued } = await manager.scopes.attached(unit, org, { transaction: trx }))
    })
    assert.lengthOf(queued, 1)
    assert.equal(await rows(), 1)
  })

  test('B6 (2.5.0) · el DEFAULT es `true`: `sqlScopeOutbox()` y `sqlScopeOutbox({})` rechazan encolar sin transacción (500 nombrando requireTransaction, cero filas) y con la trx entran; `requireTransaction: false` es el opt-out explícito; un valor que no es booleano ⇒ 500 al construir', async ({ assert }) => {
    for (const options of [undefined, {}]) {
      await cleanScopeOutbox(db)
      const outbox = options === undefined ? sqlScopeOutbox() : sqlScopeOutbox(options)
      const error = await rejects(assert, () => outbox.enqueue({ op: 'detached', child: unitScope() }, {}), { status: 500, code: 'E_AUTHZ_CONFIG' }, JSON.stringify(options))
      assert.include(error.message, 'requireTransaction', 'ROJO (B6): el default no exige la transacción')
      assert.include(error.message, 'requireTransaction: false', 'la letra nombra el opt-out')
      // 🟡 3 (cierre 1 del lote B): la letra del 500 dice lo del pool — seguirla a ciegas con pool 1 (el default de
      // knex en TODO SQLite) lleva a un 503 a freezeTimeoutMs por el manager; con pool max 1 la salida es el opt-out.
      assert.include(error.message, 'pool >= 2', '🟡 3: nombra el pool que exige { transaction } por el manager')
      assert.include(error.message, 'pool max 1', '🟡 3: y la salida con pool 1')
      assert.include(error.message, 'TODO SQLite', '🟡 3: no solo :memory:')
      assert.equal(await rows(), 0, `${JSON.stringify(options)}: cero filas`)
      const trx = await db.transaction()
      await outbox.enqueue({ op: 'detached', child: unitScope() }, { transaction: trx })
      await trx.commit()
      assert.equal(await rows(), 1, `${JSON.stringify(options)}: con la trx entra`)
    }
    await cleanScopeOutbox(db)
    const optOut = sqlScopeOutbox({ requireTransaction: false })
    await optOut.enqueue({ op: 'detached', child: unitScope() }, {})
    assert.equal(await rows(), 1, 'opt-out explícito: entra sin transacción')
    for (const bad of ['true', 1, null]) {
      await rejects(assert, async () => sqlScopeOutbox({ requireTransaction: bad as any }), { status: 500, code: 'E_AUTHZ_CONFIG' }, String(bad))
    }
  })

  test('letra: README y CHANGELOG dicen que el default es `true` desde 2.5.0, que `requireTransaction: false` es el opt-out y que el contrato publicado pasa la transacción (par `requiresTransaction`); la trx CERRADA es otro 500 (abajo)', async ({ assert }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    const changelog = await readFile(new URL('../CHANGELOG.md', import.meta.url), 'utf8')
    assert.include(readme, 'requireTransaction')
    assert.include(readme, 'The default is **`true` since 2.5.0**')
    assert.include(readme, '`requireTransaction: false`')
    assert.include(readme, '`requiresTransaction`')
    assert.notInclude(readme, 'default becomes `true` in 2.5', 'la promesa de futuro se cumplió: ya no es futuro')
    // 🟡 3: el README dice «pool max 1 — knex's default for every SQLite connection», no «:memory:» a secas.
    assert.include(readme, 'pool max 1', '🟡 3: la condición real es el pool, no :memory:')
    assert.notInclude(readme, 'on SQLite `:memory:` keep the opt-out', '🟡 3: la letra vieja nombraba solo :memory:')
    const unreleased = changelog.slice(0, changelog.indexOf('## [2.5.0-alpha.1]'))
    assert.include(unreleased, 'requireTransaction')
    assert.include(unreleased, '`true` by default')
    assert.include(unreleased, '`requiresTransaction`')
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * **alpha.8 · M — los menores del panel relay 2** (cuestión 7.2): `origin`
 * en `entries` (derivado del ORIGEN del bloqueo, jamás del prefijo del
 * texto), `deadCount` siempre + `dead[]` sin `lastError` bajo `only` salvo
 * `deadDetail: 'full'`, y la transacción YA CERRADA en `enqueue` ⇒ 500
 * `E_AUTHZ_CONFIG` (hoy 503 `BACKEND_UNAVAILABLE`: `isTransaction` sigue
 * siendo `true` en una trx confirmada y knex revienta dentro de `guardSql`).
 * ════════════════════════════════════════════════════════════════════════ */

test.group('alpha.8 · M — `entries[].origin`: parked | pending | failed, el ORIGEN (transitivo) del bloqueo, derivado de `blocked` y no del texto de `reason`', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  async function forest() {
    const tree = memoryScopeTree()
    const org = orgScope()
    const o2 = orgScope()
    const unit = unitScope()
    const child = unitScope()
    const grandchild = unitScope()
    for (const x of [org, o2]) await tree.attach(x, APP_SCOPE)
    await tree.attach(unit, org)
    await tree.attach(child, unit)
    await tree.attach(grandchild, child)
    const { driver, calls } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 1 })
    const manager = managerWith({ tree, driver, outbox })
    return { tree, org, o2, unit, child, grandchild, driver, calls, outbox, manager }
  }
  const entry = (report: any, id: any) => report.entries.find((e: any) => String(e.id) === String(id))

  test('O-1 · aplazada por un APARCADO (`parked:<id>`) ⇒ `origin: "parked"`; O-4 · a dos saltos (`depends-on:` de una aplazada por aparcado) el origen sigue siendo el de la CAUSA RAÍZ: `parked`', async ({
    assert,
  }) => {
    const w = await forest()
    const { queued: [movedId] } = await w.manager.scopes.moved(w.unit, w.o2)
    w.driver.onScopeMoved = async () => {
      throw new Error('el padre ya no existe')
    }
    await w.manager.relayScopeChanges() // #1 ⇒ APARCADA
    const { queued: [childId] } = await w.manager.scopes.attached(w.child, w.unit) // parked:#1
    const { queued: [grandId] } = await w.manager.scopes.attached(w.grandchild, w.child) // depends-on:#2 (raíz: aparcado)
    const report = await w.manager.relayScopeChanges()
    assert.deepEqual([entry(report, childId).status, entry(report, childId).reason, entry(report, childId).origin], ['deferred', `parked:${movedId}`, 'parked'])
    assert.deepEqual([entry(report, grandId).status, entry(report, grandId).reason, entry(report, grandId).origin], ['deferred', `depends-on:${childId}`, 'parked'], 'a dos saltos, la causa raíz')
    assert.isUndefined(entry(report, movedId).origin, 'una entrada `dead` no lleva origin')
  })

  test('O-2 · aplazada por un FALLO real de la pasada ⇒ `origin: "failed"`, también a dos saltos; una entrada `applied` o `failed` no lleva `origin`', async ({ assert }) => {
    const w = await forest()
    const { queued: [unitId] } = await w.manager.scopes.attached(w.unit, w.org) // falla
    const { queued: [childId] } = await w.manager.scopes.attached(w.child, w.unit) // depends-on:#1 (fallo)
    const { queued: [grandId] } = await w.manager.scopes.attached(w.grandchild, w.child) // depends-on:#2 (raíz: fallo)
    const other = unitScope()
    await w.tree.attach(other, w.o2)
    const { queued: [otherId] } = await w.manager.scopes.attached(other, w.o2) // se aplica
    w.driver.onScopeAttached = async (c: any) => {
      if (keyOf(c) === keyOf(w.unit)) throw new AuthorizationBackendError('openfga', 'write', new Error('caído'))
    }
    const report = await w.manager.relayScopeChanges()
    assert.deepEqual([entry(report, unitId).status, entry(report, unitId).origin], ['failed', undefined])
    assert.deepEqual([entry(report, childId).status, entry(report, childId).reason, entry(report, childId).origin], ['deferred', `depends-on:${unitId}`, 'failed'])
    assert.deepEqual([entry(report, grandId).status, entry(report, grandId).reason, entry(report, grandId).origin], ['deferred', `depends-on:${childId}`, 'failed'])
    assert.deepEqual([entry(report, otherId).status, entry(report, otherId).origin], ['applied', undefined])
  })

  test('O-3 🔑 · bajo `only`, aplazada por una anterior PENDIENTE de verdad (ni aparcada ni fallida) ⇒ `origin: "pending"` — el mismo `depends-on:` que un fallo, con otro origen (colapsar los dos es el mutante)', async ({
    assert,
  }) => {
    const w = await forest()
    const { queued: [childId] } = await w.manager.scopes.attached(w.child, w.unit) // #1 NO pedida, aplicable
    const { queued: [detachedId] } = await w.manager.scopes.detached(w.child) // #2 pedida (purga: espera su turno)
    const { queued: [grandId] } = await w.manager.scopes.attached(w.grandchild, w.child) // #3 pedida (concede)
    const report = await w.manager.relayScopeChanges({ only: [detachedId, grandId] })
    assert.deepEqual([entry(report, detachedId).status, entry(report, detachedId).reason, entry(report, detachedId).origin], ['deferred', `depends-on:${childId}`, 'pending'])
    // #3 comparte `child` con #2 (aplazada en ESTA pasada por una pendiente): su origen heredado es `pending`, no `failed`.
    assert.deepEqual([entry(report, grandId).status, entry(report, grandId).origin], ['deferred', 'pending'])
    assert.notInclude(w.calls.join(' | '), 'purgeScope')
    // Y bajo `only` con la anterior retenida por un APARCADO el origen es `parked` (y la purga pasa: alpha.6).
    const w2 = await forest()
    const { queued: [movedId] } = await w2.manager.scopes.moved(w2.unit, w2.o2)
    w2.driver.onScopeMoved = async () => {
      throw new Error('irreparable')
    }
    await w2.manager.relayScopeChanges()
    await w2.manager.scopes.attached(w2.child, w2.unit) // NO pedida, parked:#1
    const { queued: [cousinId] } = await w2.manager.scopes.attached(unitScope(), w2.child) // pedida: concede ⇒ aplazada
    const r2 = await w2.manager.relayScopeChanges({ only: [cousinId] })
    assert.deepEqual([entry(r2, cousinId).status, entry(r2, cousinId).origin], ['deferred', 'parked'])
    assert.equal(r2.deadCount, 1)
    assert.deepEqual(r2.dead.map((d) => String(d.id)), [String(movedId)])
  })
})

test.group('alpha.8 · M — `deadCount` siempre (y global); bajo `only` `dead[]` va SIN `lastError` por defecto (`deadDetail: "full"` lo devuelve); la trx CERRADA en `enqueue` es 500 E_AUTHZ_CONFIG', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  test('D-1 · con más aparcadas que `batchSize`, `dead.length` se queda en `batchSize` y `deadCount` dice las de VERDAD (también en `dryRun` y en `busy`)', async ({ assert }) => {
    const tree = memoryScopeTree()
    const { driver } = spyDriver()
    const q = memoryQueue({ maxAttempts: 1 })
    const manager = managerWith({ tree, driver, outbox: q.outbox })
    for (let i = 0; i < 5; i++) {
      const org = orgScope()
      await tree.attach(org, APP_SCOPE)
      await manager.scopes.attached(org, APP_SCOPE)
    }
    driver.onScopeAttached = async () => {
      throw new Error('irreparable')
    }
    await manager.relayScopeChanges() // las 5 aparcan
    const report = await manager.relayScopeChanges({ batchSize: 2 })
    assert.lengthOf(report.dead, 2, 'la lista sigue acotada a batchSize')
    assert.equal(report.deadCount, 5, 'el número de verdad')
    const dry = await manager.relayScopeChanges({ batchSize: 2, dryRun: true })
    assert.equal(dry.deadCount, 5)
    assert.lengthOf(dry.dead, 2)
  })

  test('D-2 · bajo `only`, cada entrada de `dead[]` lleva id/change/attempts y NO `error` (el actor no viaja: lo que fuga es la causa del backend); `deadDetail: "full"` la devuelve; sin `only` va completa como hasta hoy; `deadDetail` inválido ⇒ 500', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = orgScope()
    const orgB = orgScope()
    const unitA = unitScope()
    const unitB = unitScope()
    for (const x of [orgA, orgB]) await tree.attach(x, APP_SCOPE)
    await tree.attach(unitA, orgA)
    await tree.attach(unitB, orgB)
    const { driver } = spyDriver()
    const outbox = sqlScopeOutbox({ requireTransaction: false, maxAttempts: 1 })
    const manager = managerWith({ tree, driver, outbox })
    const { queued: [parkedId] } = await manager.scopes.attached(unitA, orgA)
    driver.onScopeAttached = async (c: any) => {
      if (keyOf(c) === keyOf(unitA)) throw new Error('la causa del otro tenant, con texto del backend')
    }
    await manager.relayScopeChanges() // #1 aparcada
    const { queued: [mine] } = await manager.scopes.attached(unitB, orgB)

    const filtered = await manager.relayScopeChanges({ only: [mine] })
    assert.deepEqual(filtered.entries.map((e) => e.status), ['applied'])
    assert.equal(filtered.deadCount, 1)
    assert.lengthOf(filtered.dead, 1, '`dead` sigue siendo global')
    assert.deepEqual(Object.keys(filtered.dead[0]).sort(), ['attempts', 'change', 'id'], 'sin `error` por defecto bajo only')
    assert.equal(String(filtered.dead[0].id), String(parkedId))

    const full = await manager.relayScopeChanges({ only: [mine], deadDetail: 'full' })
    assert.equal(full.dead[0].error, 'la causa del otro tenant, con texto del backend')

    const whole = await manager.relayScopeChanges()
    assert.equal(whole.dead[0].error, 'la causa del otro tenant, con texto del backend', 'sin only, como hasta hoy')

    await rejects(assert, () => manager.relayScopeChanges({ deadDetail: 'ids' as any }), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'valor desconocido')
  })

  test('C-1 · una transacción YA CONFIRMADA (o revertida) en `enqueue` ⇒ 500 E_AUTHZ_CONFIG nombrando la operación y «confirmada/revertida», ANTES de la sentencia y con cero filas (hoy: 503 BACKEND_UNAVAILABLE desde dentro de knex)', async ({
    assert,
  }) => {
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const rows = async () => Number(((await db.from('authz_scope_outbox').count('* as n')) as any[])[0]?.n ?? 0)
    const committed = await db.transaction()
    await committed.commit()
    const error = await rejects(assert, () => outbox.enqueue({ op: 'detached', child: unitScope() }, { transaction: committed }), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'confirmada')
    assert.include(error.message, 'sqlScopeOutbox.enqueue')
    assert.match(error.message, /confirmada|revertida/)
    const rolled = await db.transaction()
    await rolled.rollback()
    await rejects(assert, () => outbox.enqueue({ op: 'detached', child: unitScope() }, { transaction: rolled }), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'revertida')
    assert.equal(await rows(), 0)
  })

  test('letra: el README dice `origin`, `deadCount`, `deadDetail` y qué campos de `dead` son seguros bajo `only`', async ({ assert }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, 'deadCount')
    assert.include(readme, "deadDetail: 'full'")
    assert.include(readme, '`origin`')
  })
})

test.group('cierre alpha.6 — la retirada del lock viejo está atada a la versión', () => {
  test('SCOPE_OUTBOX_TAKES_LEGACY_LOCK vale exactamente «package.json ≤ SCOPE_OUTBOX_LEGACY_LOCK_UNTIL»: subir la versión sin retirar el lock viejo es ROJO', async ({ assert }) => {
    const { SCOPE_OUTBOX_LEGACY_LOCK_UNTIL, SCOPE_OUTBOX_TAKES_LEGACY_LOCK } = await import('../src/scope_outbox.js')
    const { version } = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf-8'))
    const past = isVersionAfter(version, SCOPE_OUTBOX_LEGACY_LOCK_UNTIL)
    assert.equal(
      SCOPE_OUTBOX_TAKES_LEGACY_LOCK,
      !past,
      past
        ? `package.json es ${version} > ${SCOPE_OUTBOX_LEGACY_LOCK_UNTIL}: la transición terminó. Pon SCOPE_OUTBOX_TAKES_LEGACY_LOCK = false, ajusta el caso MySQL de R6 (ya no se toma el viejo) y anota la retirada en el CHANGELOG.`
        : `package.json es ${version} ≤ ${SCOPE_OUTBOX_LEGACY_LOCK_UNTIL}: durante la transición se toman los DOS locks.`
    )
    // Autocomprobación del comparador, para que el diente no dependa de una implementación muda.
    assert.isTrue(isVersionAfter('2.4.0-alpha.7', '2.4.0-alpha.6'))
    assert.isTrue(isVersionAfter('2.4.0', '2.4.0-alpha.6'))
    assert.isTrue(isVersionAfter('2.5.0-alpha.1', '2.4.0-alpha.6'))
    assert.isFalse(isVersionAfter('2.4.0-alpha.6', '2.4.0-alpha.6'))
    assert.isFalse(isVersionAfter('2.4.0-alpha.5', '2.4.0-alpha.6'))
  })
})

test.group('alpha.5 · R6 — `GET_LOCK` con nombre estable y transición de dos locks', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  /** Dos tablas cuyos nombres de lock coinciden en los primeros 64 caracteres. */
  const prefix = 't_' + 'a'.repeat(36)
  const tableA = `${prefix}x`
  const tableB = `${prefix}y`

  test('dos tablas con los mismos 64 primeros caracteres ya NO comparten el nombre nuevo del lease (estable, ≤ 64); el viejo sí lo compartían', ({ assert }) => {
    const a = scopeOutboxLockNames(undefined, tableA)
    const b = scopeOutboxLockNames(undefined, tableB)
    assert.equal(a.legacy, b.legacy, 'el recorte de alpha.4: el MISMO lock para las dos')
    assert.notEqual(a.current, b.current, 'el hash del nombre completo: uno por tabla')
    assert.isAtMost(a.current.length, 64)
    assert.equal(a.current, scopeOutboxLockNames(undefined, tableA).current, 'estable entre procesos: no lleva nada del proceso')
    assert.equal(a.current, scopeOutboxLockNames('default', tableA).current, '`default` es la conexión sin nombre')
  })

  if (testEngine() === 'mysql') {
    /** El primer valor de un `rawQuery`, sea cual sea la forma del dialecto. */
    const firstValue = (result: any, column: string) => {
      const rows = Array.isArray(result) ? result[0] : (result?.rows ?? result)
      const row = Array.isArray(rows) ? rows[0] : rows
      return row?.[column]
    }
    const holderOf = async (lockName: string) => firstValue(await db.rawQuery('select is_used_lock(?) as holder', [lockName]), 'holder')

    test('MySQL · desde alpha.7 el lease toma SOLO el lock nuevo (la transición de alpha.5/6 terminó) y lo suelta al liberarlo', async ({ assert }) => {
      const outbox = sqlScopeOutbox({ requireTransaction: false })
      const names = scopeOutboxLockNames(undefined, 'authz_scope_outbox')
      const lease = await outbox.acquire!()
      assert.isNotNull(lease)
      try {
        assert.isNotNull(await holderOf(names.current), 'el nuevo, tomado')
        assert.isNull(await holderOf(names.legacy), 'el viejo YA NO se toma: la transición terminó (SCOPE_OUTBOX_TAKES_LEGACY_LOCK = false)')
        assert.isNull(await outbox.acquire!(), 'una segunda pasada es busy')
      } finally {
        await lease!.release()
      }
      assert.isNull(await holderOf(names.current), 'soltado')
    })

    test('MySQL · un proceso de ≤ alpha.4 (solo el lock VIEJO) YA NO excluye al relay actual — el precio DECLARADO de terminar la transición: subir desde ≤ alpha.4 exige parada completa, no despliegue rodante', async ({ assert }) => {
      const outbox = sqlScopeOutbox({ requireTransaction: false })
      const names = scopeOutboxLockNames(undefined, 'authz_scope_outbox')
      const alpha4 = await db.transaction()
      try {
        assert.equal(Number(firstValue(await alpha4.rawQuery('select get_lock(?, 0) as taken', [names.legacy]), 'taken')), 1)
        const lease = await outbox.acquire!()
        try {
          assert.isNotNull(lease, 'el relay actual no mira el lock viejo: entra aunque un alpha.4 lo sostenga (por eso la subida desde ≤ alpha.4 en MySQL es con parada, README)')
        } finally {
          await lease?.release()
        }
        await alpha4.rawQuery('select release_lock(?)', [names.legacy])
      } finally {
        await alpha4.rollback()
      }
    })
  }
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

  /**
   * L-1 · 🟠 8: estos tres casos notifican `scopes.moved` DENTRO de la
   * transacción del consumidor. Desde L-1 la barrera del freeze se lee
   * SIEMPRE por la conexión del motor (la autoridad nunca comparte snapshot
   * con el llamante), así que `{ transaction }` exige pool ≥ 2: en `:memory:`
   * (pool 1/1) la notificación es un 503 `E_AUTHZ_BACKEND_TIMEOUT` declarado
   * —caso en `freeze.spec.ts`— y la demostración del rollback solo es
   * observable en `sqlite-file`/pg/mysql (precedente:
   * `freeze_multiprocess.spec.ts`). Solo ESTE grupo se gatea.
   */
  if (testEngine() !== 'sqlite') test.group('3b-2d · el rollback del consumidor, contra el servidor real (pool ≥ 2)', (group) => {
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
        // paquete documenta para poder contrastar el `within` de origen), y
        // le pasa SU transacción — desde 3b-7 la barrera del freeze lee la
        // fila compartida y con el pool de 1 de `:memory:` esa lectura tiene
        // que ir por la conexión que el consumidor ya sostiene.
        await manager.scopes.moved(unit, orgB, { transaction: trx } as any)
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
      const outbox = sqlScopeOutbox({ requireTransaction: false })
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
      const outbox = sqlScopeOutbox({ requireTransaction: false })
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

  /* ══════════════════════════════════════════════════════════════════════
   * **3b-2h**, contra el servidor real: las tres reproducciones del auditor
   * R2 sobre la composición de la outbox, ya sin efecto. En `facts` un doble
   * en memoria no prueba nada — quien decide es el store.
   * ══════════════════════════════════════════════════════════════════════ */
  test.group('3b-2h · las reproducciones del auditor R2, contra el servidor real', (group) => {
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

    const HOLDERS_2H = { users: 'user' }
    const PERMS_2H = ['docs:write']

    /**
     * Un mundo con el catálogo del auditor: un rol de organización y otro de
     * unit, para poder conceder ABAJO y denegar ARRIBA — que es como se
     * observa si la arista `parent` llegó al store.
     */
    async function factsWorld(options: { outbox?: any } = {}) {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({
        name: `lote-2h-${Date.now()}-${stores.length}`,
      })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS_2H, PERMS_2H)
      )
      const tree = sqlScopeTree(db)
      const chainOf = (scope: any) => sqlScopeTree(db).chainOf(scope)
      const driver = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id,
        holderTypes: HOLDERS_2H,
        resolveChain: chainOf,
        outbox: options.outbox,
        acceptScopeDriftRisk: options.outbox ? undefined : true,
        catalogRevalidate: { everyMs: 60_000 },
        logger: { warn: () => {} },
      })
      await syncAuthzCatalog(
        {
          permissions: [{ slug: 'docs:write' }],
          roles: [
            { slug: 'org-admin', scopeType: 'organization', permissions: ['docs:write'] },
            { slug: 'unit-editor', scopeType: 'unit', permissions: ['docs:write'] },
          ],
        },
        { projection: driver.catalogProjection() }
      )
      const manager = new AuthorizationManager({
        default: 'openfga',
        drivers: { openfga: () => driver },
        holderTypes: HOLDERS_2H,
        scopes: {
          resolveChain: chainOf,
          outbox: options.outbox,
          ...(options.outbox ? {} : { acceptScopeDriftRisk: true }),
        },
        warnOnOptInSecurity: false,
      } as any)
      const raw = new OpenFgaClient({
        apiUrl,
        storeId: store.id!,
        authorizationModelId: model.authorization_model_id,
      })
      return { driver, manager, tree, raw }
    }

    const alice = { type: 'users', uuid: '0192f000-0000-7000-8000-00000000a11c' }

    /**
     * 🔴 2 · la reproducción `b1_relay_poison.ts` del auditor: `attached(C,P)`
     * encolado y `P` borrado antes del relevo. Lo que él midió tres pasadas
     * después: la unit NUEVA nunca recibía su arista `parent`, así que el
     * deny explícito de su organización no la alcanzaba (`facts=true`,
     * `database=false`) y un `detached` posterior nunca purgaba.
     */
    test('🔴 2 · con una entrada envenenada en la cola, la unit NUEVA recibe su arista y el deny la alcanza', async ({
      assert,
    }) => {
      const outbox = sqlScopeOutbox({ requireTransaction: false })
      const { manager, tree, raw } = await factsWorld({ outbox })
      const org = orgScope()
      await tree.attach(org, APP_SCOPE)
      await manager.scopes.attached(org, APP_SCOPE)
      await manager.relayScopeChanges()
      await manager.deny(alice, 'docs:write', org)

      // El tapón, con operaciones todas legítimas de un tenant cualquiera.
      const padre = orgScope()
      const hijo = unitScope()
      await tree.attach(padre, org)
      await manager.scopes.attached(padre, org)
      await tree.attach(hijo, padre)
      await manager.scopes.attached(hijo, padre)
      await manager.scopes.detached(padre)
      await tree.detach(padre)

      // Y detrás, el cambio de otro: una unit nueva bajo la organization que
      // tiene el deny.
      const unit = unitScope()
      await tree.attach(unit, org)
      await manager.scopes.attached(unit, org)

      const report = await manager.relayScopeChanges()

      assert.equal(report.failures.length, 1, 'la entrada envenenada falla')
      assert.match(report.failures[0].error, /no existe para el resolutor/)
      assert.include(
        report.applied.map((a: any) => `${a.change.op} ${a.change.child.uuid}`),
        `attached ${unit.uuid}`,
        'y aun así la unit nueva SÍ se propaga'
      )
      const edges = await raw.read({ object: `scope:unit|${unit.uuid}`, relation: 'parent' })
      assert.lengthOf(edges.tuples ?? [], 1, 'la arista `parent` está en el store')

      await manager.grant(alice, 'unit-editor', unit, { expiresAt: null })
      assert.isFalse(
        await manager.authorize(alice, 'docs:write', unit),
        'el deny de la organization alcanza a la unit nueva: ya no hay fail-open permanente'
      )

      // Y lo que se borra, se purga: el `detached` de la unit no se queda
      // detrás del tapón.
      await manager.scopes.detached(unit)
      await tree.detach(unit)
      await manager.relayScopeChanges()
      const left = await raw.read({ object: `scope:unit|${unit.uuid}` })
      assert.lengthOf(left.tuples ?? [], 0, 'la purga llegó: el scope borrado no conserva nada')
    }).timeout(60_000)

    /**
     * 🟠 3 · la reproducción `c1_alias_fail_open.ts`: el `detached` llega con
     * el uuid SIN guiones y la fila ya borrada (en PostgreSQL el motor funde
     * las dos formas, así que el `DELETE` del controlador acierta con el
     * alias). Lo que él midió: `purgeScope` devolvía OK habiendo demostrado
     * cero sobre un objeto que no existe, y el scope real conservaba `parent`
     * y `binding` — `authorize` decía `true` para siempre.
     */
    test('🟠 3 · un `detached` con el uuid SIN guiones y la fila borrada purga el scope REAL', async ({
      assert,
    }) => {
      const { manager, tree, raw } = await factsWorld()
      const org = orgScope()
      const unit = unitScope()
      await tree.attach(org, APP_SCOPE)
      await manager.scopes.attached(org, APP_SCOPE)
      await tree.attach(unit, org)
      await manager.scopes.attached(unit, org)
      await manager.grant(alice, 'unit-editor', unit, { expiresAt: null })
      assert.isTrue(await manager.authorize(alice, 'docs:write', unit), 'de partida concede')

      await tree.detach(unit)
      await manager.scopes.detached({ type: 'unit', uuid: unit.uuid!.replaceAll('-', '') } as any)

      const left = await raw.read({ object: `scope:unit|${unit.uuid}` })
      assert.lengthOf(
        left.tuples ?? [],
        0,
        'bajo la identidad REAL no queda ni el `parent` ni el `binding`'
      )
      assert.isFalse(
        await manager.authorize(alice, 'docs:write', unit),
        'y el scope borrado deja de conceder, como en `database`'
      )
    }).timeout(60_000)

    /**
     * 🟠 R1 (cierre-2 del lote A) · el MISMO 🟠 3 con la otra ortografía que PG
     * funde: `8-4-4-16`. Hasta el cierre-2 `scopeSpellings` no la expandía,
     * `purgeScope` demostraba cero sobre `scope:unit|<alias>` (sin hechos) y
     * el scope real conservaba `parent` y `binding`: `authorize` true para
     * siempre. Medido contra el servidor: ahora deja de conceder.
     */
    test('🟠 R1 · un `detached` con el uuid en 8-4-4-16 y la fila borrada purga el scope REAL: deja de conceder en `facts`', async ({
      assert,
    }) => {
      const { manager, tree, raw } = await factsWorld()
      const org = orgScope()
      const unit = unitScope()
      await tree.attach(org, APP_SCOPE)
      await manager.scopes.attached(org, APP_SCOPE)
      await tree.attach(unit, org)
      await manager.scopes.attached(unit, org)
      await manager.grant(alice, 'unit-editor', unit, { expiresAt: null })
      assert.isTrue(await manager.authorize(alice, 'docs:write', unit), 'de partida concede')

      const alias = unit.uuid!.slice(0, 23) + unit.uuid!.slice(24)
      assert.isTrue(isNonCanonicalUuid(alias))
      await tree.detach(unit)
      await manager.scopes.detached({ type: 'unit', uuid: alias } as any)

      const left = await raw.read({ object: `scope:unit|${unit.uuid}` })
      assert.lengthOf(left.tuples ?? [], 0, 'ROJO (R1): bajo la identidad REAL quedaban `parent` y `binding`')
      assert.isFalse(
        await manager.authorize(alice, 'docs:write', unit),
        'ROJO (R1): el scope borrado concedía para siempre'
      )
    }).timeout(60_000)

    /**
     * 🟠 4 · el choque de dos escritores del árbol. Es lo que hacen dos
     * pasadas del relay sobre el mismo lote, y el invariante 6 lo tiene
     * escrito: un choque no es una caída del backend.
     */
    test('🟠 4 · dos `attached` del mismo nodo a la vez: los dos OK, UN padre, y jamás un 503', async ({
      assert,
    }) => {
      const { driver, tree, raw } = await factsWorld()
      const org = orgScope()
      const unit = unitScope()
      await tree.attach(org, APP_SCOPE)
      await driver.onScopeAttached(org, APP_SCOPE)
      await tree.attach(unit, org)

      const results = await Promise.allSettled([
        driver.onScopeAttached(unit, org),
        driver.onScopeAttached(unit, org),
      ])

      assert.deepEqual(
        results.map((r) => r.status),
        ['fulfilled', 'fulfilled'],
        'el perdedor de la carrera se llevaba un 503 «el backend no respondió»'
      )
      const parents = await raw.read({ object: `scope:unit|${unit.uuid}`, relation: 'parent' })
      assert.lengthOf(parents.tuples ?? [], 1)
    }).timeout(60_000)

    /**
     * 🟠 4 · la CONSECUENCIA, y el punto que el informe del auditor deja
     * corto: un nodo con dos padres (que dos escritores del árbol a padres
     * DISTINTOS todavía pueden dejar — FGA no tiene compare-and-set) hereda
     * por las dos ramas y cruza tenants, `moved` lo DENUNCIA (500
     * `E_AUTHZ_SCOPE_TREE_DRIFT`: no se elige por ti) y `purgeScope` no toca
     * la arista a propósito… pero **`scopes.detached` sí se las lleva todas**,
     * así que la vía publicada —sacar el nodo y volver a colgarlo— repara.
     * No es irreparable con el paquete; lo irreparable era con `moved`.
     */
    test('🟠 4 · un nodo con DOS padres se repara con `scopes.detached` + `attached` (y `moved` lo denuncia)', async ({
      assert,
    }) => {
      const { driver, manager, tree, raw } = await factsWorld()
      const orgA = orgScope()
      const orgB = orgScope()
      const unit = unitScope()
      await tree.attach(orgA, APP_SCOPE)
      await tree.attach(orgB, APP_SCOPE)
      await driver.onScopeAttached(orgA, APP_SCOPE)
      await driver.onScopeAttached(orgB, APP_SCOPE)
      await tree.attach(unit, orgA)
      await Promise.allSettled([driver.onScopeAttached(unit, orgA), driver.onScopeAttached(unit, orgB)])
      const parentsOf = async () =>
        ((await raw.read({ object: `scope:unit|${unit.uuid}`, relation: 'parent' })).tuples ?? []).map(
          (t: any) => t.key.user
        )
      const parents = async () => (await parentsOf()).length

      // **3b-2i · el rojo intermitente, identificado.** La carrera tiene DOS
      // entrelazados legales, porque `reparent` es Read-luego-Write y FGA no
      // tiene compare-and-set:
      //  (a) los dos `Read` ven 0 padres ⇒ los dos escriben sin deletes ⇒ DOS
      //      aristas, que es la deriva que este caso repara;
      //  (b) el segundo `Read` llega después del primer `Write` ⇒ ve 1 padre,
      //      lo trata como un `moved` (delete + write) ⇒ UNA arista.
      // Exigir (a) era una aserción de moneda al aire —medido: ~2 de cada 9
      // pasadas en PostgreSQL daban (b)— y un caso flaky en el artefacto
      // publicado es la lección de 3G · Y1 otra vez. Así que se afirma lo que
      // de verdad es cierto (los dos finales son legales) y **el estado que
      // este caso juzga —el nodo con DOS padres— se garantiza**: si la carrera
      // salió benigna, la arista que falta se escribe a mano, que es lo mismo
      // que deja el otro entrelazado (o un operador con el SDK).
      const afterRace = await parentsOf()
      assert.include(
        [1, 2],
        afterRace.length,
        'la carrera a padres distintos deja una arista o las dos, según el entrelazado'
      )
      if (afterRace.length === 1) {
        const missing = afterRace[0] === `scope:organization|${orgA.uuid}` ? orgB : orgA
        await raw.write({
          writes: [
            {
              user: `scope:organization|${missing.uuid}`,
              relation: 'parent',
              object: `scope:unit|${unit.uuid}`,
            },
          ],
        })
      }
      assert.equal(await parents(), 2, 'el nodo tiene DOS padres: la deriva que se va a reparar')

      const mallory = { type: 'users', uuid: '0192f000-0000-7000-8000-00000000ba11' }
      await manager.grant(mallory, 'org-admin', orgB, { expiresAt: null })
      assert.isTrue(
        await manager.authorize(mallory, 'docs:write', unit),
        'CRUCE: el admin de la organization B alcanza una unit del tenant A'
      )

      await rejects(assert, () => manager.scopes.moved(unit, orgA), {
        status: 500,
        code: 'E_AUTHZ_SCOPE_TREE_DRIFT',
      })

      await tree.detach(unit)
      await manager.scopes.detached(unit)
      assert.equal(await parents(), 0, '`detached` se lleva TODAS las aristas del nodo')
      await tree.attach(unit, orgA)
      await manager.scopes.attached(unit, orgA)

      assert.equal(await parents(), 1)
      assert.isFalse(
        await manager.authorize(mallory, 'docs:write', unit),
        'reparado: el cruce entre tenants se ha ido'
      )
    }).timeout(60_000)
  })
}

test.group('3b-2d · el README dice el riesgo con SUS palabras', () => {
  /**
   * El dueño lo pidió literal, y con razón: el documento que este paquete
   * sustituye vendía esto como «cambios del árbol fuera del servicio», es
   * decir, mal uso. El hallazgo es que el USO CORRECTO fuga. Un test es lo
   * único que impide que la frase se suavice en la próxima pasada de estilo.
   */
  test('el lag del relay va escrito con los DOS signos: fail-open en `moved`/`detached`, fail-CLOSED en `attached`', async ({
    assert,
  }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, 'seconds during which FGA decides with the old tree')
    assert.include(readme, 'temporary fail-open')
    assert.include(readme, 'old tenant keeps access')
    assert.include(readme, 'persistent escalation your own database cannot show you')
    assert.include(readme, 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED')

    // **3b-2i.** La frase del 2d —«tras un `attached` los denies heredados no
    // aplican»— era la descripción del fail-open que (c2r) cierra, y hoy es
    // FALSA: un scope sin relevar no concede nada, ni siquiera de más. Si
    // reaparece en una pasada de estilo, el README estaría vendiendo el
    // defecto como comportamiento.
    assert.notInclude(
      readme,
      'inherited denies do not apply',
      'con (c2r) un `attached` sin relevar no concede: no hay denies que dejen de aplicar'
    )
    assert.include(readme, 'temporary fail-CLOSED')
    assert.include(readme, 'a newly created scope grants nothing at all until the relay runs')
    assert.include(readme, 'Without an outbox the window is zero')
    assert.include(readme, 'drain the queue in the same request')
  })

  /**
   * 3b-2h · 🔴 2: la frase que el 2d puso en el README —«cuanto más corto tu
   * ciclo de relay, más corta la ventana»— la desmintió el auditor R2 con una
   * medida: una entrada que no se puede aplicar congelaba el árbol del store
   * para siempre, así que la ventana no estaba acotada por el ciclo. El
   * arreglo destapona la cola, pero la frase entera seguía siendo falsa para
   * lo que NO se puede aplicar, y eso hay que decirlo con estas palabras.
   */
  test('el ciclo del relay NO acota la ventana de lo que no se puede aplicar, y va escrito', async ({
    assert,
  }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.notInclude(
      readme,
      'the shorter your relay cycle the shorter the window',
      'la frase del 2d era falsa: una entrada atascada hace la ventana infinita'
    )
    assert.include(readme, 'only for the changes the queue can actually apply')
    assert.include(readme, 'A change that fails is not bounded by your cycle')
    assert.include(readme, 'once it is parked it is never applied at all')
    assert.include(readme, 'defers what depends on it and lets the rest through')
    assert.include(readme, 'The relay is a single writer')
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * **3b-2i · I6 — la ventana del relay cambia de SIGNO.**
 *
 * Con (c2) un scope recién creado y todavía sin relevar CONCEDÍA (no había
 * llegado su arista, así que tampoco heredaba los denies de arriba: fail-open
 * temporal). Con (c2r) ese mismo scope no alcanza la raíz, y por tanto **no
 * concede nada**: el lag pasa a ser fail-CLOSED.
 *
 * Es la decisión firmada del dueño (2026-08-31 (2)) y va aquí como caso, no
 * como nota: conceder de menos durante segundos es disponibilidad, conceder
 * de más es el defecto que los lotes 2d y 2h acaban de perseguir. Y con la
 * ventana medida por los dos lados: **sin outbox es cero**.
 * ══════════════════════════════════════════════════════════════════════════ */
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('3b-2i · I6 — el lag del relay es fail-CLOSED para un scope NUEVO', (group) => {
    const stores: string[] = []
    group.each.setup(async () => {
      await cleanScopeOutbox(db)
      await cleanAuthzTables()
    })
    group.each.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) {
        await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
      }
    })

    const HOLDERS_2I = { users: 'user' }
    const PERMS_2I = ['docs:write']

    /**
     * `app ← orgA` ya relevado, los dos drivers sobre el mismo catálogo y el
     * mismo árbol, y la outbox declarada (o no, que es el control).
     */
    async function world(options: { outbox?: any } = {}) {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({
        name: `outbox-2i-${Date.now()}-${stores.length}`,
      })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS_2I, PERMS_2I)
      )
      const tree = memoryScopeTree()
      const chainOf = resolveChainFrom(tree)
      const fga: any = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id,
        holderTypes: HOLDERS_2I,
        resolveChain: chainOf,
        outbox: options.outbox,
        acceptScopeDriftRisk: options.outbox ? undefined : true,
        logger: { warn: () => {} },
      })
      await syncAuthzCatalog(
        {
          permissions: [{ slug: 'docs:write' }],
          roles: [{ slug: 'unit-editor', scopeType: 'unit', permissions: ['docs:write'] }],
        },
        { projection: fga.catalogProjection() }
      )
      const sql: any = new DatabaseAuthorizationDriver({ resolveChain: chainOf })
      const manager: any = new AuthorizationManager({
        default: 'openfga',
        drivers: { openfga: () => fga },
        holderTypes: HOLDERS_2I,
        scopes: {
          resolveChain: chainOf,
          outbox: options.outbox,
          ...(options.outbox ? {} : { acceptScopeDriftRisk: true }),
        },
        warnOnOptInSecurity: false,
      } as any)

      const orgA = orgScope()
      await tree.attach(orgA, APP_SCOPE)
      await fga.onScopeAttached(orgA, APP_SCOPE)

      const ask = async (subject: any, scope: any) => ({
        facts: await fga.authorize(subject, 'docs:write', scope),
        database: await sql.authorize(subject, 'docs:write', scope),
      })
      return { fga, sql, manager, tree, orgA, ask }
    }

    test('CON outbox: el tenant nuevo no concede hasta que pasa el relay (fail-CLOSED declarado)', async ({
      assert,
    }) => {
      const outbox = sqlScopeOutbox({ requireTransaction: false })
      const h = await world({ outbox })
      const alice = { type: 'users', uuid: uuidv7() }
      const unit = unitScope()

      // El consumidor crea la unit en SU base y la notifica: con outbox eso
      // ENCOLA, no toca el store.
      await h.tree.attach(unit, h.orgA)
      await h.manager.scopes.attached(unit, h.orgA)
      await h.fga.grant(alice, 'unit-editor', unit, { expiresAt: null })
      await h.sql.grant(alice, 'unit-editor', unit, { expiresAt: null })

      assert.lengthOf(await outbox.pending(10), 1, 'el `attached` está en la cola, sin relevar')
      assert.deepEqual(
        await h.ask(alice, unit),
        { facts: false, database: true },
        'FAIL-CLOSED declarado: hasta el relevo la unit no alcanza `app`, así que no concede'
      )

      const report = await h.manager.relayScopeChanges()
      assert.deepEqual(report.applied.map((a: any) => a.change.op), ['attached'])
      assert.deepEqual(
        await h.ask(alice, unit),
        { facts: true, database: true },
        'relevada la cola, los dos drivers vuelven a decir lo mismo'
      )
    }).timeout(60_000)

    test('SIN outbox la ventana es CERO: el manager llama al driver en línea y concede ya', async ({
      assert,
    }) => {
      const h = await world()
      const alice = { type: 'users', uuid: uuidv7() }
      const unit = unitScope()

      await h.tree.attach(unit, h.orgA)
      await h.manager.scopes.attached(unit, h.orgA)
      await h.fga.grant(alice, 'unit-editor', unit, { expiresAt: null })
      await h.sql.grant(alice, 'unit-editor', unit, { expiresAt: null })

      assert.deepEqual(
        await h.ask(alice, unit),
        { facts: true, database: true },
        'sin cola no hay lag: la arista se escribió en la misma llamada'
      )
    }).timeout(60_000)
  })
}

/* ══════════════════════════════════════════════════════════════════════════
 * **2.4.0-alpha.5 · R1 — el 🔴 1 del auditor contra el servidor REAL.**
 * `relay-auditor-2.ts`, con la API de verdad en vez del envoltorio que
 * filtraba `pending()` en memoria: la unit pasa de A a B (`moved`), B le
 * cuelga un hijo (`attached`), y el consumidor releva «lo suyo» con `only`.
 * Medido en alpha.4 (con el envoltorio): `authorize(A@orgA, docs:read,
 * child) = true` con el reporte en verde. Ahora: `deferred`, y A `false`.
 * ══════════════════════════════════════════════════════════════════════════ */
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('alpha.5 · R1 — `only` contra el :8101: el `attached` no se adelanta a su `moved` (sin escalada cruzada)', (group) => {
    const stores: string[] = []
    group.each.setup(async () => {
      await cleanScopeOutbox(db)
      await cleanAuthzTables()
      await cleanSqlScopeTree(db)
    })
    group.each.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) {
        await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
      }
    })

    test('EL CASO: `only: [attached]` ⇒ `deferred` (`depends-on:<moved>`), el editor de la org VIEJA sigue sin autorizar; el relay completo aterriza en orden y B autoriza. Con el tiempo de la pasada `only` frente a 500 ajenas', async ({
      assert,
    }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `outbox-a5-only-${Date.now()}` })
      stores.push(store.id!)
      const HOLDERS_A5 = { users: 'user' }
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS_A5, ['docs:read'])
      )
      const outbox = sqlScopeOutbox({ requireTransaction: false })
      const tree = sqlScopeTree(db)
      const chainOf = (scope: any) => sqlScopeTree(db).chainOf(scope)
      const driver: any = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id,
        holderTypes: HOLDERS_A5,
        resolveChain: chainOf,
        outbox,
        catalogRevalidate: { everyMs: 60_000 },
        logger: { warn: () => {} },
      })
      await syncAuthzCatalog(
        {
          permissions: [{ slug: 'docs:read' }],
          roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] }],
        },
        { projection: driver.catalogProjection() }
      )
      const manager: any = new AuthorizationManager({
        default: 'openfga',
        drivers: { openfga: () => driver },
        holderTypes: HOLDERS_A5,
        scopes: { resolveChain: chainOf, outbox },
        warnOnOptInSecurity: false,
      } as any)

      const orgA = orgScope()
      const orgB = orgScope()
      const orgC = orgScope()
      const unit = unitScope()
      const child = unitScope()
      await tree.attach(orgA, APP_SCOPE)
      await tree.attach(orgB, APP_SCOPE)
      await tree.attach(orgC, APP_SCOPE)
      await tree.attach(unit, orgA)
      await driver.onScopeAttached(orgA, APP_SCOPE)
      await driver.onScopeAttached(orgB, APP_SCOPE)
      await driver.onScopeAttached(orgC, APP_SCOPE)
      await driver.onScopeAttached(unit, orgA)
      const holderA = { type: 'users', uuid: uuidv7() }
      const holderB = { type: 'users', uuid: uuidv7() }
      await manager.grant(holderA, 'org-editor', orgA, { expiresAt: null })
      await manager.grant(holderB, 'org-editor', orgB, { expiresAt: null })
      assert.isTrue(await manager.authorize(holderA, 'docs:read', unit), 'base: la unit es de A')

      // 500 entradas AJENAS por delante (el tenant C crea units): el backlog
      // que la receta inline pagaba entera.
      for (let i = 0; i < 500; i++) await outbox.enqueue({ op: 'attached', child: unitScope(), parent: orgC }, {})

      // La transferencia: la unit pasa a B, y B le cuelga un hijo. (Sin
      // `{ transaction }`: en `:memory:` el pool es de 1 y la barrera del
      // freeze no tendría conexión — la regla publicada de L-1; lo que se
      // juzga aquí es el ORDEN, no la transacción.)
      const { queued: [movedId] } = await manager.scopes.moved(unit, orgB)
      await db.from('demo_scopes').where('uuid', unit.uuid).update({ parent_uuid: orgB.uuid })
      await tree.attach(child, unit)
      const { queued: [attachedId] } = await manager.scopes.attached(child, unit)

      // «Solo lo mío»: el attached. Su moved no se pidió ⇒ aplazado.
      const t0 = performance.now()
      const report = await manager.relayScopeChanges({ only: [attachedId] })
      const onlyMs = performance.now() - t0
      assert.deepEqual(report.applied, [])
      assert.deepEqual(report.entries.map((e: any) => [e.status, e.reason]), [['deferred', `depends-on:${movedId}`]])
      assert.isTrue(report.remaining)
      assert.isFalse(await manager.authorize(holderA, 'docs:read', child), 'A (la org VIEJA) NO autoriza sobre el hijo: sin escalada cruzada')
      assert.isFalse(await manager.authorize(holderB, 'docs:read', child), 'B tampoco todavía: fail-CLOSED hasta que aterrice el moved')

      // Los dos: en orden. B autoriza, A no.
      const t1 = performance.now()
      const both = await manager.relayScopeChanges({ only: [movedId, attachedId] })
      const bothMs = performance.now() - t1
      assert.deepEqual(both.applied.map((a: any) => a.change.op), ['moved', 'attached'])
      assert.isTrue(await manager.authorize(holderB, 'docs:read', child), 'el dueño legítimo')
      assert.isFalse(await manager.authorize(holderA, 'docs:read', child))
      assert.isTrue(both.remaining, '500 ajenas siguen ahí y el reporte lo dice')

      // Y lo que costaba la receta de hoy: la cola entera.
      const t2 = performance.now()
      const drain = await manager.relayScopeChanges()
      const drainMs = performance.now() - t2
      assert.lengthOf(drain.applied, 500)
      assert.isFalse(drain.remaining)
      console.log(
        `[only · :8101] pasada only (1 aplazada, 0 FGA): ${onlyMs.toFixed(1)} ms · only [moved, attached]: ${bothMs.toFixed(1)} ms · ` +
          `drenar las 500 ajenas: ${drainMs.toFixed(0)} ms`
      )
      assert.isBelow(bothMs, drainMs / 10, 'relevar lo mío no paga la cola de los demás')
    }).timeout(120_000)
  })
}

test.group('alpha.5 · el README y el comando dicen el recibo, `only` y el aparcado con SUS palabras', () => {
  test('README: recibo, `only` con su regla («deferred, never out of order»), sin filtro por tenant, el 503 que no consume intento, el desdoble del aparcado y el aviso de no devolver el reporte por HTTP', async ({
    assert,
  }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, '`{ queued: [id] }`')
    assert.include(readme, 'relayScopeChanges({ only: queued })')
    assert.include(readme, 'deferred, never out of order')
    assert.include(readme, 'never from the request body')
    assert.include(readme, 'There is no filter by tenant or organization')
    assert.include(readme, 'A 503 does not consume an attempt')
    assert.include(readme, 'A parked entry blocks, by scope key, what grants or re-parents')
    assert.include(readme, 'lets through what retires')
    assert.include(readme, 'Do not return the relay report over HTTP')
    assert.include(readme, 'the inline pass returns a report, it does not throw')
    assert.include(readme, '`remaining` and `dead` are always global')
  })

  test('README (R2b): `authz:scopes:requeue --id`, la negativa con su código, `--force` solo en el comando y `attempts = maxAttempts − 1`', async ({
    assert,
  }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, 'node ace authz:scopes:requeue --id=')
    assert.include(readme, 'E_AUTHZ_REQUEUE_REFUSED')
    assert.include(readme, '`--force` exists only in the ace command')
    assert.include(readme, '`attempts` is set to `maxAttempts − 1`')
    assert.include(readme, 'requeueScopeChanges')
  })

  test('el comando declara `--only` y su salida es por entrada', async ({ assert }) => {
    const commands: any = await import('../commands/main.js')
    const nombres = flagNamesOf(commands.AuthzScopesRelay)
    assert.includeMembers(nombres, ['dry-run', 'limit', 'batch-size', 'only'])
    const source = await readFile(new URL('../commands/authz_scopes_relay.ts', import.meta.url), 'utf8')
    assert.include(source, 'report.entries')
    assert.include(source, 'report.missing')
    assert.include(source, 'parked:')
  })
})
