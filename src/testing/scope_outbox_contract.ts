/**
 * **El contrato del puerto `ScopeOutbox`** (2.4.0-alpha.5 · R5; tester del
 * panel relay, su recomendación nº 1) — el juez de una outbox del árbol,
 * SEPARADO del runner de drivers (precedente: `runRelationsDriverContract`).
 *
 *   import { runScopeOutboxContract } from '@jantstack/adonis-authz/testing'
 *
 * El puerto tiene deberes que hasta alpha.5 solo cumplía la implementación
 * del paquete y que el manager solo caza en caliente en dos casos (el bucle
 * de un `markApplied` no honrado y el `only` no honrado): el recibo, el orden
 * por antigüedad, `after` como continuación, `markApplied` idempotente,
 * `markFailed` que cuenta y no pierde la fila, el actor que viaja. Y desde
 * alpha.5 cada método OPCIONAL es un **par de capacidad**: una cara `true`
 * que juzga el deber y una cara `false` que juzga que el manager lo DICE (o
 * que la implementación degrada hacia lo seguro), jamás un `skip`. El runner
 * FALLA al registrarse si una cara no está poblada o si una capacidad `true`
 * llega sin lo que hace falta para observarla.
 *
 * Corre contra `sqlScopeOutbox` en los cuatro motores de la suite y contra
 * el doble en memoria de aquí (`makeScopeOutbox`), en sus dos formas.
 */
import { v7 as uuidv7 } from 'uuid'
import { test as japaTest } from '@japa/runner'
import type { Assert } from '@japa/assert'
import { AuthorizationManager } from '../manager.js'
import { memoryScopeTree, resolveChainFrom } from './scope_tree.js'
import { APP_SCOPE } from '../types.js'
import type { PendingScopeTreeChange, ScopeOutbox, ScopeOutboxContext, ScopeRef, ScopeTreeChange, SubjectRef } from '../types.js'
import type { ContractTestApi } from './contract.js'

/* ── El vocabulario del contrato ─────────────────────────────────────────── */

/**
 * Lo que una outbox DECLARA. Cada clave es un par: la cara `true` juzga el
 * deber, la `false` juzga la ausencia (el manager lo dice, o la
 * implementación degrada hacia lo seguro).
 */
export interface ScopeOutboxCapabilities {
  /**
   * `enqueue` escribe por `context.transaction`: un rollback del llamante no
   * deja intención ninguna, un commit sí. Es TODO el mecanismo de la
   * mitigación (README, «The tree outbox»). Exige `transactions` en el
   * harness. `false` = la implementación ignora la transacción (un doble en
   * memoria): la cara juzga solo que encolar sin transacción funciona, y la
   * mitigación queda APAGADA — dilo en tu README.
   */
  transactionalEnqueue: boolean
  /** `pending(limit, after, { ids })` filtra EN EL PUERTO (alpha.5 · R1). `false` ⇒ el manager corta `only` con 500. */
  filter: boolean
  /** `markFailed(id, error, { transient: true })` NO cuenta el intento (alpha.5 · R2a). `false` ⇒ cuenta siempre (lo de alpha.4). */
  transient: boolean
  /** `dead()` existe: tras `limits.maxAttempts` fallos la entrada sale de `pending()` y entra en `dead()` (3b-2h). */
  dead: boolean
  /** `acquire()` existe: lease SOSTENIDO y exclusivo (3b-2h · 🟠 4). `false` ⇒ el relay corre sin lease y lo dice el README. */
  acquire: boolean
  /** `earlierPending(id, scopes)` existe (alpha.5 · R1). `false` ⇒ el manager pagina `pending()` y el veredicto es el mismo. */
  earlierPending: boolean
  /** `requeue(ids)` Y `laterApplied(id, scopes, limit)` existen (alpha.5 · R2b). Exige `dead: true`. `false` ⇒ `requeueScopeChanges` es 500. */
  requeue: boolean
}

export const SCOPE_OUTBOX_CAPABILITY_KEYS: ReadonlyArray<keyof ScopeOutboxCapabilities> = [
  'transactionalEnqueue',
  'filter',
  'transient',
  'dead',
  'acquire',
  'earlierPending',
  'requeue',
]

export interface ScopeOutboxContractHarness {
  name: string
  capabilities: ScopeOutboxCapabilities
  /** Una outbox FRESCA por caso, sobre una cola VACÍA (el harness la vacía en `cleanup`). */
  makeOutbox(): ScopeOutbox | Promise<ScopeOutbox>
  /** Vacía la cola antes de cada caso. */
  cleanup?(): Promise<void>
  /**
   * Con `dead: true` (y por tanto `requeue: true`): el `maxAttempts` con el
   * que está construida la outbox, ≥ 3 (los casos cuentan dos fallos sin
   * aparcar y luego aparcan de verdad).
   */
  limits?: { maxAttempts?: number }
  /** Con `transactionalEnqueue: true`: cómo abre el juez una transacción de LA CONEXIÓN de la outbox. */
  transactions?: ScopeOutboxContractTransactions
}

/** Ver `ScopeOutboxContractHarness.transactions`. */
export interface ScopeOutboxContractTransactions {
  begin(): Promise<{ client: unknown; commit(): Promise<unknown>; rollback(): Promise<unknown> }>
}

/* ── El DOBLE en memoria ─────────────────────────────────────────────────── */

export interface MakeScopeOutboxOptions {
  capabilities: ScopeOutboxCapabilities
  /** Solo con `dead: true` (default 5). */
  maxAttempts?: number
}

function keyOf(scope: ScopeRef): string {
  return scope.type === 'app' ? 'app' : `${scope.type}|${scope.uuid}`
}

function keysOf(change: ScopeTreeChange): string[] {
  return change.op === 'detached' ? [keyOf(change.child)] : [keyOf(change.child), keyOf(change.parent)]
}

/**
 * Una outbox EN MEMORIA que implementa el puerto entero y expone SOLO lo que
 * declara: con `filter: false` ignora `ids`, con `transient: false` cuenta
 * siempre, con `dead: false` no aparca (y no tiene `dead`), y sin `acquire`/
 * `earlierPending`/`requeue` no trae esos métodos. Es la forma de ejercer LAS
 * DOS CARAS de cada par sin servidor. No escribe por ninguna transacción:
 * `transactionalEnqueue` tiene que ser `false` (lanza si no).
 */
export function makeScopeOutbox(options: MakeScopeOutboxOptions): ScopeOutbox {
  const caps = options.capabilities
  if (caps.transactionalEnqueue) {
    throw new Error('makeScopeOutbox: el doble en memoria no escribe por ninguna transacción; declara transactionalEnqueue: false')
  }
  const max = options.maxAttempts ?? 5
  const rows: Array<{ change: ScopeTreeChange; actor?: SubjectRef; attempts: number; lastError?: string; applied: boolean }> = []
  const view = (index: number): PendingScopeTreeChange => {
    const row = rows[index]
    return {
      id: index + 1,
      change: row.change,
      attempts: row.attempts,
      ...(row.actor ? { actor: row.actor } : {}),
      ...(row.lastError === undefined ? {} : { lastError: row.lastError }),
    }
  }
  const parked = (index: number) => caps.dead && rows[index].attempts >= max
  const isPending = (index: number) => !rows[index].applied && !parked(index)
  const indexOf = (id: string | number) => Number(id) - 1
  const outbox: ScopeOutbox = {
    async enqueue(change, context) {
      rows.push({ change, actor: context?.actor, attempts: 0, applied: false })
      return { id: rows.length }
    },
    async pending(limit, after, filter) {
      return rows
        .map((_, index) => index)
        .filter(isPending)
        .filter((index) => after === undefined || index + 1 > Number(after))
        .filter((index) => !caps.filter || filter === undefined || filter.ids.map(String).includes(String(index + 1)))
        .slice(0, limit)
        .map(view)
    },
    async markApplied(id) {
      const row = rows[indexOf(id)]
      if (row) row.applied = true
    },
    async markFailed(id, error, options) {
      const row = rows[indexOf(id)]
      if (!row) return
      row.lastError = String(error)
      if (!(caps.transient && options?.transient === true)) row.attempts += 1
    },
  }
  if (caps.dead) {
    outbox.dead = async (limit) =>
      rows
        .map((_, index) => index)
        .filter((index) => !rows[index].applied && parked(index))
        .slice(0, limit)
        .map(view)
  }
  if (caps.acquire) {
    let held = false
    outbox.acquire = async () => {
      if (held) return null
      held = true
      return { release: async () => void (held = false) }
    }
  }
  if (caps.earlierPending) {
    outbox.earlierPending = async (id, scopes) => {
      const wanted = scopes.map(keyOf)
      const hit = rows
        .map((_, index) => index)
        .filter((index) => index + 1 < Number(id) && isPending(index))
        .find((index) => keysOf(rows[index].change).some((k) => wanted.includes(k)))
      return hit === undefined ? null : view(hit)
    }
  }
  if (caps.requeue) {
    outbox.laterApplied = async (id, scopes, limit) => {
      const wanted = scopes.map(keyOf)
      return rows
        .map((_, index) => index)
        .filter((index) => index + 1 > Number(id) && rows[index].applied)
        .filter((index) => keysOf(rows[index].change).some((k) => wanted.includes(k)))
        .slice(0, limit)
        .map(view)
    }
    outbox.requeue = async (ids) => {
      if (!Array.isArray(ids) || ids.length === 0) throw new Error('makeScopeOutbox.requeue: ids vacío')
      const bad = ids.filter((id) => {
        const row = rows[indexOf(id)]
        return !row || row.applied || !parked(indexOf(id))
      })
      if (bad.length > 0) throw new Error(`makeScopeOutbox.requeue: ${bad.join(', ')} no está(n) aparcada(s): nada se ha tocado`)
      for (const id of ids) rows[indexOf(id)].attempts = max - 1
    }
  }
  return outbox
}

/* ── El runner ───────────────────────────────────────────────────────────── */

export function runScopeOutboxContract(harness: ScopeOutboxContractHarness) {
  return registerScopeOutboxContract(harness, {
    group: (title, define) => japaTest.group(title, define as any),
    test: (title, fn) => japaTest(title, fn as any),
  })
}

const orgScope = (): ScopeRef => ({ type: 'organization', uuid: uuidv7() })
const unitScope = (): ScopeRef => ({ type: 'unit', uuid: uuidv7() })
const ids = (items: Array<{ id: string | number }>) => items.map((item) => String(item.id))

async function rejects(assert: Assert, run: () => unknown, expected: { status?: number; code?: string }, message?: string): Promise<any> {
  let caught: any = null
  try {
    await run()
  } catch (error) {
    caught = error
  }
  assert.isNotNull(caught, `${message ?? 'la operación'}: debería haber lanzado`)
  if (expected.status !== undefined) assert.equal(caught.status, expected.status, message)
  if (expected.code !== undefined) assert.equal(caught.code, expected.code, message)
  return caught
}

/**
 * El MOTOR del runner (registro de casos), separado para que el propio
 * paquete pueda contar los casos (`scope_outbox_harness.spec.ts`). Devuelve
 * el nº de casos registrados y las capacidades cubiertas.
 */
export function registerScopeOutboxContract(
  harness: ScopeOutboxContractHarness,
  api: { group: ContractTestApi['group']; test: ContractTestApi['test'] }
): { registered: number; covered: Set<keyof ScopeOutboxCapabilities> } {
  const caps = harness.capabilities
  for (const key of SCOPE_OUTBOX_CAPABILITY_KEYS) {
    if (typeof caps[key] !== 'boolean') {
      throw new Error(`[contrato ${harness.name}] la capacidad '${key}' tiene que ser un booleano (llegó ${String(caps[key])})`)
    }
  }
  const maxAttempts = harness.limits?.maxAttempts
  if (caps.dead && !(Number.isInteger(maxAttempts) && (maxAttempts as number) >= 3)) {
    throw new Error(
      `[contrato ${harness.name}] declara 'dead: true' sin 'limits.maxAttempts' (entero >= 3): sin saber cuándo aparca tu ` +
        `outbox no hay forma de observar el aparcado (un skip disfrazado).`
    )
  }
  if (caps.requeue && !caps.dead) {
    throw new Error(`[contrato ${harness.name}] declara 'requeue: true' sin 'dead: true': solo lo aparcado se reencola.`)
  }
  if (caps.transactionalEnqueue && typeof harness.transactions?.begin !== 'function') {
    throw new Error(
      `[contrato ${harness.name}] declara 'transactionalEnqueue: true' sin 'transactions.begin': sin una transacción de TU ` +
        `conexión no se puede observar el rollback (un skip disfrazado).`
    )
  }

  const covered = new Set<keyof ScopeOutboxCapabilities>()
  let registered = 0
  const state: { outbox: ScopeOutbox } = {} as any

  /** El manager sobre la outbox del caso, con un driver espía. */
  function managerOver(outbox: ScopeOutbox, tree = memoryScopeTree()) {
    const calls: string[] = []
    const driver: any = {
      authorize: async () => false,
      onScopeAttached: async (c: ScopeRef, p: ScopeRef) => void calls.push(`attached ${keyOf(c)} → ${keyOf(p)}`),
      onScopeMoved: async (c: ScopeRef, p: ScopeRef) => void calls.push(`moved ${keyOf(c)} → ${keyOf(p)}`),
      onScopeDetached: async (c: ScopeRef) => void calls.push(`detached ${keyOf(c)}`),
      purgeScope: async () => {},
    }
    const manager = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => driver },
      scopes: { resolveChain: resolveChainFrom(tree), outbox },
      warnOnOptInSecurity: false,
    } as any)
    return { manager, driver, calls, tree }
  }

  const ctx = (actor?: SubjectRef): ScopeOutboxContext => (actor ? { actor } : {})

  api.group(`scope outbox contract [${harness.name}]`, (group) => {
    group.each.setup(async () => {
      await harness.cleanup?.()
      state.outbox = await harness.makeOutbox()
    })

    const test = (title: string, fn: (ctx: { assert: Assert }) => Promise<void>) => {
      registered++
      return api.test(title, fn)
    }

    function caseFor(capability: keyof ScopeOutboxCapabilities, pair: { whenTrue: () => void; whenFalse: () => void }) {
      if (typeof pair.whenTrue !== 'function' || typeof pair.whenFalse !== 'function') {
        throw new Error(
          `[contrato ${harness.name}] la capacidad '${capability}' no declara sus dos caras (whenTrue Y whenFalse): ` +
            `una cara ausente es un skip disfrazado.`
        )
      }
      const before = registered
      ;(caps[capability] ? pair.whenTrue : pair.whenFalse)()
      if (registered > before) covered.add(capability)
    }

    /* ── Núcleo: los deberes que todo puerto tiene ── */

    test('O-01 · recibo: `enqueue` devuelve `{ id }` (o void) y ese id es EXACTAMENTE el que `pending()` devuelve', async ({ assert }) => {
      const outbox = state.outbox
      const receipt = await outbox.enqueue({ op: 'attached', child: unitScope(), parent: orgScope() }, ctx())
      const [row] = await outbox.pending(10)
      assert.isDefined(row, 'lo encolado está pendiente')
      if (receipt !== undefined && receipt !== null) {
        assert.isTrue(typeof receipt === 'object' && ('id' in receipt), 'el recibo es { id }')
        assert.equal(String((receipt as any).id), String(row.id), 'el MISMO id que pending(): sin eso no hay only')
      }
    })

    test('O-02 · `pending` da los MÁS ANTIGUOS primero, respeta `limit`, y devuelve la identidad intacta (la raíz como padre, `detached` sin padre, el actor)', async ({
      assert,
    }) => {
      const outbox = state.outbox
      const org = orgScope()
      const unit = unitScope()
      const actor = { type: 'users', uuid: uuidv7() }
      await outbox.enqueue({ op: 'attached', child: org, parent: APP_SCOPE }, ctx(actor))
      await outbox.enqueue({ op: 'moved', child: unit, parent: org }, ctx())
      await outbox.enqueue({ op: 'detached', child: unit }, ctx())
      const all = await outbox.pending(10)
      assert.deepEqual(
        all.map((p) => p.change),
        [
          { op: 'attached', child: org, parent: APP_SCOPE },
          { op: 'moved', child: unit, parent: org },
          { op: 'detached', child: unit },
        ],
        'en orden de encolado y con la identidad tal cual'
      )
      assert.deepEqual(all[0].actor, actor, 'el actor viaja')
      assert.isUndefined(all[1].actor, 'y sin actor no se inventa')
      assert.equal(all[0].attempts ?? 0, 0)
      assert.deepEqual(ids(await outbox.pending(2)), ids(all).slice(0, 2), '`limit` acota por delante')
      assert.isTrue(new Set(ids(all)).size === 3, 'ids distintos')
    })

    test('O-03 · `after` continúa DESPUÉS de un id: lo saltado no vuelve a salir el primero (3b-2h · 🔴 2)', async ({ assert }) => {
      const outbox = state.outbox
      await outbox.enqueue({ op: 'detached', child: unitScope() }, ctx())
      await outbox.enqueue({ op: 'detached', child: unitScope() }, ctx())
      await outbox.enqueue({ op: 'detached', child: unitScope() }, ctx())
      const [a, b, c] = await outbox.pending(10)
      assert.deepEqual(ids(await outbox.pending(10, a.id)), [String(b.id), String(c.id)])
      assert.deepEqual(ids(await outbox.pending(1, a.id)), [String(b.id)])
      assert.deepEqual(await outbox.pending(10, c.id), [])
    })

    test('O-04 · `markApplied` saca la entrada de `pending()` y es idempotente; lo encolado después sigue saliendo', async ({ assert }) => {
      const outbox = state.outbox
      await outbox.enqueue({ op: 'detached', child: unitScope() }, ctx())
      const [first] = await outbox.pending(10)
      await outbox.markApplied(first.id)
      assert.deepEqual(await outbox.pending(10), [])
      await outbox.markApplied(first.id)
      assert.deepEqual(await outbox.pending(10), [], 'la segunda vez no revive nada ni lanza')
      await outbox.enqueue({ op: 'detached', child: unitScope() }, ctx())
      const rest = await outbox.pending(10)
      assert.lengthOf(rest, 1)
      assert.notEqual(String(rest[0].id), String(first.id))
    })

    test('O-05 · `markFailed` DEJA la entrada pendiente, cuenta el intento y guarda la causa (a la vista en `pending()`)', async ({ assert }) => {
      const outbox = state.outbox
      await outbox.enqueue({ op: 'detached', child: unitScope() }, ctx())
      const [row] = await outbox.pending(10)
      await outbox.markFailed(row.id, 'el padre no existe')
      const [once] = await outbox.pending(10)
      assert.equal(String(once.id), String(row.id), 'sigue pendiente')
      assert.equal(once.attempts, 1)
      assert.equal(once.lastError, 'el padre no existe')
      await outbox.markFailed(row.id, 'sigue sin existir')
      const [twice] = await outbox.pending(10)
      assert.equal(twice.attempts, 2)
      assert.equal(twice.lastError, 'sigue sin existir', 'la ÚLTIMA causa')
    })

    test('O-06 · el manager la drena: `relayScopeChanges()` aplica en orden, marca, y la pasada siguiente no vuelve a aplicar nada', async ({
      assert,
    }) => {
      const { manager, calls, tree } = managerOver(state.outbox)
      const org = orgScope()
      const unit = unitScope()
      await tree.attach(org, APP_SCOPE)
      await tree.attach(unit, org)
      await manager.scopes.attached(org, APP_SCOPE)
      await manager.scopes.attached(unit, org)
      assert.deepEqual(calls, [], 'con outbox el driver no ve nada al notificar')
      const first = await manager.relayScopeChanges()
      assert.lengthOf(first.applied, 2)
      assert.deepEqual(calls, [`attached ${keyOf(org)} → app`, `attached ${keyOf(unit)} → ${keyOf(org)}`])
      assert.isFalse(first.remaining)
      const second = await manager.relayScopeChanges()
      assert.deepEqual(second.applied, [])
      assert.lengthOf(calls, 2, 'nada se aplica dos veces')
    })

    test('O-07 · un fallo APLAZA lo que comparte clave y deja pasar el resto; la pasada siguiente retoma desde la cola (no desde memoria)', async ({
      assert,
    }) => {
      const { manager, driver, calls, tree } = managerOver(state.outbox)
      const org = orgScope()
      const unit = unitScope()
      // Independiente de verdad: no comparte NINGUNA clave (ni la raíz) con lo que falla.
      const other = unitScope()
      await tree.attach(org, APP_SCOPE)
      await tree.attach(unit, org)
      await manager.scopes.attached(org, APP_SCOPE)
      await manager.scopes.attached(unit, org)
      await manager.scopes.detached(other)
      driver.onScopeAttached = async (c: ScopeRef, p: ScopeRef) => {
        if (keyOf(c) === keyOf(org)) throw new Error('el store no lo acepta')
        calls.push(`attached ${keyOf(c)} → ${keyOf(p)}`)
      }
      const report = await manager.relayScopeChanges()
      assert.deepEqual(report.failures.map((f) => keyOf(f.change.child)), [keyOf(org)])
      assert.deepEqual(report.deferred.map((d) => keyOf(d.change.child)), [keyOf(unit)], 'lo que depende, aplazado')
      assert.deepEqual(report.applied.map((a) => keyOf(a.change.child)), [keyOf(other)], 'lo independiente, aplicado')
      assert.deepEqual(calls, [`detached ${keyOf(other)}`])
      assert.isTrue(report.remaining)
      const [head] = await state.outbox.pending(10)
      assert.equal(keyOf(head.change.child), keyOf(org), 'la fallida sigue la primera en la COLA, con su intento')
      assert.isAtLeast(head.attempts ?? 0, 1)
    })

    test('O-08 · `pending()` no ESCONDE nada: lo encolado por dos «tenants» sale entero, en orden de id — el orden del relay se apoya en esto (auditor alpha.5 · 🟡 3)', async ({
      assert,
    }) => {
      const outbox = state.outbox
      const tenantA = orgScope()
      const tenantB = orgScope()
      const unitA = unitScope()
      const unitB = unitScope()
      const wanted: ScopeTreeChange[] = [
        { op: 'attached', child: tenantA, parent: APP_SCOPE },
        { op: 'attached', child: tenantB, parent: APP_SCOPE },
        { op: 'attached', child: unitA, parent: tenantA },
        { op: 'attached', child: unitB, parent: tenantB },
        { op: 'moved', child: unitA, parent: tenantB },
        { op: 'detached', child: unitB },
      ]
      for (const change of wanted) await outbox.enqueue(change, ctx())
      const all = await outbox.pending(100)
      assert.deepEqual(all.map((p) => p.change), wanted, 'las seis, de los dos tenants, en orden de encolado')
      const first = await outbox.pending(4)
      const rest = await outbox.pending(100, first[first.length - 1].id)
      assert.deepEqual([...first, ...rest].map((p) => p.change), wanted, 'y paginando con `after` también salen todas')
    })

    /* ── Los pares de capacidad ── */

    caseFor('transactionalEnqueue', {
      whenTrue: () =>
        test('transactionalEnqueue:true · `enqueue` por la transacción del llamante: ROLLBACK ⇒ nada pendiente; COMMIT ⇒ pendiente', async ({
          assert,
        }) => {
          const outbox = state.outbox
          const rolled = await harness.transactions!.begin()
          await outbox.enqueue({ op: 'detached', child: unitScope() }, { transaction: rolled.client })
          await rolled.rollback()
          assert.deepEqual(await outbox.pending(10), [], 'el rollback se lleva la intención: es TODO el mecanismo')
          const committed = await harness.transactions!.begin()
          const unit = unitScope()
          await outbox.enqueue({ op: 'detached', child: unit }, { transaction: committed.client })
          await committed.commit()
          assert.deepEqual((await outbox.pending(10)).map((p) => p.change), [{ op: 'detached', child: unit }])
        }),
      whenFalse: () =>
        test('transactionalEnqueue:false · encolar SIN transacción funciona (y la mitigación del rollback queda apagada: dilo en tu README)', async ({
          assert,
        }) => {
          const outbox = state.outbox
          const unit = unitScope()
          await outbox.enqueue({ op: 'detached', child: unit }, {})
          assert.deepEqual((await outbox.pending(10)).map((p) => p.change), [{ op: 'detached', child: unit }])
        }),
    })

    caseFor('filter', {
      whenTrue: () =>
        test('filter:true · `pending(limit, after, { ids })` devuelve SOLO esos ids, en orden, y con `after`; el manager aplica solo lo pedido', async ({
          assert,
        }) => {
          const outbox = state.outbox
          const { manager, calls } = managerOver(outbox)
          // Tres entradas INDEPENDIENTES (sin clave común, ni la raíz): lo pedido no depende de nada.
          const [a, b, c] = [unitScope(), unitScope(), unitScope()]
          const ia = (await outbox.enqueue({ op: 'detached', child: a }, ctx()))!.id
          const ib = (await outbox.enqueue({ op: 'detached', child: b }, ctx()))!.id
          const ic = (await outbox.enqueue({ op: 'detached', child: c }, ctx()))!.id
          assert.deepEqual(ids(await outbox.pending(10, undefined, { ids: [ic, ia] })), [String(ia), String(ic)], 'en orden de id, no del array')
          assert.deepEqual(ids(await outbox.pending(10, ia, { ids: [ic, ia] })), [String(ic)], '`after` sigue valiendo')
          const report = await manager.relayScopeChanges({ only: [ib] })
          assert.deepEqual(report.applied.map((x) => String(x.id)), [String(ib)])
          assert.deepEqual(calls, [`detached ${keyOf(b)}`])
          assert.isTrue(report.remaining, 'las otras dos siguen ahí (global)')
        }),
      whenFalse: () =>
        test('filter:false · una outbox que IGNORA `ids` no aplica el backlog ajeno en silencio: `relayScopeChanges({ only })` es 500 E_AUTHZ_CONFIG con cero llamadas', async ({
          assert,
        }) => {
          const { manager, calls } = managerOver(state.outbox)
          await state.outbox.enqueue({ op: 'detached', child: unitScope() }, ctx())
          const ib = (await state.outbox.enqueue({ op: 'detached', child: unitScope() }, ctx()))!.id
          const error = await rejects(assert, () => manager.relayScopeChanges({ only: [ib] }), { status: 500, code: 'E_AUTHZ_CONFIG' })
          assert.include(error.message, 'pending(limit, after, { ids })')
          assert.deepEqual(calls, [])
        }),
    })

    caseFor('transient', {
      whenTrue: () =>
        test('transient:true · `markFailed(id, error, { transient: true })` escribe la causa y NO cuenta el intento; sin `transient`, cuenta', async ({
          assert,
        }) => {
          const outbox = state.outbox
          await outbox.enqueue({ op: 'detached', child: unitScope() }, ctx())
          const [row] = await outbox.pending(10)
          await outbox.markFailed(row.id, 'el store no responde', { transient: true })
          const [after] = await outbox.pending(10)
          assert.equal(after.attempts, 0, 'una caída del store no dice nada de la fila')
          assert.equal(after.lastError, 'el store no responde', 'pero nada se vuelve silencioso')
          await outbox.markFailed(row.id, 'el padre no existe')
          assert.equal((await outbox.pending(10))[0].attempts, 1)
        }),
      whenFalse: () =>
        test('transient:false · una outbox que ignora el tercer parámetro cuenta el intento igual (lo de alpha.4: degrada hacia lo seguro)', async ({
          assert,
        }) => {
          const outbox = state.outbox
          await outbox.enqueue({ op: 'detached', child: unitScope() }, ctx())
          const [row] = await outbox.pending(10)
          await outbox.markFailed(row.id, 'el store no responde', { transient: true })
          assert.equal((await outbox.pending(10))[0].attempts, 1)
        }),
    })

    caseFor('dead', {
      whenTrue: () =>
        test('dead:true · tras `maxAttempts` fallos la entrada sale de `pending()` y entra en `dead()` con sus intentos y su causa; el relay la reporta y tapona su clave (alpha.5 · R2a)', async ({
          assert,
        }) => {
          const outbox = state.outbox
          const { manager, calls, tree } = managerOver(outbox)
          const org = orgScope()
          const unit = unitScope()
          await tree.attach(org, APP_SCOPE)
          await tree.attach(unit, org)
          const { queued: [id] } = await manager.scopes.moved(unit, org)
          for (let i = 0; i < maxAttempts!; i++) await outbox.markFailed(id, `fallo ${i + 1}`)
          assert.deepEqual(await outbox.pending(10), [], 'agotados los intentos, deja de ofrecerse')
          const dead = await outbox.dead!(10)
          assert.deepEqual(ids(dead), [String(id)])
          assert.equal(dead[0].attempts, maxAttempts)
          assert.equal(dead[0].lastError, `fallo ${maxAttempts}`)
          assert.deepEqual(ids(await outbox.dead!(1)), [String(id)], '`limit` acota')
          // Y el manager: reportada, y el attached que nombra su clave se APLAZA (parked:<id>).
          const child = unitScope()
          await tree.attach(child, unit)
          await manager.scopes.attached(child, unit)
          const report = await manager.relayScopeChanges()
          assert.deepEqual(ids(report.dead), [String(id)])
          assert.deepEqual(report.entries.map((e) => [e.status, e.reason ?? null]), [['deferred', `parked:${id}`], ['dead', `fallo ${maxAttempts}`]])
          assert.deepEqual(calls, [])
        }),
      whenFalse: () =>
        test('dead:false · sin `dead()` nada se aparca: tras N fallos la entrada sigue en `pending()` y el reporte dice `dead: []`', async ({
          assert,
        }) => {
          const outbox = state.outbox
          assert.isUndefined(outbox.dead)
          await outbox.enqueue({ op: 'detached', child: unitScope() }, ctx())
          const [row] = await outbox.pending(10)
          for (let i = 0; i < 6; i++) await outbox.markFailed(row.id, 'irreparable')
          assert.deepEqual(ids(await outbox.pending(10)), [String(row.id)], 'sigue pendiente para siempre: es tu decisión, dila')
          const { manager } = managerOver(outbox)
          assert.deepEqual((await manager.relayScopeChanges({ dryRun: true })).dead, [])
        }),
    })

    caseFor('acquire', {
      whenTrue: () =>
        test('acquire:true · el lease es EXCLUSIVO y SOSTENIDO: un segundo `acquire()` es null mientras dura, y entra al soltarlo; dos pasadas a la vez ⇒ una `busy`', async ({
          assert,
        }) => {
          const outbox = state.outbox
          const lease = await outbox.acquire!()
          assert.isNotNull(lease, 'la primera lo toma')
          assert.isNull(await outbox.acquire!(), 'la segunda no: nada de TTL')
          await lease!.release()
          const again = await outbox.acquire!()
          assert.isNotNull(again, 'soltado, entra')
          await again!.release()
          // Y por el manager: la pasada rezagada no aplica nada y lo dice.
          const { manager, driver, calls, tree } = managerOver(outbox)
          const org = orgScope()
          await tree.attach(org, APP_SCOPE)
          await manager.scopes.attached(org, APP_SCOPE)
          driver.onScopeAttached = async (c: ScopeRef, p: ScopeRef) => {
            await new Promise((r) => setTimeout(r, 60))
            calls.push(`attached ${keyOf(c)} → ${keyOf(p)}`)
          }
          const [first, second] = await Promise.all([
            manager.relayScopeChanges(),
            new Promise((r) => setTimeout(r, 10)).then(() => manager.relayScopeChanges()),
          ])
          assert.isFalse(first.busy)
          assert.isTrue((second as any).busy)
          assert.lengthOf(calls, 1, 'el cambio se aplicó UNA vez')
        }),
      whenFalse: () =>
        test('acquire:false · sin lease el relay corre igual y NUNCA dice `busy` (y el README te obliga a correrlo de uno en uno)', async ({
          assert,
        }) => {
          const outbox = state.outbox
          assert.isUndefined(outbox.acquire)
          const { manager, tree } = managerOver(outbox)
          const org = orgScope()
          await tree.attach(org, APP_SCOPE)
          await manager.scopes.attached(org, APP_SCOPE)
          const report = await manager.relayScopeChanges()
          assert.isFalse(report.busy)
          assert.lengthOf(report.applied, 1)
        }),
    })

    caseFor('earlierPending', {
      whenTrue: () =>
        test('earlierPending:true · la pendiente más antigua ANTERIOR que nombra alguno de los scopes (hijo, padre o la raíz); ignora aplicadas y posteriores', async ({
          assert,
        }) => {
          const outbox = state.outbox
          const org = orgScope()
          const unit = unitScope()
          const child = unitScope()
          const other = unitScope()
          const a = (await outbox.enqueue({ op: 'attached', child: org, parent: APP_SCOPE }, ctx()))!.id
          const b = (await outbox.enqueue({ op: 'attached', child: unit, parent: org }, ctx()))!.id
          const c = (await outbox.enqueue({ op: 'attached', child, parent: unit }, ctx()))!.id
          const d = (await outbox.enqueue({ op: 'detached', child: other }, ctx()))!.id
          assert.equal(String((await outbox.earlierPending!(c, [child, unit]))!.id), String(b), 'por hijo')
          assert.equal(String((await outbox.earlierPending!(b, [unit, org]))!.id), String(a), 'por padre')
          assert.equal(String((await outbox.earlierPending!(d, [APP_SCOPE]))!.id), String(a), 'la raíz')
          assert.isNull(await outbox.earlierPending!(d, [other]), 'nada anterior nombra `other`')
          assert.isNull(await outbox.earlierPending!(a, [org, APP_SCOPE]), 'la primera no tiene anterior')
          await outbox.markApplied(a)
          assert.isNull(await outbox.earlierPending!(b, [unit, org]), 'una APLICADA ya no bloquea')
        }),
      whenFalse: () =>
        test('earlierPending:false · sin sonda el manager pagina `pending()` y el veredicto de `only` es el MISMO: la dependiente se aplaza (`depends-on:<id>`), cero llamadas', async ({
          assert,
        }) => {
          const outbox = state.outbox
          assert.isUndefined(outbox.earlierPending)
          const { manager, calls, tree } = managerOver(outbox)
          const org = orgScope()
          const unit = unitScope()
          await tree.attach(org, APP_SCOPE)
          await tree.attach(unit, org)
          const { queued: [movedId] } = await manager.scopes.moved(unit, org)
          const child = unitScope()
          await tree.attach(child, unit)
          const { queued: [attachedId] } = await manager.scopes.attached(child, unit)
          if (caps.filter) {
            const report = await manager.relayScopeChanges({ only: [attachedId] })
            assert.deepEqual(report.applied, [])
            assert.deepEqual(report.entries.map((e) => [String(e.id), e.status, e.reason]), [[String(attachedId), 'deferred', `depends-on:${movedId}`]])
          } else {
            // Sin filtro en el puerto tampoco hay `only`: el manager corta ANTES de sondear nada (par `filter`).
            await rejects(assert, () => manager.relayScopeChanges({ only: [attachedId] }), { status: 500, code: 'E_AUTHZ_CONFIG' })
          }
          assert.deepEqual(calls, [], 'jamás fuera de orden')
        }),
    })

    caseFor('requeue', {
      whenTrue: () =>
        test('requeue:true · `requeue` devuelve una aparcada a `pending()` con `attempts = maxAttempts − 1` (todo o nada: un id no aparcado lanza sin tocar nada); `laterApplied` da las aplicadas posteriores que comparten clave; el manager se niega si las hay (E_AUTHZ_REQUEUE_REFUSED)', async ({
          assert,
        }) => {
          const outbox = state.outbox
          const orgB = orgScope()
          const orgC = orgScope()
          const unit = unitScope()
          const old = (await outbox.enqueue({ op: 'moved', child: unit, parent: orgB }, ctx()))!.id
          for (let i = 0; i < maxAttempts!; i++) await outbox.markFailed(old, 'el store no respondía')
          const current = (await outbox.enqueue({ op: 'moved', child: unit, parent: orgC }, ctx()))!.id
          await outbox.markApplied(current)
          // Una posterior PENDIENTE que comparte `unit`: no es «aplicada», no cuenta en la sonda.
          const live = (await outbox.enqueue({ op: 'moved', child: unit, parent: orgScope() }, ctx()))!.id
          assert.deepEqual(ids(await outbox.dead!(10)), [String(old)])
          // laterApplied: SOLO la posterior APLICADA que comparte `unit`; la pendiente no; nada posterior a `current`.
          assert.deepEqual(ids(await outbox.laterApplied!(old, [unit, orgB], 10)), [String(current)])
          assert.deepEqual(await outbox.laterApplied!(old, [orgScope()], 10), [])
          assert.deepEqual(await outbox.laterApplied!(current, [unit], 10), [], 'la pendiente posterior no es una aplicada')
          // Todo o nada: un id vivo o aplicado lanza y la aparcada sigue aparcada.
          await rejects(assert, () => outbox.requeue!([old, live]), {}, 'lote mixto')
          await rejects(assert, () => outbox.requeue!([current]), {}, 'ya aplicada')
          assert.deepEqual(ids(await outbox.dead!(10)), [String(old)], 'nada tocado')
          // El manager: con una aplicada posterior que comparte clave, se NIEGA; nada cambia.
          const { manager, calls } = managerOver(outbox)
          const refused = await rejects(assert, () => manager.requeueScopeChanges([old]), { status: 500, code: 'E_AUTHZ_REQUEUE_REFUSED' })
          assert.equal(String(refused.conflicts[0].applied[0].id), String(current))
          assert.deepEqual(ids(await outbox.dead!(10)), [String(old)])
          // Y el puerto solo: vuelve con attempts = max − 1; un fallo más y vuelve a aparcarse.
          await outbox.requeue!([old])
          const [back] = await outbox.pending(10)
          assert.equal(String(back.id), String(old))
          assert.equal(back.attempts, maxAttempts! - 1)
          assert.deepEqual(await outbox.dead!(10), [])
          await outbox.markFailed(old, 'sigue rota')
          assert.deepEqual(ids(await outbox.dead!(10)), [String(old)], 'UNA pasada y vuelve a dead()')
          assert.deepEqual(calls, [])
        }),
      whenFalse: () =>
        test('requeue:false · sin `requeue`/`laterApplied` el manager lo DICE: `requeueScopeChanges` es 500 E_AUTHZ_UNSUPPORTED nombrando el método', async ({
          assert,
        }) => {
          const outbox = state.outbox
          assert.isUndefined(outbox.requeue)
          assert.isUndefined(outbox.laterApplied)
          const { manager } = managerOver(outbox)
          const error = await rejects(assert, () => manager.requeueScopeChanges([1]), { status: 500, code: 'E_AUTHZ_UNSUPPORTED' })
          assert.match(error.message, /dead|requeue|laterApplied/)
        }),
    })
  })

  return { registered, covered }
}
