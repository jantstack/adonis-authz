/**
 * **2.4.0-alpha.5 · R0 — la profundidad del árbol, declarada y acotada**
 * (panel relay, cuestión 5; decisiones del dueño del 2026-09-09 (2)).
 *
 * COGNITIV pidió que el 22 (`FACTS_MAX_RESOLVE_DEPTH`) estuviera «en el
 * README»: lo estaba, en prosa y bajo las notas de OpenFGA, no donde lee
 * quien DISEÑA su árbol. Dos piezas:
 *
 *  1. **Tabla «Limits» atada a las constantes** (tester 4-2): el caso importa
 *     `FACTS_MAX_RESOLVE_DEPTH` (y las demás cotas) y afirma que ESE número
 *     está en la tabla. Cambiar la constante sin tocar el README ⇒ rojo. Sin
 *     esto la tabla envejece a la primera medición nueva.
 *  2. **Gate opt-in por CONFIG** (`scopes.maxDepth`; no `capabilities`, que
 *     es booleana por doctrina): el manager rechaza `attached`/`moved` con
 *     422 `E_AUTHZ_SCOPE_DEPTH_LIMIT` cuando la cadena del PADRE + 1 supera
 *     el techo, ANTES de escribir o encolar (cero llamadas al driver, cero
 *     filas en la outbox) y con cero I/O extra (`#assertEdge` ya tiene la
 *     cadena del padre). Declarado PARCIAL: no ve la altura del subárbol que
 *     se mueve. Sin la opción, nada cambia (4-5: `database` no paga nada).
 *
 * Profundidad = saltos `parent` hasta `app`. La cadena del padre incluye a
 * `app`, así que la profundidad del hijo es `chain.length` del padre.
 */
import { test } from '@japa/runner'
import { readFile } from 'node:fs/promises'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { AuthorizationManager, DEFAULT_MAX_DESCENDANTS, DEFAULT_MAX_SCOPES, DEFAULT_RELAY_BATCH, DEFAULT_RELAY_LIMIT, RELAY_ORIGIN_MAX_HOPS } from '../src/manager.js'
import { DEFAULT_MAX_LOCAL_ROLES } from '../src/catalog/catalog_cache.js'
import { FACTS_MAX_RESOLVE_DEPTH, FACTS_MODEL_MAX_BYTES, FGA_MAX_BATCH_CHECK, DEFAULT_LIST_OBJECTS_DEADLINE_MS, LIST_OBJECTS_DEADLINE_RATIO, RELATIONS_PURGE_WRITE_MAX } from '../src/openfga.js'
import { RELATIONS_CHECK_MANY_MAX } from '../src/relations/check_many.js'
import { DENIABLE_RELATION_NAME_MAX } from '../src/relations/define_relations_config.js'
import { PROVISION_MODEL_HISTORY_MAX } from '../commands/openfga_provision.js'
import { RELATIONS_MEMBERS_DENY_CHECK_MAX } from '../src/drivers/database_relations_driver.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import { sqlScopeOutbox } from '../src/scope_outbox.js'
import { cleanScopeOutbox } from './helpers/schema.js'
import { reconcileLines } from '../commands/authz_reconcile.js'
import type { ReconcileReport } from '../src/types.js'

const orgScope = () => ({ type: 'organization', uuid: uuidv7() })
const unitScope = () => ({ type: 'unit', uuid: uuidv7() })
const keyOf = (s: any) => `${s.type}:${s.uuid ?? ''}`

async function rejects(assert: any, run: () => unknown, expected: { status: number; code: string }, message?: string): Promise<any> {
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

function spyDriver() {
  const calls: string[] = []
  const driver: any = {
    authorize: async () => false,
    onScopeAttached: async (c: any, p: any) => void calls.push(`attached ${keyOf(c)} → ${keyOf(p)}`),
    onScopeMoved: async (c: any, p: any) => void calls.push(`moved ${keyOf(c)} → ${keyOf(p)}`),
    onScopeDetached: async (c: any) => void calls.push(`detached ${keyOf(c)}`),
    purgeScope: async () => {},
  }
  return { driver, calls }
}

function managerWith(options: { tree: any; driver: any; outbox?: any; maxDepth?: unknown }) {
  return new AuthorizationManager({
    default: 'spy',
    drivers: { spy: () => options.driver },
    scopes: { resolveChain: resolveChainFrom(options.tree), outbox: options.outbox, maxDepth: options.maxDepth },
    warnOnOptInSecurity: false,
  } as any)
}

/** Una cadena de `depth` saltos hasta `app`: devuelve el nodo más profundo. */
async function chainOf(tree: any, depth: number) {
  let parent: any = APP_SCOPE
  let node: any = APP_SCOPE
  for (let i = 0; i < depth; i++) {
    node = i === 0 ? orgScope() : unitScope()
    await tree.attach(node, parent)
    parent = node
  }
  return node
}

test.group('alpha.5 · R0 — el README declara sus límites en una tabla atada a las constantes', () => {
  test('4-1/4-2 · la tabla «Limits» trae la profundidad 22 con su nombre, su alcance y su síntoma, y el resto de cotas, con los números del CÓDIGO', async ({
    assert,
  }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, '### Limits')
    assert.include(readme, `| \`FACTS_MAX_RESOLVE_DEPTH\` | ${FACTS_MAX_RESOLVE_DEPTH} |`, 'la constante y su número, en la misma fila')
    assert.include(readme, `| \`FACTS_MODEL_MAX_BYTES\` | ${FACTS_MODEL_MAX_BYTES.toLocaleString('en-US')} |`)
    assert.include(readme, `| \`FGA_MAX_BATCH_CHECK\` | ${FGA_MAX_BATCH_CHECK} |`)
    // Plan 2.5 · lote A (A-20): el tope de `checkMany`, atado a su constante (= el tope de batchCheck).
    assert.include(readme, `| \`RELATIONS_CHECK_MANY_MAX\` | ${RELATIONS_CHECK_MANY_MAX} |`)
    // Lote D · D-18: la cota de una relación denegable, atada a su constante DERIVADA (50 − 'denied_'.length).
    assert.include(readme, `| \`DENIABLE_RELATION_NAME_MAX\` | ${DENIABLE_RELATION_NAME_MAX} |`)
    // Lote D · D2 → cierre 2 de D2 · 🟡 N4: el barrido de `openfga:provision --allow-drop-deny` ya NO tiene cota (en
    // STREAMING: con 1 M era un exit 1 para siempre tras retirar un opt-in); la fila de la cota desaparece y la tabla dice
    // que no la hay.
    assert.notInclude(readme, 'PROVISION_DROP_DENY_SWEEP_MAX')
    assert.include(readme, '`openfga:provision --store-id` sweep for live denies of a dropped relation | — (no cap: streamed page by page)')
    // Cierre 1 de D2 · 🟡 3: la historia de modelos que la guarda lee (el ESTADO del store, no el último modelo).
    assert.include(readme, `| \`PROVISION_MODEL_HISTORY_MAX\` | ${PROVISION_MODEL_HISTORY_MAX.toLocaleString('en-US')} |`)
    assert.equal(DENIABLE_RELATION_NAME_MAX, 43)
    // Cierre 1 de D1: la cota de membersOf con deny (🟡 4) y el tope de la purga atómica de openfga (🟠 1, medido).
    assert.include(readme, `| \`RELATIONS_MEMBERS_DENY_CHECK_MAX\` | ${RELATIONS_MEMBERS_DENY_CHECK_MAX.toLocaleString('en-US')} |`)
    assert.include(readme, `| \`RELATIONS_PURGE_WRITE_MAX\` | ${RELATIONS_PURGE_WRITE_MAX} |`)
    // Cierre 2 de D1 · ⚪ N3: el REQUISITO del servidor, atado a la misma constante (subirla sin tocar la fila es rojo).
    assert.include(readme, `**Requires \`--max-tuples-per-write\` ≥ ${RELATIONS_PURGE_WRITE_MAX} on the server**`)
    // Lote B · B4: el deadline de ListObjects y su umbral, atados a las constantes del driver.
    assert.include(readme, `| \`listObjectsDeadlineMs\` (\`DEFAULT_LIST_OBJECTS_DEADLINE_MS\`) | ${DEFAULT_LIST_OBJECTS_DEADLINE_MS.toLocaleString('en-US')} ms |`)
    assert.include(readme, `\`LIST_OBJECTS_DEADLINE_RATIO\` (${LIST_OBJECTS_DEADLINE_RATIO})`)
    assert.notInclude(readme, 'never a mute partial list', 'B4: la frase absoluta era falsa para el deadline; la letra nueva dice las dos causas')
    // Cierre 2 del lote B · 🟠 N1 (retira el 🟡 8 del cierre 1): `--listObjects-deadline=0` NO es «sin deadline» — el
    // `--request-timeout` (default 3 s) sigue cortando con un 200 mudo (medido por el auditor en v1.19.0). La receta
    // `Infinity` desaparece del README; la letra dice el corte EFECTIVO (el menor de los dos) y que los dos a 0 no se soportan.
    assert.notInclude(readme, 'listObjectsDeadlineMs: Infinity', 'N1: la receta que produce la lista parcial muda ya no se publica')
    assert.notInclude(readme, 'has no deadline (measured', 'N1: la frase falsa del cierre 1')
    assert.notInclude(readme, '(no deadline, measured)', 'N1: la frase falsa de la fila Limits')
    assert.include(readme, '`--request-timeout`', 'N1: el corte efectivo con deadline 0')
    assert.include(readme, 'whichever is lower', 'N1: «declara el menor»')
    assert.include(readme, 'both at 0 is not supported', 'N1: el límite declarado (gateway HTTP sin medir)')
    assert.include(readme, 'measured on OpenFGA v1.19.0', 'N1: la versión medida')
    // ⚪ 14: el precio de la señal conservadora.
    assert.include(readme, `${(DEFAULT_LIST_OBJECTS_DEADLINE_MS * LIST_OBJECTS_DEADLINE_RATIO).toLocaleString('en-US')} ms`, '⚪ 14: el umbral con el default, en ms')
    assert.include(readme, 'p99', '⚪ 14: el precio para quien trata `truncated` como 503')
    assert.include(readme, 'the runner does not judge the deadline', '🟡 8: terceros')
    assert.equal(RELATIONS_CHECK_MANY_MAX, FGA_MAX_BATCH_CHECK, 'un lote de checkMany es UNA request de batchCheck')
    assert.include(readme, `| \`DEFAULT_RELAY_LIMIT\` | ${DEFAULT_RELAY_LIMIT.toLocaleString('en-US')} |`)
    assert.include(readme, `| \`DEFAULT_RELAY_BATCH\` | ${DEFAULT_RELAY_BATCH} |`)
    assert.include(readme, `| \`maxScopes\` | ${DEFAULT_MAX_SCOPES.toLocaleString('en-US')} |`)
    assert.include(readme, `| \`maxDescendants\` | ${DEFAULT_MAX_DESCENDANTS.toLocaleString('en-US')} |`)
    assert.include(readme, `| \`maxLocalRoles\` | ${DEFAULT_MAX_LOCAL_ROLES.toLocaleString('en-US')} |`)
    assert.include(readme, '| `maxAttempts` | 5 |')
    // Alcance y síntoma de la profundidad (tester 4-1), y el O(store) de enumerateRelations (juez, cuestión 4).
    assert.include(readme, '`openfga` only, `database` has no ceiling')
    // R3 (2.5.0-alpha.4): el síntoma lleva su código propio — sigue siendo 503 y jamás `false`.
    assert.include(readme, '`authorize` is 503 `E_AUTHZ_RESOLUTION_LIMIT` (2.5.0-alpha.4; until then the generic `E_AUTHZ_BACKEND_UNAVAILABLE`), never `false`')
    assert.include(readme, 'O(tuples in the store)')
    assert.include(readme, 'never from a tenant request')
    // alpha.6: el coste es por BARRIDO, no por partición; el prefijo sigue prohibido; y la cota de la sonda de `only`.
    assert.include(readme, 'one sweep for K partitions')
    assert.include(readme, 'a prefix object answers 200 with **zero** tuples')
    assert.include(readme, `| \`RELAY_ORIGIN_MAX_HOPS\` | ${RELAY_ORIGIN_MAX_HOPS} |`)
    assert.include(readme, '#### The source sweep, measured')
    // El gate, declarado PARCIAL con esas palabras.
    assert.include(readme, 'scopes.maxDepth')
    assert.include(readme, 'E_AUTHZ_SCOPE_DEPTH_LIMIT')
    assert.include(readme, 'The gate is **partial**')
    // Y la línea que faltaba donde lee quien diseña el árbol: en «The scope tree», con enlace a la tabla.
    const scopeTree = readme.slice(readme.indexOf('### The scope tree'), readme.indexOf('#### The tree outbox'))
    assert.include(scopeTree, '](#limits)')
    assert.include(scopeTree, `${FACTS_MAX_RESOLVE_DEPTH}`)
  })
})

test.group('alpha.5 · R0 — `scopes.maxDepth`: el gate opt-in de profundidad, en el manager', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
  })

  test('4-4 · borde exacto: con `maxDepth: 22` un hijo a 22 saltos ENTRA (y su cadena mide 22)', async ({ assert }) => {
    const tree = memoryScopeTree()
    const parent = await chainOf(tree, 21)
    const child = unitScope()
    const { driver, calls } = spyDriver()
    const manager = managerWith({ tree, driver, maxDepth: 22 })
    await tree.attach(child, parent)
    assert.lengthOf((await tree.chainOf(child))!, 23, '22 saltos = 23 nodos con `app`')

    const receipt = await manager.scopes.attached(child, parent)
    assert.deepEqual(receipt, { queued: [] })
    assert.deepEqual(calls, [`attached ${keyOf(child)} → ${keyOf(parent)}`])
  })

  test('4-3 · a 23 saltos ⇒ 422 E_AUTHZ_SCOPE_DEPTH_LIMIT ANTES de escribir o encolar: cero llamadas al driver y cero filas en la outbox; `moved` igual', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const parent = await chainOf(tree, 22)
    const child = unitScope()
    const { driver, calls } = spyDriver()
    // B6: harness (el caso mide la profundidad, no la unidad de trabajo): opt-out explícito.
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    const manager = managerWith({ tree, driver, outbox, maxDepth: 22 })

    const error = await rejects(assert, () => manager.scopes.attached(child, parent), { status: 422, code: 'E_AUTHZ_SCOPE_DEPTH_LIMIT' }, 'attached')
    assert.include(error.message, '23')
    assert.include(error.message, 'maxDepth=22')
    assert.deepEqual(calls, [])
    assert.deepEqual(await outbox.pending(10), [], 'cero filas encoladas')

    // `moved` hacia un padre demasiado profundo: mismo gate, misma letra.
    const shallow = orgScope()
    await tree.attach(shallow, APP_SCOPE)
    await tree.attach(child, shallow)
    await rejects(assert, () => manager.scopes.moved(child, parent), { status: 422, code: 'E_AUTHZ_SCOPE_DEPTH_LIMIT' }, 'moved')
    assert.deepEqual(calls, [])
    assert.deepEqual(await outbox.pending(10), [])
    // Y el mismo `moved` hacia un destino somero entra: el gate mira el DESTINO.
    const other = orgScope()
    await tree.attach(other, APP_SCOPE)
    const { queued } = await manager.scopes.moved(child, other)
    assert.lengthOf(queued, 1)
  })

  test('4-5 · sin la opción nada cambia: el mismo árbol de 23 (y de 40) es legal, en cualquier driver', async ({ assert }) => {
    const tree = memoryScopeTree()
    const parent = await chainOf(tree, 39)
    const child = unitScope()
    const { driver, calls } = spyDriver()
    const manager = managerWith({ tree, driver })
    await manager.scopes.attached(child, parent)
    assert.lengthOf(calls, 1)
  })

  test('el gate es PARCIAL a propósito: `moved` de un subárbol de altura h deja las hojas a chain + h y no lo ve (documentado, no adivinado)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const deepParent = await chainOf(tree, 20) // profundidad 20
    const top = orgScope()
    const mid = unitScope()
    const leaf = unitScope()
    await tree.attach(top, APP_SCOPE)
    await tree.attach(mid, top)
    await tree.attach(leaf, mid)
    const { driver, calls } = spyDriver()
    const manager = managerWith({ tree, driver, maxDepth: 22 })
    // `top` pasa a profundidad 21 (entra); `leaf` queda a 23, y el gate no lo sabe.
    await manager.scopes.moved(top, deepParent)
    assert.lengthOf(calls, 1)
    await tree.move(top, deepParent)
    assert.lengthOf((await tree.chainOf(leaf))!, 24, 'la hoja quedó a 23 saltos: la altura del subárbol no se mide')
  })

  test('alpha.8 · L-1/L-2 · el `message` del 422 es para el TENANT: dice la profundidad, `scopes.maxDepth` y «no se ha escrito ni encolado nada», y NO nombra `openfga`, `FACTS_MAX_RESOLVE_DEPTH` ni `OPENFGA_RESOLVE_NODE_LIMIT` (eso va en `details`, para el operador)', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const parent = await chainOf(tree, 22)
    const { driver } = spyDriver()
    const manager = managerWith({ tree, driver, maxDepth: 22 })
    const error = await rejects(assert, () => manager.scopes.attached(unitScope(), parent), { status: 422, code: 'E_AUTHZ_SCOPE_DEPTH_LIMIT' })
    assert.include(error.message, '23')
    assert.include(error.message, 'scopes.maxDepth=22')
    assert.include(error.message, 'No se ha escrito ni encolado nada')
    for (const leak of ['openfga', 'FACTS_MAX_RESOLVE_DEPTH', 'OPENFGA_RESOLVE_NODE_LIMIT', 'facts']) {
      assert.notInclude(error.message.toLowerCase(), leak.toLowerCase(), `el mensaje público no nombra ${leak}`)
    }
    assert.deepEqual(error.details.depth, 23)
    // cierre alpha.8 (🟡 3 del auditor): lo que un handler genérico serializa no enseña el backend.
    const serialized = JSON.stringify(error)
    assert.notMatch(serialized, /openfga|OPENFGA_RESOLVE_NODE_LIMIT|FACTS_MAX_RESOLVE_DEPTH/, 'details NO es enumerable')
    assert.isString(error.details.server, 'pero sigue legible para el log')
    assert.deepEqual(error.details.maxDepth, 22)
    assert.include(JSON.stringify(error.details), 'FACTS_MAX_RESOLVE_DEPTH')
    assert.include(JSON.stringify(error.details), 'OPENFGA_RESOLVE_NODE_LIMIT')
  })

  test('alpha.8 · N-2 (letra EJECUTABLE) · `maxDepth` cuenta SALTOS hasta `app`: un árbol de exactamente 3 niveles entra con `maxDepth: 3` y el tercero es 422 con `maxDepth: 2` — N niveles ⇒ `maxDepth = N`, y el README lo dice con este ejemplo', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const org = orgScope() // nivel 1 (1 salto)
    const unit = unitScope() // nivel 2 (2 saltos)
    const sub = unitScope() // nivel 3 (3 saltos)
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { driver, calls } = spyDriver()
    await rejects(assert, () => managerWith({ tree, driver, maxDepth: 2 }).scopes.attached(sub, unit), { status: 422, code: 'E_AUTHZ_SCOPE_DEPTH_LIMIT' }, 'maxDepth 2: el tercer nivel no entra')
    assert.deepEqual(calls, [])
    await managerWith({ tree, driver, maxDepth: 3 }).scopes.attached(sub, unit)
    assert.lengthOf(calls, 1, 'maxDepth 3: el tercer nivel entra')
    await tree.attach(sub, unit)
    assert.lengthOf((await tree.chainOf(sub))!, 4, '3 saltos = 4 nodos con `app`: la cadena del PADRE mide 3, y 3 > 3 es falso')
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, 'a tree of N levels below `app` needs `scopes.maxDepth = N`')
    assert.include(readme, '`maxDepth: 2` refuses the third')
    assert.include(readme, '`maxDepth: 3` lets it in')
  })

  test('`maxDepth` tiene que ser un entero >= 1: otra cosa es 500 E_AUTHZ_CONFIG al usar `scopes.*`, sin tocar nada', async ({ assert }) => {
    const tree = memoryScopeTree()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const { driver, calls } = spyDriver()
    for (const bad of [0, -1, 2.5, '22', NaN]) {
      const manager = managerWith({ tree, driver, maxDepth: bad })
      const error = await rejects(assert, () => manager.scopes.attached(unitScope(), org), { status: 500, code: 'E_AUTHZ_CONFIG' }, String(bad))
      assert.include(error.message, 'scopes.maxDepth')
    }
    assert.deepEqual(calls, [])
  })
})

test.group('alpha.5 · R0 — `authz:reconcile` avisa de las cadenas que superan el techo (deriva)', () => {
  const base = (over: Partial<ReconcileReport> = {}): ReconcileReport => ({
    to: 'openfga',
    dryRun: false,
    prune: false,
    written: 0,
    updated: 0,
    unchanged: 0,
    extra: 0,
    deleted: 0,
    phases: {
      root: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
      catalog: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
      tree: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
      facts: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
    },
    skipped: {},
    details: [],
    cycles: [],
    drift: { rootMarker: false, multiParent: [], roleVisibility: 0, pendingRelay: 0, deadRelay: 0 },
    massDelete: false,
    ...over,
  })

  test('4-6 · `drift.tooDeep` con scopes ⇒ una línea de error por scope nombrando el techo, y la pasada NO es limpia (exit 1); vacío o ausente ⇒ limpia', ({
    assert,
  }) => {
    const deep = reconcileLines(base({ drift: { ...base().drift, tooDeep: ['unit|abc', 'unit|def'], tooDeepLimit: 22 } }))
    assert.isFalse(deep.clean)
    const errores = deep.lines.filter((l) => l.level === 'error').map((l) => l.message)
    assert.lengthOf(errores.filter((m) => m.includes('unit|abc') || m.includes('unit|def')), 2)
    assert.isTrue(errores.some((m) => m.includes('22') && m.includes('503')), 'dice el techo y el síntoma')
    assert.isTrue(reconcileLines(base({ drift: { ...base().drift, tooDeep: [] } })).clean)
    assert.isTrue(reconcileLines(base()).clean, 'un driver de terceros que no lo reporta sigue siendo limpio')
  })
})
