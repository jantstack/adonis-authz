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
import { AuthorizationManager, DEFAULT_MAX_DESCENDANTS, DEFAULT_MAX_SCOPES, DEFAULT_RELAY_BATCH, DEFAULT_RELAY_LIMIT } from '../src/manager.js'
import { DEFAULT_MAX_LOCAL_ROLES } from '../src/catalog/catalog_cache.js'
import { FACTS_MAX_RESOLVE_DEPTH, FACTS_MODEL_MAX_BYTES, FGA_MAX_BATCH_CHECK } from '../src/openfga.js'
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
    assert.include(readme, `| \`DEFAULT_RELAY_LIMIT\` | ${DEFAULT_RELAY_LIMIT.toLocaleString('en-US')} |`)
    assert.include(readme, `| \`DEFAULT_RELAY_BATCH\` | ${DEFAULT_RELAY_BATCH} |`)
    assert.include(readme, `| \`maxScopes\` | ${DEFAULT_MAX_SCOPES.toLocaleString('en-US')} |`)
    assert.include(readme, `| \`maxDescendants\` | ${DEFAULT_MAX_DESCENDANTS.toLocaleString('en-US')} |`)
    assert.include(readme, `| \`maxLocalRoles\` | ${DEFAULT_MAX_LOCAL_ROLES.toLocaleString('en-US')} |`)
    assert.include(readme, '| `maxAttempts` | 5 |')
    // Alcance y síntoma de la profundidad (tester 4-1), y el O(store) de enumerateRelations (juez, cuestión 4).
    assert.include(readme, '`openfga` only, `database` has no ceiling')
    assert.include(readme, '503, never `false`')
    assert.include(readme, 'O(tuples in the store)')
    assert.include(readme, 'never from a tenant request')
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
    const outbox = sqlScopeOutbox()
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
