/**
 * **Propiedad `openfga.roles.visibility.settle`** (lote C · sublote «asentar», paso 3 del plan del juez,
 * `loteC-carreras-juez.md`; linaje L13 «visibilidad materializada con escritores concurrentes»).
 *
 * Enunciado (analista §3 con la enmienda del tester): para TODO entrelazado de escritores del driver `openfga` de roles
 * —`grant`/`revoke` de roles locales, `projectCatalogRole`, `moved`/`attached`/`detached` en línea, `purgeRole`—, en
 * QUIETUD (y tras drenar con la semántica del relay los cambios de árbol que fallaron), cada `scope#binding` de un rol
 * con asignación coincide con la regla del invariante 18 evaluada con la cadena DEL STORE, y el `Check` del intérprete
 * coincide con la referencia en la rejilla usuario × scope. **Ningún OPEN se admite nunca**; un CLOSED solo si un actor
 * recibió el 409 de la cota o un fallo inyectado (en esta fase no hay ni cota ni inyección: todo CLOSED cuenta).
 *
 * Piezas (todas sin servidor):
 * - el doble FIEL `fga_memory_client.ts` (un store, N instancias del driver REAL, una por «proceso», cada una con su
 *   memo de catálogo) y su planificador cooperativo sembrado;
 * - **dominio ampliado** (juez, paso 3): árboles T1 (C⊂A), T2 (C⊂B) y T3 = K2 (P⊂X no owner, C⊂P); roles R (local de
 *   A), R2 (local de A recién definido: K4, invisible en el memo RANCIO de un actor), RP (local de P: K6, owner == scope
 *   en P) y G (global, control); operaciones `grant`/`revoke`/`project`/`moved` (C↔A|B, C→P, C→Q, P↔A|B|X),
 *   `attached` nuevo y de un hijo existente, `detached` (purga + arista), `purgeRole` y `churn` (C de un lado a otro tres
 *   veces);
 * - **oráculo INDEPENDIENTE**: no importa nada de `src/drivers` (la regla y la cadena se reescriben aquí, sobre el TEXTO
 *   de las tuplas); (a) arista presente ⇔ la regla la exige, para todo binding con `assignee`; (b) el intérprete del
 *   modelo = la referencia en la rejilla (ve un fallo de una regla COMPARTIDA, que (a) no vería);
 * - **enumeración acotada** (una preempción: el actor 2 entero en cada I/O k del actor 1) y **PCT** con semillas fijas,
 *   3 actores, catálogo rancio por actor, en las DOS configuraciones de consistencia (`higher` = la del driver por
 *   defecto; `minimize` = driver con `minimize_latency` y doble con caché);
 * - **aserciones de progreso** (no vacuidad): cuántas corridas entrelazaron de verdad, cuántas veces terminó bien cada
 *   operación y el histograma de errores; y un control del oráculo (una arista plantada es OPEN; una quitada, CLOSED).
 *
 * El montaje del store inicial usa los constructores de tuplas del paquete (`openfga_facts.ts`: son el FORMATO del
 * store, no la regla); el oráculo no los usa.
 */
import db from '@adonisjs/lucid/services/db'
import { OpenFgaAuthorizationDriver } from '../../src/drivers/openfga_driver.js'
import { AuthorizationManager } from '../../src/manager.js'
import { makeScopeOutbox } from '../../src/testing/scope_outbox_contract.js'
import type { ScopeTreeChange } from '../../src/types.js'
import {
  factsBindingObject,
  factsBindingTuples,
  factsCatalogTuples,
  factsDenyTuple,
  factsParentTuple,
  factsRootTuples,
} from '../../src/drivers/openfga_facts.js'
import { memoryScopeTree, resolveChainFrom } from '../../src/testing/scope_tree.js'
import type { ContractScopeTree } from '../../src/testing/scope_tree.js'
import { APP_SCOPE } from '../../src/types.js'
import type { ScopeRef } from '../../src/types.js'
import { checkTuples, TupleStore, type FgaTuple } from './fga_interpreter.js'
import {
  FgaMemoryStore,
  fixedUuid,
  installMemoryClient,
  pctPolicy,
  preemptPolicy,
  runScheduled,
  sdkError,
  seededRandom,
  type ClientHooks,
  type IoEvent,
  type SchedulerPolicy,
} from './fga_memory_client.js'
import { generatedModel, TEST_MODEL_ID } from './fga_model.js'

/* ── El universo (uuids FIJOS: reproducible sin sembrar uuids) ─────────── */

const HOLDERS = { users: 'user' }
const PERMISSION = 'docs:read'
const org = (n: number): ScopeRef => ({ type: 'organization', uuid: fixedUuid(0xa00 + n) })
const unit = (n: number): ScopeRef => ({ type: 'unit', uuid: fixedUuid(0xb00 + n) })
export const U = {
  A: org(1),
  B: org(2),
  X: org(3),
  P: unit(1),
  C: unit(2),
  D: unit(3),
  Q: unit(4),
  E: unit(5),
} as const
type Node = keyof typeof U
const key = (s: ScopeRef) => (s.type === 'app' ? 'app' : `${s.type}|${s.uuid}`)
const nameOf = new Map(Object.entries(U).map(([n, s]) => [key(s), n]))

export interface Role {
  uuid: string
  slug: string
  scopeType: string
  owner: string
  rank: number
}
export const ROLES = {
  R: { uuid: fixedUuid(0xc01), slug: 'vs-lead', scopeType: 'unit', owner: key(U.A), rank: 10 },
  R2: { uuid: fixedUuid(0xc02), slug: 'vs-lead2', scopeType: 'unit', owner: key(U.A), rank: 10 },
  RP: { uuid: fixedUuid(0xc03), slug: 'vs-plead', scopeType: 'unit', owner: key(U.P), rank: 10 },
  G: { uuid: fixedUuid(0xc04), slug: 'vs-reader', scopeType: 'unit', owner: 'global', rank: 10 },
  // Panel TREE (tester, §5 regla 5): un rol GLOBAL de nivel `organization`, para ver la herencia ENTRE TENANTS (`gina`).
  GO: { uuid: fixedUuid(0xc05), slug: 'vs-orgreader', scopeType: 'organization', owner: 'global', rank: 10 },
} satisfies Record<string, Role>
type RoleName = keyof typeof ROLES
const roleName = new Map(Object.entries(ROLES).map(([n, r]) => [r.uuid, n as RoleName]))
const PERMISSION_UUID = fixedUuid(0xd01)

/**
 * Panel TREE (juez §5, regla 5): `frank` = rol GLOBAL `G@C` con deny en A (la evasión del deny por un rol global cuando el
 * árbol del store diverge del consumidor) y `gina` = rol global de organización `GO@A` (la herencia entre tenants).
 */
export const USERS = ['alice', 'victim', 'bob', 'carol', 'dave', 'erin', 'frank', 'gina'] as const

export type TreeName = 'T1' | 'T2' | 'T3'
/** Padre de cada nodo en cada árbol inicial (E no existe al empezar). */
const TREES: Record<TreeName, Partial<Record<Node, Node | 'app'>>> = {
  T1: { A: 'app', B: 'app', X: 'app', P: 'A', C: 'A', D: 'C', Q: 'B' },
  T2: { A: 'app', B: 'app', X: 'app', P: 'A', C: 'B', D: 'C', Q: 'B' },
  // K2 del auditor: P bajo X (no owner), C bajo P.
  T3: { A: 'app', B: 'app', X: 'app', P: 'X', C: 'P', D: 'C', Q: 'B' },
}

/** Asignaciones iniciales `[usuario, rol, nodo]`. Las aristas `scope#binding` las decide la REFERENCIA. */
const INITIAL_ASSIGNMENTS: Array<[string, RoleName, Node]> = [
  ['alice', 'R', 'C'],
  ['victim', 'R', 'C'],
  ['alice', 'R', 'D'],
  ['bob', 'RP', 'P'], // K6: owner == scope
  ['bob', 'RP', 'C'],
  ['carol', 'G', 'Q'],
  ['carol', 'G', 'C'],
  ['frank', 'G', 'C'],
  ['gina', 'GO', 'A'],
]

/* ── Catálogo en memoria (vista completa del puerto) ───────────────────── */

function catalogView(roles: readonly Role[], version: number) {
  const byUuid = new Map(roles.map((r) => [r.uuid, r]))
  const visible = (r: Role, chainKeys: Iterable<string>) => r.owner === 'global' || [...chainKeys].includes(r.owner)
  return {
    permission: (slug: string) => (slug === PERMISSION ? { uuid: PERMISSION_UUID, assignableAt: null } : null),
    role: (slug: string, scopeType: string) => roles.find((r) => r.slug === slug && r.scopeType === scopeType && r.owner === 'global') ?? null,
    roleVisible: (slug: string, scopeType: string, chainKeys: readonly string[]) => {
      const found = roles.filter((r) => r.slug === slug && r.scopeType === scopeType && visible(r, chainKeys))
      return found[0] ?? null
    },
    rolesNamed: (slug: string, scopeType: string) => roles.filter((r) => r.slug === slug && r.scopeType === scopeType).map((r) => ({ ...r })),
    roleByUuid: (uuid: string) => byUuid.get(uuid) ?? null,
    rolesFor: (scopeType: string, ownerKeys: Iterable<string>) => roles.filter((r) => r.scopeType === scopeType && visible(r, ownerKeys)).map((r) => ({ ...r })),
    localRoles: () => roles.filter((r) => r.owner !== 'global').map((r) => ({ ...r })),
    rolesOwnedBy: (ownerKey: string) => roles.filter((r) => r.owner === ownerKey).map((r) => ({ ...r })),
    rolesGranting: (permissionUuid: string) => {
      const out = new Map<string, any[]>()
      if (permissionUuid !== PERMISSION_UUID) return out
      for (const r of roles) out.set(r.scopeType, [...(out.get(r.scopeType) ?? []), { slug: r.slug, uuid: r.uuid, scopeType: r.scopeType, owner: r.owner }])
      return out
    },
    rolePermissionsOf: (uuid: string) => new Set(byUuid.has(uuid) ? [PERMISSION] : []),
    permissionSlug: (uuid: string) => (uuid === PERMISSION_UUID ? PERMISSION : null),
    permissionSlugs: [PERMISSION],
    topGlobalRank: Math.max(0, ...roles.filter((r) => r.owner === 'global').map((r) => r.rank)),
    loadedAt: 0,
    version,
  }
}

/* ── Operaciones ───────────────────────────────────────────────────────── */

export const OPS = [
  'grantR@C',
  'grantR2@C',
  'grantRP@P',
  'grantRP@C',
  'regrantRP@P',
  'revokeR@C',
  'projectR',
  'projectR2',
  'moveC',
  'moveCtoP',
  'moveCtoQ',
  'moveP',
  'attachE',
  'attachDtoQ',
  'detachD',
  'purgeRP',
  'churnC',
] as const
export type Op = (typeof OPS)[number]
const TREE_OPS: ReadonlySet<Op> = new Set(['moveC', 'moveCtoP', 'moveCtoQ', 'moveP', 'attachE', 'attachDtoQ', 'detachD', 'churnC'])

interface World {
  /** Punto de planificación del arnés (cede al planificador). */
  y: (kind: 'start' | 'tree') => Promise<void>
  tree: ContractScopeTree
  fga: FgaMemoryStore
  /** El catálogo VERDADERO (lo que dice la base): sin RP tras un `purgeRole` que terminó. */
  trueRoles: Set<RoleName>
  /**
   * Las notificaciones de árbol que FALLARON, con el padre que llevaban (el padre ENCOLADO): las drena el relay REAL al
   * final de la corrida (juez TREE §5, regla 7).
   */
  failed: ScopeTreeChange[]
}

const sub = (uuid: string) => ({ type: 'users', uuid })

async function parentOf(tree: ContractScopeTree, node: ScopeRef): Promise<string | null> {
  const chain = await tree.chainOf(node)
  if (!chain) return null
  return chain.length > 1 ? key(chain[1]) : 'app'
}

/** Un cambio de árbol del consumidor + la notificación EN LÍNEA (sin outbox: `acceptScopeDriftRisk`). */
async function move(w: World, d: any, node: ScopeRef, to: ScopeRef, op: 'onScopeMoved' | 'onScopeAttached' = 'onScopeMoved'): Promise<'skip' | void> {
  const chainTo = await w.tree.chainOf(to)
  if (!chainTo || chainTo.some((s) => key(s) === key(node))) return 'skip' // destino ausente o ciclo: el consumidor no lo deja
  if (!(await w.tree.chainOf(node))) return 'skip'
  if ((await parentOf(w.tree, node)) === key(to)) return 'skip'
  await w.tree.move(node, to)
  await w.y('tree')
  try {
    await d[op](node, to)
  } catch (error) {
    w.failed.push({ op: op === 'onScopeMoved' ? 'moved' : 'attached', child: node, parent: to })
    throw error
  }
}

async function runOp(w: World, d: any, op: Op): Promise<'skip' | void> {
  switch (op) {
    case 'grantR@C':
      await d.grant(sub('carol'), { uuid: ROLES.R.uuid }, U.C, { expiresAt: null })
      return
    case 'grantR2@C':
      await d.grant(sub('dave'), { uuid: ROLES.R2.uuid }, U.C, { expiresAt: null })
      return
    case 'grantRP@P':
      await d.grant(sub('erin'), { uuid: ROLES.RP.uuid }, U.P, { expiresAt: null })
      return
    case 'grantRP@C':
      await d.grant(sub('erin'), { uuid: ROLES.RP.uuid }, U.C, { expiresAt: null })
      return
    case 'regrantRP@P':
      // Asentar · cierre 1 (🟡 3 del auditor): un RE-grant (`existed: true`) con OTRA caducidad (delete + write) ∥ la purga
      // del rol: el `replaceAssignment` repone `assignee` y `role_binding#role` tras el repaso de la purga.
      await d.grant(sub('bob'), { uuid: ROLES.RP.uuid }, U.P, { expiresAt: new Date('2099-01-01T00:00:00.000Z') })
      return
    case 'revokeR@C':
      await d.revoke(sub('alice'), { uuid: ROLES.R.uuid }, U.C)
      return
    case 'projectR':
      await d.projectCatalogRole(ROLES.R.uuid)
      return
    case 'projectR2':
      await d.projectCatalogRole(ROLES.R2.uuid)
      return
    case 'moveC': {
      const p = await parentOf(w.tree, U.C)
      return move(w, d, U.C, p === key(U.A) ? U.B : U.A)
    }
    case 'moveCtoP':
      return move(w, d, U.C, U.P)
    case 'moveCtoQ':
      return move(w, d, U.C, U.Q)
    case 'moveP': {
      const p = await parentOf(w.tree, U.P)
      return move(w, d, U.P, p === key(U.A) ? U.B : p === key(U.B) ? U.X : U.A)
    }
    case 'attachE': {
      if (await w.tree.chainOf(U.E)) return 'skip'
      if (!(await w.tree.chainOf(U.C))) return 'skip'
      await w.tree.attach(U.E, U.C)
      await w.y('tree')
      try {
        await d.onScopeAttached(U.E, U.C)
      } catch (error) {
        w.failed.push({ op: 'attached', child: U.E, parent: U.C })
        throw error
      }
      return
    }
    case 'attachDtoQ':
      return move(w, d, U.D, U.Q, 'onScopeAttached')
    case 'detachD': {
      if (!(await w.tree.chainOf(U.D))) return 'skip'
      await w.tree.detach(U.D)
      await w.y('tree')
      // El orden del manager (invariante 11): purga demostrada y la arista al final.
      try {
        await d.purgeScope(U.D)
        await d.onScopeDetached(U.D)
      } catch (error) {
        w.failed.push({ op: 'detached', child: U.D })
        throw error
      }
      return
    }
    case 'purgeRP': {
      await d.purgeRole(ROLES.RP.uuid)
      w.trueRoles.delete('RP')
      return
    }
    case 'churnC': {
      for (let i = 0; i < 3; i++) {
        const p = await parentOf(w.tree, U.C)
        await move(w, d, U.C, p === key(U.A) ? U.B : U.A)
      }
      return
    }
  }
}

/* ── El oráculo INDEPENDIENTE (no importa nada de src/drivers) ─────────── */

const SCOPE = 'scope:'
const BINDING = 'role_binding:'
const scopeKeyOf = (object: string) => object.slice(SCOPE.length)
/** `role_binding:<scopeKey>|<roleUuid>`: el uuid del rol es lo que va tras el ÚLTIMO `|`. */
function parseBinding(object: string): { scope: string; role: string } | null {
  if (!object.startsWith(BINDING)) return null
  const id = object.slice(BINDING.length)
  const cut = id.lastIndexOf('|')
  return cut > 0 ? { scope: id.slice(0, cut), role: id.slice(cut + 1) } : null
}
const typeOf = (scopeKey: string) => (scopeKey === 'app' ? 'app' : scopeKey.slice(0, scopeKey.indexOf('|')))

/**
 * `ORPHAN-edge`: una arista `scope#binding` de un rol que la base ya no tiene, o una resucitada (sin `role_binding#role`);
 * `ORPHAN-fact` (paso 4, hallazgo 2): un `assignee` de un rol que la base ya no tiene (el `grant` que lo creó a la vez que
 * el `purgeRole` tiene que deshacerlo; la purga repasa lo reaparecido).
 */
export type ViolationKind = 'OPEN-edge' | 'CLOSED-edge' | 'ORPHAN-edge' | 'ORPHAN-fact' | 'OPEN-grant' | 'CLOSED-grant' | 'TREE'
export interface Violation {
  kind: ViolationKind
  detail: string
}

/**
 * Juzga el store en quietud contra el árbol del consumidor y el catálogo verdadero. `roles` = los roles que la base
 * declara (uuid ⇒ owner/nivel).
 */
export function judgeQuiescent(
  tuples: readonly FgaTuple[],
  consumer: ReadonlyMap<string, string>,
  roles: readonly Role[],
  model: any,
  /**
   * Panel TREE (juez §5, regla 2): `store` = la cara L13 (aristas y referencia con la cadena DEL STORE: el contrato del
   * settle); `consumer` = la misma referencia con la cadena del árbol del CONSUMIDOR (lo que `database` respondería). El
   * intérprete pregunta siempre al store.
   */
  against: 'store' | 'consumer' = 'store'
): Violation[] {
  const out: Violation[] = []
  const parents = new Map<string, string[]>()
  const assignees = new Map<string, Set<string>>()
  const edges = new Set<string>()
  /** Los `role_binding` con su arista estructural `role_binding#role` (sin ella, una `scope#binding` es una resucitada). */
  const roleEdges = new Set<string>()
  const denies = new Set<string>()
  for (const t of tuples) {
    if (t.relation === 'parent' && t.object.startsWith(SCOPE) && t.user.startsWith(SCOPE)) {
      const child = scopeKeyOf(t.object)
      parents.set(child, [...(parents.get(child) ?? []), scopeKeyOf(t.user)])
    } else if (t.relation === 'assignee' && t.object.startsWith(BINDING)) {
      assignees.set(t.object, new Set([...(assignees.get(t.object) ?? []), t.user]))
    } else if (t.relation === 'binding' && t.object.startsWith(SCOPE)) {
      edges.add(`${scopeKeyOf(t.object)}>${t.user}`)
    } else if (t.relation === 'role' && t.object.startsWith(BINDING)) {
      roleEdges.add(t.object)
    } else if (t.relation === 'denied_docs_read' && t.object.startsWith(SCOPE)) {
      denies.add(`${scopeKeyOf(t.object)}>${t.user}`)
    }
  }
  const label = (k: string) => nameOf.get(k) ?? k
  // (0) El árbol del store = el del consumidor (tras drenar).
  const nodes = new Set([...consumer.keys(), ...parents.keys()])
  for (const node of nodes) {
    const want = consumer.get(node)
    const have = parents.get(node) ?? []
    if (want === undefined ? have.length !== 0 : have.length !== 1 || have[0] !== want) {
      out.push({ kind: 'TREE', detail: `${label(node)}: store=[${have.map(label)}] consumidor=${want ? label(want) : '∅'}` })
    }
  }
  /** Cadena del CONSUMIDOR desde un scope (inclusive); `null` si un ciclo. */
  const consumerChain = (k: string): string[] | null => {
    const seen = [k]
    let current = k
    while (consumer.has(current)) {
      current = consumer.get(current)!
      if (seen.includes(current)) return null
      seen.push(current)
    }
    return seen
  }
  const chain = (k: string): string[] | null => (against === 'consumer' ? consumerChain(k) : storeChain(k))
  /** Cadena del STORE desde un scope (inclusive); `null` si dos padres o ciclo (deriva: se denuncia aparte). */
  const storeChain = (k: string): string[] | null => {
    const seen = [k]
    let current = k
    for (;;) {
      const ps = parents.get(current) ?? []
      if (ps.length === 0) return seen
      if (ps.length > 1 || seen.includes(ps[0])) return null
      seen.push(ps[0])
      current = ps[0]
    }
  }
  const byUuid = new Map(roles.map((r) => [r.uuid, r]))
  const visibleAt = (scope: string, roleUuid: string): boolean => {
    const r = byUuid.get(roleUuid)
    if (!r || r.scopeType !== typeOf(scope)) return false
    if (r.owner === 'global') return true
    const c = chain(scope)
    return c !== null && c.includes(r.owner)
  }
  // (a) La arista de cada binding con asignación.
  for (const [object, users] of assignees) {
    if (users.size === 0) continue
    const b = parseBinding(object)
    if (!b) continue
    const present = edges.has(`${b.scope}>${object}`)
    const known = byUuid.has(b.role)
    const expected = visibleAt(b.scope, b.role)
    const what = `${roleName.get(b.role) ?? b.role}@${label(b.scope)} [${[...users].map((u) => u.slice(5)).join(',')}]`
    if (!known && present) out.push({ kind: 'ORPHAN-edge', detail: what })
    else if (!known) out.push({ kind: 'ORPHAN-fact', detail: what })
    else if (present && !expected) out.push({ kind: 'OPEN-edge', detail: what })
    else if (!present && expected) out.push({ kind: 'CLOSED-edge', detail: what })
  }
  // (a') Paso 4 · «nada resucita» (auditor ⚪ 8, invariante 11): una `scope#binding` cuyo `role_binding` ya no tiene su
  // arista estructural `role_binding#role` la escribió alguien DESPUÉS de una purga (`revoke` no la toca; `purgeScope` y
  // `purgeRole` se la llevan): no concede, pero ningún barrido la ve (enumeran por `role_binding#role`).
  for (const edge of edges) {
    const binding = edge.slice(edge.indexOf('>') + 1)
    if (!roleEdges.has(binding)) {
      const b = parseBinding(binding)
      out.push({ kind: 'ORPHAN-edge', detail: `${b ? `${roleName.get(b.role) ?? b.role}@${label(b.scope)}` : binding} (resucitada: sin role_binding#role)` })
    }
  }
  // (b) El intérprete = la referencia, en la rejilla usuario × scope del consumidor.
  const state = new TupleStore(tuples)
  const compiled = model
  const at = { current_time: new Date(0).toISOString() }
  for (const scope of consumer.keys()) {
    if (scope === 'app' || typeOf(scope) !== 'unit') continue
    const c = chain(scope)
    for (const u of USERS) {
      const user = `user:${u}`
      let ref = false
      if (c && c[c.length - 1] === 'app' && !c.some((s) => denies.has(`${s}>${user}`))) {
        for (const s of c) {
          for (const r of roles) {
            const object = `${BINDING}${s}|${r.uuid}`
            if (assignees.get(object)?.has(user) && visibleAt(s, r.uuid)) ref = true
          }
        }
      }
      const got = checkTuples(compiled, state, { user, relation: 'can_docs_read', object: `${SCOPE}${scope}`, context: at }).verdict === 'T'
      if (got && !ref) out.push({ kind: 'OPEN-grant', detail: `${u}@${label(scope)}` })
      if (!got && ref) out.push({ kind: 'CLOSED-grant', detail: `${u}@${label(scope)}` })
    }
  }
  return out
}

/* ── Una corrida ───────────────────────────────────────────────────────── */

export type Consistency = 'higher' | 'minimize'
export type PolicySpec =
  | { kind: 'pct'; seed: number; changePoints: number; maxSteps: number }
  | { kind: 'preempt'; k: number }
  | { kind: 'solo' }

export interface RunSpec {
  tree: TreeName
  ops: Op[]
  /** Por actor: memo de catálogo RANCIO (sin R2, K4). */
  stale: boolean[]
  consistency: Consistency
  policy: PolicySpec
  /**
   * Fallo INYECTADO (juez TREE §5, regla 7 y regla 1): el `nth`-ésimo `Write` del actor `actor` es un 503 con la forma del
   * SDK, ANTES de aplicarse (`before`) o DESPUÉS (`after`: venció el deadline pero se confirmó, invariante 13). Una
   * notificación de árbol que falla la drena el relay REAL con el padre que llevaba.
   */
  fault?: { actor: number; nth: number; when: 'before' | 'after'; on?: 'write' | 'batchCheck' }
  /** Sin drenaje del relay (el modo en línea puro): lo que falló se queda como esté. */
  noDrain?: boolean
  /** Guardar los `Write` efectivos por actor (`RunResult.writes`): los casos que juzgan una ventana TRANSITORIA. */
  trace?: boolean
  /**
   * Tras el drenaje, la pasada de MANTENIMIENTO del store (`authz:reconcile --to=openfga`, origen = el propio store):
   * primero `--dry-run` (lo que cuenta sin `--prune`) y después con `--prune`; `RunResult.reconcile.after` es el juez
   * de nuevo sobre lo que deja (asentar · cierre 2, C1-4). `violations` sigue siendo el estado de ANTES.
   */
  reconcile?: boolean
}

export interface RunResult {
  /** El fallo inyectado llegó a dispararse. */
  faulted: boolean
  /** Con `spec.trace`: los `Write` aplicados, en orden, con su actor (`a0`, `a1`…, `relay`). */
  writes: Array<{ actor: string; writes: FgaTuple[]; deletes: FgaTuple[] }>
  /** Cara L13 (contra el STORE). */
  violations: Violation[]
  /** Cara contra el CONSUMIDOR (juez TREE §5, regla 2). */
  vConsumer: Violation[]
  /**
   * TREE eximido por un predicado CON NOMBRE (juez TREE §5, regla 3): `same-node-inline` = ≥ 2 operaciones terminadas que
   * cambian el MISMO nodo en línea (límite declarado bajo `acceptScopeDriftRisk`); `purge-incomplete` = un `detached` con
   * `E_AUTHZ_PURGE_INCOMPLETE` observado (invariante 11, fail-closed). `null` si no hay TREE o si no lo exime nada.
   */
  treeExempt: 'same-node-inline' | 'purge-incomplete' | null
  /** El relay real drenó estas entradas (con su estado y motivo). */
  relay: string[]
  /**
   * `cap`: el 409 es el de la COTA del settle o el del `grant` que deshace la asignación de un rol purgado a la vez (los
   * dos únicos 409 que la regla 1 admite como causa de un CLOSED; un 409 de árbol no lo es — asentar · cierre 1, 🟡-6).
   */
  outcomes: Array<{ op: Op; status: 'ok' | 'skip' | 'error'; code?: string; cap?: true }>
  /** El índice del actor al que se le inyectó el fallo (si `faulted`). */
  faultedActor?: number
  steps: number
  switches: number
  /** Enumeración: ¿llegó a preemptar? (si el actor 1 terminó antes del I/O k, la corrida no cuenta). */
  fired: boolean
  /** I/O por actor. */
  io: number[]
  drained: number
  /** Con `spec.reconcile`: el reporte de `--dry-run` y la cara L13 contra el store tras `--prune`. */
  reconcile?: { dryRun: any; prune: any; after: Violation[] }
}

const errCode = (e: any) => String(e?.code ?? e?.apiErrorCode ?? e?.name ?? e).slice(0, 60)

function initialTuples(tree: TreeName): FgaTuple[] {
  const parents = TREES[tree]
  const consumer = new Map<string, string>()
  for (const [n, p] of Object.entries(parents)) consumer.set(key(U[n as Node]), p === 'app' ? 'app' : key(U[p as Node]))
  const tuples: FgaTuple[] = [
    ...factsRootTuples(HOLDERS),
    ...factsCatalogTuples(Object.values(ROLES).map((r) => ({ uuid: r.uuid, permissions: [PERMISSION] })) as any, HOLDERS),
    ...[...consumer].map(([c, p]) => factsParentTuple(c, p)),
    factsDenyTuple(key(U.A), PERMISSION, 'user:victim'),
    factsDenyTuple(key(U.A), PERMISSION, 'user:frank'),
  ]
  // Las aristas de visibilidad iniciales las decide la regla (estado de partida CONSISTENTE).
  const chainOf = (k: string) => {
    const out = [k]
    while (consumer.has(out[out.length - 1])) out.push(consumer.get(out[out.length - 1])!)
    return out
  }
  const bindings = new Set<string>()
  for (const [user, rn, node] of INITIAL_ASSIGNMENTS) {
    const r = ROLES[rn]
    const s = key(U[node])
    if (!bindings.has(`${s}|${r.uuid}`)) {
      bindings.add(`${s}|${r.uuid}`)
      const visible = r.owner === 'global' || chainOf(s).includes(r.owner)
      tuples.push(...factsBindingTuples(s, r.uuid).filter((t) => visible || t.relation !== 'binding'))
    }
    tuples.push({ user: `user:${user}`, relation: 'assignee', object: factsBindingObject(s, r.uuid) })
  }
  return tuples
}

/**
 * Filas de `authz_roles`: las leen `purgeScope` (los roles del nivel EN FRESCO), `purgeRole` y —desde el paso 4— el
 * catálogo FRESCO de cada actor (`freshView`: el de las escrituras, K4), así que un `purgeRole` que borra la fila se ve en
 * la siguiente decisión de cualquier actor, como en producción.
 */
export async function seedSettleRoles(): Promise<void> {
  const now = new Date()
  for (const r of Object.values(ROLES)) {
    const exists = await db.from('authz_roles').where('uuid', r.uuid).first()
    if (!exists) {
      await db.table('authz_roles').insert({ uuid: r.uuid, slug: r.slug, name: r.slug, scope_type: r.scopeType, rank: r.rank, owner_scope_key: r.owner, created_at: now, updated_at: now })
    }
  }
}

export async function dropSettleRoles(): Promise<void> {
  await db.from('authz_roles').whereIn('uuid', Object.values(ROLES).map((r) => r.uuid)).delete()
}

const ALL_ROLE_UUIDS = Object.values(ROLES).map((r) => r.uuid)

export async function runSettleCase(spec: RunSpec): Promise<RunResult> {
  const tree = memoryScopeTree()
  for (const [n, p] of Object.entries(TREES[spec.tree])) await tree.attach(U[n as Node], p === 'app' ? APP_SCOPE : U[p as Node])
  const fga = new FgaMemoryStore({ model: generatedModel(HOLDERS, [PERMISSION]), initial: initialTuples(spec.tree), staleBy: spec.consistency === 'minimize' ? 2 : 0, trace: spec.trace === true })
  const w: World = { y: async () => {}, tree, fga, trueRoles: new Set(Object.keys(ROLES) as RoleName[]), failed: [] }
  await seedSettleRoles()
  /** El catálogo de la BASE (lo que ve una foto contrastada en fresco): sin RP en cuanto `purgeRole` borra la fila. */
  const freshView = async () => {
    const rows: Array<{ uuid: string }> = await db.from('authz_roles').whereIn('uuid', ALL_ROLE_UUIDS).select('uuid')
    const present = new Set(rows.map((r) => r.uuid))
    const roles = Object.values(ROLES).filter((r) => present.has(r.uuid))
    return catalogView(roles, 10 - roles.length)
  }
  // K4: el memo RANCIO es una foto de ANTES de definir R2 (y no se entera de la purga de RP). Es lo que sirve `view()` a
  // un actor con `{ everyMs }`; `freshView()` —el de las escrituras desde el paso 4— contrasta la versión y ve la base.
  const staleSnapshot = catalogView([ROLES.R, ROLES.RP, ROLES.G, ROLES.GO], 0)
  let faulted = false
  const faultFor = (index: number): ClientHooks['fault'] => {
    const fault = spec.fault
    if (!fault || fault.actor !== index) return undefined
    let writes = 0
    return (event) => {
      if (event.kind !== (fault.on ?? 'write') || ++writes !== fault.nth) return undefined
      faulted = true
      return { error: sdkError('fake-503-unavailable'), when: fault.when }
    }
  }
  const driverFor = (actor: string, stale: boolean, hooks: Parameters<FgaMemoryStore['client']>[1] = {}) => {
    const d: any = new OpenFgaAuthorizationDriver({
      apiUrl: 'http://127.0.0.1:1',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      modelId: TEST_MODEL_ID,
      holderTypes: HOLDERS,
      resolveChain: resolveChainFrom(tree),
      catalog: { view: async () => (stale ? staleSnapshot : freshView()), freshView, invalidate: () => {} } as any,
      acceptScopeDriftRisk: true,
      consistency: spec.consistency === 'minimize' ? 'minimize_latency' : undefined,
      logger: { warn: () => {} },
    } as any)
    installMemoryClient(d, fga.client(actor, hooks))
    // **El commit SQL de `purgeRole` es un punto de planificación del arnés** (paso 4, hallazgo 2): entre la demostración
    // de cero y el DELETE de `authz_roles` puede aterrizar un `grant` entero que decidió con el rol VIVO; sin este punto
    // la ventana no se podía construir (el SQL no pasa por el cliente FGA) y la pata Dekker de la purga —el repaso tras el
    // DELETE— no tenía juez.
    const sql = d.sql.bind(d)
    d.sql = async (operation: string, fn: () => Promise<unknown>) => {
      if (operation === 'purgeRole' && hooks.onIo) await hooks.onIo({ actor, k: 0, kind: 'sql', body: null, consistency: undefined })
      return sql(operation, fn)
    }
    return d
  }
  const outcomes: RunResult['outcomes'] = spec.ops.map((op) => ({ op, status: 'ok' as const }))
  const io = spec.ops.map(() => 0)
  let policy: SchedulerPolicy
  let fired = () => true
  const ids = spec.ops.map((_, i) => `a${i}`)
  if (spec.policy.kind === 'pct') policy = pctPolicy(seededRandom(spec.policy.seed), ids, spec.policy.changePoints, spec.policy.maxSteps)
  else if (spec.policy.kind === 'preempt') {
    const p = preemptPolicy('a0', 'a1', spec.policy.k)
    policy = p
    fired = p.fired
  } else policy = ({ waiting }) => waiting[0]
  const schedule = await runScheduled(
    spec.ops.map((op, i) => ({
      id: ids[i],
      run: async (onIo: (e: IoEvent) => Promise<void>) => {
        const hook = async (e: IoEvent) => {
          io[i]++
          await onIo(e)
        }
        const d = driverFor(ids[i], spec.stale[i] ?? false, { onIo: hook, fault: faultFor(i) })
        const y = (kind: 'start' | 'tree') => hook({ actor: ids[i], k: 0, kind, body: null, consistency: undefined })
        await y('start')
        const r = await runOp({ ...w, y }, d, op)
        if (r === 'skip') outcomes[i] = { op, status: 'skip' }
      },
    })),
    policy,
    // El catálogo fresco y `purgeRole` leen/escriben SQL fuera de los ganchos: en PG/MySQL un viaje a la base dura más que
    // los 10 000 `setImmediate` del drenaje por defecto (medido en PG: «un actor no llega a su gancho»).
    { maxDrain: 2_000_000 }
  )
  spec.ops.forEach((op, i) => {
    const r = schedule.results.get(ids[i])
    if (r && !r.ok) {
      const capped = errCode(r.error) === 'E_AUTHZ_WRITE_CONFLICT' && /no convergió|se purgó del catálogo/.test(String((r.error as any)?.message))
      outcomes[i] = { op, status: 'error', code: errCode(r.error), ...(capped ? { cap: true as const } : {}) }
    }
  })
  // **Drenaje con el relay REAL** (juez TREE §5, regla 7; hasta el paso 4 el arnés re-aplicaba él mismo el padre de HOY
  // del consumidor, que es justo lo que el relay NO hacía y la causa de la conclusión falsa de la fase 1): cada
  // notificación de árbol que falló se encola en una outbox doble CON EL PADRE QUE LLEVABA y la drena
  // `manager.relayScopeChanges()` sobre un driver propio. El relay decide qué padre aplica (desde el lote C: el FRESCO del
  // consumidor; el mutante `relay.trust-enqueued-parent` vuelve al encolado).
  let drained = 0
  const relay: string[] = []
  if (w.failed.length > 0 && !spec.noDrain) {
    drained = w.failed.length
    const outbox = makeScopeOutbox({
      capabilities: { transactionalEnqueue: false, filter: true, transient: true, dead: true, acquire: false, earlierPending: false, requeue: false, createdAt: false },
      maxAttempts: 5,
    })
    for (const change of w.failed) await outbox.enqueue(change, {})
    const drainer = driverFor('relay', false)
    const manager = new AuthorizationManager({
      default: 'fga',
      drivers: { fga: () => drainer },
      holderTypes: HOLDERS,
      scopes: { resolveChain: resolveChainFrom(tree), outbox },
      warnOnOptInSecurity: false,
    } as any)
    try {
      // Como el comando en un cron: unas pasadas (lo transitorio no consume intento) hasta que no quede nada aplicable.
      for (let pass = 0; pass < 3; pass++) {
        const report = await manager.relayScopeChanges()
        for (const e of report.entries) {
          // Un fallo se nombra por su `code` (el `reason` es el mensaje entero).
          const why = e.status === 'failed' ? report.failures.find((f) => String(f.id) === String(e.id))?.code : e.reason
          relay.push(`${e.status}:${e.change.op}${why ? `(${why})` : ''}`)
        }
        if (!report.remaining) break
      }
    } catch (error) {
      relay.push(`error:${errCode(error)}`)
    }
  }
  const consumer = new Map<string, string>()
  for (const n of Object.keys(U) as Node[]) {
    const p = await parentOf(tree, U[n])
    if (p !== null) consumer.set(key(U[n]), p)
  }
  const roles = [...w.trueRoles].map((n) => ROLES[n])
  const violations = judgeQuiescent(fga.tuples(), consumer, roles, fga.model)
  const vConsumer = judgeQuiescent(fga.tuples(), consumer, roles, fga.model, 'consumer')
  let reconciled: RunResult['reconcile']
  if (spec.reconcile) {
    const maintainer = driverFor('reconciler', false)
    const source = maintenanceSource(tree, maintainer)
    // La pasada rehace la proyección `permits_*` desde `authz_*` (la foto del sync): el arnés solo siembra las filas de
    // `authz_roles`, así que mientras dura se escriben el permiso y los vínculos de los roles vivos (y se retiran al
    // terminar). Sin ellos la pasada borraría la proyección entera y el juez vería CLOSED en todo el store.
    const restore = await seedCatalogLinks(roles)
    try {
      const dryRun = await maintainer.reconcile(source, { dryRun: true })
      const prune = await maintainer.reconcile(source, { prune: true })
      reconciled = { dryRun, prune, after: judgeQuiescent(fga.tuples(), consumer, roles, fga.model) }
    } finally {
      await restore()
    }
  }
  return {
    faulted,
    ...(faulted && spec.fault ? { faultedActor: spec.fault.actor } : {}),
    writes: fga.trace.filter((e) => e.kind === 'write' && e.result === 'ok').map((e) => ({ actor: e.actor, writes: e.writes ?? [], deletes: e.deletes ?? [] })),
    violations,
    vConsumer,
    treeExempt: violations.some((v) => v.kind === 'TREE') ? treeExemption(spec.ops, outcomes, violations) : null,
    relay,
    outcomes,
    steps: schedule.steps,
    switches: schedule.switches,
    fired: fired(),
    io,
    drained,
    ...(reconciled ? { reconcile: reconciled } : {}),
  }
}

/** El permiso del universo y sus vínculos con `roles` en `authz_*` (lo que el sync dejaría), con su deshacer. */
export async function seedCatalogLinks(roles: readonly Role[]): Promise<() => Promise<void>> {
  const now = new Date()
  const existing: any = await db.from('authz_permissions').where('slug', PERMISSION).first()
  const permissionUuid = existing ? String(existing.uuid) : PERMISSION_UUID
  if (!existing) await db.table('authz_permissions').insert({ uuid: permissionUuid, slug: PERMISSION, description: null, created_at: now, updated_at: now })
  const links = roles.map((r, i) => ({ uuid: fixedUuid(0xe00 + i), role_uuid: r.uuid, permission_uuid: permissionUuid, created_at: now }))
  const present = new Set((await db.from('authz_roles').whereIn('uuid', links.map((l) => l.role_uuid)).select('uuid')).map((r: any) => String(r.uuid)))
  const live = links.filter((l) => present.has(l.role_uuid))
  if (live.length) await db.table('authz_role_permissions').insert(live)
  return async () => {
    if (live.length) await db.from('authz_role_permissions').whereIn('uuid', live.map((l) => l.uuid)).delete()
    if (!existing) await db.from('authz_permissions').where('uuid', permissionUuid).delete()
  }
}

/**
 * El origen de la pasada de MANTENIMIENTO de `authz:reconcile --to=openfga` sobre el propio store: las aristas del árbol
 * del consumidor (paginadas, como `enumerateEdges`), su resolutor y los hechos del store (`enumerateFacts`, origen
 * propio: con `--prune` lo que sobra se BORRA).
 */
export function maintenanceSource(tree: ContractScopeTree, driver: any) {
  const edges = async ({ limit, after }: { limit: number; after?: string }) => {
    const all: Array<{ child: ScopeRef; parent: ScopeRef }> = []
    for (const node of Object.values(U)) {
      const chain = await tree.chainOf(node)
      if (chain) all.push({ child: chain[0], parent: chain[1] })
    }
    all.sort((a, b) => String(a.child.uuid).localeCompare(String(b.child.uuid)))
    const from = after ? all.findIndex((e) => e.child.uuid === after) + 1 : 0
    const page = all.slice(from, from + limit)
    return { edges: page, ...(from + limit < all.length ? { cursor: String(page[page.length - 1].child.uuid) } : {}) }
  }
  return {
    enumerateEdges: edges,
    resolveChain: resolveChainFrom(tree),
    facts: (page: any) => driver.enumerateFacts(page),
    factsOrigin: { name: 'openfga', authzTables: false, self: true },
  }
}

/** El nodo cuyo PADRE cambia cada operación de árbol (para el predicado (i) de la regla 3). */
const NODE_CHANGED: Partial<Record<Op, Node>> = {
  moveC: 'C',
  moveCtoP: 'C',
  moveCtoQ: 'C',
  churnC: 'C',
  moveP: 'P',
  attachE: 'E',
  attachDtoQ: 'D',
  detachD: 'D',
}

/**
 * Juez TREE §5, regla 3: un TREE solo se admite con un predicado CON NOMBRE. (i) ≥ 2 operaciones TERMINADAS que cambian el
 * MISMO nodo, en línea (el límite declarado: dos `moved` concurrentes del mismo nodo sin outbox); (ii) un `detached` con
 * `E_AUTHZ_PURGE_INCOMPLETE` observado en la corrida (invariante 11: la arista se queda, fail-closed). Cualquier otro TREE
 * es rojo — incluido `churnC` SOLO en `minimize` (hallazgo 3: lo cierra el HIGHER de la lectura del padre de `reparent`).
 */
export function treeExemption(ops: readonly Op[], outcomes: RunResult['outcomes'], violations: readonly Violation[] = []): RunResult['treeExempt'] {
  const finished = new Map<Node, number>()
  ops.forEach((op, i) => {
    const node = NODE_CHANGED[op]
    if (node && outcomes[i].status === 'ok') finished.set(node, (finished.get(node) ?? 0) + 1)
  })
  // Asentar · cierre 1 (⚪-1 del tester): el TREE tiene que ser DEL nodo doblado (medido 637/637 coincidentes: endurecerlo
  // es gratis). La etiqueta del TREE es `<nodo>: store=… consumidor=…`.
  const doubled = new Set([...finished].filter(([, n]) => n >= 2).map(([node]) => node as string))
  const trees = violations.filter((v) => v.kind === 'TREE')
  if (doubled.size > 0 && trees.every((v) => doubled.has(v.detail.slice(0, v.detail.indexOf(':'))))) return 'same-node-inline'
  if (outcomes.some((o) => o.op === 'detachD' && o.status === 'error' && o.code === 'E_AUTHZ_PURGE_INCOMPLETE')) return 'purge-incomplete'
  return null
}

/* ── Campañas: enumeración acotada y PCT ───────────────────────────────── */

export interface CampaignReport {
  runs: number
  /** Corridas con entrelazado real (preempción disparada o ≥ 1 cambio de actor con los dos vivos). */
  effective: number
  open: number
  closed: number
  orphan: number
  tree: number
  /** Corridas con OPEN y SIN deriva del árbol (TREE): el fail-open puro de visibilidad. */
  openNoTree: number
  /** OPEN por combinación de operaciones (las etiquetas ordenadas). */
  openByOps: Record<string, number>
  /** Etiquetas de TODAS las corridas con OPEN (semilla / caso enumerado): el rojo reproducible. */
  openCases: string[]
  byKind: Record<string, number>
  /** CLOSED atribuido a un 409 de la cota del settle (juez TREE §5, regla 1: el único CLOSED admitido). */
  closedAttributed: number
  /** TREE eximido por predicado (regla 3), por nombre. */
  treeExempt: Record<string, number>
  /** TREE SIN predicado que lo exima (regla 3: rojo). */
  treeSilent: number
  /** Regla 2: corridas SIN TREE con OPEN contra el consumidor u OPEN contra el store. */
  consumerOpenNoTree: number
  /** La cifra del límite declarado (regla 6 / Limits): corridas TREE eximidas con OPEN contra el CONSUMIDOR. */
  exemptConsumerOpen: number
  /** Etiquetas de las corridas que rompen alguna de las reglas 1–3 (el rojo reproducible del paso 4). */
  badCases: string[]
  /**
   * Residuo DECLARADO y firmado (C1-4, asentar · cierre 1): corridas de `raceFaultCampaign` con la firma `purgeRP` con un
   * 503 en su 2.º `Write` ∥ `moveCtoP`, cuyo único defecto es un ORPHAN-edge de RP (scope#binding sin #role: no concede;
   * lo recoge `reconcile --prune`). Se cuentan AQUÍ y no en `badCases`; cualquier otra violación de esas corridas sí.
   */
  residue: string[]
  /** Estados de las entradas que drenó el relay real. */
  relay: Record<string, number>
  opOk: Record<string, number>
  opErr: Record<string, number>
  errors: Record<string, number>
  examples: string[]
  seconds: number
}

function emptyReport(): CampaignReport {
  return { runs: 0, effective: 0, open: 0, closed: 0, orphan: 0, tree: 0, openNoTree: 0, openByOps: {}, openCases: [], byKind: {}, closedAttributed: 0, treeExempt: {}, treeSilent: 0, consumerOpenNoTree: 0, exemptConsumerOpen: 0, badCases: [], residue: [], relay: {}, opOk: {}, opErr: {}, errors: {}, examples: [], seconds: 0 }
}

function tally(report: CampaignReport, label: string, r: RunResult, maxExamples: number) {
  report.runs++
  if (r.fired && r.switches > 0) report.effective++
  for (const o of r.outcomes) {
    if (o.status === 'ok') report.opOk[o.op] = (report.opOk[o.op] ?? 0) + 1
    if (o.status === 'error') {
      report.opErr[o.op] = (report.opErr[o.op] ?? 0) + 1
      report.errors[o.code!] = (report.errors[o.code!] ?? 0) + 1
    }
  }
  const kinds = new Set(r.violations.map((v) => v.kind))
  for (const k of kinds) report.byKind[k] = (report.byKind[k] ?? 0) + 1
  if (kinds.has('OPEN-edge') || kinds.has('OPEN-grant')) {
    report.open++
    if (!kinds.has('TREE')) report.openNoTree++
    const combo = r.outcomes.map((o) => o.op).sort().join('+')
    report.openByOps[combo] = (report.openByOps[combo] ?? 0) + 1
    report.openCases.push(label)
  }
  const closed = kinds.has('CLOSED-edge') || kinds.has('CLOSED-grant')
  const attributed = closed && closedAttribution(r) !== null
  if (closed) report.closed++
  if (attributed) report.closedAttributed++
  if (kinds.has('ORPHAN-edge') || kinds.has('ORPHAN-fact')) report.orphan++
  if (kinds.has('TREE')) report.tree++
  for (const entry of r.relay) report.relay[entry] = (report.relay[entry] ?? 0) + 1
  const consumerOpen = r.vConsumer.some((v) => v.kind === 'OPEN-edge' || v.kind === 'OPEN-grant')
  let bad = kinds.has('OPEN-edge') || kinds.has('OPEN-grant') || kinds.has('ORPHAN-edge') || kinds.has('ORPHAN-fact') || (closed && !attributed)
  if (kinds.has('TREE')) {
    if (r.treeExempt) {
      report.treeExempt[r.treeExempt] = (report.treeExempt[r.treeExempt] ?? 0) + 1
      if (consumerOpen) report.exemptConsumerOpen++
    } else {
      report.treeSilent++
      bad = true
    }
  } else if (consumerOpen) {
    report.consumerOpenNoTree++
    bad = true
  }
  if (bad) report.badCases.push(label)
  if (bad && report.examples.length < maxExamples) {
    report.examples.push(
      `${label} ⇒ ${r.violations.slice(0, 3).map((v) => `${v.kind} ${v.detail}`).join('; ')} || consumidor: ${r.vConsumer.filter((v) => v.kind !== 'TREE').slice(0, 3).map((v) => `${v.kind} ${v.detail}`).join('; ')} | ${r.outcomes.map((o) => `${o.op}:${o.status}${o.code ? `(${o.code})` : ''}`).join(' ')}${r.relay.length ? ` | relay ${r.relay.join(',')}` : ''}`
    )
  }
}

/** Lo que cada operación puede tocar: roles (`*` = cualquiera) y nodos (`*` = cualquiera) — la atribución de un CLOSED. */
const TOUCHES: Record<Op, { roles: readonly RoleName[] | '*'; nodes: readonly Node[] | '*' }> = {
  'grantR@C': { roles: ['R'], nodes: ['C'] },
  'grantR2@C': { roles: ['R2'], nodes: ['C'] },
  'grantRP@P': { roles: ['RP'], nodes: ['P'] },
  'grantRP@C': { roles: ['RP'], nodes: ['C'] },
  'regrantRP@P': { roles: ['RP'], nodes: ['P'] },
  'revokeR@C': { roles: ['R'], nodes: ['C'] },
  projectR: { roles: ['R'], nodes: '*' },
  projectR2: { roles: ['R2'], nodes: '*' },
  purgeRP: { roles: ['RP'], nodes: '*' },
  moveC: { roles: '*', nodes: ['C', 'D', 'E'] },
  moveCtoP: { roles: '*', nodes: ['C', 'D', 'E'] },
  moveCtoQ: { roles: '*', nodes: ['C', 'D', 'E'] },
  churnC: { roles: '*', nodes: ['C', 'D', 'E'] },
  moveP: { roles: '*', nodes: ['P', 'C', 'D', 'E'] },
  attachE: { roles: '*', nodes: ['E'] },
  attachDtoQ: { roles: '*', nodes: ['D'] },
  detachD: { roles: '*', nodes: ['D'] },
}

/** ¿Toca la operación `op` el CLOSED `v`? (`CLOSED-edge` = `ROL@NODO […]`; `CLOSED-grant` = `usuario@NODO`.) */
function touches(op: Op, v: Violation): boolean {
  const t = TOUCHES[op]
  const at = v.detail.indexOf('@')
  const head = v.detail.slice(0, at)
  const node = v.detail.slice(at + 1).split(' ')[0]
  const nodeOk = t.nodes === '*' || (t.nodes as readonly string[]).includes(node)
  if (v.kind === 'CLOSED-grant') return nodeOk
  return nodeOk && (t.roles === '*' || (t.roles as readonly string[]).includes(head))
}

/**
 * Juez TREE §5, regla 1: un CLOSED solo se admite ATRIBUIDO, y **solo a lo que tocó el actor que lo causa** (asentar ·
 * cierre 1, 🟡-6 del tester: hasta aquí era una manta —cualquier fallo inyectado o CUALQUIER 409 de la corrida eximía TODOS
 * sus CLOSED—). `fault` = el actor al que se le inyectó el fallo tocaba ese rol/nodo; `cap-409` = un actor recibió el 409
 * de la COTA del settle (o el del `grant` que deshace un rol purgado a la vez: `cap` en su desenlace) y tocaba ese
 * rol/nodo. **La atribución `purge-incomplete` desaparece** (desviación 2 = (b), firma del dueño 2026-10-21): `purgeRole`
 * borra la proyección `permits_*` DESPUÉS de demostrar cero en los hechos, así que una purga que falla ya no deja CLOSED.
 */
export function closedAttribution(r: RunResult): 'fault' | 'cap-409' | null {
  const closed = r.violations.filter((v) => v.kind === 'CLOSED-edge' || v.kind === 'CLOSED-grant')
  if (closed.length === 0) return null
  const faulted = r.faulted && r.faultedActor !== undefined ? [r.outcomes[r.faultedActor]?.op].filter(Boolean) as Op[] : []
  const capped = r.outcomes.filter((o) => o.cap).map((o) => o.op)
  const by = (ops: Op[]) => ops.length > 0 && closed.every((v) => ops.some((op) => touches(op, v)))
  if (by(faulted)) return 'fault'
  if (by(capped)) return 'cap-409'
  if (by([...faulted, ...capped])) return faulted.length ? 'fault' : 'cap-409'
  return null
}

/** Una preempción: para cada par ordenado, el actor 2 ENTERO en cada I/O k del actor 1 (k = 1…I/O del 1 en solitario). */
export async function enumerationCampaign(options: {
  ops?: readonly Op[]
  trees?: readonly TreeName[]
  consistency: Consistency
  /** Pares con R2: el actor que NO concede R2 lleva el memo rancio (K4). */
  staleForR2?: boolean
  maxExamples?: number
  filter?: (a1: Op, a2: Op) => boolean
}): Promise<CampaignReport> {
  const started = performance.now()
  const report = emptyReport()
  const ops = options.ops ?? OPS
  for (const tree of options.trees ?? (['T1', 'T2', 'T3'] as const)) {
    for (const a1 of ops) {
      const solo = await runSettleCase({ tree, ops: [a1], stale: [false], consistency: options.consistency, policy: { kind: 'solo' } })
      const n = solo.io[0]
      for (const a2 of ops) {
        if (a1 === 'purgeRP' && a2 === 'purgeRP') continue
        if (options.filter && !options.filter(a1, a2)) continue
        const stale = options.staleForR2 ? [a1 !== 'grantR2@C' && a2 === 'grantR2@C', a2 !== 'grantR2@C' && a1 === 'grantR2@C'] : [false, false]
        if (options.staleForR2 && !stale.some(Boolean)) continue
        for (let k = 1; k <= n; k++) {
          const r = await runSettleCase({ tree, ops: [a1, a2], stale, consistency: options.consistency, policy: { kind: 'preempt', k } })
          if (!r.fired) continue
          tally(report, `enum ${tree} ${a1}∥${a2}@${k}${stale.some(Boolean) ? ' rancio' : ''} ${options.consistency}`, r, options.maxExamples ?? 12)
        }
      }
    }
  }
  report.seconds = (performance.now() - started) / 1000
  return report
}

/** PCT con semillas fijas: 3 actores, operaciones, árbol y memo rancio derivados de la semilla. */
export function pctSpec(seed: number, consistency: Consistency, actors = 3): RunSpec {
  const rnd = seededRandom(seed * 7919 + (consistency === 'minimize' ? 1 : 0))
  const tree = (['T1', 'T2', 'T3'] as const)[Math.floor(rnd() * 3)]
  const ops: Op[] = []
  while (ops.length < actors) {
    const op = OPS[Math.floor(rnd() * OPS.length)]
    if (op === 'purgeRP' && ops.includes('purgeRP')) continue
    ops.push(op)
  }
  const stale = ops.map(() => rnd() < 0.3)
  return { tree, ops, stale, consistency, policy: { kind: 'pct', seed, changePoints: 1 + Math.floor(rnd() * 3), maxSteps: 60 } }
}

export async function pctCampaign(options: { from: number; to: number; consistency: Consistency; maxExamples?: number }): Promise<CampaignReport> {
  const started = performance.now()
  const report = emptyReport()
  for (let seed = options.from; seed <= options.to; seed++) {
    const spec = pctSpec(seed, options.consistency)
    const r = await runSettleCase(spec)
    tally(report, `pct seed=${seed} ${spec.tree} [${spec.ops.map((o, i) => o + (spec.stale[i] ? '*' : '')).join(', ')}] ${options.consistency}`, r, options.maxExamples ?? 12)
  }
  report.seconds = (performance.now() - started) / 1000
  return report
}

/**
 * **Fallos inyectados + relay REAL** (juez TREE §5, regla 7): el actor 1 recibe un 503 en su `nth`-ésimo `Write` (antes o
 * después de aplicarse), el actor 2 corre DESPUÉS entero (o no hay actor 2), y lo que falló lo drena
 * `relayScopeChanges()` con el padre ENCOLADO. Es la campaña que ejercita el relay: sin fallos, nada llega a la outbox.
 * El caso que discrimina el padre fresco: `moveC` falla (encola C→B) y otro `moveC` lo devuelve a A; relevar el encolado
 * deja C bajo B en el store y bajo A en el consumidor, en silencio (mutante `relay.trust-enqueued-parent`).
 */
export async function faultCampaign(options: { consistency: Consistency; trees?: readonly TreeName[]; maxExamples?: number; ops?: readonly Op[] }): Promise<CampaignReport> {
  const started = performance.now()
  const report = emptyReport()
  const ops = options.ops ?? OPS
  for (const tree of options.trees ?? (['T1', 'T2', 'T3'] as const)) {
    for (const a1 of ops) {
      for (const second of [null, ...ops] as Array<Op | null>) {
        if (a1 === 'purgeRP' && second === 'purgeRP') continue
        for (const when of ['before', 'after'] as const) {
          for (let nth = 1; nth <= 4; nth++) {
            const spec: RunSpec = {
              tree,
              ops: second ? [a1, second] : [a1],
              stale: second ? [false, false] : [false],
              consistency: options.consistency,
              policy: { kind: 'solo' },
              fault: { actor: 0, nth, when },
            }
            const r = await runSettleCase(spec)
            if (!r.faulted) break
            tally(report, `fault ${tree} ${a1}!w${nth}:${when}${second ? ` → ${second}` : ''} ${options.consistency}`, { ...r, fired: true, switches: 1 }, options.maxExamples ?? 12)
          }
        }
      }
    }
  }
  report.seconds = (performance.now() - started) / 1000
  return report
}

/**
 * **Fallo ∥ carrera** (asentar · cierre 1, 🟡 4 del auditor): la campaña de fallos es SECUENCIAL y nunca combina un fallo
 * con una carrera. Aquí, para cada par ordenado y cada I/O k del actor 1 (el actor 2 entero en k), un 503 NO-timeout en el
 * `nth`-ésimo `batchCheck` o `Write` del actor 1 (el que el settle usa para releer o corregir). `drain` = con el relay real
 * después (outbox) o en línea puro.
 */
export async function raceFaultCampaign(options: { consistency: Consistency; trees?: readonly TreeName[]; ops?: readonly Op[]; drain: boolean; maxExamples?: number }): Promise<CampaignReport> {
  const started = performance.now()
  const report = emptyReport()
  const ops = options.ops ?? OPS
  for (const tree of options.trees ?? (['T1', 'T2', 'T3'] as const)) {
    for (const a1 of ops) {
      const solo = await runSettleCase({ tree, ops: [a1], stale: [false], consistency: options.consistency, policy: { kind: 'solo' } })
      for (const a2 of ops) {
        if (a1 === 'purgeRP' && a2 === 'purgeRP') continue
        for (const on of ['batchCheck', 'write'] as const) {
          for (let nth = 1; nth <= 2; nth++) {
            for (let k = 1; k <= solo.io[0]; k++) {
              const r = await runSettleCase({ tree, ops: [a1, a2], stale: [false, false], consistency: options.consistency, policy: { kind: 'preempt', k }, fault: { actor: 0, nth, when: 'before', on }, noDrain: !options.drain })
              if (!r.fired || !r.faulted) continue
              const label = `racefault ${tree} ${a1}!${on}${nth}∥${a2}@${k} ${options.drain ? 'drain' : 'inline'}`
              // C1-4 (firmado): el ORPHAN-edge de RP con esta firma exacta va a `residue`; el resto de la corrida se juzga.
              const c14 = a1 === 'purgeRP' && on === 'write' && nth === 2 && a2 === 'moveCtoP'
              const residual = c14 ? r.violations.filter((v) => v.kind === 'ORPHAN-edge' && v.detail.startsWith('RP@')) : []
              if (residual.length > 0) report.residue.push(label)
              tally(report, label, residual.length > 0 ? { ...r, violations: r.violations.filter((v) => !residual.includes(v)) } : r, options.maxExamples ?? 12)
            }
          }
        }
      }
    }
  }
  report.seconds = (performance.now() - started) / 1000
  return report
}

/** Control del oráculo: un estado consistente da 0; una arista plantada fuera del owner es OPEN; una quitada, CLOSED. */
export function oracleSelfCheck(): { clean: Violation[]; planted: Violation[]; removed: Violation[] } {
  const tuples = initialTuples('T2')
  const consumer = new Map<string, string>()
  for (const [n, p] of Object.entries(TREES.T2)) consumer.set(key(U[n as Node]), p === 'app' ? 'app' : key(U[p as Node]))
  const roles = Object.values(ROLES)
  const model = new FgaMemoryStore({ model: generatedModel(HOLDERS, [PERMISSION]) }).model
  const clean = judgeQuiescent(tuples, consumer, roles, model)
  // T2: C bajo B ⇒ la arista de R en C no está; plantarla es el fail-open del 🟠.
  const edge = { user: factsBindingObject(key(U.C), ROLES.R.uuid), relation: 'binding', object: `scope:${key(U.C)}` }
  const planted = judgeQuiescent([...tuples, edge], consumer, roles, model)
  // La de G en C (global) sí está; quitarla es CLOSED.
  const gEdge = (t: FgaTuple) => t.relation === 'binding' && t.user === factsBindingObject(key(U.C), ROLES.G.uuid)
  const removed = judgeQuiescent(tuples.filter((t) => !gEdge(t)), consumer, roles, model)
  return { clean, planted, removed }
}

/**
 * **La COTA del settle, alcanzada de verdad** (resolución 7 del juez; auditor 🟡 2: «un caso que llegue de verdad a la
 * cota»). Un `grant` de R (local de A) en C bajo T1 mientras otro escritor del árbol mueve C entre A y B JUSTO en cada
 * relectura del settle (en cada `batchCheck` del actor): ninguna lectura posterior ve el store coherente con su última
 * escritura, el settle se rinde a las `SETTLE_MAX_ROUNDS` vueltas, BORRA la arista y lanza 409 marcado parcial. `regrant`
 * = la asignación ya existía (alice): solo se va la arista; si no (carol), también el `assignee` (vuelta a «no ocurrió»).
 */
export async function settleCapCase(regrant: boolean | 'direct' | 'direct-two'): Promise<{ error: any; tuples: FgaTuple[]; flips: number }> {
  const fga = new FgaMemoryStore({ model: generatedModel(HOLDERS, [PERMISSION]), initial: initialTuples('T1'), trace: false })
  const tree = memoryScopeTree()
  for (const [n, p] of Object.entries(TREES.T1)) await tree.attach(U[n as Node], p === 'app' ? APP_SCOPE : U[p as Node])
  const view = catalogView(Object.values(ROLES), 1)
  const churner = fga.client('churner')
  let flips = 0
  const d: any = new OpenFgaAuthorizationDriver({
    apiUrl: 'http://127.0.0.1:1',
    storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    modelId: TEST_MODEL_ID,
    holderTypes: HOLDERS,
    resolveChain: resolveChainFrom(tree),
    catalog: { view: async () => view, freshView: async () => view, invalidate: () => {} } as any,
    acceptScopeDriftRisk: true,
    logger: { warn: () => {} },
  } as any)
  installMemoryClient(
    d,
    fga.client('grant', {
      onIo: async (event) => {
        if (event.kind !== 'batchCheck') return
        // El otro escritor del árbol: justo antes de que esta relectura se evalúe, deja C donde la arista de R@C que hay
        // AHORA está mal (con arista ⇒ C bajo B; sin ella ⇒ C bajo A): ninguna relectura ve el store coherente.
        const edgeNow = fga.has({ user: factsBindingObject(key(U.C), ROLES.R.uuid), relation: 'binding', object: `scope:${key(U.C)}` })
        const to = edgeNow ? U.B : U.A
        const from = edgeNow ? U.A : U.B
        if (fga.has(factsParentTuple(key(U.C), key(from)))) {
          await churner.write({ writes: [factsParentTuple(key(U.C), key(to))], deletes: [factsParentTuple(key(U.C), key(from))] })
        }
        flips++
      },
    })
  )
  let error: any = null
  try {
    // `direct` (asentar · cierre 1, mutante `settle.cap-unmarked`): el settle a secas, con `progress.writes = 0` — como lo
    // llama `reconcile`, el único de los CUATRO llamadores que no marca parcial por su cuenta.
    if (regrant === 'direct') await d.settleRoleVisibility([{ scope: key(U.C), role: ROLES.R.uuid }], { writes: 0 })
    // `direct-two` (🟡 2 del auditor): junto al par que el churn no deja converger, uno que SÍ converge (RP@P: owner ==
    // scope, el churn de C no le afecta). La rendición no puede llevárselo.
    else if (regrant === 'direct-two') await d.settleRoleVisibility([{ scope: key(U.C), role: ROLES.R.uuid }, { scope: key(U.P), role: ROLES.RP.uuid }], { writes: 0 })
    else await d.grant(sub(regrant ? 'alice' : 'carol'), { uuid: ROLES.R.uuid }, U.C, { expiresAt: null })
  } catch (e) {
    error = e
  }
  return { error, tuples: fga.tuples(), flips }
}

/* ── Asentar · cierre 1: un banco de UN driver sobre el doble fiel (casos dirigidos) ─────────────────────────────── */

export interface SettleRig {
  fga: FgaMemoryStore
  tree: ContractScopeTree
  driver: any
  /** Cambia el catálogo que ven `view()`/`freshView()` (p. ej. el NIVEL de un rol: 🟠-2 del tester). */
  setRoles: (roles: Role[]) => void
  /** ¿Está la arista `scope#binding` de `role` en `node`? */
  edge: (role: RoleName, node: Node) => boolean
  /** `can_docs_read` del intérprete sobre el store. */
  can: (user: string, node: Node) => boolean
  /** Otro «proceso»: un driver REAL más sobre el MISMO store, árbol y catálogo (sin ganchos). */
  another: (actor: string) => any
  /** Juez de quietud (cara L13) con el catálogo y el árbol del consumidor actuales. */
  judge: () => Promise<Violation[]>
}

/**
 * Un driver REAL sobre el doble fiel, con el árbol inicial `tree`, el catálogo inyectado (mutable) y los ganchos del
 * cliente que el caso quiera (`onIo`, `fault`), más la cota de profundidad del doble. Para los casos dirigidos del cierre
 * 1 que la propiedad no construye (nivel del rol, error por ítem, caída a `storeChain`, `finally`, cota directa).
 */
export async function settleRig(options: {
  tree?: TreeName
  hooks?: ClientHooks
  depthLimits?: { ancestor?: number; other?: number }
  /** Catálogo (por defecto, el universo) y, si se da, el que sirve `view()` (un memo RANCIO de `{ everyMs }`). */
  roles?: Role[]
  staleRoles?: Role[]
} = {}): Promise<SettleRig> {
  const treeName = options.tree ?? 'T1'
  const fga = new FgaMemoryStore({
    model: generatedModel(HOLDERS, [PERMISSION]),
    initial: initialTuples(treeName),
    trace: false,
    ...(options.depthLimits ? { depthLimits: options.depthLimits } : {}),
  })
  const tree = memoryScopeTree()
  for (const [n, p] of Object.entries(TREES[treeName])) await tree.attach(U[n as Node], p === 'app' ? APP_SCOPE : U[p as Node])
  let roles: Role[] = options.roles ?? Object.values(ROLES)
  let version = 1
  const fresh = async () => catalogView(roles, version)
  const view = options.staleRoles ? async () => catalogView(options.staleRoles!, 0) : fresh
  const build = (actor: string, hooks: ClientHooks) => {
    const d: any = new OpenFgaAuthorizationDriver({
      apiUrl: 'http://127.0.0.1:1',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      modelId: TEST_MODEL_ID,
      holderTypes: HOLDERS,
      resolveChain: resolveChainFrom(tree),
      catalog: { view, freshView: fresh, invalidate: () => {} } as any,
      acceptScopeDriftRisk: true,
      logger: { warn: () => {} },
    } as any)
    installMemoryClient(d, fga.client(actor, hooks))
    return d
  }
  const driver = build('a0', options.hooks ?? {})
  const consumerMap = async () => {
    const consumer = new Map<string, string>()
    for (const n of Object.keys(U) as Node[]) {
      const p = await parentOf(tree, U[n])
      if (p !== null) consumer.set(key(U[n]), p)
    }
    return consumer
  }
  return {
    fga,
    tree,
    driver,
    setRoles: (next) => {
      roles = next
      version++
    },
    another: (actor) => build(actor, {}),
    edge: (role, node) => fga.has({ user: factsBindingObject(key(U[node]), ROLES[role].uuid), relation: 'binding', object: `scope:${key(U[node])}` }),
    can: (user, node) =>
      checkTuples(fga.model, new TupleStore(fga.tuples()), {
        user: `user:${user}`,
        relation: 'can_docs_read',
        object: `scope:${key(U[node])}`,
        context: { current_time: new Date(0).toISOString() },
      }).verdict === 'T',
    judge: async () => judgeQuiescent(fga.tuples(), await consumerMap(), roles, fga.model),
  }
}
