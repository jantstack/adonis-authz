/**
 * **La demostración por FUERZA BRUTA del orden de una transición de relaciones** (plan 2.5 · lote D · cierre 2 de D2,
 * 🟡 N3; linaje L10). Sin servidor, sin base: el universo es un conjunto pequeño de tuplas en la forma del STORE y el
 * oráculo es el corte de camino (D5) de UNA relación con deny (`viewer`): concede ⇔ algún allow alcanza al sujeto
 * (directo o por `group#member`, anidado) y ningún deny lo alcanza. Para cada par (inicial, final) —el final es el ORIGEN
 * con `--prune` y la UNIÓN sin él— se pide a `relationTransitionOrder` el orden del diff y se recorre CADA prefijo:
 *
 *   concedido(prefijo) ⊆ concedido(inicial) ∪ concedido(final), y ningún sujeto denegado en los dos concede.
 *
 * Además, para cada par en el que el orden concede, se mide si EXISTÍA algún orden seguro (programación dinámica sobre el
 * retículo de subconjuntos del diff): así se sabe qué parte del residuo es inherente.
 *
 * Lo usan la propiedad `relations.order.exhaustive` de la guardia de superficie (universo reducido, en cada mutante) y
 * `tests/relations_order_exhaustive.spec.ts` (los universos completos, con sus cifras y su tiempo).
 */
import { cutPathAllows, defineRelationsConfig, relationsUp } from '../../src/relations/define_relations_config.js'
import { denyCarrierGroups, relationTransitionOrder } from '../../src/relations/tuple_order.js'
import { liveInDestination } from '../../src/relations/reconcile.js'
import type { RelationCuts, RelationOrderView } from '../../src/relations/tuple_order.js'

export type UniverseName = 'E1' | 'E1-reduced' | 'U2' | 'E3'

const U1 = 'user:u1'
const U2 = 'user:u2'
const X = 'document:x'
const Y = 'document:y'
const member = (group: string) => `${group}#member`
const m = (user: string, group: string): RelationOrderView => ({ deny: false, object: group, user, relation: 'member' })
const a = (user: string, object: string): RelationOrderView => ({ deny: false, object, user, relation: 'viewer' })
const d = (user: string, object: string): RelationOrderView => ({ deny: true, object, user, relation: 'viewer' })

/**
 * Los universos (cada uno, la lista de tuplas POSIBLES):
 *  - `E1` (EXHAUSTIVO, 10 tuplas ⇒ 4^10 pares por modo): 1 usuario, 2 grupos (g, h) con 1 nivel de anidamiento (h ⊂ g),
 *    2 objetos, `viewer` con deny; allows directos y por grupo, denies por grupo. Reúne las cinco formas medidas: el
 *    ex-miembro que compone con un allow nuevo (🟡 N3), la composición ANIDADA, el grupo que solo transporta un deny
 *    (🟡 N2), el cambio de grupo denegado, y el cruce de dos grupos (residuo).
 *  - `E1-reduced` (EXHAUSTIVO, 8 tuplas): el de la guardia — corre en cada mutante del corredor.
 *  - `U2` (MUESTRA): el universo del brief entero — 2 usuarios, 2 grupos (h ⊂ g), 2 objetos, allows y denies directos y
 *    por grupo (21 tuplas, 4^21 pares: no se recorre entero).
 *  - `E3` (MUESTRA): 1 usuario, 3 grupos con DOS niveles de anidamiento (a ⊂ b ⊂ c y a ⊂ c), 2 objetos (20 tuplas).
 */
export function universe(name: UniverseName): RelationOrderView[] {
  const g = 'group:g'
  const h = 'group:h'
  if (name === 'E1') {
    return [m(U1, g), m(U1, h), m(member(h), g), a(U1, X), a(member(g), X), a(member(h), X), a(member(h), Y), d(member(g), X), d(member(h), X), d(member(g), Y)]
  }
  if (name === 'E1-reduced') {
    return [m(U1, g), m(U1, h), m(member(h), g), a(U1, X), a(member(g), X), a(member(h), Y), d(member(h), X), d(member(g), Y)]
  }
  if (name === 'E3') {
    const ga = 'group:a'
    const gb = 'group:b'
    const gc = 'group:c'
    const out = [m(U1, ga), m(U1, gb), m(U1, gc), m(member(ga), gb), m(member(gb), gc), m(member(ga), gc)]
    for (const s of [U1, member(ga), member(gb), member(gc)]) for (const o of [X, Y]) out.push(a(s, o))
    for (const s of [member(ga), member(gb), member(gc)]) for (const o of [X, Y]) out.push(d(s, o))
    return out
  }
  const out = [m(U1, g), m(U1, h), m(U2, g), m(U2, h), m(member(h), g)]
  for (const s of [U1, U2, member(g), member(h)]) for (const o of [X, Y]) out.push(a(s, o))
  for (const s of [U1, U2, member(g), member(h)]) for (const o of [X, Y]) out.push(d(s, o))
  return out
}

/** La config de UNA relación con deny del universo: el predicado `cuts` del auto-corte sale de aquí (D5). */
export const ORDER_CONFIG = defineRelationsConfig({
  objectTypes: [{ type: 'document', relations: [{ name: 'viewer' }], deny: 'write' }],
  holderTypes: ['user'],
})
export const ORDER_CUTS: RelationCuts = (objectType, denied, allowed) => relationsUp(ORDER_CONFIG, objectType, allowed).includes(denied)

/**
 * El ORÁCULO: por máscara de presencia, los bits de (usuario, objeto) concedidos y denegados. Con `package: true` decide
 * con `cutPathAllows` del paquete (la MISMA función que `database`, el doble y el modelo FGA); si no, la regla de una
 * relación escrita a mano (más rápida) — el spec cruza las dos sobre `E1`.
 *
 * **Cierre 5 de D2 (D4-2 del auditor del cierre 4): los objetos `group:` CUENTAN.** Un par (usuario, `group:G`) se
 * concede si el usuario ALCANZA `G#member` (directo o anidado): ser miembro es en sí una concesión (`check(member)`,
 * `listSubjects(group)`, `membersOf`). Hasta el cierre 4 el oráculo los excluía y era ciego a una membresía que sobra
 * (la que la retención no borraba). En `group` no hay deny posible (422 `E_AUTHZ_RELATION_NOT_DENYABLE`).
 */
export function oracle(views: RelationOrderView[], opts: { package?: boolean } = {}) {
  const users = [...new Set(views.map((v) => v.user).filter((u) => !u.includes('#')))].sort()
  const objects = [...new Set(views.filter((v) => !v.object.startsWith('group:')).map((v) => v.object))].sort()
  const groups = [...new Set(views.filter((v) => v.object.startsWith('group:')).map((v) => v.object))].sort()
  const pairs = users.flatMap((u) => [...objects, ...groups].map((o) => [u, o] as const))
  if (pairs.length > 31) throw new Error(`el oráculo cabe en 31 bits: ${pairs.length} pares`)
  const size = 1 << views.length
  const granted = new Uint32Array(size)
  const denied = new Uint32Array(size)
  // Las membresías del universo (pocas): el alcance de cada usuario se calcula UNA vez por sub-máscara de membresías.
  const memberships = views.map((v, i) => [v, i] as const).filter(([v]) => !v.deny && v.object.startsWith('group:'))
  const reachMemo = new Map<string, Set<string>>()
  const reachOf = (user: string, membershipMask: number): Set<string> => {
    const memoKey = `${user}|${membershipMask}`
    let reached = reachMemo.get(memoKey)
    if (reached) return reached
    reached = new Set([user])
    for (let grew = true; grew; ) {
      grew = false
      for (const [t, i] of memberships) {
        if (!(membershipMask & (1 << i))) continue
        if (reached.has(t.user) && !reached.has(member(t.object))) {
          reached.add(member(t.object))
          grew = true
        }
      }
    }
    reachMemo.set(memoKey, reached)
    return reached
  }
  const membershipBits = memberships.reduce((acc, [, i]) => acc | (1 << i), 0)
  const facts = views.map((v, i) => [v, i] as const).filter(([v]) => !v.object.startsWith('group:'))
  for (let mask = 0; mask < size; mask++) {
    let g = 0
    let dn = 0
    pairs.forEach(([user, object], bit) => {
      const reached = reachOf(user, mask & membershipBits)
      if (object.startsWith('group:')) {
        if (reached.has(member(object))) g |= 1 << bit
        return
      }
      const allows = new Set<string>()
      const denies = new Set<string>()
      for (const [t, i] of facts) {
        if (!(mask & (1 << i)) || t.object !== object || !reached.has(t.user)) continue
        ;(t.deny ? denies : allows).add(t.relation!)
      }
      const grant = opts.package ? cutPathAllows(ORDER_CONFIG, 'document', 'viewer', allows, denies) : allows.size > 0 && denies.size === 0
      if (grant) g |= 1 << bit
      if (denies.size > 0) dn |= 1 << bit
    })
    granted[mask] = g
    denied[mask] = dn
  }
  return { granted, denied, pairs }
}

/**
 * Un par CONCRETO (inicial, final, en vistas del universo) recorrido con `order`: el primer prefijo que concede fuera de
 * inicial ∪ final (o a un denegado en los dos), o `null`. Para fijar los contraejemplos literales del informe.
 */
export function walkPair(name: UniverseName, order: OrderFn, initial: RelationOrderView[], final: RelationOrderView[]): { bad: number | null; steps: string[] } {
  const views = universe(name)
  const { granted, denied } = oracle(views)
  const key = (v: RelationOrderView) => `${v.deny}|${v.object}|${v.user}`
  const index = new Map(views.map((v, i) => [key(v), i]))
  const maskOf = (list: RelationOrderView[]) => list.reduce((acc, v) => acc | (1 << index.get(key(v))!), 0)
  const i0 = maskOf(initial)
  const f0 = maskOf(final)
  const plan = order({
    writes: views.filter((_, i) => f0 & ~i0 & (1 << i)),
    deletes: views.filter((_, i) => i0 & ~f0 & (1 << i)),
    context: views.filter((_, i) => (i0 | f0) & (1 << i)),
  })
  const bound = granted[i0] | granted[f0]
  const both = denied[i0] & denied[f0]
  let mask = i0
  let bad: number | null = null
  plan.steps.forEach((step, k) => {
    const i = index.get(key(step.item))!
    mask = step.op === 'write' ? mask | (1 << i) : step.op === 'delete' ? mask & ~(1 << i) : mask
    if (bad === null && ((granted[mask] & ~bound) !== 0 || (granted[mask] & both) !== 0)) bad = k + 1
  })
  return { bad, steps: plan.steps.map((s) => (s.op === 'write' ? '+' : '-') + show(s.item)) }
}

/** Las vistas del universo, por nombre corto (`g@u1`, `x@g#member`, `¬x@h#member`): para escribir pares a mano. */
export function pick(name: UniverseName, ...shorts: string[]): RelationOrderView[] {
  const views = universe(name)
  return shorts.map((short) => {
    const found = views.find((v) => show(v) === short)
    if (!found) throw new Error(`'${short}' no está en el universo ${name}`)
    return found
  })
}

export type OrderFn = (transition: {
  writes: RelationOrderView[]
  deletes: RelationOrderView[]
  context: RelationOrderView[]
  renewals?: RelationOrderView[]
  shortening?: RelationOrderView[]
}) => {
  steps: Array<{ item: RelationOrderView; op: 'write' | 'delete' | 'renew' }>
  residue: RelationOrderView[]
}

/** El orden del paquete, con (`cuts`) o sin el predicado del auto-corte (sin él, el modo conservador). */
export function packageOrder(cuts: RelationCuts | undefined): OrderFn {
  return (transition) => relationTransitionOrder(transition, (v) => v, cuts ? { cuts } : {})
}

export interface BruteForceResult {
  universe: UniverseName
  tuples: number
  mode: 'exhaustive' | 'sample'
  /** Pares (inicial, final) recorridos, sumando los dos modos (`--prune` y sin él). */
  pairs: number
  /** Pares cuyo grafo de precedencias tiene un ciclo (`residue` no vacío). */
  residuePairs: number
  /** Pares en los que algún prefijo concede fuera de inicial ∪ final (o a un denegado en los dos). */
  unsafe: number
  /** De esos, los que NO tenían ningún orden seguro (inherentes). */
  inherent: number
  /** ROJO: pares que conceden SIN residuo declarado (la propiedad exige cero). */
  unsafeWithoutResidue: number
  /** ROJO: el orden no es una permutación del diff o no llega al final. */
  malformed: number
  ms: number
  examples: string[]
}

export function show(v: RelationOrderView): string {
  const s = (x: string) => x.replace('document:', '').replace('group:', '').replace('user:', '')
  return `${v.deny ? '¬' : ''}${s(v.object)}@${s(v.user)}`
}

/** Recorre el universo (entero o una muestra con semilla) contra `order`. */
export function bruteForce(name: UniverseName, order: OrderFn, opts: { sample?: number; seed?: number; maxExamples?: number } = {}): BruteForceResult {
  const started = Date.now()
  const views = universe(name)
  const n = views.length
  const { granted, denied } = oracle(views)
  const full = (1 << n) - 1
  const index = new Map(views.map((v, i) => [`${v.deny}|${v.object}|${v.user}`, i]))
  const result: BruteForceResult = {
    universe: name,
    tuples: n,
    mode: opts.sample ? 'sample' : 'exhaustive',
    pairs: 0,
    residuePairs: 0,
    unsafe: 0,
    inherent: 0,
    unsafeWithoutResidue: 0,
    malformed: 0,
    ms: 0,
    examples: [],
  }
  // mulberry32: muestra reproducible.
  let seed = opts.seed ?? 20261015
  const random = () => {
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  const total = opts.sample ?? 4 ** n
  for (const prune of [true, false]) {
    for (let t = 0; t < total; t++) {
      const initial = opts.sample ? Math.floor(random() * (full + 1)) : t & full
      const source = opts.sample ? Math.floor(random() * (full + 1)) : Math.floor(t / (full + 1))
      const final = prune ? source : initial | source
      const writes = views.filter((_, i) => final & ~initial & (1 << i))
      const deletes = views.filter((_, i) => initial & ~final & (1 << i))
      const context = views.filter((_, i) => (initial | final) & (1 << i))
      result.pairs++
      const plan = order({ writes, deletes, context })
      if (plan.residue.length > 0) result.residuePairs++
      const bound = granted[initial] | granted[final]
      const both = denied[initial] & denied[final]
      let mask = initial
      let bad: number | null = (granted[mask] & ~bound) !== 0 || (granted[mask] & both) !== 0 ? 0 : null
      const seen = new Set<number>()
      plan.steps.forEach((step, k) => {
        const i = index.get(`${step.item.deny}|${step.item.object}|${step.item.user}`)!
        seen.add(i)
        mask = step.op === 'write' ? mask | (1 << i) : step.op === 'delete' ? mask & ~(1 << i) : mask
        if (bad === null && ((granted[mask] & ~bound) !== 0 || (granted[mask] & both) !== 0)) bad = k + 1
      })
      if (mask !== final || seen.size !== writes.length + deletes.length || plan.steps.length !== writes.length + deletes.length) result.malformed++
      if (bad === null) continue
      result.unsafe++
      const inherent = !admissible(initial, final, n, granted, bound, both)
      if (inherent) result.inherent++
      if (plan.residue.length === 0) result.unsafeWithoutResidue++
      if (result.examples.length < (opts.maxExamples ?? 3) && (plan.residue.length === 0 || result.examples.length === 0)) {
        result.examples.push(
          `${prune ? '--prune' : 'sin --prune'} · inicial [${views.filter((_, i) => initial & (1 << i)).map(show).join(' ')}] · final [${views
            .filter((_, i) => final & (1 << i))
            .map(show)
            .join(' ')}] · orden [${plan.steps.map((s) => (s.op === 'write' ? '+' : '-') + show(s.item)).join(' ')}] · concede tras ${bad} · residuo [${plan.residue.map(show).join(' ')}]${inherent ? ' · sin orden seguro' : ''}`
        )
      }
    }
  }
  result.ms = Date.now() - started
  return result
}

/** ¿Existe ALGUNA permutación del diff con todos los prefijos seguros? DP sobre los subconjuntos del diff. */
export function admissible(initial: number, final: number, n: number, granted: Uint32Array, bound: number, both: number): boolean {
  const diff: number[] = []
  for (let i = 0; i < n; i++) if (((initial ^ final) >> i) & 1) diff.push(i)
  const reach = new Uint8Array(1 << diff.length)
  reach[0] = 1
  for (let sub = 0; sub < reach.length; sub++) {
    if (!reach[sub]) continue
    for (let j = 0; j < diff.length; j++) {
      const next = sub | (1 << j)
      if (next === sub || reach[next]) continue
      let mask = initial
      for (let k = 0; k < diff.length; k++) if (next & (1 << k)) mask ^= 1 << diff[k]
      if ((granted[mask] & ~bound) === 0 && (granted[mask] & both) === 0) reach[next] = 1
    }
  }
  return reach[reach.length - 1] === 1
}

/* ── Cierre 3 de D2 · 🟡 C2-2 y cierre 4 · 🟡 horizonte: la VIGENCIA en el universo ─────────────────────────────── */

/**
 * Los OCHO estados de una tupla del universo con vigencia (destino × origen): el destino la tiene AUSENTE, VENCIDA o VIVA
 * (caduca en `now + 1 h`); el origen AUSENTE o VIVA —con la MISMA caducidad que el destino, con una MÁS LARGA (`+2 h`,
 * una renovación que ALARGA) o con una MÁS CORTA (`+30 min`, cierre 4: una que ACORTA)—. Una vencida del origen es una
 * ausente (el plan la descarta en `skipped.expired`), así que no es un estado aparte.
 */
const VIG_STATES = [
  { dest: 'absent', source: 'absent' },
  { dest: 'absent', source: 'same' },
  { dest: 'expired', source: 'absent' },
  { dest: 'expired', source: 'same' },
  { dest: 'live', source: 'absent' },
  { dest: 'live', source: 'same' },
  { dest: 'live', source: 'other' },
  { dest: 'live', source: 'shorter' },
] as const

export interface VigenciaResult extends BruteForceResult {
  atomic: boolean
  /** Renovaciones de portadoras que el destino no puede ejecutar (`renewal-unsafe`, destino sin `atomicRenewal`). */
  renewalUnsafe: number
  /** Cierre 4 · 🟡 C3-2: denies del origen que el destino no puede (re)escribir (`deny-conditional`, sin `atomicRenewal`). */
  denyConditional: number
  /**
   * Cierre 5 de D2 (opción A): combinaciones cuya PARTICIÓN se NIEGA (≥ 1 `renewal-unsafe` o `deny-conditional`): cero
   * escrituras y cero borrados, así que el estado en TODO instante es el inicial — no hay nada que comprobar. Es la ÚNICA
   * exclusión del oráculo (la general `preexisting` del cierre 4 se fue: H2 del auditor del panel).
   */
  refused: number
  /** Combinaciones con al menos una tupla VENCIDA en el destino. */
  withExpired: number
  /** Renovaciones ejecutadas (con su hueco si el destino no es atómico). */
  renewals: number
}

export interface VigenciaOptions {
  atomic: boolean
  sample?: number
  seed?: number
  maxExamples?: number
  /**
   * `false` = NO negar la partición (lo que la pasada haría sin la opción A: no renueva la portadora, no rehace el deny
   * condicional y aplica todo lo demás). Solo para DEMOSTRAR que la negativa hace falta: con `false` el estado final
   * concede en el horizonte. Por defecto `true` (el paquete).
   */
  refuse?: boolean
}

interface VigenciaContext {
  views: RelationOrderView[]
  n: number
  granted: Uint32Array
  denied: Uint32Array
  index: Map<string, number>
  order: OrderFn
  atomic: boolean
  refuse: boolean
  instants: number[]
  expiry: { expired: Date; live: Date; other: Date; shorter: Date }
  now: Date
  denyBits: number
}

function vigenciaContext(name: UniverseName, order: OrderFn, opts: VigenciaOptions): VigenciaContext {
  const views = universe(name)
  const { granted, denied } = oracle(views)
  const now = new Date('2026-10-16T12:00:00.000Z')
  const H = 3_600_000
  const expiry = {
    expired: new Date(now.getTime() - H),
    live: new Date(now.getTime() + H),
    other: new Date(now.getTime() + 2 * H),
    shorter: new Date(now.getTime() + H / 2),
  }
  return {
    views,
    n: views.length,
    granted,
    denied,
    index: new Map(views.map((v, i) => [`${v.deny}|${v.object}|${v.user}`, i])),
    order,
    atomic: opts.atomic,
    refuse: opts.refuse ?? true,
    // Los instantes del horizonte: `now` y cada caducidad viva (en ella, la tupla ya no está: `isActiveExpiry` es estricta).
    instants: [now.getTime(), expiry.shorter.getTime(), expiry.live.getTime()],
    expiry,
    now,
    denyBits: views.reduce((acc, v, i) => (v.deny ? acc | (1 << i) : acc), 0),
  }
}

function emptyVigencia(name: UniverseName, ctx: VigenciaContext, mode: 'exhaustive' | 'sample'): VigenciaResult {
  return {
    universe: name,
    tuples: ctx.n,
    mode,
    pairs: 0,
    residuePairs: 0,
    unsafe: 0,
    inherent: 0,
    unsafeWithoutResidue: 0,
    malformed: 0,
    ms: 0,
    examples: [],
    atomic: ctx.atomic,
    renewalUnsafe: 0,
    denyConditional: 0,
    refused: 0,
    withExpired: 0,
    renewals: 0,
  }
}

/**
 * UNA combinación (estado por tupla, `prune`): deriva el plan como `planPartition`, lo recorre y suma en `result`.
 * Devuelve el primer paso que concede (`bad`), si el estado FINAL concede en el horizonte, si se NEGÓ y el orden.
 */
function vigenciaCombination(
  ctx: VigenciaContext,
  states: readonly number[],
  prune: boolean,
  result: VigenciaResult,
  maxExamples: number
): { bad: number | null; finalBad: boolean; refused: boolean; steps: string[] } {
  const { views, n, granted, denied, index, instants, expiry, now, denyBits } = ctx
  const sourceMs = (source: string) => (source === 'other' ? expiry.other : source === 'shorter' ? expiry.shorter : expiry.live).getTime()
  const stateOf = (v: RelationOrderView) => VIG_STATES[states[index.get(`${v.deny}|${v.object}|${v.user}`)!]]
  let initial = 0
  let source = 0
  let extraLive = 0
  let anyExpired = false
  const writes: RelationOrderView[] = []
  const deletes: RelationOrderView[] = []
  const renewals: RelationOrderView[] = []
  const context: RelationOrderView[] = []
  const lost: RelationOrderView[] = []
  const destAlive = instants.map(() => 0)
  const sourceAlive = instants.map(() => 0)
  for (let i = 0; i < n; i++) {
    const { dest, source: src } = VIG_STATES[states[i]]
    const v = views[i]
    const bit = 1 << i
    if (dest === 'expired') anyExpired = true
    if (dest === 'live') {
      initial |= bit
      instants.forEach((at, k) => {
        if (expiry.live.getTime() > at) destAlive[k] |= bit
      })
    }
    if (src !== 'absent') {
      source |= bit
      instants.forEach((at, k) => {
        if (sourceMs(src) > at) sourceAlive[k] |= bit
      })
    } else if (dest === 'live') extraLive |= bit
    // El plan, por el punto de paso ÚNICO de la vigencia.
    const destExpiry = dest === 'absent' ? undefined : dest === 'expired' ? expiry.expired : expiry.live
    const counts = destExpiry !== undefined && liveInDestination({ expiresAt: destExpiry }, now)
    if (src !== 'absent') {
      const changes = !counts || destExpiry!.getTime() !== sourceMs(src)
      // Cierre 4 · 🟡 C3-2: un deny del destino CON caducidad (aquí, todo deny del destino) que el origen tiene y que
      // cambia, en un destino sin `atomicRenewal`, no se puede rehacer: `deny-conditional`, decidido en el PLAN.
      if (v.deny && dest !== 'absent' && changes && !ctx.atomic) lost.push(v)
      else if (!counts) writes.push(v)
      else if (changes) renewals.push(v)
    } else if (prune && dest !== 'absent') {
      if (counts) deletes.push(v)
    }
    if (src !== 'absent' || counts) context.push(v)
  }
  if (anyExpired) result.withExpired++
  result.denyConditional += lost.length
  // El plan (`planPartition`): sin `atomicRenewal`, la renovación de una membresía PORTADORA no se ejecuta.
  let executable = renewals
  const held: RelationOrderView[] = []
  if (!ctx.atomic) {
    const carriers = denyCarrierGroups(context)
    executable = []
    for (const v of renewals) {
      if (!v.deny && v.object.startsWith('group:') && carriers.has(v.object)) held.push(v)
      else executable.push(v)
    }
    result.renewalUnsafe += held.length
  }
  result.pairs++
  // **Cierre 5 de D2 (opción A)**: con ≥ 1 `renewal-unsafe` o `deny-conditional` la PARTICIÓN se niega: cero escrituras y
  // cero borrados, el estado es el inicial en todo instante. Es la única exclusión.
  if (ctx.refuse && held.length + lost.length > 0) {
    result.refused++
    return { bad: null, finalBad: false, refused: true, steps: [] }
  }
  // Sin negar (solo `refuse: false`): la portadora conserva su caducidad vieja y el deny condicional no se rehace.
  const lostAbsent = lost.filter((v) => stateOf(v).dest !== 'live').reduce((acc, v) => acc | (1 << index.get(`${v.deny}|${v.object}|${v.user}`)!), 0)
  const orderContext = context.filter((v) => !(lost.includes(v) && stateOf(v).dest !== 'live'))
  const plan = ctx.order({ writes, deletes, renewals: executable, shortening: executable.filter((v) => stateOf(v).source === 'shorter'), context: orderContext })
  if (plan.residue.length > 0) result.residuePairs++
  const intendedMask = prune ? source : source | extraLive
  const intendedAt = instants.map((_, k) => (source & sourceAlive[k]) | (prune ? 0 : extraLive & destAlive[k]))
  const initialAt = instants.map((_, k) => initial & destAlive[k])
  const bound = instants.map((_, k) => granted[initialAt[k]] | granted[intendedAt[k]])
  const both = instants.map((_, k) => denied[initialAt[k]] & denied[intendedAt[k]])
  // Vivas en t si la pasada las TOCÓ (escribió o renovó): la caducidad del origen; un deny escrito es permanente.
  const touchedAlive = instants.map((_, k) => sourceAlive[k] | denyBits)
  let mask = initial
  let touched = 0
  const at = (k: number) => (mask & touched & touchedAlive[k]) | (mask & ~touched & destAlive[k])
  let bad: number | null = null
  const probe = (step: number) => {
    if (bad !== null) return
    for (let k = 0; k < instants.length; k++) {
      const g = granted[at(k)]
      if ((g & ~bound[k]) !== 0 || (g & both[k]) !== 0) {
        bad = step
        return
      }
    }
  }
  probe(0)
  plan.steps.forEach((step, k) => {
    const i = index.get(`${step.item.deny}|${step.item.object}|${step.item.user}`)!
    if (step.op === 'write') {
      mask |= 1 << i
      touched |= 1 << i
    } else if (step.op === 'delete') mask &= ~(1 << i)
    else {
      result.renewals++
      if (!ctx.atomic && !step.item.deny) {
        mask &= ~(1 << i) // el hueco entre los dos `Write`
        probe(k + 0.5)
      }
      mask |= 1 << i
      touched |= 1 << i
    }
    probe(k + 1)
  })
  if (mask !== (intendedMask & ~lostAbsent) || plan.steps.length !== writes.length + deletes.length + executable.length) result.malformed++
  // El estado FINAL en el horizonte: NADA que el origen no conceda en t (ni a un denegado en los dos). Sin excepción
  // (cierre 5: la `preexisting` del cierre 4 se fue — una partición que no se niega migra ENTERA).
  let finalBad = false
  for (let k = 0; k < instants.length; k++) {
    const g = granted[at(k)]
    if ((g & ~granted[intendedAt[k]]) !== 0 || (g & both[k]) !== 0) finalBad = true
  }
  const steps = plan.steps.map((s) => (s.op === 'write' ? '+' : s.op === 'delete' ? '-' : '~') + show(s.item))
  if (bad === null && !finalBad) return { bad, finalBad, refused: false, steps }
  result.unsafe++
  const inherent = bad !== null && !finalBad && !admissible(initial, intendedMask, n, granted, granted[initial] | granted[intendedMask], denied[initial] & denied[intendedMask])
  if (inherent) result.inherent++
  const without = finalBad || plan.residue.length === 0
  if (without) result.unsafeWithoutResidue++
  if (result.examples.length < maxExamples && (without || result.examples.length === 0)) {
    const label = (i: number) => `${show(views[i])}:${VIG_STATES[states[i]].dest}/${VIG_STATES[states[i]].source}`
    result.examples.push(
      `${prune ? '--prune' : 'sin --prune'} · ${ctx.atomic ? 'atómico' : 'dos Write'} · estados [${views
        .map((_, i) => i)
        .filter((i) => states[i] !== 0)
        .map(label)
        .join(' ')}] · orden [${steps.join(' ')}] · concede tras ${bad ?? 'final'}${finalBad ? ' (estado FINAL en el horizonte)' : ''} · residuo [${plan.residue.map(show).join(' ')}]`
    )
  }
  return { bad, finalBad, refused: false, steps }
}

/**
 * **La fuerza bruta con VIGENCIA y HORIZONTE** (cierre 3 de D2 · 🟡 C2-2; cierre 4 · 🟡 horizonte; cierre 5 · opción A).
 * Cada tupla del universo está en uno de los ocho estados de arriba; el plan se deriva como lo deriva `planPartition`,
 * con sus puntos de paso ÚNICOS (`liveInDestination` para la vigencia, `denyCarrierGroups` para la portadora):
 *
 *  - la del destino cuenta sii está viva en `now` —una vencida es ausente: su reescritura es ESCRITURA y no entra en el
 *    contexto—; misma clave y otra caducidad es RENOVACIÓN; sin el origen, con `--prune`, se BORRA (la vencida, antes y
 *    fuera del orden);
 *  - `atomic` (`database`): una renovación es una escritura; un deny se (re)escribe PERMANENTE;
 *  - no atómica (`openfga`): una renovación de membresía PORTADORA (`renewal-unsafe`) o un deny del destino CON caducidad
 *    que cambia (`deny-conditional`) NIEGA LA PARTICIÓN (cero escrituras: el estado es el inicial en todo instante, la
 *    ÚNICA exclusión); si no, las renovaciones son DOS pasos con su hueco comprobado.
 *
 * **El oráculo mira la vigencia REAL en cada instante del HORIZONTE** —`now`, `now + 30 min` y `now + 1 h` (después de
 * `+2 h` no queda nada vivo)— y los objetos `group:` (cierre 5, D4-2): la presencia de cada tupla en un prefijo se cruza
 * con SU caducidad (la del destino si la pasada no la ha tocado; la del origen si la escribió o la renovó; ∞ para un deny
 * que escribió). Propiedad (cierre 5): en una partición que NO se niega, **ningún prefijo, en ningún instante t del
 * horizonte, concede lo que ni el inicial(t) ni el origen(t) conceden** (ni a un denegado en los dos), salvo con residuo
 * de ORDEN declarado (un ciclo); y **el estado FINAL, en ningún t, concede lo que el origen niega**, sin excepción. El
 * estado alcanzado tiene que ser el final del plan (si no, `malformed`).
 */
export function bruteForceVigencia(name: UniverseName, order: OrderFn, opts: VigenciaOptions): VigenciaResult {
  const started = Date.now()
  const ctx = vigenciaContext(name, order, opts)
  const result = emptyVigencia(name, ctx, opts.sample ? 'sample' : 'exhaustive')
  let seed = opts.seed ?? 20261016
  const random = () => {
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  const S = VIG_STATES.length
  const total = opts.sample ?? S ** ctx.n
  const states = new Array<number>(ctx.n)
  for (const prune of [true, false]) {
    for (let t = 0; t < total; t++) {
      if (opts.sample) for (let i = 0; i < ctx.n; i++) states[i] = Math.floor(random() * S)
      else for (let i = 0, rest = t; i < ctx.n; i++, rest = Math.floor(rest / S)) states[i] = rest % S
      vigenciaCombination(ctx, states, prune, result, opts.maxExamples ?? 3)
    }
  }
  result.ms = Date.now() - started
  return result
}

/**
 * **Una combinación CONCRETA con vigencia** (cierre 5 de D2; hueco de infraestructura del tester del panel: `walkPair` no
 * tiene vigencia): `states` = `'<tupla>:<destino>/<origen>'` por tupla del universo con nombre corto (`a@u1:absent/same`,
 * `¬x@c#member:live/same`; destino `absent|expired|live`, origen `absent|same|other|shorter`); las no nombradas,
 * `absent/absent`. Devuelve el primer paso que concede (`bad`, `null` si ninguno), si el estado FINAL concede en el
 * horizonte, si la partición se NEGÓ y el orden. Para fijar contraejemplos LITERALES (mutantes que la muestra no ve).
 */
export function walkVigencia(
  name: UniverseName,
  order: OrderFn,
  states: string[],
  opts: { prune: boolean; atomic: boolean; refuse?: boolean }
): { bad: number | null; finalBad: boolean; refused: boolean; steps: string[] } {
  const ctx = vigenciaContext(name, order, { atomic: opts.atomic, refuse: opts.refuse })
  const vector = new Array<number>(ctx.n).fill(0)
  for (const entry of states) {
    const at = entry.lastIndexOf(':')
    const short = entry.slice(0, at)
    const [dest, source] = entry.slice(at + 1).split('/')
    const i = ctx.views.findIndex((v) => show(v) === short)
    if (i < 0) throw new Error(`'${short}' no está en el universo ${name}`)
    const s = VIG_STATES.findIndex((x) => x.dest === dest && x.source === source)
    if (s < 0) throw new Error(`estado desconocido '${dest}/${source}'`)
    vector[i] = s
  }
  return vigenciaCombination(ctx, vector, opts.prune, emptyVigencia(name, ctx, 'exhaustive'), 0)
}
