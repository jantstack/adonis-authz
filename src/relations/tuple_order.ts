/**
 * **El ORDEN de las escrituras y de los borrados de relaciones — punto de paso ÚNICO** (plan 2.5 · lote D; linaje L10
 * «el estado intermedio de una operación multi-request concede», PROMOVIDO: 3b-2f R3, 3b-6 P1, D1 🟠 1 —la purga de
 * `openfga`—, D2 🟠 1 —el reconcile— y, en el cierre 2 de D2, 🟡 N3 —escrituras y poda COMPUESTAS—). Lo usan los DOS
 * caminos que escriben o borran relaciones en varias requests: `applyPartition` del reconcile
 * (`src/relations/reconcile.ts`) y `purgeWrites` de las purgas de `openfga` (`src/drivers/openfga_relations_driver.ts`).
 *
 * **Cierre 2 de D2 · 🟡 N3 (estructural).** Hasta aquí había DOS órdenes (uno de escritura y otro de borrado) y el reconcile
 * los encadenaba: TODAS las escrituras y luego TODA la poda. Un ex-miembro componía con un allow nuevo (U ∈ g sobra,
 * `g#member viewer X` es nuevo: cortada tras la 1.ª escritura, U concedía sobre X y ni el inicial ni el final lo hacían).
 * Ahora hay UNA función, `relationTransitionOrder`, que ordena la TRANSICIÓN entera (escrituras, borrados y renovaciones)
 * y una propiedad que se DEMUESTRA por fuerza bruta (`tests/helpers/order_bruteforce.ts`, propiedad
 * `relations.order.exhaustive` de la guardia y `tests/relations_order_exhaustive.spec.ts`).
 *
 * **Cinco fases** (las cuatro de los extremos solo restringen o solo amplían; lo difícil es la de en medio):
 *
 *  1. escribir los DENIES nuevos (y rehacer los que cambian) — solo restringe;
 *  2. borrar los ALLOWS sobrantes sobre objetos que no son `group` — solo restringe;
 *  3. las MEMBRESÍAS `group:*#member` que entran y que salen, en el orden de un GRAFO DE PRECEDENCIAS (abajo); con los
 *     allows reducidos a los que están en los dos estados y TODOS los denies de los dos estados presentes, que es el
 *     contexto más restrictivo posible para el paso difícil;
 *  4. escribir los ALLOWS nuevos (y las renovaciones que no son denies) — con las membresías y los denies finales
 *     presentes, solo puede conceder lo que concede el final;
 *  5. borrar los DENIES sobrantes, los ÚLTIMOS — idem.
 *
 * **El grafo de la fase 3.** Para cada membresía que cambia (arista `sujeto → grupo`) se calcula, en el grafo UNIÓN de
 * los dos estados, qué objetos DENIEGA lo que alcanza su grupo (`D`) y qué objetos le CONCEDE de forma efectiva (`A`: los
 * allows que están en los dos estados, menos los que cortan los denies que su grupo alcanza por aristas que no cambian —
 * el «auto-corte», que solo se aplica con el predicado `cuts` de la config: sin él, ningún allow se da por cortado, lo
 * conservador). Las precedencias, entre aristas que comparten algún sujeto:
 *
 *  - **C1** (dos que entran): la que trae un deny sobre X antes que la que trae un allow sobre X;
 *  - **C2** (dos que salen): la que lleva un allow sobre X antes que la que lleva un deny sobre X (salvo que el sujeto
 *    solo alcance la primera a través de la segunda);
 *  - **C3** (una que sale y otra que entra en el MISMO camino anidado, `U ∈ h` sobra y `h ⊂ g` es nueva): la que sale
 *    antes, si el camino compuesto llevaría un allow efectivo — es el 🟡 N3 con anidamiento;
 *  - **C4** (una que entra y otra que sale y las dos traen un deny sobre X que protege un allow del sujeto): la que entra
 *    antes — el sujeto cambia de grupo denegado sin un instante sin deny.
 *
 * Se ordena por componentes fuertemente conexas (Tarjan) en orden topológico; entre las disponibles, escrituras antes que
 * borrados, las escrituras de más lejos del sujeto primero y los borrados de más cerca primero, y (objeto, sujeto): el
 * reparto NO depende del orden de enumeración del origen ni del `Read`.
 *
 * **Lo que garantiza, exactamente** (demostrado por fuerza bruta; README «Denies migrate as denies»): **si el grafo de
 * precedencias no tiene un CICLO, ningún estado intermedio concede algo que no concedían el estado inicial o el final, y
 * ningún sujeto denegado en los dos concede en ninguno.** El RESIDUO es exactamente el ciclo (`residue`): dos membresías
 * que cambian en la misma pasada cuyas exigencias se contradicen —la forma típica: el mismo sujeto entra (o sale) a la
 * vez en dos grupos y cada uno trae un deny que corta un allow que trae el otro—. Ahí NO existe en general ningún orden
 * seguro (la fuerza bruta lo mide: de los casos del ciclo que conceden, una parte no admite NINGUNA permutación del diff
 * segura), así que el orden aplica las aristas del ciclo en el orden de prioridad y lo DEVUELVE para que la pasada lo diga.
 *
 * Pura (regla 2 de pureza): no importa nada del paquete. Coste: lineal en las tuplas más los pares de membresías que
 * cambian de un MISMO sujeto, y los de cada arista anidada (`group:x#member`) con las de los sujetos que tiene debajo.
 */

/** La clase de una tupla para el orden. */
export type RelationOrderClass = 'deny' | 'membership' | 'allow'

/**
 * La vista mínima de una tupla para ordenarla, en la forma del STORE: `object` = `<tipo>:<id>`, `user` =
 * `<tipo>:<id>` (holder) o `<tipo>:<id>#<rel>` (userset); `relation` = la relación PÚBLICA (sin `denied_`), que solo hace
 * falta con el predicado `cuts`. Basta con que sea CONSISTENTE dentro de una llamada (el reconcile la compone sin
 * partición; `openfga` con la clave de partición en el id).
 */
export interface RelationOrderView {
  deny: boolean
  object: string
  user: string
  relation?: string
}

/** ¿Un deny de `deniedRelation` corta un allow de `allowedRelation` sobre un objeto de `objectType`? (D5: `d ∈ up*(a)`). */
export type RelationCuts = (objectType: string, deniedRelation: string, allowedRelation: string) => boolean

/** Un paso del orden: `write` (la tupla entra), `delete` (sale) o `renew` (está en los dos estados y se reescribe). */
export interface RelationOrderStep<T> {
  item: T
  op: 'write' | 'delete' | 'renew'
}

/** El orden de una transición y su RESIDUO: las membresías de un ciclo del grafo de precedencias (sin garantía). */
export interface RelationOrderPlan<T> {
  steps: RelationOrderStep<T>[]
  residue: T[]
}

export interface RelationTransition<T> {
  /** Las tuplas que ENTRAN (no están en el estado inicial). */
  writes?: readonly T[]
  /** Las tuplas que SALEN (no están en el estado final). */
  deletes?: readonly T[]
  /** Las que están en los dos estados y se reescriben (otra caducidad): no cambian lo que se concede EN `now`. */
  renewals?: readonly T[]
  /**
   * Cierre 4 de D2 · 🟡 horizonte: las de `renewals` que ACORTAN la caducidad (el resto la alarga o la quita). En `now` una
   * renovación no cambia nada, pero en el instante en que vence la caducidad más corta de las dos es una tupla que SALE
   * (acorta) o que ENTRA (alarga) — y un corte de la pasada que dure hasta entonces lo ve. Por eso una renovación de
   * MEMBRESÍA entra en el grafo de la fase 3 como una salida o una entrada (sin cambiar lo que hace: `op: 'renew'`), y la
   * de un allow que ACORTA va con los borrados de la fase 2.
   */
  shortening?: readonly T[]
  /** Las tuplas que EXISTEN en el estado inicial o en el final (pueden incluir las de arriba). */
  context?: readonly RelationOrderView[]
}

/** El tipo built-in que transporta usersets (`group:g#member`). */
const GROUP_PREFIX = 'group:'
const MEMBER_SUFFIX = '#member'

export function relationOrderClass(view: RelationOrderView): RelationOrderClass {
  if (view.deny) return 'deny'
  return view.object.startsWith(GROUP_PREFIX) ? 'membership' : 'allow'
}

/** `group:<id>#member` ⇒ `group:<id>`; cualquier otro sujeto ⇒ `null`. */
function usersetGroup(user: string): string | null {
  return user.startsWith(GROUP_PREFIX) && user.endsWith(MEMBER_SUFFIX) ? user.slice(0, -MEMBER_SUFFIX.length) : null
}

function viewKey(v: RelationOrderView): string {
  return `${v.deny ? 'd' : 'a'}\u0000${v.object}\u0000${v.user}\u0000${v.relation ?? ''}`
}

function objectTypeOf(object: string): string {
  const colon = object.indexOf(':')
  return colon < 0 ? object : object.slice(0, colon)
}

/**
 * Los grupos PORTADORES de deny: el `#member` de cada uno es sujeto de algún deny de `views`, más el cierre por la
 * anidación (`group:G#member@group:H#member` con G portador ⇒ H portador). Devuelve los OBJETOS (`group:<id>`). Lo usa
 * el reconcile para clasificar la renovación de una membresía PORTADORA (cierre 2 de D2 · 🟠 N1, `renewal-unsafe`).
 */
export function denyCarrierGroups(views: Iterable<RelationOrderView>): Set<string> {
  const all = [...views]
  const carriers = new Set<string>()
  for (const v of all) {
    const group = v.deny ? usersetGroup(v.user) : null
    if (group !== null) carriers.add(group)
  }
  const nested = all.filter((v) => relationOrderClass(v) === 'membership' && usersetGroup(v.user) !== null)
  for (let grew = true; grew; ) {
    grew = false
    for (const v of nested) {
      const inner = usersetGroup(v.user)!
      if (carriers.has(v.object) && !carriers.has(inner)) {
        carriers.add(inner)
        grew = true
      }
    }
  }
  return carriers
}

/**
 * **Los denies que TRANSPORTA un grupo** (cierre 6 de D2 · ⚪ D5-3, para la letra): los `deny` cuyo sujeto es el `#member`
 * del grupo o de un grupo que lo contiene, transitivamente (`group:G#member@group:H#member`: los miembros de H heredan los
 * denies de G). Devuelve las VISTAS de esos denies, en el orden de entrada. Misma regla que `denyCarrierGroups`, al revés.
 */
export function carriedDenies(views: Iterable<RelationOrderView>, group: string): RelationOrderView[] {
  const all = [...views]
  const reach = new Set([group])
  const nested = all.filter((v) => relationOrderClass(v) === 'membership' && usersetGroup(v.user) !== null)
  for (let grew = true; grew; ) {
    grew = false
    for (const v of nested) {
      if (reach.has(usersetGroup(v.user)!) && !reach.has(v.object)) {
        reach.add(v.object)
        grew = true
      }
    }
  }
  return all.filter((v) => v.deny && reach.has(usersetGroup(v.user) ?? ''))
}

/** Un grafo de membresías (aristas `sujeto → grupo`): hacia arriba (`up`), hacia abajo (`below`) y altura. */
class MembershipGraph {
  readonly #parents = new Map<string, Set<string>>()
  readonly #into = new Map<string, RelationOrderView[]>()
  readonly #childGroups = new Map<string, Set<string>>()
  readonly #up = new Map<string, Set<string>>()
  readonly #below = new Map<string, Set<string>>()
  readonly #height = new Map<string, number>()

  constructor(edges: Iterable<RelationOrderView>) {
    for (const e of edges) {
      let list = this.#into.get(e.object)
      if (!list) this.#into.set(e.object, (list = []))
      list.push(e)
      const child = usersetGroup(e.user)
      if (child === null) continue
      let parents = this.#parents.get(child)
      if (!parents) this.#parents.set(child, (parents = new Set()))
      parents.add(e.object)
      let children = this.#childGroups.get(e.object)
      if (!children) this.#childGroups.set(e.object, (children = new Set()))
      children.add(child)
    }
  }

  /** Los grupos que alcanza `group` (él incluido). */
  up(group: string): Set<string> {
    let seen = this.#up.get(group)
    if (seen) return seen
    seen = new Set([group])
    const stack = [group]
    while (stack.length > 0) {
      for (const parent of this.#parents.get(stack.pop()!) ?? []) {
        if (!seen.has(parent)) {
          seen.add(parent)
          stack.push(parent)
        }
      }
    }
    this.#up.set(group, seen)
    return seen
  }

  /** Los sujetos (holders y usersets) que alcanzan al sujeto `user` (él incluido), opcionalmente SIN la arista `without`. */
  below(user: string, without?: string): Set<string> {
    if (usersetGroup(user) === null) return new Set([user])
    if (without === undefined) {
      const memo = this.#below.get(user)
      if (memo) return memo
    }
    const out = new Set([user])
    const stack = [user]
    while (stack.length > 0) {
      const group = usersetGroup(stack.pop()!)
      if (group === null) continue
      for (const e of this.#into.get(group) ?? []) {
        if (without !== undefined && viewKey(e) === without) continue
        if (!out.has(e.user)) {
          out.add(e.user)
          stack.push(e.user)
        }
      }
    }
    if (without === undefined) this.#below.set(user, out)
    return out
  }

  /** Distancia de un sujeto a los holders: 0 un holder; un userset, 1 + la de su grupo hijo más profundo. */
  depth(user: string): number {
    const group = usersetGroup(user)
    return group === null ? 0 : this.#groupHeight(group, new Set())
  }

  #groupHeight(group: string, path: Set<string>): number {
    const memo = this.#height.get(group)
    if (memo !== undefined) return memo
    if (path.has(group)) return 1
    path.add(group)
    let height = 1
    for (const child of this.#childGroups.get(group) ?? []) height = Math.max(height, 1 + this.#groupHeight(child, path))
    path.delete(group)
    this.#height.set(group, height)
    return height
  }
}

/** Índice de tuplas (allows o denies) por sujeto: `sujeto → objeto → relaciones`. */
function bySubject(views: Iterable<RelationOrderView>): Map<string, Map<string, Set<string>>> {
  const out = new Map<string, Map<string, Set<string>>>()
  for (const v of views) {
    let objects = out.get(v.user)
    if (!objects) out.set(v.user, (objects = new Map()))
    let relations = objects.get(v.object)
    if (!relations) objects.set(v.object, (relations = new Set()))
    relations.add(v.relation ?? '')
  }
  return out
}

/** Lo que alcanza un grupo por un grafo: `objeto → relaciones` (los `#member` de los grupos de `up`). */
function reach(graph: MembershipGraph, index: Map<string, Map<string, Set<string>>>, group: string): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>()
  for (const g of graph.up(group)) {
    for (const [object, relations] of index.get(g + MEMBER_SUFFIX) ?? []) {
      let set = out.get(object)
      if (!set) out.set(object, (set = new Set()))
      for (const r of relations) set.add(r)
    }
  }
  return out
}

interface MembershipOp<T> {
  item: T
  view: RelationOrderView
  op: 'write' | 'delete'
  /** Lo que el paso HACE: `renew` para una renovación (que en el grafo cuenta como la entrada o la salida que es en el horizonte). */
  emit: 'write' | 'delete' | 'renew'
  key: string
  head: string
  tail: string | null
  /** Objetos que deniega lo que alcanza el grupo (grafo unión). */
  denies: Set<string>
  /** Objetos que concede de forma efectiva (allows de los dos estados, menos el auto-corte). */
  allows: Set<string>
  depth: number
}

/**
 * **El orden de una TRANSICIÓN** (cierre 2 de D2 · 🟡 N3): ver el docblock del módulo. `residue` = las membresías de los
 * ciclos del grafo de precedencias (sin garantía); vacío ⇒ ningún estado intermedio concede fuera de inicial ∪ final.
 */
export function relationTransitionOrder<T>(
  transition: RelationTransition<T>,
  view: (item: T) => RelationOrderView,
  options: { cuts?: RelationCuts } = {}
): RelationOrderPlan<T> {
  const writes = (transition.writes ?? []).map((item) => ({ item, view: view(item) }))
  const deletes = (transition.deletes ?? []).map((item) => ({ item, view: view(item) }))
  const renewals = (transition.renewals ?? []).map((item) => ({ item, view: view(item) }))
  const shortening = new Set(transition.shortening ?? [])
  const renewedMemberships = renewals.filter((r) => relationOrderClass(r.view) === 'membership')
  const changing = new Set([...writes, ...deletes, ...renewedMemberships].map((w) => viewKey(w.view)))
  const everything = new Map<string, RelationOrderView>()
  for (const v of [...(transition.context ?? []), ...writes.map((w) => w.view), ...deletes.map((d) => d.view), ...renewals.map((r) => r.view)]) {
    everything.set(viewKey(v), v)
  }
  const edges: RelationOrderView[] = []
  const keptAllows: RelationOrderView[] = []
  const denies: RelationOrderView[] = []
  for (const [key, v] of everything) {
    const cls = relationOrderClass(v)
    if (cls === 'deny') denies.push(v)
    else if (cls === 'membership') edges.push(v)
    else if (!changing.has(key)) keptAllows.push(v)
  }
  const renewedAs = (r: { item: T }) => (shortening.has(r.item) ? 'delete' : 'write') as 'write' | 'delete'
  const membership = planMemberships(
    [
      ...writes.filter((w) => relationOrderClass(w.view) === 'membership').map((w) => ({ ...w, emit: 'write' as const })),
      ...renewedMemberships.filter((r) => renewedAs(r) === 'write').map((r) => ({ ...r, emit: 'renew' as const })),
    ],
    [
      ...deletes.filter((d) => relationOrderClass(d.view) === 'membership').map((d) => ({ ...d, emit: 'delete' as const })),
      ...renewedMemberships.filter((r) => renewedAs(r) === 'delete').map((r) => ({ ...r, emit: 'renew' as const })),
    ],
    { edges, keptAllows, denies, changing, cuts: options.cuts }
  )
  const steps: RelationOrderStep<T>[] = []
  // 1. denies nuevos (y los que se rehacen: un deny no caduca, D3) — solo restringen.
  for (const w of writes) if (w.view.deny) steps.push({ item: w.item, op: 'write' })
  for (const r of renewals) if (r.view.deny) steps.push({ item: r.item, op: 'renew' })
  // 2. allows sobrantes sobre objetos que no son `group` — solo restringen; y (cierre 4) las renovaciones de allows que
  //    ACORTAN: en su caducidad nueva salen.
  for (const d of deletes) if (relationOrderClass(d.view) === 'allow') steps.push({ item: d.item, op: 'delete' })
  for (const r of renewals) if (relationOrderClass(r.view) === 'allow' && renewedAs(r) === 'delete') steps.push({ item: r.item, op: 'renew' })
  // 3. membresías (y, cierre 4, sus renovaciones como la entrada o la salida que son en el horizonte), por el grafo.
  steps.push(...membership.steps)
  // 4. allows nuevos y las renovaciones de allows que ALARGAN (en `now` no cambian lo que se concede).
  for (const w of writes) if (relationOrderClass(w.view) === 'allow') steps.push({ item: w.item, op: 'write' })
  for (const r of renewals) if (relationOrderClass(r.view) === 'allow' && renewedAs(r) === 'write') steps.push({ item: r.item, op: 'renew' })
  // 5. denies sobrantes, los ÚLTIMOS.
  for (const d of deletes) if (d.view.deny) steps.push({ item: d.item, op: 'delete' })
  return { steps, residue: membership.residue }
}

function planMemberships<T>(
  writes: Array<{ item: T; view: RelationOrderView; emit: 'write' | 'renew' }>,
  deletes: Array<{ item: T; view: RelationOrderView; emit: 'delete' | 'renew' }>,
  context: { edges: RelationOrderView[]; keptAllows: RelationOrderView[]; denies: RelationOrderView[]; changing: Set<string>; cuts?: RelationCuts }
): { steps: RelationOrderStep<T>[]; residue: T[] } {
  if (writes.length + deletes.length === 0) return { steps: [], residue: [] }
  const union = new MembershipGraph(context.edges)
  const kept = new MembershipGraph(context.edges.filter((e) => !context.changing.has(viewKey(e))))
  const allowIndex = bySubject(context.keptAllows)
  const denyIndex = bySubject(context.denies)
  const cuts = context.cuts
  const deniedBy = new Map<string, Set<string>>()
  /** Objetos denegados por lo que alcanza `group` en el grafo unión. */
  const deniedObjects = (group: string): Set<string> => {
    let out = deniedBy.get(group)
    if (!out) deniedBy.set(group, (out = new Set(reach(union, denyIndex, group).keys())))
    return out
  }
  /**
   * Objetos que concede de forma EFECTIVA lo que alcanza `group` (grafo unión, allows de los dos estados), menos los que
   * corta TODO lo que deniegan, por aristas que NO cambian, los grupos `cutters` (el auto-corte). Sin `cuts`, nada se corta.
   */
  const effective = (group: string, cutters: string[]): Set<string> => {
    const allowed = reach(union, allowIndex, group)
    if (!cuts) return new Set(allowed.keys())
    const keptDenies = new Map<string, Set<string>>()
    for (const cutter of cutters) {
      for (const [object, relations] of reach(kept, denyIndex, cutter)) {
        let set = keptDenies.get(object)
        if (!set) keptDenies.set(object, (set = new Set()))
        for (const r of relations) set.add(r)
      }
    }
    const out = new Set<string>()
    for (const [object, relations] of allowed) {
      const denied = keptDenies.get(object)
      const type = objectTypeOf(object)
      const cut = denied !== undefined && [...relations].every((a) => [...denied].some((d) => cuts(type, d, a)))
      if (!cut) out.add(object)
    }
    return out
  }
  const effectiveMemo = new Map<string, Set<string>>()
  const ops: MembershipOp<T>[] = []
  for (const [list, op] of [
    [writes, 'write'],
    [deletes, 'delete'],
  ] as const) {
    for (const { item, view, emit } of list) {
      let allows = effectiveMemo.get(view.object)
      if (!allows) effectiveMemo.set(view.object, (allows = effective(view.object, [view.object])))
      ops.push({
        item,
        view,
        op,
        emit,
        key: viewKey(view),
        head: view.object,
        tail: usersetGroup(view.user),
        denies: deniedObjects(view.object),
        allows,
        depth: union.depth(view.user),
      })
    }
  }
  const subjectAllows = new Map<string, Set<string>>()
  /** Los objetos con algún allow (de los dos estados) que alcanza el sujeto, directo o por cualquier grupo (grafo unión). */
  const allowsOfSubject = (subject: string): Set<string> => {
    let out = subjectAllows.get(subject)
    if (out) return out
    out = new Set([...(allowIndex.get(subject)?.keys() ?? [])])
    for (const e of context.edges) {
      if (e.user !== subject) continue
      for (const object of reach(union, allowIndex, e.object).keys()) out.add(object)
    }
    subjectAllows.set(subject, out)
    return out
  }
  const intersects = (a: Set<string>, b: Set<string>): boolean => {
    const [small, large] = a.size <= b.size ? [a, b] : [b, a]
    for (const x of small) if (large.has(x)) return true
    return false
  }
  /**
   * C3: ¿`d` (sale) y `w` (entra) componen un camino NUEVO? Cierre 5 de D2 (D4-2; el oráculo cuenta los objetos `group:`):
   * el camino compuesto concede SIEMPRE algo —la propia membresía del sujeto en el grupo de arriba (`check(member)`,
   * `membersOf`)—, así que ya no se exige un allow efectivo al final del camino (hasta el cierre 4 sí, y un corte entre
   * `+U∈h` y `-h⊂g` hacía a U miembro de g, cosa que ni el inicial ni el final hacían).
   */
  const composes = (d: MembershipOp<T>, w: MembershipOp<T>): boolean => {
    if (w.tail !== null && union.up(d.head).has(w.tail)) return true
    if (d.tail !== null && union.up(w.head).has(d.tail)) return true
    return false
  }
  /** ¿`a` va ANTES que `b`? (C1–C4). */
  const before = (a: MembershipOp<T>, b: MembershipOp<T>): boolean => {
    if (a.op === 'write' && b.op === 'write') {
      return [...a.denies].some((x) => b.allows.has(x)) && intersects(union.below(a.view.user), union.below(b.view.user))
    }
    if (a.op === 'delete' && b.op === 'delete') {
      return [...a.allows].some((x) => b.denies.has(x)) && intersects(union.below(a.view.user, b.key), union.below(b.view.user))
    }
    if (a.op === 'delete') return composes(a, b)
    // C4, con la exclusión de C2 (cierre 5 de D2): un sujeto que solo alcanza la que sale A TRAVÉS de la que entra (o la
    // que entra a través de la que sale) no tenía ese deny en el inicial (o no lo tiene en el final): no hay «instante sin
    // deny» que evitar. Sin la exclusión, C4 chocaba con C3 —que ahora cuenta la membresía como concesión— en ciclos
    // espurios (`+U∈h`, `-h⊂g` con el deny en g: U nunca estuvo en g).
    const belowB = union.below(b.view.user, a.key)
    const common = [...union.below(a.view.user, b.key)].filter((s) => belowB.has(s))
    if (common.length === 0) return false
    return [...a.denies].some((x) => b.denies.has(x) && common.some((s) => allowsOfSubject(s).has(x)))
  }
  // Los pares que pueden tener precedencia: los de un MISMO sujeto holder, y los de cada arista anidada con todas las
  // que tienen un sujeto por debajo de ella o un grupo en su camino.
  const succ: number[][] = ops.map(() => [])
  const link = (i: number, j: number) => {
    if (before(ops[i], ops[j])) succ[i].push(j)
  }
  const byHolder = new Map<string, number[]>()
  const nested: number[] = []
  ops.forEach((o, i) => {
    if (o.tail !== null) nested.push(i)
    else {
      let list = byHolder.get(o.view.user)
      if (!list) byHolder.set(o.view.user, (list = []))
      list.push(i)
    }
  })
  for (const list of byHolder.values()) for (const i of list) for (const j of list) if (i !== j) link(i, j)
  for (const i of nested) {
    for (let j = 0; j < ops.length; j++) {
      if (i === j || (ops[j].tail !== null && j < i)) continue
      link(i, j)
      link(j, i)
    }
  }
  const order = orderByPrecedence(ops, succ)
  return {
    steps: order.order.map((i) => ({ item: ops[i].item, op: ops[i].emit })),
    residue: order.cyclic.map((i) => ops[i].item),
  }
}

/** Prioridad entre disponibles: escrituras antes que borrados; escrituras de lejos primero, borrados de cerca; (objeto, sujeto). */
function priority<T>(a: MembershipOp<T>, b: MembershipOp<T>): number {
  if (a.op !== b.op) return a.op === 'write' ? -1 : 1
  if (a.depth !== b.depth) return a.op === 'write' ? b.depth - a.depth : a.depth - b.depth
  if (a.view.object !== b.view.object) return a.view.object < b.view.object ? -1 : 1
  if (a.view.user !== b.view.user) return a.view.user < b.view.user ? -1 : 1
  return 0
}

/**
 * Orden topológico por componentes fuertemente conexas (Tarjan, iterativo): una componente sale cuando no le queda
 * ninguna predecesora; entre las disponibles, la de mayor prioridad. Dentro de una componente con CICLO, Kahn sobre sus
 * aristas internas y, cuando se atasca, la de mayor prioridad (`cyclic` las devuelve todas: el residuo).
 */
function orderByPrecedence<T>(ops: MembershipOp<T>[], succ: number[][]): { order: number[]; cyclic: number[] } {
  const n = ops.length
  const index = new Array<number>(n).fill(-1)
  const low = new Array<number>(n).fill(0)
  const onStack = new Array<boolean>(n).fill(false)
  const component = new Array<number>(n).fill(-1)
  const stack: number[] = []
  const members: number[][] = []
  let counter = 0
  for (let root = 0; root < n; root++) {
    if (index[root] !== -1) continue
    const work: Array<{ v: number; next: number }> = [{ v: root, next: 0 }]
    index[root] = low[root] = counter++
    stack.push(root)
    onStack[root] = true
    while (work.length > 0) {
      const frame = work[work.length - 1]
      const edges = succ[frame.v]
      if (frame.next < edges.length) {
        const w = edges[frame.next++]
        if (index[w] === -1) {
          index[w] = low[w] = counter++
          stack.push(w)
          onStack[w] = true
          work.push({ v: w, next: 0 })
        } else if (onStack[w]) low[frame.v] = Math.min(low[frame.v], index[w])
        continue
      }
      work.pop()
      if (work.length > 0) low[work[work.length - 1].v] = Math.min(low[work[work.length - 1].v], low[frame.v])
      if (low[frame.v] === index[frame.v]) {
        const list: number[] = []
        let w: number
        do {
          w = stack.pop()!
          onStack[w] = false
          component[w] = members.length
          list.push(w)
        } while (w !== frame.v)
        members.push(list)
      }
    }
  }
  const pending = new Array<number>(members.length).fill(0)
  for (let v = 0; v < n; v++) for (const w of succ[v]) if (component[v] !== component[w]) pending[component[w]]++
  const best = members.map((list) => list.reduce((a, b) => (priority(ops[a], ops[b]) <= 0 ? a : b)))
  const ready = members.map((_, c) => c).filter((c) => pending[c] === 0)
  const order: number[] = []
  const cyclic: number[] = []
  while (ready.length > 0) {
    let pick = 0
    for (let k = 1; k < ready.length; k++) if (priority(ops[best[ready[k]]], ops[best[ready[pick]]]) < 0) pick = k
    const c = ready.splice(pick, 1)[0]
    const list = members[c]
    if (list.length === 1) order.push(list[0])
    else {
      cyclic.push(...list)
      const inside = new Set(list)
      const done = new Set<number>()
      const preds = new Map(list.map((v) => [v, 0]))
      for (const v of list) for (const w of succ[v]) if (inside.has(w)) preds.set(w, preds.get(w)! + 1)
      while (done.size < list.length) {
        const left = list.filter((v) => !done.has(v))
        const free = left.filter((v) => preds.get(v) === 0)
        const pool = free.length > 0 ? free : left
        const v = pool.reduce((a, b) => (priority(ops[a], ops[b]) <= 0 ? a : b))
        done.add(v)
        order.push(v)
        for (const w of succ[v]) if (inside.has(w) && !done.has(w)) preds.set(w, preds.get(w)! - 1)
      }
    }
    for (const v of list) for (const w of succ[v]) if (component[w] !== c && --pending[component[w]] === 0) ready.push(component[w])
  }
  return { order, cyclic }
}

/**
 * **El orden de ESCRITURA** de un conjunto que solo ENTRA (atajo de `relationTransitionOrder` sin borrados): `context` =
 * las tuplas que existen y no se escriben.
 */
export function relationWriteOrder<T>(items: readonly T[], view: (item: T) => RelationOrderView, context: readonly RelationOrderView[] = []): T[] {
  return relationTransitionOrder({ writes: items, context }, view).steps.map((s) => s.item)
}

/** **El orden de BORRADO** de un conjunto que solo SALE (las purgas de `openfga`): allows → membresías → denies. */
export function relationDeleteOrder<T>(items: readonly T[], view: (item: T) => RelationOrderView, context: readonly RelationOrderView[] = []): T[] {
  return relationTransitionOrder({ deletes: items, context }, view).steps.map((s) => s.item)
}

/*
 * Cierre 5 de D2 (decisión del dueño §2026-10-16 (10), opción A): aquí vivía `relationWithheldWrites` (cierre 4), la
 * RETENCIÓN de lo que un deny que no viaja (`renewal-unsafe`, `deny-conditional`) dejaría conceder. Se fue entera: en vez
 * de retener tupla a tupla —con su cascada, su conflicto global `carrier-conflict` y el hueco D4-1 que el auditor midió—,
 * la PARTICIÓN afectada recibe CERO escrituras y cero borrados (`src/relations/reconcile.ts`, `planPartition` ⇒
 * `refusal`), y el resto migra. Una partición negada queda exactamente como estaba, que es lo único que se puede
 * certificar sin una escritura atómica de la renovación (openfga/openfga#2151).
 */
