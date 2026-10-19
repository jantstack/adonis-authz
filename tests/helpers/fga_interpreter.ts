/**
 * **Intérprete del modelo FGA en proceso** (lote «antes de RC», 6b, opción E del juez; diseño del tester, punto 1).
 *
 * Herramienta de TEST, no de producción: vive en `tests/helpers/`, no se publica y no añade dependencias. Evalúa
 * `Check` sobre el JSON de modelo que genera `openFgaFactsModel` (y el modelo de relaciones fusionado de
 * `defineRelationsConfig`) contra tuplas en memoria. Sirve de ORÁCULO donde el servidor no puede serlo:
 *
 * - **modo determinista**: un solo estado del store (equivalencias, coste por profundidad);
 * - **modo «lector rasgado»** (posibilidad): cada LECTURA de un `(objeto, relación)` puede resolverse contra
 *   cualquiera de varios estados del store (antes/después de una escritura, o los prefijos de una operación de
 *   varios `Write`), de forma independiente por APARICIÓN. Devuelve el conjunto de veredictos posibles ⊆ {T, F, E}.
 *   Es una SOBREAPROXIMACIÓN del servidor (ignora la correlación temporal entre lecturas secuenciales): para demostrar
 *   «nunca concede» es la dirección segura; puede dar falsas alarmas, y por eso el comprobador lleva control positivo.
 *
 * **Qué modela** (semántica de OpenFGA v1.19, medida en el diferencial `tests/fga_interpreter.spec.ts`):
 * - reescrituras `this`, `computedUserset`, `tupleToUserset`, `union`, `intersection`, `difference` (`but not`);
 * - `this` con sujeto exacto, comodín `<tipo>:*` (solo para sujetos objeto del mismo tipo) y userset
 *   `<tipo>:<id>#<rel>` (se despacha; nidos de `group#member`);
 * - las tuplas se FILTRAN por las restricciones de tipo del modelo (`directly_related_user_types`, con comodín,
 *   relación y nombre de condición), como hace el servidor al leer;
 * - condiciones de la forma `<param> <op> <param>` sobre `TYPE_NAME_TIMESTAMP` (la `not_expired` del paquete:
 *   `current_time < valid_until`), comparadas en NANOSEGUNDOS con BigInt (M-b de `loteRC-F0-mediciones.md`): fracción de
 *   cualquier longitud truncada a 9, `.` o `,`, `Z` o `±hh:mm` con `hh` ≤ 24. El contexto de la TUPLA gana al de la
 *   petición en un parámetro repetido (medido en el diferencial). Parámetro ausente o ilegible ⇒ `E`;
 * - errores con la semántica de los operadores del servidor: `union` = T si algún hijo es T, si no E si alguno es E;
 *   `intersection` = F si alguno es F, si no E; `difference` = F si la base es F o la resta es T, si no E si alguna es E;
 * - ciclos: una rama que vuelve a `(objeto, relación, sujeto)` ya en el camino da F y las hermanas siguen (semántica de
 *   PUNTO FIJO: la del resolutor recursivo del servidor; `openfga_facts.spec.ts` · «el ciclo que FGA acepta»).
 *   **Divergencia declarada**: v1.19 elige resolutor por relación con un planificador adaptativo (`recursiveTTU` o el
 *   clásico por caminos, `internal/graph/check.go`), y el clásico marca la rama `CycleDetected` y `exclusion` la
 *   convierte en F venga por la base o por la resta. Con ciclos el servidor puede ser MÁS estricto que el intérprete
 *   (medido: c3u en un ciclo ⇒ servidor F, intérprete T), nunca más permisivo; el diferencial lo acepta solo en esa
 *   dirección. El paquete no escribe ciclos (anti-ciclos en el paquete), así que está fuera del contrato.
 *
 * **Qué NO modela** (declarado):
 * - **`--resolve-node-limit`**: el servidor da `resolution_too_complex` (400 ⇒ 503 en el paquete) pasados ~22–24 saltos
 *   según la forma y la RESPUESTA (M-c; `FACTS_MAX_RESOLVE_DEPTH` = 22). El intérprete resuelve a cualquier
 *   profundidad (hasta `maxDepth`, default 512, solo para no reventar la pila). El diferencial fija la divergencia:
 *   pasado el borde el servidor da error y el intérprete un booleano, jamás un booleano distinto;
 * - el cortocircuito y el paralelismo del servidor: aquí se evalúan TODOS los hijos (el contador de lecturas es una
 *   cota superior determinista, no la cuenta del servidor), y sin memoizar dentro del `Check` (el servidor tampoco);
 * - `ListObjects`/`ListUsers`, tuplas contextuales, consistencia, `intersection`/`difference` dentro de usersets de
 *   tipos distintos de los que generan los dos generadores del paquete (funcionan, pero no se han contrastado);
 * - condiciones con otras expresiones o tipos de parámetro (se rechazan al compilar el modelo, no se adivinan);
 * - la validación de `Write` (tamaño, tipos, duplicados en el mismo `Write`): `TupleStore` solo replica «no escribir
 *   una tupla que ya existe / no borrar una que no existe» (el comportamiento por defecto del servidor).
 */

/* ── Tuplas y store en memoria ─────────────────────────────────────────── */

/** Una tupla con la forma del API (y de `FactsTuple`), con la condición opcional del SDK. */
export interface FgaTuple {
  user: string
  relation: string
  object: string
  condition?: { name: string; context?: Record<string, unknown> }
}

/** Una tupla ya descompuesta para evaluar (se cachea por su texto canónico). */
interface StoredTuple {
  readonly user: string
  /** Tipo del sujeto (`user`, `group`, `scope`…). */
  readonly userType: string
  /** `<tipo>:<id>` del sujeto (sin la relación del userset). */
  readonly userObject: string
  /** Relación del userset (`member` en `group:g#member`), o `undefined` si el sujeto es un objeto. */
  readonly userRelation: string | undefined
  readonly wildcard: boolean
  readonly condName: string
  readonly context: Record<string, unknown> | undefined
  /** Firma contra las restricciones de tipo: `<tipo>[:*][#rel]|<condición>`. */
  readonly sig: string
  /** Identidad de la tupla para el servidor: `objeto#relación@sujeto` (la condición no es parte de la clave). */
  readonly id: string
  /** Texto canónico CON la condición (para comparar versiones de una lectura). */
  readonly text: string
}

const PARSED = new Map<string, StoredTuple>()

function canonicalContext(context: Record<string, unknown> | undefined): string {
  if (!context) return ''
  return JSON.stringify(Object.keys(context).sort().map((key) => [key, context[key]]))
}

function store(tuple: FgaTuple): StoredTuple {
  const condName = tuple.condition?.name ?? ''
  const context = tuple.condition?.context
  const text = `${tuple.object}#${tuple.relation}@${tuple.user}|${condName}|${canonicalContext(context)}`
  const cached = PARSED.get(text)
  if (cached) return cached
  const hash = tuple.user.indexOf('#')
  const userObject = hash === -1 ? tuple.user : tuple.user.slice(0, hash)
  const userRelation = hash === -1 ? undefined : tuple.user.slice(hash + 1)
  const colon = userObject.indexOf(':')
  if (colon <= 0) throw new Error(`Tupla mal formada (sujeto sin tipo): ${text}`)
  if (tuple.object.indexOf(':') <= 0) throw new Error(`Tupla mal formada (objeto sin tipo): ${text}`)
  const userType = userObject.slice(0, colon)
  const wildcard = userObject.slice(colon + 1) === '*'
  const parsed: StoredTuple = Object.freeze({
    user: tuple.user,
    userType,
    userObject,
    userRelation,
    wildcard,
    condName,
    context: context ? { ...context } : undefined,
    sig: `${userType}${wildcard ? ':*' : ''}${userRelation === undefined ? '' : '#' + userRelation}|${condName}`,
    id: `${tuple.object}#${tuple.relation}@${tuple.user}`,
    text,
  })
  PARSED.set(text, parsed)
  return parsed
}

/** Un `Write` del API: borrados y escrituras que el servidor aplica a la vez (todo o nada). */
export interface WriteStep {
  writes?: readonly FgaTuple[]
  deletes?: readonly FgaTuple[]
}

/** Las versiones de UNA lectura: `[lista]` en un estado; varias en el lector rasgado. */
type Versions = readonly (readonly StoredTuple[])[]

const EMPTY: readonly StoredTuple[] = Object.freeze([])
const EMPTY_VERSIONS: Versions = Object.freeze([EMPTY])

const keyOf = (object: string, relation: string) => `${object}#${relation}`

/**
 * Un store de tuplas en memoria, INMUTABLE: `apply` devuelve un store DERIVADO (copia solo las `(objeto, relación)`
 * tocadas), así que los estados antes/después/prefijos de una operación conviven sin copiar el store entero. El
 * índice es objeto ⇒ relación ⇒ `[lista]` (la lista envuelta, para que una lectura no reserve memoria).
 */
export class TupleStore {
  readonly #parent: TupleStore | undefined
  readonly #own = new Map<string, Map<string, Versions>>()
  /** El store raíz del que deriva (él mismo si no deriva de nadie). */
  readonly root: TupleStore
  /** Claves `objeto#relación` cambiadas respecto de `root`. */
  readonly changed: ReadonlySet<string>

  constructor(tuples: Iterable<FgaTuple> = [], parent?: TupleStore, changed?: ReadonlySet<string>) {
    this.#parent = parent
    this.root = parent ? parent.root : this
    this.changed = changed ?? new Set()
    if (parent) return
    const ids = new Set<string>()
    const lists = new Map<string, Map<string, StoredTuple[]>>()
    for (const tuple of tuples) {
      const parsed = store(tuple)
      if (ids.has(parsed.id)) throw new Error(`TupleStore: tupla duplicada ${parsed.id}`)
      ids.add(parsed.id)
      let byRelation = lists.get(tuple.object)
      if (!byRelation) lists.set(tuple.object, (byRelation = new Map()))
      const list = byRelation.get(tuple.relation)
      if (list) list.push(parsed)
      else byRelation.set(tuple.relation, [parsed])
    }
    for (const [object, byRelation] of lists) {
      const own = new Map<string, Versions>()
      for (const [relation, list] of byRelation) own.set(relation, [list])
      this.#own.set(object, own)
    }
  }

  /** Las tuplas de `(objeto, relación)` en este estado. */
  read(object: string, relation: string): readonly StoredTuple[] {
    return this.versions(object, relation)[0]
  }

  /** `[las tuplas de (objeto, relación)]`, sin reservar memoria. */
  versions(object: string, relation: string): Versions {
    const own = this.#own.get(object)?.get(relation)
    if (own) return own
    return this.#parent ? this.#parent.versions(object, relation) : EMPTY_VERSIONS
  }

  /** Todas las claves `objeto#relación` con alguna tupla en este estado. */
  keys(): string[] {
    const out = new Set<string>(this.#parent ? this.#parent.keys() : [])
    for (const [object, byRelation] of this.#own) {
      for (const [relation, versions] of byRelation) {
        if (versions[0].length) out.add(keyOf(object, relation))
        else out.delete(keyOf(object, relation))
      }
    }
    return [...out]
  }

  /** Todas las tuplas (forma del API), para escribirlas en un servidor. */
  tuples(): FgaTuple[] {
    const out: FgaTuple[] = []
    for (const key of this.keys()) {
      const [object, relation] = splitKey(key)
      for (const t of this.read(object, relation)) {
        const tuple: FgaTuple = { object, relation, user: t.user }
        if (t.condName) tuple.condition = { name: t.condName, ...(t.context ? { context: { ...t.context } } : {}) }
        out.push(tuple)
      }
    }
    return out
  }

  /**
   * El estado tras UN `Write` del API: borra y escribe a la vez. Como el servidor por defecto, borrar una tupla que no
   * existe o escribir una que ya existe (misma clave, con o sin condición) LANZA.
   */
  apply(step: WriteStep): TupleStore {
    const touched = new Map<string, { object: string; relation: string; list: StoredTuple[] }>()
    const list = (tuple: FgaTuple) => {
      const key = keyOf(tuple.object, tuple.relation)
      let current = touched.get(key)
      if (!current) {
        current = { object: tuple.object, relation: tuple.relation, list: [...this.read(tuple.object, tuple.relation)] }
        touched.set(key, current)
      }
      return current.list
    }
    for (const tuple of step.deletes ?? []) {
      const parsed = store(tuple)
      const current = list(tuple)
      const at = current.findIndex((t) => t.id === parsed.id)
      if (at === -1) throw new Error(`TupleStore.apply: borrar una tupla que no existe (${parsed.id})`)
      current.splice(at, 1)
    }
    for (const tuple of step.writes ?? []) {
      const parsed = store(tuple)
      const current = list(tuple)
      if (current.some((t) => t.id === parsed.id)) {
        throw new Error(`TupleStore.apply: escribir una tupla que ya existe (${parsed.id})`)
      }
      current.push(parsed)
    }
    const changed = new Set(this.changed)
    for (const key of touched.keys()) changed.add(key)
    const next = new TupleStore([], this, changed)
    for (const { object, relation, list: tuples } of touched.values()) {
      let own = next.#own.get(object)
      if (!own) next.#own.set(object, (own = new Map()))
      own.set(relation, [tuples])
    }
    return next
  }
}

function splitKey(key: string): [string, string] {
  const hash = key.indexOf('#')
  return [key.slice(0, hash), key.slice(hash + 1)]
}

/* ── Vistas de lectura: determinista y rasgada ─────────────────────────── */

/** Lo que el evaluador lee: por `(objeto, relación)`, una o varias VERSIONES de la lista de tuplas. */
export interface ReadView {
  versions(object: string, relation: string): Versions
}

/** Un solo estado: cada lectura tiene una versión. */
export function determinateView(state: TupleStore): ReadView {
  return state
}

/**
 * **El lector rasgado**: cada lectura puede ver cualquiera de los `states`. Solo las claves cuya lista difiere entre
 * estados tienen más de una versión. Si todos los estados derivan del mismo store raíz, los candidatos son las claves
 * `changed` (barato); si no, se comparan todas.
 */
export function tornView(states: readonly TupleStore[]): ReadView {
  if (states.length === 0) throw new Error('tornView: hacen falta estados')
  const sameRoot = states.every((s) => s.root === states[0].root)
  const candidates = new Set<string>()
  if (sameRoot) for (const s of states) for (const key of s.changed) candidates.add(key)
  else for (const s of states) for (const key of s.keys()) candidates.add(key)
  const torn = new Map<string, Map<string, Versions>>()
  for (const key of candidates) {
    const [object, relation] = splitKey(key)
    const seen = new Map<string, readonly StoredTuple[]>()
    for (const s of states) {
      const tuples = s.read(object, relation)
      const text = tuples.map((t) => t.text).sort().join('\n')
      if (!seen.has(text)) seen.set(text, tuples)
    }
    if (seen.size > 1) {
      let byRelation = torn.get(object)
      if (!byRelation) torn.set(object, (byRelation = new Map()))
      byRelation.set(relation, [...seen.values()])
    }
  }
  const first = states[0]
  if (torn.size === 0) return first
  return { versions: (object, relation) => torn.get(object)?.get(relation) ?? first.versions(object, relation) }
}

/* ── El modelo compilado ───────────────────────────────────────────────── */

type Rewrite =
  | { kind: 'this' }
  | { kind: 'computed'; relation: string }
  | { kind: 'ttu'; tupleset: string; relation: string }
  | { kind: 'union' | 'intersection'; children: Rewrite[] }
  | { kind: 'difference'; base: Rewrite; subtract: Rewrite }

interface Condition {
  left: string
  op: '<' | '<=' | '>' | '>='
  right: string
}

interface CompiledRelation {
  readonly name: string
  readonly rewrite: Rewrite
  /** Firmas de sujeto admitidas (`<tipo>[:*][#rel]|<condición>`), de `directly_related_user_types`. */
  readonly allowed: ReadonlySet<string>
}

export interface CompiledModel {
  /** `tipo` ⇒ `relación` ⇒ reescritura + restricciones de tipo. */
  readonly relations: ReadonlyMap<string, ReadonlyMap<string, CompiledRelation>>
  readonly conditions: ReadonlyMap<string, Condition>
}

function compileRewrite(node: any, where: string): Rewrite {
  if (node?.this) return { kind: 'this' }
  if (node?.computedUserset) return { kind: 'computed', relation: node.computedUserset.relation }
  if (node?.tupleToUserset) {
    return {
      kind: 'ttu',
      tupleset: node.tupleToUserset.tupleset.relation,
      relation: node.tupleToUserset.computedUserset.relation,
    }
  }
  if (node?.union) return { kind: 'union', children: node.union.child.map((c: any) => compileRewrite(c, where)) }
  if (node?.intersection) {
    return { kind: 'intersection', children: node.intersection.child.map((c: any) => compileRewrite(c, where)) }
  }
  if (node?.difference) {
    return {
      kind: 'difference',
      base: compileRewrite(node.difference.base, where),
      subtract: compileRewrite(node.difference.subtract, where),
    }
  }
  throw new Error(`Intérprete FGA: reescritura no modelada en ${where}: ${JSON.stringify(node)}`)
}

/** Compila el JSON del API (`schema_version` 1.1) a la forma que evalúa el intérprete. */
export function compileModel(model: any): CompiledModel {
  if (model?.schema_version !== '1.1') throw new Error(`Intérprete FGA: schema_version ${model?.schema_version} no modelada`)
  const relations = new Map<string, Map<string, CompiledRelation>>()
  for (const definition of model.type_definitions ?? []) {
    const rels = new Map<string, CompiledRelation>()
    for (const [name, node] of Object.entries(definition.relations ?? {})) {
      const allowed = new Set<string>()
      for (const r of definition.metadata?.relations?.[name]?.directly_related_user_types ?? []) {
        allowed.add(`${r.type}${r.wildcard ? ':*' : ''}${r.relation ? '#' + r.relation : ''}|${r.condition ?? ''}`)
      }
      rels.set(name, { name, rewrite: compileRewrite(node, `${definition.type}#${name}`), allowed })
    }
    relations.set(definition.type, rels)
  }
  const conditions = new Map<string, Condition>()
  for (const [name, def] of Object.entries<any>(model.conditions ?? {})) {
    const match = /^\s*([A-Za-z_]\w*)\s*(<=|>=|<|>)\s*([A-Za-z_]\w*)\s*$/.exec(def.expression ?? '')
    const params = def.parameters ?? {}
    if (!match || params[match[1]]?.type_name !== 'TYPE_NAME_TIMESTAMP' || params[match[3]]?.type_name !== 'TYPE_NAME_TIMESTAMP') {
      throw new Error(`Intérprete FGA: condición '${name}' no modelada (${def.expression})`)
    }
    conditions.set(name, { left: match[1], op: match[2] as Condition['op'], right: match[3] })
  }
  return { relations, conditions }
}

/* ── Marcas de tiempo en nanosegundos (M-b) ────────────────────────────── */

const TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?(Z|([+-])(\d{2}):(\d{2}))$/
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

function daysFromCivil(y: number, m: number, d: number): number {
  // Howard Hinnant, `days_from_civil`: días desde 1970-01-01 en el calendario gregoriano proléptico.
  const yy = m <= 2 ? y - 1 : y
  const era = Math.floor(yy / 400)
  const yoe = yy - era * 400
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
}

const NS_CACHE = new Map<string, bigint | null>()

/**
 * Una marca RFC 3339 a nanosegundos desde la época, con la gramática que ACEPTA el servidor (M-b): fracción `.`/`,`
 * de cualquier longitud TRUNCADA a 9, `Z` o `±hh:mm` con `hh` ≤ 24 (25–98 sin medir: se rechazan). `null` si no es
 * legible (el servidor la habría rechazado en el `Write`, o el `Check` da error).
 */
export function timestampNs(value: unknown): bigint | null {
  if (typeof value !== 'string') return null
  const cached = NS_CACHE.get(value)
  if (cached !== undefined) return cached
  let out: bigint | null = null
  const m = TIMESTAMP.exec(value)
  if (m) {
    const [y, mo, d, h, mi, s] = [m[1], m[2], m[3], m[4], m[5], m[6]].map(Number)
    const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0
    const dim = mo === 2 && leap ? 29 : DAYS_IN_MONTH[mo - 1]
    const oh = m[10] === undefined ? 0 : Number(m[10])
    const om = m[11] === undefined ? 0 : Number(m[11])
    if (mo >= 1 && mo <= 12 && d >= 1 && d <= dim && h <= 23 && mi <= 59 && s <= 59 && oh <= 24 && om <= 59) {
      const offset = (m[9] === '-' ? -1 : 1) * (oh * 3600 + om * 60)
      const seconds = BigInt(daysFromCivil(y, mo, d)) * 86400n + BigInt(h * 3600 + mi * 60 + s - offset)
      const fraction = BigInt(((m[7] ?? '') + '000000000').slice(0, 9))
      out = seconds * 1_000_000_000n + fraction
    }
  }
  NS_CACHE.set(value, out)
  return out
}

/* ── El evaluador ──────────────────────────────────────────────────────── */

/** Conjunto de veredictos como máscara: T = 1, F = 2, E = 4. */
const T = 1
const F = 2
const E = 4

function single(op: 'or' | 'and' | 'diff', x: number, y: number): number {
  if (op === 'or') return x === T || y === T ? T : x === E || y === E ? E : F
  if (op === 'and') return x === F || y === F ? F : x === E || y === E ? E : T
  return x === F || y === T ? F : x === E || y === E ? E : T
}

/** Tablas 8×8 sobre máscaras: el producto de las elecciones independientes de los dos operandos. */
function table(op: 'or' | 'and' | 'diff'): number[][] {
  const out: number[][] = []
  for (let a = 0; a < 8; a++) {
    out.push([])
    for (let b = 0; b < 8; b++) {
      let mask = 0
      for (const x of [T, F, E]) if (a & x) for (const y of [T, F, E]) if (b & y) mask |= single(op, x, y)
      out[a].push(mask)
    }
  }
  return out
}
const OR = table('or')
const AND = table('and')
const DIFF = table('diff')

/** Contadores de UN `Check`. */
export interface EvalStats {
  /** Lecturas: cada `this` y cada tupleset de una TTU cuentan 1 (sin memoizar, sin cortocircuito). */
  reads: number
  /** Mayor anidamiento de despachos alcanzado (informativo: NO es el `resolve-node-limit` del servidor). */
  maxDepth: number
}

export interface CheckRequest {
  user: string
  relation: string
  object: string
  context?: Record<string, unknown>
}

export interface EvalOptions {
  /** Corte de anidamiento para no reventar la pila (default 512): pasado ⇒ `E`. No modela al servidor. */
  maxDepth?: number
  stats?: EvalStats
}

class Evaluator {
  // La pila del camino (objeto, relación, sujeto) para detectar ciclos: arrays paralelos, sin claves de texto.
  readonly #objects: string[] = []
  readonly #relations: string[] = []
  readonly #users: string[] = []

  constructor(
    private readonly model: CompiledModel,
    private readonly view: ReadView,
    private readonly context: Record<string, unknown>,
    private readonly maxDepth: number,
    private readonly stats: EvalStats
  ) {}

  dispatch(user: string, relation: string, object: string): number {
    const depth = this.#objects.length
    for (let i = 0; i < depth; i++) {
      if (this.#objects[i] === object && this.#relations[i] === relation && this.#users[i] === user) return F
    }
    const types = this.model.relations.get(object.slice(0, object.indexOf(':')))
    const compiled = types?.get(relation)
    if (!types || !compiled) return E
    if (depth >= this.maxDepth) return E
    if (depth + 1 > this.stats.maxDepth) this.stats.maxDepth = depth + 1
    this.#objects.push(object)
    this.#relations.push(relation)
    this.#users.push(user)
    try {
      return this.rewrite(compiled.rewrite, types, compiled, object, user)
    } finally {
      this.#objects.pop()
      this.#relations.pop()
      this.#users.pop()
    }
  }

  rewrite(
    node: Rewrite,
    types: ReadonlyMap<string, CompiledRelation>,
    self: CompiledRelation,
    object: string,
    user: string
  ): number {
    switch (node.kind) {
      case 'this':
        return this.direct(self.allowed, self.name, object, user)
      case 'computed':
        return this.dispatch(user, node.relation, object)
      case 'ttu':
        return this.tupleToUserset(types.get(node.tupleset)?.allowed, node.tupleset, node.relation, object, user)
      case 'union': {
        let acc = F
        for (const child of node.children) acc = OR[acc][this.rewrite(child, types, self, object, user)]
        return acc
      }
      case 'intersection': {
        let acc = T
        for (const child of node.children) acc = AND[acc][this.rewrite(child, types, self, object, user)]
        return acc
      }
      case 'difference': {
        const base = this.rewrite(node.base, types, self, object, user)
        const subtract = this.rewrite(node.subtract, types, self, object, user)
        return DIFF[base][subtract]
      }
    }
  }

  direct(allowed: ReadonlySet<string>, relation: string, object: string, user: string): number {
    this.stats.reads++
    const userType = user.slice(0, user.indexOf(':'))
    const userIsObject = user.indexOf('#') === -1
    let total = 0
    for (const tuples of this.view.versions(object, relation)) {
      let acc = F
      for (const t of tuples) {
        if (!allowed.has(t.sig)) continue
        let m: number
        if (t.user === user) m = this.condition(t)
        else if (t.wildcard && userIsObject && t.userType === userType) m = this.condition(t)
        else if (t.userRelation !== undefined) m = AND[this.condition(t)][this.dispatch(user, t.userRelation, t.userObject)]
        else continue
        acc = OR[acc][m]
      }
      total |= acc
    }
    return total
  }

  tupleToUserset(
    allowed: ReadonlySet<string> | undefined,
    tupleset: string,
    relation: string,
    object: string,
    user: string
  ): number {
    this.stats.reads++
    let total = 0
    for (const tuples of this.view.versions(object, tupleset)) {
      let acc = F
      for (const t of tuples) {
        if (!allowed?.has(t.sig) || t.userRelation !== undefined || t.wildcard) continue
        // El servidor salta el objeto cuyo tipo no declara la relación computada.
        if (!this.model.relations.get(t.userType)?.has(relation)) continue
        acc = OR[acc][AND[this.condition(t)][this.dispatch(user, relation, t.userObject)]]
      }
      total |= acc
    }
    return total
  }

  condition(t: StoredTuple): number {
    if (!t.condName) return T
    const condition = this.model.conditions.get(t.condName)
    if (!condition) return E
    const value = (param: string) =>
      timestampNs(t.context && param in t.context ? t.context[param] : this.context[param])
    const left = value(condition.left)
    const right = value(condition.right)
    if (left === null || right === null) return E
    switch (condition.op) {
      case '<':
        return left < right ? T : F
      case '<=':
        return left <= right ? T : F
      case '>':
        return left > right ? T : F
      case '>=':
        return left >= right ? T : F
    }
  }
}

/** Evalúa un `Check` sobre una vista y devuelve la MÁSCARA de veredictos posibles (T = 1, F = 2, E = 4). */
export function evaluateMask(model: CompiledModel, view: ReadView, request: CheckRequest, options: EvalOptions = {}): number {
  const stats = options.stats ?? { reads: 0, maxDepth: 0 }
  return new Evaluator(model, view, request.context ?? {}, options.maxDepth ?? 512, stats).dispatch(
    request.user,
    request.relation,
    request.object
  )
}

export type Verdict = 'T' | 'F' | 'E'

const VERDICT: Record<number, Verdict> = { [T]: 'T', [F]: 'F', [E]: 'E' }

/** Las letras de una máscara, en orden T, F, E. */
export function verdicts(mask: number): Verdict[] {
  return (['T', 'F', 'E'] as const).filter((v) => mask & { T, F, E }[v])
}

/** `Check` determinista sobre UN estado: veredicto y contadores. */
export function checkTuples(
  model: CompiledModel,
  state: TupleStore,
  request: CheckRequest,
  options: Omit<EvalOptions, 'stats'> = {}
): { verdict: Verdict; reads: number; maxDepth: number } {
  const stats: EvalStats = { reads: 0, maxDepth: 0 }
  const mask = evaluateMask(model, determinateView(state), request, { ...options, stats })
  const verdict = VERDICT[mask]
  if (!verdict) throw new Error(`Intérprete FGA: una vista determinista dio la máscara ${mask}`)
  return { verdict, reads: stats.reads, maxDepth: stats.maxDepth }
}

/** Modo posibilidad: los veredictos que el lector rasgado puede producir mezclando `states` lectura a lectura. */
export function possibleVerdicts(model: CompiledModel, states: readonly TupleStore[], request: CheckRequest): Verdict[] {
  return verdicts(evaluateMask(model, tornView(states), request))
}

/* ── El comprobador: `true` imposibles ─────────────────────────────────── */

export interface ImpossibleTrue {
  request: CheckRequest
  /**
   * `prefix`: un estado INTERMEDIO confirmado (tras el `Write` k de la operación) concede — es un estado real del
   * store, no una mezcla. `torn`: solo lo da una mezcla de lecturas entre estados (el lector rasgado).
   */
  kind: 'prefix' | 'torn'
  /** Índices (1..n−1) de los prefijos que conceden, si `kind = 'prefix'`. */
  prefixes: number[]
}

/** Los estados de una operación: `before`, y el estado tras cada `Write` de `steps` (el último es «después»). */
export function operationStates(before: TupleStore, steps: readonly WriteStep[]): TupleStore[] {
  const states = [before]
  for (const step of steps) states.push(states[states.length - 1].apply(step))
  return states
}

/**
 * Dado el estado ANTES y la operación (uno o varios `Write`), devuelve los `true` que no da ni el estado de antes ni el
 * de después: los del PREFIJO (un estado intermedio real) y los del LECTOR RASGADO (mezcla de lecturas).
 */
export function impossibleTrues(
  model: CompiledModel,
  before: TupleStore,
  steps: readonly WriteStep[],
  requests: readonly CheckRequest[]
): ImpossibleTrue[] {
  const states = operationStates(before, steps)
  const after = states[states.length - 1]
  const torn = tornView(states)
  const out: ImpossibleTrue[] = []
  for (const request of requests) {
    if (evaluateMask(model, determinateView(before), request) === T) continue
    if (evaluateMask(model, determinateView(after), request) === T) continue
    const prefixes: number[] = []
    for (let k = 1; k < states.length - 1; k++) {
      if (evaluateMask(model, determinateView(states[k]), request) === T) prefixes.push(k)
    }
    if (prefixes.length) out.push({ request, kind: 'prefix', prefixes })
    else if (evaluateMask(model, torn, request) & T) out.push({ request, kind: 'torn', prefixes })
  }
  return out
}

/* ── El universo exhaustivo (T-1 del tester) ───────────────────────────── */

/** Nodos del universo: la raíz y tres scopes. */
export const UNIVERSE_NODES = ['a', 'b', 'c'] as const
export type UniverseNode = (typeof UNIVERSE_NODES)[number]
/** Padre de un nodo: `app`, otro nodo, o `null` (desgajado). */
export type UniverseParent = 'app' | UniverseNode | null
/** Hechos de `(u, P)` en un nodo: nada, grant (rol global), deny, o los dos. */
export type UniverseFact = '' | 'G' | 'D' | 'GD'

export interface UniverseCase {
  parents: Record<UniverseNode, UniverseParent>
  facts: Record<'app' | UniverseNode, UniverseFact>
  change: { node: UniverseNode; from: UniverseParent; to: UniverseParent; kind: 'moved' | 'attached' | 'detached' }
  target: 'app' | UniverseNode
}

/** Las tuplas que el universo necesita, construidas por quien llama con los helpers REALES del generador. */
export interface UniverseTuples {
  /** Marcador de raíz + proyección del catálogo (fijas en todo el universo). */
  fixed: FgaTuple[]
  edge(child: UniverseNode, parent: 'app' | UniverseNode): FgaTuple
  grant(node: 'app' | UniverseNode): FgaTuple[]
  deny(node: 'app' | UniverseNode): FgaTuple
  request(target: 'app' | UniverseNode): CheckRequest
}

const PARENT_CHOICES: readonly UniverseParent[] = ['app', null, ...UNIVERSE_NODES]
const FACT_CHOICES: readonly UniverseFact[] = ['', 'G', 'D', 'GD']

function acyclic(parents: Record<UniverseNode, UniverseParent>): boolean {
  for (const start of UNIVERSE_NODES) {
    let at: UniverseParent = parents[start]
    for (let i = 0; i <= UNIVERSE_NODES.length && at !== null && at !== 'app'; i++) {
      if (at === start) return false
      at = parents[at]
    }
    if (at !== null && at !== 'app') return false
  }
  return true
}

/** Todos los bosques de 3 nodos bajo `app` (padre ∈ {app, otro nodo, ninguno}), sin ciclos. */
export function universeForests(): Array<Record<UniverseNode, UniverseParent>> {
  const out: Array<Record<UniverseNode, UniverseParent>> = []
  for (const pa of PARENT_CHOICES) {
    for (const pb of PARENT_CHOICES) {
      for (const pc of PARENT_CHOICES) {
        const parents = { a: pa, b: pb, c: pc } as Record<UniverseNode, UniverseParent>
        if (pa === 'a' || pb === 'b' || pc === 'c') continue
        if (acyclic(parents)) out.push(parents)
      }
    }
  }
  return out
}

/** Los cambios de UNA arista válidos desde un bosque (`moved` a cada padre válido, `attached`, `detached`). */
export function universeChanges(parents: Record<UniverseNode, UniverseParent>): UniverseCase['change'][] {
  const out: UniverseCase['change'][] = []
  for (const node of UNIVERSE_NODES) {
    for (const to of PARENT_CHOICES) {
      if (to === node || to === parents[node]) continue
      if (!acyclic({ ...parents, [node]: to })) continue
      const from = parents[node]
      out.push({ node, from, to, kind: from === null ? 'attached' : to === null ? 'detached' : 'moved' })
    }
  }
  return out
}

export function describeUniverseCase(c: UniverseCase): string {
  const p = (x: UniverseParent) => (x === null ? '-' : x)
  const forest = UNIVERSE_NODES.map((n) => `${n}<${p(c.parents[n])}`).join(' ')
  const facts = (['app', ...UNIVERSE_NODES] as const).map((n) => `${n}:${c.facts[n] || '·'}`).join(' ')
  return `[${forest}] [${facts}] ${c.change.kind} ${c.change.node} ${p(c.change.from)}→${p(c.change.to)} @${c.target}`
}

/** El estado ANTES y el `Write` del cambio, para un caso del universo. */
export function universeOperation(
  tuples: UniverseTuples,
  parents: Record<UniverseNode, UniverseParent>,
  facts: UniverseCase['facts'],
  change: UniverseCase['change']
): { before: TupleStore; step: WriteStep } {
  const list: FgaTuple[] = [...tuples.fixed]
  for (const node of UNIVERSE_NODES) {
    const parent = parents[node]
    if (parent !== null) list.push(tuples.edge(node, parent))
  }
  for (const node of ['app', ...UNIVERSE_NODES] as const) {
    if (facts[node].includes('G')) list.push(...tuples.grant(node))
    if (facts[node].includes('D')) list.push(tuples.deny(node))
  }
  const step: WriteStep = {
    deletes: change.from === null ? [] : [tuples.edge(change.node, change.from)],
    writes: change.to === null ? [] : [tuples.edge(change.node, change.to)],
  }
  return { before: new TupleStore(list), step }
}

export interface UniverseReport {
  forests: number
  factAssignments: number
  changes: number
  /** Evaluaciones del modo posibilidad (las deterministas de antes/después aparte). */
  tornEvaluations: number
  findings: UniverseCase[]
  ms: number
}

/**
 * **T-1**: todo bosque de 3 nodos × todo reparto de hechos en los 4 nodos × todo cambio de UNA arista × los 4 nodos
 * destino. Devuelve los `true` imposibles (ni antes ni después concede y el lector rasgado sí).
 */
export function exhaustiveSingleEdge(model: CompiledModel, tuples: UniverseTuples): UniverseReport {
  const started = performance.now()
  const forests = universeForests()
  const forestIndex = new Map(forests.map((p, i) => [UNIVERSE_NODES.map((n) => p[n] ?? '-').join(','), i]))
  const targets = ['app', ...UNIVERSE_NODES] as const
  const requests = targets.map((t) => tuples.request(t))
  const findings: UniverseCase[] = []
  let changes = 0
  let tornEvaluations = 0
  const assignments: Array<UniverseCase['facts']> = []
  for (const fApp of FACT_CHOICES) {
    for (const fa of FACT_CHOICES) {
      for (const fb of FACT_CHOICES) {
        for (const fc of FACT_CHOICES) assignments.push({ app: fApp, a: fa, b: fb, c: fc })
      }
    }
  }
  // El veredicto DETERMINISTA de cada (bosque, hechos, destino) se calcula una vez: el «después» de un cambio es otro
  // bosque del mismo universo con los mismos hechos.
  const stores: TupleStore[][] = forests.map((parents) =>
    assignments.map((facts) => universeOperation(tuples, parents, facts, NO_CHANGE).before)
  )
  const grants: boolean[][][] = stores.map((row) =>
    row.map((state) => requests.map((request) => evaluateMask(model, determinateView(state), request) === T))
  )
  forests.forEach((parents, f) => {
    const forestChanges = universeChanges(parents)
    changes += forestChanges.length
    for (const change of forestChanges) {
      const g = forestIndex.get(UNIVERSE_NODES.map((n) => (n === change.node ? change.to : parents[n]) ?? '-').join(','))!
      const step: WriteStep = {
        deletes: change.from === null ? [] : [tuples.edge(change.node, change.from)],
        writes: change.to === null ? [] : [tuples.edge(change.node, change.to)],
      }
      assignments.forEach((facts, a) => {
        const before = stores[f][a]
        let torn: ReadView | undefined
        for (let i = 0; i < targets.length; i++) {
          if (grants[f][a][i] || grants[g][a][i]) continue
          torn ??= tornView([before, before.apply(step)])
          tornEvaluations++
          if (evaluateMask(model, torn, requests[i]) & T) findings.push({ parents, facts, change, target: targets[i] })
        }
      })
    }
  })
  return {
    forests: forests.length,
    factAssignments: assignments.length,
    changes,
    tornEvaluations,
    findings,
    ms: performance.now() - started,
  }
}

const NO_CHANGE: UniverseCase['change'] = { node: 'a', from: null, to: null, kind: 'attached' }
