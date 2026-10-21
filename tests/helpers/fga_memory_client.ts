/**
 * **Doble FIEL del cliente OpenFGA en memoria + planificador cooperativo sembrado** (lote C · sublote «asentar», paso 1
 * del plan del juez, `loteC-carreras-juez.md`; diseño del tester, `loteC-carreras-tester.md` §«Cómo se modelan los
 * entrelazados»).
 *
 * Herramienta de TEST (no se publica). Un `FgaMemoryStore` es UN store compartido; cada `client(actor)` es la vista de un
 * «proceso» (una instancia del driver REAL, con su memo) sobre ese store. Fidelidad, punto por punto:
 *
 * - **(a) Conflictos con la forma del SDK** medida en R3 (`tests/fixtures/fga_errors/`): escribir una tupla que existe ⇒
 *   `real-write-duplicate`, borrar una que no existe ⇒ `real-delete-absent` (400 `write_failed_due_to_invalid_input`), y
 *   el `Write` entero se rechaza (nada se aplica, como el servidor). `onDuplicateWrites` y `onMissingDeletes` se honran
 *   POR SEPARADO (el doble de F4 metía los dos bajo «hay `conflict`»). Más de 100 tuplas en un `Write` ⇒
 *   `real-write-exceeded-entity-limit`. El 409 `Aborted` (`real-write-race-409_null`) se inyecta con `fault`.
 * - **(b) `check`/`batchCheck` por el INTÉRPRETE** (`fga_interpreter.ts`) sobre el estado del store. `ancestor` se pasea
 *   SALTO A SALTO cediendo en cada uno (`kind: 'check-hop'`): un `Check` real no es una foto, y así el doble modela el
 *   `Check` rasgado de una cadena que otro escritor mueve mientras se resuelve.
 * - **(c) Cota de profundidad del servidor como PARÁMETRO** (`depthLimits`, en saltos `parent` desde el objeto): pasada,
 *   `real-check-resolution-too-complex` (400 `authorization_model_resolution_too_complex`). El intérprete no la tiene.
 *   Para `ancestor` se emula lo MEDIDO en M2 (`loteC-asentar-fase1.md`): solo la cara VERDADERA pasada la cota lanza
 *   (26 resuelve, 27 falla siempre); la falsa resuelve. Para el resto (`other`) es determinista por saltos; el servidor
 *   tiene ahí un borde probabilístico (`can_<P>` a 23, M-c): se declara.
 * - **(d) La «caché»**: con `staleBy = k`, toda lectura (`read`, `check`, `batchCheck`) que NO pide
 *   `HIGHER_CONSISTENCY` se responde desde el estado de `k` escrituras atrás. Con HIGHER, siempre el último.
 * - **(e) Fallos por (actor, k-ésimo I/O)** (`fault`): un error ANTES de aplicar (el servidor no lo vio) o DESPUÉS de
 *   aplicar un `Write` (venció el deadline pero se confirmó: invariante 13). Patrón `cutAfter` de F4.
 * - **(f) Traza**: `(tick, actor, k, kind, tuplas EFECTIVAS, consistencia, resultado)` de cada I/O.
 *
 * **Instalación**: `installMemoryClient(driver, client)` copia los métodos sobre el cliente del SDK que el driver
 * envuelve (`guardBackendErrors` no tiene trampa `set`: la asignación cae en el objetivo), de modo que los errores del
 * doble pasan por el MISMO clasificador que en producción (`classifyFgaFailure`, la marca de escritura, el deadline).
 * Sustituir `driver.client` entero —lo que hacían los dobles anteriores— se salta esa capa.
 *
 * **Qué NO modela** (declarado): validación de tipos/relaciones del `Write` (lo hace el intérprete al leer: filtra por
 * tipo), orden de `Read` del servidor (aquí: orden de inserción), tuplas contextuales, `ListObjects`, el borde
 * probabilístico de profundidad y la latencia.
 */
import {
  checkTuples,
  compileModel,
  TupleStore,
  type CompiledModel,
  type FgaTuple,
} from './fga_interpreter.js'
import { fgaErrorFromFixture, loadFgaFixtures, type FgaFixture } from './fga_fixtures.js'

/* ── Errores con la forma medida del SDK ───────────────────────────────── */

let FIXTURES: Map<string, FgaFixture> | undefined
/** La instancia del SDK de una fixture medida (`tests/fixtures/fga_errors/<id>.json`). */
export function sdkError(id: string): Error {
  FIXTURES ??= new Map(loadFgaFixtures().map((f) => [f.id, f]))
  const fixture = FIXTURES.get(id)
  if (!fixture) throw new Error(`fga_memory_client: fixture desconocida ${id}`)
  return fgaErrorFromFixture(fixture)
}

/* ── Tipos ─────────────────────────────────────────────────────────────── */

/** I/O del doble, más tres puntos de planificación del ARNÉS (`start`: antes de empezar; `tree`: entre el cambio del árbol
 * del consumidor y la notificación al driver; `sql`: antes del commit SQL de `purgeRole`, paso 4). */
export type IoKind = 'read' | 'write' | 'check' | 'check-hop' | 'batchCheck' | 'start' | 'tree' | 'sql'

export interface IoEvent {
  actor: string
  /** k-ésimo I/O de ESTE actor (1-based). */
  k: number
  kind: IoKind
  body: unknown
  consistency: string | undefined
}

export interface FaultSpec {
  error: Error
  /** `before`: el servidor no lo vio. `after` (solo `write`): aplicado y DESPUÉS el error (deadline vencido). */
  when?: 'before' | 'after'
}

export interface TraceEntry {
  tick: number
  actor: string
  k: number
  kind: IoKind
  consistency: string | undefined
  /** `write`: las tuplas EFECTIVAS (tras `Ignore`); vacías si se rechazó. */
  writes?: FgaTuple[]
  deletes?: FgaTuple[]
  /** `read`: el filtro. `check`/`check-hop`/`batchCheck`: la petición (o el objeto del salto). */
  request?: unknown
  /** `ok`, `error:<apiErrorCode|statusCode>` o el veredicto. */
  result: string
  /** Versión del store vista o producida. */
  version: number
}

export interface MemoryFgaOptions {
  /** JSON del modelo (el de `generatedModel`/`openFgaFactsModel`). */
  model: any
  initial?: Iterable<FgaTuple>
  /** Cota de profundidad del servidor, en saltos `parent` desde el objeto del `Check`. Sin valor: sin cota. */
  depthLimits?: { ancestor?: number; other?: number }
  /** Caché: lecturas sin HIGHER ven el estado de `staleBy` escrituras atrás (0/undefined = sin caché). */
  staleBy?: number
  /** Tope de tuplas por `Write` (el servidor: 100). */
  maxTuplesPerWrite?: number
  /** Guardar la traza (default true). */
  trace?: boolean
}

export interface ClientHooks {
  /** Gancho cooperativo: se espera ANTES de cada I/O (el planificador decide cuándo sigue). */
  onIo?: (event: IoEvent) => Promise<void> | void
  /** Fallo inyectado para este I/O. */
  fault?: (event: IoEvent) => FaultSpec | undefined
}

const HIGHER = 'HIGHER_CONSISTENCY'
const tupleId = (t: { user: string; relation: string; object: string }) => `${t.object}#${t.relation}@${t.user}`
const plain = (t: FgaTuple): FgaTuple => {
  const out: FgaTuple = { user: t.user, relation: t.relation, object: t.object }
  if (t.condition) out.condition = { name: t.condition.name, ...(t.condition.context ? { context: { ...t.condition.context } } : {}) }
  return out
}

/* ── El store compartido ───────────────────────────────────────────────── */

export class FgaMemoryStore {
  readonly model: CompiledModel
  readonly modelJson: any
  readonly options: MemoryFgaOptions
  /** Estado actual: id ⇒ tupla, en orden de inserción. */
  #current = new Map<string, FgaTuple>()
  /** Historial de estados (para la caché): `history[v]` = tuplas de la versión v. Solo si `staleBy`. */
  #history: FgaTuple[][] = []
  #interp: { version: number; state: TupleStore } | undefined
  version = 0
  tick = 0
  readonly trace: TraceEntry[] = []
  readonly counts = { read: 0, write: 0, check: 0, checkHop: 0, batchCheck: 0, batchItems: 0, rejectedWrites: 0 }

  constructor(options: MemoryFgaOptions) {
    this.options = options
    this.modelJson = options.model
    this.model = compileModel(options.model)
    for (const t of options.initial ?? []) {
      const id = tupleId(t)
      if (this.#current.has(id)) throw new Error(`FgaMemoryStore: tupla inicial duplicada ${id}`)
      this.#current.set(id, plain(t))
    }
    if (options.staleBy) this.#history.push([...this.#current.values()])
  }

  /** Las tuplas actuales (copia). */
  tuples(): FgaTuple[] {
    return [...this.#current.values()].map(plain)
  }

  has(t: { user: string; relation: string; object: string }): boolean {
    return this.#current.has(tupleId(t))
  }

  /** Estado del intérprete de la versión actual (memo por versión). */
  state(): TupleStore {
    if (this.#interp?.version !== this.version) this.#interp = { version: this.version, state: new TupleStore(this.#current.values()) }
    return this.#interp.state
  }

  /** Las tuplas que ve una lectura con esa consistencia (la caché sirve el pasado). */
  #view(consistency: string | undefined): { tuples: Iterable<FgaTuple>; version: number; state: () => TupleStore } {
    const lag = this.options.staleBy ?? 0
    if (!lag || consistency === HIGHER) return { tuples: this.#current.values(), version: this.version, state: () => this.state() }
    const v = Math.max(0, this.version - lag)
    const tuples = this.#history[v]
    return { tuples, version: v, state: () => new TupleStore(tuples) }
  }

  #log(entry: Omit<TraceEntry, 'tick'>): void {
    this.tick++
    if (this.options.trace !== false) this.trace.push({ tick: this.tick, ...entry })
  }

  /** El cliente de un actor («proceso»): mismos métodos que usa el driver del SDK. */
  client(actor: string, hooks: ClientHooks = {}): MemoryFgaClient {
    return new MemoryFgaClient(this, actor, hooks)
  }

  /* — operaciones internas (las llama el cliente tras el gancho) — */

  _read(filter: any, consistency: string | undefined, pageSize: number, token: string | undefined) {
    const view = this.#view(consistency)
    const object: string | undefined = filter?.object
    const match = (t: FgaTuple) =>
      (object === undefined || object === '' ? true : object.endsWith(':') ? t.object.startsWith(object) : t.object === object) &&
      (!filter?.relation || t.relation === filter.relation) &&
      (!filter?.user || t.user === filter.user)
    const all = [...view.tuples].filter(match)
    const start = token ? Number(token) : 0
    const page = all.slice(start, start + pageSize)
    const next = start + pageSize < all.length ? String(start + pageSize) : ''
    return {
      response: { tuples: page.map((k) => ({ key: plain(k), timestamp: new Date(0).toISOString() })), continuation_token: next },
      version: view.version,
    }
  }

  /** Valida y calcula lo EFECTIVO; lanza con la forma del SDK sin aplicar nada. */
  _plan(body: any, options: any): { writes: FgaTuple[]; deletes: FgaTuple[] } {
    const writes: FgaTuple[] = body?.writes ?? []
    const deletes: FgaTuple[] = body?.deletes ?? []
    const max = this.options.maxTuplesPerWrite ?? 100
    if (writes.length + deletes.length > max) throw sdkError('real-write-exceeded-entity-limit')
    const ignoreDup = options?.conflict?.onDuplicateWrites === 'ignore'
    const ignoreMissing = options?.conflict?.onMissingDeletes === 'ignore'
    const effective = { writes: [] as FgaTuple[], deletes: [] as FgaTuple[] }
    const seen = new Set<string>()
    for (const t of deletes) {
      const id = tupleId(t)
      if (this.#current.has(id) && !seen.has(id)) {
        effective.deletes.push(plain(t))
        seen.add(id)
      } else if (!ignoreMissing) throw sdkError('real-delete-absent')
    }
    for (const t of writes) {
      const id = tupleId(t)
      // Una tupla que este mismo `Write` borra se puede volver a escribir (delete + write de la MISMA clave en un `Write`
      // es un 400 del servidor; el driver no lo hace, y aquí se rechaza igual que un duplicado).
      if (!this.#current.has(id) && !effective.writes.some((w) => tupleId(w) === id)) effective.writes.push(plain(t))
      else if (!ignoreDup) throw sdkError('real-write-duplicate')
    }
    return effective
  }

  _apply(effective: { writes: FgaTuple[]; deletes: FgaTuple[] }): void {
    for (const t of effective.deletes) this.#current.delete(tupleId(t))
    for (const t of effective.writes) this.#current.set(tupleId(t), t)
    this.version++
    if (this.options.staleBy) this.#history.push([...this.#current.values()])
  }

  /** Saltos `parent` desde un objeto `scope:` (máximo por cualquier camino; corte anti-ciclo). */
  hopsFrom(object: string, tuples: Iterable<FgaTuple>): number {
    const parents = new Map<string, string[]>()
    for (const t of tuples) if (t.relation === 'parent') parents.set(t.object, [...(parents.get(t.object) ?? []), t.user])
    let max = 0
    const walk = (o: string, depth: number, seen: Set<string>) => {
      if (depth > max) max = depth
      for (const p of parents.get(o) ?? []) if (!seen.has(p)) walk(p, depth + 1, new Set([...seen, p]))
    }
    walk(object, 0, new Set([object]))
    return max
  }

  _log(entry: Omit<TraceEntry, 'tick'>): void {
    this.#log(entry)
  }
}

/* ── El cliente de un actor ────────────────────────────────────────────── */

export class MemoryFgaClient {
  #k = 0
  constructor(
    readonly store: FgaMemoryStore,
    readonly actor: string,
    readonly hooks: ClientHooks
  ) {}

  /** Cede (gancho) y decide el fallo inyectado de ESTE I/O. */
  async #io(kind: IoKind, body: unknown, consistency: string | undefined): Promise<{ event: IoEvent; fault: FaultSpec | undefined }> {
    const event: IoEvent = { actor: this.actor, k: ++this.#k, kind, body, consistency }
    if (this.hooks.onIo) await this.hooks.onIo(event)
    return { event, fault: this.hooks.fault?.(event) }
  }

  #fail(event: IoEvent, error: Error): never {
    const e: any = error
    this.store._log({ actor: this.actor, k: event.k, kind: event.kind, consistency: event.consistency, request: event.body, result: `error:${e.apiErrorCode ?? e.statusCode ?? e.name}`, version: this.store.version })
    throw error
  }

  async readAuthorizationModel() {
    return { authorization_model: this.store.modelJson }
  }

  async read(filter: any = {}, options: any = {}) {
    const consistency = options?.consistency
    const { event, fault } = await this.#io('read', filter, consistency)
    this.store.counts.read++
    if (fault) this.#fail(event, fault.error)
    const { response, version } = this.store._read(filter, consistency, Math.min(options?.pageSize ?? 50, 100), options?.continuationToken)
    this.store._log({ actor: this.actor, k: event.k, kind: 'read', consistency, request: filter, result: `ok:${response.tuples.length}`, version })
    return response
  }

  async write(body: any, options: any = {}) {
    const { event, fault } = await this.#io('write', body, undefined)
    this.store.counts.write++
    if (fault && fault.when !== 'after') {
      this.store.counts.rejectedWrites++
      this.#fail(event, fault.error)
    }
    let effective: { writes: FgaTuple[]; deletes: FgaTuple[] }
    try {
      effective = this.store._plan(body, options)
    } catch (error) {
      this.store.counts.rejectedWrites++
      this.#fail(event, error as Error)
    }
    this.store._apply(effective)
    this.store._log({ actor: this.actor, k: event.k, kind: 'write', consistency: undefined, writes: effective.writes, deletes: effective.deletes, result: 'ok', version: this.store.version })
    if (fault) throw fault.error
    return {}
  }

  async writeTuples(tuples: any[], options?: any) {
    return this.write({ writes: tuples, deletes: [] }, options)
  }

  async deleteTuples(tuples: any[], options?: any) {
    return this.write({ writes: [], deletes: tuples }, options)
  }

  /** `ancestor` paseado salto a salto (cede en cada uno); el resto, una foto por el intérprete. */
  async #ancestor(event: IoEvent, object: string, target: string, consistency: string | undefined): Promise<boolean> {
    const limit = this.store.options.depthLimits?.ancestor
    let frontier = [object]
    const visited = new Set([object])
    let hop = 0
    while (frontier.length) {
      hop++
      if (hop > 1) {
        // El primer salto lo cubre el gancho del propio `check`; los siguientes ceden por su cuenta.
        const step = await this.#io('check-hop', { object: frontier, target }, consistency)
        this.store.counts.checkHop++
        if (step.fault) this.#fail(step.event, step.fault.error)
      }
      const view = this.store._read({ relation: 'parent' }, consistency, Number.MAX_SAFE_INTEGER, undefined).response.tuples
      const next: string[] = []
      for (const o of frontier) {
        for (const { key } of view) {
          if (key.object !== o) continue
          if (key.user === target) {
            // M2 (sublote «asentar», v1.19 + postgres, con y sin caché): la cara VERDADERA resuelve 500/500 hasta 26
            // saltos y falla 500/500 a 27 y 30; la cara FALSA (owner ausente: pasea hasta la raíz) resuelve a 30.
            if (limit !== undefined && hop > limit) this.#fail(event, sdkError('real-check-resolution-too-complex'))
            return true
          }
          if (!visited.has(key.user)) {
            visited.add(key.user)
            next.push(key.user)
          }
        }
      }
      frontier = next
    }
    return false
  }

  async #evaluate(event: IoEvent, request: any, consistency: string | undefined): Promise<boolean> {
    if (request.relation === 'ancestor' && String(request.object).startsWith('scope:')) {
      return this.#ancestor(event, request.object, request.user, consistency)
    }
    const read = this.store._read({}, consistency, Number.MAX_SAFE_INTEGER, undefined)
    const tuples = read.response.tuples.map((t: any) => t.key as FgaTuple)
    const limit = this.store.options.depthLimits?.other
    if (limit !== undefined && String(request.object).startsWith('scope:') && this.store.hopsFrom(request.object, tuples) > limit) {
      this.#fail(event, sdkError('real-check-resolution-too-complex'))
    }
    const state = read.version === this.store.version ? this.store.state() : new TupleStore(tuples)
    const { verdict } = checkTuples(this.store.model, state, {
      user: request.user,
      relation: request.relation,
      object: request.object,
      context: request.context,
    })
    if (verdict === 'E') this.#fail(event, sdkError('real-check-context-absent-request'))
    return verdict === 'T'
  }

  async check(request: any, options: any = {}) {
    const consistency = options?.consistency
    const { event, fault } = await this.#io('check', request, consistency)
    this.store.counts.check++
    if (fault) this.#fail(event, fault.error)
    const allowed = await this.#evaluate(event, request, consistency)
    this.store._log({ actor: this.actor, k: event.k, kind: 'check', consistency, request, result: allowed ? 'T' : 'F', version: this.store.version })
    return { allowed }
  }

  /** Un `batchCheck` = UNA petición (cede una vez); los ítems de `ancestor` se pasean salto a salto. */
  async batchCheck(body: { checks: any[] }, options: any = {}) {
    const consistency = options?.consistency
    const { event, fault } = await this.#io('batchCheck', body, consistency)
    this.store.counts.batchCheck++
    this.store.counts.batchItems += body.checks.length
    if (fault) this.#fail(event, fault.error)
    const result: any[] = []
    for (const item of body.checks) {
      try {
        const allowed = await this.#evaluate(event, item, consistency)
        result.push({ allowed, request: item, correlationId: item.correlationId })
      } catch (error: any) {
        // El servidor devuelve el error POR ÍTEM dentro de un 200 (F0 · M-d): la clave del objeto hace de código. **En
        // snake_case** (`input_error`), como lo deja pasar el SDK 0.9.6 (fixture `real-batchcheck-mixed-items`): hasta el
        // cierre 1 del asentar el doble lo escribía en camelCase y `classifyFgaFailure` lo leía como un 503 — la caída a
        // `storeChain` (resolución 9, condición 2) nunca se ejercía sin servidor.
        if (error?.apiErrorCode === 'authorization_model_resolution_too_complex') {
          result.push({ allowed: false, request: item, correlationId: item.correlationId, error: { input_error: 'authorization_model_resolution_too_complex', message: error.apiErrorMessage } })
        } else throw error
      }
    }
    this.store._log({ actor: this.actor, k: event.k, kind: 'batchCheck', consistency, request: body.checks.length, result: 'ok', version: this.store.version })
    return { result }
  }
}

/**
 * Instala el cliente en memoria DENTRO del cliente del SDK que el driver envuelve con `guardBackendErrors`: el Proxy no
 * tiene trampa `set`, así que la asignación cae en el objetivo y cada llamada sigue pasando por el clasificador, la
 * marca de escritura y el deadline del driver (fidelidad de la capa de errores).
 */
export function installMemoryClient(driver: object, client: MemoryFgaClient): void {
  const target = (driver as { client: any }).client
  for (const method of ['readAuthorizationModel', 'read', 'write', 'writeTuples', 'deleteTuples', 'check', 'batchCheck'] as const) {
    target[method] = (client as any)[method].bind(client)
  }
}

/* ── Planificador cooperativo sembrado ─────────────────────────────────── */

/** PRNG sembrado (mulberry32): mismo `seed` ⇒ misma secuencia. Nunca `Date.now()`. */
export function seededRandom(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

/** Un uuid con forma v7 derivado de un número (reproducible: el universo no usa `randomUUID`). */
export function fixedUuid(n: number): string {
  const hex = n.toString(16).padStart(12, '0').slice(-12)
  return `0190a000-0000-7000-8000-${hex}`
}

export interface SchedulerState {
  /** Actores bloqueados en su gancho, ordenados. */
  waiting: string[]
  /** Actores vivos (no terminados). */
  live: ReadonlySet<string>
  /** I/O liberados hasta ahora, por actor. */
  released: ReadonlyMap<string, number>
  step: number
}

export type SchedulerPolicy = (state: SchedulerState) => string

/** Uniforme sembrada. */
export function uniformPolicy(rnd: () => number): SchedulerPolicy {
  return ({ waiting }) => waiting[Math.floor(rnd() * waiting.length)]
}

/**
 * PCT (Burckhardt et al.): prioridades aleatorias por actor y `d − 1` puntos de cambio en pasos aleatorios de
 * `[1, maxSteps]`; siempre avanza el de mayor prioridad, y en un punto de cambio el elegido baja al fondo.
 */
export function pctPolicy(rnd: () => number, actors: readonly string[], changePoints: number, maxSteps: number): SchedulerPolicy {
  const prio = new Map(actors.map((a) => [a, rnd()]))
  const points = new Set(Array.from({ length: changePoints }, () => 1 + Math.floor(rnd() * maxSteps)))
  return ({ waiting, step }) => {
    const id = waiting.reduce((best, a) => ((prio.get(a) ?? 0) > (prio.get(best) ?? 0) ? a : best))
    if (points.has(step + 1)) prio.set(id, -1 - step)
    return id
  }
}

/**
 * Enumeración acotada de UNA preempción: `first` corre solo hasta tener pendiente su `k`-ésimo I/O; entonces `second`
 * corre ENTERO; después el resto. `fired()` dice si la preempción ocurrió (si `first` terminó antes del I/O `k`, no).
 */
export function preemptPolicy(first: string, second: string, k: number): SchedulerPolicy & { fired: () => boolean } {
  let fired = false
  const policy = (({ waiting, live, released }) => {
    const firstAtK = (released.get(first) ?? 0) >= k - 1
    if (live.has(second) && (firstAtK || !live.has(first)) && waiting.includes(second)) {
      if (live.has(first)) fired = true
      return second
    }
    if (waiting.includes(first) && (!firstAtK || !live.has(second))) return first
    return waiting[0]
  }) as SchedulerPolicy & { fired: () => boolean }
  policy.fired = () => fired
  return policy
}

export interface ScheduledActor<R> {
  id: string
  run: (onIo: (event: IoEvent) => Promise<void>) => Promise<R>
}

export interface ScheduleResult<R> {
  results: Map<string, { ok: true; value: R } | { ok: false; error: unknown }>
  steps: number
  /** Cambios de actor entre dos liberaciones consecutivas con ambos vivos (≥ 1 ⇒ hubo entrelazado). */
  switches: number
}

/**
 * Corre los actores con un planificador COOPERATIVO: cada I/O se bloquea en el gancho; cuando todos los vivos están
 * bloqueados (se drena con `setImmediate`: sin temporizadores ni `sleep`), la política elige cuál avanza. Determinista
 * para una política sembrada (el resto del código del driver es síncrono entre I/O, salvo SQL, que el drenaje espera).
 */
export async function runScheduled<R>(
  actors: Array<ScheduledActor<R>>,
  policy: SchedulerPolicy,
  options: { maxSteps?: number; maxDrain?: number } = {}
): Promise<ScheduleResult<R>> {
  const waiting = new Map<string, () => void>()
  const live = new Set(actors.map((a) => a.id))
  const released = new Map<string, number>()
  const results = new Map<string, { ok: true; value: R } | { ok: false; error: unknown }>()
  const done = actors.map((actor) =>
    actor
      .run((_event) => new Promise<void>((resolve) => waiting.set(actor.id, resolve)))
      .then(
        (value) => results.set(actor.id, { ok: true, value }),
        (error) => results.set(actor.id, { ok: false, error })
      )
      .finally(() => live.delete(actor.id))
  )
  const maxSteps = options.maxSteps ?? 20_000
  const maxDrain = options.maxDrain ?? 10_000
  let steps = 0
  let switches = 0
  let last: string | undefined
  while (live.size > 0) {
    let drains = 0
    // Todos los vivos bloqueados (o terminados): el siguiente paso es de la política.
    while (waiting.size < live.size) {
      await new Promise((r) => setImmediate(r))
      if (++drains > maxDrain) throw new Error(`runScheduled: un actor no llega a su gancho (vivos ${[...live]}, esperando ${[...waiting.keys()]})`)
    }
    if (live.size === 0) break
    if (steps >= maxSteps) throw new Error(`runScheduled: más de ${maxSteps} pasos (¿bucle sin fin?)`)
    const ids = [...waiting.keys()].sort()
    const id = policy({ waiting: ids, live, released, step: steps })
    const resume = waiting.get(id)
    if (!resume) throw new Error(`runScheduled: la política eligió ${id}, que no está esperando`)
    if (last !== undefined && last !== id && live.has(last)) switches++
    last = id
    waiting.delete(id)
    released.set(id, (released.get(id) ?? 0) + 1)
    steps++
    resume()
  }
  await Promise.all(done)
  return { results, steps, switches }
}
