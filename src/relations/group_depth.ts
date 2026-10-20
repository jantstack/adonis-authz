/**
 * **El límite de anidación de grupos** (lote «antes de RC» · R1; decisiones del dueño 2026-10-17 (5) «límite SEGÚN EL
 * DRIVER» y (5-bis) opción (a) tras F0 · M-c). Piezas PURAS (sin backend), compartidas por los dos drivers de relaciones
 * y por el plan de `reconcileRelations`, para que la regla sea UNA:
 *
 *  - **qué es una arista de anidación**: `group:<Gp>#member@group:<Gc>#member` (los miembros de Gc son miembros de Gp);
 *  - **la profundidad es el camino MÁS LARGO** de aristas grupo⊂grupo (T-3 del tester: en un DAG con un camino corto y
 *    otro largo hacia la misma cima, OpenFGA da 503 a los NO-miembros por el largo; un BFS por niveles admitiría ese
 *    grafo). Un ciclo PREEXISTENTE se cuenta de forma CONSERVADORA: sus k nodos pesan k − 1 saltos (cota superior del
 *    camino simple más largo que lo atraviesa) — más negativas, nunca menos;
 *  - **la validación de `maxGroupDepth`** (V2-1 del auditor): entero 1..`GROUP_DEPTH_CONFIG_MAX` o `false` (el ÚNICO
 *    «apagado»), y nada más — `''`, `NaN`, `0`, `-1`, `Infinity`, `24.5`, `'24'`, `null`, `true` ⇒ 500 al ARRANCAR
 *    (`defineRelationsConfig`), jamás un gate apagado en silencio;
 *  - **la calibración** (decisión 5 + 5-bis): el techo de `openfga` se MIDE contra el servidor con tuplas contextuales
 *    (solo lectura) y es el MÍNIMO de la sonda POSITIVA (un miembro: T) y la NEGATIVA (un no-miembro CON alguna
 *    membresía: F; una sonda sin membresías es CIEGA, F a cualquier profundidad, F0 · M-c). La búsqueda es pura sobre
 *    una sonda inyectada.
 *
 * Pureza (regla 2): solo depende de los errores. Nada de `manager`/`drivers/*`.
 */
import { AuthorizationBackendError, AuthorizationConfigError, GroupDepthLimitError } from '../errors.js'
import type { RelObject, RelSubject } from '../types.js'
import { isRelUserset } from '../types.js'

/** El tipo y la relación de la anidación (los mismos que `RELATION_USERSET_*`; repetidos para no crear un ciclo de imports). */
const GROUP = 'group'
const MEMBER = 'member'

/**
 * **El techo medido** en OpenFGA v1.19.0 con `--resolve-node-limit` por defecto (25): un miembro resuelve 24 saltos
 * grupo⊂grupo y un no-miembro CON membresías 22 (F0 · M-c, 200/200 en los dos bordes, independiente de `includes` 0..3 y
 * del deny) ⇒ el MÍNIMO, 22. Es la cifra de la fila de «Limits»; la VERDAD de cada despliegue es la calibración.
 */
export const RELATIONS_GROUP_DEPTH_MEASURED = 22

/**
 * **El mayor `maxGroupDepth` que se acepta** (auditor M4): la calibración usa una cadena de tuplas CONTEXTUALES y el
 * servidor admite 100 por `Check`; la forma de dominio cuesta K + 2. Por encima no hay nada que medir.
 */
export const GROUP_DEPTH_CONFIG_MAX = 97

/**
 * **El mayor K que la calibración prueba**: la sonda NEGATIVA lleva dos tuplas más (la membresía del no-miembro y la
 * suya propia, M-c) ⇒ K + 4 ≤ 100. Un `maxGroupDepth: 97` es válido en la config y, contra un servidor que resolviera
 * todo, la calibración lo deja en 96 ⇒ 500 (el techo pedido no se puede DEMOSTRAR).
 */
export const GROUP_DEPTH_CALIBRATION_MAX = 96

/**
 * **Cuántos grupos recorre como mucho la comprobación de UNA arista** (hacia arriba desde Gp más hacia abajo desde Gc).
 * Pasarla ⇒ 422 `E_AUTHZ_GROUP_DEPTH_LIMIT` con motivo `too-many-groups`, nunca «pasa». El recorrido además se corta en
 * cuanto un nivel del BFS supera el techo (el camino más corto ya excede: el largo también).
 */
export const GROUP_DEPTH_MAX_NODES = 10_000

/**
 * **El presupuesto de la comprobación de UNA arista en `openfga`** (cierre de R1 · 🟠 1 del auditor: amplificación de
 * lecturas contra el store COMPARTIDO). En `openfga` el gate hace un `Read` por grupo de la frontera, y el `Read` hacia
 * ABAJO (objeto + `member`) trae también los HOLDERS —el servidor no admite filtrar por tipo de `user` (`user: 'group:'`
 * ⇒ 400 `validation_error`, medido en :8090 v1.19)—: sin presupuesto, quien controla la anidación hacía pagar O(grupos ×
 * miembros/100) requests a cada `relate`. Pasar cualquiera de los tres ⇒ 422 `E_AUTHZ_GROUP_DEPTH_LIMIT`, motivo
 * `too-many-groups` (fail-closed: no se escribe). Requests (páginas de `Read`), tuplas leídas y un deadline TOTAL del
 * veredicto (comprobado antes de cada request; una request en vuelo la acota el `timeoutMs` del cliente).
 */
export const GROUP_DEPTH_MAX_READS = 2_000
export const GROUP_DEPTH_MAX_TUPLES = 50_000
export const GROUP_DEPTH_DEADLINE_MS = 10_000

/**
 * **La espera tras una calibración FALLIDA** (cierre-2 de R1 · D5 (a), injerto del auditor; decisión del dueño 2026-10-20):
 * la calibración de `openfga` son ~14 `Check` (bisección 0..96, dos sondas). Si cae (servidor caído, 503, deadline, el
 * 500 de una sonda ciega), durante esta ventana la siguiente escritura de anidación recibe un error de la MISMA clase —una
 * instancia nueva con el memorizado de `cause`, y un timeout como 503 no-timeout (cierre-3 · R-5)— sin volver a
 * sondear —una flota de `relate` contra un servidor que se cae no lo remata con 14 `Check` cada uno—; pasada, la
 * siguiente vuelve a calibrar (el fallo nunca se memoriza para siempre, C13a). Reloj MONÓTONO del driver.
 */
export const GROUP_DEPTH_CALIBRATION_BACKOFF_MS = 2_000

/**
 * **La cota de frecuencia de la RE-calibración** (cierre-2 de R1 · D5 (a) + P2 del juez): una lectura de `openfga` que
 * recibe 503 `E_AUTHZ_RESOLUTION_LIMIT` (el servidor ya no resuelve lo que el techo memorizado prometía: el operador BAJÓ
 * `OPENFGA_RESOLVE_NODE_LIMIT` sin reiniciar la app) invalida la calibración memorizada, como mucho UNA vez por este
 * intervalo y por proceso; la siguiente escritura de anidación vuelve a medir. Sin la cota, una forma que dé 503 en cada
 * lectura dispararía una calibración por lectura. SUBIR el límite del servidor no produce ningún 503 que lo delate: eso
 * sigue pidiendo reiniciar la app.
 */
export const GROUP_DEPTH_RECALIBRATION_MIN_INTERVAL_MS = 60_000

/** Qué cota del presupuesto se pasó (va en `details.budget` del 422). */
export type GroupDepthBudgetKind = 'nodes' | 'reads' | 'tuples' | 'deadline'

/** Señal INTERNA: el lector la lanza al pasar el presupuesto y `groupNestingVerdict` la convierte en `too-many-groups`. */
export class GroupDepthBudgetExceeded extends Error {
  constructor(readonly budget: Exclude<GroupDepthBudgetKind, 'nodes'>) {
    super(`presupuesto de la comprobación de anidación agotado (${budget})`)
  }
}

/** El contador de UN veredicto: `beforeRead()` antes de cada request, `charge(n)` con las tuplas de cada página. */
export class GroupDepthBudget {
  reads = 0
  tuples = 0
  readonly #start: number
  constructor(
    readonly limits: { reads: number; tuples: number; deadlineMs: number } = {
      reads: GROUP_DEPTH_MAX_READS,
      tuples: GROUP_DEPTH_MAX_TUPLES,
      deadlineMs: GROUP_DEPTH_DEADLINE_MS,
    },
    readonly clock: () => number = () => performance.now()
  ) {
    this.#start = clock()
  }
  beforeRead(): void {
    if (this.clock() - this.#start > this.limits.deadlineMs) throw new GroupDepthBudgetExceeded('deadline')
    if (this.reads >= this.limits.reads) throw new GroupDepthBudgetExceeded('reads')
  }
  charge(tuples: number): void {
    this.reads += 1
    this.tuples += tuples
    if (this.tuples > this.limits.tuples) throw new GroupDepthBudgetExceeded('tuples')
  }
}

/**
 * **La marca del PLAN del reconcile** (R1; cierre: 🟡 2 del auditor + 🟠 C del tester): las escrituras de
 * `reconcileRelations` llevan un objeto de opciones creado AQUÍ (`plannedRelateOptions`) porque la profundidad ya la
 * decidió el plan sobre el estado FINAL de la partición (y la negó si excedía). El gate del driver no se vuelve a
 * consultar ahí, por dos razones firmadas: (1) «un ciclo preexistente NO niega» — el gate de escritura rechaza la arista
 * que cierra un ciclo, y negarla a mitad de pasada saltaría una arista que puede transportar un deny (🔴 C-1); (2) un
 * estado INTERMEDIO de la pasada puede exceder sin que exceda el final.
 *
 * **No es falsificable** (hasta el cierre era un símbolo en las opciones y un `Proxy` que responde `true` a todo símbolo
 * apagaba el gate de los DOS drivers; y el gate vive en el driver precisamente para que `manager.driver()` NO se lo
 * salte, así que era la única puerta trasera): la marca es la IDENTIDAD del objeto, registrado en un `WeakMap` privado
 * de este módulo que nada exporta, y está ATADA a la arista (partición, hijo y padre) — un decorador que reciba el objeto
 * real no puede reutilizarlo para OTRA arista —, congelado (no se le cambia la caducidad). Además el `RelationsManager`
 * pasa al driver un objeto NUEVO con solo las claves conocidas, así que por la API nunca llega una marca.
 */
const PLANNED = new WeakMap<object, string>()

const plannedKey = (partition: { type: string; uuid: string | null }, child: string, parent: string) =>
  JSON.stringify([partition.type, partition.uuid, child, parent])

/** Las opciones de `relate` de UNA arista planificada por el reconcile (solo el reconcile del paquete las crea). */
export function plannedRelateOptions<T extends object>(
  options: T,
  tuple: { subject: RelSubject; relation: string; object: RelObject; partition: { type: string; uuid: string | null } }
): T {
  const frozen = Object.freeze({ ...options })
  if (isGroupNesting(tuple.subject, tuple.relation, tuple.object)) {
    PLANNED.set(frozen, plannedKey(tuple.partition, tuple.subject.object.id, tuple.object.id))
  }
  return frozen
}

/** ¿Llega ESTA arista (`child ⊂ parent` en `partition`) con las opciones que el reconcile creó para ella? */
export function plannedByReconcile(
  options: unknown,
  partition: { type: string; uuid: string | null },
  edge: GroupEdge
): boolean {
  return typeof options === 'object' && options !== null && PLANNED.get(options) === plannedKey(partition, edge.child, edge.parent)
}

/** El porqué del techo, para `details.why` (el operador; el `message` es del tenant). */
const WHY =
  'el driver openfga no resuelve de forma fiable una anidación de grupos más profunda: su techo se CALIBRA contra el ' +
  'servidor al primer uso (el mínimo de un miembro y de un no-miembro con membresías; 22 saltos en OpenFGA v1.19 por ' +
  'defecto; se re-calibra tras un 503 de profundidad en lectura, como mucho una vez por minuto) y, pasado, todo check ' +
  'de un no-miembro es 503 E_AUTHZ_RESOLUTION_LIMIT. En database el límite es opt-in (database.enforceGroupDepth) y el ' +
  'número lo declara maxGroupDepth (defineRelationsConfig).'
const SERVER = 'OPENFGA_RESOLVE_NODE_LIMIT (--resolve-node-limit) en el servidor OpenFGA; maxGroupDepth (defineRelationsConfig) solo puede BAJARLO'

/** `group:<Gp>#member@group:<Gc>#member`: la ÚNICA forma de anidar (B3: el único userset admitido es `group#member`). */
export function isGroupNesting(subject: RelSubject, relation: string, object: RelObject): subject is Extract<RelSubject, { relation: string }> {
  return (
    object?.type === GROUP &&
    relation === MEMBER &&
    isRelUserset(subject) &&
    subject.object?.type === GROUP &&
    subject.relation === MEMBER
  )
}

/**
 * **Valida `maxGroupDepth`** (V2-1; decisión 5: «entero 1..97 o `false`»): `undefined` ⇒ sin valor (el driver usa su
 * techo), `false` ⇒ apagado EXPLÍCITO, entero en [1, 97] ⇒ ese techo. Cualquier otra cosa ⇒ 500 `E_AUTHZ_CONFIG`: el
 * paquete no lee variables de entorno, y la línea típica `Number(env.get('X') ?? 24)` produce `0` (`''`) y `NaN` (`'abc'`),
 * que con `if (depth > max)` o `if (!max)` APAGARÍAN el gate en silencio.
 */
export function assertMaxGroupDepth(value: unknown, where = 'defineRelationsConfig'): number | false | undefined {
  if (value === undefined || value === false) return value
  if (typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= GROUP_DEPTH_CONFIG_MAX) return value
  throw new AuthorizationConfigError(
    `${where}: maxGroupDepth tiene que ser un entero entre 1 y ${GROUP_DEPTH_CONFIG_MAX} o false (apagado explícito); ` +
      `llegó ${typeof value === 'number' ? String(value) : JSON.stringify(value)} (${typeof value}). Ni 0, ni NaN, ni ` +
      `Infinity, ni una cadena: un valor así apagaría el límite en silencio. El paquete no lee variables de entorno — ` +
      `valida la tuya al arrancar (Env.schema.number.optional() en start/env.ts) y pásala como número. ${GROUP_DEPTH_CONFIG_MAX} ` +
      'es lo máximo que la calibración contra OpenFGA puede medir (100 tuplas contextuales por Check).'
  )
}

/**
 * **Valida el PAR (`maxGroupDepth`, `enforceGroupDepth`)** — en `defineRelationsConfig` al arrancar y, desde el cierre de
 * R1 (🟡 4 del auditor), OTRA VEZ en los dos drivers: una config extendida con spread
 * (`{ ...defineRelationsConfig(spec), maxGroupDepth: Number(env.get('X')) }`) llegaba al driver sin pasar por la
 * validación, y con `NaN` toda comparación `> limit` es `false`: el gate quedaba APAGADO en silencio. `enforceGroupDepth`
 * solo admite `true`/`false`/ausente y `true` exige un número. Todo lo demás ⇒ 500 `E_AUTHZ_CONFIG`.
 */
export function assertGroupDepthSettings(
  maxGroupDepth: unknown,
  enforceGroupDepth: unknown,
  where = 'defineRelationsConfig'
): { maxGroupDepth: number | false | undefined; enforceGroupDepth: boolean } {
  const max = assertMaxGroupDepth(maxGroupDepth, where)
  if (enforceGroupDepth !== undefined && typeof enforceGroupDepth !== 'boolean') {
    throw new AuthorizationConfigError(
      `${where}: database.enforceGroupDepth tiene que ser true o false (llegó ${JSON.stringify(enforceGroupDepth)}).`
    )
  }
  if (enforceGroupDepth === true && typeof max !== 'number') {
    throw new AuthorizationConfigError(
      `${where}: database.enforceGroupDepth: true exige maxGroupDepth NUMÉRICO (llegó ${String(max)}): ` +
        'database no tiene techo técnico que calibrar, así que el número lo pones tú (p. ej. 22, el techo medido de ' +
        'OpenFGA v1.19, si quieres que los datos sean portables a openfga).'
    )
  }
  return { maxGroupDepth: max, enforceGroupDepth: enforceGroupDepth === true }
}

/** Una arista grupo⊂grupo: `child` es miembro de `parent` (ids de objeto del grupo, sin partición). */
export interface GroupEdge {
  child: string
  parent: string
}

/**
 * **La cadena más larga** (en aristas grupo⊂grupo) de un conjunto de aristas, con los ciclos colapsados de forma
 * CONSERVADORA (cada componente fuertemente conexa de k nodos pesa k − 1). Devuelve la profundidad y una cadena
 * representativa (los grupos, de abajo arriba) para la letra. Lineal en nodos + aristas (Tarjan iterativo + DP).
 */
export function groupChainDepth(edges: Iterable<GroupEdge>): { depth: number; chain: string[] } {
  const up = new Map<string, Set<string>>()
  const nodes = new Set<string>()
  for (const { child, parent } of edges) {
    nodes.add(child)
    nodes.add(parent)
    if (!up.has(child)) up.set(child, new Set())
    up.get(child)!.add(parent)
  }
  // Tarjan iterativo (sin recursión: una cadena de 10 000 grupos no puede reventar la pila).
  const index = new Map<string, number>()
  const low = new Map<string, number>()
  const onStack = new Set<string>()
  const stack: string[] = []
  const component = new Map<string, number>()
  const members: string[][] = []
  let next = 0
  for (const root of nodes) {
    if (index.has(root)) continue
    const work: Array<{ node: string; it: Iterator<string> }> = []
    const open = (node: string) => {
      index.set(node, next)
      low.set(node, next)
      next += 1
      stack.push(node)
      onStack.add(node)
      work.push({ node, it: (up.get(node) ?? new Set<string>()).values() })
    }
    open(root)
    while (work.length > 0) {
      const frame = work[work.length - 1]
      const step = frame.it.next()
      if (!step.done) {
        const w = step.value
        if (!index.has(w)) open(w)
        else if (onStack.has(w)) low.set(frame.node, Math.min(low.get(frame.node)!, index.get(w)!))
        continue
      }
      work.pop()
      if (work.length > 0) {
        const parentFrame = work[work.length - 1]
        low.set(parentFrame.node, Math.min(low.get(parentFrame.node)!, low.get(frame.node)!))
      }
      if (low.get(frame.node) === index.get(frame.node)) {
        const id = members.length
        const scc: string[] = []
        let w: string
        do {
          w = stack.pop()!
          onStack.delete(w)
          component.set(w, id)
          scc.push(w)
        } while (w !== frame.node)
        members.push(scc)
      }
    }
  }
  // Tarjan emite las componentes en orden topológico INVERSO del grafo hijo→padre: primero las cimas. La DP «camino
  // más largo que EMPIEZA en c» recorre en ese orden (los padres de c ya están resueltos).
  const best = new Array<number>(members.length).fill(0)
  const nextOf = new Array<number>(members.length).fill(-1)
  for (let c = 0; c < members.length; c++) {
    const own = members[c].length - 1
    let tail = 0
    let via = -1
    for (const node of members[c]) {
      for (const parent of up.get(node) ?? []) {
        const pc = component.get(parent)!
        if (pc === c) continue
        if (1 + best[pc] > tail) {
          tail = 1 + best[pc]
          via = pc
        }
      }
    }
    best[c] = own + tail
    nextOf[c] = via
  }
  let start = -1
  for (let c = 0; c < members.length; c++) if (start < 0 || best[c] > best[start]) start = c
  const chain: string[] = []
  for (let c = start; c >= 0; c = nextOf[c]) chain.push(...[...members[c]].sort())
  return { depth: start < 0 ? 0 : best[start], chain }
}

/** El veredicto de UNA arista nueva sobre la región recorrida. */
export type GroupNestingVerdict =
  | { kind: 'ok'; depth: number }
  | { kind: 'cycle'; depth: null }
  | { kind: 'too-deep'; depth: number; chain: string[] }
  | { kind: 'too-many-groups'; depth: null; budget: GroupDepthBudgetKind }

/** Cómo leer los vecinos de un conjunto de grupos (UNA llamada por nivel del BFS en SQL; una `Read` por grupo en FGA). */
export interface GroupNeighbourReader {
  /** Las aristas VIVAS cuyo `child` está en `groups` (los grupos que los contienen). */
  parentsOf(groups: string[]): Promise<GroupEdge[]>
  /** Las aristas VIVAS cuyo `parent` está en `groups` (los grupos que contienen). */
  childrenOf(groups: string[]): Promise<GroupEdge[]>
}

/**
 * **El veredicto de la arista `child ⊂ parent`** (gate de escritura de R1): recorre hacia ARRIBA desde `parent` y hacia
 * ABAJO desde `child` (BFS por niveles, una lectura por nivel), y decide:
 *
 *  - `cycle` si `child` es `parent` o aparece por encima de `parent` (la arista lo cerraría);
 *  - `too-deep` si el camino MÁS LARGO que atraviesa la arista (`alto(parent) + 1 + bajo(child)`) supera `limit` — y
 *    también, sin terminar el recorrido, en cuanto los niveles del BFS ya lo superan (el camino corto es una cota
 *    inferior del largo);
 *  - `too-many-groups` si la región pasa de `maxNodes`, o si el LECTOR agota su presupuesto (`GroupDepthBudgetExceeded`:
 *    requests, tuplas o deadline — `openfga`, cierre de R1 · 🟠 1 del auditor);
 *  - `ok` en otro caso.
 *
 * La arista misma (si ya existe: renovación) no se cuenta dos veces.
 */
export async function groupNestingVerdict(
  edge: GroupEdge,
  limit: number,
  reader: GroupNeighbourReader,
  maxNodes: number = GROUP_DEPTH_MAX_NODES
): Promise<GroupNestingVerdict> {
  try {
    return await walkGroupNesting(edge, limit, reader, maxNodes)
  } catch (error) {
    if (error instanceof GroupDepthBudgetExceeded) return { kind: 'too-many-groups', depth: null, budget: error.budget }
    throw error
  }
}

async function walkGroupNesting(edge: GroupEdge, limit: number, reader: GroupNeighbourReader, maxNodes: number): Promise<GroupNestingVerdict> {
  if (edge.child === edge.parent) return { kind: 'cycle', depth: null }
  const region: GroupEdge[] = [edge]
  const seen = new Set<string>([edge.child, edge.parent])
  const isSelf = (e: GroupEdge) => e.child === edge.child && e.parent === edge.parent
  // Hacia ARRIBA desde `parent`.
  let frontier = [edge.parent]
  let upLevels = 0
  const above = new Set<string>([edge.parent])
  while (frontier.length > 0) {
    const found = (await reader.parentsOf(frontier)).filter((e) => !isSelf(e))
    const nextFrontier: string[] = []
    for (const e of found) {
      region.push(e)
      if (e.parent === edge.child) return { kind: 'cycle', depth: null }
      if (!above.has(e.parent)) {
        above.add(e.parent)
        nextFrontier.push(e.parent)
      }
      seen.add(e.parent)
    }
    if (nextFrontier.length > 0) upLevels += 1
    if (upLevels + 1 > limit) return { kind: 'too-deep', depth: upLevels + 1, chain: [] }
    if (seen.size > maxNodes) return { kind: 'too-many-groups', depth: null, budget: 'nodes' }
    frontier = nextFrontier
  }
  // Hacia ABAJO desde `child`.
  frontier = [edge.child]
  let downLevels = 0
  const below = new Set<string>([edge.child])
  while (frontier.length > 0) {
    const found = (await reader.childrenOf(frontier)).filter((e) => !isSelf(e))
    const nextFrontier: string[] = []
    for (const e of found) {
      region.push(e)
      if (e.child === edge.parent || above.has(e.child)) return { kind: 'cycle', depth: null }
      if (!below.has(e.child)) {
        below.add(e.child)
        nextFrontier.push(e.child)
      }
      seen.add(e.child)
    }
    if (nextFrontier.length > 0) downLevels += 1
    if (upLevels + 1 + downLevels > limit) return { kind: 'too-deep', depth: upLevels + 1 + downLevels, chain: [] }
    if (seen.size > maxNodes) return { kind: 'too-many-groups', depth: null, budget: 'nodes' }
    frontier = nextFrontier
  }
  const { depth, chain } = groupChainDepth(region)
  if (depth > limit) return { kind: 'too-deep', depth, chain }
  return { kind: 'ok', depth }
}

/**
 * **El error de un veredicto que no es `ok`** (cierre-3 de R1 · R-2 del re-ataque; decisión firmada (3): lo transitorio es
 * 503): el agotamiento del DEADLINE del presupuesto (`budget: 'deadline'`) no dice nada de los datos —el mismo grafo da
 * `ok` con el servidor descargado— sino que el backend va LENTO (o lo satura otro tenant del store compartido), así que es
 * 503 `AuthorizationBackendError` transitorio —NO la subclase timeout: la escritura no ocurrió y el manager no notifica
 * `indeterminate` (invariante 13)— y nunca el 422 «aplana la anidación», que un cliente no reintenta. Las otras cotas
 * (`nodes`, `reads`, `tuples`) son deterministas sobre los datos y siguen siendo 422 `too-many-groups`.
 */
export function groupNestingError(
  driver: string,
  verdict: Exclude<GroupNestingVerdict, { kind: 'ok' }>,
  edge: string,
  limit: number
): GroupDepthLimitError | AuthorizationBackendError {
  if (verdict.kind === 'too-many-groups' && verdict.budget === 'deadline') {
    const error = new AuthorizationBackendError(
      driver,
      'relate',
      new Error(`la comprobación de anidación de grupos agotó su deadline total de ${GROUP_DEPTH_DEADLINE_MS} ms`)
    )
    error.message =
      `El backend de autorización '${driver}' no respondió a tiempo para comprobar la arista de anidación ${edge} ` +
      `(deadline total del veredicto: ${GROUP_DEPTH_DEADLINE_MS} ms; relate). Es transitorio (el servidor va lento): ` +
      'reintenta. No se ha escrito nada.'
    return error
  }
  return groupDepthLimitError(verdict, edge, limit)
}

/** El 422 de un veredicto que no es `ok` (letra de `E_AUTHZ_SCOPE_DEPTH_LIMIT`: el `message` no nombra el backend). */
export function groupDepthLimitError(
  verdict: Exclude<GroupNestingVerdict, { kind: 'ok' }>,
  edge: string,
  limit: number
): GroupDepthLimitError {
  const head =
    verdict.kind === 'cycle'
      ? `relate: la arista de anidación ${edge} cerraría un CICLO de grupos (el grupo contenedor ya es miembro, directa o ` +
        'transitivamente, del que quieres meter)'
      : verdict.kind === 'too-many-groups'
        ? `relate: la arista de anidación ${edge} no se puede comprobar: la región de grupos anidados que habría que recorrer ` +
          (verdict.budget === 'nodes'
            ? `pasa de ${GROUP_DEPTH_MAX_NODES} grupos`
            : `agota el presupuesto de la comprobación (${verdict.budget === 'reads' ? `${GROUP_DEPTH_MAX_READS} lecturas` : verdict.budget === 'tuples' ? `${GROUP_DEPTH_MAX_TUPLES} tuplas leídas` : `${GROUP_DEPTH_DEADLINE_MS} ms`})`)
        : `relate: la arista de anidación ${edge} dejaría una cadena de ${verdict.chain.length === 0 ? 'al menos ' : ''}` +
          `${verdict.depth} saltos de grupos anidados (grupo⊂grupo, el camino MÁS LARGO que la atraviesa) y el techo es ` +
          `${limit} (maxGroupDepth de la config de relaciones, o el techo del driver)`
  return new GroupDepthLimitError(
    `${head}. No se ha escrito nada. Aplana la anidación (mete a los miembros en un grupo menos profundo) o, si el techo ` +
      'lo fija tu config, revísalo con quien opera el servicio.',
    {
      reason: verdict.kind,
      edge,
      depth: verdict.depth,
      maxGroupDepth: limit,
      ...(verdict.kind === 'too-many-groups' ? { budget: verdict.budget } : {}),
      why: verdict.kind === 'cycle' ? `un ciclo no tiene profundidad definida y el paquete no lo admite al escribir. ${WHY}` : WHY,
      server: SERVER,
    }
  )
}

/** Resultado de una sonda de calibración: el `Check` resolvió con la respuesta esperada, excedió, o dio la OTRA respuesta. */
export type CalibrationProbe = 'ok' | 'too-complex' | 'blind'

/**
 * **La calibración del techo** (decisión 5 + 5-bis, opción (a)): el mayor K en [0, `max`] para el que la sonda
 * POSITIVA (un miembro, T) Y la NEGATIVA (un no-miembro con membresía, F) resuelven — el MÍNIMO de las dos —, por
 * bisección (el borde es determinista en relaciones, M-c: 200/200). Una sonda que da la OTRA respuesta (`blind`: el
 * miembro F, el no-miembro T) es un servidor o un modelo que no evalúa como el medido ⇒ 500, jamás «pasa». Cualquier
 * otro fallo de la sonda (503, deadline) se PROPAGA: quien llama no lo memoriza.
 */
export async function calibrateGroupDepth(
  probe: (depth: number, side: 'positive' | 'negative') => Promise<CalibrationProbe>,
  max: number = GROUP_DEPTH_CALIBRATION_MAX
): Promise<number> {
  const passes = async (k: number): Promise<boolean> => {
    for (const side of ['positive', 'negative'] as const) {
      const outcome = await probe(k, side)
      if (outcome === 'blind') {
        throw new AuthorizationConfigError(
          `calibración del techo de anidación de grupos: la sonda ${side === 'positive' ? 'POSITIVA (un miembro)' : 'NEGATIVA (un no-miembro con membresía)'} ` +
            `con ${k} saltos dio la respuesta CONTRARIA a la esperada. El servidor no evalúa la anidación como el paquete ` +
            'midió (OpenFGA v1.19): no se puede fijar un techo con él, y el paquete no escribe a ciegas. Revisa la versión ' +
            'del servidor y el modelo fijado.'
        )
      }
      if (outcome === 'too-complex') return false
    }
    return true
  }
  let lo = 0
  let hi = max + 1
  while (hi - lo > 1) {
    const mid = Math.floor((lo + hi) / 2)
    if (await passes(mid)) lo = mid
    else hi = mid
  }
  return lo
}
