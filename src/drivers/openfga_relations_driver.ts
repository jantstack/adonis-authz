/**
 * Driver `openfga` del puerto `RelationsDriver` — ReBAC sobre el MISMO store y
 * `modelId` que el driver `facts` de roles (Fase 4, lote 4-4).
 *
 * Store COMPARTIDO (decisión del dueño / juez §2): las relaciones ReBAC viven
 * en el modelo FUSIONADO (`facts` + `group` + los tipos de objeto del
 * consumidor), así que `relate`/`unrelate` son `Write`/delete de tuplas del
 * mismo store, `check` es UN solo `Check` (el modelo resuelve includes +
 * usersets del lado del servidor) y `list*` van por `ListObjects`/`Read`.
 *
 * **La partición va en el ID del objeto y del userset**, no en el modelo:
 * `document:<scopeKey(partition)>|<uuid>`, `group:<scopeKey(partition)>|<uuid>#member`.
 * El cruce de particiones se corta por comparación de string —aquí NO hay
 * trigger como en `database`, así que F-05 (en el manager) + la comparación de
 * string son la ÚNICA defensa de tenant—. El id lleva DOS `|` cuando la
 * partición es un scope no-raíz (`document:unit|<partUuid>|<objUuid>`), así que
 * el parseo es CANÓNICO desde la DERECHA (⚪5, el mismo cuidado que
 * `parseBindingId`): partición = todo menos el ÚLTIMO segmento; el id del
 * objeto es el último y no contiene `|`.
 *
 * **La frontera del 🔴 (F-05) NO vive aquí**: la cierra el `RelationsManager`
 * ANTES de tocar el driver (un `object.type` no declarado ⇒ 422) junto con ⚪4
 * (un tipo reservado no se puede declarar). Si a este driver se le llama en
 * DIRECTO con `object.type: 'role_binding'` (la salida `manager.driver()`, de
 * plataforma), compondría el id de un binding real y escalaría — por eso el
 * caso-exploit del auditor se cierra en el manager, y el runner publica el
 * caso para que un driver de terceros que no lo cumpla NO pase el contrato.
 *
 * Pureza: vive detrás del subpath `@jantstack/adonis-authz/openfga`
 * (`src/openfga.ts`), como el driver `facts` de roles: es lo único que puede
 * tocar `@openfga/sdk` (peer opcional). La abstracción no filtra: ningún error
 * del SDK escapa (todo va por `#guard`, que clasifica con `classifyFgaFailure`, R3).
 */
import {
  OpenFgaClient,
  ConsistencyPreference,
  ClientWriteRequestOnMissingDeletes,
  ClientWriteRequestOnDuplicateWrites,
} from '@openfga/sdk'
import type { ClientBatchCheckItem, ConsistencyPreference as ConsistencyPreferenceType } from '@openfga/sdk'
import {
  AuthorizationBackendError,
  AuthorizationBackendTimeoutError,
  AuthorizationConfigError,
  InvalidIdentityError,
  PurgeIncompleteError,
  RenewalRacedError,
  RenewalUnsafeError,
  ResolutionLimitError,
  UnsupportedOperationError,
  markDeploymentFailure,
  markPartialWrite,
} from '../errors.js'
import { assertPartition, assertSubject, assertRelationId, assertExpiresAt, partitionKey } from '../identity.js'
import { isClock, systemClock } from '../clock.js'
import type { Clock } from '../clock.js'
import { fgaTupleExpiry, isActiveExpiry, resolveGrantExpiry, sameInstant } from '../expiry.js'
import { isRelUserset } from '../types.js'
import type {
  RelObject,
  RelSubject,
  RelationObjectsPage,
  RelationSubjectsPage,
  RelationPage,
  RelationTuple,
  RelationTuplePage,
  RelationsDriver,
  RelationsDriverCapabilities,
  RelationTransactionOptions,
  RelationWriteOptions,
  RelationDenyOptions,
  RelationDecision,
  ScopeRef,
  SubjectRef,
} from '../types.js'
import type { HolderTypeMap } from './openfga_driver.js'
import { alignBatchResults } from './openfga_driver.js'
import { FGA_MAX_BATCH_CHECK, assertExperimentalOptIn, assertPinnedModel, factsModelDifferences, factsModelDriftError } from './openfga_facts.js'
import type { FactsModelComparison } from './openfga_facts.js'
import { assertCheckManyObjects, distinctObjects, expandByPosition } from '../relations/check_many.js'
import { assertEnumeratePage, assertNoListPage } from '../relations/page.js'
import {
  assertFgaObjectId,
  FACTS_EXPIRY_CONDITION,
  FACTS_GROUP_TYPE,
  FACTS_GROUP_MEMBER_RELATION,
} from './openfga_facts.js'
import {
  assertRelationDeclared,
  assertObjectTypeDeclared,
  assertUsersetSubject,
  assertRelationDenyable,
  assertDenySubject,
  assertDenyNoExpiry,
  denyPhaseOf,
  deniedRelationOf,
  storedRelationKind,
  relationsDown,
  RELATION_DENY_PREFIX,
  RELATION_USERSET_RELATION,
  RELATION_USERSET_TYPE,
} from '../relations/define_relations_config.js'
import { relationDeleteOrder, relationOrderClass } from '../relations/tuple_order.js'
import {
  GROUP_DEPTH_CALIBRATION_BACKOFF_MS,
  GROUP_DEPTH_RECALIBRATION_MIN_INTERVAL_MS,
  GroupDepthBudget,
  assertGroupDepthSettings,
  calibrateGroupDepth,
  groupNestingError,
  groupNestingVerdict,
  isGroupNesting,
  plannedByReconcile,
} from '../relations/group_depth.js'
import type { CalibrationProbe, GroupEdge } from '../relations/group_depth.js'
import type { RelationOrderView } from '../relations/tuple_order.js'
import { fgaFailureError, isServerWriteLimit, withDeadline } from '../shared/backend_guard.js'
import type { RelationsConfig } from '../relations/define_relations_config.js'

export const DEFAULT_TIMEOUT_MS = 5_000
/**
 * **Tope de operaciones por `Write` en FGA** — `--max-tuples-per-write` del servidor, default 100. MEDIDO en v1.19.0
 * (`openfga-dev`, lote D · cierre 1 de D1): 100 deletes en un `Write` entran; 101 —o 50 writes + 51 deletes— es 400
 * «The number of write operations exceeds the allowed limit of 100» y NO se aplica nada (el `Write` es transaccional).
 * Es también la frontera de la purga atómica PARA EL ESCRITOR (`#purgeByFilters`): una purga que cabe aquí es UN
 * `Write`, sin PREFIJO que cortar —un `Check` concurrente SÍ puede observar ese `Write` a medias: lector rasgado, fila
 * «torn read» de Limits, decisión (6a) del dueño—; con más membresías de grupo que esto, el residuo es una fila DECLARADA
 * (README, «Deny on relations»).
 * **Requisito del despliegue: `--max-tuples-per-write` ≥ 100** (README, «Limits»). Un servidor con el tope MÁS BAJO
 * responde 400 `exceeded_entity_limit` al primer `Write` que lo pase, y ése puede no ser el primero de la purga (con
 * tope 50 y `[3 allows][60 membresías][40 denies]` el `Write` de 3 ya se aplicó): el driver lo dice como **500
 * `E_AUTHZ_CONFIG`** nombrando el requisito —no como un 503 que parece transitorio: repetida, la purga vuelve a pedir
 * un `Write` de más de lo que el servidor admite y no termina nunca— y, si ya borró algo, **marcado como escritura
 * parcial** (`indeterminate: true`, invariante 13). Cierre 2 de D1 · ⚪ N3 del auditor (la letra anterior, «503 sin
 * haber borrado nada», era falsa con varios `Write`). Uno con el tope más alto no cambia nada (el driver sigue partiendo
 * en 100). Sin opción para bajarlo: la cota es del servidor y el remedio es su arranque.
 */
export const RELATIONS_PURGE_WRITE_MAX = 100
/** Tamaño de página de `Read` (máximo del servidor). */
const READ_PAGE_SIZE = 100
/**
 * Cota de páginas de una enumeración por `Read`. Un `continuation_token` que
 * no avanza (servidor roto, proxy, caché) sería un bucle que ningún deadline
 * corta (el deadline es por llamada). Mismo patrón que el driver de roles.
 */
const MAX_READ_PAGES = 10_000
/**
 * El tope de `ListObjects` del servidor por defecto (`OPENFGA_LIST_OBJECTS_MAX_RESULTS`).
 * `ListObjects` NO devuelve señal de truncado ni `continuation_token`: corta al
 * tope y calla. La única forma honesta de detectar el corte es comparar el
 * número de resultados con el tope CONFIGURADO del servidor —de ahí la opción
 * `listObjectsMaxResults`—: si vuelven `>= tope`, no se puede prometer que la
 * lista esté completa ⇒ `truncated: true` (lección S16/L0.7: nunca una lista
 * parcial MUDA). Ponerlo por debajo del tope real del servidor daría un
 * truncado FALSO (el servidor devolvió todo); por encima, se perdería el corte.
 */
const DEFAULT_LIST_OBJECTS_MAX = 1_000
/**
 * **B4 (plan 2.5 · lote B): el corte EFECTIVO de `ListObjects` del servidor**.
 * Pasado, el servidor devuelve lo que llevaba resuelto con 200 y SIN señal
 * (analista M4, medido): la segunda forma —además del tope— de una lista
 * parcial muda. El driver mide cada llamada con un reloj MONÓTONO y, si duró
 * ≥ `LIST_OBJECTS_DEADLINE_RATIO` × el corte configurado, señala
 * `truncated: true` (la MISMA señal que el tope). **El corte efectivo es el
 * MENOR de dos** (cierre 2 del lote B · 🟠 N1, medido por el auditor contra
 * OpenFGA v1.19.0): `--listObjects-deadline` (3 s por defecto) si ≠ 0 y, si es
 * 0, `--request-timeout` (3 s por defecto) — `list_objects.go` solo pone su
 * propio timeout cuando el deadline ≠ 0 y, si no, hereda el ctx del
 * interceptor de `--request-timeout`, que corta igual con un 200 mudo (con
 * `--request-timeout=30ms`: `200 objects 0 of 40000`). «Sin deadline» no
 * existe: el servidor siempre corta en alguno. **El corte efectivo es el MENOR
 * de `--listObjects-deadline` (si ≠ 0), `--request-timeout` y, por HTTP,
 * `--http-upstream-timeout` (5 s por defecto en el gateway)** (⚪ N10, cierre 3
 * del lote B: el tercer corte, no medido para `ListObjects`, también cuenta);
 * declara ESE menor en `listObjectsDeadlineMs` — y nunca por encima del
 * `timeoutMs` del cliente: la señal tiene que poder saltar antes de que el
 * cliente corte (500 al construir si no).
 */
export const DEFAULT_LIST_OBJECTS_DEADLINE_MS = 3_000
export const LIST_OBJECTS_DEADLINE_RATIO = 0.9

/**
 * **SOLO TESTS** (⚪ 9 del cierre 1 del lote B): la clave —un símbolo— bajo la que
 * un test inyecta la fuente del reloj MONÓTONO en ms con el que `#listObjectsPage`
 * mide cada `ListObjects` (default `performance.now`). Fuera del tipo publicado
 * `OpenFgaRelationsDriverOptions` y NO re-exportada por `/openfga`: un
 * `monotonic: () => 0` en producción apagaría la señal del deadline, y una opción
 * con ese poder no viaja en la superficie pública. No es el reloj de pared
 * (`now`, que decide la caducidad): una ventana se mide con un reloj que no
 * salta (2E · H3), y así el caso del deadline corre sin `sleep`.
 */
export const MONOTONIC_CLOCK: unique symbol = Symbol('OpenFgaRelationsDriver.monotonic')

/**
 * Ignora duplicados en el `Write` de una tupla que NO estaba (idempotencia de
 * dos `relate` concurrentes idénticos). Cambiar la caducidad de una que SÍ
 * está es delete+write (R-15): FGA no admite reescribir la condición de una
 * tupla existente y un `Ignore` la dejaría con la caducidad vieja en silencio.
 */
const IGNORE_DUPLICATE_WRITES = {
  conflict: { onDuplicateWrites: ClientWriteRequestOnDuplicateWrites.Ignore },
}
/** Ignora deletes de tuplas ya ausentes (re-unrelate no-op seguro, invariante 6). */
const IGNORE_MISSING_DELETES = {
  conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore },
}

export interface OpenFgaRelationsDriverOptions {
  apiUrl: string
  storeId: string
  /**
   * **Pin del model FUSIONADO — OBLIGATORIO** (L11, decisión del dueño 2026-10-17 (2): D14 ampliado a los dos drivers
   * `openfga`, siempre). Sin él cada `Check` evalúa contra el ÚLTIMO modelo del store mientras la puerta L11 compara
   * el del arranque. `openfga:provision` lo imprime (`OPENFGA_MODEL_ID`).
   */
  modelId: string
  /** Holders del consumidor: morph name → tipo FGA. El MISMO mapa del driver de roles. */
  holderTypes: HolderTypeMap
  /** Deadline de cada llamada en ms (default 5000): vencido ⇒ 503. */
  timeoutMs?: number
  /** Consistencia pedida al servidor (default `higher_consistency`, como el driver de roles). */
  consistency?: 'higher_consistency' | 'minimize_latency'
  /**
   * El tope de `ListObjects` del servidor (`OPENFGA_LIST_OBJECTS_MAX_RESULTS`).
   * Default 1000 (el default de OpenFGA). Cuando `listObjects` recibe `>= este`
   * resultados, señala `truncated: true`. Ponlo igual que el del servidor.
   */
  listObjectsMaxResults?: number
  /**
   * **El corte EFECTIVO de `ListObjects` del servidor** (default 3 000 ms =
   * `DEFAULT_LIST_OBJECTS_DEADLINE_MS`; B4). Una llamada que dure ≥ 0,9 × este
   * valor (`LIST_OBJECTS_DEADLINE_RATIO`) se señala `truncated: true`: pasado
   * su corte el servidor responde 200 con la lista parcial y sin señal. **Es
   * el MENOR de `--listObjects-deadline` (si ≠ 0) y `--request-timeout`**
   * (cierre 2 del lote B · 🟠 N1, medido por el auditor contra OpenFGA v1.19.0:
   * con `--listObjects-deadline=0` el `--request-timeout`, 3 s por defecto,
   * sigue cortando con un 200 mudo — `0` NO es «sin deadline»). Entero > 0;
   * `Infinity` (la receta del cierre 1 para el deadline 0), `NaN`, ≤ 0 o no
   * entero ⇒ 500 `E_AUTHZ_CONFIG` al construir: el servidor siempre corta en
   * alguno de los dos y una lista muda es justo lo que B4 existe para impedir.
   * `0` es el valor del SERVIDOR, no del driver (aquí significaría «todo
   * truncado»). **El corte efectivo es el MENOR de los TRES**: `--listObjects-deadline`
   * (si ≠ 0), `--request-timeout` y, por HTTP, `--http-upstream-timeout` (5 s por
   * defecto en el gateway; ⚪ N10, cierre 3 del lote B): declara ese menor. Los
   * DOS primeros a 0 no se soportan: lo que hace entonces el gateway no está
   * medido para `ListObjects`, y el paquete no promete «sin deadline» sobre
   * nada que no haya medido. **Y nunca por encima de `timeoutMs`** (el deadline
   * del cliente, 5 s por defecto): la señal tiene que poder saltar antes de que
   * el cliente corte, así que `listObjectsDeadlineMs > timeoutMs` es 500 al
   * construir (`Number.MAX_SAFE_INTEGER` era «sin deadline» con otro nombre).
   */
  listObjectsDeadlineMs?: number
  /** Dónde avisar de tuplas del store que el driver no puede parsear. */
  logger?: { warn(message: string): void }
  /**
   * Reloj de pared que DECIDE la caducidad (R-15, 2.5 · J1): el `current_time`
   * de cada `Check`/`ListObjects` (la condición `not_expired` se evalúa contra
   * él), el filtro en cliente de `listSubjects` y los tres estados de
   * `expiresAt` en `relate`. Default `systemClock`; en producción lo aplica el
   * `RelationsManager` con `clock` (`withClock`).
   */
  now?: Clock
  /**
   * **`openfga` es EXPERIMENTAL en 2.5.x** (estrategia 2.5.0, firma 4): el MISMO literal versionado que el driver de roles.
   * Sin él, 500 `E_AUTHZ_CONFIG` al construir (primera línea, sin crear el cliente). Opcional en el tipo para que el stub
   * que solo registra la factory compile; obligatorio al construir.
   */
  experimental?: 'openfga@2.5'
}

/**
 * Una tupla leída del store: la clave y lo que dice su condición (L11, `fgaTupleExpiry`): `validUntil` es la caducidad
 * de una `not_expired` legible (`null` sin condición) y `invalid` el porqué cuando la condición es `foreign` o
 * `unparseable` —entonces `validUntil` es `null` y NO significa «permanente»: cada consumidor decide, fail-closed—.
 */
interface StoredRelationTuple {
  user: string
  relation: string
  object: string
  validUntil: Date | null
  invalid?: string
}

/** La condición de una tupla leída, en la forma de `StoredRelationTuple` (el ÚNICO paso por `fgaTupleExpiry`). */
function storedCondition(condition: unknown): { validUntil: Date | null; invalid?: string } {
  const expiry = fgaTupleExpiry(condition)
  if (expiry.kind === 'expiry') return { validUntil: expiry.at }
  if (expiry.kind === 'none') return { validUntil: null }
  return { validUntil: null, invalid: `${expiry.kind}: ${expiry.detail}` }
}

/**
 * **El error de una llamada DENTRO de la espera tras una calibración fallida** (cierre-3 de R1 · R-5): una instancia NUEVA
 * por llamada, con `cause` = el error memorizado. Misma clase, `status`, `code` y `details` que el memorizado, salvo un
 * TIMEOUT (`AuthorizationBackendTimeoutError`), que pasa a 503 `AuthorizationBackendError` no-timeout: lo que venció fue
 * la sonda de OTRA llamada; esta no tocó la red y su escritura no ocurrió, así que el manager no debe notificar
 * `indeterminate` (invariante 13).
 */
function backoffError(memorized: unknown, remainingMs: number): unknown {
  const suffix = ` (la calibración del techo de anidación falló hace poco; en espera ${Math.max(0, Math.ceil(remainingMs))} ms más, sin sondear)`
  if (memorized instanceof AuthorizationBackendTimeoutError) {
    const error = new AuthorizationBackendError('openfga-relations', 'groupDepthLimit', memorized)
    error.message = `${memorized.message}${suffix}`
    return error
  }
  if (!(memorized instanceof Error)) return memorized
  const copy: Error = Object.create(Object.getPrototypeOf(memorized))
  for (const key of Reflect.ownKeys(memorized)) {
    if (key === 'partialWrite' || key === 'stack') continue
    Object.defineProperty(copy, key, Object.getOwnPropertyDescriptor(memorized, key)!)
  }
  Object.defineProperty(copy, 'message', { value: `${memorized.message}${suffix}`, writable: true, configurable: true, enumerable: false })
  Object.defineProperty(copy, 'cause', { value: memorized, writable: true, configurable: true, enumerable: false })
  Error.captureStackTrace?.(copy, backoffError)
  return copy
}

export class OpenFgaRelationsDriver implements RelationsDriver {
  /**
   * Lo que declara (cada valor tiene su cara en `runRelationsDriverContract`):
   *  - `singleCheckRelations: true`: `check` es UN solo `Check` (el modelo
   *    resuelve includes + usersets del lado del servidor).
   *  - `listObjectsInherited: false`: `list*` no abren el subárbol de
   *    particiones (invariante 7); `ListObjects` sí resuelve la derivación del
   *    modelo (includes/usersets), que es «directos + derivados», no herencia
   *    de scopes.
   *  - `usersetSubjects: true`: `listSubjects` (`Read`) trae los usersets
   *    directos (`group#member`) junto con los holders.
   *  - `membersOfNative: false`: la membresía TRANSITIVA sería `ListUsers`, que
   *    trunca al tope del servidor; se declara 500 `E_AUTHZ_UNSUPPORTED`, jamás
   *    un userset enumerado a medias (par de `purgeRole` de la 3b).
   *  - `enumerateRelations: true` (4-5): es ORIGEN de `authz:reconcile` de
   *    relaciones — lee el store ENTERO (`Read({})`, la única forma de ver todo
   *    sin filtro por user u objeto: un `Read` por tipo-solo sin user es un 400)
   *    y devuelve SOLO las tuplas de relación de la partición (tipo declarado o
   *    `group`), descartando las de `facts` (scope/role/role_binding).
   *  - `listObjectsTruncation: true`: `ListObjects` trunca al tope del servidor
   *    y este driver lo SEÑALA (medido contra el `:8103` de tope 3) — y desde
   *    B4 (plan 2.5) también cuando la llamada roza el DEADLINE del servidor
   *    (≥ 0,9 × `listObjectsDeadlineMs`), la otra forma de lista parcial muda.
   *  - `injectableClock: true` (R-15): `withClock(now)` fija el reloj que viaja
   *    como `current_time` y filtra `listSubjects`, como el driver de roles.
   */
  readonly capabilities: RelationsDriverCapabilities = Object.freeze({
    singleCheckRelations: true,
    listObjectsInherited: false,
    usersetSubjects: true,
    membersOfNative: false,
    enumerateRelations: true,
    listObjectsTruncation: true,
    injectableClock: true,
    // Lote D · D1: el deny es la relación `denied_<rel>` del modelo fusionado (`X = … but not denied_X`); el corte lo
    // evalúa el SERVIDOR en `check`/`batchCheck`/`ListObjects` (una lista cortada es un subconjunto: fail-closed).
    relationDenies: true,
    // Cierre 2 de D2 · 🟠 N1: `false` EXPLÍCITO — FGA no reemplaza la misma clave en un `Write` (M5): `relate` renueva
    // con DOS (delete, write). Por eso NIEGA renovar una membresía que transporta un deny (409
    // `E_AUTHZ_RENEWAL_UNSAFE`, cero escrituras) y marca parcial la renovación permitida cuyo 2.º `Write` falla.
    atomicRenewal: false,
    // L-2/L-5 (panel `{trx}`, (C)): `false` EXPLÍCITO, y no puede ser otra
    // cosa — una tupla no entra en una transacción SQL: el store es otro
    // servicio y no hay 2PC, así que «los dos o ninguno» con la transacción
    // del consumidor es una promesa que este driver no puede hacer, y no la
    // hace. `{ transaction }` es 500 `E_AUTHZ_UNSUPPORTED` por llamada, en el
    // `RelationsManager` (puerta 1) Y en el driver (`#rejectTransaction`,
    // para quien entre por `manager.driver()` o por `reconcileRelations`),
    // con CERO llamadas al store (L-5 lo fija contra el `:8101` con espía
    // sobre el cliente). La alternativa que SÍ existe es para el ÁRBOL de
    // scopes: `scopes.outbox` encola en tu transacción y `authz:scopes:relay`
    // aplica. Para las RELACIONES no hay outbox (el panel la descartó:
    // fail-open medido durante el lag); el consumidor lee esta capacidad y
    // ajusta (usa `database` para lo que tenga que ir en su transacción, o
    // `requireTransactionalWrites` para fallar al arrancar).
    transactionalWrites: false,
    // Estrategia 2.5.0 · firma 4 (regla D15: opcional, normalizada a `false`): EXPERIMENTAL en 2.5.x, como el de roles.
    experimental: true,
  })

  private readonly client!: OpenFgaClient
  readonly #config: RelationsConfig
  readonly #options: OpenFgaRelationsDriverOptions
  readonly #now: Clock
  readonly #holderTypes: HolderTypeMap
  readonly #fgaToMorph: Record<string, string>
  readonly #timeoutMs: number
  readonly #consistency: ConsistencyPreferenceType
  readonly #listObjectsMax: number
  readonly #listObjectsDeadlineMs: number
  readonly #monotonic: () => number
  readonly #logger: { warn(message: string): void }
  /**
   * **La comparación modelo ↔ config de L11** (`#modelGate`): se lee UNA vez por proceso (`readAuthorizationModel` del
   * `modelId` fijado, obligatorio) y se comparte con las vistas `withClock` (objeto que se muta). Un fallo transitorio
   * al leerla no se memoriza (503 y se reintenta en la siguiente).
   */
  #modelMemo: { gate?: Promise<FactsModelComparison> } = {}
  /**
   * **La calibración del techo de anidación de grupos** (R1, decisión 5 + 5-bis): UNA por proceso, compartida con las
   * vistas `withClock` (objeto que se muta, como `#modelMemo`). Se memoriza SOLO el éxito: un fallo (503, deadline, el
   * 500 de una sonda ciega) no se queda — la siguiente operación vuelve a calibrar (C13a), pero no antes de
   * `GROUP_DEPTH_CALIBRATION_BACKOFF_MS` (`failure`: hasta entonces se relanza ese mismo error sin sondear; cierre-2 de
   * R1 · D5). Y un 503 `E_AUTHZ_RESOLUTION_LIMIT` de una lectura invalida el éxito memorizado, como mucho una vez cada
   * `GROUP_DEPTH_RECALIBRATION_MIN_INTERVAL_MS` (`invalidatedAt`; P2 del juez): el límite BAJADO en el servidor se ve
   * sin reiniciar la app.
   */
  #groupDepthMemo: { calibrated?: Promise<number>; failure?: { at: number; error: unknown }; invalidatedAt?: number } = {}

  readonly diagnostics = { unparseableTuples: 0 }

  constructor(config: RelationsConfig, options: OpenFgaRelationsDriverOptions) {
    // Estrategia 2.5.0 · firma 4: `openfga` es EXPERIMENTAL en 2.5.x. PRIMERA línea: sin el token, 500 sin crear el cliente
    // (la vista `withClock` reconstruye con las MISMAS opciones, así que hereda el token y vuelve a pasar por aquí).
    assertExperimentalOptIn('OpenFgaRelationsDriver', (options as { experimental?: unknown } | undefined)?.experimental)
    // Cierre de R1 · 🟡 4 del auditor: el driver RE-VALIDA el techo de la config (una config extendida con spread no pasó
    // por `defineRelationsConfig`; `NaN` apagaba el gate en silencio). 500 al construir.
    assertGroupDepthSettings(config.maxGroupDepth, config.enforceGroupDepth, 'OpenFgaRelationsDriver')
    this.#config = config
    this.#options = options
    this.#now = options.now ?? systemClock
    this.#holderTypes = options.holderTypes
    this.#fgaToMorph = Object.fromEntries(Object.entries(options.holderTypes).map(([morph, fga]) => [fga, morph]))
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.#consistency =
      options.consistency === 'minimize_latency'
        ? ConsistencyPreference.MinimizeLatency
        : ConsistencyPreference.HigherConsistency
    this.#listObjectsMax = options.listObjectsMaxResults ?? DEFAULT_LIST_OBJECTS_MAX
    const deadline = options.listObjectsDeadlineMs ?? DEFAULT_LIST_OBJECTS_DEADLINE_MS
    // 🟠 N1 (cierre 2 del lote B): `Infinity` se RETIRA. Con `--listObjects-deadline=0`
    // el `--request-timeout` del servidor sigue cortando con un 200 mudo
    // (medido, v1.19.0), así que «sin deadline» era una receta para la lista
    // parcial muda que B4 impide. Solo un entero > 0: el corte efectivo.
    if (!(Number.isInteger(deadline) && deadline > 0)) {
      throw new AuthorizationConfigError(
        `OpenFgaRelationsDriver: listObjectsDeadlineMs debe ser un entero > 0 en ms: el corte EFECTIVO de ListObjects ` +
          `de tu servidor, que es --listObjects-deadline si no es 0 y, si es 0, --request-timeout (3 s por defecto; ` +
          `medido en OpenFGA v1.19.0: con el deadline a 0 el request-timeout corta igual con un 200 mudo). El servidor ` +
          `siempre corta en alguno de los dos; declara el menor. No hay «sin deadline» (Infinity ya no se admite) ` +
          `(llegó ${String(options.listObjectsDeadlineMs)}); default ${DEFAULT_LIST_OBJECTS_DEADLINE_MS}.`
      )
    }
    // ⚪ N10 (cierre 3 del lote B): la señal tiene que poder SALTAR antes de que
    // el cliente corte. Un deadline declarado por encima del `timeoutMs` del
    // cliente (5 s por defecto) nunca alcanza su umbral 0,9 × D —el cliente
    // aborta con 503 antes— y, si el servidor corta ANTES que D, la lista muda
    // pasa como completa (`Number.MAX_SAFE_INTEGER` era «sin deadline» con otro
    // nombre y pasaba `Number.isInteger`). Guarda por construcción, sin tope
    // arbitrario: D ≤ timeoutMs del cliente, o 500.
    if (deadline > this.#timeoutMs) {
      throw new AuthorizationConfigError(
        `OpenFgaRelationsDriver: listObjectsDeadlineMs (${deadline}) no puede ser mayor que el timeoutMs del cliente ` +
          `(${this.#timeoutMs}): la señal tiene que poder saltar antes de que el cliente corte. Con un deadline por encima ` +
          `del timeout el umbral 0,9 × listObjectsDeadlineMs nunca se alcanza (el cliente aborta con 503 antes) y, si el ` +
          `servidor corta antes, la lista parcial muda pasa como completa. Declara el corte EFECTIVO del servidor —el MENOR ` +
          `de --listObjects-deadline (si ≠ 0), --request-timeout y, por HTTP, --http-upstream-timeout— y un timeoutMs ≥ a él.`
      )
    }
    this.#listObjectsDeadlineMs = deadline
    // ⚪ 9 (cierre 1 del lote B): el reloj monótono inyectable SOLO entra por el
    // símbolo (no está en el tipo publicado); la clave de texto `monotonic` de
    // alpha.2 ya no gobierna nada y se rechaza (L5: una opción inerte no cae en
    // silencio en el default).
    if ((options as unknown as Record<string, unknown>).monotonic !== undefined) {
      throw new AuthorizationConfigError(
        `OpenFgaRelationsDriver: 'monotonic' no es una opción pública (era SOLO TESTS); el reloj monótono se inyecta ` +
          `por el símbolo MONOTONIC_CLOCK del módulo del driver, que no se exporta por '/openfga'.`
      )
    }
    const monotonic = (options as unknown as Record<symbol, unknown>)[MONOTONIC_CLOCK]
    if (monotonic !== undefined && typeof monotonic !== 'function') {
      throw new AuthorizationConfigError(`OpenFgaRelationsDriver: [MONOTONIC_CLOCK] debe ser una función () => number (llegó ${typeof monotonic})`)
    }
    this.#monotonic = (monotonic as (() => number) | undefined) ?? (() => performance.now())
    this.#logger = options.logger ?? console
    // **L11 · `modelId` OBLIGATORIO, siempre** (decisión del dueño 2026-10-17 (2); sustituye a D14 —«solo con deny»— y a
    // `#assertPinnedForDecideMany`, P5/P6): sin el pin, la puerta L11 compara el modelo del arranque y el servidor
    // evalúa con el último de AHORA, así que la igualdad no protegería nada.
    assertPinnedModel('OpenFgaRelationsDriver', options.modelId)
    this.client = new OpenFgaClient({
      apiUrl: options.apiUrl,
      storeId: options.storeId,
      authorizationModelId: options.modelId,
      baseOptions: { timeout: this.#timeoutMs },
      retryParams: { maxRetry: 0 },
    })
  }

  /**
   * Vista de este driver con OTRO reloj de pared (R-15, paridad con
   * `AuthorizationDriver.withClock`): MISMO cliente (store, modelo, deadline),
   * solo cambia el `now` que decide la caducidad. Se construye una instancia
   * nueva y se le presta el cliente (el espía de «1 Check» envuelve
   * `client.check` de la instancia base y tiene que seguir viéndolo).
   */
  withClock(now: Clock): RelationsDriver {
    if (!isClock(now)) {
      throw new AuthorizationConfigError(`withClock: now debe ser una función () => Date (llegó ${typeof now})`)
    }
    const view = new OpenFgaRelationsDriver(this.#config, { ...this.#options, now })
    ;(view as unknown as { client: OpenFgaClient }).client = this.client
    // La puerta L11 es del PROCESO: la vista comparte la lectura del modelo (el MISMO objeto, que se muta).
    view.#modelMemo = this.#modelMemo
    view.#groupDepthMemo = this.#groupDepthMemo
    return view
  }

  /** El `context` de todo `Check`/`ListObjects`: la condición `not_expired` se evalúa contra este instante (un `now` por operación). */
  #checkContext(at: Date): { current_time: string } {
    return { current_time: at.toISOString() }
  }

  /** La clave de partición (D4: `partitionKey` de `identity.ts`, la ÚNICA puerta hacia el id del store). */
  #keyOf(partition: ScopeRef): string {
    return partitionKey(partition)
  }

  /* ── Clasificación de fallos (la abstracción no filtra) ─────────────────── */

  /**
   * **El MISMO criterio que el driver de roles** (`guardBackendErrors`,
   * `openfga_driver.ts`; cierre-2 de alpha.3, ⚪ 5 del re-ataque): un
   * deadline TOTAL PROPIO por llamada (`withDeadline`, `timeoutMs`) que es lo
   * que dice «venció el deadline» —503 `E_AUTHZ_BACKEND_TIMEOUT`, indeterminado—,
   * y para lo que el cliente lanza por su cuenta el `isTimeoutLike` ESTRICTO
   * de `backend_guard.ts` (`ECONNABORTED`/`ETIMEDOUT`/`.timeout` numérico/
   * `KnexTimeoutError` y, desde R3, el `FgaError` sin respuesta, por la cadena de `cause`); el RESTO lo clasifica
   * `classifyFgaFailure` (R3: transitorio 503, `E_AUTHZ_RESOLUTION_LIMIT` 503, despliegue 500, carrera 409, 4xx
   * desconocido 500). Hasta el cierre-2 este
   * driver duplicaba la función con una rama por SUBSTRING del mensaje
   * (`/timeout/i`): un error que decía «no es timeout» salía como timeout con
   * `indeterminate: true` sin haber borrado nada, y el docblock afirmaba en
   * falso «mismo criterio que roles».
   */
  async #guard<T>(operation: string, fn: () => Promise<T>, write = false): Promise<T> {
    const fail = (error: unknown): Error => {
      // Un error del paquete (422/500 ya clasificado) se propaga tal cual.
      if (error instanceof InvalidIdentityError || error instanceof PurgeIncompleteError) return error
      // R3 (decisión del dueño 2026-10-17 (3)): la clase la decide `classifyFgaFailure`, el MISMO punto de paso que el
      // driver de roles (por `statusCode` + `apiErrorCode`, jamás por el mensaje).
      // Cierre de R3 (🟡 R3-A2): `write` ⇒ el 504 / `deadline_exceeded` del `Write` es indeterminado (timeout).
      const failure = fgaFailureError('openfga-relations', operation, error, { timeoutMs: this.#timeoutMs, write })
      // Cierre-2 de R1 · D5 (P2 del juez): un 503 de profundidad FUERA de la calibración dice que el servidor ya no
      // resuelve lo que el techo memorizado prometía (límite bajado sin reiniciar la app) ⇒ re-calibrar, acotado.
      if (failure instanceof ResolutionLimitError && operation !== 'groupDepthLimit') this.#invalidateGroupDepth()
      return failure
    }
    let pending: Promise<T>
    try {
      pending = fn()
    } catch (error) {
      throw fail(error)
    }
    return withDeadline(
      pending.catch((error: unknown) => {
        throw fail(error)
      }),
      this.#timeoutMs,
      () => new AuthorizationBackendTimeoutError('openfga-relations', operation, this.#timeoutMs)
    )
  }

  /* ── L11: el modelo FIJADO es el que genera la config (una puerta, por tipo) ─────────────────────────── */

  /**
   * **La lectura del modelo, UNA por proceso** (L11; memo compartido con las vistas `withClock` — es un OBJETO que se
   * MUTA, nunca se reasigna en la vista, H11 b): `readAuthorizationModel` del `modelId` FIJADO (obligatorio desde L11) y
   * `factsModelDifferences` contra la config de este proceso, con el MISMO mapa de holders que usa `openfga:provision`
   * (H11 a). Se memoriza el ÉXITO de la lectura —también si hay diferencias: el modelo fijado no cambia (C13 b)— y un
   * generador que no puede generar (500, H11 d); **un fallo al LEER el modelo NO se memoriza, sea de la clase que sea**
   * (C13 a; cierre de L11): la siguiente operación vuelve a leer.
   */
  #modelGate(): Promise<FactsModelComparison> {
    const memo = this.#modelMemo
    if (memo.gate) return memo.gate
    // Cierre de L11 (🟡-6 del tester): «comparación hecha ⇒ memo» y «fallo al leer el modelo ⇒ no memo», por la FASE y no
    // por la clase del error — con R3 un 401/403 o un modelo inexistente serán 500 de despliegue y no pueden quedarse
    // memorizados de por vida en el proceso.
    let compared = false
    const gate = this.#guard('readAuthorizationModel', async () => {
      const response: any = await this.client.readAuthorizationModel()
      const served = response?.authorization_model
      if (!Array.isArray(served?.type_definitions)) {
        throw new Error('la respuesta de ReadAuthorizationModel no trae type_definitions; no se toma por un modelo igual')
      }
      return served
    }).then((served) => {
      compared = true
      return factsModelDifferences(served, { holderTypes: this.#holderTypes, relations: this.#config, slice: 'relations' })
    })
    const pending: Promise<FactsModelComparison> = gate.catch((error: unknown) => {
      if (!compared && memo.gate === pending) memo.gate = undefined
      throw error
    })
    memo.gate = pending
    pending.catch(() => {})
    return pending
  }

  /**
   * **La puerta L11** (lote «antes de RC», decisión del dueño 2026-10-17 (1); sustituye a P1–P4 —D-31, R2, la excepción
   * D8 por relación y `#modelDenied`— y a P6 —`#assertPinnedForDecideMany`—): antes de la PRIMERA llamada al servidor
   * de la operación, el modelo que sirve el driver tiene que ser IGUAL al que genera la config en los tipos que la
   * operación toca, más `group` (un `group#member` distinto cambia quién es miembro y, con ello, qué concede un `check`
   * de cualquier tipo), más los holders y las CONDICIONES (deciden la vigencia de toda tupla). Si no, 500
   * `E_AUTHZ_CONFIG` nombrando las diferencias por ruta y CERO llamadas que evalúen o escriban.
   *
   * Sin exenciones (injerto 4 del juez): las purgas y los `list*` pasan la puerta ENTERA —el orden de la purga (L10) se
   * demostró sobre la semántica de la CONFIG y la vigencia la decide la condición del modelo—; `enumerateRelations(Many)`,
   * que es el ORIGEN de una migración y tiene que poder rescatar un store con deriva, pasa SOLO la parte `conditions`
   * (`part: 'conditions'`). El orden en cada operación: la puerta de `{ transaction }`, F-05 y la gramática (422, cero
   * llamadas) van ANTES; la puerta va justo antes de la primera llamada (H1-5).
   */
  async #assertModel(operation: string, types: Iterable<string>, part: 'full' | 'conditions' = 'full'): Promise<FactsModelComparison> {
    const comparison = await this.#modelGate()
    const touched = [...types]
    // Una operación sobre `group` (una membresía) cambia lo que concede o niega CUALQUIER tipo —y su renovación lee los
    // `denied_*` de los tipos con deny (`#carriedDeny`)—: compara todos los tipos de la config.
    const groupWide = touched.includes(RELATION_USERSET_TYPE) ? this.#config.objectTypes.map((t) => t.type) : []
    const relevant = new Set<string>([...touched, ...groupWide, RELATION_USERSET_TYPE, ...Object.values(this.#holderTypes)])
    const hits = comparison.differences.filter((d) =>
      part === 'conditions' ? d.type === null && d.path.startsWith('conditions.') : d.type === null || relevant.has(d.type)
    )
    if (hits.length > 0) throw factsModelDriftError('OpenFgaRelationsDriver', operation, this.#options.modelId, hits)
    return comparison
  }

  /* ── Composición y parseo de ids (⚪5: partición por string en el id) ────── */

  /** `<type>:<scopeKey(partition)>|<objectUuid>`. */
  #objectId(objectType: string, partitionKey: string, objectUuid: string): string {
    // R-16 (defensa en profundidad, paridad con `database`): el `object.id` con
    // la gramática estricta ANTES de componer. Un `|`/`#`/`:`/espacio dentro se
    // escribía (solo se medía la longitud) y luego se perdía en el parseo por
    // el último `|` —invisible en enumeración y `reconcile`—. `manager.driver()`
    // salta el manager, así que el driver aplica la MISMA regla que él.
    assertRelationId(`el id del objeto '${objectType}'`, objectUuid)
    const id = `${objectType}:${partitionKey}|${objectUuid}`
    assertFgaObjectId(objectType, id)
    return id
  }

  /**
   * El `user` FGA de un sujeto: holder ⇒ `<fgaType>:<uuid>`; userset ⇒
   * `<type>:<scopeKey(partition)>|<objUuid>#<relation>`. El userset comparte la
   * partición de la tupla (el manager lo exige).
   */
  #subjectUser(subject: RelSubject, partitionKey: string): string {
    if (isRelUserset(subject)) {
      // alpha.3 · F-05 también en el USERSET del sujeto (la misma función que
      // el manager): `role_binding:<key>|<R>#role` como `user` de un `Read`/
      // `Check`/`Write` no se compone nunca. B3 (lote B): y solo `group#member`
      // — otro userset era un 400 del servidor (503 mal clasificado).
      assertUsersetSubject(this.#config, subject)
      const object = this.#objectId(subject.object.type, partitionKey, subject.object.id)
      return `${object}#${subject.relation}`
    }
    const fgaType = this.#holderTypes[subject.type]
    if (!fgaType) {
      throw new InvalidIdentityError(
        `Holder type '${subject.type}' no está en holderTypes del driver openfga de relaciones ` +
          `(declarados: ${Object.keys(this.#holderTypes).join(', ') || 'ninguno'}).`
      )
    }
    return `${fgaType}:${subject.uuid}`
  }

  /**
   * **Parseo CANÓNICO del id de un objeto de relación** (⚪5): a partir de
   * `<type>:<scopeKey>|<objUuid>`, separa `type` (antes del primer `:`),
   * `partitionKey` (todo menos el ÚLTIMO segmento tras el `:`) y `objectUuid`
   * (el último segmento, que no contiene `|`). Es el MISMO parseo-desde-la-
   * derecha que `parseBindingId`: `lastIndexOf('|')` corta el objeto de la
   * clave de partición (que tiene 1 parte `app` o 2 `<tipo>|<uuid>`). `null` si
   * el id no tiene la forma que este driver escribe.
   */
  #parseObjectId(fullId: string): { type: string; partitionKey: string; objectUuid: string } | null {
    const colon = fullId.indexOf(':')
    if (colon <= 0) return null
    const type = fullId.slice(0, colon)
    const rest = fullId.slice(colon + 1)
    const cut = rest.lastIndexOf('|')
    if (cut < 0) return null
    const partitionKey = rest.slice(0, cut)
    const objectUuid = rest.slice(cut + 1)
    if (!partitionKey || !objectUuid) return null
    return { type, partitionKey, objectUuid }
  }

  /** Un `user` del store de vuelta a `RelSubject`: userset (`…#rel`) o holder (`<fga>:<uuid>`). */
  #userToSubject(user: string): RelSubject | null {
    const hash = user.indexOf('#')
    if (hash >= 0) {
      const parsed = this.#parseObjectId(user.slice(0, hash))
      const relation = user.slice(hash + 1)
      if (!parsed || !relation) return null
      return { object: { type: parsed.type, id: parsed.objectUuid }, relation }
    }
    const colon = user.indexOf(':')
    if (colon <= 0) return null
    const morph = this.#fgaToMorph[user.slice(0, colon)]
    const uuid = user.slice(colon + 1)
    if (!morph || !uuid || uuid === '*' || uuid.includes('|')) return null
    return { type: morph, uuid }
  }

  /* ── Escrituras ─────────────────────────────────────────────────────────── */

  /**
   * `relate` con los tres estados de `expiresAt` (R-15, invariante 10). Se LEE
   * primero la tupla exacta (un `Read` por clave, como `grant` de roles):
   *  - ausente ⇒ un `Write` (con la condición `not_expired` si caduca);
   *  - presente con la caducidad que toca ⇒ no-op (idempotente, invariante 6);
   *  - presente con OTRA ⇒ delete + write en DOS llamadas (FGA no admite
   *    delete+write de la misma clave en un `Write`, ni reescribir su
   *    condición): entre ambas la tupla NO está. Para un allow eso solo
   *    quita (fail-closed, la misma ventana que el `grant` de roles); para una
   *    membresía `group:*#member` que TRANSPORTA un deny, CONCEDERÍA — desde el
   *    cierre 2 de D2 (🟠 N1) esa renovación es 409 `E_AUTHZ_RENEWAL_UNSAFE`
   *    con cero escrituras (`#carriedDeny`), y si el 2.º `Write` de una
   *    renovación permitida falla el error va marcado PARCIAL (`markPartialWrite`).
   */
  /**
   * **`{ transaction }` se rechaza también AQUÍ** (L-5, defensa en
   * profundidad como F-05 en L-0): la puerta 1 vive en el `RelationsManager`,
   * pero `manager.driver()` y `reconcileRelations` entran por el driver; sin
   * esta guarda un `{ transaction }` por ahí escribiría la tupla en el store
   * IGNORANDO la transacción — una escritura que finge ir en tu transacción y
   * que tu rollback no deshace, que es exactamente el fail-open que
   * `transactionalWrites: false` declara no poder evitar. Primera línea de
   * las cuatro escrituras, antes de F-05, del `Read` y del `Write`: CERO
   * llamadas al cliente.
   */
  #rejectTransaction(operation: string, options: RelationTransactionOptions | undefined): void {
    if (options?.transaction === undefined || options.transaction === null) return
    throw UnsupportedOperationError.transactionalDriver(`relations.${operation}`, 'openfga', 'relations')
  }

  async relate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    options?: RelationWriteOptions
  ): Promise<void> {
    this.#rejectTransaction('relate', options)
    // L-0 · F-05 en el DRIVER (defensa en profundidad, la MISMA función que el
    // manager): `manager.driver()` y `reconcileRelations` entran por aquí, y en
    // el store COMPARTIDO un tipo no declarado (`role_binding`) compondría el
    // id exacto de un binding de roles. Corta ANTES del `Read` y del `Write`.
    assertRelationDeclared(this.#config, object, relation)
    assertPartition(partition)
    assertExpiresAt(options?.expiresAt)
    const partitionKey = this.#keyOf(partition)
    const objectId = this.#objectId(object.type, partitionKey, object.id)
    const user = this.#subjectUser(subject, partitionKey)
    const key = { user, relation, object: objectId }
    const now = this.#now()
    await this.#assertModel('relate', [object.type])
    const current = await this.#readTuple('relate', key)
    // L11 · H8: la clave YA existe con una condición que el paquete no escribe (`foreign`) o no sabe leer
    // (`unparseable`). Tratarla como «sin caducidad» haría de este `relate` un no-op mudo (y la tupla inerte para el
    // servidor, M-a); como «vencida», una renovación en dos `Write` sin mirar portadoras. 409, cero escrituras, receta.
    if (current?.invalid !== undefined) {
      throw RenewalUnsafeError.foreignCondition('relate', `${objectId}#${relation}@${user}`, current.invalid)
    }
    const previous = current ? current.validUntil : null
    const expiresAt = resolveGrantExpiry(previous, options?.expiresAt, now)
    if (current && sameInstant(previous, expiresAt)) return
    // R1 (decisión del dueño 2026-10-17 (5)): una arista de anidación que queda VIVA —nueva, renovada o revivida— pasa el
    // gate del techo (calibrado, o el `maxGroupDepth` menor de la config) ANTES de cualquier `Write`: 422 y cero escrituras.
    // El no-op idéntico de ARRIBA va ANTES (invariante 6: un `relate` repetido de una arista preexistente no se vuelve 422).
    if (
      isGroupNesting(subject, relation, object) &&
      isActiveExpiry(expiresAt, now) &&
      !plannedByReconcile(options, partition, { child: subject.object.id, parent: object.id })
    ) {
      const limit = await this.groupDepthLimit()
      // El presupuesto (y su deadline TOTAL) empieza DESPUÉS de la calibración: el primer `relate` de un proceso en frío
      // paga la calibración aparte y no puede dar un 422 espurio por ella (cierre de R1, panel).
      const budget = new GroupDepthBudget()
      if (limit !== null) await this.#assertGroupNesting(partitionKey, { child: subject.object.id, parent: object.id }, now, limit, budget)
    }
    const tuple = expiresAt
      ? { ...key, condition: { name: FACTS_EXPIRY_CONDITION, context: { valid_until: expiresAt.toISOString() } } }
      : key
    if (current) {
      // Cierre 2 de D2 · 🟠 N1 (decisión del dueño 2026-10-15 (9)): una membresía que TRANSPORTA un deny no se renueva
      // con dos `Write` — entre el delete y el write el sujeto quedaría sin el deny y concedería. 409, CERO escrituras.
      // Cierre 3 de D2 · ⚪ C2-4: una membresía YA VENCIDA no conecta nada (el deny ya no alcanza al sujeto por ella), así
      // que no hay ventana que proteger: se reescribe sin comprobar portadora (hasta el cierre 3 era un 409 espurio).
      const guarded = object.type === RELATION_USERSET_TYPE && isActiveExpiry(previous, now)
      const membership = `${objectId}#${relation}@${user}`
      if (guarded) {
        const carried = await this.#carriedDeny(objectId, partitionKey, now)
        if (carried !== null) throw RenewalUnsafeError.carrier(membership, carried)
      }
      await this.#guard('relate', () => this.client.write({ deletes: [key] }, IGNORE_MISSING_DELETES), true)
      // Cierre 2 de D2 · 🟠 N1 (b): el delete YA entró — si el write falla, la escritura es PARCIAL (invariante 13: el
      // manager notifica `indeterminate: true`); hasta el cierre era un 503 «sin escribir» con la tupla borrada.
      try {
        await this.#guard('relate', () => this.client.write({ writes: [tuple] }, IGNORE_DUPLICATE_WRITES), true)
      } catch (error) {
        // Cierre 3 de D2 · 🟡 C2-3: la membresía quedó BORRADA. Si entre la comprobación y el delete entró un deny en el
        // grupo (TOCTOU), ese deny ya no alcanza al sujeto —y no lo alcanzará hasta que la membresía se reescriba—: el
        // error parcial lo NOMBRA (`carriedDeny`) con la receta. Mejor esfuerzo: si la re-lectura también falla, se dice.
        if (guarded && error !== null && typeof error === 'object') {
          annotateRacedDeny(error, membership, await this.#recheckCarried(objectId, partitionKey, now))
        }
        throw error !== null && typeof error === 'object' ? markPartialWrite(error) : error
      }
      // Cierre 3 de D2 · 🟡 C2-3: la RE-COMPROBACIÓN. Un deny que entró entre `#carriedDeny` y los dos `Write` no alcanzó
      // al sujeto durante la ventana; la renovación se aplicó (el estado final es correcto) y el error lo dice, marcado
      // parcial (el manager notifica `indeterminate: true`). La ventana NO se cierra (FGA no tiene una primitiva para
      // serializar `deny` contra la renovación): deja de ser muda. README «Every other renewal stays two `Write`s».
      if (guarded) {
        const recheck = await this.#recheckCarried(objectId, partitionKey, now)
        if (recheck.deny !== null) throw markPartialWrite(RenewalRacedError.raced(membership, recheck.deny))
        if (recheck.error !== undefined) {
          const error = recheck.error
          throw error !== null && typeof error === 'object'
            ? markPartialWrite(annotateRacedDeny(error, membership, recheck, true))
            : error
        }
      }
      return
    }
    await this.#guard('relate', () => this.client.write({ writes: [tuple] }, IGNORE_DUPLICATE_WRITES), true)
  }

  /**
   * **El techo de anidación de grupos de ESTE driver** (lote «antes de RC» · R1, decisiones del dueño 2026-10-17 (5) y
   * (5-bis), opción (a)): ACTIVO por defecto. Se CALIBRA contra el servidor (`#calibratedGroupDepth`) y es el mínimo de
   * la sonda positiva y la negativa (22 en OpenFGA v1.19 con `--resolve-node-limit` por defecto, medido en F0 · M-c); el
   * `maxGroupDepth` de la config solo puede BAJARLO — uno mayor que el calibrado es 500 `E_AUTHZ_CONFIG` con las dos
   * cifras (el despliegue promete un techo que el servidor no resuelve) —, y `false` lo apaga de forma explícita (sin
   * calibrar). Solo lectura: lo usa `relate` antes de escribir una arista `group#member` y el plan de
   * `reconcileRelations` sobre el destino.
   */
  async groupDepthLimit(): Promise<number | null> {
    const configured = assertGroupDepthSettings(this.#config.maxGroupDepth, this.#config.enforceGroupDepth, 'OpenFgaRelationsDriver').maxGroupDepth
    if (configured === false) return null
    const calibrated = await this.#calibratedGroupDepth()
    if (configured !== undefined && configured > calibrated) {
      throw Object.assign(
        new AuthorizationConfigError(
          `OpenFgaRelationsDriver: maxGroupDepth = ${configured} en la config de relaciones y el servidor solo resuelve ` +
            `${calibrated} saltos de grupos anidados (calibrado con tuplas contextuales: el mínimo de un miembro y de un ` +
            'no-miembro con membresía). Un techo por encima del calibrado admitiría cadenas que darán 503 ' +
            `E_AUTHZ_RESOLUTION_LIMIT a los no-miembros. Baja maxGroupDepth a ≤ ${calibrated}, o sube ` +
            'OPENFGA_RESOLVE_NODE_LIMIT (--resolve-node-limit) en el servidor y reinicia la app: SUBIR el límite no lo ' +
            'detecta nada (la calibración se memoriza por proceso); BAJARLO sí, sin reinicio — el 503 de profundidad de ' +
            'una lectura la re-calibra, como mucho una vez por minuto.'
        ),
        { details: { maxGroupDepth: configured, calibrated } }
      )
    }
    return configured ?? calibrated
  }

  /**
   * La calibración memorizada (solo el éxito; una en vuelo se comparte). Tras un fallo, durante
   * `GROUP_DEPTH_CALIBRATION_BACKOFF_MS` se relanza la MISMA CLASE de error sin sondear (cierre-2 de R1 · D5: el backoff);
   * después se vuelve a calibrar. Cada llamada de la ventana recibe un error NUEVO con `cause` = el memorizado (cierre-3 ·
   * R-5: compartir la instancia compartía cualquier anotación de un llamador), y un TIMEOUT de la calibración se relanza
   * como 503 no-timeout: la escritura de la ventana no tocó la red, así que no es indeterminada (invariante 13).
   */
  #calibratedGroupDepth(): Promise<number> {
    const memo = this.#groupDepthMemo
    if (memo.calibrated) return memo.calibrated
    if (memo.failure && this.#monotonic() - memo.failure.at < GROUP_DEPTH_CALIBRATION_BACKOFF_MS) {
      return Promise.reject(backoffError(memo.failure.error, GROUP_DEPTH_CALIBRATION_BACKOFF_MS - (this.#monotonic() - memo.failure.at)))
    }
    const pending: Promise<number> = this.#calibrate().then(
      (calibrated) => {
        if (memo.calibrated === pending) memo.failure = undefined
        return calibrated
      },
      (error: unknown) => {
        if (memo.calibrated === pending) {
          memo.calibrated = undefined
          memo.failure = { at: this.#monotonic(), error }
        }
        throw error
      }
    )
    memo.calibrated = pending
    pending.catch(() => {})
    return pending
  }

  /**
   * **Re-calibración tras un 503 de profundidad** (cierre-2 de R1 · D5 (a), P2 del juez): olvida el techo memorizado para
   * que la siguiente escritura de anidación lo vuelva a medir, como mucho UNA vez cada
   * `GROUP_DEPTH_RECALIBRATION_MIN_INTERVAL_MS` por proceso (reloj monótono). Es lo que hace honesta (5-bis) —«nadie
   * recibe 503 dentro del límite»— cuando el operador BAJA el límite del servidor sin reiniciar; subirlo no da 503 y
   * sigue pidiendo reinicio. Sin techo memorizado (nunca calibró, o falló) no hay nada que olvidar.
   */
  #invalidateGroupDepth(): void {
    const memo = this.#groupDepthMemo
    if (memo.calibrated === undefined) return
    const now = this.#monotonic()
    if (memo.invalidatedAt !== undefined && now - memo.invalidatedAt < GROUP_DEPTH_RECALIBRATION_MIN_INTERVAL_MS) return
    memo.calibrated = undefined
    memo.invalidatedAt = now
  }

  /**
   * **La calibración** (decisión 5: «con tuplas contextuales, solo lectura, forma de dominio»; 5-bis: el MÍNIMO de las
   * dos sondas): un `Check` con TODO el grafo en `contextual_tuples` sobre ids que no existen en el store —
   * `<holder>:authz-calibration-member ∈ g0 ⊂ … ⊂ gK` y la relación de DOMINIO del primer tipo declarado sobre
   * `gK#member` (positiva: T), y `<holder>:authz-calibration-outsider ∈ h0 ⊂ h1` (negativa CON membresía: F; sin
   * membresías la sonda es CIEGA, M-c) —, siempre con `HIGHER_CONSISTENCY`. Pasa antes la puerta L11 (el modelo fijado es
   * el de la config). Sin ningún tipo con relación (que acepte `group#member`) calibra con `group#member` y resta 1
   * (T-4: la forma `member` resuelve un salto más que la de dominio).
   */
  async #calibrate(): Promise<number> {
    const domainType = this.#config.objectTypes.find((t) => t.relations.length > 0)
    const domain = domainType ? { type: domainType.type, relation: domainType.relations[0].name } : null
    await this.#assertModel('groupDepthLimit', [domain?.type ?? RELATION_USERSET_TYPE])
    const holder = Object.values(this.#holderTypes)[0]
    if (!holder) {
      throw new AuthorizationConfigError(
        'OpenFgaRelationsDriver: sin holderTypes no se puede calibrar el techo de anidación de grupos (la sonda necesita un holder).'
      )
    }
    const ns = 'authz-calibration'
    const group = (name: string) => `${RELATION_USERSET_TYPE}:${ns}|${name}`
    const member = `${holder}:${ns}-member`
    const outsider = `${holder}:${ns}-outsider`
    const context = this.#checkContext(this.#now())
    const probe = async (depth: number, side: 'positive' | 'negative'): Promise<CalibrationProbe> => {
      const tuples: Array<{ user: string; relation: string; object: string }> = [
        { user: member, relation: RELATION_USERSET_RELATION, object: group('g0') },
      ]
      for (let i = 0; i < depth; i++) {
        tuples.push({ user: `${group(`g${i}`)}#${RELATION_USERSET_RELATION}`, relation: RELATION_USERSET_RELATION, object: group(`g${i + 1}`) })
      }
      tuples.push({ user: outsider, relation: RELATION_USERSET_RELATION, object: group('h0') })
      tuples.push({ user: `${group('h0')}#${RELATION_USERSET_RELATION}`, relation: RELATION_USERSET_RELATION, object: group('h1') })
      const top = `${group(`g${depth}`)}#${RELATION_USERSET_RELATION}`
      const target = domain
        ? { relation: domain.relation, object: `${domain.type}:${ns}|x` }
        : { relation: RELATION_USERSET_RELATION, object: group(`g${depth}`) }
      if (domain) tuples.push({ user: top, relation: domain.relation, object: target.object })
      try {
        const response = await this.#guard('groupDepthLimit', () =>
          this.client.check(
            { user: side === 'positive' ? member : outsider, relation: target.relation, object: target.object, contextualTuples: tuples, context },
            { consistency: ConsistencyPreference.HigherConsistency }
          )
        )
        return (response?.allowed === true) === (side === 'positive') ? 'ok' : 'blind'
      } catch (error) {
        if (error instanceof ResolutionLimitError) return 'too-complex'
        throw error
      }
    }
    const calibrated = await calibrateGroupDepth(probe)
    return domain ? calibrated : Math.max(0, calibrated - 1)
  }

  /**
   * **El gate de R1 en `openfga`**: lee el grafo de anidación de la partición hacia ARRIBA desde el contenedor (un `Read`
   * por `user` = `group:<g>#member` y tipo `group:`, por grupo) y hacia ABAJO desde el contenido (un `Read` por objeto
   * `group:<g>` y relación `member`, que trae también los holders: O(miembros) en una escritura rara, declarado), con la
   * vigencia del instante de la escritura (una arista vencida no conecta; una con condición `foreign`/`unparseable`
   * CUENTA: más 422, nunca menos). Concurrencia: dos `relate` que juntas exceden pasan las dos (cada una lee el grafo
   * sin la otra) — declarado parcial, como `scopes.maxDepth`.
   *
   * **Presupuesto** (cierre de R1 · 🟠 1 del auditor): cada página de `Read` pasa por `GroupDepthBudget` —requests,
   * tuplas leídas (los holders que el `Read` hacia abajo no puede filtrar cuentan) y deadline TOTAL del veredicto—; al
   * pasarlo, 422 `too-many-groups` sin escribir.
   */
  async #assertGroupNesting(partitionKey: string, edge: GroupEdge, now: Date, limit: number, budget: GroupDepthBudget): Promise<void> {
    const pages = { before: () => budget.beforeRead(), after: (n: number) => budget.charge(n) }
    const prefix = `${RELATION_USERSET_TYPE}:${partitionKey}|`
    const live = (t: StoredRelationTuple) => t.invalid !== undefined || isActiveExpiry(t.validUntil ?? null, now)
    const idOf = (fullObject: string): string | null => {
      const parsed = this.#parseObjectId(fullObject)
      return parsed && parsed.type === RELATION_USERSET_TYPE && parsed.partitionKey === partitionKey ? parsed.objectUuid : null
    }
    const verdict = await groupNestingVerdict(edge, limit, {
      parentsOf: async (groups) => {
        const out: GroupEdge[] = []
        for (const child of groups) {
          const user = `${prefix}${child}#${RELATION_USERSET_RELATION}`
          for (const t of await this.#readAll('relate', { user, relation: RELATION_USERSET_RELATION, object: `${RELATION_USERSET_TYPE}:` }, pages)) {
            const parent = t.user === user && t.relation === RELATION_USERSET_RELATION && live(t) ? idOf(t.object) : null
            if (parent !== null) out.push({ child, parent })
          }
        }
        return out
      },
      childrenOf: async (groups) => {
        const out: GroupEdge[] = []
        for (const parent of groups) {
          const object = `${prefix}${parent}`
          for (const t of await this.#readAll('relate', { object, relation: RELATION_USERSET_RELATION }, pages)) {
            const suffix = `#${RELATION_USERSET_RELATION}`
            if (t.object !== object || t.relation !== RELATION_USERSET_RELATION || !t.user.endsWith(suffix) || !live(t)) continue
            const child = idOf(t.user.slice(0, -suffix.length))
            if (child !== null) out.push({ child, parent })
          }
        }
        return out
      },
    })
    if (verdict.kind !== 'ok') {
      throw groupNestingError('openfga-relations', verdict, `group:${edge.parent}#member@group:${edge.child}#member`, limit)
    }
  }

  /**
   * **¿Transporta el grupo un deny vivo?** (cierre 2 de D2 · 🟠 N1): el `#member` de `group` —o el de un grupo que lo
   * contiene, transitivamente (`group:G#member@group:H#member`: los miembros de H heredan los denies de G)— es sujeto de
   * una tupla `denied_*` de la partición, en algún tipo con opt-in del deny. Devuelve la primera que encuentra (para la
   * letra) o `null`. Coste: por cada grupo del cierre hacia arriba, un `Read` por `user` + tipo (el filtro que FGA admite:
   * `user` y `object` tipo) por cada tipo con deny, y uno de sus padres. Solo corre en una RENOVACIÓN de membresía.
   */
  async #carriedDeny(groupObjectId: string, partitionKey: string, now: Date): Promise<string | null> {
    const denyTypes = this.#config.objectTypes.filter((t) => denyPhaseOf(this.#config, t.type) !== undefined).map((t) => t.type)
    if (denyTypes.length === 0) return null
    const seen = new Set([groupObjectId])
    const queue = [groupObjectId]
    while (queue.length > 0) {
      const userset = `${queue.shift()!}#${RELATION_USERSET_RELATION}`
      for (const type of denyTypes) {
        for (const t of await this.#readAll('relate', { user: userset, object: `${type}:` })) {
          // Cierre 6 de D2 · 🟡 D5-1: un deny VENCIDO no transporta nada (la MISMA regla que C2-4 para la arista y que el
          // plan para toda tupla del destino: vencida = ausente). Contarlo hacía de la pasada REAL un 409 que el dry-run
          // no anunciaba, y las particiones siguientes no migraban.
          if (
            t.relation.startsWith(RELATION_DENY_PREFIX) &&
            t.object.startsWith(`${type}:${partitionKey}|`) &&
            // L11: un deny con una condición `foreign`/`unparseable` cuenta como VIVO (fail-closed: más 409, nunca menos).
            (t.invalid !== undefined || isActiveExpiry(t.validUntil ?? null, now))
          ) {
            return `${t.object}#${t.relation}@${t.user}`
          }
        }
      }
      for (const parent of await this.#readAll('relate', { user: userset, relation: RELATION_USERSET_RELATION, object: `${RELATION_USERSET_TYPE}:` })) {
        // Cierre 3 de D2 · ⚪ C2-4: una arista de anidación VENCIDA no transporta nada (no conecta en FGA).
        // L11: una arista con condición `foreign`/`unparseable` se sigue (más grupos que mirar: más 409, nunca menos).
        if (parent.invalid === undefined && !isActiveExpiry(parent.validUntil ?? null, now)) continue
        if (!seen.has(parent.object)) {
          seen.add(parent.object)
          queue.push(parent.object)
        }
      }
    }
    return null
  }

  /** `#carriedDeny` tras los dos `Write` (🟡 C2-3): nunca lanza; un fallo de la re-lectura viaja en `error`. */
  async #recheckCarried(groupObjectId: string, partitionKey: string, now: Date): Promise<{ deny: string | null; error?: unknown }> {
    try {
      return { deny: await this.#carriedDeny(groupObjectId, partitionKey, now) }
    } catch (error) {
      return { deny: null, error }
    }
  }

  /**
   * La tupla EXACTA de una clave (un `Read` por clave completa), con su caducidad si la lleva.
   * ⚪ N5 (cierre 2 del lote B): un 200 sin `tuples` NO es «no existe» — hasta el cierre `?? []` lo
   * vendía así y `relate` escribía a ciegas (una caducidad vigente que no se ve no se preserva).
   * Es 503, como `#readAll`: exhaustivo-o-ruidoso también en la lectura de UNA clave.
   */
  async #readTuple(
    operation: string,
    key: { user: string; relation: string; object: string }
  ): Promise<StoredRelationTuple | null> {
    const response = await this.#guard(operation, () => this.client.read(key, { consistency: this.#consistency }))
    if (!Array.isArray(response?.tuples)) {
      throw new AuthorizationBackendError(
        'openfga-relations',
        operation,
        new Error(`la respuesta del Read de la clave no trae 'tuples'; no se toma por «no existe»`)
      )
    }
    const found = response.tuples.map((t) => t.key as any).find(
      (k) => k?.user === key.user && k?.relation === key.relation && k?.object === key.object
    )
    if (!found) return null
    return { ...key, ...storedCondition(found.condition) }
  }

  async unrelate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    options?: RelationWriteOptions
  ): Promise<void> {
    this.#rejectTransaction('unrelate', options)
    // L-0 · F-05 también al RETIRAR: un `unrelate(alice, assignee, role_binding)`
    // sería un revoke de roles por la puerta de relaciones.
    assertRelationDeclared(this.#config, object, relation)
    assertPartition(partition)
    const partitionKey = this.#keyOf(partition)
    const objectId = this.#objectId(object.type, partitionKey, object.id)
    const user = this.#subjectUser(subject, partitionKey)
    await this.#assertModel('unrelate', [object.type])
    await this.#guard('unrelate', () =>
      // Re-unrelate no-op seguro: borrar una tupla ausente se ignora.
      this.client.write({ deletes: [{ user, relation, object: objectId }] }, IGNORE_MISSING_DELETES),
      true
    )
  }

  /**
   * **`deny` = UN `Write` de la tupla `denied_<rel>`** (lote D · D1): sin caducidad (D3), así que no hay renovación
   * ni ventana —un re-deny idéntico lo ignora el servidor (`on_duplicate: ignore`)—; una tupla de deny escrita a mano
   * CON condición devuelve 409 y, desde el cierre 1 de D2 (🟡 4), sale como 500 `E_AUTHZ_CONFIG` con la receta
   * (`AuthorizationConfigError.conditionalDeny`; hasta entonces era un 503 que se repetía para siempre). Antes del `Write`: la
   * puerta de `{ transaction }` (L-5), F-05 sobre el nombre PÚBLICO, la puerta del opt-in (fase `'write'`), sin
   * caducidad, la partición, `*`, el sujeto y la puerta del modelo (L11). CERO llamadas si algo de eso falla.
   */
  async deny(subject: RelSubject, relation: string, object: RelObject, partition: ScopeRef, options?: RelationDenyOptions): Promise<void> {
    this.#rejectTransaction('deny', options)
    assertRelationDeclared(this.#config, object, relation)
    assertRelationDenyable(this.#config, object, relation)
    assertDenyNoExpiry(options)
    assertPartition(partition)
    assertDenySubject(subject)
    const partitionKey = this.#keyOf(partition)
    const objectId = this.#objectId(object.type, partitionKey, object.id)
    const user = this.#subjectUser(subject, partitionKey)
    await this.#assertModel('deny', [object.type])
    const key = { user, relation: deniedRelationOf(relation), object: objectId }
    try {
      await this.#guard('deny', () => this.client.write({ writes: [key] }, IGNORE_DUPLICATE_WRITES), true)
    } catch (error: any) {
      // Cierre 1 de D2 · 🟡 4: el 409 de una clave que ya existe CON condición (medido en v1.19.0: «already exists with
      // a different condition») no es una caída. Se confirma RELEYENDO la tupla (no por el texto del mensaje): si está y
      // lleva condición, 500 con la receta; si no, el 409 de la carrera (R3; hasta R3, 503).
      // R3: el 409 es la clase «carrera» (409 `E_AUTHZ_WRITE_CONFLICT`, antes 503); se mira la CAUSA del SDK.
      if (error?.cause?.statusCode === 409) {
        const found = await this.#guard('deny', () => this.client.read(key, { consistency: this.#consistency }))
        if (Array.isArray(found?.tuples) && found.tuples.some((t: any) => t?.key?.condition)) {
          throw AuthorizationConfigError.conditionalDeny('deny', `${key.object}#${key.relation}@${key.user}`)
        }
      }
      throw error
    }
  }

  /**
   * **`removeDeny` = UN delete de `denied_<rel>`** (no-op si no está). Sobre CUALQUIER tipo declarado (D8/R2-4 b):
   * `Write` con delete no valida la relación contra el modelo (medido en v1.19.0), así que un deny vivo de un tipo
   * que retiró el opt-in se puede borrar. Ojo: quitar un deny CONCEDE (filas declaradas S8–S10).
   * **La puerta del modelo (L11, antes D-31) SÍ corre aquí** (letra corregida en el cierre 1 de D1, ⚪ 5 del auditor:
   * la decisión 4 del informe decía que no): con el opt-in vivo y un modelo fijado sin `denied_*` ⇒ 500 antes del
   * delete. Con el opt-in RETIRADO no hay guarda (el tipo no está en la config con `deny`) y el delete borra de verdad
   * (medido por el auditor: `listDenies` de 1 a 0 y `check` vuelve a `true` con el modelo viejo) — retirar es reversible.
   */
  async removeDeny(subject: RelSubject, relation: string, object: RelObject, partition: ScopeRef, options?: RelationDenyOptions): Promise<void> {
    this.#rejectTransaction('removeDeny', options)
    assertRelationDeclared(this.#config, object, relation)
    assertDenyNoExpiry(options)
    assertPartition(partition)
    const partitionKey = this.#keyOf(partition)
    const objectId = this.#objectId(object.type, partitionKey, object.id)
    const user = this.#subjectUser(subject, partitionKey)
    await this.#assertModel('removeDeny', [object.type])
    await this.#guard('removeDeny', () =>
      this.client.write({ deletes: [{ user, relation: deniedRelationOf(relation), object: objectId }] }, IGNORE_MISSING_DELETES),
      true
    )
  }

  /* ── Lecturas ───────────────────────────────────────────────────────────── */

  /**
   * **F-05 en las LECTURAS y las PURGAS del driver** (2.4.0-alpha.3, cierre
   * del 🔴 1 / 🟠 2 del auditor; la MISMA función y la misma posición que
   * L-0 en `relate`/`unrelate` y que L-5 con `{ transaction }`): PRIMERA
   * línea (tras `#rejectTransaction` en las purgas), CERO llamadas al
   * cliente. Reproducido contra el `:8101` en el store compartido:
   * `purgeObject({ type: 'role_binding', id: R }, S)` componía
   * `role_binding:<scopeKey>|<R>` —byte a byte el binding real— y
   * `#purgeByFilter` lo borraba con demostración de cero (`authorize` de
   * `true` a `false`); `listSubjects('assignee', role_binding)` enumeraba sus
   * asignados. `check`/`listSubjects` validan el par; `listObjects`/
   * `purgeObject` el tipo; `purgeSubject` el userset.
   */
  /** `check` = UN solo `Check` (el modelo resuelve includes + usersets). */
  async check(subject: RelSubject, relation: string, object: RelObject, partition: ScopeRef): Promise<boolean> {
    assertRelationDeclared(this.#config, object, relation)
    assertPartition(partition)
    const partitionKey = this.#keyOf(partition)
    const objectId = this.#objectId(object.type, partitionKey, object.id)
    const user = this.#subjectUser(subject, partitionKey)
    const context = this.#checkContext(this.#now())
    await this.#assertModel('check', [object.type])
    const response = await this.#guard('check', () =>
      this.client.check({ user, relation, object: objectId, context }, { consistency: this.#consistency })
    )
    return response.allowed === true
  }

  /**
   * **`checkMany` = un `batchCheck` por cada `FGA_MAX_BATCH_CHECK` objetos
   * DISTINTOS** (plan 2.5 · lote A, P4-8; con el tope del manager, 50, es
   * UNA request), alineado por `correlationId` y NUNCA por posición
   * (`correlateBatchResults`, la misma función que el driver de roles: el
   * SDK reparte y concatena según llegan). El `current_time` viaja en CADA
   * ítem y es el MISMO para todo el lote (un `now`). Un `error` en UN ítem
   * (`input_error`, `internal_error`…) es una caída parcial del backend ⇒
   * 503 para todo el lote, jamás `false` (invariante 5). F-05 y la gramática
   * del id POR ÍTEM antes de componer nada (defensa en profundidad).
   */
  async checkMany(subject: RelSubject, relation: string, objects: RelObject[], partition: ScopeRef): Promise<boolean[]> {
    assertCheckManyObjects(objects)
    for (const object of objects) assertRelationDeclared(this.#config, object, relation)
    assertPartition(partition)
    const partitionKey = this.#keyOf(partition)
    const user = this.#subjectUser(subject, partitionKey)
    const { distinct, index } = distinctObjects(objects)
    const context = this.#checkContext(this.#now())
    await this.#assertModel('checkMany', distinct.map((object) => object.type))
    const checks: ClientBatchCheckItem[] = distinct.map((object, i) => ({
      user,
      relation,
      object: this.#objectId(object.type, partitionKey, object.id),
      context,
      correlationId: String(i),
    }))
    const answers: boolean[] = new Array(distinct.length)
    for (let start = 0; start < checks.length; start += FGA_MAX_BATCH_CHECK) {
      const chunk = checks.slice(start, start + FGA_MAX_BATCH_CHECK)
      const response = await this.#guard('checkMany', () =>
        this.client.batchCheck({ checks: chunk }, { consistency: this.#consistency })
      )
      // A10: alineación por id + «error ⇒ 503 / ausente ⇒ 500» en UNA función, la del driver de roles.
      const results = alignBatchResults('openfga-relations', 'checkMany', chunk, response.result)
      results.forEach((r, i) => {
        answers[Number(chunk[i].correlationId)] = r.allowed === true
      })
    }
    return expandByPosition(index, answers)
  }

  /**
   * **`decideMany` = un `batchCheck` con `R` y los `denied_<m>` de las relaciones FUENTE de `down*(R)`** (lote D ·
   * D9, juez ronda 2 §4): por el cierre ascendente del modelo (`denied_X = this ∨ denied_P`), `denied_<fuente>`
   * cubre todo `up*(down*(R))` — en el retículo del contrato, 2 ítems por objeto (`R` y `denied_owner`). Mismo
   * `current_time` en TODOS los ítems (un `now` por lote), alineado por `correlationId` (`alignBatchResults`, la
   * misma función que `checkMany` y roles), troceado por `FGA_MAX_BATCH_CHECK`, y un `error` en UN ítem ⇒ 503 para
   * todo el lote (nunca `none`: S15). La decisión sale de `decideFrom`, la regla ÚNICA (la misma que `database` y el
   * doble). En un tipo sin opt-in se pregunta el deny solo si el modelo que sirve el driver lo declara (opt-in
   * retirado con el modelo aún publicado, D8); si no, cada posición es `allow` o `none` (no hay deny posible).
   */
  async decideMany(subject: RelSubject, relation: string, objects: RelObject[], partition: ScopeRef): Promise<RelationDecision[]> {
    assertCheckManyObjects(objects, 'decideMany')
    for (const object of objects) assertRelationDeclared(this.#config, object, relation)
    assertPartition(partition)
    const partitionKey = this.#keyOf(partition)
    const user = this.#subjectUser(subject, partitionKey)
    const { distinct, index } = distinctObjects(objects)
    const context = this.#checkContext(this.#now())
    // L11: con la puerta, el modelo ES el que genera la config (con D8 por TIPO ENTERO): un tipo en forma `deny` declara
    // `denied_<rel>` para TODAS sus relaciones, uno en forma `plain` para ninguna.
    const { denyForm } = await this.#assertModel('decideMany', distinct.map((object) => object.type))
    const checks: ClientBatchCheckItem[] = []
    const plan: Array<{ object: RelObject; sources: string[] }> = []
    distinct.forEach((object, i) => {
      const objectId = this.#objectId(object.type, partitionKey, object.id)
      const down = relationsDown(this.#config, object.type, relation)
      const type = this.#config.objectTypes.find((t) => t.type === object.type)
      const sources = down.filter((name) => {
        const includes = type?.relations.find((r) => r.name === name)?.includes ?? []
        return includes.length === 0 && denyForm.get(object.type) === 'deny'
      })
      plan.push({ object, sources })
      // `correlationId` del servidor: `^[\w\d-]{1,36}$` (sin `:`): `a<i>` para R, `d<i>-<k>` para la fuente k.
      checks.push({ user, relation, object: objectId, context, correlationId: `a${i}` })
      sources.forEach((source, k) => {
        checks.push({ user, relation: deniedRelationOf(source), object: objectId, context, correlationId: `d${i}-${k}` })
      })
    })
    const allowed = new Map<string, boolean>()
    for (let start = 0; start < checks.length; start += FGA_MAX_BATCH_CHECK) {
      const chunk = checks.slice(start, start + FGA_MAX_BATCH_CHECK)
      const response = await this.#guard('decideMany', () =>
        this.client.batchCheck({ checks: chunk }, { consistency: this.#consistency })
      )
      const results = alignBatchResults('openfga-relations', 'decideMany', chunk, response.result)
      results.forEach((r, i) => allowed.set(chunk[i].correlationId!, r.allowed === true))
    }
    // D9, por posición: `allow` si el `Check` de R concede (el servidor ya aplicó el corte); si no, `deny` si alguno
    // de los `denied_<fuente>` alcanza al sujeto (su cierre cubre up*(down*(R))); si no, `none`. Es `decideFrom` con el
    // corte ya evaluado en el servidor (los dos drivers y el doble responden la misma tabla: casos D9 de la COMÚN).
    const answers = plan.map(({ sources }, i): RelationDecision => {
      if (allowed.get(`a${i}`)) return 'allow'
      return sources.some((_, k) => allowed.get(`d${i}-${k}`)) ? 'deny' : 'none'
    })
    return index.map((at) => answers[at])
  }

  /**
   * **`denyPhase` — ¿admite este driver escrituras de deny en el tipo?** (lote D · D2, R2-5). La fase del opt-in EN
   * LA CONFIG DE ESTE DRIVER y, con opt-in, el modelo FIJADO comprobado con la MISMA puerta L11 que `deny` (500 si
   * no declara `denied_<rel>`). F-05 estricto del par, antes de nada (422, cero llamadas). La llama
   * `reconcileRelations` en la fase de plan cuando el origen trae denies: un destino `openfga` sin `'write'` en el
   * tipo, o con un pin a un modelo sin el deny, NIEGA la pasada antes de la primera escritura (jamás `skipped`).
   */
  async denyPhase(object: { type: string }, relation: string): Promise<'read' | 'write' | null> {
    assertRelationDeclared(this.#config, object, relation)
    const phase = denyPhaseOf(this.#config, object.type)
    if (phase === undefined) return null
    await this.#assertModel('denyPhase', [object.type])
    return phase
  }

  /** `listDenies` = `Read` por `(object, denied_<rel>)`: los denies DIRECTOS (hechos). Cualquier tipo declarado (D8). */
  async listDenies(relation: string, object: RelObject, partition: ScopeRef): Promise<RelationSubjectsPage> {
    assertRelationDeclared(this.#config, object, relation)
    assertPartition(partition)
    // 7.4: sin página (≠ undefined ⇒ 500 con cero llamadas al cliente), después de F-05 y la partición.
    assertNoListPage('listDenies', arguments[3], 'openfga')
    const partitionKey = this.#keyOf(partition)
    const objectId = this.#objectId(object.type, partitionKey, object.id)
    const now = this.#now()
    await this.#assertModel('listDenies', [object.type])
    const tuples = await this.#readAll('listDenies', { object: objectId, relation: deniedRelationOf(relation) })
    const subjects: RelSubject[] = []
    for (const t of tuples) {
      // L11: una condición `foreign`/`unparseable` no se lista (se avisa y se cuenta): el paquete no sabe si está viva.
      if (t.invalid !== undefined) {
        this.#warnUnparseable('listDenies', `${t.object}#${t.relation}@${t.user} (${t.invalid})`)
        continue
      }
      if (t.validUntil && t.validUntil.getTime() <= now.getTime()) continue
      const subject = this.#userToSubject(t.user)
      if (subject) subjects.push(subject)
      else this.#warnUnparseable('listDenies', t.user)
    }
    return { subjects }
  }

  /**
   * **El envoltorio ÚNICO de `ListObjects`** (plan 2.5 · lote B · B4; linaje L8,
   * 5.ª iteración ⇒ M8: propiedad universal «toda enumeración que se puede
   * cortar devuelve `truncated` o lanza»). `ListObjects` corta de DOS formas,
   * las dos con 200 y sin `continuation_token` ni bandera: (1) al tope del
   * servidor (`listObjectsMaxResults`): `>= tope` resultados CRUDOS ⇒ no se
   * puede prometer la lista completa; (2) al DEADLINE del servidor
   * (`--listObjects-deadline`, 3 s por defecto): pasado, devuelve lo que
   * llevaba resuelto (analista M4, medido). La (2) se detecta midiendo la
   * llamada con el reloj MONÓTONO (`monotonic`, `performance.now`): si duró
   * ≥ `LIST_OBJECTS_DEADLINE_RATIO` × `listObjectsDeadlineMs`, `truncated`. Es
   * una señal conservadora a propósito (una llamada lenta pero completa sale
   * como truncada; una cortada JAMÁS como completa). Todo `ListObjects` del
   * driver pasa por aquí — la guardia de superficie (columna `truncation`) lo
   * sondea con las dos causas y un mutante por cada una. Las enumeraciones por
   * `Read` (`listSubjects`, `enumerateRelations`, las purgas) no se cortan:
   * `#readAll` agota el token o lanza 503 («exhaustivo o ruidoso»).
   */
  async #listObjectsPage(request: { user: string; relation: string; type: string; context: { current_time: string } }): Promise<{
    raw: string[]
    truncated: boolean
    elapsedMs: number
  }> {
    const started = this.#monotonic()
    const response = await this.#guard('listObjects', () => this.client.listObjects(request, { consistency: this.#consistency }))
    const elapsedMs = this.#monotonic() - started
    // 🟡 4 (cierre 1 del lote B): un 200 sin `objects` (un proxy, una caché, un
    // cuerpo vacío) NO es una lista completa vacía: es una enumeración que no
    // se puede prometer ⇒ 503, como `#readAll` con una respuesta sin `tuples`.
    // Hasta el cierre `response.objects ?? []` la vendía como `{ objects: [] }`
    // sin `truncated` — la lista «completa» muda que M8 prohíbe.
    if (!Array.isArray(response?.objects)) {
      throw new AuthorizationBackendError(
        'openfga-relations',
        'listObjects',
        new Error(`la respuesta de ListObjects no trae 'objects'; no se toma por vacía (sería una lista completa muda)`)
      )
    }
    const raw: string[] = response.objects
    const byCap = raw.length >= this.#listObjectsMax
    const byDeadline = elapsedMs >= LIST_OBJECTS_DEADLINE_RATIO * this.#listObjectsDeadlineMs
    return { raw, truncated: byCap || byDeadline, elapsedMs }
  }

  /**
   * `listObjects` = `ListObjects` (resuelve includes + usersets del lado del
   * servidor) + FILTRO por partición + señal de TRUNCADO (`#listObjectsPage`:
   * tope o deadline, B4). El filtro por partición se aplica DESPUÉS (los ids
   * llevan la partición), así que en un store con varias particiones el tope
   * se consume entre todas — otra razón para señalar el truncado y no callar
   * (documentado en el README).
   */
  async listObjects(subject: RelSubject, relation: string, objectType: string, partition: ScopeRef): Promise<RelationObjectsPage> {
    assertRelationDeclared(this.#config, { type: objectType }, relation)
    assertPartition(partition)
    assertNoListPage('listObjects', arguments[4], 'openfga')
    const partitionKey = this.#keyOf(partition)
    const user = this.#subjectUser(subject, partitionKey)
    const context = this.#checkContext(this.#now())
    await this.#assertModel('listObjects', [objectType])
    const { raw, truncated } = await this.#listObjectsPage({ user, relation, type: objectType, context })
    const objects: RelObject[] = []
    for (const full of raw) {
      const parsed = this.#parseObjectId(full)
      if (!parsed || parsed.type !== objectType) {
        this.#warnUnparseable('listObjects', full)
        continue
      }
      if (parsed.partitionKey !== partitionKey) continue // otra partición: no cruza
      objects.push({ type: objectType, id: parsed.objectUuid })
    }
    objects.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    return truncated ? { objects, truncated: true } : { objects }
  }

  /**
   * `listSubjects` = `Read` por `(object, relation)` — hechos DIRECTOS del
   * relation EXACTO (invariante 7): ni transitivo (eso es `membersOf`) ni
   * derivado por includes. `usersetSubjects: true` ⇒ los usersets
   * (`group#member`) salen junto con los holders.
   */
  async listSubjects(relation: string, object: RelObject, partition: ScopeRef): Promise<RelationSubjectsPage> {
    assertRelationDeclared(this.#config, object, relation)
    assertPartition(partition)
    assertNoListPage('listSubjects', arguments[3], 'openfga')
    const partitionKey = this.#keyOf(partition)
    const objectId = this.#objectId(object.type, partitionKey, object.id)
    // `Read` devuelve tuplas ESCRITAS, no evaluadas: la caducidad se filtra en
    // cliente con el MISMO reloj del driver (R-15, estricta: la que vence en
    // `now` ya no cuenta), como las enumeraciones del driver de roles.
    const now = this.#now()
    await this.#assertModel('listSubjects', [object.type])
    const tuples = await this.#readAll('listSubjects', { object: objectId, relation })
    const subjects: RelSubject[] = []
    for (const t of tuples) {
      // L11: una condición `foreign`/`unparseable` NO es un hecho vigente que listar (sería «permanente» por defecto);
      // se avisa y se cuenta en `diagnostics.unparseableTuples`.
      if (t.invalid !== undefined) {
        this.#warnUnparseable('listSubjects', `${t.object}#${t.relation}@${t.user} (${t.invalid})`)
        continue
      }
      if (t.validUntil && t.validUntil.getTime() <= now.getTime()) continue
      const subject = this.#userToSubject(t.user)
      if (subject) subjects.push(subject)
      else this.#warnUnparseable('listSubjects', t.user)
    }
    return { subjects }
  }

  /**
   * **`membersOf` ⇒ 500 `E_AUTHZ_UNSUPPORTED`** (cara `whenFalse`): la
   * membresía TRANSITIVA de un grupo sería `ListUsers`, que trunca al tope del
   * servidor sin señal fiable. No hay userset transitivo enumerable aquí; se
   * dice con 500 nombrándolo, jamás un userset a medias. Es el análogo del par
   * `purgeRole` de la 3b. (El método existe en el prototipo para que el manager
   * lo despache, pero la capacidad `membersOfNative: false` lo corta antes.)
   */
  async membersOf(): Promise<RelationSubjectsPage> {
    throw new UnsupportedOperationError(
      'membersOf',
      'la membresía transitiva de un grupo',
      'openfga',
      `En 'openfga' la transitiva sería 'ListUsers', que trunca al tope del servidor sin señal fiable. ` +
        `Usa el driver 'database' (CTE recursiva) o 'listSubjects' para los hechos directos.`
    )
  }

  /* ── ORIGEN de reconcile (4-5): las tuplas de relación de la partición ──── */

  /**
   * **`enumerateRelations` — el ORIGEN de `authz:reconcile` de relaciones**
   * (4-5). Lee el store ENTERO (`Read({})`) —la única forma de ver todo sin un
   * filtro por `user` u `object`, que un `Read` por tipo-solo sin user
   * rechazaría con 400— y devuelve SOLO las tuplas de relación de la partición
   * pedida: tipo `group` o un tipo declarado en la config, DESCARTANDO las de
   * `facts` (`scope`/`role`/`role_binding`, que no llevan la partición en el id
   * con la forma `<key>|<uuid>` de relaciones —o cuyo tipo no está declarado—).
   *
   * `truncated`/paginación: `enumerateRelations` agota el `Read` (exhaustivo,
   * como `listSubjects`/`purge*`), así que devuelve TODO en una página sin
   * cursor —el reconcile itera hasta que no hay cursor—. Es el ORIGEN de una
   * migración: una tupla que no llegara aquí desaparecería sin rastro — por eso
   * la CADUCADA también llega, con su `expiresAt` (R-15), para que el destino
   * la cuente en `skipped`.
   *
   * **Una tupla con condición AJENA llega marcada** (`invalidCondition`, L11) y
   * con `expiresAt` = la ÉPOCA. Eso es conservador SOLO para los allows: un
   * lector que ignore la marca lee el deny (o la membresía de `group` que lo
   * transporta) como VENCIDO y deja de negar —fail-OPEN— (cierre-2 · ⚪ C3).
   * Ninguna fecha sirve para los dos tipos de tupla: el lector tiene que mirar
   * `invalidCondition` ANTES que `expiresAt` (el plan del paquete lo hace).
   *
   * **Coste: O(tuplas del store) por PASADA** (2.4.0-alpha.6): es un barrido
   * entero por llamada, sea cual sea el tamaño de la partición (medido: 5 000
   * tuplas ⇒ 50 páginas ≈ 170 ms; 15 000 ⇒ 151 páginas ≈ 0,5 s). Para K
   * particiones usa `enumerateRelationsMany`: UN barrido en vez de K.
   */
  async enumerateRelations(partition: ScopeRef, page?: RelationPage): Promise<RelationTuplePage> {
    assertPartition(partition)
    // 7.4 (injerto 4): limit basura ⇒ 422; after ⇒ 500 (este driver no emite cursor: devuelve TODO en una página).
    // Un limit válido se IGNORA (una página, O(store)): declarado en «Limits».
    assertEnumeratePage('enumerateRelations', page, 'none', 'openfga')
    // L11: el ORIGEN de una migración pasa SOLO la parte `conditions` de la puerta (tiene que poder rescatar un store
    // con deriva de reglas; la vigencia de lo que emite sí depende de la condición del modelo).
    await this.#assertModel('enumerateRelations', [], 'conditions')
    return this.#sweep([partition], 'enumerateRelations')
  }

  /**
   * **`enumerateRelationsMany` — K particiones en UN barrido** (2.4.0-alpha.6;
   * panel relay, analista §3: con 3 particiones 1,4 s → 0,46 s). MISMA
   * semántica que `enumerateRelations` por cada partición pedida —exhaustiva,
   * sin filtrar la caducada, todo en una página sin cursor— y cada tupla
   * viene con SU `partition` (la referencia que pasó el llamante, casada por
   * `scopeKey` ENTERA), de modo que el llamante reparte por `partition`.
   * Reparte un solo `Read({})` paginado del store entero.
   *
   * **Lo que este método NO hace, a propósito: un `Read` por PREFIJO de id.**
   * OpenFGA no tiene prefix-match: `Read({ object: 'document:unit|<uuid>|' })`
   * responde **200 con cero tuplas** (medido por el panel, auditor 🔴 3) — en
   * el ORIGEN de una migración eso es «esta partición está vacía» en silencio,
   * y en una purga, «demostrado cero» sin haber borrado nada. El único filtro
   * legal es `{}`; la partición se decide comparando la CLAVE entera del id
   * parseado desde la derecha (`#parseObjectId`), así que `app` no arrastra a
   * `appliance|…`, `org|U` no arrastra a `organization|U` y cada ortografía del
   * uuid es su propia partición. La suite espía el FILTRO de cada `read`.
   *
   * **Exhaustivo o ruidoso**: una página con cero tuplas y token de
   * continuación NO es el fin; un token que se repite, más de
   * `MAX_READ_PAGES` páginas o una respuesta sin `tuples` son 503
   * `E_AUTHZ_BACKEND_UNAVAILABLE` (`#readAll`); una tupla que no se entiende
   * se cuenta en `diagnostics.unparseableTuples` y se avisa. Sin particiones
   * es 500 `E_AUTHZ_CONFIG` con cero lecturas: no hay «éxito vacío».
   */
  async enumerateRelationsMany(partitions: ScopeRef[], page?: RelationPage): Promise<RelationTuplePage> {
    if (!Array.isArray(partitions) || partitions.length === 0) {
      throw new AuthorizationConfigError(
        'enumerateRelationsMany: sin particiones no hay nada que enumerar (y un barrido del store para nadie no es un éxito vacío). ' +
          'Pasa al menos una partición.'
      )
    }
    for (const partition of partitions) assertPartition(partition)
    assertEnumeratePage('enumerateRelationsMany', page, 'none', 'openfga')
    await this.#assertModel('enumerateRelationsMany', [], 'conditions')
    return this.#sweep(partitions, 'enumerateRelationsMany')
  }

  /** El barrido: UN `Read({})` paginado del store entero, repartido por la clave ENTERA de partición. */
  async #sweep(partitions: ScopeRef[], operation: string): Promise<RelationTuplePage> {
    // La primera referencia de cada clave es la que viaja en `tuple.partition`
    // (dos ortografías del mismo uuid son dos claves, como en `enumerateRelations`).
    const wanted = new Map<string, ScopeRef>()
    for (const partition of partitions) {
      const key = this.#keyOf(partition)
      if (!wanted.has(key)) wanted.set(key, partition)
    }
    const relationTypes = new Set<string>([FACTS_GROUP_TYPE, ...this.#config.objectTypes.map((t) => t.type)])
    const all = await this.#readAll(operation, {})
    const tuples: RelationTuple[] = []
    for (const key of all) {
      const parsed = this.#parseObjectId(key.object)
      // No es una tupla de relación (facts: scope/role/role_binding, o un tipo
      // no declarado): no la migra este puerto.
      if (!parsed || !relationTypes.has(parsed.type)) continue
      const partition = wanted.get(parsed.partitionKey)
      if (partition === undefined) continue // otra partición: no cruza (clave ENTERA, nunca prefijo)
      const subject = this.#userToSubject(key.user)
      if (!subject) {
        this.#warnUnparseable(operation, key.user)
        continue
      }
      tuples.push({
        subject,
        // Lote D · D2: `denied_<rel>` ⇒ `{ relation: <rel>, kind: 'deny' }` (`storedRelationKind`, punto de paso único).
        ...storedRelationKind(key.relation),
        object: { type: parsed.type, id: parsed.objectUuid },
        partition,
        // Cierre de L11 (⚪ A3.3 del auditor): con una condición que el paquete no escribe (o no sabe leer) `expiresAt` NO
        // es `null` sino la ÉPOCA. Cierre-2 (⚪ C3): eso es fail-CLOSED para un allow que lea un tercero sin mirar
        // `invalidCondition` (lo lee VENCIDO), pero fail-OPEN para un deny o una membresía que transporta uno (deja de negar);
        // con `null` era al revés. Ninguna fecha vale para los dos: la marca es lo que manda, y VIAJA al plan, que la
        // clasifica antes de mirar la fecha (`invalid-condition`, L9): nunca se migra ni se poda como sobrante.
        expiresAt: key.invalid !== undefined ? new Date(0) : key.validUntil,
        ...(key.invalid !== undefined ? { invalidCondition: key.invalid } : {}),
      })
    }
    return { tuples }
  }

  /* ── Purga (invariante 11): borra y DEMUESTRA cero, o lanza ─────────────── */

  /**
   * Borra TODAS las tuplas del objeto (cualquier relación) y demuestra cero.
   * Hasta 2.5.0 barría las DOS ortografías del uuid de partición (🟡2);
   * desde D4 (plan 2.5 · lote A) la ortografía sin guiones es 422 en la
   * puerta y la clave es una. Si tras borrar quedan tuplas ⇒ 500
   * `E_AUTHZ_PURGE_INCOMPLETE`.
   */
  async purgeObject(object: RelObject, partition: ScopeRef, options?: RelationTransactionOptions): Promise<void> {
    this.#rejectTransaction('purgeObject', options)
    // alpha.3 · F-05 (solo el TIPO: una purga no nombra relación), antes de componer el id.
    // Cierre-2: la función de TIPO, no la estricta con relación opcional.
    assertObjectTypeDeclared(this.#config, object)
    assertPartition(partition)
    const objectId = this.#objectId(object.type, this.#keyOf(partition), object.id)
    await this.#assertModel('purgeObject', [object.type])
    const progress = { deleted: 0 }
    try {
      await this.#purgeByFilters('purgeObject', [[{ object: objectId }, `objeto ${objectId}`]], progress)
    } catch (error) {
      throw this.#partialIfDeleted(error, progress)
    }
  }

  /**
   * Borra TODAS las tuplas cuyo SUJETO es este subject en la partición, en
   * cualquier tipo de objeto declarado, y demuestra cero. `Read` exige un
   * filtro de objeto (un `Read` solo por `user` es un 400 del servidor), así
   * que se recorre cada tipo declarado (`group` + los del consumidor) con
   * `Read({ user, object: '<type>:' })`.
   */
  async purgeSubject(subject: RelSubject, partition: ScopeRef, options?: RelationTransactionOptions): Promise<void> {
    this.#rejectTransaction('purgeSubject', options)
    // alpha.3 · F-05 del USERSET (una purga por sujeto no nombra objeto), antes de nada.
    if (isRelUserset(subject)) assertRelationDeclared(this.#config, subject.object, subject.relation)
    assertPartition(partition)
    if (!isRelUserset(subject)) assertSubject(subject)
    const user = this.#subjectUser(subject, this.#keyOf(partition))
    const types = [FACTS_GROUP_TYPE, ...this.#config.objectTypes.map((t) => t.type)]
    // Toca TODOS los tipos declarados: la puerta los compara todos.
    await this.#assertModel('purgeSubject', types)
    const progress = { deleted: 0 }
    try {
      await this.#purgeByFilters(
        'purgeSubject',
        types.map((type) => [{ user, object: `${type}:` }, `sujeto ${user} en '${type}'`] as const),
        progress
      )
    } catch (error) {
      throw this.#partialIfDeleted(error, progress)
    }
  }

  /**
   * **Una purga que muere a MEDIAS es indeterminada** (invariante 13,
   * 2.4.0-alpha.3, cierre del 🟡 6 del auditor). La purga NO es un `Write`:
   * son N `Read`+`deleteTuples` (ortografías × tipos, y lotes de
   * `RELATIONS_PURGE_WRITE_MAX`), y un 503 que no es timeout —o el 500
   * `E_AUTHZ_PURGE_INCOMPLETE` de la demostración de cero— puede llegar
   * después de haber borrado parte. Si YA se borró al menos una tupla, el
   * error se marca (`markPartialWrite`, `src/errors.ts`: una propiedad, la
   * clase y el `code` no cambian) y el `RelationsManager` notifica
   * `onRelationWrite` con `indeterminate: true` ANTES de propagarlo — «puede
   * haber ocurrido», como con el deadline. Si no se borró nada, el error va
   * tal cual: «esa escritura no ocurrió» sigue siendo verdad. En `database`
   * la purga es UN `DELETE` y no necesita la marca.
   */
  #partialIfDeleted(error: unknown, progress: { deleted: number }): unknown {
    if (progress.deleted > 0 && error !== null && typeof error === 'object') return markPartialWrite(error)
    return error
  }

  /**
   * **Lee TODOS los filtros, borra en un `Write` si cabe —y si no, en ORDEN GLOBAL: allows → membresías → denies— y
   * RE-LEE cada filtro para demostrar cero (o lanza)** (lote D · D-16/D-26/S3; cierre 1 de D1, 🟠 1 del auditor; el
   * orden S6 de roles, invariante 6). La propiedad: **una purga cortada a medias no concede nada que no concedieran el
   * estado inicial o el final** —con la única excepción DECLARADA de abajo—.
   *
   *  - **Cabe en `RELATIONS_PURGE_WRITE_MAX` (100) ⇒ UN solo `Write`**: FGA lo aplica de forma transaccional (medido:
   *    101 es 400 y no se aplica nada), así que NO hay PREFIJO que cortar (atómico para el ESCRITOR: un `Check`
   *    concurrente puede observar el `Write` a medias —lector rasgado, fila «torn read» de Limits, decisión (6a)—).
   *  - **No cabe ⇒ tres clases, cada una en sus propios `Write`, en el orden de BORRADO del punto de paso ÚNICO
   *    `relationDeleteOrder`** (`src/relations/tuple_order.ts`; cierre 1 de D2 · 🟠 1: el mismo que el reconcile): (1) los allows sobre objetos que no son
   *    `group` —quitar un allow solo resta (D-12, monotonía)—; (2) las MEMBRESÍAS `group:*#member@<sujeto>` —una membresía
   *    TRANSPORTA allows y denies a la vez: borrarla antes que un allow directo deja ese allow sin el deny que lo cortaba
   *    (🟠 1: con el orden «solo prefijo» de alpha.3-dev, `group:g#member@U` caía en el lote 1 y `doc:V#viewer@U` en el 2;
   *    cortada entre los dos, U CONCEDÍA sobre V; la gemela `purgeSubject(g#member)` con la arista anidada
   *    `group:h#member@group:g#member`)—, en UN `Write` PROPIO si caben (ordenadas por objeto, las portadoras de deny al
   *    final: el reparto no depende del `Read`); (3) los `denied_*`, al final —quedan denies de MÁS, nunca de menos—.
   *  - **Residuo DECLARADO**: con MÁS de 100 membresías del sujeto no caben en un `Write`, y una que transporta un deny
   *    puede caer en un lote anterior a otra que transporta un allow (fila con caso en `relations_openfga.spec`, frase en
   *    el README). No se niega la purga antes de borrar (invariante 11: una purga no espera; un 500 dejaría al sujeto de
   *    baja con TODO su acceso): sale marcada como parcial (`indeterminate: true`) y se repite.
   *
   * `purgeObject` pasa por aquí igual: sobre un objeto que no es `group` no hay membresías (allows → denies); sobre
   * `group:g` todo son membresías de g, y cada miembro queda dentro o fuera de g —su estado inicial o el final—.
   * `progress.deleted` cuenta lo que YA se borró (un lote que falla no borró nada) para la marca de escritura parcial
   * (invariante 13).
   */
  async #purgeByFilters(
    operation: string,
    filters: ReadonlyArray<readonly [{ user?: string; relation?: string; object: string }, string]>,
    progress: { deleted: number }
  ): Promise<void> {
    const read: Array<{ filter: { user?: string; relation?: string; object: string }; what: string; keys: StoredRelationTuple[] }> = []
    for (const [filter, what] of filters) read.push({ filter, what, keys: await this.#readAll(operation, filter) })
    for (const batch of purgeWrites(read.flatMap((r) => r.keys))) {
      try {
        await this.#guard(operation, () =>
          this.client.deleteTuples(
            batch.map((k) => ({ user: k.user, relation: k.relation, object: k.object })),
            IGNORE_MISSING_DELETES
          ),
          true
        )
      } catch (error) {
        // Cierre 2 de D1 · ⚪ N3: el 400 del tope de operaciones por `Write` del SERVIDOR no es una caída (503
        // reintentable): es un despliegue con `--max-tuples-per-write` < `RELATIONS_PURGE_WRITE_MAX`. 500 con la letra;
        // la marca de escritura parcial la pone `#partialIfDeleted` si ya se aplicó un `Write` anterior.
        if (isServerWriteLimit(error)) throw purgeWriteLimitError(operation, batch.length, progress.deleted, error)
        throw error
      }
      progress.deleted += batch.length
    }
    // Demostración de cero: re-lee tras borrar (invariante 11), solo los filtros que tenían algo.
    for (const { filter, what, keys } of read) {
      if (keys.length === 0) continue
      const residue = await this.#readAll(operation, filter)
      if (residue.length > 0) {
        throw new PurgeIncompleteError(
          `${operation}: quedan ${residue.length} tuplas de ${what} tras el borrado ` +
            `(${residue.slice(0, 3).map((k) => `${k.user}#${k.relation}@${k.object}`).join('; ')}). ` +
            `No se confirma la purga.`
        )
      }
    }
  }

  /* ── Helpers ────────────────────────────────────────────────────────────── */

  /**
   * **El envoltorio ÚNICO de `Read`** (B4, la otra mitad de la propiedad
   * universal): TODAS las tuplas que casan con el filtro, paginando `Read`
   * hasta agotar el `continuation_token`. `Read` no tiene tope de resultados
   * (a diferencia de `ListObjects`), así que es exhaustivo — por eso las purgas,
   * `listSubjects` y `enumerateRelations(Many)` van por aquí, no por
   * `ListObjects` — y cuando NO puede serlo, lanza 503 en vez de devolver una
   * página corta: una respuesta sin `tuples`, un token que se repite (el
   * servidor no avanza; una página vacía con token cae aquí) o más de
   * `MAX_READ_PAGES` páginas. La guardia de superficie (columna `truncation`)
   * sondea las cinco operaciones que entran por aquí con un mutante que
   * «termina» en la página vacía.
   */
  async #readAll(
    operation: string,
    filter: { user?: string; relation?: string; object?: string },
    /** R1: el presupuesto del gate de anidación (antes de cada página y con las tuplas de cada una). */
    pageHooks?: { before(): void; after(tuples: number): void }
  ): Promise<StoredRelationTuple[]> {
    const keys: StoredRelationTuple[] = []
    let continuationToken: string | undefined
    const seenTokens = new Set<string>()
    let pages = 0
    do {
      pageHooks?.before()
      const response = await this.#guard(operation, () =>
        this.client.read(filter, {
          pageSize: READ_PAGE_SIZE,
          continuationToken,
          consistency: this.#consistency,
        })
      )
      pages += 1
      // «Exhaustivo o ruidoso» (alpha.6): una respuesta que no trae `tuples`
      // no se entiende — no es una página vacía. Un 200 sin forma en el ORIGEN
      // de una migración sería «no hay nada» en silencio.
      if (!Array.isArray(response?.tuples)) {
        throw new AuthorizationBackendError(
          'openfga-relations',
          operation,
          new Error(`la respuesta del Read (página ${pages}) no trae 'tuples'; no se toma por vacía`)
        )
      }
      pageHooks?.after(response.tuples.length)
      for (const tuple of response.tuples) {
        const key: any = tuple?.key
        if (!key?.user || !key?.relation || !key?.object) {
          this.#warnUnparseable(operation, JSON.stringify(key ?? null))
          continue
        }
        // Con su caducidad (R-15): quien la lee decide si filtra (`listSubjects`),
        // la emite (`enumerateRelations`) o la ignora (`purge*` borra TODO).
        keys.push({ user: key.user, relation: key.relation, object: key.object, ...storedCondition(key.condition) })
      }
      continuationToken = response.continuation_token || undefined
      if (continuationToken) {
        if (seenTokens.has(continuationToken)) {
          throw new AuthorizationBackendError(
            'openfga-relations',
            operation,
            new Error(`el continuation_token se repite (página ${pages}); el servidor no avanza`)
          )
        }
        if (pages >= MAX_READ_PAGES) {
          throw new AuthorizationBackendError(
            'openfga-relations',
            operation,
            new Error(`más de ${MAX_READ_PAGES} páginas sin agotar el Read`)
          )
        }
        seenTokens.add(continuationToken)
      }
    } while (continuationToken)
    return keys
  }

  #warnUnparseable(operation: string, detail: string): void {
    this.diagnostics.unparseableTuples += 1
    this.#logger.warn(
      `authz(openfga-relations): tupla no parseable en ${operation} (${detail}); ` +
        `se ignora en la enumeración (total: ${this.diagnostics.unparseableTuples})`
    )
  }
}

// Cierre-2 de alpha.3 (⚪ 5 del re-ataque): la clasificación de timeout es la
// de `src/shared/backend_guard.ts` —`isTimeoutLike`: `KnexTimeoutError`,
// `.timeout` numérico, `ECONNABORTED`/`ETIMEDOUT`, por la cadena de `cause`—,
// la MISMA que importa el driver de roles. Hasta el cierre-2 este fichero
// duplicaba la función con una rama por SUBSTRING del mensaje (`/timeout/i`),
// de modo que un 400 de validación de FGA o el cuerpo de un 502 que mencionara
// la palabra salía como 503 `E_AUTHZ_BACKEND_TIMEOUT` con `indeterminate: true`
// sin haber borrado nada (medido por el auditor: `alpha3-cierre-parcial.ts` B).

/** La LETRA del 500 de N3 (fijada por `relations_openfga.spec`, «⚪ N3 · …»). */
function purgeWriteLimitError(operation: string, size: number, deleted: number, cause: unknown): AuthorizationConfigError {
  const sdk = (cause as { cause?: { apiErrorMessage?: unknown } } | null)?.cause?.apiErrorMessage
  // R3: es un fallo de DESPLIEGUE (transitorio para el relay), como el que ya clasificó `#guard`.
  return markDeploymentFailure(new AuthorizationConfigError(
    `OpenFgaRelationsDriver: ${operation}: el servidor OpenFGA rechazó un Write de ${size} tuplas por su tope de ` +
      `operaciones por Write (exceeded_entity_limit${typeof sdk === 'string' ? `: «${sdk}»` : ''}). El driver parte las ` +
      `purgas en RELATIONS_PURGE_WRITE_MAX = ${RELATIONS_PURGE_WRITE_MAX} y exige --max-tuples-per-write ≥ ` +
      `${RELATIONS_PURGE_WRITE_MAX} en el servidor (OPENFGA_MAX_TUPLES_PER_WRITE; el default es ${RELATIONS_PURGE_WRITE_MAX}). ` +
      `No es transitorio: repetida, la purga vuelve a fallar igual. ` +
      (deleted > 0
        ? `Ya se habían borrado ${deleted} tuplas en Write anteriores: la purga quedó A MEDIAS (escritura parcial).`
        : 'No se borró nada.'),
    { cause }
  ))
}

/**
 * **Los `Write` de una purga, en orden** (lote D · cierre 1 de D1, 🟠 1; ver `#purgeByFilters`): uno solo si todo cabe
 * en `RELATIONS_PURGE_WRITE_MAX`; si no, en el orden de BORRADO del punto de paso ÚNICO `relationDeleteOrder`
 * (`src/relations/tuple_order.ts`, cierre 1 de D2 · 🟠 1: el MISMO que usa el reconcile) — allows sobre objetos que no
 * son `group`, luego las membresías `group:*#member` (las portadoras de deny al final, ordenadas por objeto y sujeto) y
 * al final los `denied_*` —, con CADA CLASE en sus PROPIOS `Write` (con ≤ 100 membresías, uno). Pura: la tabla de verdad
 * del caso la juzga contra el servidor, y la PROPIEDAD la juzga sin servidor la guardia de superficie
 * (`GS · P · openfga.purge.order`, cierre 2 de D1 · ⚪ N2), con los mutantes de orden en el corredor publicado
 * (`npm run check:guard-mutants`). Exportada solo para eso: no sale por `/openfga`.
 */
export function purgeWrites<K extends { user: string; relation: string; object: string }>(keys: readonly K[]): K[][] {
  if (keys.length === 0) return []
  if (keys.length <= RELATIONS_PURGE_WRITE_MAX) return [[...keys]]
  const view = (k: K): RelationOrderView => ({ deny: k.relation.startsWith(RELATION_DENY_PREFIX), object: k.object, user: k.user })
  const ordered = relationDeleteOrder(keys, view)
  const chunks = (list: K[]): K[][] => {
    const out: K[][] = []
    for (let i = 0; i < list.length; i += RELATIONS_PURGE_WRITE_MAX) out.push(list.slice(i, i + RELATIONS_PURGE_WRITE_MAX))
    return out
  }
  // Cada CLASE en sus propios `Write`: una membresía nunca comparte lote con el último allow ni con el primer deny.
  const runs: K[][] = []
  let previous: string | undefined
  for (const k of ordered) {
    const cls = relationOrderClass(view(k))
    if (cls !== previous) runs.push([])
    runs[runs.length - 1].push(k)
    previous = cls
  }
  return runs.flatMap(chunks)
}

/**
 * **El error de una renovación en dos `Write` NOMBRA el deny que entró en la ventana** (cierre 3 de D2 · 🟡 C2-3). Sobre
 * el error que se propaga (su clase y su `code` no cambian): `carriedDeny` = el deny que la re-comprobación encontró, y la
 * letra con la receta; si la re-comprobación también falló, lo dice (`carriedDenyUnknown: true`). `applied` = la
 * renovación SÍ se aplicó y lo que falló es solo la re-comprobación. Un error congelado se propaga tal cual.
 */
function annotateRacedDeny<E extends object>(
  error: E,
  membership: string,
  recheck: { deny: string | null; error?: unknown },
  applied = false
): E {
  let note: string | null = null
  const target = error as any
  try {
    if (recheck.deny !== null) {
      target.carriedDeny = recheck.deny
      note =
        ` — Cierre 3 de D2 (C2-3): la membresía ${membership} quedó BORRADA y un deny concurrente (${recheck.deny}) que ` +
        'entró en el grupo durante la renovación ya NO alcanza al sujeto por ella, y no lo alcanzará hasta que la ' +
        'membresía se reescriba. Receta: vuelve a escribirla (relate: ya no existe, así que es UN Write) o retira y ' +
        'reescribe ese deny después.'
    } else if (recheck.error !== undefined) {
      target.carriedDenyUnknown = true
      note = applied
        ? ` — Cierre 3 de D2 (C2-3): la renovación de ${membership} SE APLICÓ, pero la re-comprobación de un deny ` +
          'concurrente en su grupo falló: no se sabe si un deny entró en la ventana entre los dos Write. Receta: lista los ' +
          'denies del grupo (listDenies) y revisa las decisiones de ese sujeto en esa ventana.'
        : ` — Cierre 3 de D2 (C2-3): la membresía ${membership} quedó BORRADA y la re-comprobación de un deny concurrente ` +
          'en su grupo también falló. Receta: vuelve a escribir la membresía (relate) y lista los denies del grupo.'
    }
    if (note !== null && typeof target.message === 'string') target.message += note
  } catch {
    // Un error congelado no admite la nota: se propaga el original (la clase y el `code` no cambian).
  }
  return error
}
