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
 * del SDK escapa (todo va por `#guard`, que clasifica a 503/timeout).
 */
import {
  OpenFgaClient,
  ConsistencyPreference,
  ClientWriteRequestOnMissingDeletes,
  ClientWriteRequestOnDuplicateWrites,
} from '@openfga/sdk'
import type { ConsistencyPreference as ConsistencyPreferenceType } from '@openfga/sdk'
import {
  AuthorizationBackendError,
  AuthorizationBackendTimeoutError,
  AuthorizationConfigError,
  InvalidIdentityError,
  PurgeIncompleteError,
  UnsupportedOperationError,
} from '../errors.js'
import { assertScope, assertSubject, assertRelationId, assertExpiresAt, scopeKey, scopeSpellings } from '../identity.js'
import { isClock, systemClock } from '../clock.js'
import type { Clock } from '../clock.js'
import { resolveGrantExpiry, sameInstant, toExpiryDate } from '../expiry.js'
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
  RelationWriteOptions,
  ScopeRef,
  SubjectRef,
} from '../types.js'
import type { HolderTypeMap } from './openfga_driver.js'
import {
  assertFgaObjectId,
  FACTS_EXPIRY_CONDITION,
  FACTS_GROUP_TYPE,
  FACTS_GROUP_MEMBER_RELATION,
} from './openfga_facts.js'
import { assertRelationDeclared } from '../relations/define_relations_config.js'
import type { RelationsConfig } from '../relations/define_relations_config.js'

export const DEFAULT_TIMEOUT_MS = 5_000
/** Tope de operaciones por `Write` en FGA (`exceeded_entity_limit` a partir de 100). */
const WRITE_BATCH_SIZE = 100
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
  /** Pin del model FUSIONADO; si se omite, FGA usa el último del store. */
  modelId?: string
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
}

/** Una tupla leída del store: la clave y, si la lleva, su caducidad (`valid_until`). */
interface StoredRelationTuple {
  user: string
  relation: string
  object: string
  validUntil: Date | null
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
   *    y este driver lo SEÑALA (medido contra el `:8103` de tope 3).
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
  readonly #logger: { warn(message: string): void }

  readonly diagnostics = { unparseableTuples: 0 }

  constructor(config: RelationsConfig, options: OpenFgaRelationsDriverOptions) {
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
    this.#logger = options.logger ?? console
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
    return view
  }

  /** El `context` de todo `Check`/`ListObjects`: la condición `not_expired` se evalúa contra este instante (un `now` por operación). */
  #checkContext(at: Date): { current_time: string } {
    return { current_time: at.toISOString() }
  }

  /* ── Clasificación de fallos (la abstracción no filtra) ─────────────────── */

  async #guard<T>(operation: string, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn()
    } catch (error) {
      // Un error del paquete (422/500 ya clasificado) se propaga tal cual.
      if (error instanceof InvalidIdentityError || error instanceof PurgeIncompleteError) throw error
      if (isTimeoutLike(error)) {
        throw new AuthorizationBackendTimeoutError('openfga-relations', operation, this.#timeoutMs, error)
      }
      throw new AuthorizationBackendError('openfga-relations', operation, error)
    }
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
   *    condición): entre ambas hay un instante en el que `check` responde
   *    `false` —fail-closed, la misma ventana que el `grant` de roles—.
   */
  async relate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    options?: RelationWriteOptions
  ): Promise<void> {
    // L-0 · F-05 en el DRIVER (defensa en profundidad, la MISMA función que el
    // manager): `manager.driver()` y `reconcileRelations` entran por aquí, y en
    // el store COMPARTIDO un tipo no declarado (`role_binding`) compondría el
    // id exacto de un binding de roles. Corta ANTES del `Read` y del `Write`.
    assertRelationDeclared(this.#config, object, relation)
    assertScope(partition)
    assertExpiresAt(options?.expiresAt)
    const partitionKey = scopeKey(partition)
    const objectId = this.#objectId(object.type, partitionKey, object.id)
    const user = this.#subjectUser(subject, partitionKey)
    const key = { user, relation, object: objectId }
    const now = this.#now()
    const current = await this.#readTuple('relate', key)
    const previous = current ? current.validUntil : null
    const expiresAt = resolveGrantExpiry(previous, options?.expiresAt, now)
    if (current && sameInstant(previous, expiresAt)) return
    const tuple = expiresAt
      ? { ...key, condition: { name: FACTS_EXPIRY_CONDITION, context: { valid_until: expiresAt.toISOString() } } }
      : key
    if (current) {
      await this.#guard('relate', () => this.client.write({ deletes: [key] }, IGNORE_MISSING_DELETES))
    }
    await this.#guard('relate', () => this.client.write({ writes: [tuple] }, IGNORE_DUPLICATE_WRITES))
  }

  /** La tupla EXACTA de una clave (un `Read` por clave completa), con su caducidad si la lleva. */
  async #readTuple(
    operation: string,
    key: { user: string; relation: string; object: string }
  ): Promise<StoredRelationTuple | null> {
    const response = await this.#guard(operation, () => this.client.read(key, { consistency: this.#consistency }))
    const found = (response.tuples ?? []).map((t) => t.key as any).find(
      (k) => k?.user === key.user && k?.relation === key.relation && k?.object === key.object
    )
    if (!found) return null
    return { ...key, validUntil: toExpiryDate(found.condition?.context?.valid_until) }
  }

  async unrelate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    _options?: RelationWriteOptions
  ): Promise<void> {
    // L-0 · F-05 también al RETIRAR: un `unrelate(alice, assignee, role_binding)`
    // sería un revoke de roles por la puerta de relaciones.
    assertRelationDeclared(this.#config, object, relation)
    assertScope(partition)
    const partitionKey = scopeKey(partition)
    const objectId = this.#objectId(object.type, partitionKey, object.id)
    const user = this.#subjectUser(subject, partitionKey)
    await this.#guard('unrelate', () =>
      // Re-unrelate no-op seguro: borrar una tupla ausente se ignora.
      this.client.write({ deletes: [{ user, relation, object: objectId }] }, IGNORE_MISSING_DELETES)
    )
  }

  /* ── Lecturas ───────────────────────────────────────────────────────────── */

  /** `check` = UN solo `Check` (el modelo resuelve includes + usersets). */
  async check(subject: RelSubject, relation: string, object: RelObject, partition: ScopeRef): Promise<boolean> {
    assertScope(partition)
    const partitionKey = scopeKey(partition)
    const objectId = this.#objectId(object.type, partitionKey, object.id)
    const user = this.#subjectUser(subject, partitionKey)
    const context = this.#checkContext(this.#now())
    const response = await this.#guard('check', () =>
      this.client.check({ user, relation, object: objectId, context }, { consistency: this.#consistency })
    )
    return response.allowed === true
  }

  /**
   * `listObjects` = `ListObjects` (resuelve includes + usersets del lado del
   * servidor) + FILTRO por partición + señal de TRUNCADO. `ListObjects` corta
   * al tope del servidor sin `continuation_token` ni bandera, así que el
   * truncado se detecta comparando el número de resultados CRUDOS con el tope
   * configurado (`listObjectsMaxResults`): `>= tope` ⇒ no se puede prometer la
   * lista completa ⇒ `truncated: true`. El filtro por partición se aplica
   * DESPUÉS (los ids llevan la partición), así que en un store con varias
   * particiones el tope se consume entre todas — otra razón para señalar el
   * truncado y no callar (documentado en el README).
   */
  async listObjects(
    subject: RelSubject,
    relation: string,
    objectType: string,
    partition: ScopeRef,
    _page?: RelationPage
  ): Promise<RelationObjectsPage> {
    assertScope(partition)
    const partitionKey = scopeKey(partition)
    const user = this.#subjectUser(subject, partitionKey)
    const context = this.#checkContext(this.#now())
    const response = await this.#guard('listObjects', () =>
      this.client.listObjects({ user, relation, type: objectType, context }, { consistency: this.#consistency })
    )
    const raw = response.objects ?? []
    const truncated = raw.length >= this.#listObjectsMax
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
  async listSubjects(
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    _page?: RelationPage
  ): Promise<RelationSubjectsPage> {
    assertScope(partition)
    const partitionKey = scopeKey(partition)
    const objectId = this.#objectId(object.type, partitionKey, object.id)
    // `Read` devuelve tuplas ESCRITAS, no evaluadas: la caducidad se filtra en
    // cliente con el MISMO reloj del driver (R-15, estricta: la que vence en
    // `now` ya no cuenta), como las enumeraciones del driver de roles.
    const now = this.#now()
    const tuples = await this.#readAll('listSubjects', { object: objectId, relation })
    const subjects: RelSubject[] = []
    for (const t of tuples) {
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
   */
  async enumerateRelations(partition: ScopeRef, _page?: RelationPage): Promise<RelationTuplePage> {
    assertScope(partition)
    const partitionKey = scopeKey(partition)
    const relationTypes = new Set<string>([FACTS_GROUP_TYPE, ...this.#config.objectTypes.map((t) => t.type)])
    const all = await this.#readAll('enumerateRelations', {})
    const tuples: RelationTuple[] = []
    for (const key of all) {
      const parsed = this.#parseObjectId(key.object)
      // No es una tupla de relación (facts: scope/role/role_binding, o un tipo
      // no declarado): no la migra este puerto.
      if (!parsed || !relationTypes.has(parsed.type)) continue
      if (parsed.partitionKey !== partitionKey) continue // otra partición: no cruza
      const subject = this.#userToSubject(key.user)
      if (!subject) {
        this.#warnUnparseable('enumerateRelations', key.user)
        continue
      }
      tuples.push({
        subject,
        relation: key.relation,
        object: { type: parsed.type, id: parsed.objectUuid },
        partition,
        expiresAt: key.validUntil,
      })
    }
    return { tuples }
  }

  /* ── Purga (invariante 11): borra y DEMUESTRA cero, o lanza ─────────────── */

  /**
   * Borra TODAS las tuplas del objeto (cualquier relación) y demuestra cero.
   * Barre las DOS ortografías del uuid de partición (🟡2, paridad con
   * `database`): un motor que funda `aaa…` con `aaa-…` dejaría la fila del
   * alias concediendo tras una purga «exitosa». Si tras borrar quedan tuplas
   * ⇒ 500 `E_AUTHZ_PURGE_INCOMPLETE`.
   */
  async purgeObject(object: RelObject, partition: ScopeRef): Promise<void> {
    assertScope(partition)
    const objectIds = this.#partitionSpellings(partition).map((key) =>
      this.#objectId(object.type, key, object.id)
    )
    for (const objectId of objectIds) {
      await this.#purgeByFilter('purgeObject', { object: objectId }, `objeto ${objectId}`)
    }
  }

  /**
   * Borra TODAS las tuplas cuyo SUJETO es este subject en la partición, en
   * cualquier tipo de objeto declarado, y demuestra cero. `Read` exige un
   * filtro de objeto (un `Read` solo por `user` es un 400 del servidor), así
   * que se recorre cada tipo declarado (`group` + los del consumidor) con
   * `Read({ user, object: '<type>:' })`.
   */
  async purgeSubject(subject: RelSubject, partition: ScopeRef): Promise<void> {
    assertScope(partition)
    if (!isRelUserset(subject)) assertSubject(subject)
    const partitionKeys = this.#partitionSpellings(partition)
    const types = [FACTS_GROUP_TYPE, ...this.#config.objectTypes.map((t) => t.type)]
    for (const partitionKey of partitionKeys) {
      const user = this.#subjectUser(subject, partitionKey)
      for (const type of types) {
        await this.#purgeByFilter(
          'purgeSubject',
          { user, object: `${type}:` },
          `sujeto ${user} en '${type}'`
        )
      }
    }
  }

  /** Lee por filtro, borra en lotes, y RE-LEE para demostrar cero (o lanza). */
  async #purgeByFilter(
    operation: string,
    filter: { user?: string; relation?: string; object: string },
    what: string
  ): Promise<void> {
    const keys = await this.#readAll(operation, filter)
    for (let i = 0; i < keys.length; i += WRITE_BATCH_SIZE) {
      await this.#guard(operation, () =>
        this.client.deleteTuples(
          keys.slice(i, i + WRITE_BATCH_SIZE).map((k) => ({ user: k.user, relation: k.relation, object: k.object })),
          IGNORE_MISSING_DELETES
        )
      )
    }
    if (keys.length === 0) return
    // Demostración de cero: re-lee tras borrar (invariante 11).
    const residue = await this.#readAll(operation, filter)
    if (residue.length > 0) {
      throw new PurgeIncompleteError(
        `${operation}: quedan ${residue.length} tuplas de ${what} tras el borrado ` +
          `(${residue.slice(0, 3).map((k) => `${k.user}#${k.relation}@${k.object}`).join('; ')}). ` +
          `No se confirma la purga.`
      )
    }
  }

  /* ── Helpers ────────────────────────────────────────────────────────────── */

  /** Las dos ortografías del uuid de partición, como claves de scope (🟡2). */
  #partitionSpellings(partition: ScopeRef): string[] {
    return [...new Set(scopeSpellings(partition).map((s) => scopeKey(s)))]
  }

  /**
   * TODAS las tuplas que casan con el filtro, paginando `Read` hasta agotar el
   * `continuation_token`. `Read` no tiene tope de resultados (a diferencia de
   * `ListObjects`), así que es exhaustivo — por eso las purgas y `listSubjects`
   * van por aquí, no por `ListObjects`.
   */
  async #readAll(
    operation: string,
    filter: { user?: string; relation?: string; object?: string }
  ): Promise<StoredRelationTuple[]> {
    const keys: StoredRelationTuple[] = []
    let continuationToken: string | undefined
    const seenTokens = new Set<string>()
    let pages = 0
    do {
      const response = await this.#guard(operation, () =>
        this.client.read(filter, {
          pageSize: READ_PAGE_SIZE,
          continuationToken,
          consistency: this.#consistency,
        })
      )
      pages += 1
      for (const tuple of response.tuples ?? []) {
        const key: any = tuple?.key
        if (!key?.user || !key?.relation || !key?.object) {
          this.#warnUnparseable(operation, JSON.stringify(key ?? null))
          continue
        }
        // Con su caducidad (R-15): quien la lee decide si filtra (`listSubjects`),
        // la emite (`enumerateRelations`) o la ignora (`purge*` borra TODO).
        keys.push({
          user: key.user,
          relation: key.relation,
          object: key.object,
          validUntil: toExpiryDate(key.condition?.context?.valid_until),
        })
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

/** ¿El error huele a timeout de red/axios? (mismo criterio que el driver de roles). */
function isTimeoutLike(error: unknown): boolean {
  let current: any = error
  for (let depth = 0; current && depth < 6; depth++) {
    const code = String(current.code ?? '')
    if (code === 'ECONNABORTED' || code === 'ETIMEDOUT' || /timeout/i.test(String(current.message ?? ''))) {
      return true
    }
    current = current.cause
  }
  return false
}
