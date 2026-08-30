import db from '@adonisjs/lucid/services/db'
import {
  OpenFgaClient,
  ClientWriteRequestOnDuplicateWrites,
  ClientWriteRequestOnMissingDeletes,
  ConsistencyPreference,
} from '@openfga/sdk'
import type { ClientBatchCheckItem, ClientBatchCheckSingleResponse } from '@openfga/sdk'
import {
  AuthorizationBackendError,
  AuthorizationBackendTimeoutError,
  AuthorizationConfigError,
  AuthorizationInternalError,
  InvalidIdentityError,
  PurgeIncompleteError,
  ScopeCycleError,
  ScopeDriftUnguardedError,
  ScopeTreeDriftError,
  StoreNotEmptyError,
  UnknownPermissionError,
  UnknownRoleError,
  WriteConflictError,
} from '../errors.js'
import type {
  AuthorizationDriver,
  CatalogProjection,
  CatalogProjectionReport,
  CatalogProjectionSnapshot,
  DenyRef,
  GrantOptions,
  GrantOutcome,
  HolderTypeMap,
  RoleQuery,
  ScopeChainResolver,
  ScopeOutbox,
  ScopeRef,
  ScopeType,
  SubjectRef,
} from '../types.js'
import { APP_SCOPE_TYPE } from '../types.js'
import {
  APP_SCOPE_DB_UUID,
  assertRoleAssignableAt,
  declaredRoleAt,
  hasRoleTargets,
  resolveRoleQuery,
  rolesToRevoke,
  visibleRoleFor,
} from './database_driver.js'
import {
  assertCatalogUuid,
  assertIdentity,
  assertScope,
  chainKeysFrom,
  isCatalogUuid,
  isValidScope,
  normalizeRoleQuery,
  scopeFromKey,
  scopeKey,
} from '../identity.js'
import { resolveGrantExpiry, sameInstant, toExpiryDate } from '../expiry.js'
import {
  assertKnownScope,
  canonicalScope,
  guardSql,
  isTimeoutLike,
  resolveChain,
  rootOnlyResolver,
  withDeadline,
} from './backend_guard.js'
import { CatalogCache, GLOBAL_OWNER_KEY, assertCatalogOptions, isRoleVisibleWith, withAuthzCatalogWrite } from '../catalog_cache.js'
import type { CatalogRevalidate, CatalogRole, CatalogRoleRef, CatalogView } from '../catalog_cache.js'
import {
  FACTS_ASSIGNEE_RELATION,
  FACTS_BINDING_RELATION,
  FACTS_BINDING_TYPE,
  FACTS_DENIED_PREFIX,
  FACTS_PARENT_RELATION,
  FACTS_PERMITS_PREFIX,
  FACTS_ROLE_RELATION,
  FACTS_ROLE_TYPE,
  FACTS_SCOPE_TYPE,
  assertFactsModelPublishable,
  assertHolderTypes,
  factsBindingTuples,
  factsCatalogTuples,
  factsDenyTuple,
  factsParentTuple,
  factsRelationsOf,
  factsScopeObject,
  factsTupleId,
} from './openfga_facts.js'
import type { FactsCatalogTuple, FactsTuple } from './openfga_facts.js'
import { isClock, systemClock } from '../clock.js'
import { sqlExpiryCodec } from './sql_expiry.js'
import type { Clock } from '../clock.js'

/**
 * Driver `openfga` — los HECHOS (asignaciones y denies) viven en un servidor
 * OpenFGA; el CATÁLOGO (roles/permisos/vínculos) y la JERARQUÍA (orgs/units)
 * siguen siendo metadata local en las tablas del chasis (split de propiedad
 * de datos del análisis: cambiar de driver = migrar una tabla de hechos).
 *
 * Modelo FGA genérico (ver `openFgaAuthorizationModel()`):
 *  - `role_binding:<scopeKey>|<roleUuid>`       #assignee → asignación de rol
 *  - `deny_binding:<scopeKey>|<permissionUuid>` #denied   → deny explícito
 *    (3A · A1: el id lleva el UUID del catálogo, nunca el slug. Un store
 *    escrito por 1.x/2.0–2.1 —ids con slug— NO lo lee 2.2: `openfga:import
 *    --reconcile` lo cuenta como `extra` y `--prune` lo borra. No hay comando
 *    de migración por decisión del dueño: no había stores en producción.)
 *  - Expiración vía condition `not_expired` (valid_until en la tupla,
 *    current_time en cada check) — ni scheduler necesita.
 *
 * La herencia se resuelve igual que en el driver database: la cadena de
 * scopes se calcula localmente (el árbol lo declara el consumidor vía
 * `resolveChain`) y se consulta FGA por batchCheck sobre la cadena.
 *
 * NADA del dominio está cableado: los holders llegan como `holderTypes`
 * (morph name → tipo FGA) y los niveles de scope se derivan del propio
 * `ScopeRef`, así que un consumidor con otros guards u otra jerarquía solo
 * cambia config.
 */

/**
 * Mapa morph name → tipo del modelo FGA (`users` → `user`). Debe ser el
 * MISMO con el que se generó el authorization model del store. Definido en
 * el puerto (`types.ts`) y re-exportado aquí.
 */
export type { HolderTypeMap }

/**
 * La inyectividad de `holderTypes` la comprueba el módulo del modelo
 * (`openfga_facts.ts`, compartido por los dos generadores). Se re-exporta
 * desde aquí porque el subpath `/openfga` es la puerta publicada.
 */
export { assertHolderTypes }

// La clave de scope del id del binding (`app` | `<tipo>|<uuid>`) es la
// misma `scopeKey` del paquete (`identity.ts`; desde 3B también el owner de
// un rol local): `|` es el separador y `assertScope` impide que un
// componente lo lleve (dos scopes distintos no producen la misma clave) y
// rechaza `{app, uuid}` (L0.10).

/**
 * Id de binding (`<scopeKey>|<uuid>`: `app|<uuid>` o `<tipo>|<uuidScope>|<uuid>`)
 * → scope + uuid del catálogo (del rol en `role_binding`, del permiso en
 * `deny_binding`). Se parsea DESDE LA DERECHA (3A · A1): el último componente
 * es el uuid y el resto la clave del scope, que tiene 1 parte (`app`) o 2
 * (`<tipo>|<uuid>`). Antes el último componente era el slug codificado
 * (`docs~read`) y el parseo contaba partes: ambiguo en cuanto la clave del
 * scope variara de longitud (panel 2026-08-28, §2-C), y con un escape no
 * inyectivo desde el llamante (L0.8a).
 *
 * `null` si no tiene la forma del motor O si alguna parte no pasa su
 * gramática —el scope, la de identidad; el uuid, la de UUID canónico del
 * catálogo—: un id que el driver no escribiría no es un hecho del motor
 * aunque esté en el store. Los ids de 1.x/2.0–2.1 (con slug) caen aquí:
 * 2.2 no los lee, y `openfga:import --reconcile` los cuenta como `extra`.
 * Exportada para probarla sin servidor.
 */
export function parseBindingId(id: string): { scope: ScopeRef; uuid: string } | null {
  const cut = id.lastIndexOf('|')
  if (cut < 0) return null
  const uuid = id.slice(cut + 1)
  const keyParts = id.slice(0, cut).split('|')
  let scope: ScopeRef
  if (keyParts.length === 1 && keyParts[0] === APP_SCOPE_TYPE) {
    scope = { type: APP_SCOPE_TYPE, uuid: null }
  } else if (keyParts.length === 2) {
    scope = { type: keyParts[0], uuid: keyParts[1] }
  } else {
    return null
  }
  if (!isValidScope(scope) || !isCatalogUuid(uuid)) return null
  return { scope, uuid }
}

/** `<tipoFga>:<uuid>` a partir del morph name del holder. */
function fgaSubjectWith(subject: SubjectRef, holderTypes: HolderTypeMap): string {
  const fgaType = holderTypes[subject.type]
  if (!fgaType) {
    // Contradicción de config (D15): el modelo del store no tiene ese tipo.
    throw new AuthorizationConfigError(
      `Holder type '${subject.type}' no está en el modelo FGA ` +
        `(declarados: ${Object.keys(holderTypes).join(', ') || 'ninguno'}). ` +
        `Añádelo a holderTypes y regenera el authorization model.`
    )
  }
  return `${fgaType}:${subject.uuid}`
}

/**
 * El `context` de TODA consulta que evalúe relaciones: checks de roles y de
 * denies. Un único constructor a propósito (S17): en cuanto una tupla del
 * camino lleva la condición `not_expired`, un check sin `current_time` falla
 * entero (400 → 503). Hoy los denies no llevan condición; el modo facts (3b)
 * evalúa deny y grant en un solo check, así que no hay margen. Las
 * enumeraciones no evalúan nada (`Read` devuelve tuplas escritas): filtran
 * la caducidad en cliente con el MISMO reloj del driver (`now()`, J1): el
 * `current_time` que viaja en cada check es el instante que decide.
 */
function checkContext(now: Date): { current_time: string } {
  return { current_time: now.toISOString() }
}

/**
 * Alinea los resultados de un batchCheck con los checks pedidos por
 * `correlationId`, no por posición (L0.14). El SDK reparte el lote en
 * sub-lotes paralelos y concatena las respuestas según llegan: el orden no es
 * el de los checks. Cardinalidad igual no basta —un id duplicado y otro
 * ausente pasan el conteo—: cada check debe tener EXACTAMENTE un resultado y
 * ningún resultado puede ser de un check que no se pidió.
 */
export function correlateBatchResults(
  checks: ClientBatchCheckItem[],
  results: ClientBatchCheckSingleResponse[]
): ClientBatchCheckSingleResponse[] {
  const byId = new Map<string, ClientBatchCheckSingleResponse>()
  for (const result of results) {
    const id = result.correlationId
    if (byId.has(id)) {
      throw new AuthorizationInternalError(
        `OpenFGA batchCheck devolvió dos resultados para el correlationId '${id}'`
      )
    }
    byId.set(id, result)
  }
  const aligned = checks.map((check) => {
    const result = byId.get(check.correlationId!)
    if (!result) {
      throw new AuthorizationInternalError(
        `OpenFGA batchCheck no devolvió resultado para el check '${check.correlationId}' (${check.relation} ${check.object})`
      )
    }
    return result
  })
  if (byId.size !== checks.length) {
    const requested = new Set(checks.map((c) => c.correlationId))
    const foreign = [...byId.keys()].filter((id) => !requested.has(id))
    throw new AuthorizationInternalError(
      `OpenFGA batchCheck devolvió resultados de checks no pedidos: ${foreign.join(', ')}`
    )
  }
  return aligned
}

/**
 * El authorization model en formato JSON del API de FGA, generado a partir
 * de los holders del consumidor. El mismo mapa debe usarse al construir el
 * driver: si difieren, los checks no encuentran las tuplas.
 */
export function openFgaAuthorizationModel(holderTypeMap: HolderTypeMap): any {
  assertHolderTypes(holderTypeMap)
  const holderTypes = Object.values(holderTypeMap)
  const direct = holderTypes.map((type) => ({ type }))
  const directWithExpiry = [
    ...direct,
    ...holderTypes.map((type) => ({ type, condition: 'not_expired' })),
  ]
  return {
    schema_version: '1.1',
    type_definitions: [
      ...holderTypes.map((type) => ({ type, relations: {}, metadata: null })),
      {
        type: 'role_binding',
        relations: { assignee: { this: {} } },
        metadata: {
          relations: { assignee: { directly_related_user_types: directWithExpiry } },
        },
      },
      {
        type: 'deny_binding',
        relations: { denied: { this: {} } },
        metadata: {
          relations: { denied: { directly_related_user_types: direct } },
        },
      },
    ],
    conditions: {
      not_expired: {
        name: 'not_expired',
        expression: 'current_time < valid_until',
        parameters: {
          current_time: { type_name: 'TYPE_NAME_TIMESTAMP' },
          valid_until: { type_name: 'TYPE_NAME_TIMESTAMP' },
        },
      },
    },
  }
}

/**
 * Crea un store nuevo + escribe el authorization model derivado de los
 * holders del consumidor. Para bootstrap de un appliance o del harness de
 * tests. El `name` lo decide el caller (el comando openfga:provision
 * resuelve APP_NAME del entorno — el motor no lee env).
 */
export async function provisionOpenFgaStore(
  apiUrl: string,
  name: string,
  holderTypeMap: HolderTypeMap
): Promise<{ storeId: string; modelId: string }> {
  const client = new OpenFgaClient({ apiUrl })
  const store = await client.createStore({ name })
  const scoped = new OpenFgaClient({ apiUrl, storeId: store.id })
  const model = await scoped.writeAuthorizationModel(openFgaAuthorizationModel(holderTypeMap))
  return { storeId: store.id!, modelId: model.authorization_model_id! }
}

/**
 * ¿El error (o su cadena de causas) es el rechazo de FGA a escribir una tuple
 * key que ya existe? Es la ÚNICA señal de carrera check-then-write que
 * `grant` acepta: un 400 de validación (`validation_error`) o un 5xx no son
 * "alguien escribió antes" y se propagan clasificados, con el error del SDK
 * como causa (D6). Verificado contra OpenFGA v1.19: el duplicado llega como
 * HTTP 400 con `apiErrorCode: 'write_failed_due_to_invalid_input'` y el
 * mensaje "cannot write a tuple which already exists".
 *
 * **Y el 409 tiene nombre propio** (3b-2f · R3, medido contra el servidor):
 * es el `Aborted` de un `Write` transaccional cuyas tuplas escribió otra
 * transacción a la vez ("transactional write failed due to conflict: one or
 * more tuples to write were inserted by another transaction"). Dice lo mismo
 * —otro escritor llegó antes— y se trata igual: releer y re-aplicar. Lo que
 * NO dice es QUÉ tupla chocó, así que quién existía lo decide la relectura y
 * nunca el mensaje.
 */
export function isDuplicateWrite(error: unknown): boolean {
  let current: any = error
  for (let depth = 0; current && depth < 6; depth++) {
    if (current.statusCode === 409) return true
    if (
      current.apiErrorCode === 'write_failed_due_to_invalid_input' &&
      /already exists/i.test(String(current.apiErrorMessage ?? current.message ?? ''))
    ) {
      return true
    }
    current = current.cause
  }
  return false
}

/**
 * Receta que acompaña al 503 de un `grant` SIN `expiresAt` cuando no se pudo
 * leer la caducidad vigente: preservar exige saber qué hay, y asumir
 * "permanente" sería L0.4 en modo degradado. Se añade al mensaje del error
 * ya clasificado (mismo tipo, mismo `code`, misma causa).
 */
function withPreserveRecipe<T extends Error>(error: T): T {
  error.message +=
    `. 'grant' sin 'expiresAt' necesita leer la caducidad vigente para preservarla y no se ` +
    `escribe a ciegas: si la intención es "permanente", pasa { expiresAt: null }; si es temporal, una Date.`
  return error
}

/**
 * Devuelve el cliente con TODOS sus métodos envueltos: un fallo de red o un
 * 5xx sale como `AuthorizationBackendError` (503) y no como el `FgaError` del
 * SDK, que acoplaría el call-site al backend que este paquete abstrae.
 *
 * Se envuelve el cliente entero, y no llamada por llamada, a propósito: con
 * once puntos de invocación lo fácil es olvidar uno, y quien añada el número
 * doce no tendría por qué saber que debe envolverlo. Así la garantía se
 * cumple por construcción en vez de por disciplina.
 *
 * Solo lo usa el driver. `provisionOpenFgaStore` y el importador son
 * herramientas explícitamente de OpenFGA —las invocas por su nombre—, así que
 * ahí el error del SDK es la información más útil y no rompe ninguna
 * abstracción.
 */
function guardBackendErrors(client: OpenFgaClient, timeoutMs: number): OpenFgaClient {
  return new Proxy(client, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver)
      if (typeof value !== 'function') return value
      return (...args: unknown[]) => {
        const operation = String(prop)
        const fail = (cause: unknown) =>
          isTimeoutLike(cause)
            ? new AuthorizationBackendTimeoutError('openfga', operation, timeoutMs, cause)
            : new AuthorizationBackendError('openfga', operation, cause)
        try {
          const result = (value as (...a: unknown[]) => unknown).apply(target, args)
          if (!(result instanceof Promise)) return result
          // Deadline TOTAL por llamada (reintentos del SDK incluidos): el
          // `timeout` de axios corta cada intento, pero el SDK reintenta los
          // errores de red con backoff y sin esto el llamante esperaría la
          // suma de todos. Un deadline es un deadline.
          return withDeadline(
            result.catch((error: unknown) => {
              throw fail(error)
            }),
            timeoutMs,
            () => new AuthorizationBackendTimeoutError('openfga', operation, timeoutMs)
          )
        } catch (error) {
          throw fail(error)
        }
      }
    },
  })
}

export interface OpenFgaDriverOptions {
  apiUrl: string
  storeId: string
  /** Pin del model; si se omite, FGA usa el último. */
  modelId?: string
  /** Jerarquía del consumidor (ver ScopeChainResolver). */
  resolveChain?: ScopeChainResolver
  /**
   * Holders del consumidor: morph name → tipo FGA. Debe coincidir con el
   * mapa usado al escribir el authorization model del store.
   */
  holderTypes: HolderTypeMap
  /**
   * Dónde avisar de lo que el driver ve y no puede representar (bindings que
   * no entiende). Inyectado y síncrono a propósito: el logger de la app en
   * producción, la consola por defecto, un array en los tests.
   */
  logger?: { warn(message: string): void }
  /**
   * Deadline de cada llamada (catálogo SQL y FGA) en ms, default 5000.
   * Vencido ⇒ 503 `E_AUTHZ_BACKEND_TIMEOUT` (L0.13).
   */
  timeoutMs?: number
  /**
   * Consistencia pedida al servidor en cada lectura. Default
   * `higher_consistency`: con la caché de Check activada en el servidor
   * (`--check-query-cache-enabled`, TTL 10 s) un revoke o un deny recién
   * escritos seguirían concediendo hasta que expire; el paquete promete que
   * "quitar el deny restaura" y lo garantiza él (S11). `minimize_latency` es
   * el opt-out explícito: "acepto hasta N segundos de fail-open a cambio de
   * latencia".
   */
  consistency?: 'higher_consistency' | 'minimize_latency'
  /**
   * Reintentos del SDK ante errores de red. Default `{ maxRetry: 0 }`: el
   * paquete libera al llamante con 503 al vencer `timeoutMs`, y un SDK que
   * siguiera reintentando en segundo plano haría aterrizar la escritura
   * DESPUÉS del error, sin evento `onWrite` — una escritura fantasma (D2).
   * Con reintentos, el llamante recibe además `indeterminate: true` en el
   * hook cuando la escritura vence el deadline; activarlos es aceptar que un
   * 503 por timeout puede haber escrito.
   */
  retryParams?: { maxRetry?: number; minWaitInMs?: number }
  /**
   * Memo del catálogo compartido con otro driver del mismo proceso (2A). Si
   * se omite, el driver construye el suyo. Se revalida contra la versión
   * compartida de la base (`authz_catalog_version`) según `catalogRevalidate`.
   */
  catalog?: CatalogCache
  /**
   * Cuándo contrastar el memo con la versión compartida (2D · F1): `'always'`
   * (default; un SELECT por clave primaria por pregunta) o `{ everyMs }`
   * (opt-in: ventana acotada en la que un sync de OTRO proceso aún no se ve).
   * Solo aplica al memo que construye este driver.
   */
  catalogRevalidate?: CatalogRevalidate
  /**
   * Reloj de pared del driver (2.5 · J1): el `current_time` de cada check
   * (la condición `not_expired` se evalúa contra él), el filtro de caducidad
   * en cliente de las enumeraciones y los tres estados del re-grant. Default
   * `() => new Date()`. Inyectable para fijar el instante en tests; en
   * producción lo normal es `clock` en el config del manager (`withClock`).
   */
  now?: Clock
  /**
   * Dónde vive el ÁRBOL de scopes (3b-2b). Default `'resolver'`: el de hoy
   * —la jerarquía la resuelve el paquete con `resolveChain` y `scopes.*` no
   * escribe nada en el store—. Con `'facts'` el árbol se materializa como
   * hechos: `scopes.attached/moved/detached` mantienen UNA arista
   * `scope:<hijo>#parent@scope:<padre>` por nodo, que es lo que el modelo
   * (c2) necesita para heredar hacia abajo sin preguntarle al consumidor.
   *
   * El anti-ciclos sigue siendo del PAQUETE en los dos modos, y no es
   * opcional: FGA acepta un ciclo de `parent`, no se cuelga, responde en 2-7
   * ms y la herencia se vuelve BIDIRECCIONAL —un grant en un descendiente
   * concede en el ancestro— sin decir nada (cruce 3 del panel 2, reproducido
   * en la suite contra el servidor real).
   */
  hierarchy?: 'resolver' | 'facts'
  /**
   * La outbox del árbol del config (`scopes.outbox`), la MISMA instancia
   * (3b-2d). El driver no la usa para nada: quien encola es el manager. Está
   * aquí como EVIDENCIA del gate — un driver `facts` que se construye sin
   * ella y sin `acceptScopeDriftRisk` es un montaje en el que un `rollback`
   * del consumidor deja una escalada persistente e invisible (cruce 4 · S5),
   * y eso se descubre al construir, no en la primera escritura de un tenant.
   */
  outbox?: ScopeOutbox
  /**
   * «Sé que sin outbox un rollback de mi transacción deja el árbol de FGA
   * adelantado al mío, y lo asumo». Es la salida explícita del gate para
   * quien mueve el árbol solo desde la plataforma, en un proceso que no
   * comparte transacción con nada. Tiene que ser el booleano `true`: un
   * valor «truthy» no es una aceptación.
   */
  acceptScopeDriftRisk?: boolean
}

/**
 * **El gate de construcción de `facts`** (3b-2d, panel 2 cruce 4 · S5).
 *
 * En `hierarchy: 'facts'` el árbol vive en el store de FGA y FGA es el PDP.
 * El consumidor notifica `scopes.moved` dentro de su transacción, el paquete
 * escribe la arista en FGA… y si esa transacción hace `rollback` —una
 * constraint, una validación, un timeout de pool: no hace falta un crash—
 * la escritura de FGA NO se deshace. SQL sigue diciendo que la unit es del
 * tenant A y FGA que es del B: todos los holders con rol en B tienen acceso
 * a una unidad de A, y la aplicación, que lista y audita contra SQL, no
 * puede verlo. La ventana no es un hueco entre dos operaciones: dura hasta
 * que alguien lo descubra.
 *
 * Por eso `scopes.outbox` no puede ser una recomendación: una recomendación
 * no es un mecanismo. O está el puerto, o está la firma del dueño.
 */
export function assertScopeDriftGuarded(
  hierarchy: 'resolver' | 'facts',
  options: { outbox?: ScopeOutbox; acceptScopeDriftRisk?: boolean }
): void {
  if (hierarchy !== 'facts') return
  if (options.outbox) return
  if (options.acceptScopeDriftRisk === true) return
  throw new ScopeDriftUnguardedError(
    "OpenFgaAuthorizationDriver con hierarchy: 'facts' necesita la outbox del árbol: pasa la misma " +
      "'scopes.outbox' del config (el manager encola ahí los cambios del árbol dentro de TU transacción y " +
      "'authz:scopes:relay' los aplica). Sin ella, un rollback de tu transacción deja el árbol de FGA " +
      'adelantado al tuyo y esa escalada no se ve desde tu base. Si mueves el árbol solo desde la ' +
      "plataforma y lo asumes, dilo por escrito con acceptScopeDriftRisk: true."
  )
}

export const DEFAULT_TIMEOUT_MS = 5_000
/**
 * Opciones de un `Write` que da por buena una tupla que ya estaba. Solo se
 * usa donde el duplicado es IDÉNTICO por construcción (las aristas de (c2),
 * que no llevan condición) o donde ya se sabe que la asignación no existe:
 * en FGA la condición NO es parte de la clave, así que ignorar duplicados
 * sobre una tupla con caducidad se quedaría la vieja (ver `StoreNotEmptyError`).
 */
const IGNORE_DUPLICATE_WRITES = {
  conflict: { onDuplicateWrites: ClientWriteRequestOnDuplicateWrites.Ignore },
}
/**
 * Vueltas que da el `grant` ante un choque de escritura antes de rendirse con
 * un 409 (3b-2f · R3). Dos bastan para el caso real —la primera descubre que
 * la estructura ya estaba, la segunda la da por buena—; la tercera es el
 * margen para una contención de verdad.
 */
const GRANT_WRITE_ATTEMPTS = 3
/** Tope de operaciones por `Write` en FGA (verificado: `exceeded_entity_limit` a partir de 100). */
const PURGE_BATCH_SIZE = 100
/** Tamaño de página de `Read` (máximo del servidor). */
const READ_PAGE_SIZE = 100
/**
 * Cota de páginas de una enumeración (1.000.000 de tuplas a 100 por página).
 * Un `continuation_token` que no avanza —un servidor roto, un proxy o una
 * caché delante— era un bucle infinito que ningún deadline cortaba, porque
 * el deadline es por llamada (D12, auditor H7).
 */
export const MAX_READ_PAGES = 10_000
/**
 * Tope de saltos al subir el árbol DEL STORE (3b-2e · E1). No es el techo de
 * decisión —ese lo pone el servidor al evaluar (c2) y está medido en
 * `FACTS_MAX_RESOLVE_DEPTH`—: es la red del recorrido, para que un árbol con
 * una deriva que el anti-ciclos no vio no deje el proceso dando vueltas.
 */
export const MAX_SCOPE_CHAIN_HOPS = 1_000

export interface ImportFactsResult {
  /** Tuplas nuevas escritas. */
  written: number
  /** Tuplas que existían con OTRA condición y se reescribieron (delete+write). */
  updated: number
  /** Tuplas que ya estaban exactamente igual. */
  unchanged: number
  /**
   * Tuplas `role_binding`/`deny_binding` del store SIN correspondencia en SQL
   * (un grant revocado en SQL, un holder que nunca estuvo, una asignación ya
   * expirada). Solo se cuentan con `reconcile` (D14); sin `prune` siguen
   * concediendo y el reporte lo dice.
   */
  extra: number
  /** De las `extra`, las borradas (`prune`). En `dryRun`, las que se borrarían. */
  deleted: number
  /** Asignaciones ya expiradas en SQL, no se copian. */
  skippedExpired: number
  dryRun: boolean
}

export interface ImportFactsOptions {
  dryRun?: boolean
  /**
   * Permite importar sobre un store CON tuplas: por cada hecho se lee la
   * tupla exacta; ausente ⇒ write, presente con otra condición ⇒ delete+write
   * (`updated`), igual ⇒ `unchanged`. Además se lee el store ENTERO
   * (`Read({})` paginado) y lo que SQL no tiene se cuenta como `extra` (D14).
   * Sin esto, un store no vacío es 409 `E_AUTHZ_STORE_NOT_EMPTY`.
   */
  reconcile?: boolean
  /**
   * Con `reconcile`: borra las tuplas `extra` (`deleted`). Es lo que hace que
   * el reconcile CONVERJA: sin prune, un reporte de ceros no distingue "en
   * sync" de "sobra algo que sigue concediendo". Sin `reconcile` es 500
   * `E_AUTHZ_CONFIG`.
   */
  prune?: boolean
  /** Reloj con el que se decide qué asignación de SQL ya expiró (`skippedExpired`). Default: la hora del proceso. */
  now?: Clock
}

/**
 * Recorre TODAS las páginas de un `Read` con la misma cota que el driver
 * (D12): token repetido o más de `MAX_READ_PAGES` páginas ⇒ 500. Lo usa el
 * importador, que trabaja con un cliente crudo (herramienta FGA).
 */
async function* readPages(
  client: OpenFgaClient,
  filter: { user?: string; relation?: string; object?: string }
): AsyncGenerator<any> {
  let continuationToken: string | undefined
  const seen = new Set<string>()
  let pages = 0
  do {
    const response = await client.read(filter, {
      pageSize: READ_PAGE_SIZE,
      continuationToken,
      consistency: ConsistencyPreference.HigherConsistency,
    })
    pages += 1
    for (const tuple of response.tuples ?? []) yield tuple
    continuationToken = response.continuation_token || undefined
    if (continuationToken) {
      if (seen.has(continuationToken)) {
        throw new AuthorizationInternalError(`Read: el continuation_token se repite (página ${pages})`)
      }
      if (pages >= MAX_READ_PAGES) {
        throw new AuthorizationInternalError(`Read: más de ${MAX_READ_PAGES} páginas sin agotar el continuation_token`)
      }
      seen.add(continuationToken)
    }
  } while (continuationToken)
}

/** Clave textual de una tupla, para comparar conjuntos. */
function tupleId(key: { user: string; relation: string; object: string }): string {
  return `${key.user}#${key.relation}@${key.object}`
}

/** Un hecho de SQL expresado como tupla FGA (clave + caducidad). */
interface FactTuple {
  key: { user: string; relation: string; object: string }
  expiresAt: Date | null
}

function tupleOf(fact: FactTuple): any {
  return fact.expiresAt
    ? {
        ...fact.key,
        condition: { name: 'not_expired', context: { valid_until: fact.expiresAt.toISOString() } },
      }
    : fact.key
}

/** Tope de tuplas por `Write` transaccional de FGA. */
const IMPORT_BATCH_SIZE = 100

/**
 * Migración de hechos database → openfga: copia las asignaciones vigentes y
 * los denies de las tablas `authz_*` como tuples del store FGA.
 *
 * - COPIA, no mueve: las tablas locales quedan intactas → el rollback es
 *   volver a AUTHZ_DRIVER=database (solo se pierde lo escrito mientras se
 *   operó con openfga). El catálogo y la jerarquía nunca migran: son
 *   metadata local para ambos drivers.
 * - Las asignaciones ya expiradas se saltan (no tiene sentido copiarlas);
 *   las de expiración futura viajan con la condition `not_expired`.
 * - NUNCA `onDuplicateWrites: Ignore` (S7): en FGA la condición no es parte
 *   de la clave, así que "ignorar el duplicado" dejaba la caducidad vieja y
 *   reportaba éxito. Un store con tuplas exige `reconcile`, que compara
 *   tupla a tupla, reescribe las que difieren y cuenta las que SQL no tiene
 *   (`extra`); con `prune` las borra (`deleted`) y el reconcile converge
 *   (D14). Nunca silencioso: el reporte distingue written / updated /
 *   unchanged / extra / deleted / skippedExpired.
 *
 * Herramienta explícitamente de OpenFGA: los errores del SDK salen crudos.
 */
export async function importAuthzFactsToOpenFga(
  options: OpenFgaDriverOptions & ImportFactsOptions
): Promise<ImportFactsResult> {
  assertHolderTypes(options.holderTypes)
  if (options.prune && !options.reconcile) {
    throw new AuthorizationConfigError(
      'openfga:import: `prune` solo tiene sentido con `reconcile` (es lo que sobra respecto a SQL lo que se borra)'
    )
  }
  const client = new OpenFgaClient({
    apiUrl: options.apiUrl,
    storeId: options.storeId,
    authorizationModelId: options.modelId,
  })

  const now = (options.now ?? systemClock)()
  const result: ImportFactsResult = {
    written: 0,
    updated: 0,
    unchanged: 0,
    extra: 0,
    deleted: 0,
    skippedExpired: 0,
    dryRun: options.dryRun ?? false,
  }

  const rowScope = (row: any): ScopeRef => ({
    type: row.scope_type,
    uuid: row.scope_uuid === APP_SCOPE_DB_UUID ? null : row.scope_uuid,
  })
  const facts: FactTuple[] = []

  // `expires_at` se lee con el codec del motor (2.5-B · K2): en MySQL como
  // cadena UTC vía DATE_FORMAT, sin depender de la zona del cliente.
  const expiry = sqlExpiryCodec(db.connection())
  const assignments = await db
    .from('authz_assignments as a')
    .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
    .select('a.holder_type', 'a.holder_uuid', 'a.scope_type', 'a.scope_uuid', expiry.select('a.expires_at', 'expires_at') as any)
    .select('r.uuid as role_uuid')
  for (const row of assignments) {
    const expiresAt = expiry.fromDb(row.expires_at)
    if (expiresAt && expiresAt <= now) {
      result.skippedExpired++
      continue
    }
    facts.push({
      key: {
        user: fgaSubjectWith({ type: row.holder_type, uuid: row.holder_uuid }, options.holderTypes),
        relation: 'assignee',
        object: `role_binding:${scopeKey(rowScope(row))}|${row.role_uuid}`,
      },
      expiresAt,
    })
  }

  const denies = await db
    .from('authz_denies as d')
    .join('authz_permissions as p', 'p.uuid', 'd.permission_uuid')
    .select('d.holder_type', 'd.holder_uuid', 'd.scope_type', 'd.scope_uuid')
    .select('p.uuid as permission_uuid')
  for (const row of denies) {
    facts.push({
      key: {
        user: fgaSubjectWith({ type: row.holder_type, uuid: row.holder_uuid }, options.holderTypes),
        relation: 'denied',
        object: `deny_binding:${scopeKey(rowScope(row))}|${row.permission_uuid}`,
      },
      expiresAt: null,
    })
  }

  // ¿Store vacío? Un Read sin filtro devuelve cualquier tupla que haya.
  const probe = await client.read({}, { pageSize: 1 })
  const storeIsEmpty = (probe.tuples ?? []).length === 0
  if (!storeIsEmpty && !options.reconcile) {
    throw new StoreNotEmptyError(
      `El store ${options.storeId} ya tiene tuplas. Importar encima sin comparar dejaría ` +
        `caducidades viejas en pie: usa --reconcile (compara tupla a tupla) o un store nuevo.`
    )
  }

  const toWrite: FactTuple[] = []
  const toReplace: FactTuple[] = []
  const toDelete: Array<{ user: string; relation: string; object: string }> = []
  if (storeIsEmpty) {
    toWrite.push(...facts)
  } else {
    for (const fact of facts) {
      const stored = await client.read(fact.key)
      const tuple = stored.tuples?.[0]
      if (!tuple) {
        toWrite.push(fact)
        continue
      }
      const storedExpiry = toExpiryDate((tuple.key as any)?.condition?.context?.valid_until)
      if (sameInstant(storedExpiry, fact.expiresAt)) result.unchanged++
      else toReplace.push(fact)
    }
    // Lo que el store tiene de MÁS (D14): se lee entero y se resta el
    // conjunto de SQL. Solo los objetos del motor; nada más vive en este
    // modelo, pero si algo hubiera no es asunto del importador.
    const wanted = new Set(facts.map((f) => tupleId(f.key)))
    for await (const tuple of readPages(client, {})) {
      const k: any = tuple?.key
      if (!k?.user || !k?.relation || !k?.object) continue
      if (!/^(role_binding|deny_binding):/.test(k.object)) continue
      const key = { user: k.user, relation: k.relation, object: k.object }
      if (!wanted.has(tupleId(key))) toDelete.push(key)
    }
  }
  result.written = toWrite.length
  result.updated = toReplace.length
  result.extra = toDelete.length
  result.deleted = options.prune ? toDelete.length : 0
  if (result.dryRun) return result

  // Sin Ignore: en un store vacío un duplicado es un bug (dos filas de SQL
  // con la misma clave, imposible por el unique) y debe verse.
  for (let i = 0; i < toWrite.length; i += IMPORT_BATCH_SIZE) {
    await client.writeTuples(toWrite.slice(i, i + IMPORT_BATCH_SIZE).map(tupleOf))
  }
  // delete + write no caben en una misma request para la misma clave.
  for (let i = 0; i < toReplace.length; i += IMPORT_BATCH_SIZE) {
    const batch = toReplace.slice(i, i + IMPORT_BATCH_SIZE)
    await client.deleteTuples(batch.map((f) => f.key))
    await client.writeTuples(batch.map(tupleOf))
  }
  if (options.prune) {
    for (let i = 0; i < toDelete.length; i += IMPORT_BATCH_SIZE) {
      await client.deleteTuples(toDelete.slice(i, i + IMPORT_BATCH_SIZE))
    }
  }
  return result
}

export class OpenFgaAuthorizationDriver implements AuthorizationDriver {
  /**
   * Lo que este driver declara (3b-2e · E2). Depende del MODO, así que es un
   * getter y no un campo: una vista por prototipo (`withChainResolver`,
   * `withClock`) declara lo mismo que su original.
   *
   * `roleInheritanceNative` y `listObjectsInherited` son `false` **también en
   * `facts`**, y eso es el cruce 6 del panel: `hasRole`/`listRoles`/
   * `listRoleScopes`/`listSubjects`/`listScopes` siguen usando `resolveChain`
   * (en (c2) no hay alternativa, y está medido), y los `list*` enumeran con
   * `Read` paginado, nunca con `ListObjects` (que trunca al tope del servidor
   * sin señal). Lo único que `facts` cambia es `authorize`.
   */
  get capabilities() {
    const facts = this.hierarchy === 'facts'
    return Object.freeze({
      hierarchyFacts: facts,
      singleCheckAuthorize: facts,
      roleInheritanceNative: false,
      listObjectsInherited: false,
      purgeRole: facts,
    })
  }

  private client: OpenFgaClient
  private chainResolver: ScopeChainResolver
  private holderTypes: HolderTypeMap

  /**
   * Contadores observables del driver. `unparseableBindings`: ids del store
   * que el motor no entiende (L0.16). Cada uno es un hecho que las
   * enumeraciones NO muestran; se registra y se cuenta, jamás un `continue`
   * mudo — quien opera el store tiene que poder verlo.
   */
  readonly diagnostics = { unparseableBindings: 0 }
  private logger: { warn(message: string): void }
  private timeoutMs: number
  private consistency: ConsistencyPreference
  /** Reloj de pared del driver (J1): el ÚNICO `now` de checks, filtros y re-grant. */
  private now: Clock
  /**
   * Memo del catálogo (2A): permisos, roles por nivel y roles que conceden
   * cada permiso se leen de aquí en el camino caliente; antes eran dos
   * consultas SQL por `authorize`. Los hechos siguen en FGA en cada pregunta.
   * Se revalida contra `authz_catalog_version` (2D · F1): cada operación
   * toma la foto UNA vez (`view()`) y lee de ella todo lo que necesita.
   * `catalog.invalidate()` fuerza la recarga de ESTE memo.
   */
  readonly catalog: CatalogCache

  /** Dónde vive el árbol (3b-2b): `'resolver'` (default, el de hoy) o `'facts'`. */
  private hierarchy: 'resolver' | 'facts'

  constructor(options: OpenFgaDriverOptions) {
    assertHolderTypes(options.holderTypes)
    assertCatalogOptions('OpenFgaAuthorizationDriver', options)
    if (options.now !== undefined && !isClock(options.now)) {
      throw new AuthorizationConfigError(
        `OpenFgaAuthorizationDriver: 'now' debe ser una función () => Date (llegó ${typeof options.now})`
      )
    }
    this.now = options.now ?? systemClock
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.catalog =
      options.catalog ?? new CatalogCache({ driver: 'openfga', timeoutMs, revalidate: options.catalogRevalidate })
    this.client = guardBackendErrors(
      new OpenFgaClient({
        apiUrl: options.apiUrl,
        storeId: options.storeId,
        authorizationModelId: options.modelId,
        // `baseOptions` se funde en la config de axios de cada request: es la
        // única vía del SDK (no tiene `timeoutMs` propio; su default es 10 s).
        baseOptions: { timeout: timeoutMs },
        // Sin reintentos a escondidas (ver `OpenFgaDriverOptions.retryParams`).
        retryParams: { maxRetry: 0, ...options.retryParams },
      }),
      timeoutMs
    )
    // Sin resolutor solo existe la raíz (L0.3: el default plano desapareció).
    this.chainResolver = options.resolveChain ?? rootOnlyResolver
    this.holderTypes = options.holderTypes
    this.hierarchy = options.hierarchy ?? 'resolver'
    assertScopeDriftGuarded(this.hierarchy, options)
    if (this.hierarchy !== 'facts') {
      // `purgeRole` NO existe en el modo `resolver` (3b-2e · E4): sin las
      // aristas de (c2) (`role_binding#role` y `scope#binding`) los bindings
      // de un rol no se enumeran sin leer el store entero, y borrar la fila
      // del catálogo sin sus tuplas dejaría hechos huérfanos que resucitan al
      // recrear el slug. NO declararlo es la forma documentada de decir «no sé
      // purgar» (3E · Q4): el manager lo ve ANTES de escribir y `defineScopedRole`
      // se niega (P4) en vez de crear un rol que nada podría borrar.
      Object.defineProperty(this, 'purgeRole', { value: undefined, enumerable: false })
    }
    this.logger = options.logger ?? console
    this.timeoutMs = timeoutMs
    this.consistency =
      options.consistency === 'minimize_latency'
        ? ConsistencyPreference.MinimizeLatency
        : ConsistencyPreference.HigherConsistency
  }

  /**
   * `[scope canónico, ...ancestros]`, o `null` si el scope no existe
   * (lecturas: denegar). `chain[0]` —la fila del consumidor, no lo que
   * escribió el llamante— es el scope que va en la clave de cada binding
   * (2.5-B · K1): un alias del uuid que el árbol funde con la fila real
   * llega aquí ya canónico y el `deny_binding` escrito canónico casa.
   */
  private chain(scope: ScopeRef, operation: string): Promise<ScopeRef[] | null> {
    return resolveChain(this.chainResolver, scope, operation)
  }

  /** La cadena o 422: una escritura no puede ir a un scope que nadie reconoce. */
  private knownScope(scope: ScopeRef, operation: string): Promise<ScopeRef[]> {
    return assertKnownScope(this.chainResolver, scope, operation)
  }

  /** El scope canónico para `revoke`/`removeDeny`/`purgeScope` (ver `canonicalScope`). */
  private canonicalOrSelf(scope: ScopeRef, operation: string): Promise<ScopeRef> {
    return canonicalScope(this.chainResolver, scope, operation)
  }

  /**
   * Vista de este driver con OTRO resolutor de ancestros y el mismo estado
   * (cliente, memo del catálogo, deadline, diagnósticos). Es lo que usa
   * `AuthorizationManager.forRequest()` para leer con un resolutor memoizado
   * sin tocar el driver compartido: hereda por prototipo y solo sobrescribe
   * el resolutor.
   */
  withChainResolver(resolveChain: ScopeChainResolver): AuthorizationDriver {
    const view: this = Object.create(this)
    view.chainResolver = resolveChain
    return view
  }

  /**
   * Vista de este driver con OTRO reloj de pared (2.5 · J1): mismo cliente,
   * store, memo y resolutor; solo cambia el `now` que viaja como
   * `current_time` y filtra las enumeraciones. Lo aplica el manager con
   * `config.clock` y el juez para fijar el instante.
   */
  withClock(now: Clock): AuthorizationDriver {
    if (!isClock(now)) {
      throw new AuthorizationConfigError(`withClock: now debe ser una función () => Date (llegó ${typeof now})`)
    }
    const view: this = Object.create(this)
    view.now = now
    return view
  }

  /**
   * El `context` de los checks de UNA operación, con el reloj de ESTE driver
   * (o vista): se construye una vez por operación y viaja en todos sus
   * checks (2.5-B · K9). Antes se leía el reloj por check y un mismo
   * `authorize` evaluaba el deny en un instante y el rol en otro.
   */
  private checkContext(): { current_time: string } {
    return checkContext(this.now())
  }

  /**
   * Consulta al catálogo local clasificando su fallo. Con este driver el
   * catálogo SQL sigue siendo una dependencia dura de cada pregunta: su caída
   * era un error crudo de Lucid que se presentaba como bug de aplicación (N3).
   */
  private sql<T>(operation: string, fn: () => Promise<T>): Promise<T> {
    return guardSql('openfga', operation, this.timeoutMs, fn)
  }

  private fgaSubject(subject: SubjectRef): string {
    return fgaSubjectWith(subject, this.holderTypes)
  }

  /**
   * Un batchCheck con TODOS los checks (el SDK trocea a 50 por request y
   * paraleliza), cada uno con un `correlationId` propio, y la respuesta
   * alineada por ese id: un resultado por check, ni uno más ni uno menos.
   */
  private async batchCheckAll(
    checks: Array<Omit<ClientBatchCheckItem, 'correlationId'>>
  ): Promise<ClientBatchCheckSingleResponse[]> {
    if (checks.length === 0) return []
    const withIds: ClientBatchCheckItem[] = checks.map((check, index) => ({
      ...check,
      correlationId: String(index),
    }))
    const response = await this.client.batchCheck(
      { checks: withIds },
      { consistency: this.consistency }
    )
    const results = correlateBatchResults(withIds, response.result)
    // Un 200 con `error` en un check individual (`input_error`,
    // `internal_error`…) es una caída parcial del backend, no un "sin
    // permiso": se clasifica igual que un 5xx (invariante 5, D1). Antes la
    // fase de roles y `hasRole` lo colapsaban en `false`.
    const failed = results.find((r) => r.error)
    if (failed) {
      throw new AuthorizationBackendError(
        'openfga',
        `batchCheck (${failed.request?.relation} ${failed.request?.object})`,
        failed.error
      )
    }
    return results
  }

  // ── Catálogo local (compartido entre drivers), desde el memo (2A) ──────
  // Una carga por driver/proceso en vez de una o dos consultas SQL por
  // pregunta, más una revalidación por operación (2D · F1). Un fallo de
  // carga sale como 503, igual que antes.

  private async findPermission(slug: string): Promise<{ uuid: string } | null> {
    return (await this.catalog.view()).permission(slug)
  }

  /**
   * Filtro por catálogo de las lecturas de membresía (`listRoles`,
   * `listRoleScopes`, `rolesInChain`, `listScopes`): un binding cuyo uuid ya
   * no está en `authz_roles` —o está, pero declarado para OTRO nivel, o es
   * local a un scope que no está en la cadena del binding (3B · B2)— es una
   * tupla huérfana, no una membresía; igual que en `database`, donde el
   * catálogo lo excluye (D5). La tupla la recoge `authz:reconcile`. Desde 3A
   * la resolución es por uuid (`roleByUuid`), nunca por slug. `chainKeys` es
   * la cadena del scope del BINDING (desde él hacia la raíz).
   */
  private declaredRole(
    catalog: CatalogView,
    binding: { scope: ScopeRef; uuid: string },
    chainKeys: readonly string[]
  ): CatalogRole | null {
    return declaredRoleAt(catalog, binding.uuid, binding.scope.type, chainKeys)
  }

  // ── Contrato ──────────────────────────────────────────────────────────

  /**
   * Los checks de UNA pregunta (subject, permiso, cadena): los denies de cada
   * nivel y los roles del catálogo que conceden el permiso en cada nivel.
   * Sin rol que conceda ⇒ `null`: la respuesta es `false` digan lo que digan
   * los denies y no se pregunta al backend (2A).
   */
  private checksFor(
    user: string,
    permissionUuid: string,
    chain: ScopeRef[],
    granting: Map<string, CatalogRoleRef[]>,
    context: { current_time: string }
  ): { denies: Array<Omit<ClientBatchCheckItem, 'correlationId'>>; roles: Array<Omit<ClientBatchCheckItem, 'correlationId'>> } | null {
    // Por nivel, solo los roles que EXISTEN ahí (3B · B2): globales, o locales
    // a un scope de la cadena desde ese nivel. Un rol de otro tenant no
    // cuesta un check (mismo número de checks que sin roles locales).
    const keysFrom = chainKeysFrom(chain)
    const roles = chain.flatMap((s, i) =>
      (granting.get(s.type) ?? [])
        .filter((role) => isRoleVisibleWith(role, keysFrom[i]))
        .map((role) => ({
          user,
          relation: 'assignee',
          object: `role_binding:${scopeKey(s)}|${role.uuid}`,
          context,
        }))
    )
    if (roles.length === 0) return null
    const denies = chain.map((s) => ({
      user,
      relation: 'denied',
      object: `deny_binding:${scopeKey(s)}|${permissionUuid}`,
      context,
    }))
    return { denies, roles }
  }

  async authorize(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, permission, scope })
    // Una foto del catálogo por pregunta: permiso y roles que conceden salen
    // de la misma versión (y se paga una sola revalidación).
    const catalog = await this.catalog.view()
    const perm = catalog.permission(permission)
    if (!perm) return false

    const user = this.fgaSubject(subject)
    // Modo `facts` (3b-2c): la jerarquía, el catálogo y los denies ya están
    // en el store, así que la pregunta entera cabe en UN `Check`.
    if (this.hierarchy === 'facts') {
      return this.factsAuthorize(user, permission, scope)
    }
    const chain = await this.chain(scope, 'authorize')
    if (!chain) return false

    // Si ningún rol de la cadena concede el permiso, la respuesta es `false`
    // digan lo que digan los denies: no se pregunta al backend.
    const checks = this.checksFor(user, perm.uuid, chain, catalog.rolesGranting(perm.uuid), this.checkContext())
    if (!checks) return false

    // UN solo batchCheck (2A): los denies de la cadena y los roles que
    // conceden van en la misma request; el SDK trocea a 50 y paraleliza.
    // Regla, en este orden: cualquier `error` ⇒ 503 (D1, dentro de
    // `batchCheckAll`, antes de mirar nada); algún deny `allowed` ⇒ false;
    // algún rol `allowed` ⇒ true. Antes eran dos requests secuenciales
    // (denies, luego roles) con la misma regla.
    const results = await this.batchCheckAll([...checks.denies, ...checks.roles])
    if (results.slice(0, checks.denies.length).some((r) => r.allowed)) return false
    return results.slice(checks.denies.length).some((r) => r.allowed)
  }

  /**
   * **`authorize` del modo `facts` (3b-2c): UN solo `Check`.**
   *
   * `can_<P>` sobre `scope:<key>` con el subject como user. El modelo (c2)
   * ya lleva dentro las tres cosas que el modo `resolver` compone aquí:
   * la herencia hacia abajo (`<P> from parent`), el deny explícito heredado
   * (`denied_<P> from parent`) y la resta que hace ganar al deny
   * (`can_<P> = <P> but not denied_<P>`). No hay `batchCheck`, no se expande
   * la cadena y **no se llama al resolutor del consumidor** (cruce 6 del
   * panel 2, que es también el literal que el README puede prometer).
   *
   * Lo único local que queda es el MEMO del catálogo, y es OBLIGATORIO: lo
   * comprueba el llamante antes de llegar aquí. Sin esa guardia un permiso
   * desconocido sería un `Check` de una relación que el modelo no declara —
   * un 400 del servidor que saldría como 503— en vez del `false` que exige el
   * invariante 5.
   *
   * Un scope que el árbol del consumidor no conoce no tiene tuplas en el
   * store: responde `false` sin preguntar por él (invariante 9), pero aquí
   * eso lo decide el propio store, no `resolveChain`. Cualquier fallo del
   * backend sale como 503 desde el cliente envuelto; jamás un `false` mudo.
   */
  private async factsAuthorize(user: string, permission: string, scope: ScopeRef): Promise<boolean> {
    const response = await this.client.check(
      {
        user,
        relation: factsRelationsOf(permission).can,
        object: factsScopeObject(scopeKey(scope)),
        context: this.checkContext(),
      },
      { consistency: this.consistency }
    )
    return response.allowed === true
  }

  /**
   * `authorize` sobre N scopes con UN batchCheck (2.1, B6): los checks de
   * todas las cadenas viajan juntos (el SDK trocea a 50 y paraleliza) y se
   * atribuyen a su scope por posición dentro del lote correlacionado
   * (L0.14). Misma regla que `authorize`, por scope: `error` en cualquier
   * check ⇒ 503 entero (D1); deny `allowed` ⇒ false; rol `allowed` ⇒ true.
   * Scope desconocido o sin rol que conceda ⇒ false sin checks.
   */
  async authorizeMany(subject: SubjectRef, permission: string, scopes: ScopeRef[]): Promise<boolean[]> {
    assertIdentity({ subject, permission })
    for (const scope of scopes) assertIdentity({ scope })
    if (scopes.length === 0) return []
    const catalog = await this.catalog.view()
    const perm = catalog.permission(permission)
    if (!perm) return scopes.map(() => false)

    const user = this.fgaSubject(subject)
    // Modo `facts` (3b-2c): UN `batchCheck` con UN item por scope —no el
    // N×M de la cadena por el catálogo—, y un scope repetido comparte item.
    if (this.hierarchy === 'facts') {
      return this.factsAuthorizeMany(user, permission, scopes)
    }
    const granting = catalog.rolesGranting(perm.uuid)
    // Un instante para todo el lote (K9): N scopes, una pregunta.
    const context = this.checkContext()
    const batch: Array<Omit<ClientBatchCheckItem, 'correlationId'>> = []
    /** Por posición: `null` = false sin preguntar; si no, [inicio, nºDenies, nºRoles] dentro del lote. */
    const slots: Array<[number, number, number] | null> = []
    // Un scope repetido comparte slot (y cadena) con su primera aparición
    // (G2, CR9): mismos checks, misma respuesta por posición, sin duplicar
    // el lote.
    const slotByScope = new Map<string, [number, number, number] | null>()
    for (const scope of scopes) {
      const scopeId = scopeKey(scope)
      if (slotByScope.has(scopeId)) {
        slots.push(slotByScope.get(scopeId)!)
        continue
      }
      const chain = await this.chain(scope, 'authorizeMany')
      const checks = chain ? this.checksFor(user, perm.uuid, chain, granting, context) : null
      const slot: [number, number, number] | null = checks ? [batch.length, checks.denies.length, checks.roles.length] : null
      if (checks) batch.push(...checks.denies, ...checks.roles)
      slotByScope.set(scopeId, slot)
      slots.push(slot)
    }
    const results = await this.batchCheckAll(batch)
    return slots.map((slot) => {
      if (!slot) return false
      const [start, denies, roles] = slot
      if (results.slice(start, start + denies).some((r) => r.allowed)) return false
      return results.slice(start + denies, start + denies + roles).some((r) => r.allowed)
    })
  }

  /**
   * `authorizeMany` del modo `facts` (3b-2c): **UN `batchCheck` de N items**,
   * uno por scope DISTINTO. En el modo `resolver` cada scope aporta los
   * denies de su cadena más un check por (nivel, rol que concede): el lote
   * crecía como N×M. Aquí cada scope es exactamente una pregunta,
   * `can_<P>@scope:<key>`, y un scope repetido comparte item y respuesta
   * (G2, CR9) en vez de duplicar el lote.
   *
   * Un `error` en cualquier check sigue siendo 503 entero (invariante 5, D1):
   * lo lanza `batchCheckAll` antes de mirar un solo `allowed`.
   */
  private async factsAuthorizeMany(
    user: string,
    permission: string,
    scopes: ScopeRef[]
  ): Promise<boolean[]> {
    const relation = factsRelationsOf(permission).can
    // Un instante para todo el lote (K9): N scopes, una pregunta.
    const context = this.checkContext()
    const batch: Array<Omit<ClientBatchCheckItem, 'correlationId'>> = []
    const itemByScope = new Map<string, number>()
    const slots: number[] = []
    for (const scope of scopes) {
      const id = scopeKey(scope)
      let item = itemByScope.get(id)
      if (item === undefined) {
        item = batch.length
        batch.push({ user, relation, object: factsScopeObject(id), context })
        itemByScope.set(id, item)
      }
      slots.push(item)
    }
    const results = await this.batchCheckAll(batch)
    return slots.map((item) => results[item].allowed === true)
  }

  async grant(
    subject: SubjectRef,
    role: RoleQuery,
    scope: ScopeRef,
    options: GrantOptions = {}
  ): Promise<GrantOutcome> {
    assertIdentity({ subject, role, scope, expiresAt: options.expiresAt })
    // El binding lleva la identidad canónica del árbol (K1), nunca la forma
    // del llamante, y el uuid del rol, nunca su slug (3A · A1). El rol tiene
    // que EXISTIR en ese scope (3B · B2: global, o local a un ancestro-o-igual)
    // con una composición legal (B5).
    const chain = await this.knownScope(scope, 'grant')
    const [target] = chain
    const catalog = await this.catalog.view()
    const declared = resolveRoleQuery(catalog, role, target, chainKeysFrom(chain)[0])
    assertRoleAssignableAt(catalog, declared)
    const roleUuid = declared.uuid

    const key = {
      user: this.fgaSubject(subject),
      relation: 'assignee',
      object: `role_binding:${scopeKey(target)}|${roleUuid}`,
    }
    // **La forma nueva de los objetos (3b-2c), en UNA sola escritura
    // (3b-2f · R3).** En (c2) la asignación no es alcanzable con el
    // `assignee` a secas: el binding tiene que colgar del scope
    // (`scope#binding`) y apuntar a su rol (`role_binding#role`). Son
    // ESTRUCTURA —no llevan caducidad ni dicen quién está asignado, así que
    // sin `assignee` no conceden nada—, pero mandarlas en un `Write` aparte
    // (como hacía el 2c) hacía del `grant` una escritura NO atómica: contra
    // un `purgeScope` concurrente quedaba el `assignee` sin su arista, y
    // entonces `listRoles`/`hasRole` decían que la asignación existe y
    // `authorize` que no concede — dos lecturas contradiciéndose sobre el
    // mismo hecho, que es peor que perder la escritura. Ahora las TRES van
    // en el mismo `Write` (transaccional en FGA): o están las tres o no está
    // ninguna.
    const structure = this.hierarchy === 'facts' ? factsBindingTuples(scopeKey(target), roleUuid) : []
    /** El write COMPLETO de una asignación: su estructura y ella. */
    const writeSet = (tuple: any) => [...structure, tuple]
    const tupleFor = (expiresAt: Date | null) =>
      expiresAt
        ? {
            ...key,
            condition: {
              name: 'not_expired',
              context: { valid_until: expiresAt.toISOString() },
            },
          }
        : key

    // FGA no admite delete+write de la misma tuple key en una transacción, así
    // que cambiar la expiración obliga a dos llamadas — y entre ellas hay un
    // instante en el que authorize() responde false.
    //
    // Se mira primero qué hay, para NO pagar esa ventana cuando no hace falta:
    //  - si no existe la tuple → solo write (el caso del primer grant);
    //  - si existe con la caducidad que toca → no-op (un seeder no toca nada);
    //  - solo si la caducidad CAMBIA de verdad se hace delete+write.
    // Y la lectura es lo que hace posible "omitido = preservar" (L0.4).
    const current = await this.readAssignment(key)

    if (current.kind === 'unknown') {
      // Sin lectura no hay forma de preservar una caducidad vigente: asumir
      // "permanente" sería exactamente el defecto en modo degradado. Con un
      // objetivo explícito (`Date`/`null`) sí se puede escribir a ciegas.
      if (options.expiresAt === undefined) throw withPreserveRecipe(current.error as Error)
      const expiresAt = options.expiresAt
      const existed = await this.writeAssignment(key, tupleFor(expiresAt), structure)
      return { existed, expiresAt }
    }

    if (current.kind === 'present') {
      const expiresAt = resolveGrantExpiry(current.validUntil, options.expiresAt, this.now())
      if (sameInstant(current.validUntil, expiresAt)) {
        return { existed: true, previousExpiresAt: current.validUntil, expiresAt }
      }
      await this.replaceAssignment(key, tupleFor(expiresAt), structure)
      return { existed: true, previousExpiresAt: current.validUntil, expiresAt }
    }

    // No había nada: un write basta y no hay ventana de denegación. Ese write
    // puede chocar por DOS motivos distintos, y la diferencia importa
    // (D6 + 3b-2f · R3):
    //
    //  - la ASIGNACIÓN ya existe — otro proceso la escribió entre el read y
    //    el write, o dos `grant` simultáneos —: se relee y se re-aplica sobre
    //    lo que quedó, para que gane el último escritor y no se pierda esta
    //    caducidad;
    //  - la ESTRUCTURA ya estaba — otro holder con el mismo rol en el mismo
    //    scope, que es el caso más común que hay — o la escribió otro `grant`
    //    a la vez: la asignación sigue sin existir, así que se repite el
    //    MISMO write ignorando duplicados (las aristas no llevan condición,
    //    así que un duplicado suyo es idéntico por construcción). Sigue
    //    siendo UNA escritura y sigue siendo atómica.
    //
    // Cuál de los dos fue lo dice la RELECTURA, no el error: el conflicto
    // transaccional de FGA (`Aborted`, HTTP 409) no nombra ninguna tupla.
    // Cualquier otro fallo del write no es una carrera y se propaga (D6); y
    // una contención que no cede en `GRANT_WRITE_ATTEMPTS` vueltas sale como
    // 409 —el estado del destino no es el que esta escritura esperaba—,
    // jamás como un 503 "el backend no respondió", porque respondió.
    //
    // El límite honesto: si entre la relectura y el write con `Ignore` un
    // tercero escribe la asignación, la suya se queda y esta se pierde en
    // silencio (FGA no tiene un compare-and-set). Es la misma ventana que ya
    // tenía el `replace`, estrechada a dos llamadas seguidas.
    const expiresAt = options.expiresAt ?? null
    for (let attempt = 0; ; attempt++) {
      try {
        await this.client.writeTuples(
          writeSet(tupleFor(expiresAt)),
          attempt === 0 ? undefined : IGNORE_DUPLICATE_WRITES
        )
        return { existed: false, expiresAt }
      } catch (error) {
        if (!isDuplicateWrite(error)) throw error
        if (attempt >= GRANT_WRITE_ATTEMPTS - 1) {
          throw new WriteConflictError(
            `grant: ${GRANT_WRITE_ATTEMPTS} intentos y el store sigue en conflicto sobre ` +
              `${key.object}. Reintenta la escritura.`,
            { cause: error }
          )
        }
        const raced = await this.readAssignment(key)
        if (raced.kind === 'present') {
          const target = resolveGrantExpiry(raced.validUntil, options.expiresAt, this.now())
          if (!sameInstant(raced.validUntil, target)) {
            await this.replaceAssignment(key, tupleFor(target), structure)
          }
          return { existed: true, previousExpiresAt: raced.validUntil, expiresAt: target }
        }
        if (raced.kind === 'unknown' || !structure.length) {
          // Dos caminos que no son el choque estructural:
          //  - la relectura FALLÓ: sin objetivo explícito no se sabe qué
          //    preservar, y el error de lectura va como causa;
          //  - no hay estructura (modo `resolver`: el `assignee` es la única
          //    tupla del write), así que un duplicado cuya relectura no ve
          //    nada es inexplicable y sigue siendo el 503 de D6.
          if (options.expiresAt === undefined) {
            throw withPreserveRecipe(
              raced.kind === 'unknown'
                ? (raced.error as Error)
                : new AuthorizationBackendError('openfga', 'grant (el write chocó y la relectura no ve la tupla)', error)
            )
          }
          const existed = await this.writeAssignment(key, tupleFor(options.expiresAt), structure)
          return { existed, expiresAt: options.expiresAt }
        }
        // `absent` con estructura: el choque fue de las aristas, que las
        // comparten todos los holders del mismo rol en el mismo scope. Otra
        // vuelta, esta vez dándolas por buenas.
      }
    }
  }

  /**
   * Write directo de la asignación CON su estructura (3b-2f · R3); si algo ya
   * estaba, camino largo. Devuelve si existía la ASIGNACIÓN —lo dice la
   * relectura, no el error: el choque puede ser de las aristas, que en (c2)
   * las comparten todos los holders del mismo rol en el mismo scope—.
   * Cualquier otro fallo se propaga tal cual (ya clasificado).
   */
  private async writeAssignment(
    key: { user: string; relation: string; object: string },
    tuple: any,
    structure: FactsTuple[] = []
  ): Promise<boolean> {
    try {
      await this.client.writeTuples([...structure, tuple])
      return false
    } catch (error) {
      if (!isDuplicateWrite(error)) throw error
      // Sin estructura el duplicado solo puede ser la asignación; con ella
      // puede ser una arista compartida, y entonces quién existía lo dice la
      // relectura y no el error.
      const existed = structure.length ? (await this.readAssignment(key)).kind !== 'absent' : true
      await this.replaceAssignment(key, tuple, structure)
      return existed
    }
  }

  /**
   * delete + write (dos llamadas: FGA no admite ambas sobre la misma key en
   * una). El write repone la ESTRUCTURA junto a la asignación: si un
   * `purgeScope` concurrente se llevó la arista `scope#binding` entre medias,
   * lo que queda vuelve a ser coherente en vez de una asignación inerte que
   * `listRoles` ve y `authorize` no (3b-2f · R3).
   */
  private async replaceAssignment(
    key: { user: string; relation: string; object: string },
    tuple: any,
    structure: FactsTuple[] = []
  ): Promise<void> {
    await this.client.deleteTuples([key], {
      conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore },
    })
    await this.client.writeTuples([...structure, tuple], IGNORE_DUPLICATE_WRITES)
  }

  /**
   * Estado actual de una asignación, con TRES resultados posibles y no dos.
   *
   * Distinguir `unknown` de `present` sin condición es lo que impide un bug
   * feo: si un fallo de lectura se pareciera a "existe y sin expiración", un
   * grant sin expiración saldría por el atajo del no-op y se perdería. El
   * error de lectura (ya clasificado como 503) viaja con el resultado para
   * que quien no pueda seguir sin él lo propague.
   */
  private async readAssignment(key: {
    user: string
    relation: string
    object: string
  }): Promise<
    | { kind: 'absent' }
    | { kind: 'present'; validUntil: Date | null }
    | { kind: 'unknown'; error: unknown }
  > {
    try {
      const response = await this.client.read(key, { consistency: this.consistency })
      const tuple = response.tuples?.[0]
      if (!tuple) return { kind: 'absent' }
      const validUntil = (tuple.key as any)?.condition?.context?.valid_until
      return { kind: 'present', validUntil: toExpiryDate(validUntil) }
    } catch (error) {
      return { kind: 'unknown', error }
    }
  }

  async revoke(subject: SubjectRef, role: RoleQuery, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, role, scope })
    // Rol fuera del catálogo para ese nivel ⇒ 422, como en `grant` (D10). Se
    // quitan los bindings de TODOS los roles con ese nombre en el scope
    // exacto (3B): a lo sumo uno es visible ahí; quitar nunca concede.
    const named = rolesToRevoke(await this.catalog.view(), role, scope)
    const target = await this.canonicalOrSelf(scope, 'revoke')
    const user = this.fgaSubject(subject)
    await this.client.deleteTuples(
      named.map((r) => ({ user, relation: 'assignee', object: `role_binding:${scopeKey(target)}|${r.uuid}` })),
      { conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore } }
    )
  }

  async hasRole(subject: SubjectRef, role: RoleQuery, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, role, scope })
    const user = this.fgaSubject(subject)
    const chain = await this.chain(scope, 'hasRole')
    if (!chain) return false
    // El id del binding lleva el scope (y con él su tipo) y el UUID del rol
    // que el catálogo declara con ese slug para el tipo de ESE nivel (3A):
    // en cada nivel solo casa el rol de ese nivel. Con `{ slug, scopeType }`
    // se recorta la cadena a los niveles de ese tipo (L0.6). Y solo se
    // pregunta por los niveles para los que el catálogo declara el rol (D5):
    // un rol retirado no es membresía aunque su tupla siga en el store.
    const catalog = await this.catalog.view()
    const targets = hasRoleTargets(catalog, role, chain)
    if (targets.length === 0) return false
    const context = this.checkContext()
    const results = await this.batchCheckAll(
      targets.map(({ scope: s, roleUuid }) => ({
        user,
        relation: 'assignee',
        object: `role_binding:${scopeKey(s)}|${roleUuid}`,
        context,
      }))
    )
    return results.some((r) => r.allowed)
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    const perm = await this.findPermission(permission)
    if (!perm) throw new UnknownPermissionError(permission)
    const [target] = await this.knownScope(scope, 'deny')
    await this.client.writeTuples([this.denyTuple(subject, permission, perm.uuid, target)], {
      conflict: { onDuplicateWrites: ClientWriteRequestOnDuplicateWrites.Ignore },
    })
  }

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    const perm = await this.findPermission(permission)
    if (!perm) throw new UnknownPermissionError(permission)
    const target = await this.canonicalOrSelf(scope, 'removeDeny')
    await this.client.deleteTuples([this.denyTuple(subject, permission, perm.uuid, target)], {
      conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore },
    })
  }

  /**
   * El hecho de un deny, en la forma del modo que corre (3b-2c). En
   * `resolver` es un objeto propio, `deny_binding:<scopeKey>|<permissionUuid>`
   * (el uuid del catálogo, 3A · A1). En `facts` el deny es una relación DEL
   * SCOPE, `scope:<key>#denied_<P>@<holder>`: así el modelo lo hereda hacia
   * abajo por `parent` y `can_<P>` puede restarlo dentro del mismo `Check`
   * (invariante 2) sin que el paquete pasee la cadena.
   *
   * Las dos formas nombran el permiso de manera distinta a propósito: el
   * `deny_binding` lleva el uuid porque el id es opaco para el modelo, y la
   * relación lleva el SLUG proyectado porque el modelo la declara por nombre.
   * El slug que llega aquí es el del catálogo: el llamante ya pasó por
   * `findPermission`, que es quien decide qué existe.
   */
  private denyTuple(
    subject: SubjectRef,
    permission: string,
    permissionUuid: string,
    target: ScopeRef
  ): { user: string; relation: string; object: string } {
    const user = this.fgaSubject(subject)
    return this.hierarchy === 'facts'
      ? factsDenyTuple(scopeKey(target), permission, user)
      : { user, relation: 'denied', object: `deny_binding:${scopeKey(target)}|${permissionUuid}` }
  }

  /**
   * Holders con asignación vigente del rol en el scope exacto: `Read` por
   * objeto exacto, paginado, con la caducidad filtrada en cliente. Antes era
   * `ListUsers`, que trunca al tope del servidor sin señal (L0.7).
   */
  async listSubjects(role: RoleQuery, scope: ScopeRef): Promise<SubjectRef[]> {
    assertIdentity({ role, scope })
    // Un rol que el catálogo no declara para ese nivel (en ningún owner) no
    // tiene holders (D5): nada que leer, ni árbol ni store. Un scope que el
    // árbol no conoce no existe para el motor (D8, K1): nada; uno que conoce
    // se lee bajo su identidad canónica, y el rol tiene que existir AHÍ (3B ·
    // B2); el que existe se lee por su uuid (3A).
    const catalog = await this.catalog.view()
    const asked = normalizeRoleQuery(role)
    if (asked.uuid !== undefined ? catalog.roleByUuid(asked.uuid) === null : catalog.rolesNamed(asked.slug, asked.scopeType ?? scope.type).length === 0) {
      return []
    }
    const chain = await this.chain(scope, 'listSubjects')
    if (!chain) return []
    const declared = visibleRoleFor(catalog, asked, scope, chainKeysFrom(chain)[0])
    if (!declared) return []
    const fgaToMorph = Object.fromEntries(
      Object.entries(this.holderTypes).map(([morph, fga]) => [fga, morph])
    )
    const tuples = await this.readAllTuples({
      relation: 'assignee',
      object: `role_binding:${scopeKey(chain[0])}|${declared.uuid}`,
    })
    const results: SubjectRef[] = []
    for (const tuple of tuples) {
      // `<tipoFga>:<uuid>`; un userset (`#`) o un tipo que no está en el mapa
      // no es un holder que este driver haya escrito.
      const separator = tuple.user.indexOf(':')
      const fgaType = separator > 0 ? tuple.user.slice(0, separator) : ''
      const uuid = separator > 0 ? tuple.user.slice(separator + 1) : ''
      const morph = fgaToMorph[fgaType]
      if (!morph || !uuid || uuid.includes('#')) {
        this.diagnostics.unparseableBindings += 1
        this.warn(
          `authz(openfga): el user '${tuple.user}' de '${tuple.object}' no es un holder del motor; se ignora en la enumeración (total: ${this.diagnostics.unparseableBindings})`
        )
        continue
      }
      results.push({ type: morph, uuid })
    }
    return results
  }

  /**
   * Bindings del subject ya parseados (asignaciones directas vigentes). Los
   * ids que no se entienden se registran y se cuentan, no se descartan.
   */
  private async listBindings(subject: SubjectRef, at?: Date): Promise<Array<{ scope: ScopeRef; uuid: string }>> {
    const tuples = await this.readAllTuples(
      {
        user: this.fgaSubject(subject),
        relation: 'assignee',
        object: 'role_binding:',
      },
      { at }
    )
    return this.parseBindings('role_binding', tuples.map((t) => t.object))
  }

  /** Scopes (por clave) donde el subject tiene un deny directo del permiso (por su uuid). */
  private async deniedScopeKeys(subject: SubjectRef, permissionUuid: string, at?: Date): Promise<Set<string>> {
    // En `facts` el deny es una relación del scope: se pide por esa relación
    // exacta y la lectura devuelve ya solo los denies de ESTE permiso (una
    // request, sin filtrar en cliente). Un permiso que el catálogo ya no
    // declara no tiene relación que leer: sin denies, como en `resolver`
    // (D5).
    if (this.hierarchy === 'facts') {
      const slug = (await this.catalog.view()).permissionSlug(permissionUuid)
      if (!slug) return new Set<string>()
      const tuples = await this.readAllTuples(
        {
          user: this.fgaSubject(subject),
          relation: factsRelationsOf(slug).denied,
          object: `${FACTS_SCOPE_TYPE}:`,
        },
        { at }
      )
      return new Set(tuples.map((t) => t.object.slice(FACTS_SCOPE_TYPE.length + 1)))
    }
    const tuples = await this.readAllTuples(
      {
        user: this.fgaSubject(subject),
        relation: 'denied',
        object: 'deny_binding:',
      },
      { at }
    )
    return new Set(
      this.parseBindings('deny_binding', tuples.map((t) => t.object))
        .filter((p) => p.uuid === permissionUuid)
        .map((p) => scopeKey(p.scope))
    )
  }

  /**
   * Los denies DIRECTOS del holder en el modo `facts`, ya traducidos a
   * `(scope, permiso)`. No hay `deny_binding` que enumerar: se leen de una
   * pasada las tuplas del holder sobre objetos `scope:` y se quedan las de la
   * familia `denied_<P>`. La vuelta de relación a slug la da el CATÁLOGO —una
   * relación que ya no declara ningún permiso no es un deny (D5), igual que
   * un `deny_binding` de un permiso retirado—, y una clave de scope que el
   * motor no entiende se cuenta y se registra, nunca se descarta en silencio
   * (L0.16).
   */
  private async factsDenies(
    subject: SubjectRef,
    catalog: CatalogView,
    at?: Date
  ): Promise<Array<{ scope: ScopeRef; permission: string }>> {
    const permissionByRelation = new Map<string, string>()
    for (const slug of catalog.permissionSlugs) {
      permissionByRelation.set(factsRelationsOf(slug).denied, slug)
    }
    const tuples = await this.readAllTuples(
      { user: this.fgaSubject(subject), object: `${FACTS_SCOPE_TYPE}:` },
      { at }
    )
    const denies: Array<{ scope: ScopeRef; permission: string }> = []
    for (const tuple of tuples) {
      if (!tuple.relation.startsWith(FACTS_DENIED_PREFIX)) continue
      const permission = permissionByRelation.get(tuple.relation)
      if (!permission) continue
      const scope = scopeFromKey(tuple.object.slice(FACTS_SCOPE_TYPE.length + 1))
      if (!scope) {
        this.diagnostics.unparseableBindings += 1
        this.warn(
          `authz(openfga): el objeto '${tuple.object}' de un deny no tiene la forma de un scope del motor; se ignora en la enumeración (total: ${this.diagnostics.unparseableBindings})`
        )
        continue
      }
      denies.push({ scope, permission })
    }
    return denies
  }

  private parseBindings(
    type: 'role_binding' | 'deny_binding',
    objects: string[]
  ): Array<{ scope: ScopeRef; uuid: string }> {
    const parsed: Array<{ scope: ScopeRef; uuid: string }> = []
    for (const obj of objects) {
      const id = obj.replace(new RegExp(`^${type}:`), '')
      const binding = parseBindingId(id)
      if (binding) {
        parsed.push(binding)
      } else {
        this.diagnostics.unparseableBindings += 1
        this.warn(`authz(openfga): binding '${type}:${id}' no tiene la forma del motor; se ignora en la enumeración (total: ${this.diagnostics.unparseableBindings})`)
      }
    }
    return parsed
  }

  private warn(message: string): void {
    this.logger.warn(message)
  }

  async listRoles(subject: SubjectRef, scope: ScopeRef): Promise<string[]> {
    assertIdentity({ subject, scope })
    // Un scope que el árbol no conoce no existe para el motor (D8): nada.
    const chain = await this.chain(scope, 'listRoles')
    if (!chain) return []
    const prefix = scopeKey(chain[0])
    const keys = chainKeysFrom(chain)[0]
    const catalog = await this.catalog.view()
    const roles = new Set<string>()
    for (const binding of await this.listBindings(subject)) {
      if (scopeKey(binding.scope) !== prefix) continue
      const declared = this.declaredRole(catalog, binding, keys)
      if (declared) roles.add(declared.slug)
    }
    return [...roles]
  }

  /**
   * Roles directos vigentes del holder en cada scope de la cadena (2D · G5):
   * UNA lectura (`Read` paginado de sus bindings) agrupada por scope, en vez
   * de un `listRoles` por nivel. Solo roles que el catálogo declara para ese
   * nivel (D5). La cadena viene ya resuelta por el manager.
   */
  async rolesInChain(subject: SubjectRef, chain: ScopeRef[]): Promise<Array<{ scope: ScopeRef; role: CatalogRoleRef }>> {
    assertIdentity({ subject })
    for (const scope of chain) assertScope(scope)
    if (chain.length === 0) return []
    const catalog = await this.catalog.view()
    const keysFrom = chainKeysFrom(chain)
    const wanted = new Map(chain.map((s, i) => [scopeKey(s), { scope: s, keys: keysFrom[i] }]))
    const seen = new Set<string>()
    const result: Array<{ scope: ScopeRef; role: CatalogRoleRef }> = []
    for (const binding of await this.listBindings(subject)) {
      const id = scopeKey(binding.scope)
      const level = wanted.get(id)
      if (!level) continue
      const scope = level.scope
      const declared = this.declaredRole(catalog, binding, level.keys)
      if (!declared) continue
      // Dedupe por IDENTIDAD (3D · M1: el uuid, no el slug).
      const dedupe = `${id}\u001f${declared.uuid}`
      if (seen.has(dedupe)) continue
      seen.add(dedupe)
      result.push({ scope, role: declared })
    }
    return result
  }

  async listRoleScopes(subject: SubjectRef, scopeType: ScopeType): Promise<ScopeRef[]> {
    assertIdentity({ subject, scopeType })
    const catalog = await this.catalog.view()
    const byScope = new Map<string, { scope: ScopeRef; bindings: Array<{ scope: ScopeRef; uuid: string }> }>()
    for (const binding of await this.listBindings(subject)) {
      if (binding.scope.type !== scopeType) continue
      const k = scopeKey(binding.scope)
      if (!byScope.has(k)) byScope.set(k, { scope: binding.scope, bindings: [] })
      byScope.get(k)!.bindings.push(binding)
    }
    // Los scopes que el árbol ya no conoce no se listan (D8): una consulta
    // al resolutor por scope, el mismo coste que `listScopes`. Y con la
    // cadena se decide si alguno de sus roles existe ahí (D5, 3B · B2).
    const known: ScopeRef[] = []
    for (const { scope, bindings } of byScope.values()) {
      const chain = await this.chain(scope, 'listRoleScopes')
      if (!chain) continue
      const keys = chainKeysFrom(chain)[0]
      if (bindings.some((b) => this.declaredRole(catalog, b, keys))) known.push(scope)
    }
    return known
  }

  async listScopes(subject: SubjectRef, permission: string): Promise<ScopeRef[]> {
    assertIdentity({ subject, permission })
    const catalog = await this.catalog.view()
    const perm = catalog.permission(permission)
    if (!perm) return []

    const granting = catalog.rolesGranting(perm.uuid)

    // Denies directos del subject para este permiso: TODOS, paginando. Con
    // `ListObjects` el tope del servidor se consumía con los denies de
    // cualquier permiso y el relevante podía quedar fuera: fail-open (L0.7).
    // Las dos lecturas filtran la caducidad con el MISMO instante (K9).
    const at = this.now()
    const deniedKeys = await this.deniedScopeKeys(subject, perm.uuid, at)

    const result = new Map<string, ScopeRef>()
    for (const binding of await this.listBindings(subject, at)) {
      const role = (granting.get(binding.scope.type) ?? []).find((r) => r.uuid === binding.uuid)
      if (!role) continue

      // Un scope que el árbol ya no conoce no concede: no se lista. Y el rol
      // tiene que existir ahí (3B · B2: global u owner en la cadena).
      const chain = await this.chain(binding.scope, 'listScopes')
      if (!chain) continue
      if (!isRoleVisibleWith(role, chainKeysFrom(chain)[0])) continue
      const blocked = chain.some((s) => deniedKeys.has(scopeKey(s)))
      if (!blocked) result.set(scopeKey(binding.scope), binding.scope)
    }
    return [...result.values()]
  }

  /**
   * Denies directos del holder (2.1, B5): `Read` paginado de sus
   * `deny_binding` (nunca ListObjects, L0.7), filtrados por el catálogo (un
   * permiso retirado no es un deny, D5), por scope exacto si se pide, y por
   * scopes que el árbol conoce (D8).
   */
  async listDenies(subject: SubjectRef, scope?: ScopeRef): Promise<DenyRef[]> {
    assertIdentity(scope ? { subject, scope } : { subject })
    const chain = scope ? await this.chain(scope, 'listDenies') : null
    if (scope && !chain) return []
    const wanted = chain ? scopeKey(chain[0]) : null
    const view = await this.catalog.view()
    const denies = this.hierarchy === 'facts' ? await this.factsDenies(subject, view) : await this.legacyDenies(subject, view)
    const result: DenyRef[] = []
    for (const deny of denies) {
      if (wanted !== null) {
        if (scopeKey(deny.scope) !== wanted) continue
      } else if (!(await this.chain(deny.scope, 'listDenies'))) {
        continue
      }
      result.push({ permission: deny.permission, scope: deny.scope })
    }
    return result
  }

  /** Los denies directos del holder en el modo `resolver`: objetos `deny_binding`. */
  private async legacyDenies(
    subject: SubjectRef,
    catalog: CatalogView
  ): Promise<Array<{ scope: ScopeRef; permission: string }>> {
    const tuples = await this.readAllTuples({
      user: this.fgaSubject(subject),
      relation: 'denied',
      object: 'deny_binding:',
    })
    const denies: Array<{ scope: ScopeRef; permission: string }> = []
    for (const binding of this.parseBindings('deny_binding', tuples.map((t) => t.object))) {
      const permission = catalog.permissionSlug(binding.uuid)
      if (!permission) continue
      denies.push({ scope: binding.scope, permission })
    }
    return denies
  }

  /* ── El ÁRBOL como hechos (3b-2b) ──────────────────────────────────── */

  /**
   * Un nodo tiene como mucho UN padre. El paquete nunca escribe dos (cada
   * `moved` sustituye la arista entera dentro de un `Write`), así que dos
   * padres son DERIVA: alguien más escribe en el store, y mientras tanto la
   * herencia está trayendo hechos de dos ramas. Se lanza; no se "arregla",
   * porque elegir cuál sobrevive sería adivinar cuál de las dos concesiones
   * vivas es la buena (cruce 8: «si devuelve >1 ⇒ drift ⇒ lanza»).
   */
  private assertOneParent(object: string, current: Array<{ user: string }>): void {
    if (current.length <= 1) return
    throw new ScopeTreeDriftError(
      `El árbol del store tiene ${current.length} padres para ${object} ` +
        `(${current.map((t) => t.user).join(', ')}); el paquete solo escribe uno. ` +
        `No se elige por ti: reconstruye el árbol con authz:reconcile.`
    )
  }

  /**
   * El consumidor colgó un scope nuevo (o recolgó uno que ya existía: un
   * `attach` sobre un nodo conocido ES un move). En modo `facts` eso es UNA
   * tupla `scope:<hijo>#parent@scope:<padre>`; en modo `resolver` no es nada
   * (la jerarquía la resuelve el paquete en cada pregunta).
   */
  async onScopeAttached(child: ScopeRef, parent: ScopeRef): Promise<void> {
    await this.reparent(child, parent, 'scopes.attached')
  }

  /**
   * El consumidor movió un scope. Procedimiento fijado en el cruce 8 del
   * panel 2: un `Read` del padre actual —obligatorio, porque FGA rechaza
   * borrar una tupla inexistente— y **UN solo `Write`** con el delete del
   * padre viejo y el write del nuevo, que es atómico dentro de la request.
   * Dos requests, una mutación.
   */
  async onScopeMoved(child: ScopeRef, newParent: ScopeRef): Promise<void> {
    await this.reparent(child, newParent, 'scopes.moved')
  }

  /**
   * **Anti-ciclos, en el PAQUETE y antes de escribir** (cruce 3 del panel 2,
   * bloqueante S2). Medido contra OpenFGA v1.19: el servidor ACEPTA una
   * arista que cierra un ciclo, no se cuelga, responde en 2-7 ms y la
   * herencia se vuelve bidireccional —un grant en un descendiente concede en
   * el ancestro, y con la raíz dentro del ciclo concede en todo el store—.
   * Fail-open mudo: no hay nada que capturar. La suite lo reproduce contra el
   * `:8101` para que nadie proponga delegar esto en el backend.
   *
   * Las tres validaciones del cruce 8, en orden y sin escribir nada si
   * fallan: (i) la raíz no cuelga de nadie; (ii) el padre EXISTE según el
   * árbol del consumidor; (iii) el hijo no es ancestro-o-igual del padre.
   * Las mismas que hace `AuthorizationManager.#assertEdge`: aquí se repiten
   * por defensa en profundidad, porque `manager.driver()` es la salida
   * documentada de todas las barreras del paquete.
   *
   * Devuelve las dos claves CANÓNICAS (invariante 17): un alias del uuid ni
   * evade la comprobación de ciclo ni abre una segunda rama en el store.
   */
  private async assertEdge(
    child: ScopeRef,
    parent: ScopeRef,
    operation: string
  ): Promise<{ childKey: string; parentKey: string }> {
    assertScope(child)
    assertScope(parent)
    if (child.type === APP_SCOPE_TYPE) {
      throw new InvalidIdentityError(`${operation}: la raíz \`app\` no puede colgar de nada`)
    }
    // (ii) 422 E_AUTHZ_UNKNOWN_SCOPE si el padre no existe.
    const parentChain = await this.knownScope(parent, operation)
    // El hijo, si el árbol ya lo conoce, con su identidad canónica.
    const childChain = await this.chain(child, operation)
    const childKey = scopeKey(childChain ? childChain[0] : child)
    if (parentChain.some((s) => scopeKey(s) === childKey)) {
      throw new ScopeCycleError(
        `${operation}: ${parent.type}:${parent.uuid ?? ''} desciende de ${childKey} (o es él mismo); ` +
          `colgarlo cerraría un ciclo y FGA lo evaluaría en los dos sentidos: un grant en el ` +
          `descendiente concedería en el ancestro.`
      )
    }
    return { childKey, parentKey: scopeKey(parentChain[0]) }
  }

  /**
   * El consumidor sacó un scope del árbol. En modo `facts` se borra su
   * arista `#parent` — y **la arista es lo ÚLTIMO** (S6, cruce 9): el
   * manager llama primero a `purgeScope`, que borra los hechos del scope y
   * DEMUESTRA cero o lanza (invariante 11). Al revés, una purga que muriera
   * a medias dejaría grants vivos en un scope sin ancestro: los denies que
   * heredaba del padre dejarían de aplicar y esos permisos serían
   * INDENEGABLES (invariante 2).
   *
   * No se tocan las aristas de los HIJOS (`scope:<hijo>#parent@scope:<este>`):
   * el consumidor notifica un `detached` por nodo, o un `moved` para
   * recolgarlos. Lo que quede sin nodo arriba lo ve `authz:reconcile` (3b-3).
   */
  async onScopeDetached(child: ScopeRef): Promise<void> {
    if (this.hierarchy !== 'facts') return
    assertScope(child)
    if (child.type === APP_SCOPE_TYPE) {
      throw new InvalidIdentityError('scopes.detached: la raíz `app` no se puede borrar ni purgar')
    }
    const scope = await this.canonicalOrSelf(child, 'scopes.detached')
    const object = factsScopeObject(scopeKey(scope))
    const current = await this.readAllTuples(
      { object, relation: FACTS_PARENT_RELATION },
      { includeExpired: true }
    )
    // Aquí NO se exige un solo padre: el nodo se va entero y llevarse las dos
    // aristas de una deriva es lo correcto (a diferencia de `moved`, donde
    // habría que elegir cuál sobrevive).
    if (current.length === 0) return
    await this.client.write({ writes: [], deletes: current })
  }

  /**
   * Escribe la arista del árbol dejando UNA sola: se lee la que hay y se
   * sustituye en el mismo `Write`. Sin diferencia no se llama al servidor
   * (invariante 6: re-anexar al mismo padre es un no-op seguro, y además
   * escribir una tupla que ya está sería un conflicto con los defaults
   * estrictos del SDK).
   */
  private async reparent(child: ScopeRef, parent: ScopeRef, operation: string): Promise<void> {
    if (this.hierarchy !== 'facts') return
    const { childKey, parentKey } = await this.assertEdge(child, parent, operation)
    const wanted = factsParentTuple(childKey, parentKey)
    const current = await this.readAllTuples(
      { object: wanted.object, relation: FACTS_PARENT_RELATION },
      { includeExpired: true }
    )
    this.assertOneParent(wanted.object, current)
    if (current.length === 1 && current[0].user === wanted.user) return
    await this.client.write({ writes: [wanted], deletes: current })
    await this.sweepLocalRoleBindings(childKey)
  }

  /**
   * **El barrido del rol local** (3b-2e · E1; decisión del dueño del
   * 2026-08-30, opción 1).
   *
   * En (c2) el modelo no tiene `owner`, así que `authorize` NO vuelve a
   * decidir con el árbol de hoy si un rol LOCAL sigue siendo visible: un
   * `role_binding` concede mientras su scope alcance al que pregunta. Sin
   * esto, mover una unit fuera de la organización dueña de un rol local
   * dejaría de retirar lo concedido (el invariante 18 en `database`), que es
   * un **fail-open** — y encima uno que solo se ve comparando drivers.
   *
   * Lo que se toca es la arista `scope#binding`, que es lo que hace
   * ALCANZABLE la asignación: se BORRA donde el owner del rol ya no está en
   * la cadena y se REESCRIBE donde vuelve a estarlo (invariante 18: volver la
   * unit a su sitio restaura). No se toca el `assignee` —el hecho de la
   * asignación no cambia porque el árbol se mueva, igual que en `database`—
   * ni nada de un rol GLOBAL, cuya visibilidad no depende del árbol.
   *
   * **Por subárbol, no por nodo** (consecuencia 2): los descendientes del
   * nodo movido también cambian de cadena.
   *
   * Coste: si el catálogo no tiene NI UN rol local —el caso de todo consumidor
   * que no usa delegación— son **cero** requests y `moved` sigue siendo el
   * `Read` + `Write` del cruce 8. Con roles locales: una lectura por rol local
   * (sus bindings, por `role_binding#role`), la bajada del subárbol y un
   * `Write` por lote.
   */
  private async sweepLocalRoleBindings(movedKey: string): Promise<void> {
    const catalog = await this.catalog.view()
    const locals = catalog.localRoles()
    if (locals.length === 0) return

    // La cadena del nodo movido y su subárbol se leen del STORE, no del
    // consumidor: el árbol que decide en `facts` es el del store, y con la
    // outbox el relay aplica esto MÁS TARDE, cuando el árbol del consumidor
    // puede haber seguido moviéndose.
    const chainOfMoved = await this.storeChain(movedKey)
    /** `scopeKey` → claves de su cadena (él incluido), con el árbol de AHORA. */
    const subtree = new Map<string, string[]>([[movedKey, chainOfMoved]])
    const pending = [movedKey]
    while (pending.length) {
      const key = pending.pop()!
      const children = await this.readAllTuples(
        { user: factsScopeObject(key), relation: FACTS_PARENT_RELATION, object: `${FACTS_SCOPE_TYPE}:` },
        { includeExpired: true }
      )
      for (const edge of children) {
        const childKey = edge.object.slice(FACTS_SCOPE_TYPE.length + 1)
        if (subtree.has(childKey)) continue
        subtree.set(childKey, [childKey, ...subtree.get(key)!])
        pending.push(childKey)
      }
    }

    const writes: FactsTuple[] = []
    const deletes: FactsTuple[] = []
    for (const role of locals) {
      // Los bindings de ESTE rol, esté donde esté: `role_binding:…#role@role:<uuid>`.
      // El filtro lleva `user`, que es lo que el servidor real exige cuando el
      // objeto es solo un tipo (lección del 2c).
      const bindings = await this.readAllTuples(
        { user: `${FACTS_ROLE_TYPE}:${role.uuid}`, relation: 'role', object: `${FACTS_BINDING_TYPE}:` },
        { includeExpired: true }
      )
      for (const binding of bindings) {
        const id = binding.object.slice(FACTS_BINDING_TYPE.length + 1)
        const separator = id.lastIndexOf('|')
        if (separator <= 0) continue
        const scopeKeyValue = id.slice(0, separator)
        const chainKeys = subtree.get(scopeKeyValue)
        if (!chainKeys) continue
        const edge = {
          user: binding.object,
          relation: FACTS_BINDING_RELATION,
          object: factsScopeObject(scopeKeyValue),
        }
        if (chainKeys.includes(role.owner)) writes.push(edge)
        else deletes.push(edge)
      }
    }
    if (!writes.length && !deletes.length) return

    // `Ignore` en las dos direcciones: el barrido dice el estado que DEBE
    // quedar, no el delta — borrar lo que ya no está y reescribir lo que ya
    // estaba son no-ops, no errores (invariante 6).
    type Operation = { write?: FactsTuple; delete?: FactsTuple }
    const operations: Operation[] = [
      ...deletes.map((tuple) => ({ delete: tuple })),
      ...writes.map((tuple) => ({ write: tuple })),
    ]
    for (let i = 0; i < operations.length; i += PURGE_BATCH_SIZE) {
      const chunk = operations.slice(i, i + PURGE_BATCH_SIZE)
      await this.client.write(
        {
          writes: chunk.filter((o) => o.write).map((o) => o.write!),
          deletes: chunk.filter((o) => o.delete).map((o) => o.delete!),
        },
        {
          conflict: {
            onDuplicateWrites: ClientWriteRequestOnDuplicateWrites.Ignore,
            onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore,
          },
        }
      )
    }
  }

  /**
   * `[key, ...ancestros]` según el ÁRBOL DEL STORE (3b-2e · E1), subiendo por
   * `scope#parent`. Es la cadena con la que FGA va a decidir, que es la que
   * tiene que gobernar el barrido; el resolutor del consumidor no participa.
   * Un nodo con más de un padre es deriva y se dice (`assertOneParent`), y el
   * recorrido está acotado por el mismo tope de páginas que las
   * enumeraciones: un ciclo escrito a mano no cuelga el proceso.
   */
  private async storeChain(key: string): Promise<string[]> {
    const chain = [key]
    const seen = new Set([key])
    for (let hop = 0; hop < MAX_SCOPE_CHAIN_HOPS; hop++) {
      const object = factsScopeObject(chain[chain.length - 1])
      const parents = await this.readAllTuples(
        { object, relation: FACTS_PARENT_RELATION },
        { includeExpired: true }
      )
      this.assertOneParent(object, parents)
      if (parents.length === 0) return chain
      const parentKey = parents[0].user.slice(FACTS_SCOPE_TYPE.length + 1)
      if (seen.has(parentKey)) {
        throw new ScopeCycleError(
          `El árbol del store tiene un ciclo en ${factsScopeObject(parentKey)}: no se puede decidir la ` +
            `visibilidad de un rol local. Reconstruye el árbol con authz:reconcile.`
        )
      }
      seen.add(parentKey)
      chain.push(parentKey)
    }
    throw new AuthorizationInternalError(
      `El árbol del store pasa de ${MAX_SCOPE_CHAIN_HOPS} niveles desde ${factsScopeObject(key)}; ` +
        `no se puede resolver la cadena para el barrido de roles locales.`
    )
  }

  /**
   * Purga del scope exacto en FGA (N7, S6, B2). No hay "borrar todo lo de
   * este objeto": se leen por objeto EXACTO los bindings posibles — un
   * `role_binding` por cada rol del catálogo de ese `scope_type` y un
   * `deny_binding` por cada permiso — paginando `Read` (nunca ListObjects:
   * trunca sin avisar, L0.7), se borra en lotes ≤ 100 (límite del Write) y
   * se vuelve a leer cada objeto: si queda algo, se lanza. Un rol retirado
   * del catálogo deja bindings inalcanzables por esta vía; es el precio de no
   * tener un índice por objeto, y lo vigilará `authz:reconcile` (3b).
   */
  async purgeScope(purged: ScopeRef): Promise<void> {
    assertScope(purged)
    if (purged.type === APP_SCOPE_TYPE) {
      throw new InvalidIdentityError('purgeScope: la raíz `app` no se purga')
    }
    // La identidad canónica si el árbol aún lo conoce (K1); tal cual si ya no.
    const scope = await this.canonicalOrSelf(purged, 'purgeScope')
    const key = scopeKey(scope)
    const roles = await this.sql('purgeScope.roles', () =>
      db.from('authz_roles').where('scope_type', scope.type).select('uuid')
    )
    // **En `facts` los denies ya no son objetos propios** (3b-2c): son
    // relaciones `denied_<P>` DEL SCOPE, así que se purgan leyendo el objeto
    // `scope:<key>` en vez de un `deny_binding` por permiso —una lectura en
    // vez de O(permisos)—, y con ellos se va el enlace `#binding` de los
    // bindings que colgaban de aquí. Lo que NO se toca es la arista `parent`:
    // la borra `scopes.detached` DESPUÉS de que esta purga demuestre cero
    // (S6, cruce 9). Al revés, una purga que muriera a medias dejaría el
    // scope sin ancestro, sus denies heredados dejarían de aplicar y esos
    // permisos serían INDENEGABLES (invariante 2).
    const scopeObject = this.hierarchy === 'facts' ? factsScopeObject(key) : null
    const permissions = scopeObject
      ? []
      : await this.sql('purgeScope.permissions', () => db.from('authz_permissions').select('uuid'))
    const objects = [
      ...roles.map((r: any) => `role_binding:${key}|${r.uuid}`),
      ...permissions.map((p: any) => `deny_binding:${key}|${p.uuid}`),
      ...(scopeObject ? [scopeObject] : []),
    ]
    /** Lo purgable de un objeto: todo, salvo la arista `parent` del scope. */
    const purgeable = async (object: string) => {
      const keys = await this.readAllTuples({ object }, { includeExpired: true })
      return object === scopeObject ? keys.filter((k) => k.relation !== FACTS_PARENT_RELATION) : keys
    }
    /** Borra en lotes ≤ 100 (límite del `Write`), sin quejarse de lo que ya no está. */
    const deleteKeys = async (keys: Array<{ user: string; relation: string; object: string }>) => {
      for (let i = 0; i < keys.length; i += PURGE_BATCH_SIZE) {
        await this.client.deleteTuples(keys.slice(i, i + PURGE_BATCH_SIZE), {
          conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore },
        })
      }
    }
    /** Las dos aristas de (c2): estructura, no hechos (`#role` y `#binding`). */
    const isStructure = (k: { relation: string }) =>
      k.relation === FACTS_BINDING_RELATION || k.relation === FACTS_ROLE_RELATION

    if (!scopeObject) {
      // Modo `resolver`: un objeto por binding y por deny, sin aristas que
      // ordenar. Se lee y se borra, como desde el principio.
      for (const object of objects) await deleteKeys(await purgeable(object))
    } else {
      // **En `facts` el ORDEN de la purga es parte del contrato** (3b-2f · R3).
      // No hay transacción que abarque los N objetos, así que un `grant`
      // concurrente aterriza en algún hueco; lo que se elige es que NINGÚN
      // hueco deje una asignación que `listRoles`/`hasRole` ven y `authorize`
      // no honra —enumerada y sin conceder, que es peor que perder la
      // escritura—:
      //
      //  1. **la ESTRUCTURA primero** (`role_binding#role` y `scope#binding`).
      //     Son deterministas —`factsBindingTuples(key, rol)`—, así que se
      //     borran a ciegas y esta fase no cuesta ni una lectura.
      //  2. **los HECHOS después** (`assignee`), releyendo cada objeto: lo que
      //     alguien escribió después de (1) también se borra.
      //  3. **los `denied_<P>` del scope, los últimos.**
      //
      // Con el `grant` escribiendo sus TRES tuplas en un solo `Write`, un
      // grant que aterriza antes de (2) pierde su asignación ahí (cero,
      // coherente) y uno que aterriza después se queda ENTERO con las aristas
      // que él mismo escribió (concede, coherente). Al revés —las aristas al
      // final, como hasta 3b-2e— el grant que caía en medio se quedaba con el
      // `assignee` y sin arista.
      // Los denies van los ÚLTIMOS porque una purga que muere a medias tiene
      // que dejar denies de MÁS, nunca de menos (invariante 2): entre (1) y
      // (3) lo que queda del scope es inerte, no permisivo. Y (2) y (3) borran
      // SOLO lo suyo: una arista que un grant concurrente reescribió no se
      // toca —sería volver a huerfanar su asignación—; queda como residuo, y
      // el residuo es justo lo que la demostración de cero reporta. La arista
      // `parent` sigue sin tocarse: la borra `scopes.detached` DESPUÉS de que
      // esta purga demuestre cero (S6, cruce 9).
      await deleteKeys(roles.flatMap((r: any) => factsBindingTuples(key, r.uuid)))
      for (const object of objects) {
        if (object === scopeObject) continue
        await deleteKeys((await purgeable(object)).filter((k) => !isStructure(k)))
      }
      await deleteKeys(
        (await purgeable(scopeObject)).filter((k) => k.relation.startsWith(FACTS_DENIED_PREFIX))
      )
    }

    // Demostrar cero: lo que no se puede demostrar, se reporta.
    const residue: string[] = []
    for (const object of objects) {
      const left = await purgeable(object)
      if (left.length) residue.push(`${object} (${left.length})`)
    }
    if (residue.length) {
      throw new PurgeIncompleteError(
        `purgeScope ${key}: quedan tuplas tras el borrado — ${residue.join('; ')}. ` +
          `No confirmes el borrado del scope; reintenta la purga.`
      )
    }
  }

  /**
   * La **proyección derivada del catálogo** en el store (3b-2a · A5; regla
   * del catálogo reescrita, panel 2 cruce 7). Se pasa a `syncAuthzCatalog`,
   * que la usa en dos momentos: comprueba que el catálogo que va a quedar es
   * publicable (cotas de nombre y techo del modelo) ANTES de escribir, y
   * rehace las tuplas `role:<uuid>#permits_<P>@<holder>:*` con el catálogo ya
   * confirmado.
   *
   * Sigue sin ser el catálogo: es un espejo reconstruible que ningún camino
   * de LECTURA de este driver consulta para responder qué permisos tiene un
   * rol (A6). Quien decide es `authz_*` a través del memo.
   */
  catalogProjection(): CatalogProjection {
    return {
      assertPublishable: (permissions) => {
        assertFactsModelPublishable(this.holderTypes, permissions, (message) => this.warn(message))
      },
      project: (snapshot) => this.projectCatalog(snapshot),
    }
  }

  /**
   * Espeja los vínculos rol→permiso: escribe lo que falta y BORRA lo que
   * sobra, en UN `Write` por lote con deletes y writes juntos (cruce 8:
   * queda prohibido el patrón `deleteTuples()` + `writeTuples()`, que no es
   * atómico). Con (c2) quitar un permiso de un rol son tantos deletes como
   * holders y ninguna reescritura del modelo.
   *
   * Sin diferencias no se llama al servidor: un `sync` que no cambió el
   * catálogo escribe CERO tuplas.
   */
  private async projectCatalog(snapshot: CatalogProjectionSnapshot): Promise<CatalogProjectionReport> {
    const wanted = new Map<string, FactsCatalogTuple>()
    for (const tuple of factsCatalogTuples(snapshot.roles, this.holderTypes)) {
      wanted.set(factsTupleId(tuple), tuple)
    }
    // Lo que la proyección tiene HOY. `Read` por prefijo de tipo, paginado y
    // acotado como todas las enumeraciones del driver (L0.7) — y UNA lectura
    // por holder, porque el servidor REAL rechaza con un 400 un `Read` cuyo
    // objeto es solo el tipo y no trae user («the object type field is
    // required and both the object id and user cannot be empty»). Con el
    // comodín de usuario de (c2) eso no cuesta nada: la proyección son
    // exactamente las tuplas `<holder>:*`, así que preguntando por cada
    // comodín se ve el espejo ENTERO —incluidas las tuplas de roles que el
    // catálogo ya no lista, que es lo que hay que borrar—. Lo escrito con
    // otro user sobre `role:` no es de esta proyección y no se toca.
    const current = new Map<string, FactsCatalogTuple>()
    for (const holderType of Object.values(this.holderTypes)) {
      for (const key of await this.readAllTuples(
        { user: `${holderType}:*`, object: `${FACTS_ROLE_TYPE}:` },
        { includeExpired: true }
      )) {
        // Solo la familia del catálogo: si el modelo crece con otras
        // relaciones sobre `role`, no son de esta proyección.
        if (!key.relation.startsWith(FACTS_PERMITS_PREFIX)) continue
        current.set(factsTupleId(key), key)
      }
    }

    const writes = [...wanted.values()].filter((tuple) => !current.has(factsTupleId(tuple)))
    const deletes = [...current.values()].filter((tuple) => !wanted.has(factsTupleId(tuple)))
    // Los deletes van primero dentro del lote: quitar un permiso tiene que
    // caber en la misma request que lo que lo sustituye.
    const operations: Array<{ write?: FactsCatalogTuple; delete?: FactsCatalogTuple }> = [
      ...deletes.map((tuple) => ({ delete: tuple })),
      ...writes.map((tuple) => ({ write: tuple })),
    ]
    for (let i = 0; i < operations.length; i += PURGE_BATCH_SIZE) {
      const chunk = operations.slice(i, i + PURGE_BATCH_SIZE)
      await this.client.write({
        writes: chunk.filter((o) => o.write).map((o) => o.write!),
        deletes: chunk.filter((o) => o.delete).map((o) => o.delete!),
      })
    }
    return { written: writes.length, deleted: deletes.length, unchanged: wanted.size - writes.length }
  }

  /**
   * **Purga un ROL con sus hechos** (3b-2e · E4; hasta aquí este driver no lo
   * traía y por eso `defineScopedRole` era 500 `E_AUTHZ_UNSUPPORTED` antes de
   * escribir, 3E · P4).
   *
   * Lo que lo hace posible es (c2): el binding APUNTA A SU ROL
   * (`role_binding:…#role@role:<uuid>`), así que los bindings de un rol se
   * enumeran filtrando por `user` — y con la arista `scope#binding` se sabe de
   * qué scope cuelga cada uno. En el modo `resolver` esas dos aristas no
   * existen y el método TAMPOCO: el constructor lo retira (el manager lo lee
   * como «no sé purgar» y se niega antes de escribir).
   *
   * Orden: **hechos primero, catálogo después** (el mismo de `detached`, S6).
   * No hay transacción que abarque FGA y SQL, así que lo que se garantiza es
   * la dirección segura: mientras la fila del rol siga viva, lo que quede en
   * el store es visible y reintentable; al revés quedarían hechos huérfanos
   * que resucitarían al recrear el slug. Y se DEMUESTRA cero (invariante 11):
   * si algo sobrevive, 500 `E_AUTHZ_PURGE_INCOMPLETE` y el catálogo no se
   * toca.
   */
  async purgeRole(roleUuid: string): Promise<void> {
    assertCatalogUuid('rol', roleUuid)
    const existing = await this.sql('purgeRole.role', () =>
      db.from('authz_roles').where('uuid', roleUuid).select('uuid')
    )
    if (!existing.length) throw new UnknownRoleError(roleUuid)

    const roleObject = `${FACTS_ROLE_TYPE}:${roleUuid}`
    /** Los objetos `role_binding` de este rol, por su arista `#role`. */
    const bindingsOf = async (): Promise<string[]> => {
      const edges = await this.readAllTuples(
        { user: roleObject, relation: FACTS_ROLE_RELATION, object: `${FACTS_BINDING_TYPE}:` },
        { includeExpired: true }
      )
      return [...new Set(edges.map((edge) => edge.object))]
    }
    /** El scope del que cuelga un binding, según su propio id (`<scopeKey>|<roleUuid>`). */
    const scopeOf = (binding: string): string | null => {
      const id = binding.slice(FACTS_BINDING_TYPE.length + 1)
      const separator = id.lastIndexOf('|')
      return separator > 0 ? id.slice(0, separator) : null
    }
    /** Todo lo purgable del rol: sus bindings enteros, las aristas del scope y su proyección. */
    const purgeable = async (): Promise<FactsTuple[]> => {
      const keys: FactsTuple[] = []
      for (const binding of await bindingsOf()) {
        keys.push(...(await this.readAllTuples({ object: binding }, { includeExpired: true })))
        const key = scopeOf(binding)
        if (!key) continue
        // La arista vive en el objeto `scope`, así que se lee de ahí (y solo
        // la que apunta a ESTE binding: el scope tiene las de otros roles).
        const scopeEdges = await this.readAllTuples(
          { user: binding, relation: FACTS_BINDING_RELATION, object: factsScopeObject(key) },
          { includeExpired: true }
        )
        keys.push(...scopeEdges)
      }
      // La proyección del catálogo del rol: `role:<uuid>#permits_<P>@<holder>:*`.
      for (const holderType of Object.values(this.holderTypes)) {
        keys.push(
          ...(await this.readAllTuples({ user: `${holderType}:*`, object: roleObject }, { includeExpired: true }))
        )
      }
      return keys
    }

    const keys = await purgeable()
    for (let i = 0; i < keys.length; i += PURGE_BATCH_SIZE) {
      await this.client.deleteTuples(keys.slice(i, i + PURGE_BATCH_SIZE), {
        conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore },
      })
    }
    const residue = await purgeable()
    if (residue.length) {
      throw new PurgeIncompleteError(
        `purgeRole ${roleUuid}: quedan ${residue.length} tuplas tras el borrado ` +
          `(${residue.slice(0, 3).map((k) => `${k.user}#${k.relation}@${k.object}`).join('; ')}…). ` +
          `El rol NO se borra del catálogo: reintenta la purga.`
      )
    }

    try {
      await this.sql('purgeRole', () =>
        withAuthzCatalogWrite(
          async (trx) => {
            // `authz_assignments` es del driver `database` y aquí está vacía,
            // pero se limpia igual: un store que viene de una migración entre
            // drivers no puede dejar filas apuntando a un rol que ya no existe.
            await this.sql('purgeRole.assignments', () =>
              trx.from('authz_assignments').where('role_uuid', roleUuid).delete()
            )
            await this.sql('purgeRole.links', () =>
              trx.from('authz_role_permissions').where('role_uuid', roleUuid).delete()
            )
            const deleted: unknown = await this.sql('purgeRole.role.delete', () =>
              trx.from('authz_roles').where('uuid', roleUuid).delete()
            )
            if (Number(Array.isArray(deleted) ? deleted[0] : deleted) === 0) throw new UnknownRoleError(roleUuid)
          },
          { driver: 'openfga', timeoutMs: this.timeoutMs }
        )
      )
    } finally {
      this.catalog.invalidate()
    }
  }

  /**
   * **Rehace la proyección de UN rol** (3b-2e · E4). En (c2) lo que un rol
   * concede son tuplas (`role:<uuid>#permits_<P>@<holder>:*`), no el catálogo
   * local: una escritura de catálogo que no las toque deja un rol que no
   * concede nada (`defineScopedRole`) o que sigue concediendo lo que ya no
   * vincula (`updateScopedRole`) — lo segundo es un fail-open. `syncAuthzCatalog`
   * ya lo hace para el catálogo entero cuando el consumidor le pasa la
   * proyección; esto es lo mismo para las escrituras de la API de delegación,
   * y cuesta una lectura por holder.
   */
  async projectCatalogRole(roleUuid: string): Promise<void> {
    if (this.hierarchy !== 'facts') return
    assertCatalogUuid('rol', roleUuid)
    const catalog = await this.catalog.view()
    const permissions = [...catalog.rolePermissionsOf(roleUuid)].sort()
    const object = `${FACTS_ROLE_TYPE}:${roleUuid}`
    const wanted = new Map<string, FactsCatalogTuple>()
    for (const tuple of factsCatalogTuples([{ uuid: roleUuid, permissions }], this.holderTypes)) {
      wanted.set(factsTupleId(tuple), tuple)
    }
    const current = new Map<string, FactsCatalogTuple>()
    for (const holderType of Object.values(this.holderTypes)) {
      for (const key of await this.readAllTuples(
        { user: `${holderType}:*`, object },
        { includeExpired: true }
      )) {
        if (!key.relation.startsWith(FACTS_PERMITS_PREFIX)) continue
        current.set(factsTupleId(key), key)
      }
    }
    const writes = [...wanted.values()].filter((tuple) => !current.has(factsTupleId(tuple)))
    const deletes = [...current.values()].filter((tuple) => !wanted.has(factsTupleId(tuple)))
    if (!writes.length && !deletes.length) return
    await this.client.write({ writes, deletes })
  }

  /**
   * TODAS las tuplas que casan con el filtro, paginando `Read` hasta agotar
   * el `continuation_token`, sin las caducadas. Es la única primitiva de
   * enumeración del driver (L0.7): `Read` no tiene tope de resultados —a
   * diferencia de `ListObjects`/`ListUsers`, que cortan al máximo del
   * servidor sin ninguna señal— y devuelve la condición de cada tupla, así
   * que la caducidad se filtra aquí con el mismo reloj que `checkContext`.
   *
   * Contrapartida, documentada en el README: `Read` devuelve tuplas
   * ESCRITAS, no relaciones computadas. Con el modelo que genera este paquete
   * (`assignee`/`denied` directas) es exactamente lo mismo; un modelo
   * extendido con relaciones derivadas sobre `role_binding` no se enumeraría
   * por aquí.
   */
  private async readAllTuples(
    filter: { user?: string; relation?: string; object: string },
    options: { includeExpired?: boolean; at?: Date } = {}
  ): Promise<Array<{ user: string; relation: string; object: string }>> {
    // El instante con el que se filtra: el de la operación si lo trae (K9), o
    // el de esta lectura.
    const now = options.at ?? this.now()
    const keys: Array<{ user: string; relation: string; object: string }> = []
    let continuationToken: string | undefined
    const seenTokens = new Set<string>()
    let pages = 0
    do {
      const response = await this.client.read(filter, {
        pageSize: READ_PAGE_SIZE,
        continuationToken,
        consistency: this.consistency,
      })
      pages += 1
      for (const tuple of response.tuples ?? []) {
        const k: any = tuple?.key
        if (!k?.user || !k?.relation || !k?.object) {
          // Una tupla que el motor no puede leer es un hecho que las
          // enumeraciones NO muestran: se cuenta y se registra (L0.16, H16).
          this.diagnostics.unparseableBindings += 1
          this.warn(
            `authz(openfga): tupla malformada en Read ${JSON.stringify(filter)} (${JSON.stringify(k ?? null)}); se ignora en la enumeración (total: ${this.diagnostics.unparseableBindings})`
          )
          continue
        }
        if (!options.includeExpired) {
          const validUntil = toExpiryDate(k.condition?.context?.valid_until)
          if (validUntil && validUntil <= now) continue
        }
        keys.push({ user: k.user, relation: k.relation, object: k.object })
      }
      continuationToken = response.continuation_token || undefined
      if (continuationToken) {
        if (seenTokens.has(continuationToken)) {
          throw new AuthorizationInternalError(
            `Read ${JSON.stringify(filter)}: el continuation_token se repite (página ${pages}); el servidor no avanza`
          )
        }
        if (pages >= MAX_READ_PAGES) {
          throw new AuthorizationInternalError(
            `Read ${JSON.stringify(filter)}: más de ${MAX_READ_PAGES} páginas sin agotar el continuation_token`
          )
        }
        seenTokens.add(continuationToken)
      }
    } while (continuationToken)
    return keys
  }
}
