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
  StoreNotEmptyError,
  UnknownPermissionError,
  UnknownRoleError,
} from '../errors.js'
import type {
  AuthorizationDriver,
  GrantOptions,
  GrantOutcome,
  HolderTypeMap,
  RoleQuery,
  ScopeAncestorsResolver,
  ScopeRef,
  ScopeType,
  SubjectRef,
} from '../types.js'
import { APP_SCOPE_TYPE } from '../types.js'
import { APP_SCOPE_DB_UUID } from './database_driver.js'
import {
  assertIdentity,
  assertScope,
  isValidScope,
  isValidSlug,
  normalizeRoleQuery,
} from '../identity.js'
import { resolveGrantExpiry, sameInstant, toExpiryDate } from '../expiry.js'
import {
  assertKnownScope,
  guardSql,
  isTimeoutLike,
  resolveChain,
  rootOnlyResolver,
  withDeadline,
} from './backend_guard.js'

/**
 * Driver `openfga` — los HECHOS (asignaciones y denies) viven en un servidor
 * OpenFGA; el CATÁLOGO (roles/permisos/vínculos) y la JERARQUÍA (orgs/units)
 * siguen siendo metadata local en las tablas del chasis (split de propiedad
 * de datos del análisis: cambiar de driver = migrar una tabla de hechos).
 *
 * Modelo FGA genérico (ver `openFgaAuthorizationModel()`):
 *  - `role_binding:<scopeKey>|<rol>`   #assignee  → asignación de rol
 *  - `deny_binding:<scopeKey>|<perm>`  #denied    → deny explícito
 *  - Expiración vía condition `not_expired` (valid_until en la tupla,
 *    current_time en cada check) — ni scheduler necesita.
 *
 * La herencia se resuelve igual que en el driver database: la cadena de
 * scopes se calcula localmente (el árbol lo declara el consumidor vía
 * `resolveAncestors`) y se consulta FGA por batchCheck sobre la cadena.
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

/** Nombre de tipo admitido por FGA (`^[^:#@\s]{1,254}$`). */
const FGA_TYPE_FORMAT = /^[^:#@\s]{1,254}$/

/**
 * `holderTypes` tiene que ser INYECTIVO. Si dos morph names caen en el mismo
 * tipo FGA, para el store son un solo holder: un grant a `users:U` autoriza a
 * `integrations:U`, `listSubjects` devuelve el morph equivocado y un revoke
 * borra al otro (invariante 4, L0.2). El generador del modelo lo "sabía"
 * (deduplicaba con un Set) y publicaba sin quejarse: ahora lanza aquí, al
 * construir el driver y al generar el modelo, antes de tocar nada.
 */
export function assertHolderTypes(holderTypes: HolderTypeMap): void {
  if (!holderTypes || typeof holderTypes !== 'object' || Object.keys(holderTypes).length === 0) {
    throw new AuthorizationConfigError(
      'holderTypes vacío: el driver openfga necesita al menos un holder (morph name → tipo FGA)'
    )
  }
  const morphsByFgaType = new Map<string, string[]>()
  for (const [morph, fgaType] of Object.entries(holderTypes)) {
    if (typeof fgaType !== 'string' || !FGA_TYPE_FORMAT.test(fgaType)) {
      throw new AuthorizationConfigError(
        `holderTypes['${morph}'] = ${JSON.stringify(fgaType)} no es un tipo FGA válido ` +
          `(1-254 caracteres, sin ':', '#', '@' ni espacios)`
      )
    }
    morphsByFgaType.set(fgaType, [...(morphsByFgaType.get(fgaType) ?? []), morph])
  }
  const collisions = [...morphsByFgaType.entries()].filter(([, morphs]) => morphs.length > 1)
  if (collisions.length) {
    throw new AuthorizationConfigError(
      `holderTypes no es inyectivo: ` +
        collisions.map(([fga, morphs]) => `${morphs.join(' y ')} → '${fga}'`).join('; ') +
        `. Dos holders con el mismo tipo FGA serían uno solo para el store.`
    )
  }
}

/** `:` no es válido en ids de FGA — se encodea (`audit:read` → `audit~read`). */
function encodeSlug(slug: string): string {
  return slug.replaceAll(':', '~')
}
function decodeSlug(encoded: string): string {
  return encoded.replaceAll('~', ':')
}

/**
 * Clave de scope dentro del id del binding: `app` para la raíz,
 * `<tipo>|<uuid>` para el resto. Genérico: sirve para cualquier nivel que
 * defina el consumidor sin tocar el driver.
 *
 * `|` es el separador y `~` el escape de los slugs: si alguno apareciera
 * dentro de un componente, dos scopes DISTINTOS podrían producir la misma
 * clave —p. ej. `{org, 'anization|X'}` y `{'org|anization', 'X'}`— y un grant
 * en uno autorizaría en el otro. `assertScope` (la misma validación que el
 * manager) lo impide, y además rechaza `{app, uuid}`: antes el uuid se
 * descartaba en silencio y el grant caía en la raíz global (L0.10).
 */
function scopeKey(scope: ScopeRef): string {
  assertScope(scope)
  if (scope.type === APP_SCOPE_TYPE) return APP_SCOPE_TYPE
  return `${scope.type}|${scope.uuid}`
}

/**
 * Id de binding (`app|<slug>` o `<tipo>|<uuid>|<slug>`) → scope + slug. `null`
 * si no tiene la forma del motor O si alguna parte no pasa la validación de
 * identidad: un id que el driver no escribiría no es un hecho del motor,
 * aunque esté en el store. Exportada para probarla sin servidor.
 */
export function parseBindingId(id: string): { scope: ScopeRef; slug: string } | null {
  const parts = id.split('|')
  let parsed: { scope: ScopeRef; slug: string } | null = null
  if (parts.length === 2 && parts[0] === APP_SCOPE_TYPE) {
    parsed = { scope: { type: APP_SCOPE_TYPE, uuid: null }, slug: decodeSlug(parts[1]) }
  } else if (parts.length === 3) {
    parsed = { scope: { type: parts[0], uuid: parts[1] }, slug: decodeSlug(parts[2]) }
  }
  if (!parsed) return null
  if (!isValidScope(parsed.scope)) return null
  // Un slug de rol o de permiso: la gramática de permiso es la más amplia.
  if (!isValidSlug('permiso', parsed.slug)) return null
  return parsed
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
 * la caducidad en cliente con `new Date()`, el mismo reloj.
 */
function checkContext(): { current_time: string } {
  return { current_time: new Date().toISOString() }
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
 * mensaje "cannot write a tuple which already exists"; un 409 se acepta por
 * si una versión del servidor lo devuelve así.
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
  /** Jerarquía del consumidor (ver ScopeAncestorsResolver). */
  resolveAncestors?: ScopeAncestorsResolver
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
}

export const DEFAULT_TIMEOUT_MS = 5_000
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

  const now = new Date()
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

  const assignments = await db
    .from('authz_assignments as a')
    .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
    .select('a.holder_type', 'a.holder_uuid', 'a.scope_type', 'a.scope_uuid', 'a.expires_at')
    .select('r.slug as role_slug')
  for (const row of assignments) {
    const expiresAt = toExpiryDate(row.expires_at)
    if (expiresAt && expiresAt <= now) {
      result.skippedExpired++
      continue
    }
    facts.push({
      key: {
        user: fgaSubjectWith({ type: row.holder_type, uuid: row.holder_uuid }, options.holderTypes),
        relation: 'assignee',
        object: `role_binding:${scopeKey(rowScope(row))}|${encodeSlug(row.role_slug)}`,
      },
      expiresAt,
    })
  }

  const denies = await db
    .from('authz_denies as d')
    .join('authz_permissions as p', 'p.uuid', 'd.permission_uuid')
    .select('d.holder_type', 'd.holder_uuid', 'd.scope_type', 'd.scope_uuid')
    .select('p.slug as permission_slug')
  for (const row of denies) {
    facts.push({
      key: {
        user: fgaSubjectWith({ type: row.holder_type, uuid: row.holder_uuid }, options.holderTypes),
        relation: 'denied',
        object: `deny_binding:${scopeKey(rowScope(row))}|${encodeSlug(row.permission_slug)}`,
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
  private client: OpenFgaClient
  private resolveAncestors: ScopeAncestorsResolver
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

  constructor(options: OpenFgaDriverOptions) {
    assertHolderTypes(options.holderTypes)
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
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
    this.resolveAncestors = options.resolveAncestors ?? rootOnlyResolver
    this.holderTypes = options.holderTypes
    this.logger = options.logger ?? console
    this.timeoutMs = timeoutMs
    this.consistency =
      options.consistency === 'minimize_latency'
        ? ConsistencyPreference.MinimizeLatency
        : ConsistencyPreference.HigherConsistency
  }

  /** `[scope, ...ancestros]`, o `null` si el scope no existe (lecturas: denegar). */
  private chain(scope: ScopeRef, operation: string): Promise<ScopeRef[] | null> {
    return resolveChain(this.resolveAncestors, scope, operation)
  }

  /** La cadena o 422: una escritura no puede ir a un scope que nadie reconoce. */
  private knownScope(scope: ScopeRef, operation: string): Promise<ScopeRef[]> {
    return assertKnownScope(this.resolveAncestors, scope, operation)
  }

  /**
   * Consulta al catálogo local clasificando su fallo. Con este driver el
   * catálogo SQL sigue siendo una dependencia dura de cada pregunta: su caída
   * era un error crudo de Lucid que se presentaba como bug de aplicación (N3).
   */
  private sql<T>(operation: string, fn: () => Promise<T>): Promise<T> {
    return guardSql('openfga', operation, this.timeoutMs, fn)
  }

  /** `limit(1)` y no `.first()` de Lucid: este ejecuta al instante, sin dejar poner el deadline. */
  private async first(operation: string, fn: () => ReturnType<typeof db.from>): Promise<any | null> {
    const rows = await this.sql(operation, () => fn().limit(1))
    return rows[0] ?? null
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

  // ── Catálogo local (compartido entre drivers) ─────────────────────────

  private findPermission(slug: string): Promise<{ uuid: string } | null> {
    return this.first('findPermission', () =>
      db.from('authz_permissions').where('slug', slug).select('uuid')
    )
  }

  private async findRoleOrFail(slug: string, scopeType: string): Promise<void> {
    const role = await this.first('findRole', () =>
      db.from('authz_roles').where('slug', slug).where('scope_type', scopeType).select('uuid')
    )
    if (!role) throw new UnknownRoleError(slug, scopeType)
  }

  /**
   * Slugs de rol que el catálogo declara para un nivel. Las lecturas de
   * membresía (`hasRole`, `listRoles`, `listRoleScopes`, `listSubjects`)
   * filtran con esto: un binding cuyo rol ya no está en `authz_roles` es una
   * tupla huérfana, no una membresía — igual que en `database`, donde el join
   * con el catálogo lo excluye (D5). La tupla la recoge `authz:reconcile`.
   */
  private async catalogRoles(scopeType: string): Promise<Set<string>> {
    const rows = await this.sql('catalogRoles', () =>
      db.from('authz_roles').where('scope_type', scopeType).select('slug')
    )
    return new Set(rows.map((r: any) => r.slug as string))
  }

  /** Niveles (`scope_type`) para los que el catálogo declara el rol. */
  private async roleLevels(slug: string): Promise<Set<string>> {
    const rows = await this.sql('roleLevels', () =>
      db.from('authz_roles').where('slug', slug).select('scope_type')
    )
    return new Set(rows.map((r: any) => r.scope_type as string))
  }

  /** Roles del catálogo que conceden el permiso, agrupados por scope_type. */
  private async rolesGranting(permissionUuid: string): Promise<Map<string, string[]>> {
    const rows = await this.sql('rolesGranting', () =>
      db
        .from('authz_role_permissions as rp')
        .join('authz_roles as r', 'r.uuid', 'rp.role_uuid')
        .where('rp.permission_uuid', permissionUuid)
        .select('r.slug', 'r.scope_type')
    )
    const byScopeType = new Map<string, string[]>()
    for (const row of rows) {
      const list = byScopeType.get(row.scope_type) ?? []
      list.push(row.slug)
      byScopeType.set(row.scope_type, list)
    }
    return byScopeType
  }

  // ── Contrato ──────────────────────────────────────────────────────────

  async authorize(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, permission, scope })
    const perm = await this.findPermission(permission)
    if (!perm) return false

    const user = this.fgaSubject(subject)
    const chain = await this.chain(scope, 'authorize')
    if (!chain) return false

    // 1. Denies en la cadena. Un check con error no llega aquí: `batchCheckAll`
    //    lo lanza como 503 (jamás se ignora un deny por un fallo puntual, y
    //    jamás se disfraza una caída de "sin permiso").
    const denyChecks = chain.map((s) => ({
      user,
      relation: 'denied',
      object: `deny_binding:${scopeKey(s)}|${encodeSlug(permission)}`,
      context: checkContext(),
    }))
    const denyResults = await this.batchCheckAll(denyChecks)
    if (denyResults.some((r) => r.allowed)) return false

    // 2. Alguna asignación vigente en la cadena cuyo rol concede el permiso.
    const granting = await this.rolesGranting(perm.uuid)
    const checks = chain.flatMap((s) =>
      (granting.get(s.type) ?? []).map((roleSlug) => ({
        user,
        relation: 'assignee',
        object: `role_binding:${scopeKey(s)}|${encodeSlug(roleSlug)}`,
        context: checkContext(),
      }))
    )
    if (checks.length === 0) return false

    const results = await this.batchCheckAll(checks)
    return results.some((r) => r.allowed)
  }

  async grant(
    subject: SubjectRef,
    role: string,
    scope: ScopeRef,
    options: GrantOptions = {}
  ): Promise<GrantOutcome> {
    assertIdentity({ subject, roleSlug: role, scope, expiresAt: options.expiresAt })
    await this.findRoleOrFail(role, scope.type)
    await this.knownScope(scope, 'grant')

    const key = {
      user: this.fgaSubject(subject),
      relation: 'assignee',
      object: `role_binding:${scopeKey(scope)}|${encodeSlug(role)}`,
    }
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
      const existed = await this.writeAssignment(key, tupleFor(expiresAt))
      return { existed, expiresAt }
    }

    if (current.kind === 'present') {
      const expiresAt = resolveGrantExpiry(current.validUntil, options.expiresAt)
      if (sameInstant(current.validUntil, expiresAt)) {
        return { existed: true, previousExpiresAt: current.validUntil, expiresAt }
      }
      await this.replaceAssignment(key, tupleFor(expiresAt))
      return { existed: true, previousExpiresAt: current.validUntil, expiresAt }
    }

    // No había nada: un write basta y no hay ventana de denegación. Si entre
    // el read y el write otro proceso escribió la misma key, este write
    // choca con un 409 — entonces se relee y se aplica el re-grant sobre lo
    // que quedó, para que gane el último escritor y no se pierda esta
    // caducidad. Cualquier otro fallo del write no es una carrera (D6).
    const expiresAt = options.expiresAt ?? null
    try {
      await this.client.writeTuples([tupleFor(expiresAt)])
      return { existed: false, expiresAt }
    } catch (error) {
      if (!isDuplicateWrite(error)) throw error
      const raced = await this.readAssignment(key)
      if (raced.kind === 'present') {
        const target = resolveGrantExpiry(raced.validUntil, options.expiresAt)
        if (!sameInstant(raced.validUntil, target)) await this.replaceAssignment(key, tupleFor(target))
        return { existed: true, previousExpiresAt: raced.validUntil, expiresAt: target }
      }
      if (options.expiresAt === undefined) {
        // El write chocó y la relectura no ve la tupla (o falló): sin objetivo
        // explícito no se sabe qué preservar. El 409 original va como causa.
        throw withPreserveRecipe(
          raced.kind === 'unknown'
            ? (raced.error as Error)
            : new AuthorizationBackendError('openfga', 'grant (el write chocó y la relectura no ve la tupla)', error)
        )
      }
      const existed = await this.writeAssignment(key, tupleFor(options.expiresAt))
      return { existed, expiresAt: options.expiresAt }
    }
  }

  /**
   * Write directo; si la key ya existía (409), camino largo. Devuelve si
   * existía. Cualquier otro fallo se propaga tal cual (ya clasificado).
   */
  private async writeAssignment(
    key: { user: string; relation: string; object: string },
    tuple: any
  ): Promise<boolean> {
    try {
      await this.client.writeTuples([tuple])
      return false
    } catch (error) {
      if (!isDuplicateWrite(error)) throw error
      await this.replaceAssignment(key, tuple)
      return true
    }
  }

  /** delete + write (dos llamadas: FGA no admite ambas sobre la misma key en una). */
  private async replaceAssignment(
    key: { user: string; relation: string; object: string },
    tuple: any
  ): Promise<void> {
    await this.client.deleteTuples([key], {
      conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore },
    })
    await this.client.writeTuples([tuple], {
      conflict: { onDuplicateWrites: ClientWriteRequestOnDuplicateWrites.Ignore },
    })
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

  async revoke(subject: SubjectRef, role: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, roleSlug: role, scope })
    // Rol fuera del catálogo para ese nivel ⇒ 422, como en `grant` (D10).
    await this.findRoleOrFail(role, scope.type)
    await this.client.deleteTuples(
      [
        {
          user: this.fgaSubject(subject),
          relation: 'assignee',
          object: `role_binding:${scopeKey(scope)}|${encodeSlug(role)}`,
        },
      ],
      { conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore } }
    )
  }

  async hasRole(subject: SubjectRef, role: RoleQuery, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, role, scope })
    const { slug, scopeType } = normalizeRoleQuery(role)
    const user = this.fgaSubject(subject)
    const chain = await this.chain(scope, 'hasRole')
    if (!chain) return false
    // El id del binding lleva el scope (y con él su tipo) y el slug: en cada
    // nivel solo casa el rol de ese nivel. Con `{ slug, scopeType }` se
    // recorta la cadena a los niveles de ese tipo (L0.6). Y solo se pregunta
    // por los niveles para los que el catálogo declara el rol (D5): un rol
    // retirado no es membresía aunque su tupla siga en el store.
    const declared = await this.roleLevels(slug)
    const levels = chain.filter((s) => declared.has(s.type) && (!scopeType || s.type === scopeType))
    if (levels.length === 0) return false
    const results = await this.batchCheckAll(
      levels.map((s) => ({
        user,
        relation: 'assignee',
        object: `role_binding:${scopeKey(s)}|${encodeSlug(slug)}`,
        context: checkContext(),
      }))
    )
    return results.some((r) => r.allowed)
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    const perm = await this.findPermission(permission)
    if (!perm) throw new UnknownPermissionError(permission)
    await this.knownScope(scope, 'deny')
    await this.client.writeTuples(
      [
        {
          user: this.fgaSubject(subject),
          relation: 'denied',
          object: `deny_binding:${scopeKey(scope)}|${encodeSlug(permission)}`,
        },
      ],
      { conflict: { onDuplicateWrites: ClientWriteRequestOnDuplicateWrites.Ignore } }
    )
  }

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    if (!(await this.findPermission(permission))) throw new UnknownPermissionError(permission)
    await this.client.deleteTuples(
      [
        {
          user: this.fgaSubject(subject),
          relation: 'denied',
          object: `deny_binding:${scopeKey(scope)}|${encodeSlug(permission)}`,
        },
      ],
      { conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore } }
    )
  }

  /**
   * Holders con asignación vigente del rol en el scope exacto: `Read` por
   * objeto exacto, paginado, con la caducidad filtrada en cliente. Antes era
   * `ListUsers`, que trunca al tope del servidor sin señal (L0.7).
   */
  async listSubjects(role: string, scope: ScopeRef): Promise<SubjectRef[]> {
    assertIdentity({ roleSlug: role, scope })
    // Un rol que el catálogo no declara para ese nivel no tiene holders (D5).
    if (!(await this.catalogRoles(scope.type)).has(role)) return []
    const fgaToMorph = Object.fromEntries(
      Object.entries(this.holderTypes).map(([morph, fga]) => [fga, morph])
    )
    const tuples = await this.readAllTuples({
      relation: 'assignee',
      object: `role_binding:${scopeKey(scope)}|${encodeSlug(role)}`,
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
  private async listBindings(subject: SubjectRef): Promise<Array<{ scope: ScopeRef; slug: string }>> {
    const tuples = await this.readAllTuples({
      user: this.fgaSubject(subject),
      relation: 'assignee',
      object: 'role_binding:',
    })
    return this.parseBindings('role_binding', tuples.map((t) => t.object))
  }

  /** Scopes (por clave) donde el subject tiene un deny directo del permiso. */
  private async deniedScopeKeys(subject: SubjectRef, permission: string): Promise<Set<string>> {
    const tuples = await this.readAllTuples({
      user: this.fgaSubject(subject),
      relation: 'denied',
      object: 'deny_binding:',
    })
    return new Set(
      this.parseBindings('deny_binding', tuples.map((t) => t.object))
        .filter((p) => p.slug === permission)
        .map((p) => scopeKey(p.scope))
    )
  }

  private parseBindings(
    type: 'role_binding' | 'deny_binding',
    objects: string[]
  ): Array<{ scope: ScopeRef; slug: string }> {
    const parsed: Array<{ scope: ScopeRef; slug: string }> = []
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
    if (!(await this.chain(scope, 'listRoles'))) return []
    const prefix = scopeKey(scope)
    const declared = await this.catalogRoles(scope.type)
    const roles = new Set<string>()
    for (const binding of await this.listBindings(subject)) {
      if (scopeKey(binding.scope) === prefix && declared.has(binding.slug)) roles.add(binding.slug)
    }
    return [...roles]
  }

  async listRoleScopes(subject: SubjectRef, scopeType: ScopeType): Promise<ScopeRef[]> {
    assertIdentity({ subject, scopeType })
    const declared = await this.catalogRoles(scopeType)
    const seen = new Map<string, ScopeRef>()
    for (const binding of await this.listBindings(subject)) {
      if (binding.scope.type === scopeType && declared.has(binding.slug)) {
        seen.set(scopeKey(binding.scope), binding.scope)
      }
    }
    // Los scopes que el árbol ya no conoce no se listan (D8): una consulta
    // al resolutor por scope, el mismo coste que `listScopes`.
    const known: ScopeRef[] = []
    for (const scope of seen.values()) {
      if (await this.chain(scope, 'listRoleScopes')) known.push(scope)
    }
    return known
  }

  async listScopes(subject: SubjectRef, permission: string): Promise<ScopeRef[]> {
    assertIdentity({ subject, permission })
    const perm = await this.findPermission(permission)
    if (!perm) return []

    const granting = await this.rolesGranting(perm.uuid)

    // Denies directos del subject para este permiso: TODOS, paginando. Con
    // `ListObjects` el tope del servidor se consumía con los denies de
    // cualquier permiso y el relevante podía quedar fuera: fail-open (L0.7).
    const deniedKeys = await this.deniedScopeKeys(subject, permission)

    const result = new Map<string, ScopeRef>()
    for (const binding of await this.listBindings(subject)) {
      if (!(granting.get(binding.scope.type) ?? []).includes(binding.slug)) continue

      // Un scope que el árbol ya no conoce no concede: no se lista.
      const chain = await this.chain(binding.scope, 'listScopes')
      if (!chain) continue
      const blocked = chain.some((s) => deniedKeys.has(scopeKey(s)))
      if (!blocked) result.set(scopeKey(binding.scope), binding.scope)
    }
    return [...result.values()]
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
  async purgeScope(scope: ScopeRef): Promise<void> {
    assertScope(scope)
    if (scope.type === APP_SCOPE_TYPE) {
      throw new InvalidIdentityError('purgeScope: la raíz `app` no se purga')
    }
    const key = scopeKey(scope)
    const roles = await this.sql('purgeScope.roles', () =>
      db.from('authz_roles').where('scope_type', scope.type).select('slug')
    )
    const permissions = await this.sql('purgeScope.permissions', () =>
      db.from('authz_permissions').select('slug')
    )
    const objects = [
      ...roles.map((r: any) => `role_binding:${key}|${encodeSlug(r.slug)}`),
      ...permissions.map((p: any) => `deny_binding:${key}|${encodeSlug(p.slug)}`),
    ]

    for (const object of objects) {
      const keys = await this.readAllTuples({ object }, { includeExpired: true })
      for (let i = 0; i < keys.length; i += PURGE_BATCH_SIZE) {
        await this.client.deleteTuples(keys.slice(i, i + PURGE_BATCH_SIZE), {
          conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore },
        })
      }
    }

    // Demostrar cero: lo que no se puede demostrar, se reporta.
    const residue: string[] = []
    for (const object of objects) {
      const left = await this.readAllTuples({ object }, { includeExpired: true })
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
    options: { includeExpired?: boolean } = {}
  ): Promise<Array<{ user: string; relation: string; object: string }>> {
    const now = new Date()
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
