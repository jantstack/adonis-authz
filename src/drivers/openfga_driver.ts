import { Exception } from '@adonisjs/core/exceptions'
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
} from '../errors.js'
import type {
  AuthorizationDriver,
  GrantOptions,
  ScopeAncestorsResolver,
  ScopeRef,
  ScopeType,
  SubjectRef,
} from '../types.js'
import { APP_SCOPE, APP_SCOPE_TYPE } from '../types.js'
import { APP_SCOPE_DB_UUID } from './database_driver.js'
import { assertIdentity, assertScope, isValidScope, isValidSlug } from '../identity.js'
import { guardSql, isTimeoutLike, resolveChain, withDeadline } from './backend_guard.js'

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
 * MISMO con el que se generó el authorization model del store.
 */
export type HolderTypeMap = Record<string, string>

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
    throw new Exception(
      `Holder type '${subject.type}' no está en el modelo FGA ` +
        `(declarados: ${Object.keys(holderTypes).join(', ') || 'ninguno'}). ` +
        `Añádelo a holderTypes y regenera el authorization model.`,
      { status: 500 }
    )
  }
  return `${fgaType}:${subject.uuid}`
}

/**
 * El `context` de TODA consulta que evalúe relaciones: checks de roles, de
 * denies y enumeraciones. Un único constructor a propósito (S17): en cuanto
 * una tupla del camino lleva la condición `not_expired`, un check sin
 * `current_time` falla entero (400 → 503), y `ListObjects` sin él devuelve un
 * 500 del servidor. Hoy los denies no llevan condición; el modo facts (3b)
 * evalúa deny y grant en un solo check, así que no hay margen.
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
 * ¿La expiración almacenada y la pedida son la misma? Compara el instante,
 * no la cadena: `2026-01-01T00:00:00Z` y `2026-01-01T00:00:00.000Z` son el
 * mismo momento y no justifican reescribir la tuple.
 */
function sameExpiry(
  storedValidUntil: string | undefined,
  requested: Date | null | undefined
): boolean {
  if (!storedValidUntil && !requested) return true
  if (!storedValidUntil || !requested) return false
  const stored = Date.parse(storedValidUntil)
  return Number.isFinite(stored) && stored === requested.getTime()
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
}

export const DEFAULT_TIMEOUT_MS = 5_000

export interface ImportFactsResult {
  assignments: number
  denies: number
  skippedExpired: number
  dryRun: boolean
}

/**
 * Migración de hechos database → openfga: copia las asignaciones vigentes y
 * los denies de las tablas `authz_*` como tuples del store FGA.
 *
 * - COPIA, no mueve: las tablas locales quedan intactas → el rollback es
 *   volver a AUTHZ_DRIVER=database (solo se pierde lo escrito mientras se
 *   operó con openfga). El catálogo y la jerarquía nunca migran: son
 *   metadata local para ambos drivers.
 * - Idempotente: re-ejecutar no duplica (onDuplicateWrites: Ignore).
 * - Las asignaciones ya expiradas se saltan (no tiene sentido copiarlas);
 *   las de expiración futura viajan con la condition `not_expired`.
 */
export async function importAuthzFactsToOpenFga(
  options: OpenFgaDriverOptions & { dryRun?: boolean }
): Promise<ImportFactsResult> {
  const client = new OpenFgaClient({
    apiUrl: options.apiUrl,
    storeId: options.storeId,
    authorizationModelId: options.modelId,
  })

  const now = new Date()
  const result: ImportFactsResult = {
    assignments: 0,
    denies: 0,
    skippedExpired: 0,
    dryRun: options.dryRun ?? false,
  }
  const tuples: any[] = []

  const assignments = await db
    .from('authz_assignments as a')
    .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
    .select('a.holder_type', 'a.holder_uuid', 'a.scope_type', 'a.scope_uuid', 'a.expires_at')
    .select('r.slug as role_slug')

  const rowScope = (row: any): ScopeRef => ({
    type: row.scope_type,
    uuid: row.scope_uuid === APP_SCOPE_DB_UUID ? null : row.scope_uuid,
  })

  for (const row of assignments) {
    const expiresAt = row.expires_at ? new Date(row.expires_at) : null
    if (expiresAt && expiresAt <= now) {
      result.skippedExpired++
      continue
    }
    const scope = rowScope(row)
    const key = {
      user: fgaSubjectWith({ type: row.holder_type, uuid: row.holder_uuid }, options.holderTypes),
      relation: 'assignee',
      object: `role_binding:${scopeKey(scope)}|${encodeSlug(row.role_slug)}`,
    }
    tuples.push(
      expiresAt
        ? {
            ...key,
            condition: { name: 'not_expired', context: { valid_until: expiresAt.toISOString() } },
          }
        : key
    )
    result.assignments++
  }

  const denies = await db
    .from('authz_denies as d')
    .join('authz_permissions as p', 'p.uuid', 'd.permission_uuid')
    .select('d.holder_type', 'd.holder_uuid', 'd.scope_type', 'd.scope_uuid')
    .select('p.slug as permission_slug')

  for (const row of denies) {
    const scope = rowScope(row)
    tuples.push({
      user: fgaSubjectWith({ type: row.holder_type, uuid: row.holder_uuid }, options.holderTypes),
      relation: 'denied',
      object: `deny_binding:${scopeKey(scope)}|${encodeSlug(row.permission_slug)}`,
    })
    result.denies++
  }

  if (!result.dryRun && tuples.length > 0) {
    // Chunks: el write transaccional de FGA tiene límite de tuples por request.
    for (let i = 0; i < tuples.length; i += 50) {
      await client.writeTuples(tuples.slice(i, i + 50), {
        conflict: { onDuplicateWrites: ClientWriteRequestOnDuplicateWrites.Ignore },
      })
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
      }),
      timeoutMs
    )
    this.resolveAncestors =
      options.resolveAncestors ??
      (async (scope) => (scope.type === APP_SCOPE_TYPE ? [] : [APP_SCOPE]))
    this.holderTypes = options.holderTypes
    this.logger = options.logger ?? console
    this.timeoutMs = timeoutMs
    this.consistency =
      options.consistency === 'minimize_latency'
        ? ConsistencyPreference.MinimizeLatency
        : ConsistencyPreference.HigherConsistency
  }

  private chain(scope: ScopeRef, operation: string): Promise<ScopeRef[]> {
    return resolveChain(this.resolveAncestors, scope, operation)
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
    return correlateBatchResults(withIds, response.result)
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
    if (!role) {
      throw new Exception(`Rol '${slug}' no existe en el catálogo para el nivel '${scopeType}'`, {
        status: 422,
      })
    }
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

    // 1. Denies en la cadena. FAIL-CLOSED: un check de deny con error se
    //    trata como denegado (jamás se ignora un deny por un fallo puntual).
    const denyChecks = chain.map((s) => ({
      user,
      relation: 'denied',
      object: `deny_binding:${scopeKey(s)}|${encodeSlug(permission)}`,
      context: checkContext(),
    }))
    const denyResults = await this.batchCheckAll(denyChecks)
    if (denyResults.some((r) => r.allowed || r.error)) return false

    // 2. Alguna asignación vigente en la cadena cuyo rol concede el permiso.
    //    Aquí un error individual falla cerrado por sí solo (no concede).
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
    return results.some((r) => r.allowed && !r.error)
  }

  async grant(
    subject: SubjectRef,
    role: string,
    scope: ScopeRef,
    options: GrantOptions = {}
  ): Promise<void> {
    assertIdentity({ subject, role, scope })
    await this.findRoleOrFail(role, scope.type)

    const key = {
      user: this.fgaSubject(subject),
      relation: 'assignee',
      object: `role_binding:${scopeKey(scope)}|${encodeSlug(role)}`,
    }
    const write = options.expiresAt
      ? {
          ...key,
          condition: {
            name: 'not_expired',
            context: { valid_until: options.expiresAt.toISOString() },
          },
        }
      : key

    // FGA no admite delete+write de la misma tuple key en una transacción, así
    // que refrescar la expiración obliga a dos llamadas — y entre ellas hay un
    // instante en el que authorize() responde false.
    //
    // Se mira primero qué hay, para NO pagar esa ventana cuando no hace falta:
    //  - si no existe la tuple → solo write (el caso del primer grant);
    //  - si existe idéntica → no-op (re-ejecutar un seeder no toca nada);
    //  - solo si la expiración CAMBIA de verdad se hace delete+write.
    // La ventana pasa de "cada re-grant" a "cuando el llamante quiso cambiarla".
    const current = await this.readAssignment(key)

    // Solo se salta la escritura si SABEMOS que lo almacenado ya es esto.
    if (current.kind === 'present' && sameExpiry(current.validUntil, options.expiresAt)) return

    if (current.kind === 'absent') {
      // No había nada: un write basta y no hay ventana de denegación. Si entre
      // el read y el write otro proceso escribió la misma key, este write
      // choca — y entonces sí toca el camino largo, para que gane el último
      // escritor y no se pierda esta expiración en silencio.
      try {
        await this.client.writeTuples([write])
        return
      } catch {
        // cae al delete+write de abajo
      }
    }

    await this.client.deleteTuples([key], {
      conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore },
    })
    await this.client.writeTuples([write], {
      conflict: { onDuplicateWrites: ClientWriteRequestOnDuplicateWrites.Ignore },
    })
  }

  /**
   * Estado actual de una asignación, con TRES resultados posibles y no dos.
   *
   * Distinguir `unknown` de `present` sin condición es lo que impide un bug
   * feo: si un fallo de lectura se pareciera a "existe y sin expiración", un
   * grant sin expiración saldría por el atajo del no-op y se perdería —
   * mientras el hook onWrite ya habría auditado que se concedió.
   */
  private async readAssignment(key: {
    user: string
    relation: string
    object: string
  }): Promise<
    { kind: 'absent' } | { kind: 'present'; validUntil?: string } | { kind: 'unknown' }
  > {
    try {
      const response = await this.client.read(key, { consistency: this.consistency })
      const tuple = response.tuples?.[0]
      if (!tuple) return { kind: 'absent' }
      const validUntil = (tuple.key as any)?.condition?.context?.valid_until
      return { kind: 'present', validUntil: validUntil ? String(validUntil) : undefined }
    } catch {
      // No se pudo leer: se asume lo peor y se toma el camino largo, que
      // funciona exista o no la tuple.
      return { kind: 'unknown' }
    }
  }

  async revoke(subject: SubjectRef, role: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, role, scope })
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

  async hasRole(subject: SubjectRef, role: string, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, role, scope })
    const user = this.fgaSubject(subject)
    const chain = await this.chain(scope, 'hasRole')
    const results = await this.batchCheckAll(
      chain.map((s) => ({
        user,
        relation: 'assignee',
        object: `role_binding:${scopeKey(s)}|${encodeSlug(role)}`,
        context: checkContext(),
      }))
    )
    return results.some((r) => r.allowed && !r.error)
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    const perm = await this.findPermission(permission)
    if (!perm) {
      throw new Exception(`Permiso '${permission}' no existe en el catálogo`, { status: 422 })
    }
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

  async listSubjects(role: string, scope: ScopeRef): Promise<SubjectRef[]> {
    assertIdentity({ role, scope })
    // ListUsers exige EXACTAMENTE un user_filter → una consulta por tipo.
    const results: SubjectRef[] = []
    const fgaToMorph = Object.fromEntries(
      Object.entries(this.holderTypes).map(([morph, fga]) => [fga, morph])
    )
    for (const fgaType of [...new Set(Object.values(this.holderTypes))]) {
      const response = await this.client.listUsers(
        {
          object: { type: 'role_binding', id: `${scopeKey(scope)}|${encodeSlug(role)}` },
          relation: 'assignee',
          user_filters: [{ type: fgaType }],
          context: checkContext(),
        },
        { consistency: this.consistency }
      )
      for (const u of response.users ?? []) {
        if (u.object) {
          results.push({ type: fgaToMorph[u.object.type] ?? u.object.type, uuid: u.object.id })
        }
      }
    }
    return results
  }

  /**
   * Bindings del subject ya parseados (asignaciones directas vigentes). Los
   * ids que no se entienden se registran y se cuentan, no se descartan.
   */
  private async listBindings(subject: SubjectRef): Promise<Array<{ scope: ScopeRef; slug: string }>> {
    const response = await this.client.listObjects(
      {
        user: this.fgaSubject(subject),
        relation: 'assignee',
        type: 'role_binding',
        context: checkContext(),
      },
      { consistency: this.consistency }
    )
    return this.parseBindings('role_binding', response.objects ?? [])
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
    const prefix = scopeKey(scope)
    const roles = new Set<string>()
    for (const binding of await this.listBindings(subject)) {
      if (scopeKey(binding.scope) === prefix) roles.add(binding.slug)
    }
    return [...roles]
  }

  async listRoleScopes(subject: SubjectRef, scopeType: ScopeType): Promise<ScopeRef[]> {
    assertIdentity({ subject, scopeType })
    const seen = new Map<string, ScopeRef>()
    for (const binding of await this.listBindings(subject)) {
      if (binding.scope.type === scopeType) seen.set(scopeKey(binding.scope), binding.scope)
    }
    return [...seen.values()]
  }

  async listScopes(subject: SubjectRef, permission: string): Promise<ScopeRef[]> {
    assertIdentity({ subject, permission })
    const perm = await this.findPermission(permission)
    if (!perm) return []

    const granting = await this.rolesGranting(perm.uuid)

    // Denies del subject para este permiso (una sola consulta).
    const denyResponse = await this.client.listObjects(
      {
        user: this.fgaSubject(subject),
        relation: 'denied',
        type: 'deny_binding',
        context: checkContext(),
      },
      { consistency: this.consistency }
    )
    const deniedKeys = new Set(
      this.parseBindings('deny_binding', denyResponse.objects ?? [])
        .filter((p) => p.slug === permission)
        .map((p) => scopeKey(p.scope))
    )

    const result = new Map<string, ScopeRef>()
    for (const binding of await this.listBindings(subject)) {
      if (!(granting.get(binding.scope.type) ?? []).includes(binding.slug)) continue

      const chain = await this.chain(binding.scope, 'listScopes')
      const blocked = chain.some((s) => deniedKeys.has(scopeKey(s)))
      if (!blocked) result.set(scopeKey(binding.scope), binding.scope)
    }
    return [...result.values()]
  }
}

