import db from '@adonisjs/lucid/services/db'
import type { TransactionClientContract } from '@adonisjs/lucid/types/database'
import type { ScopeType } from './types.js'
import { guardSql, isAuthzError, isTimeoutLike } from './drivers/backend_guard.js'
import { AuthorizationBackendError, AuthorizationBackendTimeoutError, AuthorizationConfigError } from './errors.js'

/**
 * Memo del CATÁLOGO (roles, permisos y vínculos rol→permiso), y de nada más.
 *
 * El camino caliente de `authorize` consultaba `authz_*` en cada pregunta
 * (`findPermission` en ambos drivers; `rolesGranting` además en openfga)
 * para leer algo que solo cambia cuando el consumidor sincroniza su config.
 * Este memo carga las tres tablas una vez, perezosamente, y las sirve desde
 * memoria mientras la BASE diga que siguen vigentes. Lo que NUNCA cachea:
 * hechos (asignaciones, denies) ni decisiones — un `authorize` siempre
 * pregunta al backend de hechos; lo que se ahorra es el "¿qué uuid tiene
 * `docs:read`?".
 *
 * Invariante (2D · F1): **el catálogo que decide es el de la BD.** La tabla
 * `authz_catalog_version` (una fila, `id = 1`) lleva un entero que
 * `syncAuthzCatalog` incrementa DENTRO de su transacción. Cada foto recuerda
 * con qué versión se cargó y, antes de servirse, la contrasta con la fila
 * (un SELECT por clave primaria, con deadline y clasificado 503): si difiere,
 * recarga. Así un sync en OTRO proceso (otro worker, `node ace
 * authz:catalog:sync` en un despliegue) se ve en la siguiente pregunta de
 * todos los procesos, sin pub/sub y sin reiniciar. El memo nunca sirve una
 * decisión con una versión distinta de la de la base.
 *
 * Contrato de invalidación (README, "Performance"):
 *  1. `syncAuthzCatalog` (y por tanto `authz:catalog:sync`) sube la fila en
 *     su transacción (lo ven todos los procesos) y además el contador de
 *     este módulo (lo ve este proceso al instante, también con `everyMs`).
 *  2. `invalidateAuthzCatalog()` invalida los memos de ESTE proceso; la fila
 *     la sube `bumpAuthzCatalogVersion(trx)` para TODOS, y SOLO como última
 *     sentencia de la transacción que escribe `authz_*` (2E · H2): un bump
 *     que se confirma antes que su escritura hace que otro proceso recargue
 *     los datos viejos etiquetados con la versión nueva y no vuelva a
 *     revalidar jamás. Quien escribe `authz_*` por fuera del sync (un seeder,
 *     una migración de datos) lo hace con `withAuthzCatalogWrite(async (trx)
 *     => …)`, que abre la transacción y sube la versión al final, dentro; sin
 *     eso los demás procesos no se enteran (caso negativo fijado por test).
 *  3. `revalidate: 'always'` (default) contrasta la fila en cada `view()`.
 *     `{ everyMs }` (opt-in) la contrasta como mucho una vez por ventana: es
 *     una ventana ACOTADA de catálogo viejo —de revocación fail-open— que el
 *     consumidor acepta a sabiendas a cambio de ahorrarse ese SELECT.
 *
 * Es composición: cada driver del paquete construye el suyo (o recibe uno
 * compartido en `catalog`); un driver de terceros no necesita saber que existe.
 */

/** Tabla de la versión compartida del catálogo (una fila, `id = 1`). */
export const CATALOG_VERSION_TABLE = 'authz_catalog_version'
const CATALOG_VERSION_ROW_ID = 1

export interface CatalogRoleRef {
  slug: string
  uuid: string
}

/** Foto inmutable del catálogo. Se reemplaza entera, nunca se muta. */
export interface CatalogView {
  /** `{ uuid }` del permiso, o `null` si el catálogo no lo declara. */
  permission(slug: string): { uuid: string } | null
  /** `{ uuid }` del rol `(slug, scopeType)`, o `null`. */
  role(slug: string, scopeType: ScopeType): { uuid: string } | null
  /** Roles que conceden el permiso, agrupados por nivel (`scope_type`). */
  rolesGranting(permissionUuid: string): Map<ScopeType, CatalogRoleRef[]>
  /** Slugs de permiso que concede el rol `(slug, scopeType)`; vacío si el rol no existe (2.1, B5). */
  rolePermissions(slug: string, scopeType: ScopeType): Set<string>
  /** Slug del permiso por uuid, o `null` si el catálogo ya no lo declara (2.1, B5). */
  permissionSlug(uuid: string): string | null
  /** Slugs de rol que el catálogo declara para un nivel. */
  roleSlugs(scopeType: ScopeType): Set<string>
  /** Niveles para los que el catálogo declara el slug. */
  roleLevels(slug: string): Set<ScopeType>
  /** Todos los slugs de permiso. */
  readonly permissionSlugs: readonly string[]
  /** Instante de carga (`Date.now()`). */
  readonly loadedAt: number
  /** Versión de `authz_catalog_version` con la que se cargó la foto. */
  readonly version: number
}

/**
 * Versión del catálogo en ESTE proceso. La sube `syncAuthzCatalog` al
 * terminar e `invalidateAuthzCatalog()`; cada memo recuerda con qué versión
 * cargó y se recarga si difiere. Es la señal intra-proceso (inmediata, sin
 * SQL); la señal entre procesos es la fila `authz_catalog_version`.
 */
let catalogVersion = 0

/**
 * Invalida todos los memos del catálogo de este proceso. En otro proceso no
 * hace nada: para eso está la fila compartida (`bumpAuthzCatalogVersion`).
 */
export function invalidateAuthzCatalog(): void {
  catalogVersion += 1
}

/** Deadline de cada consulta de carga (el mismo default que el catálogo). */
export const DEFAULT_CATALOG_CACHE_TIMEOUT_MS = 5_000

/** Lo mínimo que se necesita de un cliente de Lucid para leer la fila. */
export interface CatalogVersionClient {
  from(table: string): any
  table(table: string): any
}

/**
 * El cliente de una TRANSACCIÓN de Lucid (o de knex): lo que `db.transaction`
 * entrega a su callback. Se reconoce en tiempo de ejecución por
 * `isTransaction === true`, que ambos ponen; el `db` global y un
 * `QueryClient` suelto lo llevan a `false` (o no lo tienen) y se rechazan.
 */
export interface CatalogVersionTransaction extends CatalogVersionClient {
  isTransaction: boolean
}

function describeClient(client: unknown): string {
  if (client === null) return 'null'
  if (client === undefined) return 'nada'
  if (typeof client !== 'object' && typeof client !== 'function') return `un ${typeof client}`
  const c = client as { isTransaction?: unknown; constructor?: { name?: string } }
  if (c.isTransaction === false) return `un cliente que NO es una transacción (${c.constructor?.name ?? 'objeto'})`
  return `un ${c.constructor?.name ?? 'objeto'} sin isTransaction`
}

/**
 * `bumpAuthzCatalogVersion` exige la transacción que escribe `authz_*` (2E ·
 * H2, auditor 2): con el `db` global la subida se confirmaba ANTES que la
 * escritura (fuera de la transacción del consumidor) y el memo de otro
 * proceso recargaba los datos viejos con la etiqueta nueva — un fail-open
 * permanente. 500: es un error de programación, no una pregunta.
 */
function assertTransactionClient(client: unknown, operation: string): CatalogVersionTransaction {
  const c = client as Partial<CatalogVersionTransaction> | null | undefined
  if (!c || typeof c.from !== 'function' || typeof c.table !== 'function' || c.isTransaction !== true) {
    throw new AuthorizationConfigError(
      `${operation} exige el cliente de la TRANSACCIÓN que escribe authz_* (el trx de db.transaction) y llegó ` +
        `${describeClient(client)}. Un bump fuera de esa transacción se confirma antes que la escritura y deja a los ` +
        `demás procesos con el catálogo viejo etiquetado como nuevo, para siempre. Escribe authz_* con ` +
        `withAuthzCatalogWrite(async (trx) => { … }): abre la transacción, ejecuta tu escritura y sube la versión ` +
        `como última sentencia, dentro.`
    )
  }
  return c as CatalogVersionTransaction
}

/**
 * `catalog` (memo compartido) y `catalogRevalidate` juntos se contradicen
 * (2E · I3, auditor 11): la política de revalidación es la del memo y se fija
 * al construir el `CatalogCache`; el `catalogRevalidate` del driver se
 * ignoraba en silencio. 500 al construir: config rota, no una pregunta. Lo
 * llaman los dos drivers del paquete desde su constructor.
 */
export function assertCatalogOptions(
  driver: string,
  options: { catalog?: unknown; catalogRevalidate?: unknown }
): void {
  if (options.catalog !== undefined && options.catalogRevalidate !== undefined) {
    throw new AuthorizationConfigError(
      `${driver}: 'catalog' (memo compartido) y 'catalogRevalidate' no pueden ir juntos: la política de ` +
        `revalidación es la del memo que se comparte (new CatalogCache({ revalidate })) y la del driver se ` +
        `ignoraría. Quita 'catalogRevalidate' o construye el driver sin 'catalog'.`
    )
  }
}

/**
 * La fila de la versión no está o no se puede leer como número (2E · I1,
 * auditor 7): es una base sin la migración 2.0 (que la siembra) o con la fila
 * borrada. Fail-closed: sin versión legible no se sirve ningún catálogo — ni
 * el memo viejo ni una carga en frío etiquetada como «versión 0».
 */
function unreadableVersionRow(driver: string, why: string): AuthorizationBackendError {
  const error = new AuthorizationBackendError(driver, 'catalog.version', new Error(why))
  error.message =
    `El backend de autorización '${driver}' no tiene una versión legible del catálogo (${CATALOG_VERSION_TABLE}, ` +
    `id = ${CATALOG_VERSION_ROW_ID}): ${why}. Probablemente la migración 2.0 no está aplicada (siembra la fila); ` +
    `sin ella no se sirve ningún catálogo.`
  return error
}

/**
 * Versión compartida del catálogo: la fila `authz_catalog_version`. Sin fila
 * legible (semilla ausente, fila borrada, valor no numérico) es 503
 * `E_AUTHZ_BACKEND_UNAVAILABLE` con «migración 2.0 no aplicada» (I1); sin
 * TABLA se clasifica como el resto de fallos SQL (503).
 */
export async function readAuthzCatalogVersion(
  options: { client?: CatalogVersionClient; driver?: string; timeoutMs?: number } = {}
): Promise<number> {
  const client = options.client ?? db
  const driver = options.driver ?? 'catalog'
  const rows: Array<{ version: unknown }> = await guardSql(
    driver,
    'catalog.version',
    options.timeoutMs ?? DEFAULT_CATALOG_CACHE_TIMEOUT_MS,
    () => client.from(CATALOG_VERSION_TABLE).where('id', CATALOG_VERSION_ROW_ID).select('version')
  )
  if (rows.length === 0) throw unreadableVersionRow(driver, 'la fila no existe')
  const raw = rows[0].version
  const version = typeof raw === 'number' ? raw : typeof raw === 'string' || typeof raw === 'bigint' ? Number(raw) : Number.NaN
  if (!Number.isFinite(version)) throw unreadableVersionRow(driver, `la columna version vale ${String(raw)}`)
  return version
}

/**
 * Sube la versión compartida del catálogo: TODOS los memos de TODOS los
 * procesos recargan en su siguiente pregunta (o al cerrar su ventana
 * `everyMs`). Exige el cliente de la transacción que escribe `authz_*` (500
 * `E_AUTHZ_CONFIG` sin él, 2E · H2) y tiene que ser su ÚLTIMA sentencia: lo
 * garantiza `withAuthzCatalogWrite`, que es por donde escriben
 * `syncAuthzCatalog` y cualquier seeder o migración de datos. Sin fila
 * (semilla ausente) la crea; la carrera de dos procesos que la crean a la vez
 * la resuelve la clave primaria: el perdedor vuelve a hacer UPDATE. Es SOLO el
 * canal entre procesos: no toca el contador de este (con `everyMs`, hasta este
 * proceso tarda una ventana en verlo; con `'always'`, la siguiente pregunta lo
 * ve).
 */
export async function bumpAuthzCatalogVersion(
  trx: CatalogVersionTransaction,
  options: { driver?: string; timeoutMs?: number } = {}
): Promise<void> {
  const client = assertTransactionClient(trx, 'bumpAuthzCatalogVersion')
  const driver = options.driver ?? 'catalog'
  const timeoutMs = options.timeoutMs ?? DEFAULT_CATALOG_CACHE_TIMEOUT_MS
  const update = () =>
    guardSql(driver, 'catalog.version.bump', timeoutMs, () =>
      client
        .from(CATALOG_VERSION_TABLE)
        .where('id', CATALOG_VERSION_ROW_ID)
        .increment('version', 1)
    )
  const updated = Number(await update())
  if (updated > 0) return
  try {
    await guardSql(driver, 'catalog.version.seed', timeoutMs, () =>
      client.table(CATALOG_VERSION_TABLE).insert({ id: CATALOG_VERSION_ROW_ID, version: 1, updated_at: new Date() })
    )
  } catch (error) {
    // Otro proceso sembró la fila entre el UPDATE y el INSERT: se sube la suya.
    if (Number(await update()) === 0) throw error
  }
}

export interface AuthzCatalogWriteOptions {
  /** Etiqueta del driver en los errores 503 (default `catalog`). */
  driver?: string
  /** Deadline de la subida de versión (default 5000): vencido ⇒ 503. */
  timeoutMs?: number
  /** Conexión de Lucid sobre la que abrir la transacción (default: la del `db` global). */
  connection?: string
}

/**
 * LA forma de escribir `authz_*` por fuera de `syncAuthzCatalog` (2E · H2):
 * abre una transacción, ejecuta `fn(trx)` —tu escritura, con ESE cliente— y
 * sube `authz_catalog_version` como última sentencia, dentro. O se confirma
 * todo (datos nuevos + versión nueva) o nada: un memo de otro proceso nunca
 * puede leer la versión nueva con los datos viejos. Devuelve lo que devuelva
 * `fn`. Si `fn` lanza, la transacción se revierte, la versión no sube y su
 * error sale tal cual (es tuyo); si falla abrir o confirmar la transacción,
 * 503 `E_AUTHZ_BACKEND_UNAVAILABLE`/`_TIMEOUT`.
 *
 * Es solo el canal entre procesos (la fila): en este proceso la siguiente
 * pregunta lo ve con `'always'` y, con `{ everyMs }`, al cerrar la ventana —
 * `syncAuthzCatalog` además invalida en memoria; hazlo tú con
 * `invalidateAuthzCatalog()` si usas `everyMs` y lo necesitas al instante.
 *
 *   await withAuthzCatalogWrite(async (trx) => {
 *     await trx.from('authz_role_permissions').where('role_uuid', role).delete()
 *   })
 */
export async function withAuthzCatalogWrite<T>(
  fn: (trx: TransactionClientContract) => Promise<T>,
  options: AuthzCatalogWriteOptions = {}
): Promise<T> {
  if (typeof fn !== 'function') {
    throw new AuthorizationConfigError(
      `withAuthzCatalogWrite espera la función que escribe authz_* (async (trx) => …) y llegó ${typeof fn}`
    )
  }
  const driver = options.driver ?? 'catalog'
  const timeoutMs = options.timeoutMs ?? DEFAULT_CATALOG_CACHE_TIMEOUT_MS
  const connection = options.connection ? db.connection(options.connection) : db
  // Lo que lance `fn` es del consumidor y sale intacto; lo que falle al abrir
  // o confirmar la transacción es la base y se clasifica (503).
  let consumerError: { error: unknown } | null = null
  try {
    return await connection.transaction(async (trx) => {
      let result: T
      try {
        result = await fn(trx)
      } catch (error) {
        consumerError = { error }
        throw error
      }
      await bumpAuthzCatalogVersion(trx, { driver, timeoutMs })
      return result
    })
  } catch (error) {
    if (consumerError !== null && (consumerError as { error: unknown }).error === error) throw error
    if (isAuthzError(error)) throw error
    if (isTimeoutLike(error)) throw new AuthorizationBackendTimeoutError(driver, 'catalog.write', timeoutMs, error)
    throw new AuthorizationBackendError(driver, 'catalog.write', error)
  }
}

/** Política de revalidación contra la fila compartida (2D · F1). */
export type CatalogRevalidate = 'always' | { everyMs: number }

export interface CatalogCacheOptions {
  /**
   * Cuándo contrastar la foto con `authz_catalog_version`: `'always'`
   * (default) en cada `view()` —un SELECT por clave primaria—; `{ everyMs }`
   * como mucho una vez por ventana. Con ventana, un sync de OTRO proceso
   * tarda hasta `everyMs` en verse: es una ventana acotada de revocación
   * fail-open que se acepta a sabiendas (el sync de ESTE proceso se ve al
   * instante igualmente).
   */
  revalidate?: CatalogRevalidate
  /** Deadline de cada consulta de carga y revalidación (default 5000): vencido ⇒ 503. */
  timeoutMs?: number
  /** Etiqueta del driver en los errores 503 (default `catalog`). */
  driver?: string
  /**
   * SOLO TESTS: fuente del reloj MONÓTONO (ms) con el que se mide la ventana
   * `everyMs` (default `performance.now`, 2E · H3): un reloj de pared que
   * retrocede —NTP, snapshot— no alarga la ventana. En producción no se toca.
   */
  now?: () => number
}

export class CatalogCache {
  #view: CatalogView | null = null
  #version = -1
  /** Generación de ESTA instancia: `invalidate()` la sube; una carga captura la suya antes de leer (F4). */
  #generation = 0
  #loadedGeneration = -1
  #loading: Promise<CatalogView> | null = null
  #checking: Promise<CatalogView> | null = null
  /** Último instante (reloj monótono) en que la foto se contrastó con la fila (base de `everyMs`). */
  #checkedAt = 0
  readonly #everyMs: number | null
  readonly #timeoutMs: number
  readonly #driver: string
  /** Reloj monótono: nunca `Date.now()` para medir una ventana (H3). */
  readonly #now: () => number

  constructor(options: CatalogCacheOptions = {}) {
    const revalidate = options.revalidate ?? 'always'
    if (revalidate !== 'always') {
      const everyMs = (revalidate as { everyMs?: unknown })?.everyMs
      if (typeof everyMs !== 'number' || !(Number.isFinite(everyMs) && everyMs > 0)) {
        throw new TypeError(
          `CatalogCache: revalidate debe ser 'always' o { everyMs: número > 0 } (llegó ${JSON.stringify(revalidate)})`
        )
      }
      this.#everyMs = everyMs
    } else {
      this.#everyMs = null
    }
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_CATALOG_CACHE_TIMEOUT_MS
    this.#driver = options.driver ?? 'catalog'
    if (options.now !== undefined && typeof options.now !== 'function') {
      throw new TypeError(`CatalogCache: now debe ser una función (llegó ${typeof options.now})`)
    }
    this.#now = options.now ?? (() => performance.now())
  }

  /**
   * La foto vigente. Sin foto, o invalidada en este proceso ⇒ carga (las
   * llamadas concurrentes comparten la misma promesa: un arranque con cien
   * requests no dispara cien cargas). Con foto ⇒ se contrasta su versión
   * con la fila compartida (según `revalidate`; las comprobaciones
   * concurrentes también comparten promesa) y, si la base va por delante,
   * recarga. Una carga o comprobación que falla (503, clasificado por
   * `guardSql`) no deja nada cacheado ni servido: la siguiente pregunta
   * vuelve a intentarlo.
   */
  async view(): Promise<CatalogView> {
    const current = this.#view
    if (current && this.#isFresh()) {
      if (!this.#needsCheck()) return current
      if (!this.#checking) {
        this.#checking = this.#revalidate(current).finally(() => {
          this.#checking = null
        })
      }
      return this.#checking
    }
    return this.#reload()
  }

  /** Una carga compartida; `knownVersion` es la fila recién leída por una revalidación (se ahorra releerla). */
  #reload(knownVersion?: number): Promise<CatalogView> {
    if (!this.#loading) {
      this.#loading = this.#load(knownVersion).finally(() => {
        this.#loading = null
      })
    }
    return this.#loading
  }

  /**
   * Olvida la foto de ESTE memo. La siguiente pregunta recarga. Es un bump
   * de generación, no un `#view = null`: una carga en vuelo capturó la
   * generación anterior y su foto aterriza ya vieja (F4, CR2).
   */
  invalidate(): void {
    this.#generation += 1
  }

  /** ¿Hay una foto cargada y vigente para este proceso? (Observabilidad para tests y diagnóstico; no consulta la base.) */
  get loaded(): boolean {
    return this.#view !== null && this.#isFresh()
  }

  #isFresh(): boolean {
    return this.#version === catalogVersion && this.#loadedGeneration === this.#generation
  }

  #needsCheck(): boolean {
    if (this.#everyMs === null) return true
    return this.#now() - this.#checkedAt >= this.#everyMs
  }

  #sql(operation: string, fn: () => any): Promise<any> {
    return guardSql(this.#driver, operation, this.#timeoutMs, fn)
  }

  #readVersion(): Promise<number> {
    return readAuthzCatalogVersion({ driver: this.#driver, timeoutMs: this.#timeoutMs })
  }

  /**
   * Contrasta la foto con la fila: misma versión ⇒ se sirve; distinta ⇒
   * recarga. Si la foto cambió mientras se leía la fila (otra carga terminó
   * antes) se sirve lo que haya ahora, que ya es más nuevo.
   */
  async #revalidate(current: CatalogView): Promise<CatalogView> {
    const dbVersion = await this.#readVersion()
    if (this.#view !== current) return this.view()
    if (dbVersion === current.version && this.#isFresh()) {
      this.#checkedAt = this.#now()
      return current
    }
    return this.#reload(dbVersion)
  }

  async #load(knownVersion?: number): Promise<CatalogView> {
    // Las versiones (proceso y fila) se toman ANTES de leer las tablas: si un
    // sync aterriza durante la carga, esta foto queda marcada como vieja y
    // la siguiente pregunta recarga. Una foto mixta solo puede ser más
    // restrictiva (permisos → roles → vínculos) y dura una pregunta.
    const version = catalogVersion
    const generation = this.#generation
    const dbVersion = knownVersion ?? (await this.#readVersion())
    const permissions: Array<{ uuid: string; slug: string }> = await this.#sql('catalog.permissions', () =>
      db.from('authz_permissions').select('uuid', 'slug')
    )
    const roles: Array<{ uuid: string; slug: string; scope_type: string }> = await this.#sql('catalog.roles', () =>
      db.from('authz_roles').select('uuid', 'slug', 'scope_type')
    )
    const links: Array<{ role_uuid: string; permission_uuid: string }> = await this.#sql('catalog.links', () =>
      db.from('authz_role_permissions').select('role_uuid', 'permission_uuid')
    )
    const view = buildCatalogView(permissions, roles, links, Date.now(), dbVersion)
    this.#view = view
    this.#version = version
    this.#loadedGeneration = generation
    // La ventana se mide con el reloj monótono; `loadedAt` es de pared (informativo).
    this.#checkedAt = this.#now()
    return view
  }
}

/**
 * Clave `(slug, scopeType)` de un rol con un separador NO imprimible
 * (`\u001f`, escrito como escape a propósito: un carácter invisible en el
 * código ya costó un bug): `a:b`+`c` y `a`+`b:c` no pueden colisionar.
 */
function roleKey(slug: string, scopeType: string): string {
  return `${slug}\u001f${scopeType}`
}

function buildCatalogView(
  permissions: Array<{ uuid: string; slug: string }>,
  roles: Array<{ uuid: string; slug: string; scope_type: string }>,
  links: Array<{ role_uuid: string; permission_uuid: string }>,
  loadedAt: number,
  version: number
): CatalogView {
  const permissionBySlug = new Map<string, { uuid: string }>()
  const slugByPermissionUuid = new Map<string, string>()
  for (const p of permissions) {
    permissionBySlug.set(p.slug, Object.freeze({ uuid: p.uuid }))
    slugByPermissionUuid.set(p.uuid, p.slug)
  }

  const roleByKey = new Map<string, { uuid: string }>()
  const roleByUuid = new Map<string, { slug: string; scopeType: string }>()
  const slugsByLevel = new Map<string, Set<string>>()
  const levelsBySlug = new Map<string, Set<string>>()
  for (const r of roles) {
    roleByKey.set(roleKey(r.slug, r.scope_type), Object.freeze({ uuid: r.uuid }))
    roleByUuid.set(r.uuid, { slug: r.slug, scopeType: r.scope_type })
    if (!slugsByLevel.has(r.scope_type)) slugsByLevel.set(r.scope_type, new Set())
    slugsByLevel.get(r.scope_type)!.add(r.slug)
    if (!levelsBySlug.has(r.slug)) levelsBySlug.set(r.slug, new Set())
    levelsBySlug.get(r.slug)!.add(r.scope_type)
  }

  // Un vínculo cuyo rol o permiso no existe (FK rota fuera del sync) no
  // concede nada: se ignora, igual que lo ignoraría el join SQL.
  const grantingByPermission = new Map<string, Map<string, CatalogRoleRef[]>>()
  const permissionsByRole = new Map<string, Set<string>>()
  for (const link of links) {
    const role = roleByUuid.get(link.role_uuid)
    if (!role) continue
    const slug = slugByPermissionUuid.get(link.permission_uuid)
    if (slug !== undefined) {
      if (!permissionsByRole.has(link.role_uuid)) permissionsByRole.set(link.role_uuid, new Set())
      permissionsByRole.get(link.role_uuid)!.add(slug)
    }
    let byLevel = grantingByPermission.get(link.permission_uuid)
    if (!byLevel) {
      byLevel = new Map()
      grantingByPermission.set(link.permission_uuid, byLevel)
    }
    let list = byLevel.get(role.scopeType)
    if (!list) {
      list = []
      byLevel.set(role.scopeType, list)
    }
    list.push({ slug: role.slug, uuid: link.role_uuid })
  }

  const EMPTY_SET: Set<string> = new Set()
  const permissionSlugs = Object.freeze([...permissionBySlug.keys()])
  return {
    permission: (slug) => permissionBySlug.get(slug) ?? null,
    role: (slug, scopeType) => roleByKey.get(roleKey(slug, scopeType)) ?? null,
    // Copia por llamada: el llamante puede mutar lo que recibe sin tocar la foto.
    rolesGranting: (permissionUuid) =>
      new Map([...(grantingByPermission.get(permissionUuid) ?? new Map())].map(([k, v]) => [k, [...v]])),
    rolePermissions: (slug, scopeType) => {
      const role = roleByKey.get(roleKey(slug, scopeType))
      return new Set(role ? (permissionsByRole.get(role.uuid) ?? EMPTY_SET) : EMPTY_SET)
    },
    permissionSlug: (uuid) => slugByPermissionUuid.get(uuid) ?? null,
    roleSlugs: (scopeType) => new Set(slugsByLevel.get(scopeType) ?? EMPTY_SET),
    roleLevels: (slug) => new Set(levelsBySlug.get(slug) ?? EMPTY_SET),
    permissionSlugs,
    loadedAt,
    version,
  }
}
