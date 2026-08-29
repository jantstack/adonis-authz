import db from '@adonisjs/lucid/services/db'
import type { TransactionClientContract } from '@adonisjs/lucid/types/database'
import type { CatalogRole, CatalogRoleRef, ScopeType } from './types.js'
import { guardSql, isAuthzError, isSqlDriverError, isTimeoutLike } from './drivers/backend_guard.js'
import {
  AmbiguousRoleError,
  AuthorizationBackendError,
  AuthorizationBackendTimeoutError,
  AuthorizationConfigError,
  AuthorizationInternalError,
} from './errors.js'
import { isValidScopeType, scopeFromKey } from './identity.js'
import { systemClock } from './clock.js'
import { isSqliteDialect } from './drivers/sql_expiry.js'

export type { CatalogRole, CatalogRoleRef }

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

/** Un permiso del catálogo: su uuid y los niveles cuyos roles pueden llevarlo (`null` = cualquiera, 3B · B5). */
export interface CatalogPermission {
  uuid: string
  assignableAt: readonly ScopeType[] | null
}

/**
 * Clave de owner de los roles GLOBALES (`authz_roles.owner_scope_key`, 3B ·
 * B1): los del catálogo del config (`syncAuthzCatalog`). Reservada: ningún
 * `scopeKey()` la produce (la raíz da `app`; el resto lleva `|`).
 */
export const GLOBAL_OWNER_KEY = 'global'

/** ¿El rol cuenta en un scope cuya cadena tiene esas claves (owner global o en la cadena)? */
export function isRoleVisibleWith(role: { owner: string }, chainKeys: ReadonlySet<string> | readonly string[]): boolean {
  if (role.owner === GLOBAL_OWNER_KEY) return true
  return Array.isArray(chainKeys) ? chainKeys.includes(role.owner) : (chainKeys as ReadonlySet<string>).has(role.owner)
}

/** Foto inmutable del catálogo. Se reemplaza entera, nunca se muta. */
export interface CatalogView {
  /** `{ uuid, assignableAt }` del permiso, o `null` si el catálogo no lo declara. */
  permission(slug: string): CatalogPermission | null
  /**
   * El rol GLOBAL `(slug, scopeType)`, o `null`. Los locales no se buscan por
   * aquí: con owners, `(slug, scopeType)` ya no identifica un rol (3B); usa
   * `roleVisible` con la cadena del scope que pregunta, o `rolesNamed`.
   */
  role(slug: string, scopeType: ScopeType): CatalogRole | null
  /**
   * EL rol `(slug, scopeType)` visible desde un scope cuya cadena tiene esas
   * claves (3B · B2): el global, o el local cuyo owner está en la cadena.
   * `null` si ninguno.
   *
   * Si hay MÁS DE UNO visible LANZA 422 `E_AUTHZ_AMBIGUOUS_ROLE` (3D · M1).
   * Hasta 3C ganaba «el owner más cercano», y eso convertía un homónimo en
   * una escalada: el admin de A concedía el rol de B por el mismo slug
   * (auditor V3) y un local tapaba al global cambiándole el significado
   * (V2-B). La ambigüedad no se resuelve, se denuncia: fail-closed. La
   * unicidad se defiende al escribir (colisiones + serialización del
   * catálogo, M2), pero un árbol que se mueve puede juntar dos owners
   * legítimos y esa lectura tiene que fallar, no elegir.
   */
  roleVisible(slug: string, scopeType: ScopeType, chainKeys: readonly string[]): CatalogRole | null
  /** TODOS los roles `(slug, scopeType)`, sea cual sea su owner (para revoke, colisiones). Copia por llamada. */
  rolesNamed(slug: string, scopeType: ScopeType): CatalogRole[]
  /** El rol por uuid, o `null` si el catálogo no lo declara (un rol retirado, un id ajeno) (3A · A3). */
  roleByUuid(uuid: string): CatalogRole | null
  /**
   * Roles declarados para un nivel cuyo owner es global o está en
   * `ownerKeys` (las claves de la cadena del scope que pregunta) (3B · B2).
   * Copia por llamada.
   */
  rolesFor(scopeType: ScopeType, ownerKeys: Iterable<string>): CatalogRole[]
  /**
   * Roles LOCALES cuyo owner es exactamente esa clave (3D · M4): lo que
   * `scopes.detached` tiene que purgar para que el scope no deje roles
   * huérfanos que bloqueen su `(slug, nivel)` para siempre. Copia por llamada.
   */
  rolesOwnedBy(ownerKey: string): CatalogRole[]
  /** Roles que conceden el permiso (con su owner), agrupados por nivel (`scope_type`). Copia por llamada. */
  rolesGranting(permissionUuid: string): Map<ScopeType, CatalogRoleRef[]>
  /** Slugs de permiso que concede el rol (por uuid); vacío si el rol no existe. Copia por llamada. */
  rolePermissionsOf(roleUuid: string): Set<string>
  /** Slug del permiso por uuid, o `null` si el catálogo ya no lo declara (2.1, B5). */
  permissionSlug(uuid: string): string | null
  /** Todos los slugs de permiso. */
  readonly permissionSlugs: readonly string[]
  /** El `rank` más alto entre los roles GLOBALES (0 sin roles): el techo de la delegación (3B · B3). */
  readonly topGlobalRank: number
  /** Instante de carga (ms de pared, `systemClock`; informativo). */
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
      client.table(CATALOG_VERSION_TABLE).insert({ id: CATALOG_VERSION_ROW_ID, version: 1, updated_at: systemClock() })
    )
  } catch (error) {
    // Otro proceso sembró la fila entre el UPDATE y el INSERT: se sube la suya.
    if (Number(await update()) === 0) throw error
  }
}

/**
 * Los roles LOCALES de esos owners leídos de la BASE, en fresco, con sus
 * permisos (3E · P2, auditor A2 bis).
 *
 * `scopes.detached` decidía qué purgar con la foto del MEMO: con
 * `catalogRevalidate: { everyMs }` —config legal y documentada— un rol que
 * otro proceso acababa de confirmar no estaba en la foto y SOBREVIVÍA a la
 * desaparición de su owner, bloqueando ese `(slug, nivel)` para el catálogo
 * global para siempre. M2 ya había aprendido a releer la base dentro de la
 * transacción; M4 no.
 *
 * Queda una ventana (un `defineScopedRole` confirmado entre este SELECT y la
 * purga) que no cierra ningún cerrojo razonable: `purgeRole` abre su propia
 * transacción con el cerrojo del catálogo y leer aquí dentro de otra sería
 * un abrazo mortal con un pool de 1. Es una carrera que el tenant pierde de
 * todas formas —define un rol en un scope que se está borrando— y la
 * siguiente notificación (o `authz:reconcile`, 3b) lo recoge.
 *
 * El orden es ESTABLE por `uuid` (3F · U5, tester 3E · §4.3): sin `ORDER BY`
 * lo ponía el motor, así que la secuencia de `role_purged` que ve el hook de
 * auditoría —y el rol por el que empezaría una purga interrumpida a medias—
 * cambiaba entre PostgreSQL, MySQL y SQLite. La policy de rango se comprueba
 * sobre TODOS antes de tocar ninguno (3E · P3), así que el orden no decide
 * QUÉ se purga; decide lo que se REPRODUCE. Con uuid v7 es además el orden
 * de creación.
 */
export async function readRolesOwnedBy(
  ownerKeys: readonly string[],
  options: { timeoutMs?: number; driver?: string } = {}
): Promise<Array<{ role: CatalogRole; permissions: string[] }>> {
  const owners = [...new Set(ownerKeys)].filter((key) => key !== GLOBAL_OWNER_KEY)
  if (owners.length === 0) return []
  const timeoutMs = options.timeoutMs ?? DEFAULT_CATALOG_CACHE_TIMEOUT_MS
  const driver = options.driver ?? 'catalog'
  const rows: any[] = []
  // Por lotes: `descendantsOf` puede traer miles de owners y un `IN` de
  // 10 000 elementos es una consulta que algunos motores rechazan.
  for (let i = 0; i < owners.length; i += 500) {
    const chunk = owners.slice(i, i + 500)
    rows.push(
      ...(await guardSql(driver, 'catalog.rolesOwnedBy', timeoutMs, () =>
        db
          .from('authz_roles')
          .whereIn('owner_scope_key', chunk)
          .orderBy('uuid', 'asc')
          .select('uuid', 'slug', 'scope_type', 'rank', 'owner_scope_key')
      ))
    )
  }
  if (rows.length === 0) return []
  // Los lotes se concatenan en el orden de `owners`, así que el orden estable
  // del conjunto entero se fija aquí.
  rows.sort((a, b) => String(a.uuid).localeCompare(String(b.uuid)))
  const links: any[] = await guardSql(driver, 'catalog.rolePermissionsOwnedBy', timeoutMs, () =>
    db
      .from('authz_role_permissions')
      .join('authz_permissions', 'authz_permissions.uuid', 'authz_role_permissions.permission_uuid')
      .whereIn(
        'authz_role_permissions.role_uuid',
        rows.map((row) => String(row.uuid))
      )
      .select('authz_role_permissions.role_uuid as role_uuid', 'authz_permissions.slug as permission_slug')
  )
  const permissionsOf = new Map<string, string[]>()
  for (const link of links) {
    const list = permissionsOf.get(String(link.role_uuid)) ?? []
    list.push(String(link.permission_slug))
    permissionsOf.set(String(link.role_uuid), list)
  }
  return rows.map((row) => ({
    role: Object.freeze({
      uuid: String(row.uuid),
      slug: String(row.slug),
      scopeType: String(row.scope_type) as ScopeType,
      owner: String(row.owner_scope_key),
      rank: Number(row.rank),
    }),
    permissions: (permissionsOf.get(String(row.uuid)) ?? []).sort(),
  }))
}

/**
 * Serializa las escrituras del CATÁLOGO bloqueando la fila de
 * `authz_catalog_version` (3D · M2, auditor V2 🔴).
 *
 * La unicidad de la que depende todo el modelo de roles locales —«dentro de
 * una cadena un `(slug, nivel)` identifica un solo rol»— era un
 * *read-then-write*: cada escritor comprobaba la colisión contra SU foto del
 * memo y el unique de la base es `(slug, scope_type, owner_scope_key)`, así
 * que dos `define` con owners distintos (o un `define` contra un `sync`)
 * insertaban los dos y dejaban dos homónimos PERMANENTES. Un `SELECT … FOR
 * UPDATE` sobre `authz_roles WHERE slug=? AND scope_type=?` no lo cierra: no
 * hay filas que bloquear (en PostgreSQL no hay gap locks), que es justo el
 * caso. La fila de la versión sí existe siempre y TODA escritura de `authz_*`
 * pasa por aquí, así que bloquearla es la barrera real: los escritores del
 * catálogo van en serie y el re-chequeo de colisión dentro de la transacción
 * (leyendo la BASE, no el memo) ve lo que el anterior confirmó.
 *
 * Coste: las escrituras del catálogo son raras (un sync por despliegue, la
 * API de delegación). Los HECHOS (`grant`/`deny`/…) no pasan por aquí.
 *
 * SQLite no tiene `FOR UPDATE` y no lo necesita: sus escrituras ya se
 * serializan a nivel de base (una transacción de escritura a la vez).
 */
async function lockCatalogForWrite(
  trx: TransactionClientContract,
  options: { driver: string; timeoutMs: number }
): Promise<void> {
  // 3E · Q5: Lucid llama `better-sqlite3` a su dialecto de SQLite.
  if (isSqliteDialect(trx)) return
  await guardSql(options.driver, 'catalog.lock', options.timeoutMs, () =>
    trx.from(CATALOG_VERSION_TABLE).where('id', CATALOG_VERSION_ROW_ID).forUpdate().select('version')
  )
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
 * error sale tal cual (es tuyo) — salvo que sea un error del cliente SQL
 * (2.5-B · K12), que se clasifica como 503 igual que un fallo al abrir o
 * confirmar la transacción. NO te tragues errores de SQL dentro de `fn`: en
 * PostgreSQL la transacción queda abortada y todo lo que sigue falla; en
 * MySQL y SQLite el motor no la aborta y lo que sigue SE CONFIRMA.
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
      // Primero el cerrojo del catálogo (M2), después la escritura y, como
      // última sentencia, el bump (H2).
      await lockCatalogForWrite(trx, { driver, timeoutMs })
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
    // Lo que `fn` lanzó y es SUYO (su `Error`, un 422 del paquete) sale
    // intacto. Lo que `fn` dejó escapar del CLIENTE SQL (2.5-B · K12: en
    // PostgreSQL, tras tragarse un fallo, la transacción está abortada y el
    // siguiente UPDATE lanza `25P02` con el SQL dentro) se clasifica igual
    // que un fallo al abrir o confirmar: 503, causa conservada, sin SQL en el
    // mensaje. `fn` NO debe tragarse errores de SQL: en MySQL y SQLite el
    // motor no aborta la transacción y lo que sigue SE CONFIRMA.
    const fromConsumer = consumerError !== null && (consumerError as { error: unknown }).error === error
    if (fromConsumer && !isSqlDriverError(error)) throw error
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
    const permissions: PermissionRow[] = await this.#sql('catalog.permissions', () =>
      db.from('authz_permissions').select('uuid', 'slug', 'assignable_at')
    )
    const roles: RoleRow[] = await this.#sql('catalog.roles', () =>
      db.from('authz_roles').select('uuid', 'slug', 'scope_type', 'owner_scope_key', 'rank')
    )
    const links: Array<{ role_uuid: string; permission_uuid: string }> = await this.#sql('catalog.links', () =>
      db.from('authz_role_permissions').select('role_uuid', 'permission_uuid')
    )
    const view = buildCatalogView(permissions, roles, links, systemClock().getTime(), dbVersion)
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

interface PermissionRow {
  uuid: string
  slug: string
  assignable_at: unknown
}

interface RoleRow {
  uuid: string
  slug: string
  scope_type: string
  owner_scope_key: unknown
  rank: unknown
}

/**
 * `assignable_at` tal como viene de la base: `NULL` = cualquier nivel; si
 * no, un JSON con una lista no vacía de tipos de scope válidos. Otra cosa
 * (una edición a mano) es catálogo corrupto: 500 `E_AUTHZ_INTERNAL`, nunca
 * «cualquiera» (sería relajar una restricción en silencio) ni «ninguno»
 * disfrazado de dato.
 */
export function parseAssignableAt(slug: string, raw: unknown): readonly ScopeType[] | null {
  if (raw === null || raw === undefined) return null
  let parsed: unknown = raw
  if (typeof raw === 'string') {
    try {
      parsed = JSON.parse(raw)
    } catch {
      parsed = undefined
    }
  }
  if (!Array.isArray(parsed) || parsed.length === 0 || !parsed.every((t) => typeof t === 'string' && isValidScopeType(t))) {
    throw new AuthorizationInternalError(
      `authz_permissions.assignable_at del permiso '${slug}' no es una lista JSON no vacía de tipos de scope válidos ` +
        `(llegó ${typeof raw === 'string' ? raw : typeof raw}); corrige la fila o vuelve a sincronizar el catálogo.`
    )
  }
  return Object.freeze([...new Set(parsed as string[])])
}

/**
 * `authz_roles.owner_scope_key` tal como viene de la base: `global` o la
 * clave de un scope que NO es la raíz. Cualquier otra cosa es catálogo
 * corrupto (500 `E_AUTHZ_INTERNAL`), nunca un default silencioso.
 *
 * `'app'` en particular (3D · N3, auditor V7): la raíz está SIEMPRE en toda
 * cadena, así que un rol con ese owner sería visible en todas partes — un
 * global disfrazado que `syncAuthzCatalog` no gobierna. La API lo impide
 * (`#assertOwnerScope`); aquí se cierra la fila escrita a mano.
 */
function ownerOf(row: RoleRow): string {
  const owner = row.owner_scope_key
  const valid = typeof owner === 'string' && (owner === GLOBAL_OWNER_KEY || scopeFromKey(owner)?.uuid != null)
  if (!valid) {
    throw new AuthorizationInternalError(
      `authz_roles.owner_scope_key del rol '${row.slug}@${row.scope_type}' (${row.uuid}) no es una clave de owner ` +
        `(llegó ${typeof owner === 'string' ? `'${owner}'` : owner === null ? 'null' : typeof owner}); se espera ` +
        `'${GLOBAL_OWNER_KEY}' o '<tipo>|<uuid>' de un scope que no sea la raíz. Corrige la fila o aplica la migración 2.2.`
    )
  }
  return owner as string
}

function buildCatalogView(
  permissions: PermissionRow[],
  roles: RoleRow[],
  links: Array<{ role_uuid: string; permission_uuid: string }>,
  loadedAt: number,
  version: number
): CatalogView {
  const permissionBySlug = new Map<string, CatalogPermission>()
  const slugByPermissionUuid = new Map<string, string>()
  for (const p of permissions) {
    permissionBySlug.set(p.slug, Object.freeze({ uuid: p.uuid, assignableAt: parseAssignableAt(p.slug, p.assignable_at) }))
    slugByPermissionUuid.set(p.uuid, p.slug)
  }

  // Por `(slug, scopeType)` puede haber VARIOS roles (owners distintos, 3B):
  // la lista guarda primero el global (si lo hay) y luego los locales.
  const rolesByKey = new Map<string, CatalogRole[]>()
  const roleByUuid = new Map<string, CatalogRole>()
  const rolesByLevel = new Map<string, CatalogRole[]>()
  const rolesByOwner = new Map<string, CatalogRole[]>()
  let topGlobalRank = 0
  for (const r of roles) {
    const owner = ownerOf(r)
    const rank = Number(r.rank ?? 0)
    const role: CatalogRole = Object.freeze({
      uuid: r.uuid,
      slug: r.slug,
      scopeType: r.scope_type,
      owner,
      rank: Number.isFinite(rank) ? rank : 0,
    })
    const key = roleKey(r.slug, r.scope_type)
    if (!rolesByKey.has(key)) rolesByKey.set(key, [])
    if (owner === GLOBAL_OWNER_KEY) {
      rolesByKey.get(key)!.unshift(role)
      if (role.rank > topGlobalRank) topGlobalRank = role.rank
    } else {
      rolesByKey.get(key)!.push(role)
    }
    roleByUuid.set(r.uuid, role)
    if (!rolesByLevel.has(r.scope_type)) rolesByLevel.set(r.scope_type, [])
    rolesByLevel.get(r.scope_type)!.push(role)
    if (owner !== GLOBAL_OWNER_KEY) {
      if (!rolesByOwner.has(owner)) rolesByOwner.set(owner, [])
      rolesByOwner.get(owner)!.push(role)
    }
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
    list.push({ slug: role.slug, uuid: link.role_uuid, scopeType: role.scopeType, owner: role.owner })
  }

  const EMPTY_SET: Set<string> = new Set()
  const permissionSlugs = Object.freeze([...permissionBySlug.keys()])
  return {
    permission: (slug) => permissionBySlug.get(slug) ?? null,
    role: (slug, scopeType) => (rolesByKey.get(roleKey(slug, scopeType)) ?? []).find((r) => r.owner === GLOBAL_OWNER_KEY) ?? null,
    roleVisible: (slug, scopeType, chainKeys) => {
      const named = rolesByKey.get(roleKey(slug, scopeType))
      if (!named) return null
      const owners = new Set(chainKeys)
      const visible = named.filter((role) => isRoleVisibleWith(role, owners))
      if (visible.length === 0) return null
      if (visible.length > 1) {
        // 3D · M1: fail-closed. Se nombran uuid y owner de los que SON
        // visibles en esta cadena —y solo esos (3E · Q2): el llamante ya
        // puede verlos, así que no hay fuga de otro árbol—, que es lo que le
        // permite direccionar por `{ uuid }`.
        //
        // 3E · Q1 (auditor A5): el mensaje aconsejaba «renombra uno de
        // ellos» y la API PROHÍBE renombrar (`updateScopedRole` solo cambia
        // name/description/rank/permissions). La salida real es `{ uuid }`
        // para seguir operando y purgar uno para deshacer la ambigüedad.
        throw new AmbiguousRoleError(
          `'${slug}' (nivel '${scopeType}') es AMBIGUO aquí: hay ${visible.length} roles visibles en esta cadena ` +
            `(${visible.map((r) => `${r.uuid} owner=${r.owner}`).join('; ')}). Un slug ya no identifica un rol: ` +
            `pregunta por { uuid }, que sigue funcionando. Un rol local no se renombra: para deshacer la ambigüedad ` +
            `hay que PURGAR uno (deleteScopedRole con rank suficiente, o la plataforma con driver().purgeRole). ` +
            `authz:catalog:diff los lista (3F · S3: los ensombrecidos por autoridad NO son deriva y salen con exit 0).`
        )
      }
      return visible[0]
    },
    rolesNamed: (slug, scopeType) => [...(rolesByKey.get(roleKey(slug, scopeType)) ?? [])],
    rolesOwnedBy: (ownerKey) => [...(rolesByOwner.get(ownerKey) ?? [])],
    roleByUuid: (uuid) => roleByUuid.get(uuid) ?? null,
    rolesFor: (scopeType, ownerKeys) => {
      const owners = new Set(ownerKeys)
      return (rolesByLevel.get(scopeType) ?? []).filter((r) => isRoleVisibleWith(r, owners))
    },
    // Copia por llamada: el llamante puede mutar lo que recibe sin tocar la foto.
    rolesGranting: (permissionUuid) =>
      new Map([...(grantingByPermission.get(permissionUuid) ?? new Map())].map(([k, v]) => [k, [...v]])),
    rolePermissionsOf: (roleUuid) => new Set(permissionsByRole.get(roleUuid) ?? EMPTY_SET),
    permissionSlug: (uuid) => slugByPermissionUuid.get(uuid) ?? null,
    permissionSlugs,
    topGlobalRank,
    loadedAt,
    version,
  }
}
