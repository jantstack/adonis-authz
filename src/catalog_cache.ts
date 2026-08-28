import db from '@adonisjs/lucid/services/db'
import type { ScopeType } from './types.js'
import { guardSql } from './drivers/backend_guard.js'

/**
 * Memo del CATÁLOGO (roles, permisos y vínculos rol→permiso), y de nada más.
 *
 * El camino caliente de `authorize` consultaba `authz_*` en cada pregunta
 * (`findPermission` en ambos drivers; `rolesGranting` además en openfga)
 * para leer algo que solo cambia cuando el consumidor sincroniza su config.
 * Este memo carga las tres tablas una vez, perezosamente, y las sirve desde
 * memoria hasta que algo lo invalida. Lo que NUNCA cachea: hechos
 * (asignaciones, denies) ni decisiones — un `authorize` siempre pregunta al
 * backend de hechos; lo que se ahorra es el "¿qué uuid tiene `docs:read`?".
 *
 * Contrato de invalidación (README, "Performance"):
 *  1. `syncAuthzCatalog` (y por tanto `authz:catalog:sync`) invalida TODOS
 *     los memos del proceso al terminar, vía el contador de versión de este
 *     módulo. Un sync ve su efecto en la siguiente pregunta.
 *  2. `invalidateAuthzCatalog()` (exportada por el paquete) hace lo mismo a
 *     mano: es lo que llama un consumidor que escribe `authz_*` por fuera
 *     del sync (un seeder, una migración de datos, un script).
 *  3. `ttlMs` opcional (default sin TTL): cinturón para procesos múltiples.
 *     El sync de un proceso NO invalida el memo de otro (el contador vive en
 *     memoria): en un despliegue con varios workers, o se reinician tras el
 *     sync, o se pone un TTL y se acepta esa ventana de catálogo viejo.
 *
 * Caso negativo, fijado por test: un cambio en `authz_*` sin sync, sin
 * `invalidate` y sin TTL no se ve. Es el precio del memo y está escrito.
 *
 * Es composición: cada driver del paquete construye el suyo (o recibe uno
 * compartido en `catalog`); un driver de terceros no necesita saber que existe.
 */

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
  /** Instante de carga (`Date.now()`), base del TTL. */
  readonly loadedAt: number
}

/**
 * Versión del catálogo en ESTE proceso. La sube `syncAuthzCatalog` al
 * terminar e `invalidateAuthzCatalog()`; cada memo recuerda con qué versión
 * cargó y se recarga si difiere. No hay suscriptores ni emisores: un entero
 * es lo mínimo que resuelve "el sync invalida a todos los drivers".
 */
let catalogVersion = 0

/**
 * Invalida todos los memos del catálogo de este proceso. Llámala tras
 * escribir `authz_*` sin pasar por `syncAuthzCatalog`. En otro proceso no
 * hace nada: ver `ttlMs`.
 */
export function invalidateAuthzCatalog(): void {
  catalogVersion += 1
}

/** Deadline de cada consulta de carga (el mismo default que el catálogo). */
export const DEFAULT_CATALOG_CACHE_TIMEOUT_MS = 5_000

export interface CatalogCacheOptions {
  /**
   * Caducidad del memo en ms. Sin ella (default) solo invalidan el sync y
   * `invalidate`. Ponla en despliegues multi-proceso donde el sync corre en
   * un worker y los demás no se reinician.
   */
  ttlMs?: number
  /** Deadline de cada consulta de carga (default 5000): vencido ⇒ 503. */
  timeoutMs?: number
  /** Etiqueta del driver en los errores 503 (default `catalog`). */
  driver?: string
}

export class CatalogCache {
  #view: CatalogView | null = null
  #version = -1
  #loading: Promise<CatalogView> | null = null
  readonly #ttlMs: number | null
  readonly #timeoutMs: number
  readonly #driver: string

  constructor(options: CatalogCacheOptions = {}) {
    if (options.ttlMs !== undefined && !(Number.isFinite(options.ttlMs) && options.ttlMs > 0)) {
      throw new TypeError(`CatalogCache: ttlMs debe ser un número > 0 (llegó ${String(options.ttlMs)})`)
    }
    this.#ttlMs = options.ttlMs ?? null
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_CATALOG_CACHE_TIMEOUT_MS
    this.#driver = options.driver ?? 'catalog'
  }

  /**
   * La foto vigente, cargándola si no hay o si caducó (versión o TTL). Las
   * llamadas concurrentes durante una carga comparten la misma promesa: un
   * arranque con cien requests no dispara cien cargas. Una carga que falla
   * (503, clasificado por `guardSql`) no deja nada cacheado: la siguiente
   * pregunta vuelve a intentarlo.
   */
  async view(): Promise<CatalogView> {
    if (this.#view && this.#isFresh(this.#view)) return this.#view
    if (!this.#loading) {
      this.#loading = this.#load().finally(() => {
        this.#loading = null
      })
    }
    return this.#loading
  }

  /** Olvida la foto de ESTE memo. La siguiente pregunta recarga. */
  invalidate(): void {
    this.#view = null
  }

  /** ¿Hay una foto cargada y vigente? (Observabilidad para tests y diagnóstico.) */
  get loaded(): boolean {
    return this.#view !== null && this.#isFresh(this.#view)
  }

  #isFresh(view: CatalogView): boolean {
    if (this.#version !== catalogVersion) return false
    if (this.#ttlMs !== null && Date.now() - view.loadedAt >= this.#ttlMs) return false
    return true
  }

  async #load(): Promise<CatalogView> {
    // La versión se toma ANTES de leer: si un sync aterriza durante la carga,
    // esta foto queda marcada como vieja y la siguiente pregunta recarga.
    const version = catalogVersion
    const sql = (operation: string, fn: () => any): Promise<any> =>
      guardSql(this.#driver, operation, this.#timeoutMs, fn)
    const permissions: Array<{ uuid: string; slug: string }> = await sql('catalog.permissions', () =>
      db.from('authz_permissions').select('uuid', 'slug')
    )
    const roles: Array<{ uuid: string; slug: string; scope_type: string }> = await sql('catalog.roles', () =>
      db.from('authz_roles').select('uuid', 'slug', 'scope_type')
    )
    const links: Array<{ role_uuid: string; permission_uuid: string }> = await sql('catalog.links', () =>
      db.from('authz_role_permissions').select('role_uuid', 'permission_uuid')
    )
    const view = buildCatalogView(permissions, roles, links, Date.now())
    this.#view = view
    this.#version = version
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
  loadedAt: number
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
  }
}
