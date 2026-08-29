import db from '@adonisjs/lucid/services/db'
import { v7 as uuidv7 } from 'uuid'
import type { CatalogSpec, ScopeType } from './types.js'
import { assertNoSlugCollisions, assertScopeType, assertValidSlug } from './identity.js'
import { CatalogConflictError, UnknownPermissionError } from './errors.js'
import { guardSql } from './drivers/backend_guard.js'
import { invalidateAuthzCatalog, withAuthzCatalogWrite } from './catalog_cache.js'
import { systemClock } from './clock.js'

/** Deadline de cada consulta del catálogo (D15); configurable por `timeoutMs`. */
export const DEFAULT_CATALOG_TIMEOUT_MS = 5_000

export interface SyncCatalogOptions {
  /**
   * Qué hacer con los vínculos rol→permiso que el spec YA NO lista, para los
   * roles DEL SPEC (L0.9). `'links'` (default): se eliminan en la misma
   * transacción. `'none'`: sync solo aditivo (el comportamiento de 1.x).
   * Nunca se borran roles ni permisos, y los roles ajenos al spec no se
   * tocan: dos catálogos (plataforma y tenant) coexisten.
   */
  prune?: 'links' | 'none'
  /**
   * Deadline de cada consulta en ms (default 5000). La base caída o lenta
   * es 503 `E_AUTHZ_BACKEND_UNAVAILABLE`/`_TIMEOUT`, no un error crudo del
   * cliente SQL: el sync corre en el arranque de un despliegue (D15).
   */
  timeoutMs?: number
}

/**
 * Valida la gramática del catálogo entero ANTES de tocar la base: formato,
 * longitud publicable en FGA, reservados, familias de prefijos y colisiones
 * tras codificar (`docs:write` / `docs_write`). Un catálogo inválido no
 * escribe nada.
 */
function assertCatalogGrammar(catalog: CatalogSpec): void {
  for (const perm of catalog.permissions) assertValidSlug('permiso', perm.slug)
  for (const role of catalog.roles) {
    assertValidSlug('rol', role.slug)
    // El nivel del rol es identidad de scope (minúsculas, ≤ 20, sin
    // separadores): lo que no pase aquí no puede llegar a `scope_type` (E4).
    assertScopeType(role.scopeType)
    for (const slug of role.permissions) assertValidSlug('permiso', slug)
  }
  assertNoSlugCollisions(
    'permiso',
    catalog.permissions.map((p) => p.slug)
  )
  assertNoSlugCollisions(
    'rol',
    catalog.roles.map((r) => r.slug)
  )
}

/**
 * Sincroniza un catálogo (roles + permisos + vínculos) a las tablas `authz_*`.
 *
 * Idempotente y transaccional. Permisos y roles se crean si faltan (nunca se
 * borran: la limpieza de un rol o permiso retirado es una decisión explícita
 * del consumidor, porque arrastra asignaciones). Los vínculos rol→permiso
 * son la excepción: con `prune: 'links'` (default) el spec MANDA sobre los
 * roles que declara. Antes el sync era solo aditivo y quitar un permiso de
 * un rol en el config no lo quitaba de ningún entorno — la única fuente de
 * verdad visible mentía sobre los permisos efectivos (L0.9, N1).
 *
 * Un rol que concede un permiso que no existe ni en este spec ni en la base
 * (sincronizado por otro catálogo) es 422 `E_AUTHZ_UNKNOWN_PERMISSION`:
 * antes se saltaba en silencio.
 *
 * Lo usan el seeder del nivel app, `authz:catalog:sync` y el harness de la
 * suite de contrato. El catálogo es metadata compartida entre drivers: un
 * driver externo (openfga) materializa aparte solo los hechos.
 */
export async function syncAuthzCatalog(
  catalog: CatalogSpec,
  options: SyncCatalogOptions = {}
): Promise<void> {
  assertCatalogGrammar(catalog)
  const prune = options.prune ?? 'links'
  const timeoutMs = options.timeoutMs ?? DEFAULT_CATALOG_TIMEOUT_MS
  // Cada consulta con deadline y fallo clasificado (D15). `fn` devuelve el
  // builder sin ejecutar (nada de `.first()`, que ejecuta al instante).
  const sql = (operation: string, fn: () => any): Promise<any> => guardSql('catalog', operation, timeoutMs, fn)
  const one = async (operation: string, fn: () => any): Promise<any | null> =>
    (await sql(operation, () => fn().limit(1)))[0] ?? null

  // Todo o nada. Un fallo a mitad (una constraint, la conexión) dejaba el
  // catálogo escrito a medias: roles sin sus permisos, es decir holders que
  // "tienen" un rol que no concede nada. El guard exterior clasifica lo que
  // falle al abrir o confirmar la transacción.
  //
  // La versión compartida (`authz_catalog_version`) sube DENTRO de la
  // transacción y como su ÚLTIMA sentencia (2D · F1, 2E · H2), por el mismo
  // camino que cualquier escritura a mano: `withAuthzCatalogWrite`. Los memos
  // de todos los procesos la contrastan antes de servir y recargan. Al salir
  // —bien o mal— se invalida además el memo de este proceso (2A): un sync
  // que confirmó tiene que verse en la siguiente pregunta también con
  // `everyMs`, y uno que falló al confirmar no se sabe si confirmó. Recargar
  // de más es gratis; servir un catálogo viejo no.
  try {
    await syncInTransaction(catalog, prune, sql, one, timeoutMs)
  } finally {
    invalidateAuthzCatalog()
  }
}

async function syncInTransaction(
  catalog: CatalogSpec,
  prune: 'links' | 'none',
  sql: (operation: string, fn: () => any) => Promise<any>,
  one: (operation: string, fn: () => any) => Promise<any | null>,
  timeoutMs: number
): Promise<void> {
  await sql('sync', () =>
    withAuthzCatalogWrite(async (trx) => {
      // 0. Colisión tras codificar también contra lo que YA hay en la base:
      //    `docs:write` de otro catálogo y `docs_write` de este serían UNA
      //    relación FGA (D3). Dentro de la transacción, para verlo consistente.
      const stored = await sql('sync.permissions', () => trx.from('authz_permissions').select('slug'))
      assertNoSlugCollisions('permiso', [
        ...catalog.permissions.map((p) => p.slug),
        ...stored.map((p: any) => p.slug as string),
      ])

      // 1. Permisos: upsert por slug.
      for (const perm of catalog.permissions) {
        const existing = await one('sync.permission', () =>
          trx.from('authz_permissions').where('slug', perm.slug).select('uuid')
        )
        if (existing) continue
        await sql('sync.permission.insert', () =>
          trx.table('authz_permissions').insert({
            uuid: uuidv7(),
            slug: perm.slug,
            description: perm.description ?? null,
            created_at: systemClock(),
            updated_at: systemClock(),
          })
        )
      }

      // Los permisos que los roles referencian, estén en este spec o vengan de
      // otro catálogo ya sincronizado.
      const referenced = new Set<string>(catalog.permissions.map((p) => p.slug))
      for (const role of catalog.roles) for (const slug of role.permissions) referenced.add(slug)
      const dbPerms = await sql('sync.referenced', () =>
        trx
          .from('authz_permissions')
          .whereIn('slug', [...referenced])
          .select('uuid', 'slug')
      )
      const permUuidBySlug = new Map<string, string>(dbPerms.map((p: any) => [p.slug, p.uuid]))
      for (const role of catalog.roles) {
        for (const slug of role.permissions) {
          if (!permUuidBySlug.has(slug)) throw new UnknownPermissionError(slug)
        }
      }

      // 2. Roles: upsert por (slug, scope_type).
      for (const role of catalog.roles) {
        const existing = await one('sync.role', () =>
          trx
            .from('authz_roles')
            .where('slug', role.slug)
            .where('scope_type', role.scopeType)
            .select('uuid', 'rank')
        )

        const roleUuid = existing?.uuid ?? role.uuid ?? uuidv7()
        if (!existing) {
          await sql('sync.role.insert', () =>
            trx.table('authz_roles').insert({
              uuid: roleUuid,
              slug: role.slug,
              name: role.name ?? role.slug,
              description: role.description ?? null,
              scope_type: role.scopeType,
              rank: role.rank ?? 0,
              created_at: systemClock(),
              updated_at: systemClock(),
            })
          )
        } else if (role.rank !== undefined && existing.rank !== role.rank) {
          // El rank es metadata de policy: el config manda.
          await sql('sync.role.rank', () =>
            trx.from('authz_roles').where('uuid', roleUuid).update({ rank: role.rank })
          )
        }

        // 3. Vínculos rol→permiso: el spec manda para ESTE rol.
        const wanted = new Set(role.permissions.map((slug) => permUuidBySlug.get(slug)!))
        const current = await sql('sync.links', () =>
          trx.from('authz_role_permissions').where('role_uuid', roleUuid).select('uuid', 'permission_uuid')
        )
        const linked = new Set<string>(current.map((l: any) => l.permission_uuid))

        for (const permUuid of wanted) {
          if (linked.has(permUuid)) continue
          await sql('sync.link.insert', () =>
            trx.table('authz_role_permissions').insert({
              uuid: uuidv7(),
              role_uuid: roleUuid,
              permission_uuid: permUuid,
              created_at: systemClock(),
            })
          )
        }

        if (prune === 'links') {
          const stale = current.filter((l: any) => !wanted.has(l.permission_uuid))
          if (stale.length) {
            await sql('sync.link.prune', () =>
              trx
                .from('authz_role_permissions')
                .whereIn(
                  'uuid',
                  stale.map((l: any) => l.uuid)
                )
                .delete()
            )
          }
        }
      }

      // 4. La versión compartida la sube `withAuthzCatalogWrite` al salir de
      //    aquí, como última sentencia: o se confirma todo (catálogo nuevo +
      //    versión nueva) o nada.
    }, { driver: 'catalog', timeoutMs })
  )
}

/* ── Diff (lo que hace `authz:catalog:diff`) ────────────────────────────── */

export interface CatalogLinkRef {
  role: string
  scopeType: ScopeType
  permission: string
}

export interface CatalogDiff {
  /** Permisos del spec que no existen en la base. */
  missingPermissions: string[]
  /** Roles del spec que no existen en la base. */
  missingRoles: Array<{ slug: string; scopeType: ScopeType }>
  /** Vínculos que el spec declara y la base no tiene. */
  missingLinks: CatalogLinkRef[]
  /** Vínculos que la base tiene, en roles DEL SPEC, y el spec ya no lista (privilegio zombi). */
  extraLinks: CatalogLinkRef[]
  /** Roles cuyo rank en la base difiere del spec. */
  rankMismatches: Array<{ role: string; scopeType: ScopeType; expected: number; actual: number }>
}

/**
 * Compara un spec con lo que hay en `authz_*`, sin escribir. Igual que el
 * sync, solo mira los roles del spec: lo ajeno (otro catálogo) no es una
 * diferencia. Un diff limpio significa que `syncAuthzCatalog(spec)` sería un
 * no-op.
 */
export async function diffAuthzCatalog(
  catalog: CatalogSpec,
  options: { timeoutMs?: number } = {}
): Promise<CatalogDiff> {
  assertCatalogGrammar(catalog)
  const timeoutMs = options.timeoutMs ?? DEFAULT_CATALOG_TIMEOUT_MS
  const sql = (operation: string, fn: () => any): Promise<any> => guardSql('catalog', operation, timeoutMs, fn)
  const diff: CatalogDiff = {
    missingPermissions: [],
    missingRoles: [],
    missingLinks: [],
    extraLinks: [],
    rankMismatches: [],
  }

  const dbPerms = await sql('diff.permissions', () => db.from('authz_permissions').select('uuid', 'slug'))
  // Lo que el sync rechazaría, el diff lo dice antes (D3).
  assertNoSlugCollisions('permiso', [
    ...catalog.permissions.map((p) => p.slug),
    ...dbPerms.map((p: any) => p.slug as string),
  ])
  const permUuidBySlug = new Map<string, string>(dbPerms.map((p: any) => [p.slug, p.uuid]))
  const permSlugByUuid = new Map<string, string>(dbPerms.map((p: any) => [p.uuid, p.slug]))
  for (const perm of catalog.permissions) {
    if (!permUuidBySlug.has(perm.slug)) diff.missingPermissions.push(perm.slug)
  }

  for (const role of catalog.roles) {
    const existing = (
      await sql('diff.role', () =>
        db
          .from('authz_roles')
          .where('slug', role.slug)
          .where('scope_type', role.scopeType)
          .select('uuid', 'rank')
          .limit(1)
      )
    )[0]
    if (!existing) {
      diff.missingRoles.push({ slug: role.slug, scopeType: role.scopeType })
      for (const permission of role.permissions) {
        diff.missingLinks.push({ role: role.slug, scopeType: role.scopeType, permission })
      }
      continue
    }
    if (role.rank !== undefined && existing.rank !== role.rank) {
      diff.rankMismatches.push({
        role: role.slug,
        scopeType: role.scopeType,
        expected: role.rank,
        actual: existing.rank,
      })
    }
    const current = await sql('diff.links', () =>
      db.from('authz_role_permissions').where('role_uuid', existing.uuid).select('permission_uuid')
    )
    const linked = new Set<string>(
      current.map((l: any) => permSlugByUuid.get(l.permission_uuid) ?? l.permission_uuid)
    )
    for (const permission of role.permissions) {
      if (!linked.has(permission)) {
        diff.missingLinks.push({ role: role.slug, scopeType: role.scopeType, permission })
      }
    }
    for (const permission of [...linked].sort()) {
      if (!role.permissions.includes(permission)) {
        diff.extraLinks.push({ role: role.slug, scopeType: role.scopeType, permission })
      }
    }
  }
  return diff
}

export function catalogInSync(diff: CatalogDiff): boolean {
  return (
    diff.missingPermissions.length === 0 &&
    diff.missingRoles.length === 0 &&
    diff.missingLinks.length === 0 &&
    diff.extraLinks.length === 0 &&
    diff.rankMismatches.length === 0
  )
}

/** Líneas legibles del diff (vacío si está en sync). */
export function formatCatalogDiff(diff: CatalogDiff): string[] {
  const lines: string[] = []
  const link = (l: CatalogLinkRef) => `${l.role}@${l.scopeType} → ${l.permission}`
  for (const slug of diff.missingPermissions) lines.push(`permiso ausente en la base: ${slug}`)
  for (const role of diff.missingRoles) lines.push(`rol ausente en la base: ${role.slug}@${role.scopeType}`)
  for (const l of diff.missingLinks) lines.push(`vínculo ausente en la base: ${link(l)}`)
  for (const l of diff.extraLinks) lines.push(`vínculo SOBRANTE en la base (privilegio zombi): ${link(l)}`)
  for (const r of diff.rankMismatches) {
    lines.push(`rank distinto: ${r.role}@${r.scopeType} spec=${r.expected} base=${r.actual}`)
  }
  return lines
}

/** Fábricas de catálogo tal como se declaran en `config.catalogs`. */
export type CatalogSource = () => Promise<CatalogSpec> | CatalogSpec

/**
 * Resuelve todos los catálogos y comprueba que ningún rol `(slug, scopeType)`
 * ni permiso aparezca en dos de ellos (422 `E_AUTHZ_CATALOG_CONFLICT`). Se
 * hace ANTES de tocar la base: el sync de un catálogo poda los vínculos de
 * los roles que declara, así que dos catálogos con el mismo rol se pisarían
 * y el último en el orden ganaría en silencio (D3). Un rol pertenece a
 * exactamente un catálogo. También valida la gramática de cada uno.
 */
async function resolveDisjointCatalogs(catalogs: CatalogSource[]): Promise<CatalogSpec[]> {
  const specs: CatalogSpec[] = []
  for (const source of catalogs) specs.push(await source())
  for (const spec of specs) assertCatalogGrammar(spec)

  const roleOwner = new Map<string, number>()
  const permissionOwner = new Map<string, number>()
  const conflicts: string[] = []
  for (const [index, spec] of specs.entries()) {
    for (const role of spec.roles) {
      const id = `${role.slug}@${role.scopeType}`
      const owner = roleOwner.get(id)
      if (owner !== undefined) conflicts.push(`rol ${id} (catálogos #${owner + 1} y #${index + 1})`)
      else roleOwner.set(id, index)
    }
    for (const perm of spec.permissions) {
      const owner = permissionOwner.get(perm.slug)
      if (owner !== undefined) {
        conflicts.push(`permiso ${perm.slug} (catálogos #${owner + 1} y #${index + 1})`)
      } else permissionOwner.set(perm.slug, index)
    }
  }
  if (conflicts.length) {
    throw new CatalogConflictError(
      `Catálogos en conflicto: ${conflicts.join('; ')}. Un rol (slug + scopeType) y un permiso ` +
        `pertenecen a exactamente un catálogo: el sync del segundo podaría los vínculos del primero.`
    )
  }
  return specs
}

/**
 * El diff de TODOS los catálogos del config. `inSync: false` ⇒ el comando
 * sale con código ≠ 0 (para CI). Separado del comando para poder probarlo
 * sin un kernel de ace.
 */
export async function runCatalogDiff(
  catalogs: CatalogSource[]
): Promise<{ inSync: boolean; lines: string[] }> {
  const lines: string[] = []
  let inSync = true
  const specs = await resolveDisjointCatalogs(catalogs)
  for (const [index, spec] of specs.entries()) {
    const diff = await diffAuthzCatalog(spec)
    if (catalogInSync(diff)) {
      lines.push(`catálogo #${index + 1}: en sync`)
      continue
    }
    inSync = false
    lines.push(`catálogo #${index + 1}: DIFERENCIAS`)
    for (const line of formatCatalogDiff(diff)) lines.push(`  ${line}`)
  }
  return { inSync, lines }
}

/** Sincroniza todos los catálogos del config, en orden (lo que hace `authz:catalog:sync`). */
export async function syncCatalogs(
  catalogs: CatalogSource[],
  options: SyncCatalogOptions = {}
): Promise<number> {
  let count = 0
  for (const spec of await resolveDisjointCatalogs(catalogs)) {
    await syncAuthzCatalog(spec, options)
    count += 1
  }
  return count
}
