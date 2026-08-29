import db from '@adonisjs/lucid/services/db'
import { v7 as uuidv7 } from 'uuid'
import type { CatalogSpec, ScopeType } from './types.js'
import { assertCatalogUuid, assertNoSlugCollisions, assertScopeType, assertValidSlug } from './identity.js'
import { CatalogConflictError, InvalidIdentityError, RoleNotAssignableAtError, UnknownPermissionError } from './errors.js'
import { guardSql } from './drivers/backend_guard.js'
import { GLOBAL_OWNER_KEY, invalidateAuthzCatalog, parseAssignableAt, withAuthzCatalogWrite } from './catalog_cache.js'
import { systemClock } from './clock.js'

/**
 * `assignableAt` de un permiso tal como se GUARDA (`authz_permissions.assignable_at`):
 * JSON ordenado y sin duplicados, o `null` = cualquier nivel. Ordenado para
 * que dos specs equivalentes sean la misma cadena (el sync compara texto).
 */
export function encodeAssignableAt(levels: ScopeType[] | undefined): string | null {
  if (levels === undefined) return null
  return JSON.stringify([...new Set(levels)].sort())
}

/** Un rol de nivel `scopeType` que lleva `permission` con esos `levels` (o `null`): legal, o 422 `E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT`. */
export function assertAssignableAt(
  role: { slug: string; scopeType: ScopeType },
  permission: string,
  levels: readonly ScopeType[] | null
): void {
  if (levels && !levels.includes(role.scopeType)) {
    throw new RoleNotAssignableAtError(
      `El rol '${role.slug}' (nivel '${role.scopeType}') no puede llevar '${permission}': solo pueden llevarlo roles de ` +
        `${levels.join(', ')} (assignableAt). Es un control de composición del catálogo, no de evaluación.`
    )
  }
}

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
  const levelsBySlug = new Map<string, readonly ScopeType[] | null>()
  for (const perm of catalog.permissions) {
    assertValidSlug('permiso', perm.slug)
    // `assignableAt` (3B · B5): omitido = cualquier nivel; si viene, una
    // lista no vacía de tipos de scope válidos (mismo formato que un
    // `scope_type`). `[]` sería «ningún rol puede llevarlo»: un permiso
    // muerto disfrazado de restricción, se rechaza.
    if (perm.assignableAt !== undefined) {
      if (!Array.isArray(perm.assignableAt) || perm.assignableAt.length === 0) {
        throw new InvalidIdentityError(
          `assignableAt del permiso '${perm.slug}' inválido: se esperaba una lista no vacía de tipos de scope (u omitirlo) y llegó ` +
            `${Array.isArray(perm.assignableAt) ? '[]' : typeof perm.assignableAt}`
        )
      }
      for (const level of perm.assignableAt) assertScopeType(level)
    }
    levelsBySlug.set(perm.slug, perm.assignableAt ? Object.freeze([...perm.assignableAt]) : null)
  }
  for (const role of catalog.roles) {
    assertValidSlug('rol', role.slug)
    // El nivel del rol es identidad de scope (minúsculas, ≤ 20, sin
    // separadores): lo que no pase aquí no puede llegar a `scope_type` (E4).
    assertScopeType(role.scopeType)
    // El uuid fijo del spec es la identidad del rol en ambos drivers y viaja
    // en los ids de binding de FGA (3A · A1): canónico y en minúsculas, o 422.
    if (role.uuid !== undefined) assertCatalogUuid(`rol '${role.slug}'`, role.uuid)
    for (const slug of role.permissions) {
      assertValidSlug('permiso', slug)
      // Composición dentro del spec (B5); los permisos de OTRO catálogo se
      // contrastan con la base dentro de la transacción.
      assertAssignableAt(role, slug, levelsBySlug.get(slug) ?? null)
    }
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

      // 1. Permisos: upsert por slug; `assignable_at` manda el config (B5).
      for (const perm of catalog.permissions) {
        const existing = await one('sync.permission', () =>
          trx.from('authz_permissions').where('slug', perm.slug).select('uuid', 'assignable_at')
        )
        const assignableAt = encodeAssignableAt(perm.assignableAt)
        if (existing) {
          if ((existing.assignable_at ?? null) !== assignableAt) {
            await sql('sync.permission.levels', () =>
              trx.from('authz_permissions').where('uuid', existing.uuid).update({ assignable_at: assignableAt, updated_at: systemClock() })
            )
          }
          continue
        }
        await sql('sync.permission.insert', () =>
          trx.table('authz_permissions').insert({
            uuid: uuidv7(),
            slug: perm.slug,
            description: perm.description ?? null,
            assignable_at: assignableAt,
            created_at: systemClock(),
            updated_at: systemClock(),
          })
        )
      }

      // Los permisos que los roles referencian, estén en este spec o vengan de
      // otro catálogo ya sincronizado — con sus niveles (B5): un rol de este
      // spec tampoco puede llevar un permiso ajeno fuera de su nivel.
      const referenced = new Set<string>(catalog.permissions.map((p) => p.slug))
      for (const role of catalog.roles) for (const slug of role.permissions) referenced.add(slug)
      const dbPerms = await sql('sync.referenced', () =>
        trx
          .from('authz_permissions')
          .whereIn('slug', [...referenced])
          .select('uuid', 'slug', 'assignable_at')
      )
      const permUuidBySlug = new Map<string, string>(dbPerms.map((p: any) => [p.slug, p.uuid]))
      const levelsBySlug = new Map<string, readonly ScopeType[] | null>(
        dbPerms.map((p: any) => [p.slug, parseAssignableAt(p.slug, p.assignable_at)])
      )
      for (const role of catalog.roles) {
        for (const slug of role.permissions) {
          if (!permUuidBySlug.has(slug)) throw new UnknownPermissionError(slug)
          assertAssignableAt(role, slug, levelsBySlug.get(slug) ?? null)
        }
      }

      // 2. Roles: upsert por (slug, scope_type) entre los GLOBALES (3B · B6).
      //    Un rol LOCAL con ese (slug, scope_type) es una colisión: el spec
      //    no puede ocupar un nombre que un tenant ya usa (dentro de ese
      //    tenant habría dos roles con el mismo nombre) — 422, nada escrito.
      for (const role of catalog.roles) {
        const locals = await sql('sync.role.locals', () =>
          trx
            .from('authz_roles')
            .where('slug', role.slug)
            .where('scope_type', role.scopeType)
            .whereNot('owner_scope_key', GLOBAL_OWNER_KEY)
            .select('owner_scope_key')
        )
        if (locals.length) {
          throw new CatalogConflictError(
            `El rol ${role.slug}@${role.scopeType} del spec colisiona con un rol LOCAL del mismo nombre ` +
              `(owner ${locals.map((l: any) => l.owner_scope_key).join(', ')}). Un rol global no puede ocupar un nombre ` +
              `que un scope ya definió con defineScopedRole; elige otro slug o purga el local (deleteScopedRole).`
          )
        }
        const existing = await one('sync.role', () =>
          trx
            .from('authz_roles')
            .where('slug', role.slug)
            .where('scope_type', role.scopeType)
            .where('owner_scope_key', GLOBAL_OWNER_KEY)
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
              owner_scope_key: GLOBAL_OWNER_KEY,
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
  /** Permisos del spec cuyo `assignableAt` en la base difiere (3B · B5): `null` = cualquier nivel. */
  assignableAtMismatches: Array<{ permission: string; expected: ScopeType[] | null; actual: ScopeType[] | null }>
  /**
   * Roles LOCALES (3B): propios de un scope, definidos con `defineScopedRole`.
   * Informativo: no son sobrantes ni faltantes (el spec solo declara
   * globales) y no afectan a `catalogInSync`.
   */
  scopedRoles: Array<{ slug: string; scopeType: ScopeType; owner: string }>
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
    assignableAtMismatches: [],
    scopedRoles: [],
  }

  const dbPerms = await sql('diff.permissions', () => db.from('authz_permissions').select('uuid', 'slug', 'assignable_at'))
  // Lo que el sync rechazaría, el diff lo dice antes (D3).
  assertNoSlugCollisions('permiso', [
    ...catalog.permissions.map((p) => p.slug),
    ...dbPerms.map((p: any) => p.slug as string),
  ])
  const permUuidBySlug = new Map<string, string>(dbPerms.map((p: any) => [p.slug, p.uuid]))
  const permSlugByUuid = new Map<string, string>(dbPerms.map((p: any) => [p.uuid, p.slug]))
  const levelsBySlug = new Map<string, readonly ScopeType[] | null>(
    dbPerms.map((p: any) => [p.slug, parseAssignableAt(p.slug, p.assignable_at)])
  )
  for (const perm of catalog.permissions) {
    if (!permUuidBySlug.has(perm.slug)) {
      diff.missingPermissions.push(perm.slug)
      continue
    }
    const expected = encodeAssignableAt(perm.assignableAt)
    const actual = levelsBySlug.get(perm.slug) ?? null
    if (expected !== encodeAssignableAt(actual ? [...actual] : undefined)) {
      diff.assignableAtMismatches.push({
        permission: perm.slug,
        expected: expected ? (JSON.parse(expected) as ScopeType[]) : null,
        actual: actual ? [...actual].sort() : null,
      })
    }
  }
  // Un rol del spec que lleve un permiso de OTRO catálogo fuera de su nivel:
  // el sync lo rechazaría (B5), el diff lo dice antes.
  for (const role of catalog.roles) {
    for (const slug of role.permissions) {
      if (!catalog.permissions.some((p) => p.slug === slug)) assertAssignableAt(role, slug, levelsBySlug.get(slug) ?? null)
    }
  }

  // Roles locales (3B): se listan como propios de un scope; y un global del
  // spec con el nombre de uno de ellos es la misma colisión que en el sync.
  const locals = await sql('diff.locals', () =>
    db.from('authz_roles').whereNot('owner_scope_key', GLOBAL_OWNER_KEY).select('slug', 'scope_type', 'owner_scope_key')
  )
  for (const local of locals) {
    diff.scopedRoles.push({ slug: local.slug, scopeType: local.scope_type, owner: local.owner_scope_key })
    const clash = catalog.roles.find((r) => r.slug === local.slug && r.scopeType === local.scope_type)
    if (clash) {
      throw new CatalogConflictError(
        `El rol ${clash.slug}@${clash.scopeType} del spec colisiona con un rol LOCAL del mismo nombre (owner ${local.owner_scope_key}); ` +
          `el sync lo rechazaría. Elige otro slug o purga el local (deleteScopedRole).`
      )
    }
  }

  for (const role of catalog.roles) {
    const existing = (
      await sql('diff.role', () =>
        db
          .from('authz_roles')
          .where('slug', role.slug)
          .where('scope_type', role.scopeType)
          .where('owner_scope_key', GLOBAL_OWNER_KEY)
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
    diff.rankMismatches.length === 0 &&
    diff.assignableAtMismatches.length === 0
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
  const levels = (l: ScopeType[] | null) => (l ? l.join(',') : 'cualquiera')
  for (const a of diff.assignableAtMismatches) {
    lines.push(`assignableAt distinto: ${a.permission} spec=${levels(a.expected)} base=${levels(a.actual)}`)
  }
  return lines
}

/** Líneas informativas del diff (no son diferencias): los roles locales, propios de un scope. */
export function formatScopedRoles(diff: CatalogDiff): string[] {
  return diff.scopedRoles.map((r) => `rol local (propio de ${r.owner}): ${r.slug}@${r.scopeType}`)
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
  // Los roles locales (3B) se informan una vez: no son deriva del config.
  const scoped = specs.length ? formatScopedRoles(await diffAuthzCatalog(specs[0])) : []
  for (const line of scoped) lines.push(`  ${line}`)
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
