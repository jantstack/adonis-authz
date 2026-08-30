import db from '@adonisjs/lucid/services/db'
import { v7 as uuidv7 } from 'uuid'
import type { CatalogRoleRef, CatalogSpec, ScopeChainResolver, ScopeType } from './types.js'
import { assertCatalogUuid, assertNoSlugCollisions, assertScopeType, assertValidSlug, scopeFromKey, scopeKey } from './identity.js'
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

/**
 * `assignable_at` tal como está EN LA BASE, normalizado a la forma en la que
 * el spec lo codifica (3D · N5): es lo que permite que el sync y el diff
 * comparen lo mismo. Hasta aquí el sync comparaba la cadena cruda y el diff
 * la lista parseada, así que un valor desordenado a mano (`["unit","app"]`)
 * salía «en sync» y el sync lo reescribía. Un valor CORRUPTO no lanza aquí:
 * cuenta como distinto, para que el sync lo repare en vez de atragantarse
 * (leerlo sí es 500, `parseAssignableAt`).
 */
export function storedAssignableAt(slug: string, raw: unknown): string | null {
  try {
    const parsed = parseAssignableAt(slug, raw)
    return encodeAssignableAt(parsed ? [...parsed] : undefined)
  } catch {
    return CORRUPT_ASSIGNABLE_AT
  }
}

/** Marca de `storedAssignableAt` para una fila que no se puede leer (3D · N5). */
export const CORRUPT_ASSIGNABLE_AT = '\u0000corrupto'

/**
 * `assignable_at` de la base para el DIFF (3E · P5): una fila corrupta vale
 * `null` (cualquier nivel) en vez de 500. El diff EXISTE para reportar filas
 * así —`storedAssignableAt` ya las cuenta como distintas— y hasta 3E se
 * atragantaba con `parseAssignableAt`: el comando moría con 500 justo en el
 * despliegue que iba a repararlo. Leerlo para DECIDIR sigue siendo 500
 * (`parseAssignableAt`, el memo).
 */
function tolerantAssignableAt(slug: string, raw: unknown): readonly ScopeType[] | null {
  try {
    return parseAssignableAt(slug, raw)
  } catch {
    return null
  }
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

/**
 * Longitud de `authz_permissions.assignable_at` (`varchar(500)` en el stub y
 * en el espejo). El JSON codificado tiene que caber (3D · N3).
 */
export const ASSIGNABLE_AT_MAX = 500

/** Deadline de cada consulta del catálogo (D15); configurable por `timeoutMs`. */
export const DEFAULT_CATALOG_TIMEOUT_MS = 5_000

/**
 * Lo que un `syncAuthzCatalog` deja DICHO (3E · P1 b / P6). El sync del
 * despliegue es todo-o-nada para lo que ESCRIBE, pero no puede abortar por
 * lo que un tenant hizo en su scope: hasta 3E, un rol local homónimo tumbaba
 * el catálogo entero de la plataforma (auditor A1: el actor de menor
 * privilegio del sistema paraba el deploy). La política es **reportar y
 * seguir**, nunca romper en silencio: se escribe el global —los globales
 * ganan— y aquí queda quién se ve afectado.
 */
export interface CatalogSyncReport {
  /**
   * Roles LOCALES cuyo `(slug, nivel)` acaba de ocupar un rol GLOBAL del
   * spec (3E · P1 b). El global manda; el local sigue en la base pero desde
   * ya toda ruta por slug en su cadena es 422 `E_AUTHZ_AMBIGUOUS_ROLE` (M1,
   * fail-closed): su tenant tiene que direccionar por `{ uuid }` o pedir que
   * lo purguen. `authz:catalog:diff` los lista y sale con código ≠ 0.
   */
  shadowedByGlobal: CatalogRoleRef[]
  /**
   * Vínculos rol→permiso que YA existían y que el `assignableAt` nuevo del
   * config ya no admite (3E · P6): estrechar `assignableAt` no revalidaba
   * los roles que ya llevaban el permiso —ni el diff los mencionaba—, así
   * que la restricción entraba a medias y en silencio. No se borran (lo
   * asignado sigue concediendo, invariante 1): se reportan para que el
   * operador decida (`updateScopedRole`, `deleteScopedRole` o ampliar el
   * `assignableAt`).
   */
  assignableAtViolations: Array<{ role: CatalogRoleRef; permission: string }>
}

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
      // 3D · N3 (auditor V7): `authz_permissions.assignable_at` es
      // `varchar(500)`. Un JSON que no cabe se trunca en un MySQL no
      // estricto y `parseAssignableAt` respondería 500 en CADA `view()` —un
      // corte de servicio total por un dato de config—. Se rechaza al
      // escribir, que es donde el operador puede arreglarlo.
      const encoded = encodeAssignableAt([...perm.assignableAt])!
      if (encoded.length > ASSIGNABLE_AT_MAX) {
        throw new InvalidIdentityError(
          `assignableAt del permiso '${perm.slug}' no cabe en authz_permissions.assignable_at ` +
            `(${encoded.length} caracteres, máximo ${ASSIGNABLE_AT_MAX}): declara menos niveles o nombres más cortos.`
        )
      }
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
): Promise<CatalogSyncReport> {
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
    return await syncInTransaction(catalog, prune, sql, one, timeoutMs)
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
): Promise<CatalogSyncReport> {
  const report: CatalogSyncReport = { shadowedByGlobal: [], assignableAtViolations: [] }
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
          if (storedAssignableAt(perm.slug, existing.assignable_at) !== assignableAt) {
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
      // 3E · P1 b (auditor A1): un rol LOCAL homónimo ya NO aborta el catálogo
      // entero. Un tenant con rank 2 tumbaba el despliegue de la plataforma
      // para siempre —y con él roles nuevos que no tenían nada que ver—. Los
      // globales GANAN: se escribe el global, el local afectado se REPORTA
      // (`shadowedByGlobal`) y el perjuicio queda en quien ocupó el nombre:
      // con M1 la ambigüedad es fail-closed, así que sus rutas por slug pasan
      // a 422 y le queda `{ uuid }` o pedir la purga. `defineScopedRole`
      // sigue rechazando las colisiones hacia ARRIBA (3F · S3), y hacia
      // ABAJO ensombrecer exige superar en RANGO al ensombrecido (3G · W3):
      // la autoridad no es solo posición en el árbol.
      //
      // En UNA consulta, no una por rol (3F · T2, auditor N6): esto corre con
      // el cerrojo de `authz_catalog_version` sostenido, y un deploy con
      // cientos de roles alargaba la sección crítica hasta hacer probable el
      // 503 `E_AUTHZ_BACKEND_TIMEOUT` de los `defineScopedRole` concurrentes.
      const localesHomonimas = catalog.roles.length
        ? await sql('sync.role.locals', () =>
            trx
              .from('authz_roles')
              .whereIn('slug', [...new Set(catalog.roles.map((r) => r.slug))])
              .whereNot('owner_scope_key', GLOBAL_OWNER_KEY)
              .select('uuid', 'slug', 'scope_type', 'owner_scope_key')
          )
        : []
      for (const role of catalog.roles) {
        const locals = localesHomonimas.filter(
          (row: any) => row.slug === role.slug && String(row.scope_type) === role.scopeType
        )
        for (const local of locals) {
          report.shadowedByGlobal.push({
            uuid: String(local.uuid),
            slug: role.slug,
            scopeType: role.scopeType,
            owner: String(local.owner_scope_key),
          })
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

      // 3.5 Revalidación de composición contra el `assignableAt` que acaba
      //     de mandar el config (3E · P6): los roles DEL SPEC ya se validan
      //     arriba (un spec incoherente consigo mismo es 422 y no escribe
      //     nada), pero los que ya estaban —LOCALES de los tenants y
      //     globales de otro catálogo— llevaban el permiso desde antes y
      //     nadie los miraba: estrechar `assignableAt` entraba a medias y en
      //     silencio. No se les quita el vínculo (lo asignado sigue
      //     concediendo, invariante 1): se REPORTAN, como `shadowedByGlobal`.
      const limited = catalog.permissions.filter((p) => p.assignableAt)
      if (limited.length) {
        const levelsOf = new Map<string, ReadonlySet<ScopeType>>(
          limited.map((p) => [p.slug, new Set(p.assignableAt!)])
        )
        const links = await sql('sync.revalidate', () =>
          trx
            .from('authz_role_permissions')
            .join('authz_roles', 'authz_roles.uuid', 'authz_role_permissions.role_uuid')
            .join('authz_permissions', 'authz_permissions.uuid', 'authz_role_permissions.permission_uuid')
            .whereIn(
              'authz_permissions.slug',
              limited.map((p) => p.slug)
            )
            .select(
              'authz_roles.uuid as role_uuid',
              'authz_roles.slug as role_slug',
              'authz_roles.scope_type as scope_type',
              'authz_roles.owner_scope_key as owner_scope_key',
              'authz_permissions.slug as permission_slug'
            )
        )
        for (const link of links) {
          const levels = levelsOf.get(String(link.permission_slug))
          if (!levels || levels.has(String(link.scope_type) as ScopeType)) continue
          report.assignableAtViolations.push({
            role: {
              uuid: String(link.role_uuid),
              slug: String(link.role_slug),
              scopeType: String(link.scope_type) as ScopeType,
              owner: String(link.owner_scope_key),
            },
            permission: String(link.permission_slug),
          })
        }
      }

      // 4. La versión compartida la sube `withAuthzCatalogWrite` al salir de
      //    aquí, como última sentencia: o se confirma todo (catálogo nuevo +
      //    versión nueva) o nada.
    }, { driver: 'catalog', timeoutMs })
  )
  return report
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
  /**
   * Permisos del spec cuyo `assignableAt` en la base difiere (3B · B5):
   * `null` = cualquier nivel. `corrupt: true` (3E · P5) es una fila que no
   * se puede leer (`assignable_at` que no es JSON de niveles): cuenta como
   * diferencia —el sync la repara— y el diff la nombra en vez de morir.
   */
  assignableAtMismatches: Array<{ permission: string; expected: ScopeType[] | null; actual: ScopeType[] | null; corrupt?: boolean }>
  /**
   * Roles LOCALES (3B): propios de un scope, definidos con `defineScopedRole`.
   * Informativo: no son sobrantes ni faltantes (el spec solo declara
   * globales) y no afectan a `catalogInSync`.
   */
  scopedRoles: Array<{ slug: string; scopeType: ScopeType; owner: string }>
  /**
   * `(slug, nivel)` con MÁS DE UN rol visible desde una misma cadena que la
   * AUTORIDAD no sabe ordenar (3D · M2 d; 3F · S3). Desde 3F, la pareja
   * global+local va a `shadowedByGlobal` y la de ancestro+descendiente a
   * `shadowedByAncestor` —las dos son el orden de autoridad funcionando, no
   * deriva—, así que aquí solo queda lo que NINGUNA regla ordena: dos
   * locales que se declaran ancestro el uno del otro (un `resolveChain` con
   * un ciclo o que se contradice). Eso sí es deriva REAL —`catalogInSync` es
   * `false` y el comando sale con código ≠ 0—: mientras dure, toda ruta por
   * slug ahí responde 422 `E_AUTHZ_AMBIGUOUS_ROLE` (M1) y el operador tiene
   * que PURGAR uno (un rol local no se renombra: 3E · Q1). Las parejas de
   * locales solo se juzgan con `resolveChain` (el árbol es del consumidor):
   * sin resolutor se dice en el informe.
   */
  ambiguousRoles: Array<{ slug: string; scopeType: ScopeType; owners: string[] }>
  /**
   * Roles LOCALES ensombrecidos por un rol GLOBAL homónimo: el del spec que
   * el sync va a escribir (3E · P1 b) o uno que ya está en la base. **No es
   * deriva** desde 3F · S3: es el orden de AUTORIDAD funcionando (global >
   * local), igual que `shadowedByAncestor`. Se listan para que el operador
   * los vea —mientras duren, ese slug es 422 `E_AUTHZ_AMBIGUOUS_ROLE` en la
   * cadena de esos owners y se opera por `{ uuid }`—, pero no dejan el gate
   * de CI en rojo: un tenant que ocupa un nombre no puede parar el deploy de
   * la plataforma, ni siquiera por la vía del `exit 1` (auditor N1).
   */
  shadowedByGlobal: Array<{ slug: string; scopeType: ScopeType; owner: string }>
  /**
   * Roles LOCALES ensombrecidos por otro LOCAL homónimo cuyo owner es un
   * ANCESTRO suyo (3F · S3): el dueño del árbol definió el suyo y el del
   * descendiente queda tapado dentro de su propio subárbol. Como
   * `shadowedByGlobal`: se lista, no es deriva.
   */
  shadowedByAncestor: Array<{ slug: string; scopeType: ScopeType; owner: string; shadowedBy: string }>
  /**
   * Vínculos rol→permiso vivos que el `assignableAt` del spec ya no admite
   * (3E · P6), en roles que el sync no toca (locales y globales de otro
   * catálogo). El sync los reporta igual; el diff los dice antes.
   */
  assignableAtViolations: Array<{ role: string; scopeType: ScopeType; owner: string; permission: string }>
}

/**
 * Compara un spec con lo que hay en `authz_*`, sin escribir. Igual que el
 * sync, solo mira los roles del spec: lo ajeno (otro catálogo) no es una
 * diferencia. Un diff limpio significa que `syncAuthzCatalog(spec)` sería un
 * no-op.
 */
export async function diffAuthzCatalog(
  catalog: CatalogSpec,
  options: { timeoutMs?: number; resolveChain?: ScopeChainResolver } = {}
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
    ambiguousRoles: [],
    shadowedByGlobal: [],
    shadowedByAncestor: [],
    assignableAtViolations: [],
  }

  const dbPerms = await sql('diff.permissions', () => db.from('authz_permissions').select('uuid', 'slug', 'assignable_at'))
  // Lo que el sync rechazaría, el diff lo dice antes (D3).
  assertNoSlugCollisions('permiso', [
    ...catalog.permissions.map((p) => p.slug),
    ...dbPerms.map((p: any) => p.slug as string),
  ])
  const permUuidBySlug = new Map<string, string>(dbPerms.map((p: any) => [p.slug, p.uuid]))
  const permSlugByUuid = new Map<string, string>(dbPerms.map((p: any) => [p.uuid, p.slug]))
  // Tolerante con la fila corrupta (3E · P5): el diff la REPORTA, no muere.
  const levelsBySlug = new Map<string, readonly ScopeType[] | null>(
    dbPerms.map((p: any) => [p.slug, tolerantAssignableAt(p.slug, p.assignable_at)])
  )
  const storedBySlug = new Map<string, string | null>(
    dbPerms.map((p: any) => [p.slug, storedAssignableAt(p.slug, p.assignable_at)])
  )
  for (const perm of catalog.permissions) {
    if (!permUuidBySlug.has(perm.slug)) {
      diff.missingPermissions.push(perm.slug)
      continue
    }
    const expected = encodeAssignableAt(perm.assignableAt)
    const actual = levelsBySlug.get(perm.slug) ?? null
    // La MISMA normalización que el sync (3D · N5): lo que el diff dice «en
    // sync» tiene que ser exactamente lo que el sync dejaría sin tocar.
    const stored = storedBySlug.get(perm.slug) ?? null
    if (expected !== stored) {
      const corrupt = stored === CORRUPT_ASSIGNABLE_AT
      diff.assignableAtMismatches.push({
        permission: perm.slug,
        expected: expected ? (JSON.parse(expected) as ScopeType[]) : null,
        actual: corrupt ? null : actual ? [...actual].sort() : null,
        ...(corrupt ? { corrupt: true } : {}),
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
    // 3E · P1 b: ya no es un 422 (el sync escribe el global y ensombrece al
    // local). Es deriva que hay que ver ANTES del deploy, no una excepción
    // que impide ver el resto del informe.
    const clash = catalog.roles.find((r) => r.slug === local.slug && r.scopeType === local.scope_type)
    if (clash) {
      diff.shadowedByGlobal.push({ slug: local.slug, scopeType: local.scope_type, owner: local.owner_scope_key })
    }
  }
  diff.assignableAtViolations = await findAssignableAtViolations(sql, catalog)
  // 3F · S3: los homónimos visibles en una misma cadena se clasifican por
  // AUTORIDAD; solo lo que la autoridad no ordena es deriva.
  const homonimos = await classifyHomonyms(sql, options.resolveChain)
  diff.ambiguousRoles = homonimos.ambiguousRoles
  diff.shadowedByAncestor = homonimos.shadowedByAncestor
  for (const shadow of homonimos.shadowedByGlobal) {
    if (diff.shadowedByGlobal.some((s) => s.slug === shadow.slug && s.scopeType === shadow.scopeType && s.owner === shadow.owner)) continue
    diff.shadowedByGlobal.push(shadow)
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
    diff.assignableAtMismatches.length === 0 &&
    diff.ambiguousRoles.length === 0 &&
    diff.assignableAtViolations.length === 0
  )
}

/**
 * Vínculos rol→permiso vivos que el `assignableAt` del spec ya no admite
 * (3E · P6). Mira TODOS los roles de la base (los del spec los rechaza
 * `assertAssignableAt` antes, con 422): los que quedan son locales de los
 * tenants y globales de otro catálogo, justo los que el sync no revalidaba.
 */
async function findAssignableAtViolations(
  sql: (operation: string, fn: () => any) => Promise<any>,
  catalog: CatalogSpec
): Promise<CatalogDiff['assignableAtViolations']> {
  const limited = catalog.permissions.filter((p) => p.assignableAt)
  if (!limited.length) return []
  const levelsOf = new Map<string, ReadonlySet<ScopeType>>(limited.map((p) => [p.slug, new Set(p.assignableAt!)]))
  const links = await sql('diff.assignableAt', () =>
    db
      .from('authz_role_permissions')
      .join('authz_roles', 'authz_roles.uuid', 'authz_role_permissions.role_uuid')
      .join('authz_permissions', 'authz_permissions.uuid', 'authz_role_permissions.permission_uuid')
      .whereIn(
        'authz_permissions.slug',
        limited.map((p) => p.slug)
      )
      .select(
        'authz_roles.slug as role_slug',
        'authz_roles.scope_type as scope_type',
        'authz_roles.owner_scope_key as owner_scope_key',
        'authz_permissions.slug as permission_slug'
      )
  )
  const found: CatalogDiff['assignableAtViolations'] = []
  for (const link of links) {
    const levels = levelsOf.get(String(link.permission_slug))
    if (!levels || levels.has(String(link.scope_type) as ScopeType)) continue
    found.push({
      role: String(link.role_slug),
      scopeType: String(link.scope_type) as ScopeType,
      owner: String(link.owner_scope_key),
      permission: String(link.permission_slug),
    })
  }
  return found
}

/**
 * `(slug, nivel)` con dos o más roles visibles a la vez desde una misma
 * cadena (3D · M2 d), clasificados por AUTORIDAD (3F · S3): global > local
 * de un ancestro > local de un descendiente. Un global + cualquier local
 * siempre conviven (el global se ve en todas partes) y el global gana; dos
 * locales solo conviven si un owner está en la cadena del otro —eso exige el
 * árbol del consumidor, así que sin `resolveChain` la pareja no se juzga (y
 * el informe lo dice)— y gana el ancestro. Lo que queda en `ambiguousRoles`
 * es lo que ninguna regla ordena: dos owners que se declaran ancestro el uno
 * del otro (un `resolveChain` con un ciclo o contradictorio). Eso es deriva.
 */
async function classifyHomonyms(
  sql: (operation: string, fn: () => any) => Promise<any>,
  resolveChain?: ScopeChainResolver
): Promise<Pick<CatalogDiff, 'ambiguousRoles' | 'shadowedByGlobal' | 'shadowedByAncestor'>> {
  const rows = await sql('diff.ambiguous', () =>
    db.from('authz_roles').select('slug', 'scope_type', 'owner_scope_key')
  )
  const byName = new Map<string, string[]>()
  for (const row of rows) {
    const key = `${row.slug}\u001f${row.scope_type}`
    if (!byName.has(key)) byName.set(key, [])
    byName.get(key)!.push(String(row.owner_scope_key))
  }
  const chains = new Map<string, string[] | null>()
  const chainOf = async (ownerKey: string): Promise<string[] | null> => {
    if (chains.has(ownerKey)) return chains.get(ownerKey)!
    const owner = scopeFromKey(ownerKey)
    let keys: string[] | null = null
    if (owner && resolveChain) {
      const chain = await resolveChain(owner)
      keys = chain ? chain.map(scopeKey) : null
    }
    chains.set(ownerKey, keys)
    return keys
  }

  const result: Pick<CatalogDiff, 'ambiguousRoles' | 'shadowedByGlobal' | 'shadowedByAncestor'> = {
    ambiguousRoles: [],
    shadowedByGlobal: [],
    shadowedByAncestor: [],
  }
  for (const [key, owners] of byName) {
    if (owners.length < 2) continue
    const [slug, scopeType] = key.split('\u001f') as [string, ScopeType]
    const locals = owners.filter((o) => o !== GLOBAL_OWNER_KEY)
    if (owners.length > locals.length) {
      // Hay un global: convive con TODOS los locales homónimos y GANA.
      for (const owner of locals) result.shadowedByGlobal.push({ slug, scopeType, owner })
    }
    // 3G · X3 (auditor P5 b): la pareja de LOCALES se clasifica igual haya
    // global o no. Hasta aquí un global en el grupo hacía `continue` y con
    // eso dejaba de detectarse una pareja de locales CONTRADICTORIA (dos
    // owners que se declaran ancestro el uno del otro), que es la única
    // deriva de verdad de esta clasificación: un caso ciego nuevo.
    // 3b-1 · T-3b 3 (tester 3F · §6.3): UNA línea por rol ENSOMBRECIDO, no
    // una por pareja. Con owners anidados a > b > c salían tres (a→b, a→c,
    // b→c) para tres roles, y la tercera no añadía nada: lo que el operador
    // necesita saber es qué `(slug, nivel)` está muerto y quién manda ahí.
    // El ensombrecedor que se nombra es el MÁS AUTORIZADO —el ancestro más
    // alto de la cadena del ensombrecido—, que es el orden que 3F · S3 fijó.
    for (const b of locals) {
      const chainB = await chainOf(b)
      if (!chainB) continue
      const shadowers: string[] = []
      for (const a of locals) {
        if (a === b) continue
        // `a` está en la cadena de `b`: `a` es su ancestro y lo ensombrece.
        if (!chainB.includes(a)) continue
        if ((await chainOf(a))?.includes(b)) {
          // Y `b` en la de `a`: el árbol se contradice y nadie manda.
          const owners2 = [a, b].sort()
          if (!result.ambiguousRoles.some((r) => r.slug === slug && r.scopeType === scopeType && r.owners.join() === owners2.join())) {
            result.ambiguousRoles.push({ slug, scopeType, owners: owners2 })
          }
          continue
        }
        shadowers.push(a)
      }
      if (!shadowers.length) continue
      // Más lejos en la cadena de `b` = más arriba en el árbol = más autoridad.
      shadowers.sort((x, y) => chainB.indexOf(y) - chainB.indexOf(x))
      result.shadowedByAncestor.push({ slug, scopeType, owner: b, shadowedBy: shadowers[0] })
    }
  }
  return result
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
    if (a.corrupt) {
      lines.push(
        `assignableAt CORRUPTO en la base: ${a.permission} (spec=${levels(a.expected)}); authz_permissions.assignable_at ` +
          `no es una lista JSON de niveles y el memo lo lee con 500: sincroniza para repararlo`
      )
      continue
    }
    lines.push(`assignableAt distinto: ${a.permission} spec=${levels(a.expected)} base=${levels(a.actual)}`)
  }
  for (const v of diff.assignableAtViolations) {
    lines.push(
      `vínculo fuera de assignableAt: ${v.role}@${v.scopeType} (owner ${v.owner}) → ${v.permission} — ` +
        `el config ya no admite ese nivel; el sync no lo borra (lo asignado sigue concediendo): arréglalo tú`
    )
  }
  for (const a of diff.ambiguousRoles) {
    lines.push(
      `rol AMBIGUO que la autoridad no ordena (los dos owners se declaran ancestro del otro): ${a.slug}@${a.scopeType} ` +
        `owners=${a.owners.join(', ')} — toda ruta por slug ahí responde 422 E_AUTHZ_AMBIGUOUS_ROLE; se opera por ` +
        `{ uuid } y se deshace PURGANDO uno (un rol local no se renombra) o arreglando el árbol`
    )
  }
  return lines
}

/** Líneas informativas del diff (no son diferencias): los roles locales, propios de un scope. */
export function formatScopedRoles(diff: CatalogDiff): string[] {
  return diff.scopedRoles.map((r) => `rol local (propio de ${r.owner}): ${r.slug}@${r.scopeType}`)
}

/**
 * Líneas informativas del diff (3F · S3): los roles locales ENSOMBRECIDOS
 * por una definición más autorizada —un global, o un local de un ancestro—.
 * No son deriva: es el orden de autoridad funcionando. Se listan porque
 * mientras duren, ese slug es 422 `E_AUTHZ_AMBIGUOUS_ROLE` en la cadena de
 * su owner y hay que operar por `{ uuid }` (o purgar uno de los dos).
 */
export function formatShadowedRoles(diff: Pick<CatalogDiff, 'shadowedByGlobal' | 'shadowedByAncestor'>): string[] {
  const lines: string[] = []
  for (const s of diff.shadowedByGlobal) {
    lines.push(
      `rol local ENSOMBRECIDO por un global homónimo: ${s.slug}@${s.scopeType} (owner ${s.owner}) — el global gana; ` +
        `en la cadena de ese owner el slug pasa a 422 E_AUTHZ_AMBIGUOUS_ROLE (para TODOS, la plataforma incluida: ` +
        `se direcciona por { uuid }) hasta que se purgue uno`
    )
  }
  for (const s of diff.shadowedByAncestor) {
    lines.push(
      `rol local ENSOMBRECIDO por el de un ancestro: ${s.slug}@${s.scopeType} (owner ${s.owner}, ensombrecido por ` +
        `${s.shadowedBy}) — el ancestro gana; en la cadena de ${s.owner} el slug pasa a 422 E_AUTHZ_AMBIGUOUS_ROLE ` +
        `(se direcciona por { uuid }) hasta que se purgue uno`
    )
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
  catalogs: CatalogSource[],
  options: { resolveChain?: ScopeChainResolver; failOnShadows?: boolean } = {}
): Promise<{ inSync: boolean; lines: string[] }> {
  const lines: string[] = []
  let inSync = true
  const specs = await resolveDisjointCatalogs(catalogs)
  // Los roles locales (3B) no son deriva del config y no dependen del spec:
  // se toman del PRIMER diff que ya se calcula (3E · Q6; hasta aquí el
  // comando repetía el diff entero —todas sus consultas— solo para
  // extraerlos, y sus líneas salían indentadas DENTRO del bloque de
  // diferencias del último catálogo, como si fueran suyas).
  let scoped: string[] = []
  // 3b-1 · T-3b 1 (tester 3F · §6.1): las sombras se ACUMULAN sobre todos los
  // catálogos, con deduplicación. `diff.shadowedByGlobal` tiene una fuente
  // DEPENDIENTE del spec (un rol del spec homónimo de un local), así que
  // tomarlas del índice 0 perdía por completo las que causaba un rol del
  // catálogo #2: no salían como línea de sombras ni como diferencia de ese
  // catálogo. `scopedRoles` sí sale del índice 0: lee la BASE y no depende
  // del spec, así que repetir el diff entero solo para él sería gratuito
  // (3E · Q6).
  const sombras: Pick<CatalogDiff, 'shadowedByGlobal' | 'shadowedByAncestor'> = {
    shadowedByGlobal: [],
    shadowedByAncestor: [],
  }
  for (const [index, spec] of specs.entries()) {
    const diff = await diffAuthzCatalog(spec, options)
    for (const s of diff.shadowedByGlobal) {
      if (sombras.shadowedByGlobal.some((x) => x.slug === s.slug && x.scopeType === s.scopeType && x.owner === s.owner)) continue
      sombras.shadowedByGlobal.push(s)
    }
    for (const s of diff.shadowedByAncestor) {
      if (
        sombras.shadowedByAncestor.some(
          (x) => x.slug === s.slug && x.scopeType === s.scopeType && x.owner === s.owner && x.shadowedBy === s.shadowedBy
        )
      ) {
        continue
      }
      sombras.shadowedByAncestor.push(s)
    }
    if (index === 0) scoped = formatScopedRoles(diff)
    if (catalogInSync(diff)) {
      lines.push(`catálogo #${index + 1}: en sync`)
      continue
    }
    inSync = false
    lines.push(`catálogo #${index + 1}: DIFERENCIAS`)
    for (const line of formatCatalogDiff(diff)) lines.push(`  ${line}`)
  }
  const shadowed = formatShadowedRoles(sombras)
  if (shadowed.length) {
    lines.push('roles locales ENSOMBRECIDOS por una definición más autorizada (no son deriva: 3F · S3):')
    for (const line of shadowed) lines.push(`  ${line}`)
    // 3G · X3 (auditor P5): que un tenant no pueda dejar en rojo el gate de
    // CI de la plataforma es la decisión de 3F · S3, pero el efecto es que
    // NADIE se entera por CI de que las rutas por slug de un subárbol están
    // muertas. `--fail-on-shadows` es el opt-in de quien sí quiere enterarse.
    if (options.failOnShadows) {
      inSync = false
      lines.push('  (--fail-on-shadows: los ensombrecidos cuentan como deriva en ESTA ejecución)')
    }
  }
  if (scoped.length) {
    lines.push('roles locales (no son deriva del config):')
    for (const line of scoped) lines.push(`  ${line}`)
    if (!options.resolveChain) {
      lines.push(
        '  (sin scopes.resolveChain no se puede juzgar si dos roles locales homónimos son visibles en la misma cadena; ' +
          'la pareja global+local sí se detecta)'
      )
    }
  }
  return { inSync, lines }
}

/**
 * Sincroniza todos los catálogos del config, en orden (lo que hace
 * `authz:catalog:sync`). Devuelve cuántos y lo que hay que DECIR (3E · P1 b
 * / P6): el comando lo imprime como aviso — reportar y seguir, nunca romper
 * en silencio.
 */
export async function syncCatalogs(
  catalogs: CatalogSource[],
  options: SyncCatalogOptions = {}
): Promise<{ count: number } & CatalogSyncReport> {
  let count = 0
  const shadowedByGlobal: CatalogRoleRef[] = []
  const assignableAtViolations: CatalogSyncReport['assignableAtViolations'] = []
  for (const spec of await resolveDisjointCatalogs(catalogs)) {
    const report = await syncAuthzCatalog(spec, options)
    shadowedByGlobal.push(...report.shadowedByGlobal)
    assignableAtViolations.push(...report.assignableAtViolations)
    count += 1
  }
  return { count, shadowedByGlobal, assignableAtViolations }
}
