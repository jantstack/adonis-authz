import db from '@adonisjs/lucid/services/db'
import { Exception } from '@adonisjs/core/exceptions'
import { v7 as uuidv7 } from 'uuid'
import type { CatalogSpec } from './types.js'

/**
 * Sincroniza un catálogo (roles + permisos + vínculos) a las tablas `authz_*`.
 *
 * Idempotente y aditivo (mismo contrato que el organization_acl_seeder): lo
 * existente se respeta, solo se insertan los diffs nuevos. Quitar algo del
 * catálogo NO lo borra de DB (limpieza explícita vía migración).
 *
 * Lo usan el seeder del nivel app (`app_acl_seeder`) y el harness de la
 * suite de contrato. El catálogo es metadata compartida entre drivers:
 * un driver externo (openfga) materializa aparte solo los hechos.
 */
/**
 * Slugs válidos del catálogo: minúsculas, dígitos y . _ - con `:` opcional
 * (gramática recurso:accion). Prohibidos `~` y `|`: son los caracteres de
 * encoding/separador del driver openfga — un slug que los contenga
 * corrompería el mapeo de bindings.
 */
const CATALOG_SLUG_FORMAT = /^[a-z0-9][a-z0-9_.-]*(:[a-z0-9][a-z0-9_.-]*)?$/

function assertValidSlug(kind: string, slug: string): void {
  if (!CATALOG_SLUG_FORMAT.test(slug)) {
    throw new Exception(
      `Slug de ${kind} inválido: '${slug}'. Formato: minúsculas/dígitos/._- ` +
        `con ':' único opcional (recurso:accion); '~' y '|' están prohibidos.`,
      { status: 500 }
    )
  }
}

export async function syncAuthzCatalog(catalog: CatalogSpec): Promise<void> {
  for (const perm of catalog.permissions) assertValidSlug('permiso', perm.slug)
  for (const role of catalog.roles) assertValidSlug('rol', role.slug)

  // Todo o nada. Un fallo a mitad (una constraint, la conexión) dejaba el
  // catálogo escrito a medias: roles sin sus permisos, es decir holders que
  // "tienen" un rol que no concede nada. Es idempotente y re-ejecutarlo lo
  // arreglaba, pero mientras tanto la autorización respondía de menos.
  await db.transaction(async (trx) => {
    // 1. Permisos: upsert por slug.
    for (const perm of catalog.permissions) {
      const existing = await trx.from('authz_permissions').where('slug', perm.slug).first()
      if (existing) continue
      await trx.table('authz_permissions').insert({
        uuid: uuidv7(),
        slug: perm.slug,
        description: perm.description ?? null,
        created_at: new Date(),
        updated_at: new Date(),
      })
    }

    const dbPerms = await trx
      .from('authz_permissions')
      .whereIn(
        'slug',
        catalog.permissions.map((p) => p.slug)
      )
      .select('uuid', 'slug')
    const permUuidBySlug = new Map<string, string>(dbPerms.map((p: any) => [p.slug, p.uuid]))

    // 2. Roles: upsert por (slug, scope_type).
    for (const role of catalog.roles) {
      const existing = await trx
        .from('authz_roles')
        .where('slug', role.slug)
        .where('scope_type', role.scopeType)
        .first()

      const roleUuid = existing?.uuid ?? role.uuid ?? uuidv7()
      if (!existing) {
        await trx.table('authz_roles').insert({
          uuid: roleUuid,
          slug: role.slug,
          name: role.name ?? role.slug,
          description: role.description ?? null,
          scope_type: role.scopeType,
          rank: role.rank ?? 0,
          created_at: new Date(),
          updated_at: new Date(),
        })
      } else if (role.rank !== undefined && existing.rank !== role.rank) {
        // El rank es metadata de policy: el config manda (a diferencia de los
        // vínculos, que son aditivos).
        await trx.from('authz_roles').where('uuid', roleUuid).update({ rank: role.rank })
      }

      // 3. Vínculos rol→permiso: upsert por par.
      for (const permSlug of role.permissions) {
        const permUuid = permUuidBySlug.get(permSlug)
        if (!permUuid) continue

        const linked = await trx
          .from('authz_role_permissions')
          .where('role_uuid', roleUuid)
          .where('permission_uuid', permUuid)
          .first()
        if (linked) continue

        await trx.table('authz_role_permissions').insert({
          uuid: uuidv7(),
          role_uuid: roleUuid,
          permission_uuid: permUuid,
          created_at: new Date(),
        })
      }
    }
  })
}
