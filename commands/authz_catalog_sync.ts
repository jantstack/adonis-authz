import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'

/**
 * Sincroniza a las tablas `authz_*` los catálogos declarados en
 * `config/authorization.ts` (`catalogs`), en orden. Transaccional por
 * catálogo; con la poda de vínculos activa por defecto (L0.9): un permiso que
 * el config quita de un rol deja de concederse. Nunca borra roles ni
 * permisos.
 *
 *   node ace authz:catalog:sync
 *   node ace authz:catalog:sync --keep-links   # solo aditivo (1.x)
 */
export default class AuthzCatalogSync extends BaseCommand {
  static commandName = 'authz:catalog:sync'
  static description = 'Sync the catalogs declared in config into the authz_* tables'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.boolean({ description: 'Do not prune role→permission links missing from the spec' })
  declare keepLinks: boolean | undefined

  async run() {
    const config = this.app.config.get('authorization') as any
    const catalogs = config?.catalogs
    if (!Array.isArray(catalogs) || catalogs.length === 0) {
      this.logger.error(
        'No hay catálogos declarados: añade `catalogs: [() => import(...)]` a config/authorization.ts'
      )
      this.exitCode = 1
      return
    }

    const { syncCatalogs } = await import('../src/catalog.js')
    const { count, shadowedByGlobal, assignableAtViolations } = await syncCatalogs(catalogs, {
      prune: this.keepLinks ? 'none' : 'links',
    })
    // 3E · P1 b / P6: el sync ya no aborta por lo que un tenant hizo en su
    // scope, pero tampoco lo silencia. Un despliegue que ensombrece roles de
    // tenants —o que deja vínculos fuera del `assignableAt` nuevo— tiene que
    // salir por pantalla y quedar en el log del deploy.
    for (const role of shadowedByGlobal) {
      this.logger.warning(
        `rol local ENSOMBRECIDO por el global del spec: ${role.slug}@${role.scopeType} (uuid ${role.uuid}, owner ${role.owner}). ` +
          `El global gana; en esa cadena el slug pasa a 422 E_AUTHZ_AMBIGUOUS_ROLE hasta que se purgue uno.`
      )
    }
    for (const violation of assignableAtViolations) {
      this.logger.warning(
        `vínculo fuera de assignableAt: ${violation.role.slug}@${violation.role.scopeType} (owner ${violation.role.owner}) → ` +
          `${violation.permission}. No se ha borrado (lo asignado sigue concediendo): quítalo o amplía el assignableAt.`
      )
    }
    this.logger.success(
      `${count} catálogo(s) sincronizado(s)` + (this.keepLinks ? ' (sin poda de vínculos).' : '.')
    )
  }
}
