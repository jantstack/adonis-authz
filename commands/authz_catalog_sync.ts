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
    const count = await syncCatalogs(catalogs, { prune: this.keepLinks ? 'none' : 'links' })
    this.logger.success(
      `${count} catálogo(s) sincronizado(s)` + (this.keepLinks ? ' (sin poda de vínculos).' : '.')
    )
  }
}
