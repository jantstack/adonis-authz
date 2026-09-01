import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'

/**
 * Compara los catálogos declarados en `config/authorization.ts` (`catalogs`)
 * con las tablas `authz_*` y sale con código ≠ 0 si hay diferencias: roles o
 * permisos que faltan, vínculos que faltan, vínculos SOBRANTES (un permiso
 * que el config ya no da y la base sigue dando: L0.9) y roles AMBIGUOS (dos
 * homónimos visibles en la misma cadena, 3D · M2). Pensado para CI: un
 * config que no coincide con producción no pasa.
 *
 *   node ace authz:catalog:diff
 *   node ace authz:catalog:diff --fail-on-shadows
 *
 * Los roles locales ENSOMBRECIDOS por una definición más autorizada (un
 * global, o el de un ancestro) se LISTAN y no cuentan como deriva (3F · S3):
 * un tenant no puede dejar en rojo el gate de CI de la plataforma. El precio
 * es que nadie se entera por CI de que las rutas por slug de ese subárbol
 * están muertas, así que `--fail-on-shadows` lo convierte en deriva para
 * quien sí quiera enterarse (3G · X3).
 */
export default class AuthzCatalogDiff extends BaseCommand {
  static commandName = 'authz:catalog:diff'
  static description = 'Compare the catalogs declared in config with the authz_* tables (exit 1 on drift)'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.boolean({
    name: 'fail-on-shadows',
    description: 'Exit 1 too when a local role is shadowed by a more authoritative one (global or ancestor)',
  })
  declare failOnShadows: boolean

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

    const { runCatalogDiff } = await import('../src/catalog/catalog.js')
    // Con el resolutor del config el diff puede juzgar además si dos roles
    // LOCALES homónimos son visibles en la misma cadena (3D · M2 d).
    const { inSync, lines } = await runCatalogDiff(catalogs, {
      resolveChain: config?.scopes?.resolveChain,
      failOnShadows: this.failOnShadows === true,
    })
    for (const line of lines) this.logger.log(line)
    if (inSync) {
      this.logger.success('Catálogo en sync con la base.')
      return
    }
    this.logger.error('El catálogo NO está en sync: ejecuta `node ace authz:catalog:sync`.')
    this.exitCode = 1
  }
}
