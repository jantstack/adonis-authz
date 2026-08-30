import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'

/**
 * Lista —y con `--force` borra— los roles LOCALES cuyo owner el árbol del
 * consumidor YA NO conoce (3b-0 · Z2).
 *
 * Un rol así está DORMIDO: la regla de visibilidad del invariante 18 exige
 * que su owner esté en la cadena del scope preguntado, así que no concede
 * nada, no es membresía de nadie y no se puede asignar. Lo único que queda
 * ocupado es su `(slug, nivel)` allí donde todavía se le vea, y
 * `deleteScopedRole` no lo alcanza (resuelve el owner en fresco: 422
 * `E_AUTHZ_UNKNOWN_SCOPE`). Esta es su salida.
 *
 *   node ace authz:catalog:prune-orphans            # --dry-run: solo lista
 *   node ace authz:catalog:prune-orphans --force    # purga de verdad
 *
 * Es una operación de PLATAFORMA, no una escritura que dispare un tenant: no
 * lleva actor ni mide rangos. Hasta 3G esta limpieza la arrastraba
 * `scopes.detached` —que SÍ dispara un tenant, sobre un scope que ya no
 * resuelve—, y de ahí salieron tres de las cuatro regresiones de la Fase 3.
 */
export default class AuthzCatalogPruneOrphans extends BaseCommand {
  static commandName = 'authz:catalog:prune-orphans'
  static description = 'List (or, with --force, purge) local roles whose owner scope no longer exists'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.boolean({ description: 'Actually purge the orphan roles (default is a dry run)' })
  declare force: boolean | undefined

  async run() {
    const { default: authorization } = await import('../services/main.js')
    const { orphans, purged, dryRun } = await authorization.pruneOrphanRoles({ force: this.force === true })

    for (const { role, owner, permissions } of orphans) {
      this.logger.log(
        `${dryRun ? 'huérfano' : 'purgado'}: ${role.slug}@${role.scopeType} (uuid ${role.uuid}, rank ${role.rank}) ` +
          `— owner ${owner.type}:${owner.uuid ?? ''} ya no existe en el árbol; permisos: ${permissions.join(', ') || '—'}`
      )
    }
    if (orphans.length === 0) {
      this.logger.success('No hay roles locales huérfanos: todos los owners resuelven.')
      return
    }
    if (dryRun) {
      this.logger.warning(
        `${orphans.length} rol(es) local(es) con el owner fuera del árbol. No se ha borrado nada: repite con --force.`
      )
      return
    }
    this.logger.success(`${purged} rol(es) local(es) huérfano(s) purgado(s).`)
  }
}
