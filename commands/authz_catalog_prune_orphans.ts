import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'

/**
 * Lista —y con `--force` borra— los roles LOCALES cuyo owner el árbol del
 * consumidor YA NO conoce (3b-0 · Z2).
 *
 * Un rol así está DORMIDO, y «dormido» significa exactamente esto
 * (3b-0b · AA1): no es visible desde ningún scope vivo cuya cadena NO pase
 * por su owner. NO significa que no conceda: un descendiente vivo cuya ruta
 * materializada siga pasando por el owner cumple la regla de visibilidad
 * (invariante 18), y desde ahí el rol concede, es membresía y se puede
 * asignar. Por eso este comando puede estar revocando permisos VIVOS, y por
 * eso los huérfanos que aún tienen asignaciones vigentes se listan aparte,
 * con aviso. Lo que el rol dormido hace en todo caso es ocupar su
 * `(slug, nivel)` allí donde todavía se le vea, y `deleteScopedRole` no lo
 * alcanza (resuelve el owner en fresco: 422 `E_AUTHZ_UNKNOWN_SCOPE`). Esta
 * es su salida.
 *
 *   node ace authz:catalog:prune-orphans                      # --dry-run: solo lista
 *   node ace authz:catalog:prune-orphans --force              # purga de verdad
 *   node ace authz:catalog:prune-orphans --force --allow-mass-purge
 *
 * Es una operación de PLATAFORMA, no una escritura que dispare un tenant: no
 * lleva actor ni mide rangos. Hasta 3G esta limpieza la arrastraba
 * `scopes.detached` —que SÍ dispara un tenant, sobre un scope que ya no
 * resuelve—, y de ahí salieron tres de las cuatro regresiones de la Fase 3.
 *
 * `--allow-mass-purge` (3b-0b · AA2) desbloquea la cota que rechaza una
 * pasada con la firma de un resolutor ciego (todos los owners huérfanos, o
 * más del 50 % de los roles locales): es una decisión humana, no un default.
 */
export default class AuthzCatalogPruneOrphans extends BaseCommand {
  static commandName = 'authz:catalog:prune-orphans'
  static description = 'List (or, with --force, purge) local roles whose owner scope no longer exists'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.boolean({ description: 'Actually purge the orphan roles (default is a dry run)' })
  declare force: boolean | undefined

  @flags.boolean({
    name: 'allow-mass-purge',
    description: 'Allow a pass that would purge every owner (or more than half the local roles) — check your resolveChain first',
  })
  declare allowMassPurge: boolean | undefined

  async run() {
    const { default: authorization } = await import('../services/main.js')
    const { orphans, purged, skipped, massPurge, dryRun } = await authorization.pruneOrphanRoles({
      force: this.force === true,
      allowMassPurge: this.allowMassPurge === true,
    })

    const purgados = new Set(purged.map((role) => role.uuid))
    const saltados = new Set(skipped.map(({ role }) => role.uuid))
    const linea = (o: (typeof orphans)[number]) =>
      `${o.role.slug}@${o.role.scopeType} (uuid ${o.role.uuid}, rank ${o.role.rank}) — owner ` +
      `${o.owner.type}:${o.owner.uuid ?? ''} ya no existe en el árbol; permisos: ${o.permissions.join(', ') || '—'}` +
      (o.stillGranting ? `; asignaciones VIGENTES: ${o.assignments}` : '')

    // Los que todavía conceden van aparte: purgarlos es revocar permisos
    // vivos, no recoger basura (3b-0b · AA1).
    const vivos = orphans.filter((o) => o.stillGranting)
    for (const o of orphans.filter((o) => !o.stillGranting)) {
      const estado = saltados.has(o.role.uuid) ? 'saltado (el owner volvió)' : purgados.has(o.role.uuid) ? 'purgado' : 'huérfano'
      this.logger.log(`${estado}: ${linea(o)}`)
    }
    for (const o of vivos) {
      const estado = saltados.has(o.role.uuid) ? 'saltado (el owner volvió)' : purgados.has(o.role.uuid) ? 'purgado' : 'huérfano'
      this.logger.warning(`${estado} · TODAVÍA CONCEDE: ${linea(o)}`)
    }
    if (vivos.length > 0) {
      this.logger.warning(
        `${vivos.length} rol(es) huérfano(s) siguen teniendo asignaciones vigentes: un rol dormido NO deja de conceder si ` +
          `algún scope vivo conserva al owner en su cadena (rutas materializadas, borrado en dos pasos). Purgarlos revoca ` +
          `permisos que hoy funcionan.`
      )
    }

    if (orphans.length === 0) {
      this.logger.success('No hay roles locales huérfanos: todos los owners resuelven.')
      return
    }
    if (dryRun) {
      if (massPurge) {
        this.logger.warning(
          `${orphans.length} de los roles locales quedarían huérfanos: eso es la firma de un 'scopes.resolveChain' ciego. ` +
            `Con --force esto se rechaza (E_AUTHZ_MASS_PURGE_REFUSED); comprueba el resolutor antes de añadir --allow-mass-purge.`
        )
      }
      this.logger.warning(
        `${orphans.length} rol(es) local(es) con el owner fuera del árbol. No se ha borrado nada: repite con --force.`
      )
      return
    }
    if (skipped.length > 0) {
      this.logger.warning(`${skipped.length} rol(es) saltado(s): su owner volvió al árbol durante la pasada.`)
    }
    this.logger.success(`${purged.length} rol(es) local(es) huérfano(s) purgado(s).`)
  }
}
