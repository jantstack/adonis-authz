import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'

/**
 * Drena la OUTBOX del árbol de scopes y aplica los cambios al driver
 * (3b-2d; panel 2, cruce 4 · S5).
 *
 * Con `scopes.outbox` declarada, `authorization.scopes.attached/moved/
 * detached` no escriben en el backend: encolan el cambio DENTRO de la
 * transacción del consumidor. Este comando es quien lo propaga.
 *
 *   node ace authz:scopes:relay                 # drena
 *   node ace authz:scopes:relay --dry-run       # solo dice qué haría
 *   node ace authz:scopes:relay --limit 500     # una pasada acotada
 *
 * Pensado para un supervisor (un bucle, un cron corto, un worker): la pasada
 * es REANUDABLE —lo que no entra sigue pendiente— y **para en el primer
 * fallo**, porque el orden del árbol importa: aplicar el `detached` de un
 * nodo cuyo `moved` no ha entrado dejaría el store con un árbol que nunca
 * existió. Sale con código ≠ 0 si algo falló, para que el supervisor se
 * entere.
 *
 * **Lo que este comando no puede arreglar**: entre el commit del consumidor
 * y la pasada hay un lag (segundos) en el que el backend decide con el árbol
 * VIEJO. Es un fail-open temporal —el tenant antiguo conserva acceso tras un
 * `moved`, los denies heredados no aplican tras un `attached`—. No hay 2PC.
 * Cuanto más corto el ciclo, más corta la ventana.
 *
 * Es una operación de PLATAFORMA (como `authz:catalog:prune-orphans`): se
 * salta `requireActor`/`requireWithin` porque la policy ya se juzgó al
 * ENCOLAR, con el árbol y la sesión de aquel momento. No se expone por HTTP.
 */
export default class AuthzScopesRelay extends BaseCommand {
  static commandName = 'authz:scopes:relay'
  static description = 'Drain the scope-tree outbox and apply the pending tree changes to the driver'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.boolean({
    name: 'dry-run',
    description: 'List the pending tree changes without applying any of them',
  })
  declare dryRun: boolean | undefined

  @flags.number({ description: 'Stop after applying this many changes (the rest stays pending)' })
  declare limit: number | undefined

  @flags.number({ name: 'batch-size', description: 'How many pending changes to read per round trip' })
  declare batchSize: number | undefined

  async run() {
    const { default: authorization } = await import('../services/main.js')
    const report = await authorization.relayScopeChanges({
      dryRun: this.dryRun === true,
      limit: this.limit,
      batchSize: this.batchSize,
    })

    const linea = (item: { id: string | number; change: any; attempts?: number }) => {
      const { change } = item
      const scope = (s: any) => `${s.type}:${s.uuid ?? ''}`
      const destino = change.op === 'detached' ? '' : ` → ${scope(change.parent)}`
      const intentos = item.attempts ? ` (intentos previos: ${item.attempts})` : ''
      return `#${item.id} ${change.op} ${scope(change.child)}${destino}${intentos}`
    }

    if (report.dryRun) {
      for (const item of report.wouldApply) this.logger.log(`pendiente: ${linea(item)}`)
      if (report.wouldApply.length === 0) {
        this.logger.success('La outbox del árbol está vacía: nada que propagar.')
        return
      }
      this.logger.warning(
        `${report.wouldApply.length} cambio(s) del árbol sin propagar. No se ha aplicado nada: repite sin --dry-run. ` +
          `Mientras tanto el backend decide con el árbol VIEJO.`
      )
      return
    }

    // Qué se aplicó, uno a uno: la pasada no es atómica y un contador no
    // permite retomar nada.
    for (const item of report.applied) this.logger.log(`aplicado: ${linea(item)}`)

    if (report.failed) {
      this.logger.error(
        `parado en #${report.failed.id} (${report.failed.change.op} ` +
          `${report.failed.change.child.type}:${report.failed.change.child.uuid ?? ''}): ${report.failed.error}`
      )
      this.logger.warning(
        'El relay para en el primer fallo A PROPÓSITO: el orden del árbol importa, y adelantar el siguiente cambio ' +
          'dejaría el backend con un árbol que nunca existió. Arregla la causa y vuelve a ejecutar; retoma donde lo dejó.'
      )
      this.exitCode = 1
      return
    }

    if (report.applied.length === 0) {
      this.logger.success('La outbox del árbol está vacía: nada que propagar.')
      return
    }
    this.logger.success(`${report.applied.length} cambio(s) del árbol propagado(s) al driver.`)
    if (report.remaining) {
      this.logger.warning('Quedan cambios pendientes (se alcanzó el límite de la pasada): vuelve a ejecutar.')
    }
  }
}
