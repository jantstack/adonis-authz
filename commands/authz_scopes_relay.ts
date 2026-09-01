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
 * es REANUDABLE —lo que no entra sigue pendiente—. Un cambio que falla
 * **aplaza lo que depende de él** (todo cambio posterior que nombre alguno de
 * sus scopes) y deja pasar el resto: hasta 3b-2h paraba la pasada entera, y
 * eso convertía una entrada irreparable en un tapón permanente para todos los
 * tenants (3b-2h · 🔴 2). Sale con código ≠ 0 si algo falló o hay entradas
 * APARCADAS, para que el supervisor se entere.
 *
 * **Escritor ÚNICO**: si la outbox sabe dar lease (`sqlScopeOutbox` lo hace),
 * una segunda pasada simultánea no hace nada y lo dice. Sin lease, no lances
 * dos a la vez: la rezagada re-aplica cambios viejos sobre el árbol nuevo.
 *
 * **Lo que este comando no puede arreglar**: entre el commit del consumidor
 * y la pasada hay un lag (segundos) en el que el backend decide con el árbol
 * VIEJO. Es un fail-open temporal —el tenant antiguo conserva acceso tras un
 * `moved`, los denies heredados no aplican tras un `attached`—. No hay 2PC.
 * Un ciclo más corto acorta esa ventana **mientras la cola avance**: lo que
 * falla o se aparca no está acotado por el ciclo y hay que mirarlo.
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

    // Lo APARCADO se dice siempre, aplique o no esta pasada: es una
    // divergencia permanente del árbol del backend, no un incidente pasado.
    for (const item of report.dead) {
      this.logger.error(`APARCADO tras agotar los intentos: ${linea(item)}${item.error ? ` — ${item.error}` : ''}`)
    }
    if (report.dead.length > 0) {
      this.logger.warning(
        'Una entrada aparcada NO se va a aplicar sola: el árbol del backend está divergente en ese nodo. ' +
          'Revísala en la cola (el consumidor puede volver a notificar el cambio) o reconcilia.'
      )
    }

    if (report.busy) {
      this.logger.info('Otra pasada del relay tiene el lease de la cola: esta no ha aplicado nada (el relay es escritor único).')
      if (report.dead.length > 0) this.exitCode = 1
      return
    }

    if (report.dryRun) {
      for (const item of report.wouldApply) this.logger.log(`pendiente: ${linea(item)}`)
      if (report.wouldApply.length === 0) {
        if (report.dead.length > 0) this.exitCode = 1
        else this.logger.success('La outbox del árbol está vacía: nada que propagar.')
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

    for (const item of report.deferred) {
      this.logger.warning(`aplazado: ${linea(item)}${item.error ? ` — ${item.error}` : ''}`)
    }

    if (report.failures.length > 0) {
      for (const item of report.failures) {
        this.logger.error(
          `falló #${item.id} (${item.change.op} ` +
            `${item.change.child.type}:${item.change.child.uuid ?? ''}): ${item.error}`
        )
      }
      this.logger.warning(
        'Lo que DEPENDE de un cambio fallido no se adelanta (el orden del árbol importa: aparece como «aplazado»), ' +
          'pero el resto de la cola sí avanza. Arregla la causa y vuelve a ejecutar; retoma donde lo dejó. ' +
          'Agotados los intentos que declare tu outbox, una entrada irreparable se APARCA y se reporta.'
      )
      this.exitCode = 1
      return
    }

    if (report.dead.length > 0) this.exitCode = 1
    if (report.applied.length === 0) {
      if (report.dead.length === 0) this.logger.success('La outbox del árbol está vacía: nada que propagar.')
      return
    }
    this.logger.success(`${report.applied.length} cambio(s) del árbol propagado(s) al driver.`)
    if (report.remaining) {
      this.logger.warning('Quedan cambios pendientes (se alcanzó el límite de la pasada o hay aplazados): vuelve a ejecutar.')
    }
  }
}
