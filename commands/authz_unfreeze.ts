import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'
import type { FreezeStatus } from '../src/manager.js'

/**
 * Qué hacer con el freeze vivo, en una función PURA (mismo patrón que
 * `reconcileLines`): es la única decisión del comando y así tiene su caso
 * sin montar un ace.
 *
 * Reglas:
 *  - Sin freeze vivo ⇒ no-op en verde (idempotente: descongelar lo
 *    descongelado no es un incidente).
 *  - Freeze de OPERADOR ⇒ se levanta (este comando es su otra mitad).
 *  - Freeze de OTRO dueño (`reconcile`, `platform`) ⇒ NO se levanta sin
 *    `--fence`: levantar la barrera de una pasada viva es exactamente el
 *    A1.3 que el token cierra. `--fence=<n>` es la decisión humana explícita
 *    («ese proceso murió sin lease»), y tiene que coincidir con el fence
 *    vivo — un fence viejo no levanta la ventana de otro.
 */
export function unfreezePlan(
  status: FreezeStatus | null,
  fence: number | undefined
): { action: 'noop' | 'lift' | 'refuse'; message: string } {
  if (status === null) {
    return { action: 'noop', message: 'No hay ningún freeze vivo: nada que levantar.' }
  }
  if (fence !== undefined && fence !== status.fence) {
    return {
      action: 'refuse',
      message:
        `El fence vivo es ${status.fence} y pediste levantar el ${fence}: ese freeze ya no existe. ` +
        `Mira el estado y repite con el fence actual si de verdad quieres levantarlo.`,
    }
  }
  if (status.kind !== 'operator' && fence === undefined) {
    return {
      action: 'refuse',
      message:
        `El freeze vivo NO es de operador: lo sostiene ${status.holder} (${status.reason}). ` +
        `Levantárselo dejaría su pasada corriendo sin barrera (y su reporte lo delatará como lapsed). ` +
        `Espera a que termine${status.untilMs === null ? '' : ' — o a que su lease venza solo'}; si su proceso ` +
        `murió sin lease, la decisión humana es --fence=${status.fence}.`,
    }
  }
  return {
    action: 'lift',
    message: `Freeze de ${status.holder} (${status.reason}, fence ${status.fence}) levantado: la flota vuelve a escribir.`,
  }
}

/**
 * **Cierra la ventana de cutover** (3b-7): levanta el freeze de operador que
 * abrió `authz:freeze`. La otra mitad de ese comando; ver su docblock.
 *
 *   node ace authz:unfreeze              # levanta la ventana del operador
 *   node ace authz:unfreeze --fence=7    # decisión humana: levanta ESE freeze aunque no sea de operador
 */
export default class AuthzUnfreeze extends BaseCommand {
  static commandName = 'authz:unfreeze'
  static description = 'Close the cutover window: lift the operator freeze and let the fleet write again'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.number({
    description: 'Lift exactly this freeze even if it is not an operator window (its owner died without a lease)',
  })
  declare fence: number | undefined

  async run() {
    const { default: authorization } = await import('../services/main.js')
    const status = await authorization.freezeStatus()
    const plan = unfreezePlan(status, this.fence)
    if (plan.action === 'noop') {
      this.logger.success(plan.message)
      return
    }
    if (plan.action === 'refuse') {
      this.logger.error(plan.message)
      this.exitCode = 1
      return
    }
    const lifted = await authorization.unfreeze({ fence: status!.fence, holder: status!.holder })
    if (!lifted) {
      // Entre el SELECT y el UPDATE alguien lo levantó o venció: no es un error.
      this.logger.success('El freeze ya no estaba (lo levantó su dueño o venció su lease).')
      return
    }
    this.logger.success(plan.message)
  }
}
