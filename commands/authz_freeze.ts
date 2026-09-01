import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'

/**
 * **Abre la ventana de CUTOVER: congela las escrituras del motor** (3b-7;
 * condición explícita del juez del panel 3 — el intervalo entre la última
 * pasada de `authz:reconcile` y el cambio de `config.default` es donde
 * ocurre la pérdida, lo decide un humano y dura minutos u horas).
 *
 *   node ace authz:freeze --reason="cutover a openfga"
 *   node ace authz:freeze --reason="cutover" --lease-ms=600000   # opt-in: caduca sola
 *   … node ace authz:reconcile --to=openfga --from=database …    # corre DENTRO de la ventana
 *   … cambiar config.default y redesplegar …
 *   node ace authz:unfreeze
 *
 * Mientras la ventana está abierta, toda ESCRITURA del manager —en TODOS los
 * procesos que comparten `authz_*`— es 503 `E_AUTHZ_FROZEN` reintentable;
 * las lecturas siguen. `authz:reconcile` reconoce esta ventana como contexto
 * propio: corre dentro sin tomar otro freeze y NO la levanta al terminar —
 * cerrar el intervalo pasada→cutover es exactamente para lo que existe.
 *
 * **La ventana del operador NO caduca por defecto** (decisión de este lote,
 * justificada en el informe): un cutover no tiene duración conocida de
 * antemano —duración de la ventana y tolerancia a la parada son magnitudes
 * independientes, el argumento que tumbó el TTL fijo— y una ventana que
 * caduca en mitad del cutover devuelve en SILENCIO el fail-open que este
 * mecanismo existe para cerrar. El precio, declarado: si te olvidas de
 * `authz:unfreeze`, la flota no escribe hasta que alguien lo ejecute — pero
 * es un incidente RUIDOSO (cada 503 nombra el motivo y el comando que lo
 * levanta), no una pérdida invisible. `--lease-ms` es el opt-in contrario:
 * la ventana caduca sola pasados esos ms (no hay proceso que renueve: este
 * comando termina), con SU contra declarado — si el cutover tarda más que el
 * lease, los escritores vuelven SOLOS y sin aviso a mitad del cutover.
 *
 * Operación de PLATAFORMA: sin actor, sin rangos, no se expone por HTTP.
 */
export default class AuthzFreeze extends BaseCommand {
  static commandName = 'authz:freeze'
  static description = 'Open the cutover window: freeze every engine write (503 retryable) fleet-wide until authz:unfreeze'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.string({ description: 'Why the window is open — every rejected write shows it to its caller' })
  declare reason: string | undefined

  @flags.number({
    name: 'lease-ms',
    description:
      'Opt-in expiry: the window lifts ITSELF after this many ms (nobody renews it — beware a cutover slower than the lease)',
  })
  declare leaseMs: number | undefined

  async run() {
    if (!this.reason) {
      this.logger.error(
        "Falta --reason: 'node ace authz:freeze --reason=\"cutover a openfga\"'. Cada escritura rechazada se lo " +
          'enseña a quien la intentó: una ventana sin motivo es un 503 misterioso para todos tus admins.'
      )
      this.exitCode = 1
      return
    }
    const { default: authorization } = await import('../services/main.js')
    try {
      const token = await authorization.freeze(this.reason, {
        kind: 'operator',
        leaseMs: this.leaseMs === undefined ? null : this.leaseMs,
      })
      this.logger.success(
        `Ventana de cutover ABIERTA (fence ${token.fence}): las escrituras del motor responden 503 reintentable ` +
          `en toda la flota; las lecturas siguen.`
      )
      if (this.leaseMs === undefined) {
        this.logger.info('La ventana NO caduca sola: ciérrala con `node ace authz:unfreeze` cuando el cutover termine.')
      } else {
        this.logger.warning(
          `La ventana caduca SOLA en ${this.leaseMs} ms y nadie la renueva: si el cutover tarda más, ` +
            'los escritores vuelven sin aviso. Ciérrala antes con `node ace authz:unfreeze`.'
        )
      }
      this.logger.info(
        'Lo que la ventana NO congela: syncAuthzCatalog, manager.driver() y el árbol SQL del consumidor.'
      )
    } catch (error: any) {
      if (error?.code === 'E_AUTHZ_FREEZE_HELD') {
        this.logger.error(error.message)
        this.exitCode = 1
        return
      }
      throw error
    }
  }
}
