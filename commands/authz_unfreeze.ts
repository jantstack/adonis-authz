import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'
import type { FreezeStatus } from '../src/manager.js'

/**
 * Qué hacer con el freeze vivo, en una función PURA (mismo patrón que
 * `reconcileLines`): es la única decisión del comando y así tiene su caso
 * sin montar un ace.
 *
 * Reglas:
 *  - Sin freeze (nunca hubo, o ya levantado: motivo `null`) ⇒ no-op en verde
 *    (idempotente: descongelar lo descongelado no es un incidente).
 *  - Ventana CADUCADA (2.4.0-alpha.10: motivo puesto y `untilMs` en el pasado,
 *    `lastFreezeStatus().expired`) ⇒ `expired`: ERROR con cuándo venció, exit
 *    ≠ 0, y el comando limpia la fila para que el segundo `unfreeze` sea
 *    no-op. No es «nada que levantar»: es un intervalo en el que la flota
 *    escribió — en un cutover, escrituras que el motor nuevo no vio.
 *  - Freeze de OPERADOR ⇒ se levanta (este comando es su otra mitad).
 *  - Freeze de OTRO dueño (`reconcile`, `platform`) ⇒ NO se levanta sin
 *    `--fence`: levantar la barrera de una pasada viva es exactamente el
 *    A1.3 que el token cierra. `--fence=<n>` es la decisión humana explícita
 *    («ese proceso murió sin lease»), y tiene que coincidir con el fence
 *    vivo — un fence viejo no levanta la ventana de otro.
 */
export function unfreezePlan(
  status: (FreezeStatus & { expired?: boolean; checkedAtMs?: number }) | null,
  fence: number | undefined,
  nowMs?: number
): { action: 'noop' | 'lift' | 'refuse' | 'expired'; message: string } {
  if (status === null) {
    return { action: 'noop', message: 'No hay ningún freeze vivo: nada que levantar.' }
  }
  // **La ventana CADUCADA** (2.4.0-alpha.10): va antes que `--fence` porque el
  // incidente es el mismo lo pida quien lo pida — no queda barrera que
  // levantar, queda un intervalo en el que la flota ESCRIBIÓ.
  if (status.expired === true) {
    const when = status.untilMs === null ? '?' : new Date(status.untilMs).toISOString()
    const at = nowMs ?? status.checkedAtMs
    const since = status.untilMs !== null && at !== undefined ? ` (hace ${Math.max(0, at - status.untilMs)} ms)` : ''
    return {
      action: 'expired',
      message:
        `La ventana de ${status.holder} (${status.reason}, fence ${status.fence}) CADUCÓ el ${when}${since} y nadie ` +
        `la cerró: desde entonces las escrituras volvieron a entrar en toda la flota. En un cutover eso son ` +
        `escrituras que el motor nuevo no vio si la migración ya había corrido: no des el cutover por cerrado — ` +
        `repite la migración (authz:reconcile) dentro de una ventana sin caducidad (authz:freeze sin --lease-ms) ` +
        `antes de cambiar de driver.`,
    }
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
    // `lastFreezeStatus()` y no `freezeStatus()` (2.4.0-alpha.10): este es el
    // único lector que tiene que ver también la ventana CADUCADA.
    const status = await authorization.lastFreezeStatus()
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
    // Levantar (o limpiar la caducada) es CONDICIONAL por token: si otro proceso
    // cambió la fila entre la lectura y el UPDATE no se toca nada. Cierre del
    // auditor de alpha.10 (⚪ 4): la letra la decide el RESULTADO, releyendo la
    // fila — hasta el cierre la rama caducada afirmaba «la fila queda limpia»
    // sin mirar el booleano, y la de levantar decía «o venció su lease» en verde
    // (vencer no hace fallar el UPDATE: `releaseFreeze` no mira `untilMs`).
    const done = await authorization.unfreeze({ fence: status!.fence, holder: status!.holder })
    const after = done ? null : await authorization.lastFreezeStatus()
    const ahora = (s: NonNullable<typeof after>) =>
      `${s.holder} (${s.reason}, fence ${s.fence}, ${s.expired ? 'CADUCADA' : 'viva'})`
    // Cierre-2 · C4: si el UPDATE no casó pero la fila releída es LA MISMA (holder,
    // fence y motivo), nadie la cambió: la letra no puede afirmar «otro proceso».
    const unchanged =
      after !== null && after.fence === status!.fence && after.holder === status!.holder && after.reason === status!.reason
    if (plan.action === 'expired') {
      this.logger.error(plan.message)
      if (done) {
        this.logger.info('La fila queda limpia: un segundo authz:unfreeze ya no repite este error.')
      } else if (after === null) {
        this.logger.warning('La fila ya la había limpiado otro proceso entre la lectura y la limpieza: no se ha tocado nada.')
      } else if (unchanged) {
        this.logger.error(
          `La fila NO se ha limpiado y la fila NO cambió: sigue siendo ${ahora(after)}, pero el UPDATE condicional por ` +
            'su token no casó (rama «token no casa»). Es un defecto del paquete, no una carrera: repórtalo con esta línea.'
        )
      } else {
        this.logger.error(
          `La fila NO se ha limpiado: entre la lectura y la limpieza otro proceso la cambió y ahora es ${ahora(after)}. ` +
            'Vuelve a ejecutar authz:unfreeze para ver su estado.'
        )
      }
      this.exitCode = 1
      return
    }
    if (done) {
      this.logger.success(plan.message)
      return
    }
    if (after === null) {
      // Nadie lo sostiene ya: otro lo levantó entre medias. El objetivo del operador se cumple.
      this.logger.success('El freeze ya no estaba: otro proceso lo levantó entre la lectura y el levantamiento. Nada que hacer.')
      return
    }
    if (unchanged) {
      this.logger.error(
        `No se ha levantado nada y la fila NO cambió: sigue siendo ${ahora(after)}, pero el UPDATE condicional por su ` +
          'token no casó (rama «token no casa»). Es un defecto del paquete, no una carrera: repórtalo con esta línea.'
      )
      this.exitCode = 1
      return
    }
    this.logger.error(
      `No se ha levantado nada: entre la lectura y el levantamiento la fila cambió y ahora es ${ahora(after)}. ` +
        'Vuelve a ejecutar authz:unfreeze para decidir sobre ese freeze.'
    )
    this.exitCode = 1
  }
}
