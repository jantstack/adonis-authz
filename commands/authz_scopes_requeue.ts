import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'
import type { PendingScopeTreeChange, ScopeRequeueConflict, ScopeRequeueReport } from '../src/types.js'

/** Una entrada de la cola, en una línea (misma forma que en `authz:scopes:relay`). */
function linea(item: PendingScopeTreeChange): string {
  const { change } = item
  const scope = (s: { type: string; uuid?: string | null }) => `${s.type}:${s.uuid ?? ''}`
  const destino = change.op === 'detached' ? '' : ` → ${scope(change.parent)}`
  const intentos = item.attempts ? ` (intentos: ${item.attempts})` : ''
  const causa = item.lastError ? ` — ${item.lastError}` : ''
  return `#${item.id} ${change.op} ${scope(change.child)}${destino}${intentos}${causa}`
}

/**
 * Las líneas del comando y si la ejecución es «limpia», en una función PURA
 * (mismo patrón que `reconcileLines`/`orphanLines`): es lo único del comando
 * que decide algo, y así tiene su caso sin montar un ace.
 *
 *  - `refused`: el manager se NEGÓ (500 `E_AUTHZ_REQUEUE_REFUSED`). Se imprime
 *    el DIFF entero —cada aparcada y cada entrada APLICADA posterior que
 *    reaplicarla revertiría— y se sale ≠ 0, con las dos salidas: `--force`
 *    (que entra igual, con este mismo diff delante) y `authz:reconcile`.
 *  - `report`: se reencoló. Con `forced` y `overrides`, el diff se imprime
 *    como AVISO: forzar no es un éxito mudo.
 */
export function requeueLines(input: { refused?: ScopeRequeueConflict[]; report?: ScopeRequeueReport }): {
  lines: Array<{ level: 'log' | 'warning' | 'error' | 'success'; message: string }>
  clean: boolean
} {
  const lines: Array<{ level: 'log' | 'warning' | 'error' | 'success'; message: string }> = []
  const diff = (level: 'error' | 'warning', conflict: ScopeRequeueConflict) => {
    lines.push({
      level,
      message:
        `${level === 'error' ? 'NEGADO' : 'FORZADO'}: ${linea(conflict.parked)} está APARCADA y hay ` +
        `${conflict.applied.length} entrada(s) APLICADA(s) después sobre la misma clave de scope. Reencolarla las REVERTIRÍA ` +
        `(el store quedaría con un árbol que nunca existió, y con UN solo padre nada lo delata):`,
    })
    for (const applied of conflict.applied) lines.push({ level, message: `    revertiría ${linea(applied)}` })
    if (conflict.truncated) {
      lines.push({
        level,
        message: `    … y más: solo se listan las primeras ${conflict.applied.length} aplicadas posteriores sobre esa clave; el diff está CORTADO.`,
      })
    }
  }

  if (input.refused !== undefined) {
    for (const conflict of input.refused) diff('error', conflict)
    lines.push({
      level: 'warning',
      message:
        'No se ha reencolado NADA (todo o nada). Para recalcular el store con el árbol de HOY: ' +
        'node ace authz:reconcile --to=<driver>. Si de verdad quieres revertir esas entradas, repite con --force: ' +
        'imprime este mismo diff y entra igual.',
    })
    return { lines, clean: false }
  }

  const report = input.report!
  if (report.forced) for (const conflict of report.overrides) diff('warning', conflict)
  for (const item of report.requeued) lines.push({ level: 'log', message: `reencolada: ${linea(item)}` })
  lines.push({
    level: 'success',
    message:
      `${report.requeued.length} entrada(s) devuelta(s) a la cola con attempts = maxAttempts − 1: si la causa sigue rota ` +
      'vuelve(n) a aparcarse en UNA pasada; si la arreglaste, entra(n) a la primera. Corre node ace authz:scopes:relay.',
  })
  return { lines, clean: true }
}

/**
 * **Devuelve entradas APARCADAS de la outbox a la cola** (2.4.0-alpha.5 · R2b;
 * panel relay, cuestión 2).
 *
 *   node ace authz:scopes:requeue --id=12            # una
 *   node ace authz:scopes:requeue --id=12,13         # varias (o --id repetido)
 *   node ace authz:scopes:requeue --id=12 --force    # aunque revierta lo aplicado después (diff impreso)
 *
 * Una entrada aparcada (`sqlScopeOutbox({ maxAttempts })`, 5 por defecto)
 * no se reintenta sola: el relay la reporta en cada pasada y sale ≠ 0. Cuando
 * el operador arregla la causa —el padre que faltaba vuelve, el store se
 * reconcilia— este comando la devuelve a `pending()` con **`attempts =
 * maxAttempts − 1`**: entra a la primera si está arreglada y vuelve a
 * aparcarse en UNA sola pasada si no (así un requeue automatizado de lo
 * irreparable no es un grifo de aplazamiento para el resto del scope).
 *
 * **La sonda anti-reversión es del manager y no tiene excepción**: si después
 * de la aparcada se APLICÓ otra entrada sobre la misma clave de scope,
 * reencolarla reaplicaría el cambio viejo por encima del nuevo —un `moved`
 * viejo tras el nuevo deja el store con el padre VIEJO y un solo padre—. El
 * comando imprime ese diff y sale ≠ 0. **`--force` existe SOLO aquí**
 * (decisión del dueño del 2026-09-09 (2)): imprime el diff y entra igual. Nunca
 * en una ruta alcanzable por HTTP.
 *
 * Es una operación de PLATAFORMA (como `authz:scopes:relay`): sin actor, sin
 * `within`, y no se expone por HTTP.
 */
export default class AuthzScopesRequeue extends BaseCommand {
  static commandName = 'authz:scopes:requeue'
  static description = 'Return parked scope-tree outbox entries to the queue (refuses to revert later applied changes unless --force)'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.array({
    name: 'id',
    description: 'Outbox ids to requeue (the parked entries the relay reports), comma-separated or repeated',
  })
  declare id: string[] | undefined

  @flags.boolean({
    description: 'Requeue even if a later APPLIED entry shares a scope key (the diff is printed; the store WILL be reverted)',
  })
  declare force: boolean | undefined

  /** `--id=12,13` o `--id=12 --id=13`: ids numéricos como número, el resto como cadena. */
  static parseIds(values: string[] | undefined): Array<string | number> | undefined {
    if (values === undefined) return undefined
    return values
      .flatMap((value) => String(value).split(','))
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
      .map((value) => (/^\d+$/.test(value) ? Number(value) : value))
  }

  async run() {
    const ids = AuthzScopesRequeue.parseIds(this.id)
    if (ids === undefined || ids.length === 0) {
      this.logger.error('Falta --id: di QUÉ entradas aparcadas reencolar (las que reporta authz:scopes:relay). Sin ids no se reencola nada.')
      this.exitCode = 1
      return
    }
    const { default: authorization } = await import('../services/main.js')
    let result: ReturnType<typeof requeueLines>
    try {
      const report = await authorization.requeueScopeChanges(ids, { force: this.force === true })
      result = requeueLines({ report })
    } catch (error: any) {
      if (error?.code !== 'E_AUTHZ_REQUEUE_REFUSED') throw error
      result = requeueLines({ refused: error.conflicts })
    }
    for (const line of result.lines) this.logger[line.level](line.message)
    if (!result.clean) this.exitCode = 1
  }
}
