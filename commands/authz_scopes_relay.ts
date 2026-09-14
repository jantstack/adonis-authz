import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'
import type { ScopeRelayQueue } from '../src/types.js'

/**
 * **La edad de la cola en el comando** (2.4.0-alpha.8; panel relay 2,
 * cuestión 5), en una función PURA (patrón `requeueLines`): qué se imprime y
 * si `--max-age` la convierte en salida ≠ 0.
 *
 *  - Sin cabeza con fecha (`pendingAgeMs === null`: cola vacía, solo
 *    aparcadas, o una outbox de terceros sin `createdAt`) no se dice nada y
 *    nunca se alarma.
 *  - Con edad, se INFORMA siempre (es lo que faltaba en el B2 de COGNITIV:
 *    diez pasadas con el store caído y nadie sabía desde cuándo).
 *  - **Solo con umbral** (`--max-age=<ms>`) y edad POR ENCIMA es `exceeded`
 *    (exit ≠ 0): sin umbral un cron no puede quedarse en rojo para siempre
 *    por una cola que simplemente tiene backlog. Un umbral inválido lanza.
 */
export function queueAgeLines(
  queue: ScopeRelayQueue,
  maxAgeMs: number | undefined,
  remaining: boolean = false
): { lines: Array<{ level: 'info' | 'warning' | 'error'; message: string }>; exceeded: boolean } {
  if (maxAgeMs !== undefined && !(Number.isInteger(maxAgeMs) && maxAgeMs >= 0)) {
    throw new TypeError(`authz:scopes:relay: --max-age debe ser un entero >= 0 en milisegundos (llegó ${String(maxAgeMs)})`)
  }
  if (queue.pendingAgeMs === null || queue.oldestPendingAt === null) {
    // «Cola vacía» y «no sé la edad» no son lo mismo (cierre alpha.8, 🟡 2 del
    // auditor): con entradas pendientes y una outbox que no devuelve `createdAt`
    // la alarma por edad no puede vigilar nada — y con `--max-age` eso es un
    // fallo, no un silencio.
    if (!remaining) return { lines: [], exceeded: false }
    const message =
      'Hay entradas pendientes pero la outbox no devuelve `createdAt` (par de capacidad `createdAt` del contrato): ' +
      'la edad de la cola es DESCONOCIDA y --max-age no puede vigilarla.'
    return maxAgeMs === undefined
      ? { lines: [{ level: 'warning', message }], exceeded: false }
      : { lines: [{ level: 'error', message }], exceeded: true }
  }
  const since = queue.oldestPendingAt.toISOString()
  if (maxAgeMs !== undefined && queue.pendingAgeMs > maxAgeMs) {
    return {
      exceeded: true,
      lines: [
        {
          level: 'error',
          message:
            `La entrada pendiente más antigua de la cola lleva ${queue.pendingAgeMs} ms sin aplicarse (desde ${since}), ` +
            `por encima de --max-age=${maxAgeMs}: la cola no avanza (¿el backend lleva caído desde entonces? un 503 no consume ` +
            'intento y no aparca nada). Mira `failures` de esta pasada.',
        },
      ],
    }
  }
  return {
    exceeded: false,
    lines: [{ level: 'info', message: `Cabeza de la cola: pendiente desde ${since} (${queue.pendingAgeMs} ms; medida con el reloj de quien encoló).` }],
  }
}

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
 *   node ace authz:scopes:relay --only=12,13    # SOLO esas entradas (2.4.0-alpha.5)
 *   node ace authz:scopes:relay --wait-lease-ms=5000   # espera el lease hasta 5 s en vez de salir `busy` (2.4.0-alpha.8)
 *   node ace authz:scopes:relay --max-age=300000       # exit ≠ 0 si la pendiente más antigua lleva > 5 min (2.4.0-alpha.8)
 *
 * **`--max-age`** (alpha.8, cuestión 5 del panel relay 2): el reporte lleva
 * SIEMPRE la edad de la cabeza global de la cola (`queue.pendingAgeMs`, con
 * el reloj de quien encoló) y se imprime; con umbral, superarlo es salida ≠ 0
 * — la alarma que faltaba cuando el store está caído (un 503 no consume
 * intento: `attempts` y `dead` se quedan a cero). Sin umbral solo informa.
 *
 * **`--only`** (alpha.5 · R1): releva solo los ids del recibo que devolvió
 * `scopes.attached/moved/detached` (`{ queued }`). El orden por clave no se
 * relaja: una entrada pedida que dependa de una anterior sin aplicar y no
 * pedida sale «aplazada» (`depends-on:<id>`), nunca fuera de orden; `--only`
 * vacío es un error, no «todo». La salida es POR ENTRADA (`entries`), y los
 * ids que no estaban ni pendientes ni aparcados se dicen (`missing`).
 *
 * **Lo aparcado tapona por clave** (alpha.5 · R2a): un `attached`/`moved`
 * que nombre un scope de una entrada APARCADA sale «aplazado» con
 * `parked:<id>` en todas las pasadas hasta que alguien mire la aparcada; un
 * `detached` de esa clave se aplica igual (una purga nunca queda bloqueada).
 * Y un 503 del backend NO consume intento: la caída del store es común a
 * todas las entradas y no dice nada de ninguna.
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
    description: 'List the pending tree changes without applying any of them',
  })
  declare dryRun: boolean | undefined

  @flags.number({ description: 'Stop after applying this many changes (the rest stays pending)' })
  declare limit: number | undefined

  @flags.number({ description: 'How many pending changes to read per round trip' })
  declare batchSize: number | undefined

  @flags.array({
    description: 'Apply ONLY these outbox ids (the receipt of scopes.*), comma-separated or repeated; dependencies are deferred, never skipped',
  })
  declare only: string[] | undefined

  @flags.number({
    description: 'Wait up to this many ms for the relay lease instead of reporting busy at once (default 0; needs a pool >= 2)',
  })
  declare waitLeaseMs: number | undefined

  @flags.number({
    description: 'Exit ≠ 0 if the oldest pending entry of the whole queue is older than this many ms (without it the age is only reported)',
  })
  declare maxAge: number | undefined

  /** `--only=12,13` o `--only=12 --only=13`: ids numéricos como número, el resto como cadena. */
  static parseOnly(values: string[] | undefined): Array<string | number> | undefined {
    if (values === undefined) return undefined
    return values
      .flatMap((value) => String(value).split(','))
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
      .map((value) => (/^\d+$/.test(value) ? Number(value) : value))
  }

  async run() {
    const { default: authorization } = await import('../services/main.js')
    const only = AuthzScopesRelay.parseOnly(this.only)
    if (only !== undefined && only.length === 0) {
      this.logger.error('--only está vacío: relevar «nada» no es relevar «todo». Quita --only para drenar la cola entera.')
      this.exitCode = 1
      return
    }
    // alpha.10 · S7 (auditoría de sistema): el umbral se valida ANTES de tocar
    // la cola. Hasta alpha.9 `queueAgeLines` lanzaba DESPUÉS de relevar: la
    // pasada aplicaba y marcaba entradas y el comando reventaba con un
    // TypeError sin decir qué había aplicado.
    if (this.maxAge !== undefined && !(Number.isInteger(this.maxAge) && this.maxAge >= 0)) {
      this.logger.error(
        `--max-age debe ser un entero >= 0 en milisegundos (llegó ${String(this.maxAge)}). No se ha relevado nada.`
      )
      this.exitCode = 1
      return
    }
    const report = await authorization.relayScopeChanges({
      dryRun: this.dryRun === true,
      limit: this.limit,
      batchSize: this.batchSize,
      only,
      ...(this.waitLeaseMs === undefined ? {} : { waitForLeaseMs: this.waitLeaseMs }),
    })

    // La EDAD de la cola, siempre; con `--max-age`, la alarma (2.4.0-alpha.8).
    const age = queueAgeLines(report.queue, this.maxAge, report.remaining)
    for (const line of age.lines) this.logger[line.level](line.message)
    if (age.exceeded) this.exitCode = 1

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
    // Cierre-2 · C2 (gemelo): un id PEDIDO aparcado más allá del primer lote de
    // `dead` (acotado a `batchSize`) llega en `entries`; se nombra igual.
    if (only !== undefined) {
      const listed = new Set(report.dead.map((item) => String(item.id)))
      for (const entry of report.entries) {
        if (entry.status !== 'dead' || listed.has(String(entry.id))) continue
        this.logger.error(`APARCADO tras agotar los intentos: ${linea(entry)}${entry.reason ? ` — ${entry.reason}` : ''}`)
        this.exitCode = 1
      }
    }
    // Cierre-2 · C2: `missing` (no está en la cola) ≠ `notEvaluated` (PENDIENTE y
    // la pasada no llegó: alcanzó --limit). Hasta el cierre-2 los dos salían como
    // «no estaba ni pendiente ni aparcado … o no existe», con exit 0.
    const notEvaluated = only === undefined ? [] : (report.notEvaluated ?? [])
    const limite = this.limit === undefined ? 'el --limit por defecto' : `--limit=${this.limit}`
    const rama = report.dryRun ? '--dry-run' : 'pasada que aplica'
    const notEvaluatedLines = () => {
      if (notEvaluated.length === 0) return
      for (const id of notEvaluated) {
        this.logger.error(
          `#${id} está PENDIENTE y esta pasada NO lo evaluó (${rama}): alcanzó ${limite} antes de llegar a él. ` +
            (report.dryRun ? 'No se sabe si se aplicaría.' : 'No se ha aplicado: el cambio no ha aterrizado.')
        )
      }
      this.logger.error(
        `${notEvaluated.length} de los ids pedidos NO se evaluaron por el límite de la pasada ` +
          `(${notEvaluated.map((id) => `#${id}`).join(', ')}): repite con un --limit mayor (o sin él).`
      )
      this.exitCode = 1
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
      // Cierre del auditor de alpha.10 · R3 (gemelo de S6 en --dry-run): con
      // `--only` la pregunta es «¿qué fue de LO PEDIDO?» también aquí. Hasta el
      // cierre esta rama retornaba antes del bloque S6 y `--dry-run --only=999`
      // (errata) decía «La outbox del árbol está vacía» en verde sin nombrar el id.
      // Misma letra por id que la pasada que aplica; el resumen dice su rama.
      if (only !== undefined) {
        for (const id of report.missing) {
          this.logger.warning(`#${id} no estaba ni pendiente ni aparcado: ya lo aplicó otra pasada, o no existe.`)
        }
        notEvaluatedLines()
      }
      if (report.wouldApply.length === 0) {
        if (report.dead.length > 0) this.exitCode = 1
        if (only !== undefined) {
          if (report.missing.length > 0 && notEvaluated.length === 0) {
            this.logger.warning(
              `--dry-run: ninguno de los ids pedidos está pendiente (${report.missing.map((id) => `#${id}`).join(', ')}: ` +
                'ni pendientes ni aparcados). No hay nada de LO PEDIDO que propagar; si no los aplicó otra pasada, revisa los ids.'
            )
          }
          return
        }
        if (report.dead.length === 0) this.logger.success('La outbox del árbol está vacía: nada que propagar.')
        return
      }
      this.logger.warning(
        `${report.wouldApply.length} cambio(s) del árbol sin propagar. No se ha aplicado nada: repite sin --dry-run. ` +
          `Mientras tanto el backend decide con el árbol VIEJO.`
      )
      // alpha.10 · S5: lo APARCADO es exit ≠ 0 «mientras exista» (README), haya
      // o no pendientes. Hasta alpha.9 un cron con --dry-run perdía la
      // divergencia permanente justo cuando además había tráfico.
      if (report.dead.length > 0) this.exitCode = 1
      return
    }

    // Qué fue de cada entrada, una a una (`entries`): la pasada no es atómica
    // y un contador no permite retomar nada. Lo aparcado ya se dijo arriba.
    for (const entry of report.entries) {
      if (entry.status === 'applied') this.logger.log(`aplicado: ${linea(entry)}`)
      if (entry.status === 'deferred') {
        const motivo = entry.reason?.startsWith('parked:')
          ? `aplazado por APARCADO (${entry.reason}): no se aplica hasta que alguien mire esa entrada`
          : `aplazado (${entry.reason ?? 'depende de una entrada anterior sin aplicar'}): corre el relay completo`
        this.logger.warning(`${motivo}: ${linea(entry)}`)
      }
    }
    for (const id of report.missing) {
      this.logger.warning(`#${id} no estaba ni pendiente ni aparcado: ya lo aplicó otra pasada, o no existe.`)
    }
    notEvaluatedLines()

    if (report.failures.length > 0) {
      for (const item of report.failures) {
        this.logger.error(
          `falló #${item.id} (${item.change.op} ` +
            `${item.change.child.type}:${item.change.child.uuid ?? ''}): ${item.error}` +
            (item.transient ? ' — el backend no respondió: este fallo NO consume intento' : '')
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
    // alpha.10 · S6: con `--only` la pregunta es «¿aterrizó LO QUE PEDÍ?», no
    // «¿está vacía la cola?». Hasta alpha.9 un id aplazado (o una errata)
    // imprimía «La outbox del árbol está vacía» en verde: el script de alta de
    // tenant daba por relevado un cambio que no había aterrizado.
    if (only !== undefined) {
      const deferred = report.entries.filter((entry) => entry.status === 'deferred')
      if (deferred.length > 0) {
        this.logger.error(
          `${deferred.length} de los ids pedidos NO se ha aplicado (aplazado, arriba el motivo): ` +
            `${deferred.map((entry) => `#${entry.id}`).join(', ')}. El cambio no ha aterrizado en el backend.`
        )
        this.exitCode = 1
      }
      if (report.applied.length === 0) {
        if (deferred.length === 0 && notEvaluated.length === 0 && report.missing.length > 0) {
          this.logger.warning(
            `Ninguno de los ids pedidos se ha aplicado en esta pasada (${report.missing.map((id) => `#${id}`).join(', ')}: ` +
              'ni pendientes ni aparcados). Si no los aplicó otra pasada, revisa los ids.'
          )
        }
        return
      }
    }
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
