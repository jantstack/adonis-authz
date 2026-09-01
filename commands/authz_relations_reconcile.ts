import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'
import type { RelationsReconcileOptions, RelationsReconcileReport } from '../src/relations/reconcile.js'
import type { AuthorizationManager } from '../src/manager.js'

/**
 * **La pasada de relaciones bajo la ventana DURABLE** (L-1 · J1, juez del
 * panel `{trx}`). `reconcileRelations` (`src/relations/`) no puede ver al
 * manager de roles (regla 2 de pureza), así que la ventana la abre el
 * comando, aquí, con la misma forma que `authz:reconcile` de roles:
 *
 *  - `--dry-run` **NO congela** (el verificador es read-only y está hecho
 *    para un cron: un mecanismo de indisponibilidad no se dispara desde ahí);
 *  - la pasada que ESCRIBE corre bajo `withFrozenWrites` con `kind:
 *    'reconcile'` y la ventana del OPERADOR como contexto propio (el cutover:
 *    corre dentro, no la toma, no la renueva, no la levanta); un freeze vivo
 *    de OTRA pasada es 423;
 *  - el reporte publica `frozen` —fence, lease y **`lapsed`**— y un lease
 *    perdido a mitad significa que la pasada NO se certifica (exit ≠ 0).
 *
 * Durante la ventana TODA escritura del paquete responde 503 `E_AUTHZ_FROZEN`
 * en la flota: las de roles y, desde L-1, las de relaciones
 * (`RelationsManager` pasa la misma barrera). Función exportada para tener su
 * caso sin montar un ace.
 */
export async function runRelationsReconcile(
  authorization: Pick<AuthorizationManager, 'withFrozenWrites'>,
  options: RelationsReconcileOptions & { toKey?: string }
): Promise<RelationsReconcileReport> {
  const { reconcileRelations } = await import('../src/relations/reconcile.js')
  if (options.dryRun === true) return reconcileRelations(options)
  const reason = `authz:relations:reconcile${options.toKey ? ` --to=${options.toKey}` : ''}`
  return authorization.withFrozenWrites(
    reason,
    async (window) => {
      const report = await reconcileRelations(options)
      report.frozen = { durable: true, lapsed: await window.lapsed(), leaseMs: window.leaseMs, fence: window.fence }
      return report
    },
    { kind: 'reconcile', operatorAsContext: true }
  )
}

/**
 * Las líneas del reporte de `authz:relations:reconcile` y si la pasada es
 * «limpia», en una función PURA (mismo patrón que `reconcileLines` de roles):
 * es lo único del comando que DECIDE algo, y así tiene su caso sin montar un
 * ace.
 *
 * Qué cuenta como deriva —y por tanto como exit ≠ 0—:
 *  - **`modelDrift`** (siempre): un tipo de relación presente en el ORIGEN que
 *    la config del DESTINO no declara. No cabe en su modelo fusionado, así que
 *    esas tuplas nunca resolverían allí — es la deriva del presupuesto de
 *    modelo compartido, no un detalle cosmético;
 *  - en `--dry-run`, **cualquier cosa que la pasada haría** (escribir, borrar o
 *    dejar `extra` sin `--prune`): es el verificador, y para eso está en CI.
 *
 * `extra` en una pasada que SÍ escribe (sin `--prune`) se AVISA —«repite con
 * --prune»— pero no tumba: el operador eligió no podar. Es la misma cortesía
 * que `authz:reconcile` de roles con la ventana del relay.
 */
export function relationsReconcileLines(report: RelationsReconcileReport): {
  lines: Array<{ level: 'log' | 'warning' | 'error' | 'success'; message: string }>
  clean: boolean
} {
  const lines: Array<{ level: 'log' | 'warning' | 'error' | 'success'; message: string }> = []

  lines.push({
    level: 'log',
    message:
      `relaciones: escritas ${report.written}, actualizadas ${report.updated}, borradas ${report.deleted}, ` +
      `iguales ${report.unchanged}, sobran ${report.extra}`,
  })

  // R-15: la caducada del origen es la pérdida DECLARADA de la migración (como
  // `expired` en roles, 3b-8 · B2): se dice, no es deriva.
  if (report.skipped.expired > 0) {
    lines.push({
      level: 'log',
      message:
        `${report.skipped.expired} tupla(s) del origen estaban CADUCADAS al instante de la pasada y no se ` +
        'migran (skipped.expired): no conceden nada y el destino no las necesita.',
    })
  }

  // L-0: la tupla VIVA que el destino no declara (tipo o relación, F-05) no se
  // escribió y se contó. No es una pérdida declarada como `expired` (que no
  // concede nada): es una relación que no llegó ⇒ deriva, exit ≠ 0.
  if (report.skipped.undeclared > 0) {
    lines.push({
      level: 'error',
      message:
        `${report.skipped.undeclared} tupla(s) del origen NO se escribieron porque su tipo de objeto o su relación ` +
        'no están declarados en defineRelationsConfig del DESTINO (skipped.undeclared, F-05 en el driver): ' +
        'decláralos en el destino (y republica su modelo) y repite la pasada.',
    })
  }

  for (const type of report.modelDrift) {
    lines.push({
      level: 'error',
      message:
        `El tipo de objeto '${type}' está en el ORIGEN pero NO en la config de relaciones del DESTINO: ` +
        'no cabe en su modelo fusionado y esas tuplas no resolverían allí. Declara el tipo en ' +
        'defineRelationsConfig del destino (y republica su modelo) antes de migrarlas.',
    })
  }

  // R-17: el seguro de borrado masivo. En una pasada REAL sin --allow-mass-delete
  // esto ya habría lanzado 500 antes de llegar aquí; en --dry-run NO lanza y lo
  // marca, así que el verificador tiene que sacarlo como deriva (exit ≠ 0).
  if (report.massDelete) {
    lines.push({
      level: 'error',
      message:
        `--prune borraría ${report.extra || report.deleted} tupla(s) del destino y el ORIGEN no aportó NI UNA ` +
        'utilizable: la firma de un --from equivocado o de un store vacío. En una pasada real es 500 ' +
        'E_AUTHZ_MASS_RECONCILE_REFUSED; si de verdad quieres vaciar el destino, --allow-mass-delete.',
    })
  }

  if (report.extra > 0 && !report.dryRun) {
    lines.push({
      level: 'warning',
      message:
        `${report.extra} tupla(s) del destino que el origen ya no respalda siguen ahí (no pasaste --prune): ` +
        'repite con --prune si quieres borrarlas.',
    })
  }

  // L-1 · J1: la garantía del freeze se DEMUESTRA (paridad con roles, 3b-7,
  // juez C4). Un lease perdido a mitad = escrituras pudieron entrar durante la
  // pasada y no aparecen en ningún contador ⇒ la pasada NO se certifica.
  if (report.frozen) {
    if (report.frozen.lapsed) {
      lines.push({
        level: 'error',
        message:
          `El LEASE del freeze se perdió a MITAD de la pasada (fence ${report.frozen.fence}): otras escrituras de ` +
          'relaciones o de roles pudieron entrar mientras se reconciliaba y no están en estos contadores. ' +
          'La pasada NO se certifica: repite authz:relations:reconcile.',
      })
    } else {
      lines.push({
        level: 'log',
        message:
          `Escrituras congeladas durante la pasada (fence ${report.frozen.fence}` +
          `${report.frozen.leaseMs === null ? ', ventana del operador' : `, lease ${report.frozen.leaseMs} ms`}): ` +
          'la ventana aguantó entera.',
      })
    }
  }

  const cambios = report.written + report.updated + report.deleted + (report.dryRun ? report.extra : 0)
  const clean =
    report.modelDrift.length === 0 &&
    report.skipped.undeclared === 0 &&
    !report.massDelete &&
    !(report.frozen?.lapsed === true) &&
    (!report.dryRun || cambios === 0)
  return { lines, clean }
}

/**
 * **`authz:relations:reconcile`** (Fase 4, lote 4-6) — migra las tuplas de
 * RELACIÓN de un `RelationsDriver` a otro, idempotente y bidireccional, nunca
 * silenciosa. Es el comando de plataforma que envuelve `reconcileRelations`
 * (lote 4-5), análogo a `authz:reconcile` de roles pero para el puerto
 * `RelationsDriver`.
 *
 *   node ace authz:relations:reconcile --to=openfga --dry-run   # el VERIFICADOR
 *   node ace authz:relations:reconcile --to=openfga             # migra
 *   node ace authz:relations:reconcile --to=openfga --prune     # y borra lo que el origen ya no respalda
 *
 * `--to`/`--from` nombran claves de `relations.drivers` en
 * `config/authorization.ts` (NO las de `drivers` de roles): las relaciones
 * tienen su propio puerto y sus propios drivers. La factory del driver
 * `openfga` de relaciones entra por el subpath `/openfga` DENTRO de ella, así
 * que este comando NUNCA importa el SDK (pureza).
 *
 * **Solo migra HECHOS de relación**: no hay árbol ni catálogo en `relations/`,
 * así que —a diferencia de `authz:reconcile` de roles— no hay fases de marcador
 * de raíz, proyección ni árbol. La migración es **POR partición**
 * (mono-tenant: `APP_SCOPE`, el default); para migrar otra partición se pasan
 * `--partition-type`/`--partition-uuid`, y migrar TODAS es iterar por el
 * consumidor (una migración de tenant es un caso natural).
 *
 * **`--dry-run` es el verificador y es read-only por contrato** (como el de
 * roles, S18): mismo recorrido, cero escrituras, los mismos números; NO hay
 * `--fix`. Además vigila la **deriva del modelo fusionado** (`modelDrift`): un
 * tipo del origen que el destino no declara sale como error.
 *
 * Es una operación de PLATAFORMA: no lleva actor, no se expone por HTTP.
 */
export default class AuthzRelationsReconcile extends BaseCommand {
  static commandName = 'authz:relations:reconcile'
  static description = 'Rebuild (or verify, with --dry-run) the relation tuples of one RelationsDriver from another'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.string({ description: 'Destination driver: a key of `relations.drivers` in config/authorization.ts' })
  declare to: string | undefined

  @flags.string({ description: 'Source driver (a key of `relations.drivers`); required when more than one is registered' })
  declare from: string | undefined

  @flags.boolean({ name: 'dry-run', description: 'Report what it would do and write nothing (this is the verifier)' })
  declare dryRun: boolean | undefined

  @flags.boolean({ description: 'Also delete the tuples the source no longer backs (leftovers)' })
  declare prune: boolean | undefined

  @flags.boolean({
    name: 'allow-mass-delete',
    description: 'Allow --prune to empty the destination when the source has no usable tuple (mass-delete safeguard)',
  })
  declare allowMassDelete: boolean | undefined

  @flags.string({ name: 'partition-type', description: 'Partition (tenant) scope type to migrate; default: app (mono-tenant)' })
  declare partitionType: string | undefined

  @flags.string({ name: 'partition-uuid', description: 'Partition (tenant) scope uuid; required with --partition-type' })
  declare partitionUuid: string | undefined

  async run() {
    if (!this.to) {
      this.logger.error(
        "Falta --to: 'node ace authz:relations:reconcile --to=openfga'. Es la clave del driver DESTINO en " +
          '`relations.drivers` de config/authorization.ts.'
      )
      this.exitCode = 1
      return
    }

    const config = this.app.config.get('authorization') as any
    const factories: Record<string, () => any> = config?.relations?.drivers ?? {}
    const keys = Object.keys(factories)
    if (keys.length === 0) {
      this.logger.error(
        'No hay `relations.drivers` en config/authorization.ts: declara los drivers de relaciones (por clave) ' +
          'para poder migrar sus tuplas.'
      )
      this.exitCode = 1
      return
    }

    // El ORIGEN: `--from` si se pasa; si no, el ÚNICO que no es el destino.
    let fromKey = this.from
    if (!fromKey) {
      const candidates = keys.filter((k) => k !== this.to)
      if (candidates.length !== 1) {
        this.logger.error(
          `No se puede elegir el ORIGEN solo: hay ${candidates.length} candidatos (${candidates.join(', ') || 'ninguno'}). ` +
            'Nómbralo con --from=<clave>: de dónde salen las tuplas decide lo que queda escrito.'
        )
        this.exitCode = 1
        return
      }
      fromKey = candidates[0]
    }
    if (!factories[this.to]) {
      this.logger.error(`El destino '${this.to}' no es una clave de relations.drivers (${keys.join(', ')}).`)
      this.exitCode = 1
      return
    }
    if (!factories[fromKey]) {
      this.logger.error(`El origen '${fromKey}' no es una clave de relations.drivers (${keys.join(', ')}).`)
      this.exitCode = 1
      return
    }

    // La partición (mono-tenant por defecto). El reconcile es POR partición.
    const partition =
      this.partitionType && this.partitionType !== 'app'
        ? { type: this.partitionType, uuid: this.partitionUuid ?? '' }
        : { type: 'app' as const, uuid: null }

    // La config del DESTINO, para vigilar la deriva del modelo fusionado en
    // --dry-run: es la persistida (una sola en el store compartido).
    const { readRelationsConfig } = await import('../src/relations_config_store.js')
    const toConfig = await readRelationsConfig().catch(() => undefined)

    const from = await factories[fromKey]()
    const to = await factories[this.to]()

    // L-1 · J1: la pasada que ESCRIBE corre bajo la ventana durable del
    // manager de roles (la misma fila `id = 2`, toda la flota); `--dry-run` no.
    const { default: authorization } = await import('../services/main.js')

    let report
    try {
      report = await runRelationsReconcile(authorization, {
        from,
        to,
        partition,
        dryRun: this.dryRun === true,
        prune: this.prune === true,
        allowMassDelete: this.allowMassDelete === true,
        toKey: this.to,
        ...(toConfig ? { toConfig } : {}),
      })
    } catch (error: any) {
      // R-17: el seguro de borrado masivo (500) sale como error de comando, no
      // como stack crudo. `--allow-mass-delete` es la salida humana.
      if (error?.code === 'E_AUTHZ_MASS_RECONCILE_REFUSED') {
        this.logger.error(String(error.message ?? error))
        this.exitCode = 1
        return
      }
      // L-1 · J1: un freeze vivo de OTRA pasada (423): dos migraciones no se
      // pisan; el mensaje nombra al dueño y cómo se levanta.
      if (error?.code === 'E_AUTHZ_FREEZE_HELD') {
        this.logger.error(String(error.message ?? error))
        this.exitCode = 1
        return
      }
      throw error
    }

    const { lines, clean } = relationsReconcileLines(report)
    for (const { level, message } of lines) this.logger[level](message)

    const resumen =
      `escritas ${report.written}, actualizadas ${report.updated}, borradas ${report.deleted}, ` +
      `iguales ${report.unchanged}, sobran ${report.extra}, caducadas omitidas ${report.skipped.expired}, ` +
      `no declaradas en el destino ${report.skipped.undeclared}`
    if (report.dryRun) {
      if (clean) {
        this.logger.success(`Sin deriva: '${this.to}' coincide con '${fromKey}' (${resumen}).`)
        return
      }
      this.logger.error(`DERIVA con '${this.to}': ${resumen}. No se ha escrito nada (--dry-run).`)
      this.exitCode = 1
      return
    }
    this.logger.success(`Relaciones de '${this.to}' reconciliadas desde '${fromKey}': ${resumen}.`)
    if (!clean) {
      this.logger.warning('Queda algo que esta pasada no arregla sola (mira las líneas de arriba).')
      this.exitCode = 1
    }
  }
}
