import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'
import type { RelationsReconcileReport } from '../src/relations/reconcile.js'

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
      `relaciones: escritas ${report.written}, borradas ${report.deleted}, ` +
      `iguales ${report.unchanged}, sobran ${report.extra}`,
  })

  for (const type of report.modelDrift) {
    lines.push({
      level: 'error',
      message:
        `El tipo de objeto '${type}' está en el ORIGEN pero NO en la config de relaciones del DESTINO: ` +
        'no cabe en su modelo fusionado y esas tuplas no resolverían allí. Declara el tipo en ' +
        'defineRelationsConfig del destino (y republica su modelo) antes de migrarlas.',
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

  const cambios = report.written + report.deleted + (report.dryRun ? report.extra : 0)
  const clean = report.modelDrift.length === 0 && (!report.dryRun || cambios === 0)
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

    const { reconcileRelations } = await import('../src/relations/reconcile.js')
    // La config del DESTINO, para vigilar la deriva del modelo fusionado en
    // --dry-run: es la persistida (una sola en el store compartido).
    const { readRelationsConfig } = await import('../src/relations_config_store.js')
    const toConfig = await readRelationsConfig().catch(() => undefined)

    const from = await factories[fromKey]()
    const to = await factories[this.to]()

    const report = await reconcileRelations({
      from,
      to,
      partition,
      dryRun: this.dryRun === true,
      prune: this.prune === true,
      ...(toConfig ? { toConfig } : {}),
    })

    const { lines, clean } = relationsReconcileLines(report)
    for (const { level, message } of lines) this.logger[level](message)

    const resumen = `escritas ${report.written}, borradas ${report.deleted}, iguales ${report.unchanged}, sobran ${report.extra}`
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
