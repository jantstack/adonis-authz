import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'
import type { ReconcileReport } from '../src/types.js'

/**
 * Las líneas del reporte y si la pasada es «limpia», en una función PURA
 * (mismo patrón que `orphanLines`): es lo único del comando que decide algo,
 * y así tiene su caso sin montar un ace.
 *
 * Qué cuenta como deriva —y por tanto como exit ≠ 0—:
 *  - en `--dry-run`, **cualquier cosa que la pasada haría** (escribir,
 *    actualizar o borrar): es el verificador, y para eso está en CI;
 *  - siempre, lo que una pasada NO puede arreglar sola: **ciclos** en el
 *    árbol del consumidor, **entradas aparcadas** de la outbox y hechos que
 *    se quedan fuera (`skipped`) — incluidos los del scope que ya no
 *    resuelve, que solo se van con `--prune`.
 *
 * La ventana del relay (`pendingRelay`) se AVISA pero no tumba la pasada: es
 * una ventana de segundos por diseño, no una divergencia.
 */
export function reconcileLines(report: ReconcileReport): {
  lines: Array<{ level: 'log' | 'warning' | 'error' | 'success'; message: string }>
  clean: boolean
} {
  const lines: Array<{ level: 'log' | 'warning' | 'error' | 'success'; message: string }> = []
  const fase = (nombre: string, key: keyof ReconcileReport['phases']) => {
    const c = report.phases[key]
    if (c.written + c.updated + c.unchanged + c.extra + c.deleted === 0) return
    lines.push({
      level: 'log',
      message:
        `${nombre}: escritas ${c.written}, actualizadas ${c.updated}, iguales ${c.unchanged}, ` +
        `sobran ${c.extra}, borradas ${c.deleted}`,
    })
  }
  fase('marcador de raíz', 'root')
  fase('proyección del catálogo', 'catalog')
  fase('árbol', 'tree')
  fase('hechos', 'facts')

  for (const skip of report.details) {
    lines.push({ level: 'warning', message: `sin migrar (${skip.reason}) ${skip.kind}: ${skip.detail}` })
  }
  const motivos = Object.entries(report.skipped).sort(([a], [b]) => (a < b ? -1 : 1))
  for (const [reason, count] of motivos) {
    lines.push({ level: 'warning', message: `${count} sin migrar por '${reason}'` })
  }
  if (report.skipped['unknown-scope'] && !report.prune) {
    lines.push({
      level: 'warning',
      message:
        'Los hechos de un scope que YA NO RESUELVE siguen en el destino y volverían a conceder si el scope se ' +
        'restaura con el mismo uuid: repite con --prune para borrarlos.',
    })
  }
  if (report.drift.rootMarker) {
    lines.push({
      level: 'error',
      message:
        'Faltaba el MARCADOR DE RAÍZ (scope:app#rooted): sin él el store entero deniega, en silencio. ' +
        'Lo repone esta pasada y cada authz:catalog:sync.',
    })
  }
  for (const object of report.drift.multiParent) {
    lines.push({
      level: 'error',
      message: `${object} tenía MÁS DE UN PADRE en el destino: había otro escritor del árbol. Esta pasada lo deja con el del consumidor.`,
    })
  }
  if (report.drift.roleVisibility > 0) {
    lines.push({
      level: 'error',
      message:
        `${report.drift.roleVisibility} arista(s) de visibilidad de rol (invariante 18) estaban mal en el destino: ` +
        'una escritura que el relay pudo perder. Con la de MÁS, el destino concedía lo que el catálogo y el árbol de hoy no.',
    })
  }
  for (const cycle of report.cycles) {
    lines.push({
      level: 'error',
      message:
        `CICLO en el árbol del consumidor: ${cycle.join(' → ')} → ${cycle[0]}. Ninguna de sus aristas se escribe ` +
        '(el backend evalúa el ciclo y la herencia pasa a ser bidireccional), así que ese subárbol DENIEGA hasta que lo arregles.',
    })
  }
  if (report.drift.pendingRelay > 0) {
    lines.push({
      level: 'warning',
      message:
        `${report.drift.pendingRelay} cambio(s) del árbol encolados y sin relevar: el destino decide con el árbol VIEJO ` +
        'en esa ventana. Drena la cola (authz:scopes:relay) y repite si quieres una foto sin ventana.',
    })
  }
  if (report.drift.deadRelay > 0) {
    lines.push({
      level: 'error',
      message: `${report.drift.deadRelay} cambio(s) del árbol APARCADOS en la outbox: eso no es una ventana, es divergencia permanente.`,
    })
  }
  if (report.massDelete) {
    lines.push({
      level: 'error',
      message:
        'Esta pasada borraría hechos con `authz_assignments`/`authz_denies` VACÍAS: comprueba la conexión y qué driver ' +
        'está escribiendo los hechos antes de usar --allow-mass-delete.',
    })
  }

  const cambios = report.written + report.updated + report.deleted
  const clean =
    report.cycles.length === 0 &&
    report.drift.deadRelay === 0 &&
    report.drift.multiParent.length === 0 &&
    Object.keys(report.skipped).length === 0 &&
    (!report.dryRun || cambios === 0)
  return { lines, clean }
}

/**
 * **Migra —y verifica— entre drivers** (3b-3a). Es la única primitiva de
 * migración del paquete: `openfga:import` se borró en 3b-2k · K2 porque
 * llenaba el store con las tuplas de un modelo que ya no existe.
 *
 *   node ace authz:reconcile --to=openfga --dry-run   # el VERIFICADOR (CI)
 *   node ace authz:reconcile --to=openfga             # migra
 *   node ace authz:reconcile --to=openfga --prune     # y borra lo que el origen ya no respalda
 *
 * `--to` nombra una clave de `drivers` en `config/authorization.ts`, no el
 * driver activo: migrar es llenar el destino mientras el motor sigue
 * corriendo con el otro. `--to=database` es la dirección inversa y todavía no
 * existe (500 `E_AUTHZ_UNSUPPORTED` nombrando el método que falta).
 *
 * Qué migra hacia `openfga`: el marcador de raíz, la proyección del catálogo,
 * el árbol (desde `scopes.enumerateEdges`) y los hechos de `authz_*`. Es
 * IDEMPOTENTE (la segunda pasada escribe cero), reanudable (lee por lotes con
 * cursor y converge si se repite) y **nunca silenciosa**: cada cosa que no se
 * migra sale contada y con su motivo.
 *
 * `--dry-run` es el verificador y es **read-only por contrato** (panel 2,
 * cruce 4 · S18): mismo recorrido, cero escrituras y los mismos números. **No
 * hay ni habrá un `--fix`**: sería un mecanismo de concesión.
 *
 * Durante la pasada las escrituras del motor están congeladas (503
 * reintentable) y las lecturas siguen. Es una operación de PLATAFORMA: no
 * lleva actor, no mide rangos y no se expone por HTTP.
 */
export default class AuthzReconcile extends BaseCommand {
  static commandName = 'authz:reconcile'
  static description = 'Rebuild (or verify, with --dry-run) a driver from the authz_* tables and the consumer scope tree'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.string({ description: 'Destination driver: a key of `drivers` in config/authorization.ts' })
  declare to: string | undefined

  @flags.boolean({ name: 'dry-run', description: 'Report what it would do and write nothing (this is the verifier)' })
  declare dryRun: boolean | undefined

  @flags.boolean({ description: 'Also delete the facts the source no longer backs (dead scopes, leftovers)' })
  declare prune: boolean | undefined

  @flags.boolean({
    name: 'allow-mass-delete',
    description: 'Allow --prune to delete facts while authz_assignments/authz_denies are empty — check your connection first',
  })
  declare allowMassDelete: boolean | undefined

  @flags.number({ name: 'batch-size', description: 'Rows per source batch and operations per destination write (default 100)' })
  declare batchSize: number | undefined

  async run() {
    if (!this.to) {
      this.logger.error(
        "Falta --to: 'node ace authz:reconcile --to=openfga'. Es la clave del driver DESTINO en " +
          'config/authorization.ts, no el driver activo.'
      )
      this.exitCode = 1
      return
    }
    const { default: authorization } = await import('../services/main.js')
    const report = await authorization.reconcile({
      to: this.to,
      dryRun: this.dryRun === true,
      prune: this.prune === true,
      allowMassDelete: this.allowMassDelete === true,
      batchSize: this.batchSize,
    })

    const { lines, clean } = reconcileLines(report)
    for (const { level, message } of lines) this.logger[level](message)

    const resumen =
      `escritas ${report.written}, actualizadas ${report.updated}, iguales ${report.unchanged}, ` +
      `sobran ${report.extra}, borradas ${report.deleted}`
    if (report.dryRun) {
      if (clean) {
        this.logger.success(`Sin deriva: '${this.to}' coincide con authz_* y con tu árbol (${resumen}).`)
        return
      }
      this.logger.error(`DERIVA con '${this.to}': ${resumen}. No se ha escrito nada (--dry-run).`)
      this.exitCode = 1
      return
    }
    this.logger.success(`'${this.to}' reconciliado: ${resumen}.`)
    if (!clean) {
      this.logger.warning(
        'Queda algo que esta pasada no arregla sola (mira las líneas de arriba): repítela cuando lo hayas resuelto.'
      )
      this.exitCode = 1
    }
  }
}
