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
 *    árbol del consumidor, **entradas aparcadas** de la outbox, **cadenas
 *    por encima del techo de profundidad** (`drift.tooDeep`, alpha.5 · R0: un
 *    503 esperando en `facts`) y hechos que se quedan fuera (`skipped`) —
 *    incluidos los del scope que ya no resuelve, que solo se van con
 *    `--prune`.
 *
 * La ventana del relay (`pendingRelay`) se AVISA pero no tumba la pasada: es
 * una ventana de segundos por diseño, no una divergencia. **Y lo AJENO de un
 * store compartido tampoco** (2.4.0-alpha.9 · B): esas tuplas tienen otro
 * dueño, se imprimen con su tipo y jamás son deriva — contarlas dejaba
 * `clean = false` para siempre en cualquier despliegue con relaciones. Y **`expired`
 * tampoco tumba** (3b-8 · B2): es la pérdida DECLARADA de la migración, no
 * concede en ningún driver y nada barre las filas caducadas del origen, así
 * que contarla como deriva dejaba el exit 1 clavado para siempre a la
 * primera caducidad real.
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
  // **De dónde salieron los hechos** (3b-5), lo primero: es la diferencia
  // entre una MIGRACIÓN y una pasada de mantenimiento contra el driver
  // activo, y con ella se leen todos los números de abajo.
  if (report.factsFrom !== undefined) {
    lines.push(
      report.factsFrom === report.to
        ? {
            level: 'log',
            message:
              `hechos: los del propio '${report.to}' — es el driver ACTIVO, así que sus hechos son SUYOS y no ` +
              `los de authz_assignments/authz_denies. Esta pasada rehace lo derivado (marcador de raíz, ` +
              `proyección del catálogo, árbol y visibilidad de rol) y no escribe hechos; con --prune borra los de ` +
              `scopes que ya no resuelven, los caducados, los de roles o permisos que el catálogo o el modelo ya no ` +
              `tienen (y los que sobran). ` +
              `Si lo que quieres es MIGRAR desde las tablas, nómbralas: --from=<driver cuyos hechos son authz_*>.`,
          }
        : { level: 'log', message: `hechos: leídos de ${report.factsFrom}` }
    )
  }
  // **La dirección RANCIA** (2.4.0-alpha.10): destino = el driver ACTIVO,
  // origen = otro. Sin `--allow-stale-source` solo llega aquí un `--dry-run`
  // (la pasada que escribe es 500 en el manager) y es DERIVA: una pasada así
  // resucitaría lo revocado desde el cutover.
  if (report.staleSource !== undefined) {
    const { to, from, allowed } = report.staleSource
    lines.push({
      level: 'warning',
      message:
        `dirección RANCIA: '${to}' es el driver ACTIVO y los hechos salen de '${from}', que dejó de verlos en el ` +
        'cutover — esta pasada re-escribe en el driver activo lo que el origen ya no refleja (resucita las ' +
        'revocaciones hechas desde entonces). ' +
        (allowed
          ? 'Levantada a sabiendas con --allow-stale-source.'
          : `Sin --allow-stale-source la pasada de verdad se niega (E_AUTHZ_STALE_SOURCE_REFUSED); para verificar ` +
            `el driver activo, la pasada de mantenimiento es sin --from: authz:reconcile --to=${to} --dry-run.`),
    })
  }
  fase('marcador de raíz', 'root')
  fase('proyección del catálogo', 'catalog')
  fase('árbol', 'tree')
  fase('hechos', 'facts')

  for (const skip of report.details) {
    // 🟡 A4 (auditor del lote A): lo podado se LISTA, con su `kind`, también en --dry-run.
    if (skip.pruned) {
      const verb = report.dryRun ? 'se BORRARÍA con --prune' : 'BORRADO por --prune'
      lines.push({ level: 'log', message: `${verb} (${skip.reason}) ${skip.kind}: ${skip.detail}` })
      continue
    }
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
  // **F-R1 (plan 2.5 · lote A; linaje L8)**: lo que la pasada de MANTENIMIENTO
  // descartó Y BORRÓ con --prune (el origen es el propio store) no «queda sin
  // migrar»: es un bucket aparte, se dice como lo que es y no es deriva.
  for (const [reason, count] of Object.entries(report.pruned ?? {}).sort(([a], [b]) => (a < b ? -1 : 1))) {
    lines.push({
      level: 'log',
      message: report.dryRun
        ? `${count} hecho(s) del propio store por '${reason}' se BORRARÍAN con --prune (son de este store: no hay otro sitio donde arreglarlos).`
        : `${count} hecho(s) del propio store por '${reason}' BORRADOS por --prune (mantenimiento: eran de este store y no respaldaban nada).`,
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
  // **El store COMPARTIDO** (2.4.0-alpha.9 · B). Con `openfga` las tuplas de
  // `relations/` viven en el mismo store y esta pasada las VE: se dice en voz
  // alta —con los tipos, que es lo único que permite reconocer uno que ya no
  // se declara—, no se cuentan como deriva y no se tocan ni con `--prune`.
  // Antes caían en `extra` y `--prune` las borraba (60 de 60 medidas),
  // reportando `clean = true`: el verde MUDO de una pasada destructiva.
  const foreign = report.foreign
  if (foreign !== undefined && foreign.tuples > 0) {
    const porTipo = Object.entries(foreign.types)
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([type, count]) => `${type} (${count})`)
      .join(', ')
    lines.push({
      level: 'log',
      message:
        `ajenas: ${foreign.tuples} tupla(s) de tipos que esta pasada NO gobierna [${porTipo}] — el store está ` +
        'COMPARTIDO con otro subsistema (las relaciones de relations/, o un modelo anterior de otro dueño): ' +
        'ni se borran, ni cuentan como deriva.',
    })
    if (report.prune) {
      lines.push({
        level: 'log',
        message: `--prune ha respetado ${foreign.tuples} tupla(s) ajenas: solo borra lo de esta pasada.`,
      })
    }
    if (foreign.relations !== undefined && (foreign.unknown ?? 0) > 0) {
      lines.push({
        level: 'warning',
        message:
          `${foreign.unknown} de esas tuplas no las reclama nadie: no son de esta pasada y su tipo tampoco está ` +
          'declarado en relations.config (un modelo anterior de otro subsistema, o un tipo que se retiró). ' +
          'Este paquete ya no las barre: míralas a mano.',
      })
    }
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
  for (const scope of report.drift.tooDeep ?? []) {
    lines.push({
      level: 'error',
      message:
        `${scope} está a MÁS de ${report.drift.tooDeepLimit ?? '?'} saltos de app: el modelo facts no resuelve esa cadena de ` +
        'forma fiable (authorize responde 503, nunca false, para todo ese subárbol). Es legal en database y una caída en ' +
        'openfga. Aplana el árbol, o declara scopes.maxDepth (y sube OPENFGA_RESOLVE_NODE_LIMIT en el servidor).',
    })
  }
  // alpha.10 · 3: la ventana del OPERADOR adoptada dice si caduca y cuándo
  // (antes el reporte la daba por eterna aunque se abriese con --lease-ms).
  // alpha.10 · S2: y SIEMPRE en qué ventana corrió — la del operador y una
  // propia eran letra a letra iguales, y «tomé mi ventana porque no había
  // ninguna» es lo que delata un cutover cuya ventana ya no estaba.
  if (report.frozen !== undefined && !report.frozen.lapsed && report.frozen.window === 'own') {
    lines.push({
      level: 'warning',
      message:
        `La pasada tomó SU PROPIA ventana (fence ${report.frozen.fence}, lease ${report.frozen.leaseMs} ms) y la soltó al ` +
        'terminar: NO había ventana de operador viva. Si esta pasada era parte de un cutover, la flota vuelve a escribir ' +
        'ya — abre la ventana con authz:freeze antes de cambiar de driver.',
    })
  }
  if (report.frozen !== undefined && !report.frozen.lapsed && report.frozen.window === 'enclosing') {
    lines.push({
      level: 'log',
      message: `La pasada corrió dentro de la ventana que ya sostenía este proceso (fence ${report.frozen.fence}).`,
    })
  }
  if (report.frozen !== undefined && report.frozen.untilMs !== undefined && !report.frozen.lapsed) {
    lines.push(
      report.frozen.untilMs === null
        ? {
            level: 'log',
            message: `La pasada corrió dentro de la ventana del operador (fence ${report.frozen.fence}), sin caducidad.`,
          }
        : {
            level: 'warning',
            message:
              `La pasada corrió dentro de la ventana del operador (fence ${report.frozen.fence}), que CADUCA el ` +
              `${new Date(report.frozen.untilMs).toISOString()} (le quedaban ${report.frozen.leaseMs} ms al empezar): ` +
              'si el cutover no termina antes, las escrituras vuelven solas — ciérrala con authz:unfreeze.',
          }
    )
  }
  if (report.frozen?.lapsed) {
    lines.push({
      level: 'error',
      message:
        'El LEASE del freeze se perdió a MITAD de la pasada (una pausa más larga que el lease, la base caída, o ' +
        'alguien levantó la ventana): hubo un intervalo en el que otros procesos pudieron escribir, y lo que ' +
        'escribieran no está en ningún contador. La pasada NO se certifica: repítela dentro de una ventana entera.',
    })
  }
  // **F-R2 (plan 2.5 · lote A; linaje L8)**: con el seguro LEVANTADO
  // (`--allow-mass-delete`) la pasada real YA borró — la letra lo dice así, en
  // vez de «borraría … antes de usar --allow-mass-delete». Tabla de verdad
  // massDelete × allowMassDelete × dryRun en `tests/reconcile.spec.ts`.
  if (report.massDelete && report.allowMassDelete === true) {
    const origen = report.to === 'database' ? 'el ORIGEN' : `el ORIGEN (${report.factsFrom ?? 'authz_assignments/authz_denies'})`
    lines.push({
      level: 'warning',
      message: report.dryRun
        ? `Esta pasada borraría ${report.deleted} hecho(s) con ${origen} sin devolver NI UNO; --allow-mass-delete está puesto, ` +
          'así que la pasada real los BORRARÁ. Comprueba el origen antes de correrla.'
        : `El seguro de borrado masivo se LEVANTÓ con --allow-mass-delete: se han borrado ${report.deleted} hecho(s) con ${origen} ` +
          'sin devolver NI UNO. Era tu decisión; si el origen era el equivocado, repite la pasada desde el correcto.',
    })
  } else if (report.massDelete) {
    lines.push({
      level: 'error',
      message:
        report.to === 'database'
          ? 'Esta pasada borraría hechos y el ORIGEN no ha devuelto NI UNO: comprueba el --from y el store antes de ' +
            'usar --allow-mass-delete.'
          : `Esta pasada borraría hechos y el ORIGEN (${report.factsFrom ?? 'authz_assignments/authz_denies'}) no ha ` +
            'devuelto NI UNO: comprueba la conexión y qué driver está escribiendo los hechos antes de usar ' +
            '--allow-mass-delete.',
    })
  }

  const cambios = report.written + report.updated + report.deleted
  // **`expired` no es deriva** (3b-8 · B2). Es la ÚNICA pérdida DECLARADA de
  // la migración (README, contrato de migración): una asignación caducada no
  // concede en ningún driver (invariante 3), no hay scheduler que barra sus
  // filas del ORIGEN (a propósito) y ninguna escritura en el DESTINO puede
  // «arreglarla». Contarla como deriva hacía el verde del verificador
  // INALCANZABLE con datos reales: a la primera caducidad, exit 1 para
  // siempre — el CI que el CHANGELOG promete verde no existía. Sigue saliendo
  // contada («N sin migrar por 'expired'»); lo que no hace es tumbar la
  // pasada. Las caducadas que SOBRAN en el destino sí son deriva
  // (`extra-fact`), y su barrido existe: `--prune`.
  const drifting = Object.keys(report.skipped).filter((reason) => reason !== 'expired')
  const clean =
    report.cycles.length === 0 &&
    report.drift.deadRelay === 0 &&
    report.drift.multiParent.length === 0 &&
    // Una cadena por encima del techo es un 503 esperando (alpha.5 · R0): deriva.
    (report.drift.tooDeep?.length ?? 0) === 0 &&
    drifting.length === 0 &&
    // La garantía del freeze se DEMUESTRA (3b-7, juez C4): un lease perdido a
    // mitad es una ventana en la que otros pudieron escribir ⇒ exit ≠ 0.
    report.frozen?.lapsed !== true &&
    // La dirección rancia en el verificador es deriva (2.4.0-alpha.10): la
    // pasada que certificaría haría daño.
    !(report.dryRun && report.staleSource !== undefined && !report.staleSource.allowed) &&
    (!report.dryRun || cambios === 0)
  return { lines, clean }
}

/**
 * **Migra —y verifica— entre drivers** (3b-3a). Es la única primitiva de
 * migración del paquete: `openfga:import` se borró en 3b-2k · K2 porque
 * llenaba el store con las tuplas de un modelo que ya no existe.
 *
 *   node ace authz:reconcile --to=openfga --dry-run   # el VERIFICADOR (CI)
 *   node ace authz:reconcile --to=openfga             # migra, o MANTIENE (ver abajo)
 *   node ace authz:reconcile --to=openfga --prune     # y borra lo que el origen ya no respalda
 *
 * `--to` nombra una clave de `drivers` en `config/authorization.ts`, no el
 * driver activo: migrar es llenar el destino mientras el motor sigue
 * corriendo con el otro.
 *
 * **De dónde salen los HECHOS** (3b-5): de quien sea su fuente de verdad, y
 * la pasada lo dice en su primera línea (`report.factsFrom`).
 *  - Si `--to` es el driver ACTIVO y sus hechos viven en su backend
 *    (`capabilities.hierarchyFacts`, el `openfga` de esta versión), los
 *    hechos son los SUYOS: la pasada es de MANTENIMIENTO —rehace lo derivado
 *    y aplica el barrido de visibilidad del invariante 18— y no escribe
 *    hechos; con `--prune` borra los de scopes que ya no resuelven, los
 *    caducados y los de roles/permisos retirados (y los que sobran) —
 *    alpha.10: hasta alpha.9 esta línea decía que no borraba ningún hecho y con
 *    `--prune` los borraba. `authz_assignments`/`authz_denies` no son su
 *    fuente: después de un cutover a `facts` están congeladas, y
 *    reconstruir desde ellas resucitaba lo revocado y —con `--prune`—
 *    borraba los denies vivos.
 *  - Con `--from=<driver>` mandas tú: si ese driver es el `database` del
 *    paquete, los hechos son sus tablas y `--to=openfga` es la MIGRACIÓN de
 *    un solo sentido de siempre.
 *
 * Qué migra hacia `openfga`: el marcador de raíz, la proyección del catálogo,
 * el árbol (desde `scopes.enumerateEdges`) y los hechos de `authz_*`.
 *
 * Qué migra hacia `database` (3b-3b, la VUELTA): **solo los hechos**, leídos
 * del origen por el puerto `enumerateFacts` (páginas con cursor). El ÁRBOL no
 * se migra —el driver `database` lo lee de tus tablas en cada pregunta, que
 * son su fuente de verdad— y el CATÁLOGO tampoco, que es propiedad local
 * siempre. Por eso en esa dirección las fases `marcador de raíz`,
 * `proyección del catálogo` y `árbol` son cero: no hay nada derivado que
 * rehacer, y el cero lo dice.
 *
 * El origen se elige solo si es inequívoco: con dos drivers registrados es el
 * que no es el destino; con más de un candidato hay que decirlo con
 * `--from=<driver>`, porque de dónde salen los hechos decide lo que va a
 * quedar escrito.
 *
 * Las dos direcciones son IDEMPOTENTES (la segunda pasada escribe cero),
 * reanudables (leen por lotes con cursor y convergen si se repiten) y **nunca
 * silenciosas**: cada cosa que no se migra sale contada y con su motivo.
 *
 * `--dry-run` es el verificador y es **read-only por contrato** (panel 2,
 * cruce 4 · S18): mismo recorrido, cero escrituras y los mismos números. **No
 * hay ni habrá un `--fix`**: sería un mecanismo de concesión.
 *
 * Durante la pasada que ESCRIBE, las escrituras del motor están congeladas
 * (503 reintentable) y las lecturas siguen. **Con `--dry-run` NO se congela**
 * (3b-6): el verificador no escribe nada, así que no tiene nada que proteger,
 * y está publicado para correrlo en CI y en un cron — justo el sitio desde el
 * que un mecanismo de indisponibilidad se dispara solo. Es una operación de
 * PLATAFORMA: no lleva actor, no mide rangos y no se expone por HTTP.
 */
export default class AuthzReconcile extends BaseCommand {
  static commandName = 'authz:reconcile'
  static description = 'Rebuild (or verify, with --dry-run) a driver from the authz_* tables and the consumer scope tree'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.string({ description: 'Destination driver: a key of `drivers` in config/authorization.ts' })
  declare to: string | undefined

  @flags.string({
    description: 'Source driver (a key of `drivers`). Only needed when more than one registered driver can be the source',
  })
  declare from: string | undefined

  @flags.boolean({ description: 'Report what it would do and write nothing (this is the verifier)' })
  declare dryRun: boolean | undefined

  @flags.boolean({ description: 'Also delete the facts the source no longer backs (dead scopes, leftovers)' })
  declare prune: boolean | undefined

  @flags.boolean({
    description: 'Allow --prune to delete facts while authz_assignments/authz_denies are empty — check your connection first',
  })
  declare allowMassDelete: boolean | undefined

  @flags.boolean({
    description:
      'Allow --to=<ACTIVE driver> --from=<another>: rewrites into the serving driver facts the source no longer reflects (resurrects revocations made since the cutover)',
  })
  declare allowStaleSource: boolean | undefined

  @flags.number({ description: 'Rows per source batch and operations per destination write (default 100)' })
  declare batchSize: number | undefined

  @flags.number({
    description: 'Declared cap on the destination dump this pass holds in memory (default 1000000); above it, 500 E_AUTHZ_RECONCILE_TOO_LARGE before writing anything',
  })
  declare maxTuples: number | undefined

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
    let report: ReconcileReport
    try {
      report = await authorization.reconcile({
        to: this.to,
        ...(this.from !== undefined ? { from: this.from } : {}),
        dryRun: this.dryRun === true,
        prune: this.prune === true,
        allowMassDelete: this.allowMassDelete === true,
        allowStaleSource: this.allowStaleSource === true,
        batchSize: this.batchSize,
        maxTuples: this.maxTuples,
      })
    } catch (error: any) {
      // La dirección rancia (2.4.0-alpha.10) es una negativa con letra, no un
      // stack: el mensaje ya nombra la dirección, el riesgo y la salida.
      // **F-R3 (plan 2.5 · lote A; gemelo de `authz:relations:reconcile`)**: el
      // seguro de borrado masivo (500) y un freeze VIVO de otra pasada (423)
      // también son negativas con letra —el mensaje nombra al dueño, el fence y
      // cómo se levanta—, no un error crudo: paridad con el comando gemelo.
      if (
        error?.code === 'E_AUTHZ_STALE_SOURCE_REFUSED' ||
        error?.code === 'E_AUTHZ_OPERATOR_WINDOW_EXPIRED' ||
        error?.code === 'E_AUTHZ_MASS_RECONCILE_REFUSED' ||
        error?.code === 'E_AUTHZ_FREEZE_HELD'
      ) {
        this.logger.error(String(error.message))
        this.exitCode = 1
        return
      }
      throw error
    }

    const { lines, clean } = reconcileLines(report)
    for (const { level, message } of lines) this.logger[level](message)

    const resumen =
      `escritas ${report.written}, actualizadas ${report.updated}, iguales ${report.unchanged}, ` +
      `sobran ${report.extra}, borradas ${report.deleted}`
    if (report.dryRun) {
      if (clean) {
        this.logger.success(
          `Sin deriva: '${this.to}' coincide con ${report.factsFrom ?? 'authz_*'} y con tu árbol (${resumen}).`
        )
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
