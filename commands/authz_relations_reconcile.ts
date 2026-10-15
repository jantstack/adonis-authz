import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'
import type { RelationsReconcileOptions, RelationsReconcileReport } from '../src/relations/reconcile.js'
import type { AuthorizationManager } from '../src/manager.js'
import { AuthorizationConfigError, StaleSourceRefusedError } from '../src/errors.js'

/**
 * **La ÚNICA vía pública para reconciliar relaciones** (L-1 · J1; cierre del
 * auditor de alpha.10 · R1/R4). `reconcileRelations` (`src/relations/`) es el
 * primitivo: no puede ver al manager de roles (regla 2 de pureza), así que no
 * sabe cuál es el driver ACTIVO ni puede tomar la ventana durable. Hasta el
 * cierre se exportaba desde la raíz del paquete y el README lo recomendaba para
 * K particiones: esa vía llegaba a la dirección rancia sin guard y sin freeze.
 * Ahora sale de la raíz y TODA migración de relaciones pasa por aquí —el
 * comando, un bucle por particiones de la plataforma—, que es el punto único
 * donde viven las dos garantías:
 *
 *  - **la dirección RANCIA** (alpha.10 · S1, gemelo de `manager.reconcile`):
 *    hacia el driver de relaciones activo (`relations.default ?? default`)
 *    ningún origen distinto pasa. **El origen y el destino se RESUELVEN aquí,
 *    por su clave, desde el config del manager** (R4): hasta el cierre la
 *    función recibía las instancias `from`/`to` y, aparte, las ETIQUETAS
 *    `toKey`/`fromKey`/`activeKey`, y juzgaba las etiquetas — un bucle con
 *    `fromKey === toKey` copiado y pegado, o un `activeKey` que contradecía al
 *    manager, escribía la compartición retirada en el activo. La identidad es
 *    la de la factory resuelta: dos claves con la MISMA factory son el mismo
 *    driver (un alias del activo también se niega);
 *  - **la ventana durable**: `--dry-run` **NO congela** (el verificador es
 *    read-only y está hecho para un cron); la pasada que ESCRIBE corre bajo
 *    `withFrozenWrites` con `kind: 'reconcile'` y la ventana del OPERADOR como
 *    contexto propio; un freeze vivo de OTRA pasada es 423; el reporte publica
 *    `frozen` —fence, lease, `window` y **`lapsed`**— y un lease perdido a
 *    mitad significa que la pasada NO se certifica (exit ≠ 0).
 *
 * Límite declarado (auditor · R5): el activo es el que dice el config del
 * PROCESO que ejecuta esto; un Job con otro entorno apaga el guard. El sello
 * durable del driver activo está en el roadmap (2.5).
 */
/**
 * **Las opciones PÚBLICAS de `runRelationsReconcile`** (cierre-2 de alpha.10 · C7):
 * las del primitivo sin `from`/`to` (instancias: retiradas) más las claves. Hasta el
 * cierre-2 la raíz exportaba `RelationsReconcileOptions` —la forma del primitivo, con
 * `from`/`to` obligatorios— y no esta.
 */
export type RunRelationsReconcileOptions = Omit<RelationsReconcileOptions, 'from' | 'to'> & {
  /** Clave (en `relations.drivers` del config del manager) del DESTINO. */
  toKey: string
  /** Clave del ORIGEN (el de `--from` o el elegido por descarte). */
  fromKey: string
  /** La salida humana de `E_AUTHZ_STALE_SOURCE_REFUSED`. */
  allowStaleSource?: boolean
}

/**
 * Límites DECLARADOS de la identidad (cierre-2 de alpha.10 · C1 y C6):
 *  - la identidad es la REFERENCIA de la factory: dos factories DISTINTAS que
 *    construyen el mismo backend (`fga: () => new OpenFgaRelationsDriver(…mismo
 *    store…)`) NO se detectan — el alias pasa el guard. No se construye nada antes
 *    del guard, así que no hay backend que comparar; identidad declarada por el
 *    driver ⇒ roadmap 2.5. Registra un alias con la MISMA referencia
 *    (`const fga = () => …; drivers: { openfga: fga, alias: fga }`) o no lo registres.
 *  - `authorization` es estructural (`Pick<…>`): un objeto que FALSEA
 *    `relationsDriverKey`/`relationsDriverFactory` decide el activo y las factories.
 *    Pásale el manager del servicio, nunca uno construido o envuelto a mano.
 */
export async function runRelationsReconcile(
  authorization: Pick<AuthorizationManager, 'withFrozenWrites' | 'relationsDriverKey' | 'relationsDriverFactory'>,
  options: RunRelationsReconcileOptions
): Promise<RelationsReconcileReport> {
  const { reconcileRelations } = await import('../src/relations/reconcile.js')
  const raw = options as Record<string, unknown>
  // Entradas que ya no gobiernan nada (L5: una opción inerte no cae en un
  // default en silencio). `from`/`to` como instancias y `activeKey` eran
  // justo las etiquetas desalineables del R4.
  const retiredOptions = ['from', 'to', 'activeKey'].filter((name) => raw[name] !== undefined)
  if (retiredOptions.length > 0) {
    throw new AuthorizationConfigError(
      `runRelationsReconcile: ${retiredOptions.map((n) => `\`${n}\``).join(', ')} ya no se acepta(n) (cierre de 2.4.0-alpha.10): ` +
        'el origen y el destino se resuelven por `fromKey`/`toKey` desde el config del manager, y el driver activo lo ' +
        'dice el manager (`relations.default ?? default`). Pasar instancias o un activo propio permitía que la etiqueta ' +
        'contradijera al driver y la dirección rancia pasara.'
    )
  }
  if (typeof options.toKey !== 'string' || typeof options.fromKey !== 'string') {
    throw new AuthorizationConfigError(
      'runRelationsReconcile: hacen falta `toKey` y `fromKey` (las claves de relations.drivers del destino y del ORIGEN) ' +
        'desde 2.4.0-alpha.10 — sin ellas no se puede negar la dirección rancia (re-escribir en el driver de relaciones ' +
        'ACTIVO lo que el origen dejó de ver en el cutover).'
    )
  }
  const { toKey, fromKey, allowStaleSource, ...rest } = options
  const toFactory = authorization.relationsDriverFactory(toKey)
  const fromFactory = authorization.relationsDriverFactory(fromKey)
  for (const [role, key, factory] of [['destino', toKey, toFactory], ['origen', fromKey, fromFactory]] as const) {
    if (typeof factory !== 'function') {
      throw new AuthorizationConfigError(
        `runRelationsReconcile: el ${role} '${key}' no es una clave de relations.drivers en el config del manager.`
      )
    }
  }
  const active = authorization.relationsDriverKey()
  /** Mismo driver ⇔ misma clave o misma factory resuelta (un alias es el mismo driver). */
  const sameDriver = (a: string, b: string) => a === b || authorization.relationsDriverFactory(a) === authorization.relationsDriverFactory(b)
  if (sameDriver(fromKey, toKey)) {
    throw new AuthorizationConfigError(
      `runRelationsReconcile: el origen '${fromKey}' y el destino '${toKey}' son el MISMO driver ` +
        `(${fromKey === toKey ? 'misma clave' : 'la misma factory bajo dos claves'}): no hay nada que migrar y un --prune ` +
        'se compararía consigo mismo. Nombra el otro driver.'
    )
  }
  const stale = sameDriver(toKey, active)
  const allowStale = allowStaleSource === true
  if (stale && !allowStale && options.dryRun !== true) {
    const alias = toKey === active ? '' : ` (la clave '${toKey}' resuelve la MISMA factory que el activo '${active}')`
    throw new StaleSourceRefusedError(
      `authz:relations:reconcile --to=${toKey} (origen '${fromKey}'): '${toKey}' es el driver de ` +
        `relaciones ACTIVO (relations.default ?? default)${alias} y el origen no lo es. Esa dirección re-escribiría en el driver ` +
        `activo tuplas que el origen ya no refleja: resucitaría las comparticiones retiradas desde el cutover (y con ` +
        `--prune borraría las creadas después). No se ha construido, leído, congelado ni escrito nada. Tras el cutover el driver ` +
        `activo ES la fuente de verdad de las relaciones: no hay nada que migrar hacia él; para volver atrás, migra en ` +
        `la otra dirección (--to=${fromKey} --from=${toKey}) ANTES de cambiar relations.default/default. ` +
        `Si de verdad el origen sigue siendo la fuente de verdad, la decisión humana es --allow-stale-source ` +
        `(allowStaleSource: true).`
    )
  }
  const from = await fromFactory!()
  const to = await toFactory!()
  const pass = () => reconcileRelations({ ...rest, from, to })
  const mark = (report: RelationsReconcileReport) => {
    if (stale) report.staleSource = { to: toKey, from: fromKey, allowed: allowStale }
    return report
  }
  if (options.dryRun === true) return mark(await pass())
  const reason = `authz:relations:reconcile --to=${toKey}`
  return authorization.withFrozenWrites(
    reason,
    async (window) => {
      const report = mark(await pass())
      report.frozen = {
        durable: true,
        lapsed: await window.lapsed(),
        leaseMs: window.leaseMs,
        fence: window.fence,
        ...(window.untilMs === undefined ? {} : { untilMs: window.untilMs }),
        ...(window.window === undefined ? {} : { window: window.window }),
      }
      return report
    },
    { kind: 'reconcile', operatorAsContext: true }
  )
}

/**
 * Cómo se nombra la ventana en la que corrió la pasada (2.4.0-alpha.10 · 3):
 * la del OPERADOR dice si caduca y cuándo — hasta alpha.9 una ventana abierta
 * con `--lease-ms` salía como «ventana del operador» a secas, sin caducidad.
 */
export function frozenWindowLabel(frozen: {
  leaseMs: number | null
  untilMs?: number | null
  window?: 'operator' | 'own' | 'enclosing'
}): string {
  // alpha.10 · S2: la ventana PROPIA se dice como tal — «no había ventana de
  // operador viva» es justo lo que el operador de un cutover necesita leer.
  if (frozen.window === 'own') {
    return `, ventana PROPIA de la pasada (lease ${frozen.leaseMs} ms): NO había ventana de operador viva`
  }
  if (frozen.window === 'enclosing') return `, ventana que ya sostenía este proceso`
  if (frozen.untilMs !== undefined) {
    return frozen.untilMs === null
      ? ', ventana del operador sin caducidad'
      : `, ventana del operador que CADUCA el ${new Date(frozen.untilMs).toISOString()} (le quedaban ${frozen.leaseMs} ms)`
  }
  return frozen.leaseMs === null ? ', ventana del operador' : `, lease ${frozen.leaseMs} ms`
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

  // ⚪ R2 (cierre-2 del lote A; linaje L8, «una operación destructiva lista lo
  // que destruye»): lo enumerado con una identidad fuera de la gramática, UNA
  // línea por tupla con su lado y su porqué. Nunca fue una pregunta del
  // llamante (invariante 5), así que nunca es un 422 que tumbe la pasada:
  //  - destino + prune: «se pedirá borrar» (dry-run; y dice que con los drivers
  //    del paquete la pasada real NO la borrará: a mano YA — ⚪ R2 del re-ataque
  //    al cierre-2, cierre-3) / «BORRADA» (real); si el DRIVER del destino la
  //    rechazó por el puerto, «NO se pudo borrar … a mano» (error: sigue ahí y
  //    la pasada no es limpia);
  //  - destino sin prune: sobra con motivo (warning; `extra` la cuenta);
  //  - origen: no se migra (la API no la puede escribir): deriva, a mano.
  let invalidRefused = 0
  for (const detail of report.details ?? []) {
    const what = `(${detail.reason}) ${detail.side}: ${detail.tuple} — ${detail.message}`
    if (detail.side === 'origen') {
      lines.push({
        level: 'error',
        message: `sin migrar ${what}. Es un dato del store de ORIGEN, no una pregunta: corrígela o bórrala a mano (SQL/SDK) y repite la pasada.`,
      })
      continue
    }
    if (detail.pruned === true) {
      lines.push({
        level: 'log',
        message: report.dryRun
          ? `con --prune se pedirá al driver del destino que la BORRE ${what}. OJO: con los drivers del paquete (database/openfga) la pasada real NO la borrará (su gramática en unrelate la rechaza, R-16) y saldrá con exit 1 hasta que la borres a mano (SQL/SDK): bórrala ya, no esperes a la pasada real.`
          : `BORRADA por --prune ${what}.`,
      })
      continue
    }
    if (detail.pruned === false) {
      invalidRefused += 1
      lines.push({
        level: 'error',
        message: `NO se pudo borrar con --prune ${what}: el driver del destino la rechaza por el puerto (su gramática en unrelate). Sigue ahí: bórrala a mano (SQL/SDK).`,
      })
      continue
    }
    lines.push({
      level: 'warning',
      message: `sobra ${what}: nadie del origen puede respaldarla; repite con --prune para pedir su borrado.`,
    })
  }

  // R-17: el seguro de borrado masivo. En una pasada REAL sin --allow-mass-delete
  // esto ya habría lanzado 500 antes de llegar aquí; en --dry-run NO lanza y lo
  // marca, así que el verificador tiene que sacarlo como deriva (exit ≠ 0).
  // **F-R2 (plan 2.5 · lote A; linaje L8, letra ≠ efecto)**: con el seguro
  // LEVANTADO (`--allow-mass-delete`) la pasada real YA vació el destino: la
  // letra lo dice así y es limpia (fue la decisión humana); en `--dry-run` dice
  // que la real lo HARÁ y sigue siendo deriva (haría algo). Sin la bandera, el
  // error de siempre. Tabla de verdad en `tests/relations_reconcile_cli.spec.ts`.
  const massDeleteLifted = report.massDelete && report.allowMassDelete === true
  if (massDeleteLifted) {
    lines.push({
      level: 'warning',
      message: report.dryRun
        ? `--prune borraría ${report.extra || report.deleted} tupla(s) del destino con un ORIGEN sin NI UNA utilizable; ` +
          '--allow-mass-delete está puesto, así que la pasada real las BORRARÁ. Comprueba el --from antes de correrla.'
        : `El seguro de borrado masivo se LEVANTÓ con --allow-mass-delete: se han borrado ${report.deleted} tupla(s) del destino ` +
          'con un ORIGEN que no aportó NI UNA utilizable. Era tu decisión; si el --from era el equivocado, repite la pasada desde el correcto.',
    })
  } else if (report.massDelete) {
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
          `${frozenWindowLabel(report.frozen)}): ` +
          'la ventana aguantó entera.',
      })
    }
  }

  // alpha.10 · S1: la dirección rancia se dice siempre; en el verificador es deriva.
  if (report.staleSource !== undefined) {
    const { to, from, allowed } = report.staleSource
    lines.push({
      level: 'warning',
      message:
        `dirección RANCIA: '${to}' es el driver de relaciones ACTIVO y las tuplas salen de '${from}', que dejó de verlas ` +
        'en el cutover — esta pasada resucita las comparticiones retiradas desde entonces (y con --prune borra las ' +
        'nuevas). ' +
        (allowed
          ? 'Levantada a sabiendas con --allow-stale-source.'
          : 'Sin --allow-stale-source la pasada de verdad se niega (E_AUTHZ_STALE_SOURCE_REFUSED).'),
    })
  }

  const cambios = report.written + report.updated + report.deleted + (report.dryRun ? report.extra : 0)
  const clean =
    !(report.dryRun && report.staleSource !== undefined && !report.staleSource.allowed) &&
    report.modelDrift.length === 0 &&
    report.skipped.undeclared === 0 &&
    (report.skipped.invalid ?? 0) === 0 &&
    invalidRefused === 0 &&
    !(report.massDelete && !massDeleteLifted) &&
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

  @flags.boolean({ description: 'Report what it would do and write nothing (this is the verifier)' })
  declare dryRun: boolean | undefined

  @flags.boolean({ description: 'Also delete the tuples the source no longer backs (leftovers)' })
  declare prune: boolean | undefined

  @flags.boolean({
    description: 'Allow --prune to empty the destination when the source has no usable tuple (mass-delete safeguard)',
  })
  declare allowMassDelete: boolean | undefined

  @flags.boolean({
    description:
      'Allow --to=<ACTIVE relations driver> from another source: rewrites into the serving driver tuples the source no longer reflects',
  })
  declare allowStaleSource: boolean | undefined

  @flags.string({ description: 'Partition (tenant) scope type to migrate; default: app (mono-tenant)' })
  declare partitionType: string | undefined

  @flags.string({ description: 'Partition (tenant) scope uuid; required with --partition-type' })
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

    // Cierre del auditor de alpha.10 · R4: las claves, las factories y el driver
    // ACTIVO salen del MISMO sitio — el manager de servicio (construido desde
    // config/authorization.ts) —, que es también quien toma la ventana. Hasta el
    // cierre el comando resolvía los drivers de `this.app.config` y le pasaba a
    // `runRelationsReconcile` las instancias y, aparte, las etiquetas.
    const { default: authorization } = await import('../services/main.js')
    const keys = authorization.relationsDriverKeys()
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
    if (authorization.relationsDriverFactory(this.to) === undefined) {
      this.logger.error(`El destino '${this.to}' no es una clave de relations.drivers (${keys.join(', ')}).`)
      this.exitCode = 1
      return
    }
    if (authorization.relationsDriverFactory(fromKey) === undefined) {
      this.logger.error(`El origen '${fromKey}' no es una clave de relations.drivers (${keys.join(', ')}).`)
      this.exitCode = 1
      return
    }

    // La partición (mono-tenant por defecto). El reconcile es POR partición.
    // Las DOS banderas van juntas o no va ninguna (cierre de alpha.9, 🟡 B del
    // auditor): media pareja reconciliaba `app` en silencio, escribía CERO y
    // salía `[success]` — la misma forma del 🔴 «migra 0 y reporta éxito» que
    // este lote cierra, sobreviviendo a una errata del runbook de cutover.
    if (this.partitionUuid && !this.partitionType) {
      this.logger.error(
        '--partition-uuid sin --partition-type: las dos banderas van juntas. ' +
          'Sin --partition-type se reconciliaría la partición RAÍZ (app) y tus tuplas por tenant no se migrarían.'
      )
      this.exitCode = 1
      return
    }
    // alpha.10 · 5 (sexto informe de COGNITIV): la variante que el cierre de
    // alpha.9 no cazó — pareja COMPLETA con `app` también reconciliaba la raíz
    // en silencio, tirando el uuid (una errata del runbook: `app` por el tipo).
    if (this.partitionType === 'app' && this.partitionUuid) {
      this.logger.error(
        `--partition-type=app con --partition-uuid=${this.partitionUuid}: la partición raíz no lleva uuid. ` +
          'O quitas --partition-uuid (reconciliar la raíz) o pones el tipo del tenant en --partition-type.'
      )
      this.exitCode = 1
      return
    }
    if (this.partitionType && this.partitionType !== 'app' && !this.partitionUuid) {
      this.logger.error(`--partition-type=${this.partitionType} exige --partition-uuid (el tenant concreto a reconciliar).`)
      this.exitCode = 1
      return
    }
    const partition =
      this.partitionType && this.partitionType !== 'app'
        ? { type: this.partitionType, uuid: this.partitionUuid! }
        : { type: 'app' as const, uuid: null }

    // La config del DESTINO, para vigilar la deriva del modelo fusionado en
    // --dry-run: es la persistida (una sola en el store compartido).
    const { readRelationsConfig } = await import('../src/relations_config_store.js')
    const toConfig = await readRelationsConfig().catch(() => undefined)

    // L-1 · J1: la pasada que ESCRIBE corre bajo la ventana durable del
    // manager de roles (la misma fila `id = 2`, toda la flota); `--dry-run` no.
    // Los drivers los construye `runRelationsReconcile`, DESPUÉS del guard.
    let report
    try {
      report = await runRelationsReconcile(authorization, {
        partition,
        dryRun: this.dryRun === true,
        prune: this.prune === true,
        allowMassDelete: this.allowMassDelete === true,
        allowStaleSource: this.allowStaleSource === true,
        toKey: this.to,
        fromKey,
        ...(toConfig ? { toConfig } : {}),
      })
    } catch (error: any) {
      // R-17: el seguro de borrado masivo (500) sale como error de comando, no
      // como stack crudo. `--allow-mass-delete` es la salida humana.
      if (error?.code === 'E_AUTHZ_MASS_RECONCILE_REFUSED' || error?.code === 'E_AUTHZ_STALE_SOURCE_REFUSED') {
        this.logger.error(String(error.message ?? error))
        this.exitCode = 1
        return
      }
      // L-1 · J1: un freeze vivo de OTRA pasada (423): dos migraciones no se
      // pisan; el mensaje nombra al dueño y cómo se levanta.
      if (error?.code === 'E_AUTHZ_FREEZE_HELD' || error?.code === 'E_AUTHZ_OPERATOR_WINDOW_EXPIRED') {
        this.logger.error(String(error.message ?? error))
        this.exitCode = 1
        return
      }
      // Cierre R4: origen y destino que resuelven el MISMO driver (misma clave o
      // alias de la misma factory) es un error de configuración de la pasada.
      if (error?.code === 'E_AUTHZ_CONFIG') {
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
      `no declaradas en el destino ${report.skipped.undeclared}` +
      (report.skipped.invalid ? `, fuera de la gramática en el origen ${report.skipped.invalid}` : '')
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
