import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'
import type { RelationsReconcileReport } from '../src/relations/reconcile.js'
import { RELATION_USERSET_RESIDUE_DELETE } from '../src/relations/define_relations_config.js'
import { denyReachLine } from '../src/relations/deny_reach.js'
import { RelationConfigError } from '../src/errors.js'
// Plan 2.5 · lote B · B7: la vía pública vive en su subpath (`src/relations_reconcile.ts`,
// `@jantstack/adonis-authz/relations/reconcile`); este módulo es el COMANDO y la importa de allí.
import { runRelationsReconcile } from '../src/relations_reconcile.js'

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
 * que `authz:reconcile` de roles con la ventana del relay. **Salvo el residuo
 * del destino que nadie borra** (`invalid-identity`, `userset-unsupported` y,
 * desde el cierre 3 · 🟠 N9, `undeclared` — la fila cuya relación o tipo el
 * destino ya no declara; cierre 2 del lote B · 🟡 N3): ése es deriva con o sin
 * `--prune`, y el consejo solo cuenta lo que `--prune` borraría de verdad y
 * solo si no se pasó.
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

  // Lote D · D2: los denies, en su PROPIA línea (prefijo estable «denies:»), solo si la pasada tocó o vio alguno. Los
  // contadores de arriba son allows + denies; esta línea es el subconjunto (analista §4.7).
  const denies = report.denies
  if (denies && Object.values(denies).some((n) => n > 0)) {
    lines.push({
      level: 'log',
      message:
        `denies: escritos ${denies.written}, rehechos ${denies.updated}, borrados ${denies.deleted}, ` +
        `iguales ${denies.unchanged}, sobran ${denies.extra}`,
    })
  }

  // Lote D · D2 (S6/R2-5): un deny que la pasada NO puede migrar. Solo llega en `--dry-run` (la real lanza 500 con la
  // misma letra): es DERIVA, una línea por tipo/relación y motivo, con el prefijo ESTABLE «deny NO migrable».
  for (const refusal of report.denyRefused ?? []) {
    lines.push({
      level: 'error',
      message:
        `deny NO migrable (${refusal.reason}) ${refusal.objectType}#${refusal.relation}: ${refusal.message}. ` +
        'La pasada real se NIEGA (500 E_AUTHZ_DENY_MIGRATION_REFUSED) sin escribir nada — ni los allows: escribirlos sin ' +
        // Cierre 1 de D2 · 🟡 6: la receta de SU motivo (la decide el plan, `refusal.recipe`), no una genérica.
        `el deny concedería lo que el origen niega. Receta: ${refusal.recipe}`,
    })
  }

  // Lote RC · sublote (8): el DETECTOR del alcance de los denies (solo si la pasada lo pidió: `--dry-run`). Una línea por
  // hallazgo con su prefijo ESTABLE (punto 7) y su receta: «deny con alcance ENCOGIDO» / «deny HUÉRFANO» (persistida →
  // servida) y «línea base RANCIA» (servida → persistida, firma (8 · rancia)) son deriva (exit ≠ 0). Sin línea base y con
  // denies vivos sin juzgar, la línea «alcance de denies: SIN línea base y N deny(s) vivos sin juzgar» y exit 0 (firma
  // (8 · `--dry-run`), g2: el runbook no persiste la config y no cambia). Sin nada de eso, UNA línea que dice qué se comparó.
  if (report.denyReach !== undefined) {
    const { baseline, findings, stale, unjudged } = report.denyReach
    for (const finding of [...findings, ...stale]) {
      lines.push({ level: 'error', message: `${denyReachLine(finding)} (lado: ${finding.sides.join(', ')})` })
    }
    if (baseline === 'none' && unjudged > 0) {
      lines.push({
        level: 'warning',
        message:
          `alcance de denies: SIN línea base y ${unjudged} deny(s) vivos sin juzgar (no hay config persistida en authz_relations_config): ` +
          `solo se buscaron huérfanos, y un estrechamiento de su alcance NO se ve sin línea base. Si usas deny, persistir la config es ` +
          `paso obligatorio de release: adóptala una vez con saveRelationsConfig(spec, { establishBaseline: true }) y vigila con ` +
          `checkRelationsConfigDenyReach (el detector de un solo driver).`,
      })
    } else if (findings.length === 0 && stale.length === 0) {
      lines.push({
        level: 'log',
        message:
          baseline === 'persisted'
            ? 'alcance de denies: ningún deny vivo de la partición encogió ni quedó huérfano entre la config persistida (línea base) y la que sirve este proceso, y la línea base no es más estrecha que lo servido.'
            : 'alcance de denies: SIN línea base (no hay config persistida en authz_relations_config) y ningún deny vivo en la partición que juzgar.',
      })
    }
  }

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
  // que destruye») + cierre 1 (🟠 1/🟠 2) y cierre 2 (🟡 N3, UNIFICACIÓN) del lote
  // B: lo enumerado con una identidad fuera de la gramática (`invalid-identity`)
  // y el residuo pre-2.5 de B3 (`userset-unsupported`), UNA línea por tupla con
  // su lado y su porqué. Nunca fue una pregunta del llamante (invariante 5), así
  // que nunca es un 422 que tumbe la pasada. Y UNA regla para los dos motivos
  // (coordinador, 2026-10-15): un residuo del DESTINO que ningún driver del
  // paquete borra se lista con `error` y el prefijo ESTABLE «sobra (<motivo>)
  // destino:», es deriva (exit ≠ 0) en los CUATRO modos (prune × dry-run)
  // —ninguna bandera lo toca: nunca un DELETE de plataforma ni un `unrelate`
  // que los drivers del paquete rechazarían (R-16)—, dice «--prune NO lo borra»
  // (`pruned: false`, con --prune) o «tampoco lo borraría» (sin --prune), lleva
  // la receta y JAMÁS «repite con --prune». El del ORIGEN no se migra: deriva, a
  // mano. Hasta el cierre 2, `invalid-identity` sin --prune era un warning con
  // exit 0 y el consejo falso «repite con --prune» (que tampoco lo quitaba).
  // El verificador queda rojo HASTA que se ejecute la receta — y dice qué y cómo.
  let destResidue = 0
  let pendingRenewals = 0
  for (const detail of report.details ?? []) {
    const what = `(${detail.reason}) ${detail.side}: ${detail.tuple} — ${detail.message}`
    if (detail.side === 'origen') {
      lines.push({
        level: 'error',
        message:
          detail.reason === 'userset-unsupported'
            ? `sin migrar ${what}. Es un residuo pre-2.5 (B3) del store de ORIGEN: el destino no lo admite por ninguna puerta y ningún --prune lo toca. Bórrala a mano (los tres motores): ${RELATION_USERSET_RESIDUE_DELETE} y repite la pasada.`
            : detail.reason === 'invalid-condition'
              ? `sin migrar ${what}. Es una tupla cuya condición el paquete no escribe ni sabe leer (L11): no se migra como permanente ni como caducada. Revísala y corrígela o bórrala a mano (SDK/CLI de OpenFGA) y repite la pasada.`
              : `sin migrar ${what}. Es un dato del store de ORIGEN, no una pregunta: corrígela o bórrala a mano (SQL/SDK) y repite la pasada.`,
      })
      continue
    }
    if (detail.reason === 'renewal-unsafe') {
      // Cierre 2 de D2 · 🟠 N1: la membresía NO se renovó (su grupo transporta un deny y el destino renueva con dos
      // Write). Deriva con su receta; prefijo ESTABLE «sin renovar (renewal-unsafe) destino:» (punto 7).
      pendingRenewals += 1
      lines.push({ level: 'error', message: `sin renovar ${what}.` })
      continue
    }
    if (detail.pruned === true) {
      // El paquete ya no lo emite (cierre 2 · N3): un reporte de un harness de terceros anterior.
      lines.push({ level: 'log', message: `BORRADA por --prune ${what}.` })
      continue
    }
    destResidue += 1
    const verdict = detail.pruned === false ? 'NO' : 'tampoco'
    // Cierre 3 del lote B · 🟠 N9: el tercer motivo, con el MISMO prefijo estable
    // «sobra (<motivo>) destino:» (punto 7). La fila cuya relación (o tipo) el
    // DESTINO ya no declara: `unrelate` la rechaza por F-05, así que ningún
    // --prune la borra; la receta es retirarla a mano O volver a declarar la
    // relación en el destino (y re-guardar la config persistida), y repetir.
    lines.push({
      level: 'error',
      message:
        detail.reason === 'userset-unsupported'
          ? `sobra ${what}. Es un residuo pre-2.5 (B3) del DESTINO: --prune ${verdict} lo borra${
              detail.pruned === false ? '' : 'ría'
            } (nunca un DELETE de plataforma sobre una fila que la API no admite). Bórrala a mano (los tres motores): ${RELATION_USERSET_RESIDUE_DELETE} y repite la pasada.`
          : detail.reason === 'invalid-condition'
            ? `sobra ${what}. Es una tupla del DESTINO con una condición que el paquete no escribe ni sabe leer (L11): presente e intocable —--prune ${verdict} la borra${
                detail.pruned === false ? '' : 'ría'
              }, y su clave no se reescribe desde el origen—. Revísala y bórrala a mano (SDK/CLI de OpenFGA) y repite la pasada.`
          : detail.reason === 'deny-conditional'
            ? `sobra ${what}. Es un deny CONDICIONAL del DESTINO (con caducidad, escrito fuera del paquete) que el driver destino no puede rehacer permanente (openfga no reemplaza la misma clave en un Write, M5): niega solo mientras viva (si ya venció, no niega nada) y su partición queda NEGADA (línea «partición NEGADA»: cero escrituras en ella).`
            : detail.reason === 'undeclared'
            ? `sobra ${what}. Es una fila del DESTINO cuya relación (o tipo) el destino YA NO declara (F-05): --prune ${verdict} la borra${
                detail.pruned === false ? '' : 'ría'
              } (unrelate la rechaza por F-05 y la pasada no insiste: nunca un DELETE de plataforma). Sigue ahí: retírala a mano (SQL/SDK) o vuelve a declarar la relación en el destino (y re-guarda su config persistida) y repite la pasada.`
            : `sobra ${what}. Es un dato del DESTINO fuera de la gramática: --prune ${verdict} la borra${
                detail.pruned === false ? '' : 'ría'
              } (ningún driver del paquete la admite en unrelate, R-16, y la pasada no se la pide a nadie: nunca un DELETE de plataforma). Sigue ahí: corrígela o bórrala a mano (SQL/SDK) y repite la pasada.`,
    })
  }

  // Cierre 5 de D2 (decisión del dueño §2026-10-16 (10), opción A): la PARTICIÓN NEGADA — ≥ 1 `renewal-unsafe` o
  // `deny-conditional`: cero escrituras y cero borrados en ella; el resto migra. Deriva (exit ≠ 0) con el prefijo ESTABLE
  // «partición NEGADA» (punto 7): qué partición, por qué, que su destino queda COMO ESTABA, la deriva que queda a la vista
  // y la receta (honesta: sin atomicRenewal no hay forma sin ventana).
  for (const refusal of report.partitionsRefused ?? []) {
    const causes = refusal.causes.map((cause) => `(${cause.reason}) ${cause.tuple}`)
    // Cierre 6 de D2 · ⚪ D5-3 (E3): «COMO ESTABA» no es estático — cuándo empieza a conceder el destino y qué.
    const evolves = (refusal.evolves ?? []).map(
      (e) => `a partir de ${e.at} el destino concederá a ${e.member} lo que cortan ${e.cut.join(', ')} (si otro camino se lo da; el origen lo sigue negando)`
    )
    const later = evolves.length > 0 ? ` OJO, ese estado EVOLUCIONA: ${evolves.slice(0, 5).join('; ')}${evolves.length > 5 ? '; …' : ''}.` : ''
    lines.push({
      level: 'error',
      message:
        `partición NEGADA ${refusal.partition}: ${causes.length} causa(s) por las que la pasada no puede escribir en ella sin conceder de más (una ventana entre dos Write, una tupla que el paquete no sabe leer, o una cadena de grupos anidados más larga que el techo del destino) — ` +
        `${causes.slice(0, 5).join('; ')}${causes.length > 5 ? '; …' : ''}. Cero escrituras y cero borrados en esta partición ` +
        `(también en la pasada real${report.prune === true ? ' y con --prune' : ''}): su destino queda COMO ESTABA, con la deriva ` +
        `previa a la vista (por escribir ${refusal.pending.write}, por renovar ${refusal.pending.update}, por borrar ` +
        `${refusal.pending.delete}).${later} El resto de particiones migra. Receta: ${refusal.recipe}`,
    })
  }

  // Cierre 2 de D2 · ⚪ N3/🟡 N3: el RESIDUO del orden — membresías de un ciclo del grafo de precedencias. El estado final
  // es el correcto (no es deriva): se AVISA, con el prefijo ESTABLE «orden SIN garantía». Cierre 5 de D2 (⚪ D4-4): desde
  // el cierre 4 una RENOVACIÓN de membresía entra en el grafo (en `now` ni entra ni sale: lo hace cuando vence la
  // caducidad más corta), así que la letra lo dice, y dice que el corte puede conceder en un instante POSTERIOR.
  if ((report.orderResidue?.length ?? 0) > 0) {
    lines.push({
      level: 'warning',
      message:
        `orden SIN garantía: ${report.orderResidue!.length} membresía(s) de esta pasada se contradicen en el orden (el mismo ` +
        'sujeto entra o sale de grupos que se cortan entre sí —o una RENOVACIÓN, que entra o sale cuando vence la caducidad ' +
        'más corta—: cada uno trae un deny que corta un allow del otro); un corte entre ellas puede conceder, ya o en un ' +
        'instante posterior, lo que ni el estado inicial ni el final concedían en ese instante. El estado final es el ' +
        `correcto. Si eso importa, aplícalas en dos pasadas. (${report.orderResidue!.slice(0, 5).join('; ')}${report.orderResidue!.length > 5 ? '; …' : ''})`,
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

  // Cierre 2 del lote B · 🟡 N3: el consejo «repite con --prune» SOLO cuando no
  // se pasó `--prune` (el reporte lo lleva; ausente = no pasado) Y queda algo
  // que `--prune` borra DE VERDAD: `extra` menos el residuo del destino que nadie
  // borra. Hasta el cierre 2 salía con `extra > 0` a secas, justo debajo de la
  // línea «--prune NO lo borra» de una pasada que YA llevaba --prune.
  const prunable = report.extra - destResidue
  if (prunable > 0 && !report.dryRun && report.prune !== true) {
    lines.push({
      level: 'warning',
      message:
        `${prunable} tupla(s) del destino que el origen ya no respalda siguen ahí (no pasaste --prune): ` +
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
    (report.skipped.usersetUnsupported ?? 0) === 0 &&
    destResidue === 0 &&
    pendingRenewals === 0 &&
    (report.partitionsRefused?.length ?? 0) === 0 &&
    (report.denyRefused?.length ?? 0) === 0 &&
    (report.denyReach?.findings.length ?? 0) === 0 &&
    (report.denyReach?.stale.length ?? 0) === 0 &&
    !(report.massDelete && !massDeleteLifted) &&
    !(report.frozen?.lapsed === true) &&
    (!report.dryRun || cambios === 0)
  return { lines, clean }
}

/**
 * **La pasada que revienta A MITAD dice qué quedó escrito, por partición** (plan 2.5 · lote D · D2; roadmap 2.5, 🟡 3
 * del auditor de alpha.6): con el reporte parcial que viaja en el error (`error.report`, `partial: true`). Prefijo
 * ESTABLE «pasada PARCIAL:» (punto 7). Función PURA.
 */
export function partialReportLines(report: RelationsReconcileReport): string[] {
  const lines = [
    `pasada PARCIAL: escritas ${report.written}, actualizadas ${report.updated}, borradas ${report.deleted} antes del fallo ` +
      '(la pasada es idempotente: repítela para terminar).',
  ]
  // Cierre 2 de D2 · 🟠 N1: la escritura que FALLÓ ya había aplicado parte — una renovación de `openfga` (delete + write)
  // cuyo write no entró: los contadores no la cuentan, pero el destino CAMBIÓ (jamás «sin escribir nada»).
  if (report.written + report.updated + report.deleted === 0) {
    lines.push(
      'pasada PARCIAL: la escritura que falló YA había aplicado parte (una renovación del destino: el delete entró y el write ' +
        'no) — el destino CAMBIÓ aunque los contadores digan 0; repite la pasada.'
    )
  }
  for (const row of report.partitions ?? []) {
    lines.push(
      `pasada PARCIAL: partición ${row.partition} · ${row.status === 'done' ? 'TERMINADA' : row.status === 'failed' ? 'REVENTÓ aquí' : row.status === 'refused' ? 'NEGADA (cero escrituras)' : 'sin tocar'}` +
        ` (escritas ${row.written}, actualizadas ${row.updated}, borradas ${row.deleted}; denies escritos ${row.denies.written})`
    )
  }
  return lines
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
    // **Plan 2.5 · lote B · B5** (analista §4.7, auditor R2-5; linaje L5): hasta
    // 2.5.0-alpha.1 era `readRelationsConfig().catch(() => undefined)` — un
    // FALLO de lectura seguía sin config y en silencio (sin vigilar la deriva;
    // con el deny, sin la puerta del 500 del plan). Tres ramas, cada una con su
    // línea: fallo ⇒ error + exit 1 ANTES de construir, congelar o escribir;
    // `null` («no hay config persistida», relaciones opt-in) ⇒ sigue y lo dice;
    // leída ⇒ sigue y lo dice.
    const { readRelationsConfig } = await import('../src/relations_config_store.js')
    let toConfig: Awaited<ReturnType<typeof readRelationsConfig>>
    try {
      toConfig = await readRelationsConfig()
    } catch (error: any) {
      // Cierre 1 del lote B · 🟡 7: la fila persistida EXISTE y se leyó, pero NO
      // valida en 2.5 (clave desconocida de B2, ciclo de B1, JSON corrupto…):
      // antes de 2.5 `saveRelationsConfig` guardaba el spec TAL CUAL, claves
      // tiradas en silencio incluidas. No es «la lectura falló» (503): es su
      // propia rama, con su línea y el paso que la arregla.
      if (error instanceof RelationConfigError) {
        this.logger.error(
          `La config de relaciones persistida en authz_relations_config NO valida en 2.5: ${String(error?.message ?? error)} ` +
            `Es una fila escrita por una versión anterior (que descartaba claves en silencio) o a mano. Re-guárdala con ` +
            `saveRelationsConfig(<spec corregida>) —la spec, no la config ya definida— desde un proceso con la config ` +
            `estática buena, y repite la pasada. No se ha construido, congelado ni escrito nada.`
        )
        this.exitCode = 1
        return
      }
      this.logger.error(
        `No se pudo leer la config de relaciones persistida del destino (authz_relations_config): ` +
          `${String(error?.message ?? error)}. Una lectura que falla NO es «no hay config»: sin ella la pasada no ` +
          `vigilaría la deriva del modelo del destino y escribiría a ciegas. No se ha construido, congelado ni escrito nada.`
      )
      this.exitCode = 1
      return
    }
    if (toConfig === null) {
      this.logger.info(
        'Config del destino: ninguna persistida en authz_relations_config (relaciones opt-in): la deriva del modelo NO se vigila en esta pasada.'
      )
    } else {
      this.logger.info(
        `Config del destino: leída de authz_relations_config (${toConfig.objectTypes.length} tipo(s)): la deriva del modelo se vigila.`
      )
    }

    // Lote RC · sublote (8): el DETECTOR del alcance de los denies, solo en el verificador (`--dry-run`): línea base = la
    // config persistida (`toConfig`), config nueva = la que SIRVE este proceso (`relations.config`). Sin `relations.config`
    // en el proceso no hay con qué comparar: se dice (punto 7) y la pasada sigue.
    let denyReach: { baseline: typeof toConfig; current: NonNullable<typeof toConfig> } | undefined
    if (this.dryRun === true) {
      const current = (this.app.config?.get('authorization') as any)?.relations?.config
      if (current && Array.isArray(current.objectTypes)) {
        denyReach = { baseline: toConfig, current }
      } else {
        this.logger.info(
          'alcance de denies: NO se vigila en esta pasada (este proceso no tiene relations.config en config/authorization.ts con el que comparar).'
        )
      }
    }

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
        ...(denyReach ? { denyReach } : {}),
      })
    } catch (error: any) {
      // R-17: el seguro de borrado masivo (500) sale como error de comando, no
      // como stack crudo. `--allow-mass-delete` es la salida humana.
      if (error?.code === 'E_AUTHZ_MASS_RECONCILE_REFUSED' || error?.code === 'E_AUTHZ_STALE_SOURCE_REFUSED') {
        this.logger.error(String(error.message ?? error))
        this.exitCode = 1
        return
      }
      // Lote D · D2 (S6/R2-5): la puerta del deny del DESTINO negó la pasada en la fase de plan, con CERO escrituras.
      // La letra del error empieza por el prefijo estable «deny NO migrable:».
      if (error?.code === 'E_AUTHZ_DENY_MIGRATION_REFUSED') {
        this.logger.error(String(error.message ?? error))
        this.exitCode = 1
        return
      }
      // Lote D · D2: la pasada reventó A MITAD — el reporte parcial por partición viaja en el error.
      if (error?.report?.partial === true) {
        for (const line of partialReportLines(error.report)) this.logger.error(line)
        this.logger.error(String(error?.message ?? error))
        this.exitCode = 1
        return
      }
      // ⚪ 10 (cierre 1 de D2): reventó ANTES de escribir nada — el reporte viaja con `partial: false`. La línea del
      // error con su prefijo ESTABLE, sin «PARCIAL» (la marca de escritura parcial tampoco está).
      if (error?.report && error.report.partial === false) {
        this.logger.error(`pasada FALLIDA sin escribir nada: ${String(error?.message ?? error)} (la pasada es idempotente: repítela).`)
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
      (report.skipped.invalid ? `, fuera de la gramática en el origen ${report.skipped.invalid}` : '') +
      (report.skipped.usersetUnsupported ? `, con sujeto userset no admitido en el origen ${report.skipped.usersetUnsupported}` : '')
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
