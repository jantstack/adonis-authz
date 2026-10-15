/**
 * **`authz:reconcile` de relaciones** (Fase 4, lote 4-5) — migra las tuplas de
 * relación de un `RelationsDriver` a otro, idempotente y bidireccional, nunca
 * silenciosa. Es el análogo de `manager.reconcile` de roles, pero para el
 * puerto `RelationsDriver`: solo hay HECHOS de relación (no árbol ni catálogo),
 * así que es más simple —lee el ORIGEN por `enumerateRelations`, lee el DESTINO
 * ENTERO (la única forma de ver lo que SOBRA), y aplica writes y —con
 * `prune`— deletes—.
 *
 * **La lección M1/M3/T4 de la 3b** (el agujero del 3b-4·C1): un contrato que
 * solo cruza `report.skipped` se pasa PERDIENDO datos. El verificador de
 * verdad es el CENSO (`src/testing/relations_reconcile_contract.ts`): busca
 * cada hecho sembrado en el destino UNO A UNO por el camino DIRECTO
 * (`listSubjects`), no le pregunta al origen lleno. Un tramo omisivo o una
 * pérdida de `subject_relation` (un userset migrado como holder) o de
 * partición se ve ROJA ahí, no en los contadores.
 *
 * Pureza (regla 2): este módulo vive en `src/relations/` y solo depende del
 * puerto (`../types.js`), los errores y la config de relaciones. NO importa
 * `manager` ni `drivers/*`: los drivers concretos los inyecta el llamante (la
 * plataforma), como `manager.reconcile` recibe el destino por su clave.
 *
 * **Es un PRIMITIVO PRIVADO** (cierre del auditor de alpha.10 · R1): no sabe
 * cuál es el driver activo ni toma la ventana durable, así que ya no sale de la
 * raíz del paquete. La vía pública es `runRelationsReconcile`
 * (`commands/authz_relations_reconcile.ts`), que resuelve origen y destino por
 * clave, niega la dirección rancia y congela; la guardia de superficie de
 * `command_flags.spec.ts` impide re-exportarlo por ningún subpath.
 */
import {
  AuthorizationConfigError,
  InvalidIdentityError,
  MassReconcileRefusedError,
  RelationTypeUnknownError,
  RelationUnknownError,
  UnsupportedOperationError,
} from '../errors.js'
import { systemClock } from '../clock.js'
import type { Clock } from '../clock.js'
import { isActiveExpiry, sameInstant } from '../expiry.js'
import { assertPartition, scopeKey } from '../identity.js'
import { isRelUserset } from '../types.js'
import type { RelationTuple, RelationsDriver, ScopeRef } from '../types.js'
import type { RelationsConfig } from './define_relations_config.js'
import { relationTupleKey } from './tuple_key.js'

/**
 * La clave con la que se casan origen y destino es `relationTupleKey` (plan
 * 2.5 · lote A, P3-4): la MISMA función pura y exportada que un consumidor
 * usa para indexar sus metadatos, con `kind` desde el primer día (hoy todo
 * lo que un driver enumera es `allow`; el lote D lo trae en `RelationTuple`
 * y el `kind` explícito de aquí desaparece). Este módulo no define clave
 * propia ni copia `scopeKey`
 * (`tests/relation_tuple_key.spec.ts` lo vigila por fuente).
 */
const tupleKey = relationTupleKey

export interface RelationsReconcileOptions {
  /** El driver del que se LEEN las tuplas (origen). Necesita `enumerateRelations`. */
  from: RelationsDriver
  /** El driver al que se ESCRIBEN (destino). Necesita `enumerateRelations` para ver lo que sobra. */
  to: RelationsDriver
  /** La partición a migrar (mono-tenant: `APP_SCOPE`). El reconcile es POR partición. Exactamente uno de `partition` / `partitions`. */
  partition?: ScopeRef
  /**
   * **Varias particiones en UNA pasada** (2.4.0-alpha.6). Mismo recorrido que
   * `partition` para cada una, pero el ORIGEN y el DESTINO se enumeran UNA
   * vez con `enumerateRelationsMany` si el driver lo trae (en `openfga` eso es
   * un barrido del store en vez de K; medido: 3 particiones 1,4 s → 0,46 s) y,
   * si no, con K llamadas a `enumerateRelations` (correcto, K barridos). El
   * reporte es la SUMA de las K pasadas; el seguro de borrado masivo (R-17)
   * se decide POR partición y ANTES de escribir nada en ninguna: una sola
   * partición que dispare el seguro es 500 sin tocar el destino. Para un
   * desglose por tenant, llama por partición.
   */
  partitions?: ScopeRef[]
  /** Solo reporta lo que HARÍA; cero escrituras (read-only por contrato, como el de roles). */
  dryRun?: boolean
  /** Borra del destino las tuplas que el origen ya no respalda. Sin él, solo añade. */
  prune?: boolean
  /**
   * **El seguro de borrado masivo** (R-17): con `prune` y un ORIGEN sin una
   * sola tupla utilizable, borrar TODO el destino es 500
   * `E_AUTHZ_MASS_RECONCILE_REFUSED` (la firma de un `--from` equivocado o de un
   * store vacío). `allowMassDelete: true` (`--allow-mass-delete`) es la decisión
   * humana de vaciarlo de verdad; `--dry-run` no lanza, lo marca en `massDelete`.
   * Paridad con el seguro de `authz:reconcile` de roles.
   */
  allowMassDelete?: boolean
  /**
   * La config del DESTINO. Dos usos: vigilar la deriva del modelo fusionado
   * (un tipo del origen que el destino NO declara se reporta en `modelDrift`)
   * y **embudar F-05 ANTES del driver** (L-0): la tupla cuyo tipo o relación
   * el destino no declara se descarta aquí y se cuenta en
   * `skipped.undeclared`, de modo que `--dry-run` y la pasada real dan los
   * MISMOS números. Sin ella, la embuda el 422 del propio driver del destino
   * (la misma función, `assertRelationDeclared`) y se cuenta igual — pero
   * `--dry-run` no puede anticiparla (la reporta como `written`).
   */
  toConfig?: RelationsConfig
  /**
   * El reloj que decide qué tupla del ORIGEN está CADUCADA (R-15): una caducada
   * no se migra —se cuenta en `skipped.expired`— y no respalda nada en el
   * destino. Default `systemClock`; inyectable para el juez.
   */
  now?: Clock
}

/**
 * **Una tupla ENUMERADA por un store con una identidad fuera de la gramática**
 * (⚪ R2 del re-ataque al cierre del lote A, decisión del dueño 2026-10-15 (2)):
 * `document:<key>|ABC` escrita a mano con el SDK, una fila con `object_uuid`
 * en mayúsculas insertada por otro proceso… `relationTupleKey` valida cada
 * componente (⚪ A9) y hasta el cierre-2 `planPartition` la aplicaba tal cual a
 * lo enumerado, así que un dato malo del BACKEND salía como 422
 * `E_AUTHZ_INVALID_IDENTITY` —«pregunta inválida» del llamante, invariante 5—
 * y bloqueaba el reconcile de la partición entera, también con `--dry-run`.
 * Ahora se CLASIFICA y se LISTA: en el destino es `extra` con motivo
 * (`--prune` pide al driver que la borre; `--dry-run` la lista con su línea),
 * en el origen no se migra (la API no puede escribirla) y es deriva. Nunca un
 * 422 por un dato que no vino del llamante.
 */
export interface RelationsReconcileDetail {
  /** De qué store llegó enumerada. */
  side: 'origen' | 'destino'
  reason: 'invalid-identity'
  /** La tupla, legible: `<partición> <tipo>:<id>#<relación>@<sujeto>`. */
  tuple: string
  /** El porqué: el mensaje de la gramática que la rechazó. */
  message: string
  /**
   * Solo `destino` con `prune`: `true` = borrada (en `--dry-run`: se pedirá
   * borrar); `false` = la pasada real pidió borrarla y el DRIVER del destino
   * la rechazó por el puerto (su gramática en `unrelate`): sigue ahí y hay que
   * borrarla a mano (SQL/SDK). Ausente sin `prune` y en el origen.
   */
  pruned?: boolean
}

export interface RelationsReconcileReport {
  /** ¿Fue `--dry-run` (sin escrituras)? */
  dryRun: boolean
  /** Tuplas nuevas escritas en el destino (o que se escribirían, en `--dry-run`). */
  written: number
  /** Tuplas que sobraban en el destino y se borraron (solo con `prune`; o que se borrarían). */
  deleted: number
  /**
   * Tuplas que estaban en el destino con OTRA caducidad y se reescribieron con
   * la del origen (R-15; delete+write en ambos drivers, nunca un `Ignore` a
   * ciegas que se quedara la caducidad vieja — la lección S7 de la 3b).
   */
  updated: number
  /** Tuplas que ya estaban exactamente igual (misma clave y misma caducidad). */
  unchanged: number
  /**
   * Tuplas del destino que el origen ya no respalda y que NO se borraron por
   * no pasar `--prune` (deriva recuperable; con `prune` pasan a `deleted`).
   */
  extra: number
  /**
   * Deriva del modelo fusionado del destino (`--dry-run`): tipos de relación
   * del origen que la config del destino no declara. Vacío si no aplica.
   */
  modelDrift: string[]
  /**
   * **El seguro de borrado masivo se disparó** (R-17): `prune` iba a borrar
   * tuplas y el ORIGEN no aportó ni una utilizable. En una pasada real es 500
   * (salvo `allowMassDelete`); en `--dry-run` NO lanza y esto lo marca.
   */
  massDelete: boolean
  /**
   * `allowMassDelete` tal como llegó (F-R2, plan 2.5 · lote A): con
   * `massDelete: true` el comando dice si el seguro se LEVANTÓ y se borró, o
   * si se negó. La letra no puede decir «borraría … es 500» de una pasada
   * que ya borró. Opcional en el tipo exportado (⚪ A12): un reporte de un
   * harness de terceros construido antes del lote A sigue compilando; el
   * comando lee `=== true`.
   */
  allowMassDelete?: boolean
  /**
   * Lo que el origen ENUMERÓ y no se migró, con su motivo:
   *  - `expired` (R-15) = tuplas caducadas al instante de la pasada. Es la
   *    pérdida DECLARADA de la migración (como `expired` en `authz:reconcile`
   *    de roles, 3b-8 · B2): se cuenta, no clava el exit 1. Un origen que las
   *    filtrara antes de enumerarlas las haría desaparecer sin rastro; por eso
   *    tienen que LLEGAR.
   *  - `undeclared` (L-0) = tuplas VIVAS cuyo `object.type` o `relation` el
   *    DESTINO no declara (F-05): no se escriben —hasta L-0 `modelDrift` las
   *    reportaba y `to.relate` las escribía igual, por el driver— y se cuentan
   *    aquí. Es una relación viva que no llegó, así que SÍ es deriva
   *    (exit ≠ 0 en el comando): declárala en el destino y repite la pasada.
   *  - `invalid` (⚪ R2, cierre-2 del lote A) = tuplas del ORIGEN con una
   *    identidad fuera de la gramática (`RelationsReconcileDetail`): la API
   *    no puede escribirlas en el destino, se listan en `details` y son
   *    deriva. Opcional en el tipo (un reporte de terceros anterior sigue
   *    compilando); ausente = 0.
   */
  skipped: { expired: number; undeclared: number; invalid?: number }
  /**
   * **Lo enumerado con una identidad fuera de la gramática, una línea por
   * tupla** (⚪ R2): las del destino cuentan en `extra` (o en `deleted` con
   * `prune`, salvo las que el driver rechazó borrar: `pruned: false`, que
   * vuelven a `extra`); las del origen en `skipped.invalid`. Opcional en el
   * tipo exportado (paridad con `allowMassDelete`, ⚪ A12); ausente = `[]`.
   */
  details?: RelationsReconcileDetail[]
  /**
   * **La ventana durable bajo la que corrió la pasada que ESCRIBE** (L-1 ·
   * J1; paridad con `report.frozen` de `authz:reconcile` de roles). La pone
   * `runRelationsReconcile` (el comando), no esta función —que no ve al
   * manager de roles—; ausente en `--dry-run` (el verificador no congela) y
   * cuando se llama a `reconcileRelations` a pelo. `lapsed: true` = el lease
   * se perdió a mitad ⇒ la pasada NO se certifica (exit ≠ 0).
   */
  /** `untilMs` solo dentro de la ventana del OPERADOR (2.4.0-alpha.10): cuándo caduca, o `null` si no caduca. */
  frozen?: { durable: true; lapsed: boolean; leaseMs: number | null; fence: number; untilMs?: number | null; window?: 'operator' | 'own' | 'enclosing' }
  /**
   * **La dirección RANCIA** (2.4.0-alpha.10, S1 de la auditoría de sistema):
   * el destino era el driver de relaciones ACTIVO y el origen otro. La pone
   * `runRelationsReconcile` (esta función no sabe cuál es el activo); sin
   * `allowStaleSource` solo llega en `--dry-run` y es deriva.
   */
  staleSource?: { to: string; from: string; allowed: boolean }
}

/**
 * Enumera TODAS las tuplas de las particiones pedidas, repartidas por clave de
 * partición. UNA pasada con `enumerateRelationsMany` si el driver lo trae
 * (alpha.6: en `openfga`, un barrido del store en vez de K); si no, una
 * llamada de `enumerateRelations` por partición. En los dos casos se pagina el
 * cursor hasta agotarlo, con las mismas guardas ruidosas (un cursor que se
 * repite o más de 100 000 páginas es un error, nunca una enumeración corta).
 */
async function enumerateAllMany(
  driver: RelationsDriver,
  partitions: ScopeRef[],
  role: 'origen' | 'destino'
): Promise<Map<string, RelationTuple[]>> {
  if (!driver.enumerateRelations || !driver.capabilities?.enumerateRelations) {
    throw new UnsupportedOperationError(
      'enumerateRelations',
      `ser ${role} de authz:reconcile de relaciones`,
      'relations',
      `El driver ${role} no sabe enumerar sus tuplas (capacidad 'enumerateRelations': false). ` +
        `Sin poder leer ${role === 'destino' ? 'el destino no se ve qué sobra' : 'el origen no hay nada que migrar'}.`
    )
  }
  const out = new Map<string, RelationTuple[]>()
  for (const partition of partitions) out.set(scopeKey(partition), [])
  const collect = (tuples: RelationTuple[]) => {
    for (const tuple of tuples) {
      const bucket = out.get(scopeKey(tuple.partition))
      // Una tupla de una partición que no se pidió no es de esta pasada: el
      // puerto promete «solo las pedidas», y si un driver de terceros trae de
      // más, no se migra lo ajeno.
      if (bucket) bucket.push(tuple)
    }
  }
  const many = driver.enumerateRelationsMany
  const fetch =
    typeof many === 'function' && partitions.length > 1
      ? [(after?: string) => many.call(driver, partitions, after ? { after } : undefined)]
      : partitions.map((partition) => (after?: string) => driver.enumerateRelations!(partition, after ? { after } : undefined))
  for (const pageOf of fetch) {
    const seen = new Set<string>()
    let after: string | undefined
    let pages = 0
    do {
      const page = await pageOf(after)
      collect(page.tuples)
      after = page.cursor || undefined
      if (after) {
        if (seen.has(after)) throw new Error(`enumerateRelations (${role}): el cursor '${after}' se repite; no avanza`)
        seen.add(after)
        if (++pages > 100_000) throw new Error(`enumerateRelations (${role}): más de 100000 páginas sin agotar`)
      }
    } while (after)
  }
  return out
}

/**
 * Migra las tuplas de relación de `from` a `to` en `partition`. Idempotente
 * (una segunda pasada no escribe nada) y bidireccional (funciona en cualquier
 * sentido). Nunca silenciosa: devuelve `written`/`deleted`/`unchanged`/`extra`.
 */
export async function reconcileRelations(options: RelationsReconcileOptions): Promise<RelationsReconcileReport> {
  const { from, to, dryRun = false, prune = false, allowMassDelete = false, toConfig } = options
  const now = (options.now ?? systemClock)()
  const partitions = partitionsOf(options)

  // alpha.6: origen y destino se enumeran UNA vez para todas las particiones.
  const enumeratedByKey = await enumerateAllMany(from, partitions, 'origen')
  const destByKeyAll = await enumerateAllMany(to, partitions, 'destino')

  // Primero se DECIDE todo (K diffs, K seguros R-17) y luego se escribe: un
  // seguro que salte en la partición 3 no deja las dos primeras a medias.
  const plans: PartitionPlan[] = []
  for (const partition of partitions) {
    const enumerated = enumeratedByKey.get(scopeKey(partition)) ?? []
    const destTuples = destByKeyAll.get(scopeKey(partition)) ?? []
    plans.push(planPartition(partition, enumerated, destTuples, { now, prune, toConfig }))
  }

  const report: RelationsReconcileReport = {
    dryRun,
    written: 0,
    updated: 0,
    deleted: 0,
    unchanged: 0,
    extra: 0,
    modelDrift: [],
    massDelete: false,
    allowMassDelete,
    skipped: { expired: 0, undeclared: 0, invalid: 0 },
    details: [],
  }
  for (const plan of plans) {
    // **El seguro de borrado masivo** (R-17, paridad con `authz:reconcile` de
    // roles / AA2). `prune` + un ORIGEN sin una sola tupla utilizable + un destino
    // con tuplas que borrar es la firma de un `--from` equivocado o de un store
    // vacío: vaciar el destino entero se rechaza con 500 antes de tocar nada,
    // salvo `allowMassDelete`. En `--dry-run` no lanza, lo marca. «Utilizable» =
    // una tupla VIVA del origen que cabe en el destino (las que `skipped`
    // recoge no migran, así que no cuentan como respaldo).
    if (plan.massDelete && !dryRun && !allowMassDelete) {
      throw new MassReconcileRefusedError(
        `authz:relations:reconcile --prune borraría ${plan.toDelete.length} tupla(s) de relación del destino` +
          `${partitions.length > 1 ? ` (partición ${scopeKey(plan.partition)})` : ''} y el ` +
          `ORIGEN no ha aportado NI UNA utilizable (${plan.enumerated} leídas` +
          `${toConfig ? ', todas de tipos que el destino no declara' : ''}` +
          `${plan.skipped.expired ? `, ${plan.skipped.expired} caducada(s)` : ''}). Eso es la firma de un --from ` +
          `equivocado o de un store vacío, no de un destino que sobra: esta pasada dejaría la partición sin ` +
          `una sola relación. Comprueba el --from y el store; si de verdad quieres vaciarlo, --allow-mass-delete.` +
          `${partitions.length > 1 ? ' No se ha escrito nada en ninguna partición.' : ''}`
      )
    }
    report.massDelete ||= plan.massDelete
    report.skipped.expired += plan.skipped.expired
    report.skipped.undeclared += plan.skipped.undeclared
    report.skipped.invalid! += plan.skipped.invalid
    for (const type of plan.modelDrift) if (!report.modelDrift.includes(type)) report.modelDrift.push(type)
  }

  for (const plan of plans) {
    let written = plan.toWrite.length
    let updated = plan.toUpdate.length
    if (!dryRun) {
      // La caducidad viaja EXPLÍCITA (`Date` la fija, `null` la quita): un
      // `relate` sin opciones PRESERVARÍA la del destino (invariante 10).
      // L-0: el DRIVER del destino aplica F-05 (`assertRelationDeclared`), así que
      // sin `toConfig` —o con una que no coincida con la del driver— es SU 422 el
      // que embuda la tupla no declarada: se cuenta en `skipped.undeclared` y se
      // descuenta de `written`/`updated`. Nunca un throw a mitad de pasada por
      // una tupla que el reporte puede contar, y nunca un silencio.
      for (const tuple of plan.toWrite) {
        if (await relateOrSkip(to, tuple)) continue
        report.skipped.undeclared += 1
        written -= 1
      }
      for (const tuple of plan.toUpdate) {
        if (await relateOrSkip(to, tuple)) continue
        report.skipped.undeclared += 1
        updated -= 1
      }
    }
    // ⚪ R2: lo enumerado fuera de la gramática se LISTA siempre (origen y
    // destino), con el veredicto de la poda cuando la hay.
    let refused = 0
    for (const invalid of plan.invalid) {
      const detail: RelationsReconcileDetail = {
        side: invalid.side,
        reason: 'invalid-identity',
        tuple: invalid.tuple,
        message: invalid.message,
      }
      if (invalid.side === 'destino' && prune) detail.pruned = true
      report.details!.push(detail)
    }
    if (!dryRun && prune) {
      for (const tuple of plan.toDelete) {
        // La tupla fuera de la gramática se le pide al DRIVER tal como él la
        // enumeró. Si la rechaza por el puerto (422 de su propia gramática, R-16
        // en `unrelate`) NO es la pregunta del llamante la que está mal: se
        // apunta `pruned: false`, sigue contando como `extra` y la pasada lo
        // dice (exit ≠ 0). Nunca un throw a mitad de pasada por un dato ajeno.
        const invalid = plan.invalid.find((i) => i.side === 'destino' && i.ref === tuple)
        try {
          await to.unrelate(tuple.subject, tuple.relation, tuple.object, tuple.partition)
        } catch (error) {
          if (!invalid || (error as { status?: number })?.status !== 422) throw error
          refused += 1
          const detail = report.details!.find((d) => d.side === 'destino' && d.tuple === invalid.tuple)
          if (detail) detail.pruned = false
        }
      }
    }
    report.written += written
    report.updated += updated
    report.deleted += prune ? plan.toDelete.length - refused : 0
    report.unchanged += plan.unchanged
    report.extra += prune ? refused : plan.toDelete.length
  }

  return report
}

/** Una tupla enumerada, legible, para la línea del reporte (sin validar nada: puede estar fuera de la gramática). */
function describeTuple(tuple: RelationTuple): string {
  const s: any = tuple?.subject
  const subject = isRelUserset(s) ? `${s.object?.type}:${s.object?.id}#${s.relation}` : `${s?.type}:${s?.uuid}`
  const p: any = tuple?.partition
  const partition = p?.type === 'app' ? 'app' : `${p?.type}|${p?.uuid}`
  return `${partition} ${tuple?.object?.type}:${tuple?.object?.id}#${tuple?.relation}@${subject}`
}

/** `tupleKey` de una tupla ENUMERADA: la clave, o el motivo por el que su identidad no entra en la gramática (⚪ R2). */
function enumeratedKey(tuple: RelationTuple): { key: string } | { message: string } {
  try {
    return { key: tupleKey({ ...tuple, kind: 'allow' }) }
  } catch (error) {
    if (error instanceof InvalidIdentityError) return { message: error.message }
    throw error
  }
}

/** Exactamente uno de `partition` / `partitions` (y `partitions` no vacío): lo demás es 500 antes de leer nada. */
function partitionsOf(options: RelationsReconcileOptions): ScopeRef[] {
  const { partition, partitions } = options
  if (partition !== undefined && partitions !== undefined) {
    throw new AuthorizationConfigError('reconcileRelations: pasa `partition` O `partitions`, no los dos.')
  }
  // alpha.10 · 5, gemelo en la API: `{ type: 'app', uuid: 'x' }` reconciliaba la
  // RAÍZ en silencio (la clave de `app` ignora el uuid), igual que la pareja
  // `--partition-type=app --partition-uuid=x` del comando.
  for (const p of partition !== undefined ? [partition] : Array.isArray(partitions) ? partitions : []) {
    if (p?.type === 'app' && p.uuid !== null && p.uuid !== undefined) {
      throw new AuthorizationConfigError(
        `reconcileRelations: la partición raíz no lleva uuid (llegó { type: 'app', uuid: ${JSON.stringify(p.uuid)} }). ` +
          'O la raíz ({ type: app, uuid: null }) o el tipo del tenant.'
      )
    }
    // D4 (plan 2.5 · lote A): la pasada recibe partición, así que la misma
    // regla que toda operación del puerto — un uuid sin guiones es 422 antes
    // de leer nada.
    assertPartition(p)
  }
  if (partition !== undefined) return [partition]
  if (!Array.isArray(partitions) || partitions.length === 0) {
    throw new AuthorizationConfigError(
      'reconcileRelations: pasa `partition` (una) o `partitions` (varias, al menos una): sin partición no hay nada que migrar, ' +
        'y una lista vacía no es una pasada en verde.'
    )
  }
  // Dos referencias con la misma clave son la misma partición: se migra una vez.
  const seen = new Set<string>()
  return partitions.filter((p) => {
    const key = scopeKey(p)
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

/** El diff de UNA partición, decidido sin escribir. */
interface PartitionPlan {
  partition: ScopeRef
  enumerated: number
  toWrite: RelationTuple[]
  toUpdate: RelationTuple[]
  toDelete: RelationTuple[]
  unchanged: number
  skipped: { expired: number; undeclared: number; invalid: number }
  modelDrift: string[]
  massDelete: boolean
  /** ⚪ R2: lo enumerado fuera de la gramática, de cada lado; `ref` es la tupla del destino tal como se enumeró (la que `toDelete` contiene). */
  invalid: Array<{ side: 'origen' | 'destino'; tuple: string; message: string; ref?: RelationTuple }>
}

function planPartition(
  partition: ScopeRef,
  enumerated: RelationTuple[],
  destTuples: RelationTuple[],
  context: { now: Date; prune: boolean; toConfig?: RelationsConfig }
): PartitionPlan {
  const { now, prune, toConfig } = context
  // R-15: la caducada LLEGA del origen (el puerto lo exige) y aquí se DESCARTA
  // contándola: no se migra ni respalda nada en el destino. Decidido con UN
  // `now` para toda la pasada.
  // L-0: la tupla cuyo tipo o relación el DESTINO no declara (F-05) se
  // descarta AQUÍ cuando hay `toConfig` —antes del driver, así `--dry-run` y la
  // pasada real dan los mismos números— y tampoco respalda nada en el destino
  // (una que ya estuviera allí es `extra`, y `--prune` la barre). El tipo se
  // reporta además en `modelDrift` (deriva del modelo fusionado).
  const skipped = { expired: 0, undeclared: 0, invalid: 0 }
  const modelDrift: string[] = []
  const sourceTuples: RelationTuple[] = []
  const invalid: PartitionPlan['invalid'] = []
  for (const tuple of enumerated) {
    if (!isActiveExpiry(tuple.expiresAt ?? null, now)) {
      skipped.expired += 1
      continue
    }
    // ⚪ R2: una identidad fuera de la gramática en el ORIGEN no es una pregunta
    // del llamante (invariante 5): no se migra —la API del destino no podría
    // escribirla—, se lista y se cuenta. Nunca un 422 por un dato del store.
    const keyed = enumeratedKey(tuple)
    if ('message' in keyed) {
      skipped.invalid += 1
      invalid.push({ side: 'origen', tuple: describeTuple(tuple), message: keyed.message })
      continue
    }
    if (toConfig && !declaredIn(toConfig, tuple.object.type)) {
      skipped.undeclared += 1
      if (!modelDrift.includes(tuple.object.type)) modelDrift.push(tuple.object.type)
      continue
    }
    if (toConfig && !toConfig.isDeclared(tuple.object.type, tuple.relation)) {
      skipped.undeclared += 1
      continue
    }
    sourceTuples.push(tuple)
  }

  const sourceByKey = new Map<string, RelationTuple>()
  for (const tuple of sourceTuples) sourceByKey.set(tupleKey({ ...tuple, kind: 'allow' }), tuple)
  // ⚪ R2: una tupla del DESTINO fuera de la gramática es `extra` con motivo
  // (`invalid-identity`): nadie del origen puede respaldarla (la clave no se
  // puede ni componer), `--prune` pide borrarla y `--dry-run` la lista.
  const destByKey = new Map<string, RelationTuple>()
  const destInvalid = new Set<RelationTuple>()
  for (const tuple of destTuples) {
    const keyed = enumeratedKey(tuple)
    if ('message' in keyed) {
      destInvalid.add(tuple)
      invalid.push({ side: 'destino', tuple: describeTuple(tuple), message: keyed.message, ref: tuple })
      continue
    }
    destByKey.set(keyed.key, tuple)
  }

  const toWrite: RelationTuple[] = []
  const toUpdate: RelationTuple[] = []
  let unchanged = 0
  for (const [key, tuple] of sourceByKey) {
    const present = destByKey.get(key)
    if (!present) toWrite.push(tuple)
    // Misma clave, OTRA caducidad ⇒ se reescribe con la del origen (R-15).
    else if (!sameInstant(present.expiresAt ?? null, tuple.expiresAt ?? null)) toUpdate.push(tuple)
    else unchanged += 1
  }
  const toDelete: RelationTuple[] = destTuples.filter(
    (tuple) => destInvalid.has(tuple) || !sourceByKey.has(tupleKey({ ...tuple, kind: 'allow' }))
  )
  const massDelete = prune && toDelete.length > 0 && sourceTuples.length === 0
  return { partition, enumerated: enumerated.length, toWrite, toUpdate, toDelete, unchanged, skipped, modelDrift, massDelete, invalid }
}

/** ¿El tipo de objeto cabe en el modelo fusionado del destino? (`group` es built-in: `hasType` lo incluye.) */
function declaredIn(config: RelationsConfig, objectType: string): boolean {
  return config.hasType(objectType)
}

/**
 * Escribe la tupla en el destino; `false` si el DRIVER la rechazó por F-05
 * (tipo o relación no declarados: 422 `E_AUTHZ_RELATION_TYPE_UNKNOWN` /
 * `E_AUTHZ_RELATION_UNKNOWN`). Cualquier otro error se propaga tal cual.
 */
async function relateOrSkip(to: RelationsDriver, tuple: RelationTuple): Promise<boolean> {
  try {
    await to.relate(tuple.subject, tuple.relation, tuple.object, tuple.partition, {
      expiresAt: tuple.expiresAt ?? null,
    })
    return true
  } catch (error) {
    if (error instanceof RelationTypeUnknownError || error instanceof RelationUnknownError) return false
    throw error
  }
}
