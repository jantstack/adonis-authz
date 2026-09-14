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
  MassReconcileRefusedError,
  RelationTypeUnknownError,
  RelationUnknownError,
  UnsupportedOperationError,
} from '../errors.js'
import { systemClock } from '../clock.js'
import type { Clock } from '../clock.js'
import { isActiveExpiry, sameInstant } from '../expiry.js'
import { isRelUserset } from '../types.js'
import type { RelSubject, RelationTuple, RelationsDriver, ScopeRef } from '../types.js'
import type { RelationsConfig } from './define_relations_config.js'

/** La clave estable de una tupla de relación (partición + objeto + relación + sujeto). */
function subjectKey(subject: RelSubject): string {
  if (isRelUserset(subject)) return `${subject.object.type}:${subject.object.id}#${subject.relation}`
  return `${subject.type}:${subject.uuid}`
}

function scopeKeyOf(scope: ScopeRef): string {
  return scope.type === 'app' ? 'app' : `${scope.type}|${scope.uuid}`
}

function tupleKey(tuple: RelationTuple): string {
  return `${scopeKeyOf(tuple.partition)}|${tuple.object.type}:${tuple.object.id}#${tuple.relation}@${subjectKey(
    tuple.subject
  )}`
}

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
   */
  skipped: { expired: number; undeclared: number }
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
  for (const partition of partitions) out.set(scopeKeyOf(partition), [])
  const collect = (tuples: RelationTuple[]) => {
    for (const tuple of tuples) {
      const bucket = out.get(scopeKeyOf(tuple.partition))
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
    const enumerated = enumeratedByKey.get(scopeKeyOf(partition)) ?? []
    const destTuples = destByKeyAll.get(scopeKeyOf(partition)) ?? []
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
    skipped: { expired: 0, undeclared: 0 },
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
          `${partitions.length > 1 ? ` (partición ${scopeKeyOf(plan.partition)})` : ''} y el ` +
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
      if (prune) {
        for (const tuple of plan.toDelete) {
          await to.unrelate(tuple.subject, tuple.relation, tuple.object, tuple.partition)
        }
      }
    }
    report.written += written
    report.updated += updated
    report.deleted += prune ? plan.toDelete.length : 0
    report.unchanged += plan.unchanged
    report.extra += prune ? 0 : plan.toDelete.length
  }

  return report
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
    const key = scopeKeyOf(p)
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
  skipped: { expired: number; undeclared: number }
  modelDrift: string[]
  massDelete: boolean
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
  const skipped = { expired: 0, undeclared: 0 }
  const modelDrift: string[] = []
  const sourceTuples: RelationTuple[] = []
  for (const tuple of enumerated) {
    if (!isActiveExpiry(tuple.expiresAt ?? null, now)) {
      skipped.expired += 1
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
  for (const tuple of sourceTuples) sourceByKey.set(tupleKey(tuple), tuple)
  const destByKey = new Map<string, RelationTuple>()
  for (const tuple of destTuples) destByKey.set(tupleKey(tuple), tuple)

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
  const toDelete: RelationTuple[] = destTuples.filter((tuple) => !sourceByKey.has(tupleKey(tuple)))
  const massDelete = prune && toDelete.length > 0 && sourceTuples.length === 0
  return { partition, enumerated: enumerated.length, toWrite, toUpdate, toDelete, unchanged, skipped, modelDrift, massDelete }
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
