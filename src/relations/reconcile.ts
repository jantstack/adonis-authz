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
 */
import { MassReconcileRefusedError, UnsupportedOperationError } from '../errors.js'
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
  /** La partición a migrar (mono-tenant: `APP_SCOPE`). El reconcile es POR partición. */
  partition: ScopeRef
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
   * La config del DESTINO, para vigilar la deriva del modelo fusionado en
   * `--dry-run`: un tipo de relación presente en el origen que el destino NO
   * declara no cabría en su modelo fusionado (se reporta en `modelDrift`).
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
   * Lo que el origen ENUMERÓ y no se migró, con su motivo (R-15): `expired` =
   * tuplas caducadas al instante de la pasada. Es la pérdida DECLARADA de la
   * migración (como `expired` en `authz:reconcile` de roles, 3b-8 · B2): se
   * cuenta, no clava el exit 1. Un origen que las filtrara antes de
   * enumerarlas las haría desaparecer sin rastro; por eso tienen que LLEGAR.
   */
  skipped: { expired: number }
}

/** Enumera TODAS las tuplas de una partición de un driver (paginando el cursor). */
async function enumerateAll(driver: RelationsDriver, partition: ScopeRef, role: 'origen' | 'destino'): Promise<RelationTuple[]> {
  if (!driver.enumerateRelations || !driver.capabilities?.enumerateRelations) {
    throw new UnsupportedOperationError(
      'enumerateRelations',
      `ser ${role} de authz:reconcile de relaciones`,
      'relations',
      `El driver ${role} no sabe enumerar sus tuplas (capacidad 'enumerateRelations': false). ` +
        `Sin poder leer ${role === 'destino' ? 'el destino no se ve qué sobra' : 'el origen no hay nada que migrar'}.`
    )
  }
  const out: RelationTuple[] = []
  const seen = new Set<string>()
  let after: string | undefined
  let pages = 0
  do {
    const page = await driver.enumerateRelations(partition, after ? { after } : undefined)
    out.push(...page.tuples)
    after = page.cursor || undefined
    if (after) {
      if (seen.has(after)) throw new Error(`enumerateRelations (${role}): el cursor '${after}' se repite; no avanza`)
      seen.add(after)
      if (++pages > 100_000) throw new Error(`enumerateRelations (${role}): más de 100000 páginas sin agotar`)
    }
  } while (after)
  return out
}

/**
 * Migra las tuplas de relación de `from` a `to` en `partition`. Idempotente
 * (una segunda pasada no escribe nada) y bidireccional (funciona en cualquier
 * sentido). Nunca silenciosa: devuelve `written`/`deleted`/`unchanged`/`extra`.
 */
export async function reconcileRelations(options: RelationsReconcileOptions): Promise<RelationsReconcileReport> {
  const { from, to, partition, dryRun = false, prune = false, allowMassDelete = false, toConfig } = options
  const now = (options.now ?? systemClock)()

  const enumerated = await enumerateAll(from, partition, 'origen')
  const destTuples = await enumerateAll(to, partition, 'destino')

  // R-15: la caducada LLEGA del origen (el puerto lo exige) y aquí se DESCARTA
  // contándola: no se migra ni respalda nada en el destino. Decidido con UN
  // `now` para toda la pasada.
  const skipped = { expired: 0 }
  const sourceTuples: RelationTuple[] = []
  for (const tuple of enumerated) {
    if (isActiveExpiry(tuple.expiresAt ?? null, now)) sourceTuples.push(tuple)
    else skipped.expired += 1
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

  // Deriva del modelo fusionado del destino (--dry-run): tipos del origen que
  // el destino no declara. `group` es built-in (el generador lo emite siempre).
  const modelDrift: string[] = []
  if (toConfig) {
    const declared = new Set<string>(['group', ...toConfig.objectTypes.map((t) => t.type)])
    const seenDrift = new Set<string>()
    for (const tuple of sourceTuples) {
      if (!declared.has(tuple.object.type) && !seenDrift.has(tuple.object.type)) {
        seenDrift.add(tuple.object.type)
        modelDrift.push(tuple.object.type)
      }
    }
  }

  // **El seguro de borrado masivo** (R-17, paridad con `authz:reconcile` de
  // roles / AA2). `prune` + un ORIGEN sin una sola tupla utilizable + un destino
  // con tuplas que borrar es la firma de un `--from` equivocado o de un store
  // vacío: vaciar el destino entero se rechaza con 500 antes de tocar nada,
  // salvo `allowMassDelete`. En `--dry-run` no lanza, lo marca. «Utilizable» =
  // una tupla del origen cuyo tipo cabe en el modelo del destino (los tipos que
  // `modelDrift` recoge no migrarían, así que no cuentan como respaldo).
  const usableSource = toConfig
    ? sourceTuples.filter((tuple) => declaredIn(toConfig, tuple.object.type)).length
    : sourceTuples.length
  const massDelete = prune && toDelete.length > 0 && usableSource === 0
  if (massDelete && !dryRun && !allowMassDelete) {
    throw new MassReconcileRefusedError(
      `authz:relations:reconcile --prune borraría ${toDelete.length} tupla(s) de relación del destino y el ` +
        `ORIGEN no ha aportado NI UNA utilizable (${enumerated.length} leídas` +
        `${toConfig ? ', todas de tipos que el destino no declara' : ''}` +
        `${skipped.expired ? `, ${skipped.expired} caducada(s)` : ''}). Eso es la firma de un --from ` +
        `equivocado o de un store vacío, no de un destino que sobra: esta pasada dejaría la partición sin ` +
        `una sola relación. Comprueba el --from y el store; si de verdad quieres vaciarlo, --allow-mass-delete.`
    )
  }

  if (!dryRun) {
    // La caducidad viaja EXPLÍCITA (`Date` la fija, `null` la quita): un
    // `relate` sin opciones PRESERVARÍA la del destino (invariante 10).
    for (const tuple of [...toWrite, ...toUpdate]) {
      await to.relate(tuple.subject, tuple.relation, tuple.object, tuple.partition, {
        expiresAt: tuple.expiresAt ?? null,
      })
    }
    if (prune) {
      for (const tuple of toDelete) {
        await to.unrelate(tuple.subject, tuple.relation, tuple.object, tuple.partition)
      }
    }
  }

  return {
    dryRun,
    written: toWrite.length,
    updated: toUpdate.length,
    deleted: prune ? toDelete.length : 0,
    unchanged,
    extra: prune ? 0 : toDelete.length,
    modelDrift,
    massDelete,
    skipped,
  }
}

/** ¿El tipo de objeto cabe en el modelo fusionado del destino? (`group` es built-in.) */
function declaredIn(config: RelationsConfig, objectType: string): boolean {
  return objectType === 'group' || config.objectTypes.some((t) => t.type === objectType)
}
