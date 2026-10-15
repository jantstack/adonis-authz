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
  RelationUsersetUnsupportedError,
  UnsupportedOperationError,
} from '../errors.js'
import { systemClock } from '../clock.js'
import type { Clock } from '../clock.js'
import { isActiveExpiry, sameInstant } from '../expiry.js'
import { assertPartition, scopeKey } from '../identity.js'
import { isRelUserset } from '../types.js'
import type { RelationTuple, RelationsDriver, ScopeRef } from '../types.js'
import { assertRelationDeclared, assertSupportedUserset } from './define_relations_config.js'
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
   * `--dry-run` no puede anticiparla (la reporta como `written`). **Y en el
   * DESTINO** (cierre 3 del lote B · 🟠 N9): la fila cuya relación o tipo no
   * declara es residuo `undeclared` (`extra` + `details`, `pruned: false`,
   * nunca en `toDelete`), con los mismos números en `--dry-run` y en la pasada
   * real; sin ella, `--dry-run` la cuenta en `deleted` (no puede anticipar
   * F-05) y la pasada real captura el 422 del driver, la clasifica igual y
   * sigue — nunca un throw a mitad de pasada.
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
  /**
   * `invalid-identity` (⚪ R2): la identidad no entra en la gramática.
   * `userset-unsupported` (cierre 1 del lote B · 🟠 1/🟠 2): el sujeto es un
   * userset ≠ `group#member` — el residuo pre-2.5 de B3 (una fila inerte de
   * `database` de antes de 2.5.0). Se clasifica en el PLAN, antes del driver,
   * con o sin `toConfig` (`assertSupportedUserset`), así que `--dry-run` y la
   * pasada real dan los MISMOS números; en el origen cuenta en
   * `skipped.usersetUnsupported`, en el destino en `extra`, y en los dos lados
   * es deriva (exit ≠ 0) con la receta SQL en la línea: **ningún `--prune` la
   * toca** (nunca un DELETE de plataforma sobre una fila que la API no admite,
   * decisión del coordinador 2026-10-15: se lista, exit ≠ 0, se borra a mano).
   * `undeclared` (cierre 3 del lote B · 🟠 N9, solo `destino`): la fila cuya
   * relación —o tipo— el DESTINO ya no declara (una relación RETIRADA de la
   * config con filas vivas; `#enumerateRows`/`#sweep` filtran por tipo, no por
   * relación). `unrelate` la rechaza por F-05 (422), así que es la tercera fila
   * «que la API no admite» y lleva la MISMA regla: con `toConfig` la clasifica
   * el plan (`classifyDestinationRow`, la misma `assertRelationDeclared` que el
   * driver); sin ella la captura por `code` el bucle de poda en la pasada real
   * (hasta el cierre 3 ese 422 salía como stack crudo a mitad de pasada,
   * después de escribir, y `--prune` quedaba inutilizable para esa partición).
   * Receta: retírala a mano o vuelve a declarar la relación en el destino.
   */
  reason: 'invalid-identity' | 'userset-unsupported' | 'undeclared'
  /** La tupla, legible: `<partición> <tipo>:<id>#<relación>@<sujeto>`. */
  tuple: string
  /** El porqué: el mensaje de la gramática que la rechazó. */
  message: string
  /**
   * Solo `destino` con `prune`, y desde el cierre 2 del lote B (🟡 N3) siempre
   * `false`: NO se borró y sigue ahí porque la pasada NO se la pide a nadie —
   * ni `unrelate` por el puerto (los dos drivers del paquete la rechazan por su
   * gramática, R-16) ni un DELETE de plataforma—, también en `--dry-run`, para
   * los TRES motivos (`undeclared` desde el cierre 3 · 🟠 N9: con `toConfig` no
   * se le pide; sin ella se le pidió, el driver dijo 422 y la pasada siguió).
   * Hay que borrarla a mano (SQL/SDK) o, para `undeclared`, volver a declarar
   * la relación. Ausente sin `prune` y en el origen. El tipo sigue siendo `boolean` por compatibilidad: `true`
   * («borrada») lo producía el cierre-2 del lote A para `invalid-identity`
   * cuando un driver sin gramática aceptaba el `unrelate`; el paquete ya no lo
   * emite.
   */
  pruned?: boolean
}

export interface RelationsReconcileReport {
  /** ¿Fue `--dry-run` (sin escrituras)? */
  dryRun: boolean
  /**
   * ¿Se pasó `prune` (cierre 2 del lote B · 🟡 N3)? El comando lo necesita
   * para no aconsejar «repite con --prune» en una pasada que YA lo llevaba.
   * Opcional en el tipo exportado (un reporte de terceros anterior sigue
   * compilando; ausente = no pasado).
   */
  prune?: boolean
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
   * Tuplas del destino que el origen ya no respalda y que NO se borraron: por
   * no pasar `--prune` (deriva recuperable; con `prune` pasan a `deleted`) o
   * porque son un RESIDUO que ningún driver del paquete borra —`invalid-identity`,
   * `userset-unsupported` y, desde el cierre 3 (🟠 N9), `undeclared`, en
   * `details`— y la pasada no se lo pide a nadie (o se lo pidió sin `toConfig`
   * y el driver lo rechazó con un 422 de la familia, que se clasifica igual),
   * con o sin `prune` (cierre 2 del lote B · 🟡 N3: una regla, no dos). El
   * comando solo aconseja `--prune` por lo que `--prune` borra de verdad.
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
   *  - `usersetUnsupported` (cierre 1 del lote B · 🟠 2) = tuplas del ORIGEN
   *    cuyo sujeto es un userset ≠ `group#member` (el residuo pre-2.5 de B3,
   *    `reason: 'userset-unsupported'` en `details`): el destino no las admite
   *    (422 por cualquier puerta), se clasifican en el PLAN —nunca llegan al
   *    driver; hasta el cierre `relateOrSkip` las tragaba como `undeclared`
   *    con un consejo falso y `--dry-run` decía «haría 1 escritura»— y son
   *    deriva con la receta SQL en la línea. Opcional; ausente = 0.
   */
  skipped: { expired: number; undeclared: number; invalid?: number; usersetUnsupported?: number }
  /**
   * **Lo enumerado fuera de la gramática, con un userset no admitido O cuya
   * relación/tipo el destino ya no declara, una línea por tupla** (⚪ R2; cierres
   * 1, 2 y 3 del lote B): las del destino cuentan SIEMPRE en `extra` —los tres
   * motivos, `invalid-identity`, `userset-unsupported` y `undeclared`, con
   * `pruned: false` bajo `prune`: la pasada no se las pide a nadie (ningún
   * driver del paquete las admite en `unrelate`, R-16/F-05, y nunca un DELETE
   * de plataforma), y si sin `toConfig` se las pidió y el driver respondió con
   * un 422 de la familia de relaciones, se clasifican por `code` y la poda
   * sigue (🟠 N9: nunca un throw a mitad de pasada por una fila que el reporte
   * puede contar); hasta el cierre 2 `invalid-identity` se le pedía al driver y
   * podía salir en `deleted`—; las del origen en `skipped.invalid` /
   * `skipped.usersetUnsupported`. Opcional en el tipo
   * exportado (paridad con `allowMassDelete`, ⚪ A12); ausente = `[]`.
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
    prune,
    written: 0,
    updated: 0,
    deleted: 0,
    unchanged: 0,
    extra: 0,
    modelDrift: [],
    massDelete: false,
    allowMassDelete,
    skipped: { expired: 0, undeclared: 0, invalid: 0, usersetUnsupported: 0 },
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
          `ORIGEN no ha aportado NI UNA utilizable (${plan.enumerated} leídas${describeSkipped(plan.skipped)}). Eso es la firma de un --from ` +
          `equivocado o de un store vacío, no de un destino que sobra: esta pasada dejaría la partición sin ` +
          `una sola relación. Comprueba el --from y el store; si de verdad quieres vaciarlo, --allow-mass-delete.` +
          `${partitions.length > 1 ? ' No se ha escrito nada en ninguna partición.' : ''}`
      )
    }
    report.massDelete ||= plan.massDelete
    report.skipped.expired += plan.skipped.expired
    report.skipped.undeclared += plan.skipped.undeclared
    report.skipped.invalid! += plan.skipped.invalid
    report.skipped.usersetUnsupported! += plan.skipped.usersetUnsupported
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
    // ⚪ R2 + cierre 1 y cierre 2 del lote B (🟡 N3, una regla, no dos): lo
    // enumerado fuera de la gramática (`invalid-identity`) y el residuo pre-2.5
    // de B3 (`userset-unsupported`) se LISTAN siempre, en los dos lados; con
    // `prune` el del destino lleva `pruned: false` desde el plan — también en
    // `--dry-run`—, porque NADIE lo borra: ni `toDelete` lo contiene ni el driver
    // lo ve (hasta el cierre 2 `invalid-identity` se le pedía al driver y los dos
    // del paquete lo rechazaban por el puerto, R-16). Cuenta en `extra` (abajo)
    // y es deriva en los cuatro modos.
    for (const invalid of plan.invalid) {
      const detail: RelationsReconcileDetail = {
        side: invalid.side,
        reason: 'invalid-identity',
        tuple: invalid.tuple,
        message: invalid.message,
      }
      if (invalid.side === 'destino' && prune) detail.pruned = false
      report.details!.push(detail)
    }
    for (const residue of plan.usersetResidue) {
      const detail: RelationsReconcileDetail = {
        side: residue.side,
        reason: 'userset-unsupported',
        tuple: residue.tuple,
        message: residue.message,
      }
      if (residue.side === 'destino' && prune) detail.pruned = false
      report.details!.push(detail)
    }
    // Cierre 3 del lote B · 🟠 N9, capa 1: la fila del DESTINO cuya relación o
    // tipo `toConfig` no declara (una relación RETIRADA con filas vivas) se
    // clasifica en el PLAN con la MISMA regla que los otros dos motivos: `extra`
    // + `details`, `pruned: false` bajo `prune` (también en `--dry-run`), nunca
    // en `toDelete` — `unrelate` la rechazaría por F-05 y hasta el cierre 3 ese
    // 422 tumbaba la pasada a mitad, después de escribir.
    for (const residue of plan.undeclaredResidue) {
      const detail: RelationsReconcileDetail = { side: 'destino', reason: 'undeclared', tuple: residue.tuple, message: residue.message }
      if (prune) detail.pruned = false
      report.details!.push(detail)
    }
    let deleted = prune ? plan.toDelete.length : 0
    let refused = 0
    if (!dryRun && prune) {
      // Todo lo que hay en `toDelete` pasó la gramática Y, con `toConfig`, F-05
      // del destino: un 422 del driver aquí es el driver diciendo otra cosa que
      // el plan — o el plan sin `toConfig`, que no pudo anticipar F-05 (🟠 N9,
      // capa 2). **La poda NUNCA lanza por un 422 de la familia de relaciones**:
      // se clasifica por `code` con la MISMA regla (`extra` + `details`,
      // `pruned: false`, deriva), se sigue con las demás filas y el comando sale
      // ≠ 0 con la línea «sobra (<motivo>) destino:». Un 422 de OTRA familia o
      // cualquier otro error sigue propagándose: eso sí es una contradicción que
      // el reporte no sabe contar (R2-5: el plan clasifica, el driver no absorbe
      // lo que no es suyo).
      for (const tuple of plan.toDelete) {
        const refusal = await unrelateOrClassify(to, tuple)
        if (refusal === null) continue
        report.details!.push({ side: 'destino', reason: refusal.reason, tuple: describeTuple(tuple), message: refusal.message, pruned: false })
        refused += 1
        deleted -= 1
      }
    }
    report.written += written
    report.updated += updated
    report.deleted += deleted
    report.unchanged += plan.unchanged
    // El residuo del destino (los tres motivos) sobra SIEMPRE, con o sin `prune`:
    // no está en `toDelete`, así que se suma aparte — más lo que el driver
    // rechazó con un 422 de la familia en la pasada real (capa 2 de N9).
    report.extra += (prune ? 0 : plan.toDelete.length) + plan.destResidue + refused
  }

  return report
}

/**
 * ⚪ N8 (cierre 2 del lote B): el desglose del seguro R-17, cada motivo POR SU
 * NOMBRE y solo si cuenta (> 0). Hasta el cierre decía «todas de tipos que el
 * destino no declara» siempre que había `toConfig`, también cuando el único
 * aporte era residuo B3 — y sin `toConfig` no nombraba nada.
 */
function describeSkipped(skipped: PartitionPlan['skipped']): string {
  const parts: string[] = []
  if (skipped.undeclared) parts.push(`${skipped.undeclared} de tipo o relación que el destino no declara (skipped.undeclared)`)
  if (skipped.usersetUnsupported) parts.push(`${skipped.usersetUnsupported} con sujeto userset no admitido (B3, skipped.usersetUnsupported)`)
  if (skipped.invalid) parts.push(`${skipped.invalid} con identidad fuera de la gramática (skipped.invalid)`)
  if (skipped.expired) parts.push(`${skipped.expired} caducada(s)`)
  return parts.length ? `: ${parts.join(', ')}` : ''
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

/**
 * **El sujeto de una tupla ENUMERADA, clasificado** (cierre 1 del lote B · 🟠 2;
 * cierre 2 · 🟡 N2): `ok`, `userset-unsupported` (B3: userset ≠ `group#member`,
 * con o sin config — `assertSupportedUserset` no necesita F-05), o `undeclared`
 * (solo con `toConfig`: un `group#member` cuyo tipo/relación el destino no
 * declara — F-05 del par; sin config esa cara la embuda el 422 del driver, como
 * la del objeto). **La FORMA se juzga ANTES que F-05** (N2; decisión 3 del
 * cierre 1 rechazada): un residuo B3 es inadmisible con cualquier config, así
 * que un userset `folder#viewer` o `document#reader` que `toConfig` no declara
 * es residuo con receta, nunca `undeclared` con el consejo falso «decláralo en
 * el destino» (declarado, la pasada siguiente lo reclasificaba como residuo).
 * Mutante «F-05 primero» ⇒ rojo. Nunca lanza por un dato del store
 * (invariante 5).
 */
function classifySubject(
  tuple: RelationTuple,
  toConfig: RelationsConfig | undefined
): { kind: 'ok' } | { kind: 'userset-unsupported'; message: string } | { kind: 'undeclared' } {
  const subject: any = tuple?.subject
  if (!isRelUserset(subject)) return { kind: 'ok' }
  try {
    assertSupportedUserset(subject)
    if (toConfig) assertRelationDeclared(toConfig, subject.object, subject.relation)
    return { kind: 'ok' }
  } catch (error) {
    if (error instanceof RelationUsersetUnsupportedError) return { kind: 'userset-unsupported', message: error.message }
    if (error instanceof RelationTypeUnknownError || error instanceof RelationUnknownError) return { kind: 'undeclared' }
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
  skipped: { expired: number; undeclared: number; invalid: number; usersetUnsupported: number }
  modelDrift: string[]
  massDelete: boolean
  /** ⚪ R2: lo enumerado fuera de la gramática, de cada lado; la del destino NUNCA en `toDelete` (cierre 2 · N3). */
  invalid: Array<{ side: 'origen' | 'destino'; tuple: string; message: string }>
  /** Cierre 1 del lote B: el residuo pre-2.5 de B3 (userset ≠ `group#member`), de cada lado; NUNCA en `toDelete`. */
  usersetResidue: Array<{ side: 'origen' | 'destino'; tuple: string; message: string }>
  /** Cierre 3 del lote B · 🟠 N9: la fila del DESTINO cuya relación/tipo `toConfig` no declara (solo con `toConfig`); NUNCA en `toDelete`. */
  undeclaredResidue: Array<{ tuple: string; message: string }>
  /** Cuántas del DESTINO son residuo que nadie borra (los tres motivos): suman a `extra` con o sin `prune`. */
  destResidue: number
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
  const skipped = { expired: 0, undeclared: 0, invalid: 0, usersetUnsupported: 0 }
  const modelDrift: string[] = []
  const sourceTuples: RelationTuple[] = []
  const invalid: PartitionPlan['invalid'] = []
  const usersetResidue: PartitionPlan['usersetResidue'] = []
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
    // Cierre 1 del lote B · 🟠 2: el residuo pre-2.5 de B3 en el ORIGEN se
    // clasifica AQUÍ, con o sin `toConfig` — no se migra (ninguna puerta del
    // destino lo admite), se lista con su receta y se cuenta aparte. Hasta el
    // cierre llegaba al driver, que lo rechazaba con 422, y `relateOrSkip` lo
    // tragaba como `undeclared` (consejo falso; `--dry-run` decía `written`).
    const subject = classifySubject(tuple, toConfig)
    if (subject.kind === 'userset-unsupported') {
      skipped.usersetUnsupported += 1
      usersetResidue.push({ side: 'origen', tuple: describeTuple(tuple), message: subject.message })
      continue
    }
    if (subject.kind === 'undeclared') {
      skipped.undeclared += 1
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
  // ⚪ R2 + cierre 2 · N3: una tupla del DESTINO fuera de la gramática es
  // `extra` con motivo (`invalid-identity`): nadie del origen puede respaldarla
  // (la clave no se puede ni componer) y NADIE la borra — ni `toDelete` (los dos
  // drivers del paquete la rechazan por el puerto, R-16; hasta el cierre 2 se les
  // pedía igual) ni un DELETE de plataforma—: se lista con `pruned: false` y es
  // deriva en los cuatro modos, exactamente como el residuo de B3 de abajo.
  const destByKey = new Map<string, RelationTuple>()
  const destInvalid = new Set<RelationTuple>()
  const destResidue = new Set<RelationTuple>()
  const undeclaredResidue: PartitionPlan['undeclaredResidue'] = []
  for (const tuple of destTuples) {
    const keyed = enumeratedKey(tuple)
    if ('message' in keyed) {
      destInvalid.add(tuple)
      invalid.push({ side: 'destino', tuple: describeTuple(tuple), message: keyed.message })
      continue
    }
    // Cierre 1 del lote B · 🟠 1: el residuo pre-2.5 de B3 en el DESTINO sobra
    // (nadie del origen puede respaldarlo: el origen lo descarta arriba) pero
    // NO entra en `toDelete`: la pasada no se lo pide al driver ni con `--prune`
    // —`unrelate` lo rechazaría con 422 y hasta el cierre eso ABORTABA la pasada
    // a mitad, con los `toWrite` ya escritos—. Se lista con `pruned: false` y
    // la receta, cuenta en `extra` y es deriva. Solo la forma del userset: la
    // F-05 del par del SUJETO no decide aquí (un userset que pasa la forma es
    // `group#member`, declarado en toda config).
    const subject = classifySubject(tuple, undefined)
    if (subject.kind === 'userset-unsupported') {
      destResidue.add(tuple)
      usersetResidue.push({ side: 'destino', tuple: describeTuple(tuple), message: subject.message })
      continue
    }
    // Cierre 3 del lote B · 🟠 N9 (capa 1): la fila cuya RELACIÓN o TIPO el
    // destino (`toConfig`) ya no declara — una relación retirada de la config con
    // filas vivas (`#enumerateRows`/`#sweep` filtran por tipo, no por relación) o
    // un driver con la config vieja — es la tercera fila que la API no admite:
    // `unrelate` la rechaza por F-05, así que lleva la MISMA regla que las dos de
    // arriba (nunca en `toDelete`, `pruned: false`, deriva, receta). La regla es
    // por la FILA, no por el driver (N3): hasta el cierre 3 un driver viejo la
    // borraba y el driver nuevo tumbaba la pasada a mitad con un stack crudo.
    const undeclared = toConfig ? classifyDestinationRow(toConfig, tuple) : null
    if (undeclared !== null) {
      destResidue.add(tuple)
      undeclaredResidue.push({ tuple: describeTuple(tuple), message: undeclared })
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
    (tuple) => !destResidue.has(tuple) && !destInvalid.has(tuple) && !sourceByKey.has(tupleKey({ ...tuple, kind: 'allow' }))
  )
  const massDelete = prune && toDelete.length > 0 && sourceTuples.length === 0
  return {
    partition,
    enumerated: enumerated.length,
    toWrite,
    toUpdate,
    toDelete,
    unchanged,
    skipped,
    modelDrift,
    massDelete,
    invalid,
    usersetResidue,
    undeclaredResidue,
    destResidue: destResidue.size + destInvalid.size,
  }
}

/**
 * **F-05 del destino sobre una fila ENUMERADA del destino** (cierre 3 del lote B ·
 * 🟠 N9, capa 1): la MISMA `assertRelationDeclared` que corre en la primera línea
 * de `unrelate` de los dos drivers, aplicada en el plan para que `--dry-run` y la
 * pasada real den los mismos números y la fila nunca llegue a un `unrelate` que
 * la rechazaría. Devuelve el porqué (el mensaje de F-05: tipo o relación) o
 * `null` si el destino la declara. Nunca lanza por un dato del store
 * (invariante 5): cualquier otra excepción se propaga tal cual.
 */
function classifyDestinationRow(toConfig: RelationsConfig, tuple: RelationTuple): string | null {
  try {
    assertRelationDeclared(toConfig, tuple.object, tuple.relation)
    return null
  } catch (error) {
    if (error instanceof RelationTypeUnknownError || error instanceof RelationUnknownError) return error.message
    throw error
  }
}

/**
 * **Los 422 de la FAMILIA de relaciones, clasificados por `code`** (cierre 3 del
 * lote B · 🟠 N9, capa 2): lo que el bucle de poda absorbe cuando el driver del
 * destino rechaza un `unrelate` que el plan dio por bueno — sin `toConfig` el plan
 * no puede anticipar F-05, y un driver de terceros puede decir cualquiera de los
 * cuatro—. Por `code` y `status`, no por clase: un driver de terceros lanza su
 * propia clase con el mismo código. Fuera de esta tabla NADA se absorbe.
 */
const RELATION_422_REASONS: Readonly<Record<string, RelationsReconcileDetail['reason']>> = Object.freeze({
  [RelationTypeUnknownError.code]: 'undeclared',
  [RelationUnknownError.code]: 'undeclared',
  [RelationUsersetUnsupportedError.code]: 'userset-unsupported',
  [InvalidIdentityError.code]: 'invalid-identity',
})

/**
 * Borra la tupla del destino; devuelve `null` si se borró (o ya no estaba) y el
 * motivo + porqué si el DRIVER la rechazó con un 422 de la familia de relaciones
 * (`RELATION_422_REASONS`): la pasada lo clasifica como residuo del destino con
 * `pruned: false` y SIGUE con las demás filas (🟠 N9: nunca un throw a mitad de
 * pasada por una fila que el reporte puede contar). Cualquier otro error —otro
 * 422, un 503, un `Error`— se propaga tal cual: eso sí es el driver
 * contradiciendo al plan por algo que la pasada no sabe contar.
 */
async function unrelateOrClassify(
  to: RelationsDriver,
  tuple: RelationTuple
): Promise<{ reason: RelationsReconcileDetail['reason']; message: string } | null> {
  try {
    await to.unrelate(tuple.subject, tuple.relation, tuple.object, tuple.partition)
    return null
  } catch (error: any) {
    // Por `status` Y por `code` PROPIO de la tabla (`Object.hasOwn`, repaso del cierre 3 · ⚪ N13): un 422 con un
    // `code` heredado del prototipo (`constructor`, `toString`, `__proto__`) no es de la familia y se propaga.
    const code = String(error?.code)
    const reason =
      error?.status === 422 && Object.hasOwn(RELATION_422_REASONS, code) ? RELATION_422_REASONS[code] : undefined
    if (reason === undefined) throw error
    return { reason, message: String(error?.message ?? error) }
  }
}

/** ¿El tipo de objeto cabe en el modelo fusionado del destino? (`group` es built-in: `hasType` lo incluye.) */
function declaredIn(config: RelationsConfig, objectType: string): boolean {
  return config.hasType(objectType)
}

/**
 * Escribe la tupla en el destino; `false` si el DRIVER la rechazó por F-05
 * (tipo o relación no declarados: 422 `E_AUTHZ_RELATION_TYPE_UNKNOWN` /
 * `E_AUTHZ_RELATION_UNKNOWN`). Cualquier otro error se propaga tal cual —
 * **también `E_AUTHZ_RELATION_USERSET_UNSUPPORTED`** (cierre 1 del lote B,
 * decisión 4 rechazada): esa clase ya no hereda de F-05 y aquí no se absorbe;
 * el residuo de B3 se clasifica en el PLAN y nunca llega a este `relate`. Un
 * driver que lo lanzara por una tupla que el plan dio por buena está diciendo
 * otra cosa, y eso se propaga (R2-5: el plan clasifica, el driver no absorbe).
 */
async function relateOrSkip(to: RelationsDriver, tuple: RelationTuple): Promise<boolean> {
  try {
    await to.relate(tuple.subject, tuple.relation, tuple.object, tuple.partition, {
      expiresAt: tuple.expiresAt ?? null,
    })
    return true
  } catch (error) {
    if (error instanceof RelationUsersetUnsupportedError) throw error
    if (error instanceof RelationTypeUnknownError || error instanceof RelationUnknownError) return false
    throw error
  }
}
