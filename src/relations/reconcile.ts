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
  ActorRequiredError,
  AuthorizationConfigError,
  CheckManyBatchError,
  DenyMigrationRefusedError,
  InvalidIdentityError,
  InvalidSlugError,
  MassReconcileRefusedError,
  NoScopeResolverError,
  RelationConfigError,
  RelationConfigUnknownKeyError,
  RelationDenyExpiryError,
  RelationNotDenyableError,
  RelationTypeUnknownError,
  RelationUnknownError,
  RelationUsersetUnsupportedError,
  UnknownScopeError,
  UnsupportedOperationError,
  isPartialWrite,
  markPartialWrite,
} from '../errors.js'
import { systemClock } from '../clock.js'
import type { Clock } from '../clock.js'
import { isActiveExpiry, sameInstant } from '../expiry.js'
import { assertPartition, scopeKey } from '../identity.js'
import { isRelUserset } from '../types.js'
import type { RelationTuple, RelationsDriver, ScopeRef } from '../types.js'
import { assertRelationDeclared, assertSupportedUserset, RELATION_DENY_PREFIX, RELATION_USERSET_TYPE, relationsUp } from './define_relations_config.js'
import type { RelationsConfig } from './define_relations_config.js'
import { relationTupleKey } from './tuple_key.js'
import { carriedDenies, denyCarrierGroups, relationTransitionOrder } from './tuple_order.js'
import type { RelationCuts, RelationOrderView } from './tuple_order.js'
import type { RelationTupleKind } from './tuple_key.js'

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
/**
 * **Los motivos de `RelationsReconcileDetail`, en RUNTIME** (cierre 2 de D2 · ⚪ N6): la guardia L9
 * (`tests/relations_reconcile_l9.spec.ts`) los recorre y exige que cada uno tenga su entrada en `RELATION_RESIDUES`
 * (dónde se clasifica: el PLAN o la PASADA) y su caso. `renewal-unsafe` (cierre 2 de D2 · 🟠 N1, solo `destino`): la
 * renovación (otra caducidad) de una membresía `group:*#member` que TRANSPORTA un deny, en un destino que no declara
 * `atomicRenewal` (renueva con delete + write, `openfga`): entre los dos `Write` el deny no alcanzaría al sujeto. Desde el
 * cierre 5 de D2 (opción A) NIEGA SU PARTICIÓN (`partitionsRefused`: cero escrituras y cero borrados en ella, el resto
 * migra); la línea la nombra con su receta y es deriva. `withheld-by-unsafe-deny` (cierre 4) se fue con la retención.
 */
export const RELATIONS_RECONCILE_DETAIL_REASONS = Object.freeze([
  'invalid-identity',
  'userset-unsupported',
  'undeclared',
  'deny-conditional',
  'renewal-unsafe',
  'invalid-condition',
] as const)
export type RelationsReconcileDetailReason = (typeof RELATIONS_RECONCILE_DETAIL_REASONS)[number]

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
   * `deny-conditional` (cierre 1 de D2 · 🟡 4; cierre 4 · 🟡 C3-2, solo `destino`): un deny del destino CON caducidad
   * (escrito fuera del paquete, D3) —vivo con otra caducidad o YA VENCIDO— que el origen tiene, en un destino que no
   * declara `atomicRenewal` (`openfga` no reemplaza la misma clave en un `Write`, M5). Lo decide el PLAN (mismos números
   * en `--dry-run` y real): no se reescribe, y desde el cierre 5 de D2 (opción A) NIEGA SU PARTICIÓN —cero escrituras y
   * cero borrados en ella (`partitionsRefused`), el resto migra—; lleva la receta (`removeDeny` + `deny`, con su ventana
   * declarada) y es deriva.
   */
  reason: RelationsReconcileDetailReason
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
  /**
   * **Los DENIES de la pasada, aparte** (plan 2.5 · lote D · D2; analista §4.7, tester T3): el SUBCONJUNTO de los
   * contadores de arriba que son denies (`written`/`updated`/`deleted`/`unchanged`/`extra` cuentan allows + denies).
   * `updated` = un deny del destino CON caducidad (escrito a mano) que el origen tiene distinto: se rehace permanente
   * con `to.deny` (D3: el deny no caduca; `database` lo rehace en una transacción, `openfga` responde 409 ⇒ 503 ruidoso).
   * Opcional en el tipo exportado (un reporte de terceros anterior sigue compilando).
   */
  denies?: { written: number; updated: number; deleted: number; unchanged: number; extra: number }
  /**
   * **Los denies que la pasada NO puede migrar** (D2; S6/R2-5): solo en `--dry-run` (la pasada real lanza 500
   * `E_AUTHZ_DENY_MIGRATION_REFUSED` con CERO escrituras y las mismas entradas en `error.refusals`). Es deriva: el
   * verificador sale ≠ 0 con la línea «deny NO migrable (<motivo>) …». Ausente = ninguno.
   */
  denyRefused?: DenyRefusal[]
  /**
   * **El reporte POR PARTICIÓN** (roadmap 2.5, 🟡 3 del auditor de alpha.6): el desglose de los contadores y el
   * estado de cada partición pedida, en orden. Si la pasada revienta a mitad, el error lleva `report` con
   * `partial: true`, las particiones ya escritas `done`, la que reventó `failed` (con lo que llegó a escribir) y las
   * demás `pending`, y va marcado con `markPartialWrite` si se escribió algo.
   */
  partitions?: RelationsReconcilePartitionReport[]
  /**
   * Solo en el reporte que viaja en un error (`error.report`): `true` si la pasada se cortó a mitad DESPUÉS de escribir
   * algo; `false` si reventó sin haber escrito nada (⚪ 10 del cierre 1 de D2: hasta entonces era `true` siempre y el
   * comando imprimía «pasada PARCIAL: escritas 0»). Desde el cierre 2 de D2 (🟠 N1) también `true` si el DRIVER marcó
   * el error como escritura parcial (`isPartialWrite`: un `relate` de renovación que ya borró), aunque la pasada no
   * hubiera completado ninguna escritura.
   */
  partial?: boolean
  /**
   * **El RESIDUO del orden** (cierre 2 de D2 · 🟡 N3, linaje L10): las membresías de un CICLO del grafo de precedencias de
   * `relationTransitionOrder` — dos membresías que cambian en la misma pasada cuyas exigencias de orden se contradicen
   * (típicamente: el mismo sujeto entra, o sale, a la vez en dos grupos y cada uno trae un deny que corta un allow que
   * trae el otro). Para ellas no hay orden garantizado: un corte entre las dos puede conceder lo que ni el estado inicial
   * ni el final concedían (para el resto de la pasada, la garantía vale). El estado FINAL es el correcto; no es deriva:
   * el comando lo AVISA con el prefijo estable «orden SIN garantía». Lo mismo en `--dry-run` que en la pasada real.
   * Opcional en el tipo exportado; ausente = `[]`.
   */
  orderResidue?: string[]
  /**
   * **Las particiones NEGADAS** (cierre 5 de D2, decisión del dueño §2026-10-16 (10), opción A): una partición con al
   * menos un `renewal-unsafe` (la caducidad de una membresía que transporta un deny cambia, y el destino no la puede
   * renovar en una escritura) o un `deny-conditional` (un deny del destino con caducidad que no se puede rehacer) recibe
   * CERO escrituras y CERO borrados —también con `--prune`, también las vencidas—: su destino queda EXACTAMENTE como
   * estaba, con la deriva previa a la vista (`pending`). El resto de particiones migra. Lo decide el PLAN: `--dry-run` y
   * la pasada real dan los mismos números. Es deriva (exit ≠ 0) mientras exista. Opcional en el tipo; ausente = `[]`.
   */
  partitionsRefused?: RelationsPartitionRefusal[]
}

/**
 * Por qué se NIEGA una partición: `renewal-unsafe` (membresía portadora que cambia de caducidad), `deny-conditional` (deny
 * con caducidad que el destino no puede rehacer) o, desde el cierre de L11 (🟡 A2 del auditor), `invalid-condition`: una
 * tupla de `group` (una membresía, portadora posible) con una condición que el paquete no escribe ni sabe leer
 * (`foreign`/`unparseable`) en una partición con ALGÚN deny — el servidor puede estar evaluándola VIVA (un `not_expired`
 * con `current_time` congelado lo está, medido) y transportando ese deny; saltarla como allow fabricaba una concesión.
 */
export type RelationsPartitionRefusalReason = 'renewal-unsafe' | 'deny-conditional' | 'invalid-condition'

/** Una partición NEGADA (cierre 5 de D2): por qué, qué receta, y lo que la pasada habría hecho en ella y NO hizo. */
export interface RelationsPartitionRefusal {
  partition: string
  /** Las causas, una por tupla: `renewal-unsafe` (membresía portadora) o `deny-conditional` (deny con caducidad). */
  causes: Array<{ reason: RelationsPartitionRefusalReason; tuple: string }>
  /** La deriva que queda a la vista: lo que la pasada escribiría, renovaría y (con `--prune`) borraría en ella. */
  pending: { write: number; update: number; delete: number }
  /** La receta (`partitionRefusalRecipe`): honesta — en un destino sin `atomicRenewal` no hay forma sin ventana. */
  recipe: string
  /**
   * Cierre 6 de D2 · ⚪ D5-3: «COMO ESTABA» no es estático. Por cada membresía portadora que el origen ALARGA: desde `at`
   * (su caducidad vieja en el destino) el destino deja de transportar los denies `cut` a `member` y CONCEDE lo que cortan
   * si otro camino lo da —el origen lo sigue negando—. Ausente si no aplica.
   */
  evolves?: Array<{ at: string; member: string; cut: string[] }>
}

/** El desglose de UNA partición (D2). `status`: `done` (terminó), `failed` (reventó aquí), `pending` (no se tocó), `refused` (cierre 5: negada por el plan, cero escrituras). */
export interface RelationsReconcilePartitionReport {
  partition: string
  status: 'done' | 'failed' | 'pending' | 'refused'
  written: number
  updated: number
  deleted: number
  unchanged: number
  extra: number
  denies: { written: number; updated: number; deleted: number; unchanged: number; extra: number }
}

/**
 * Un deny que la pasada no puede migrar (D2), con su motivo — uno de un conjunto CERRADO (cada uno su línea):
 *  - `no-capability`: el destino no declara `relationDenies` (o no trae `deny`/`removeDeny`);
 *  - `no-deny-phase`: el destino declara `relationDenies` pero no trae `denyPhase` (no puede decir si el tipo admite deny);
 *  - `phase`: el tipo no está en la fase que hace falta EN EL DESTINO (`'write'` para escribir; con opt-in para uno ya presente);
 *  - `undeclared`: el destino no declara el par tipo/relación (F-05);
 *  - `model`: el modelo FIJADO del destino no declara `denied_<rel>` (D-31, `openfga`);
 *  - `unmarked`: el ORIGEN enumera una tupla `denied_*` sin `kind: 'deny'` (un driver que no marca);
 *  - `invalid`: el deny del origen tiene una identidad o un sujeto que el destino no admite (gramática / B3).
 *
 * `carrier-conflict` (cierre 4 de D2) se fue en el cierre 5 con la retención: lo que no viaja niega SU partición
 * (`partitionsRefused`), nunca la pasada entera.
 */
export interface DenyRefusal {
  objectType: string
  relation: string
  reason: 'no-capability' | 'no-deny-phase' | 'phase' | 'undeclared' | 'model' | 'unmarked' | 'invalid'
  message: string
  /**
   * Cierre 1 de D2 · 🟡 6: la receta de SU motivo (`denyRefusalRecipe`), una que funciona por la API o que dice «a mano»
   * cuando la API no puede. Hasta el cierre todas llevaban la misma («pon el tipo en 'write' o retira esos denies del
   * origen»), que para `undeclared` daba 422 (F-05 en `removeDeny`) y para `unmarked`/`invalid` no aplicaba.
   */
  recipe: string
}

/**
 * **Una receta POR MOTIVO** (cierre 1 de D2 · 🟡 6, ⚪ 11). `honor` = el deny ya está en el destino y lo que falta es
 * que lo honre (opt-in), no que lo escriba. La de `undeclared` está EJECUTADA en `relations_reconcile_deny.spec`
 * (re-declarar → `removeDeny` → retirar ⇒ la pasada entra).
 */
export function denyRefusalRecipe(reason: DenyRefusal['reason'], objectType: string, relation: string, honor = false): string {
  const pair = `${objectType}#${relation}`
  switch (reason) {
    case 'no-capability':
      return (
        `el destino no sabe escribir ni honrar denies: migra a un destino que declare relationDenies (los dos drivers del ` +
        `paquete lo hacen desde 2.5.0-alpha.3), o retira esos denies en el ORIGEN con removeDeny, y repite.`
      )
    case 'no-deny-phase':
      return (
        `un driver de terceros que declara relationDenies tiene que traer denyPhase(type, relation) (puerto, 2.5.0-alpha.3): ` +
        `actualízalo; o retira esos denies en el ORIGEN con removeDeny, y repite.`
      )
    case 'phase':
      return honor
        ? `declara el opt-in de '${objectType}' en la config del DESTINO (deny: 'read' basta para honrar un deny que ya está) ` +
            `—provision → fijar modelId → desplegar—, o retira ese deny del destino con removeDeny, y repite.`
        : `pon '${objectType}' en deny: 'write' en la config del DESTINO —provision → fijar modelId → desplegar, README ` +
            `«Upgrading to 2.5.0-alpha.3»—, o retira esos denies en el ORIGEN con removeDeny, y repite.`
    case 'undeclared':
      return (
        `${pair} no está declarado. Si es una relación RETIRADA con denies vivos: vuelve a declarar la relación ` +
        `TEMPORALMENTE en la config del proceso que escribe en el ORIGEN (la relación basta: removeDeny no exige el opt-in), ` +
        `retira esos denies con removeDeny, quítala otra vez y repite — removeDeny sobre un par NO declarado es 422 (F-05). ` +
        `Si el destino debe tenerla: declárala en la config del DESTINO.`
      )
    case 'model':
      return (
        `el modelo FIJADO del destino no declara ${objectType}#denied_${relation}: publica el modelo desde la config del ` +
        `destino (openfga:provision --store-id) y fija el OPENFGA_MODEL_ID nuevo en el proceso que corre la pasada (y en la ` +
        `flota), y repite.`
      )
    case 'unmarked':
      return (
        `el driver que enumera esa tupla (origen o destino: lo dice el mensaje) no marca kind: 'deny' — un driver de terceros ` +
        `o un proceso < 2.5.0-alpha.3 —: actualízalo y repite. La pasada no la toca: su dueño es ese driver.`
      )
    case 'invalid':
      return (
        `la identidad o el sujeto del deny no entra en la gramática del destino, y removeDeny también la rechazaría: bórralo ` +
        `a mano en el ORIGEN (database: DELETE de esa fila de authz_relations; openfga: un Write con delete) y repite.`
      )
  }
}

/**
 * **La receta de una partición NEGADA** (cierre 5 de D2, opción A), por el conjunto de causas. HONESTA a propósito: en
 * un destino sin `atomicRenewal` (`openfga`: FGA no reemplaza la misma clave en un `Write` —no hay upsert,
 * openfga/openfga#2151—) NO existe forma sin ventana de cambiar la caducidad de una membresía que transporta un deny, ni
 * de rehacer permanente un deny con caducidad. Ninguna de las salidas de abajo se presenta como segura.
 */
export function partitionRefusalRecipe(reasons: Iterable<RelationsPartitionRefusalReason>): string {
  const set = new Set(reasons)
  const out: string[] = []
  if (set.has('renewal-unsafe')) {
    out.push(
      `renewal-unsafe: en este destino NO hay forma sin ventana de cambiar la caducidad de una membresía cuyo grupo ` +
        `transporta un deny (la renovación son dos Write; openfga/openfga#2151, sin upsert). Salidas para ESTA partición ` +
        `(ninguna sin precio): (1) unrelate de esa membresía en el ORIGEN, y repite (sin --prune el destino la conserva hasta ` +
        `su caducidad; con --prune se borra, como en el origen). (2) unrelate + relate de esa membresía en el DESTINO con la ` +
        `caducidad del ORIGEN (o SIN caducidad, si el origen no la tiene) aceptando la ventana de forma EXPLÍCITA — mientras ` +
        `dura, el sujeto no recibe el deny del grupo y concede lo que otro camino le dé y ese deny corte —, y repite la pasada. ` +
        `(3) Esperar a que venza la caducidad vieja del DESTINO: entonces la tupla cuenta como ausente, la reescritura es una ` +
        `escritura normal y la partición migra sola — y en ese intervalo el destino concede lo que ese deny corta (la línea ` +
        `lo fecha). Cambiar la membresía a SIN caducidad en el ORIGEN NO desbloquea la partición (la del destino caduca: sigue ` +
        `siendo un cambio de caducidad). Para el FUTURO, el patrón recomendado: membresías SIN caducidad en los grupos con ` +
        `deny, que se terminan con unrelate.`
    )
  }
  if (set.has('deny-conditional')) {
    out.push(
      `deny-conditional: un deny no caduca (D3) y este destino no puede rehacerlo permanente en una escritura. removeDeny + ` +
        `deny de esa tupla en el DESTINO aceptando la ventana de forma EXPLÍCITA — entre los dos el deny no niega —, y repite.`
    )
  }
  if (set.has('invalid-condition')) {
    out.push(
      `invalid-condition: una membresía de group con una condición que el paquete no escribe ni sabe leer puede estar VIVA en ` +
        `el servidor (un not_expired con current_time congelado lo está) y transportar los denies de la partición: el paquete ` +
        `no sabe qué concede y no migra la partición a ciegas. Revisa esa tupla en su store (SDK/CLI de OpenFGA): bórrala, o ` +
        `reescríbela por el paquete (unrelate + relate con la caducidad que corresponda), y repite.`
    )
  }
  return out.join(' ')
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

  // Primero se DECIDE todo (K diffs, K seguros R-17, la puerta del deny) y luego se escribe: un seguro que salte en la
  // partición 3 no deja las dos primeras a medias.
  // Cierre 2 de D2 · 🟡 N3: el auto-corte del orden (un deny de `d` corta un allow de `a` sii `d ∈ up*(a)`, D5) sale de la
  // config del DESTINO; sin ella el orden no da ningún allow por cortado (lo conservador). Cierre 4: también la retención.
  const cuts: RelationCuts | undefined = toConfig
    ? (objectType, denied, allowed) => {
        try {
          return relationsUp(toConfig, objectType, allowed).includes(denied)
        } catch {
          return false
        }
      }
    : undefined
  const plans: PartitionPlan[] = []
  for (const partition of partitions) {
    const enumerated = enumeratedByKey.get(scopeKey(partition)) ?? []
    const destTuples = destByKeyAll.get(scopeKey(partition)) ?? []
    plans.push(planPartition(partition, enumerated, destTuples, { now, prune, toConfig, atomicRenewal: to.capabilities?.atomicRenewal === true, cuts }))
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
    denies: { written: 0, updated: 0, deleted: 0, unchanged: 0, extra: 0 },
    partitions: plans.map((plan) => emptyPartitionReport(plan.partition)),
    orderResidue: [],
    partitionsRefused: [],
  }
  for (const plan of plans) {
    // **El seguro de borrado masivo** (R-17, paridad con `authz:reconcile` de
    // roles / AA2). `prune` + un ORIGEN sin una sola tupla utilizable + un destino
    // con tuplas que borrar es la firma de un `--from` equivocado o de un store
    // vacío: vaciar el destino entero se rechaza con 500 antes de tocar nada,
    // salvo `allowMassDelete`. En `--dry-run` no lanza, lo marca. «Utilizable» =
    // una tupla VIVA del origen que cabe en el destino (las que `skipped`
    // recoge no migran, así que no cuentan como respaldo) — **denies incluidos** (D2).
    if (plan.massDelete && !dryRun && !allowMassDelete) {
      throw new MassReconcileRefusedError(
        `authz:relations:reconcile --prune borraría ${plan.allowDelete.length + plan.denyDelete.length} tupla(s) de relación del destino` +
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

  // **La puerta del deny, por el DRIVER DESTINO y en la fase de PLAN** (lote D · D2; S6, R2-5): antes de la primera
  // escritura en CUALQUIER partición. Un deny que no se puede escribir (o que el destino no honraría) ⇒ 500 con CERO
  // escrituras; jamás `skipped` (escribir los allows sin él concedería lo que el origen niega). `--dry-run` lo marca.
  const refusals = await denyGate(to, plans)
  if (refusals.length > 0) {
    if (!dryRun) throw denyRefusedError(refusals, partitions.length)
    report.denyRefused = refusals
  }

  // Lo escrito en TODA la pasada: decide la marca de escritura parcial si algo revienta (invariante 13).
  const progress = { writes: 0 }
  for (let i = 0; i < plans.length; i++) {
    const plan = plans[i]
    const row = report.partitions![i]
    // Cierre 5 de D2 (opción A): la partición NEGADA por el plan no se toca —cero escrituras y cero borrados—; las demás
    // siguen. Mismo resultado en `--dry-run` y en la pasada real.
    if (plan.refusal) {
      refusePartition(plan, row, report, prune)
      continue
    }
    try {
      await applyPartition(plan, row, report, { to, dryRun, prune, progress, cuts })
      row.status = 'done'
    } catch (error: any) {
      row.status = 'failed'
      throw partialReconcileError(error, report, progress.writes)
    }
    addPartition(report, row)
  }
  return report
}

/**
 * **Una partición NEGADA** (cierre 5 de D2, opción A): cero escrituras, cero borrados. El reporte dice lo que había
 * (`unchanged`), lo que sobra y se queda (`extra`, también con `--prune`: no se borra nada) y, en `partitionsRefused`, por
 * qué, la receta y la deriva pendiente. Los residuos de la partición (`details`) se listan igual que en una aplicada.
 */
function refusePartition(plan: PartitionPlan, row: RelationsReconcilePartitionReport, report: RelationsReconcileReport, prune: boolean): void {
  const refusal = plan.refusal!
  const PRUNABLE = new Set(['invalid-identity', 'userset-unsupported', 'undeclared', 'invalid-condition'])
  for (const detail of plan.details) {
    report.details!.push(prune && detail.side === 'destino' && PRUNABLE.has(detail.reason) ? { ...detail, pruned: false } : detail)
  }
  row.status = 'refused'
  row.unchanged = plan.unchanged + plan.denyUnchanged
  row.denies.unchanged = plan.denyUnchanged
  row.denies.extra = plan.denyDelete.length + plan.denyConditional
  row.extra = plan.allowDelete.length + plan.denyDelete.length + plan.destResidue + plan.denyConditional
  report.partitionsRefused!.push(refusal)
  addPartition(report, row)
}

/** Un reporte de partición a cero, `pending` hasta que se aplica. */
function emptyPartitionReport(partition: ScopeRef): RelationsReconcilePartitionReport {
  return {
    partition: scopeKey(partition),
    status: 'pending',
    written: 0,
    updated: 0,
    deleted: 0,
    unchanged: 0,
    extra: 0,
    denies: { written: 0, updated: 0, deleted: 0, unchanged: 0, extra: 0 },
  }
}

/** Suma una partición al total del reporte. */
function addPartition(report: RelationsReconcileReport, row: RelationsReconcilePartitionReport): void {
  report.written += row.written
  report.updated += row.updated
  report.deleted += row.deleted
  report.unchanged += row.unchanged
  report.extra += row.extra
  for (const k of ['written', 'updated', 'deleted', 'unchanged', 'extra'] as const) report.denies![k] += row.denies[k]
}

/**
 * **El reporte PARCIAL viaja en el error** (roadmap 2.5): las particiones `done` y lo que la `failed` llegó a escribir,
 * sumados; `partial: true` si escribió algo (⚪ 10: `false` con cero escrituras); y la marca de escritura parcial (`markPartialWrite`, invariante 13) si la pasada escribió
 * algo. El error, su clase y su `code` no cambian (un 503 sigue siendo un 503).
 */
function partialReconcileError(error: any, report: RelationsReconcileReport, writes: number): any {
  const failed = report.partitions!.find((p) => p.status === 'failed')
  if (failed) addPartition(report, failed)
  // ⚪ 10 (cierre 1 de D2): «parcial» solo si la pasada YA escribió algo; con cero escrituras el reporte viaja igual
  // (`partial: false`) y el comando dice que no se escribió nada — la marca `markPartialWrite` y la letra, de acuerdo.
  // Cierre 2 de D2 · 🟠 N1: o lo dice el DRIVER — un `relate` de renovación de `openfga` (delete + write) cuyo 2.º
  // `Write` falla ya BORRÓ: el error llega marcado (`isPartialWrite`) aunque la pasada no hubiera completado ninguna
  // escritura, y «sin escribir nada» sería falso.
  const partial = writes > 0 || isPartialWrite(error)
  report.partial = partial
  const out = partial && error && typeof error === 'object' ? markPartialWrite(error) : error
  try {
    if (out && typeof out === 'object' && Object.isExtensible(out)) (out as any).report = report
  } catch {
    /* un error congelado no lleva el reporte; el original no se sustituye */
  }
  return out
}

/**
 * **Las fases de una partición** (lote D · D2; analista §4.7, juez ronda 2 · R2-5, tester S4/S5), en el ORDEN del punto
 * de paso ÚNICO `relationTransitionOrder` (`src/relations/tuple_order.ts`, compartido con las purgas de `openfga`). Desde
 * el cierre 2 de D2 (🟡 N3) el orden es el de la TRANSICIÓN entera —escrituras, renovaciones y poda en UNA secuencia—:
 * (1) denies nuevos y rehechos (`to.deny`), (2) con `prune` allows sobrantes (`unrelate`), (3) membresías
 * `group:*#member` que entran y que salen por el grafo de precedencias, (4) allows nuevos y renovaciones (`relate`), (5)
 * con `prune` denies sobrantes (`to.removeDeny`), los ÚLTIMOS. Hasta el cierre 2 TODAS las escrituras iban antes que
 * TODA la poda, y un ex-miembro componía con un allow nuevo (U ∈ g sobra y `g#member viewer X` es nuevo: cortada tras la
 * primera escritura, U concedía sobre X). Cortada en cualquier punto, ningún estado concede lo que no concedían ni el
 * estado inicial ni el final, salvo el RESIDUO que `relationTransitionOrder` devuelve (un ciclo del grafo de precedencias;
 * se lista en `report.orderResidue`). **Ningún deny pasa por `relateOrSkip`**: un error al escribir un deny se propaga
 * (la puerta del plan ya decidió que se puede escribir; si el driver dice otra cosa, es una contradicción que aborta).
 * Son las propiedades `relations.reconcile.order` y `relations.order.exhaustive` de la guardia de superficie (L10).
 */
async function applyPartition(
  plan: PartitionPlan,
  row: RelationsReconcilePartitionReport,
  report: RelationsReconcileReport,
  context: { to: RelationsDriver; dryRun: boolean; prune: boolean; progress: { writes: number }; cuts?: RelationCuts }
): Promise<void> {
  const { to, dryRun, prune, progress, cuts } = context
  // Cierre 4 de D2 · 🟡 C3-2: el deny condicional que el destino no puede rehacer se decide en el PLAN (dry == real).
  const conditional = plan.denyConditional
  row.unchanged = plan.unchanged + plan.denyUnchanged
  row.denies.unchanged = plan.denyUnchanged
  // ⚪ R2 + cierres 1, 2 y 3 del lote B (una regla por FILA): el residuo del destino y lo enumerado fuera de la
  // gramática se LISTA siempre, en los dos lados; con `prune` el del destino lleva `pruned: false` desde el plan. El
  // `renewal-unsafe` (cierre 2 de D2 · 🟠 N1) no es un borrado: no lleva `pruned`.
  // Cierre 4 de D2: `deny-conditional` (ya del PLAN) lleva `pruned: false` siempre.
  const PRUNABLE = new Set(['invalid-identity', 'userset-unsupported', 'undeclared', 'invalid-condition'])
  for (const detail of plan.details) {
    report.details!.push(prune && detail.side === 'destino' && PRUNABLE.has(detail.reason) ? { ...detail, pruned: false } : detail)
  }
  // Cierre 2 de D2 · 🟡 N3: UNA secuencia para la transición entera (el mismo cálculo en `--dry-run` y en la real).
  // Cierre 3 de D2 · 🟡 C2-2: las sobrantes VENCIDAS no conectan nada: se borran PRIMERO y FUERA del orden. Dentro, un deny
  // vencido que se poda contaba en el grafo unión como un deny que «ya niega» y quitaba una precedencia (medido por la
  // fuerza bruta con vigencia: U ∈ h entraba antes de que h ⊂ g saliera).
  const liveDeletes = [...plan.allowDelete, ...plan.denyDelete].filter((tuple) => !plan.expiredDelete.has(tuple))
  const transition = relationTransitionOrder(
    {
      writes: [...plan.denyWrite, ...plan.toWrite],
      deletes: prune ? liveDeletes : [],
      renewals: [...plan.denyUpdate, ...plan.toUpdate],
      // Cierre 4 de D2 · 🟡 horizonte: las renovaciones que ACORTAN salen en su caducidad nueva (y las que alargan entran
      // en la vieja): el orden las trata así para que un corte que dure hasta entonces no conceda.
      shortening: plan.shortening,
      context: plan.orderContext,
    },
    orderView,
    cuts ? { cuts } : {}
  )
  for (const tuple of transition.residue) report.orderResidue!.push(describeTuple(tuple))
  let refused = 0
  if (dryRun) {
    row.written = plan.toWrite.length + plan.denyWrite.length
    row.updated = plan.toUpdate.length + plan.denyUpdate.length
    row.denies.written = plan.denyWrite.length
    row.denies.updated = plan.denyUpdate.length
    if (prune) {
      row.deleted = plan.allowDelete.length + plan.denyDelete.length
      row.denies.deleted = plan.denyDelete.length
    }
  } else {
    // La caducidad de un allow viaja EXPLÍCITA (`Date` la fija, `null` la quita): un `relate` sin opciones PRESERVARÍA
    // la del destino (invariante 10). L-0: el DRIVER del destino aplica F-05 (`assertRelationDeclared`), así que sin
    // `toConfig` —o con una que no coincida con la del driver— es SU 422 el que embuda la tupla no declarada: se cuenta en
    // `skipped.undeclared` y se descuenta de `written`/`updated` (capa 2 del registro `RELATION_REJECTIONS`). La poda
    // NUNCA lanza por un 422 de la familia de relaciones (🟠 N9, capa 2): se clasifica por `code` y se sigue.
    const steps: Array<{ item: RelationTuple; op: 'write' | 'delete' | 'renew' }> = [
      ...(prune ? [...plan.expiredDelete].map((item) => ({ item, op: 'delete' as const })) : []),
      ...transition.steps,
    ]
    for (const step of steps) {
      const tuple = step.item
      if (step.op === 'delete') {
        const op = kindOf(tuple) === 'deny' ? 'removeDeny' : 'unrelate'
        const refusal = await deleteOrClassify(to, tuple, op)
        if (refusal === null) {
          progress.writes++
          row.deleted += 1
          if (op === 'removeDeny') row.denies.deleted += 1
          continue
        }
        report.details!.push({ side: 'destino', reason: refusal.reason, tuple: describeTuple(tuple), message: refusal.message, pruned: false })
        refused += 1
        if (op === 'removeDeny') row.denies.extra += 1
        continue
      }
      const counter = step.op === 'write' ? ('written' as const) : ('updated' as const)
      if (kindOf(tuple) === 'deny') {
        // Cierre 4 de D2 · 🟡 C3-2: el deny condicional que el destino no puede rehacer ya lo apartó el PLAN (sin
        // `atomicRenewal`): desde el cierre 5 NIEGA su partición entera, que no llega aquí. Si el driver lo dice igual (500 `denyConditional` de un
        // driver que declara `atomicRenewal`), es una contradicción con su capacidad: se propaga (hasta el cierre 4 la
        // pasada lo listaba y SEGUÍA escribiendo los allows que ese deny cortaba).
        await to.deny!(tuple.subject, tuple.relation, tuple.object, tuple.partition)
        progress.writes++
        row[counter] += 1
        row.denies[counter] += 1
        continue
      }
      if (await relateOrSkip(to, tuple)) {
        progress.writes++
        row[counter] += 1
        continue
      }
      report.skipped.undeclared += 1
    }
  }
  if (!prune) row.denies.extra += plan.denyDelete.length
  row.denies.extra += conditional
  // El residuo del destino (los tres motivos) sobra SIEMPRE, con o sin `prune`: no está en `toDelete`, así que se suma
  // aparte — más lo que el driver rechazó con un 422 de la familia en la pasada real (capa 2 de N9). (Desde el cierre 5
  // una partición con `deny-conditional` está NEGADA y no llega aquí: `conditional` es 0 en una partición aplicada.)
  row.extra = (prune ? 0 : plan.allowDelete.length + plan.denyDelete.length) + plan.destResidue + refused + conditional
}

/**
 * **La puerta del deny** (lote D · D2): las negativas de TODAS las particiones, decididas por el DRIVER DESTINO
 * (`capabilities.relationDenies` + `denyPhase`, que en `openfga` comprueba además el modelo fijado, D-31) y por lo que
 * el plan ya vio (denies sin `kind`, F-05 con `toConfig`, identidad/sujeto que el destino no admite). Un par
 * tipo/relación se pregunta UNA vez. Para ESCRIBIR un deny el tipo tiene que estar en `'write'`; para uno que el
 * destino YA tiene basta con que lo honre (opt-in en cualquier fase). Nunca escribe.
 */
async function denyGate(to: RelationsDriver, plans: PartitionPlan[]): Promise<DenyRefusal[]> {
  const refusals: DenyRefusal[] = []
  const seen = new Set<string>()
  const push = (refusal: DenyRefusal) => {
    const id = `${refusal.objectType}#${refusal.relation}:${refusal.reason}`
    if (seen.has(id)) return
    seen.add(id)
    refusals.push(refusal)
  }
  for (const plan of plans) for (const refusal of plan.denyRefusals) push(refusal)
  // Qué fase hace falta por par: 'write' si hay algo que escribir; 'honored' si solo hay denies que ya están.
  const needed = new Map<string, { objectType: string; relation: string; write: boolean }>()
  for (const plan of plans) {
    // Cierre 5 de D2: una partición NEGADA por el plan no escribe nada — sus denies no piden fase.
    if (plan.refusal) continue
    for (const [list, write] of [
      [[...plan.denyWrite, ...plan.denyUpdate], true],
      [plan.denyPresent, false],
    ] as const) {
      for (const tuple of list) {
        const id = `${tuple.object.type}#${tuple.relation}`
        const prev = needed.get(id)
        needed.set(id, { objectType: tuple.object.type, relation: tuple.relation, write: (prev?.write ?? false) || write })
      }
    }
  }
  if (needed.size === 0) return refusals
  const capable = to.capabilities?.relationDenies === true && typeof to.deny === 'function' && typeof to.removeDeny === 'function'
  for (const { objectType, relation, write } of needed.values()) {
    if (!capable) {
      push({
        objectType,
        relation,
        reason: 'no-capability',
        message:
          `el destino no declara relationDenies (o no trae deny/removeDeny): no puede escribir ni honrar el deny de ` +
          `${objectType}#${relation}`,
        recipe: denyRefusalRecipe('no-capability', objectType, relation),
      })
      continue
    }
    if (typeof to.denyPhase !== 'function') {
      push({
        objectType,
        relation,
        reason: 'no-deny-phase',
        message: `el destino declara relationDenies pero no trae denyPhase: no puede decir si ${objectType} admite deny (opt-in por tipo)`,
        recipe: denyRefusalRecipe('no-deny-phase', objectType, relation),
      })
      continue
    }
    let phase: 'read' | 'write' | null
    try {
      phase = await to.denyPhase({ type: objectType }, relation)
    } catch (error: any) {
      const rejection = error?.status === 422 ? RELATION_REJECTIONS[String(error?.code)] : undefined
      if (rejection?.kind === 'classified' && rejection.reason === 'undeclared') {
        push({ objectType, relation, reason: 'undeclared', message: String(error?.message ?? error), recipe: denyRefusalRecipe('undeclared', objectType, relation) })
        continue
      }
      if (error?.status === 500 && error?.code === AuthorizationConfigError.code) {
        push({ objectType, relation, reason: 'model', message: String(error?.message ?? error), recipe: denyRefusalRecipe('model', objectType, relation) })
        continue
      }
      throw error
    }
    if (write ? phase !== 'write' : phase === null) {
      push({
        objectType,
        relation,
        reason: 'phase',
        message:
          `en el DESTINO el tipo '${objectType}' está ${phase === null ? 'SIN opt-in de deny' : `en la fase '${phase}'`} y ` +
          `${write ? "escribir un deny exige deny: 'write' (en TODO destino)" : 'un deny que ya está exige que el destino lo honre (opt-in)'} ` +
          `(su config, no la spec persistida)` +
          // ⚪ 11 (cierre 1 de D2): por qué se niega aunque un destino `database` honre la fila igual (D8).
          (write
            ? ''
            : '. Un destino database honra un denied_* existente también sin opt-in (D8), pero la pasada no puede saberlo por ' +
              'el puerto: denyPhase = null significa «sin opt-in», y certificar un deny que el destino no declara honrar ' +
              'convertiría un detalle de implementación en la garantía'),
        recipe: denyRefusalRecipe('phase', objectType, relation, !write),
      })
    }
  }
  return refusals
}

/** El 500 de la puerta (S6/R2-5): la letra empieza por el prefijo ESTABLE «deny NO migrable:» (punto 7). */
function denyRefusedError(refusals: DenyRefusal[], partitions: number): DenyMigrationRefusedError {
  const error = new DenyMigrationRefusedError(
    `deny NO migrable: authz:relations:reconcile se NIEGA — ${refusals.length} caso(s): ` +
      refusals.map((r) => `(${r.reason}) ${r.objectType}#${r.relation}: ${r.message}`).join('; ') +
      `. Perder un deny no es una pérdida que se pueda declarar (escribir los allows sin él concedería lo que el origen niega). ` +
      `No se ha escrito nada${partitions > 1 ? ' en ninguna partición' : ''}. Recetas (una por motivo): ` +
      refusals.map((r) => `(${r.reason}) ${r.recipe}`).join(' ')
  )
  error.refusals = Object.freeze(refusals.map((r) => Object.freeze({ ...r })))
  return error
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
  return `${tuple?.kind === 'deny' ? '[deny] ' : ''}${partition} ${tuple?.object?.type}:${tuple?.object?.id}#${tuple?.relation}@${subject}`
}

/** `tupleKey` de una tupla ENUMERADA: la clave, o el motivo por el que su identidad no entra en la gramática (⚪ R2). */
function enumeratedKey(tuple: RelationTuple): { key: string } | { message: string } {
  try {
    return { key: tupleKey({ ...tuple, kind: kindOf(tuple) }) }
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
  /** Allows a escribir / con otra caducidad / sobrantes (fases 2 y 3). */
  toWrite: RelationTuple[]
  toUpdate: RelationTuple[]
  allowDelete: RelationTuple[]
  unchanged: number
  /** Lote D · D2: denies a escribir / a rehacer permanentes / ya presentes / sobrantes (fases 1 y 4). */
  denyWrite: RelationTuple[]
  denyUpdate: RelationTuple[]
  denyPresent: RelationTuple[]
  denyUnchanged: number
  denyDelete: RelationTuple[]
  /** Cierre 3 de D2 · 🟡 C2-2: las de `allowDelete`/`denyDelete` VENCIDAS en `now` — se podan antes y fuera del orden. */
  expiredDelete: Set<RelationTuple>
  /** Lote D · D2: lo que el PLAN ya sabe que no se puede migrar (sin `kind`, F-05 con `toConfig`, identidad/sujeto). */
  denyRefusals: DenyRefusal[]
  skipped: { expired: number; undeclared: number; invalid: number; usersetUnsupported: number }
  modelDrift: string[]
  massDelete: boolean
  /** ⚪ R2 + cierres 1/2/3 del lote B: el residuo listado (gramática, B3, F-05 del destino), en ese orden; NUNCA en un borrado. */
  details: RelationsReconcileDetail[]
  /** Cuántas del DESTINO son residuo que nadie borra (los tres motivos): suman a `extra` con o sin `prune`. */
  destResidue: number
  /**
   * Cierre 1 de D2 · 🟠 1: las tuplas que EXISTEN (el origen utilizable y el destino) en la forma del orden: deciden qué
   * grupos transportan un deny (`denyCarrierGroups`) y son el contexto del ORDEN (`relationTransitionOrder`). Desde el
   * cierre 5 de D2 no hay retención: el inicial ∪ el final REAL es exactamente esto (el cierre 4 lo separaba).
   */
  orderContext: RelationOrderView[]
  /** Cierre 4 de D2 · 🟡 horizonte: las de `toUpdate` que ACORTAN la caducidad. */
  shortening: RelationTuple[]
  /** Cierre 4 de D2 · 🟡 C3-2: cuántos denies del origen el destino no puede (re)escribir (`deny-conditional`, del plan). */
  denyConditional: number
  /** Cierre 5 de D2 (opción A): la partición NEGADA —≥ 1 `renewal-unsafe` o `deny-conditional`—: cero escrituras en ella. */
  refusal?: RelationsPartitionRefusal
}

function planPartition(
  partition: ScopeRef,
  enumerated: RelationTuple[],
  destTuples: RelationTuple[],
  context: { now: Date; prune: boolean; toConfig?: RelationsConfig; atomicRenewal: boolean; cuts?: RelationCuts }
): PartitionPlan {
  const { now, prune, toConfig, atomicRenewal, cuts } = context
  // R-15: la caducada LLEGA del origen (el puerto lo exige) y aquí se DESCARTA
  // contándola: no se migra ni respalda nada en el destino. Decidido con UN
  // `now` para toda la pasada.
  // L-0: la tupla cuyo tipo o relación el DESTINO no declara (F-05) se
  // descarta AQUÍ cuando hay `toConfig` —antes del driver, así `--dry-run` y la
  // pasada real dan los mismos números— y tampoco respalda nada en el destino
  // (una que ya estuviera allí es `extra`, y `--prune` la barre). El tipo se
  // reporta además en `modelDrift` (deriva del modelo fusionado).
  // Lote D · D2: un DENY nunca se descarta así — lo que impide escribirlo es una NEGATIVA de la pasada (500), jamás
  // `skipped` (perder un deny no es una pérdida que se pueda declarar). Solo la caducidad lo descarta (no niega nada).
  const skipped = { expired: 0, undeclared: 0, invalid: 0, usersetUnsupported: 0 }
  const modelDrift: string[] = []
  const sourceTuples: RelationTuple[] = []
  const invalid: RelationsReconcileDetail[] = []
  const usersetResidue: RelationsReconcileDetail[] = []
  const undeclaredResidue: RelationsReconcileDetail[] = []
  const denyRefusals: DenyRefusal[] = []
  /** Cierre de L11 (🟡 A2): las membresías (origen o destino) con una condición que el paquete no escribe ni sabe leer. */
  const invalidCarriers: RelationTuple[] = []
  const refuse = (tuple: RelationTuple, reason: DenyRefusal['reason'], message: string) => {
    const objectType = String(tuple?.object?.type)
    const relation = String(tuple?.relation)
    denyRefusals.push({ objectType, relation, reason, message, recipe: denyRefusalRecipe(reason, objectType, relation) })
  }
  for (const tuple of enumerated) {
    // L11 (injerto 3 del juez): una tupla del ORIGEN cuya condición el paquete no escribe o no sabe leer
    // (`invalidCondition`, `fgaTupleExpiry`) NO se migra —su `expiresAt` null no es «permanente»—; se lista y es deriva.
    // Un deny así NIEGA la PASADA (500 `E_AUTHZ_DENY_MIGRATION_REFUSED`: perder un deny no es una pérdida declarable); una
    // MEMBRESÍA así en una partición con algún deny niega SU partición (cierre de L11, abajo).
    if (typeof tuple?.invalidCondition === 'string') {
      if (kindOf(tuple) === 'deny') {
        refuse(tuple, 'invalid', `condición que el paquete no escribe: ${tuple.invalidCondition}`)
        continue
      }
      skipped.invalid += 1
      invalid.push({ side: 'origen', reason: 'invalid-condition', tuple: describeTuple(tuple), message: tuple.invalidCondition })
      // Cierre de L11 (🟡 A2): una MEMBRESÍA así puede ser una portadora VIVA — se decide abajo si niega la partición.
      if (tuple?.object?.type === RELATION_USERSET_TYPE) invalidCarriers.push(tuple)
      continue
    }
    if (!isActiveExpiry(tuple.expiresAt ?? null, now)) {
      skipped.expired += 1
      continue
    }
    const kind = kindOf(tuple)
    // Lote D · D2: una tupla con la relación ALMACENADA de un deny (`denied_*`, prefijo reservado) y sin `kind: 'deny'`
    // es un deny que el driver de ORIGEN no marcó: migrarla como allow escribiría `relate(denied_viewer)` (422) o la
    // contaría como no declarada — y el deny se perdería. Negativa (500), nunca `skipped`.
    if (kind === 'allow' && typeof tuple.relation === 'string' && tuple.relation.startsWith(RELATION_DENY_PREFIX)) {
      refuse(
        tuple,
        'unmarked',
        `el ORIGEN enumera ${describeTuple(tuple)} sin kind: 'deny' (un driver que declara relationDenies tiene que marcar kind; ` +
          `un proceso < 2.5.0-alpha.3 no lo hace)`
      )
      continue
    }
    // ⚪ R2: una identidad fuera de la gramática en el ORIGEN no es una pregunta
    // del llamante (invariante 5): no se migra —la API del destino no podría
    // escribirla—, se lista y se cuenta. Nunca un 422 por un dato del store.
    const keyed = enumeratedKey(tuple)
    if ('message' in keyed) {
      if (kind === 'deny') {
        refuse(tuple, 'invalid', `identidad fuera de la gramática: ${keyed.message}`)
        continue
      }
      skipped.invalid += 1
      invalid.push({ side: 'origen', reason: 'invalid-identity', tuple: describeTuple(tuple), message: keyed.message })
      continue
    }
    // Cierre 1 del lote B · 🟠 2: el residuo pre-2.5 de B3 en el ORIGEN se
    // clasifica AQUÍ, con o sin `toConfig` — no se migra (ninguna puerta del
    // destino lo admite), se lista con su receta y se cuenta aparte. Hasta el
    // cierre llegaba al driver, que lo rechazaba con 422, y `relateOrSkip` lo
    // tragaba como `undeclared` (consejo falso; `--dry-run` decía `written`).
    const subject = classifySubject(tuple, toConfig)
    if (subject.kind === 'userset-unsupported') {
      if (kind === 'deny') {
        refuse(tuple, 'invalid', `sujeto que el destino no admite: ${subject.message}`)
        continue
      }
      skipped.usersetUnsupported += 1
      usersetResidue.push({ side: 'origen', reason: 'userset-unsupported', tuple: describeTuple(tuple), message: subject.message })
      continue
    }
    if (subject.kind === 'undeclared') {
      if (kind === 'deny') {
        refuse(tuple, 'undeclared', `el sujeto userset de ${describeTuple(tuple)} no está declarado en el destino`)
        continue
      }
      skipped.undeclared += 1
      continue
    }
    if (toConfig && !declaredIn(toConfig, tuple.object.type)) {
      if (kind === 'deny') {
        refuse(tuple, 'undeclared', `el destino no declara el tipo '${tuple.object.type}'`)
        continue
      }
      skipped.undeclared += 1
      if (!modelDrift.includes(tuple.object.type)) modelDrift.push(tuple.object.type)
      continue
    }
    if (toConfig && !toConfig.isDeclared(tuple.object.type, tuple.relation)) {
      if (kind === 'deny') {
        refuse(tuple, 'undeclared', `el destino no declara la relación '${tuple.relation}' en '${tuple.object.type}'`)
        continue
      }
      skipped.undeclared += 1
      continue
    }
    sourceTuples.push(tuple)
  }

  const sourceByKey = new Map<string, RelationTuple>()
  for (const tuple of sourceTuples) sourceByKey.set(tupleKey({ ...tuple, kind: kindOf(tuple) }), tuple)
  // ⚪ R2 + cierre 2 · N3: una tupla del DESTINO fuera de la gramática es
  // `extra` con motivo (`invalid-identity`): nadie del origen puede respaldarla
  // (la clave no se puede ni componer) y NADIE la borra — ni `toDelete` (los dos
  // drivers del paquete la rechazan por el puerto, R-16; hasta el cierre 2 se les
  // pedía igual) ni un DELETE de plataforma—: se lista con `pruned: false` y es
  // deriva en los cuatro modos, exactamente como el residuo de B3 de abajo.
  const destByKey = new Map<string, RelationTuple>()
  /** Cierre 4 de D2 · 🟡 C3-2: los denies del destino VENCIDOS (no cuentan como presentes, pero el destino los tiene). */
  const expiredDenyByKey = new Map<string, RelationTuple>()
  const residue = new Set<RelationTuple>()
  /** L11: las claves del destino con una condición que el paquete no escribe: el origen no las reescribe. */
  const blockedKeys = new Set<string>()
  for (const tuple of destTuples) {
    // ⚪ 8 (cierre 1 de D2): un deny del DESTINO sin `kind` (un driver de terceros que no marca) es la MISMA negativa
    // `unmarked` que en el origen, decidida en el PLAN: planificarlo como allow lo podaría con `unrelate(denied_*)` (que
    // D-04 prohíbe y F-05 rechaza con un motivo equivocado) o lo contaría como allow que sobra.
    if (kindOf(tuple) === 'allow' && typeof tuple?.relation === 'string' && tuple.relation.startsWith(RELATION_DENY_PREFIX)) {
      residue.add(tuple)
      refuse(
        tuple,
        'unmarked',
        `el DESTINO enumera ${describeTuple(tuple)} sin kind: 'deny' (un driver que declara relationDenies tiene que marcar kind)`
      )
      continue
    }
    const keyed = enumeratedKey(tuple)
    if ('message' in keyed) {
      residue.add(tuple)
      invalid.push({ side: 'destino', reason: 'invalid-identity', tuple: describeTuple(tuple), message: keyed.message })
      continue
    }
    // Cierre 1 del lote B · 🟠 1: el residuo pre-2.5 de B3 en el DESTINO sobra
    // (nadie del origen puede respaldarlo: el origen lo descarta arriba) pero
    // NO entra en un borrado: la pasada no se lo pide al driver ni con `--prune`
    // —`unrelate` lo rechazaría con 422 y hasta el cierre eso ABORTABA la pasada
    // a mitad, con los `toWrite` ya escritos—. Se lista con `pruned: false` y
    // la receta, cuenta en `extra` y es deriva.
    const subject = classifySubject(tuple, undefined)
    if (subject.kind === 'userset-unsupported') {
      residue.add(tuple)
      usersetResidue.push({ side: 'destino', reason: 'userset-unsupported', tuple: describeTuple(tuple), message: subject.message })
      continue
    }
    // Cierre 3 del lote B · 🟠 N9 (capa 1): la fila cuya RELACIÓN o TIPO el
    // destino (`toConfig`) ya no declara — una relación retirada de la config con
    // filas vivas — es la tercera fila que la API no admite: `unrelate`/`removeDeny`
    // la rechazan por F-05, así que lleva la MISMA regla que las dos de arriba.
    const undeclared = toConfig ? classifyDestinationRow(toConfig, tuple) : null
    if (undeclared !== null) {
      residue.add(tuple)
      undeclaredResidue.push({ side: 'destino', reason: 'undeclared', tuple: describeTuple(tuple), message: undeclared })
      continue
    }
    // L11 · H8: una tupla del DESTINO con una condición que el paquete no escribe es PRESENTE e INTOCABLE: `extra` con
    // motivo y nunca `toDelete` (ni con `--prune`), y su CLAVE no se reescribe desde el origen (un `relate` sobre ella es
    // 409 a mitad de pasada). No entra en el contexto del orden, y NO porque el servidor la ignore —un `not_expired` con
    // `current_time` congelado está VIVO (medido, H2)—, sino porque si es una MEMBRESÍA (la única forma de transportar un
    // deny) en una partición con algún deny, la partición se NIEGA (cierre de L11, 🟡 A2: cero escrituras, el orden no se
    // usa); sin ningún deny en la partición no transporta nada que el orden tenga que ordenar.
    if (typeof tuple?.invalidCondition === 'string') {
      residue.add(tuple)
      invalid.push({ side: 'destino', reason: 'invalid-condition', tuple: describeTuple(tuple), message: tuple.invalidCondition })
      blockedKeys.add(keyed.key)
      if (tuple?.object?.type === RELATION_USERSET_TYPE) invalidCarriers.push(tuple)
      continue
    }
    // Cierre 3 de D2 · 🟠 C2-1 / 🟡 C2-2: una tupla del destino VENCIDA en `now` (el MISMO `now` con el que el origen
    // descarta las suyas) no conecta nada —ni en `database` ni en FGA— y el plan la trata como AUSENTE: su reescritura es
    // una escritura normal (nunca `toUpdate`, nunca `renewal-unsafe`) y no entra en el contexto del orden (ni portadora,
    // ni arista del auto-corte, ni «renovación» de la fase 4). Hasta el cierre 3 contaba como viva: una membresía
    // portadora caducada se clasificaba `renewal-unsafe` mientras el allow nuevo SÍ se escribía, y el destino concedía a
    // un denegado para siempre (R4 del auditor). Sin `--prune` sigue en el destino (sobra, vencida) y con él se barre.
    if (!liveInDestination(tuple, now)) {
      if (kindOf(tuple) === 'deny') expiredDenyByKey.set(keyed.key, tuple)
      continue
    }
    destByKey.set(keyed.key, tuple)
  }
  // L11 · H8: una clave que el destino tiene con una condición que el paquete no escribe NO se reescribe desde el origen
  // (sería un `relate` que el driver rechaza con 409 a mitad de pasada): la tupla del origen se lista y es deriva; un deny
  // NIEGA la partición. Sale también del contexto del orden (no se va a escribir).
  for (const key of blockedKeys) {
    const tuple = sourceByKey.get(key)
    if (!tuple) continue
    sourceByKey.delete(key)
    sourceTuples.splice(sourceTuples.indexOf(tuple), 1)
    if (kindOf(tuple) === 'deny') {
      refuse(tuple, 'invalid', `el DESTINO tiene ${describeTuple(tuple)} con una condición que el paquete no escribe`)
      continue
    }
    skipped.invalid += 1
    invalid.push({
      side: 'origen',
      reason: 'invalid-condition',
      tuple: describeTuple(tuple),
      message: 'la clave existe en el DESTINO con una condición que el paquete no escribe: no se reescribe (bórrala allí a mano y repite)',
    })
  }

  const toWrite: RelationTuple[] = []
  const toUpdate: RelationTuple[] = []
  const denyWrite: RelationTuple[] = []
  const denyUpdate: RelationTuple[] = []
  const denyPresent: RelationTuple[] = []
  const denyConditional: RelationsReconcileDetail[] = []
  let unchanged = 0
  let denyUnchanged = 0
  for (const [key, tuple] of sourceByKey) {
    const present = destByKey.get(key)
    if (kindOf(tuple) === 'deny') {
      // Cierre 4 de D2 · 🟡 C3-2: un deny del destino CON caducidad —vivo con otra, o ya VENCIDO— que el origen tiene, en
      // un destino que no declara `atomicRenewal` (`openfga`: no reemplaza la misma clave en un `Write`, M5, y lo dice con
      // 500 `conditionalDeny`), no se puede rehacer permanente. Se decide AQUÍ (mismos números en `--dry-run` y real;
      // hasta el cierre 4 lo decidía el driver en la pasada real, y la pasada escribía los allows que ese deny corta):
      // residuo `deny-conditional` y, desde el cierre 5 (opción A), su PARTICIÓN queda NEGADA (cero escrituras en ella).
      // Para la puerta cuenta como un deny que el destino tiene (tiene que honrarlo).
      const stale = present ?? expiredDenyByKey.get(key)
      if (!atomicRenewal && stale && stale.expiresAt != null && !sameInstant(stale.expiresAt, tuple.expiresAt ?? null)) {
        const expired = !present
        denyPresent.push(tuple)
        denyConditional.push({
          side: 'destino',
          reason: 'deny-conditional',
          tuple: describeTuple(stale),
          message:
            `el deny del destino tiene caducidad (${stale.expiresAt.toISOString()}, ${expired ? 'YA VENCIDO: no niega nada' : 'vivo: niega hasta entonces'}) ` +
            `y el origen lo tiene ${tuple.expiresAt ? `hasta ${tuple.expiresAt.toISOString()}` : 'permanente'}; el destino no declara atomicRenewal ` +
            `(openfga no reemplaza la misma clave en un Write, M5) y no puede rehacerlo en una escritura. No se reescribe y la ` +
            `PARTICIÓN ${scopeKey(partition)} queda NEGADA: cero escrituras y cero borrados en ella (su destino queda como estaba, ` +
            `con su deriva a la vista); el resto de particiones migra. Receta: ${partitionRefusalRecipe(['deny-conditional'])}`,
          pruned: false,
        })
        continue
      }
      // D3: un deny no caduca. Uno del destino SIN caducidad es el mismo deny (el del origen, con o sin una caducidad
      // escrita a mano, deniega lo mismo o menos tiempo). Uno del destino CON caducidad distinta se rehace permanente
      // (`to.deny`): dejarlo caducar concedería lo que el origen niega. Nunca delete+write (R2-8: no hay `toUpdate` de
      // denies por `relate`).
      if (!present) denyWrite.push(tuple)
      else if (present.expiresAt != null && !sameInstant(present.expiresAt, tuple.expiresAt ?? null)) denyUpdate.push(tuple)
      else {
        denyUnchanged += 1
        denyPresent.push(tuple)
      }
      continue
    }
    if (!present) toWrite.push(tuple)
    // Misma clave, OTRA caducidad ⇒ se reescribe con la del origen (R-15).
    else if (!sameInstant(present.expiresAt ?? null, tuple.expiresAt ?? null)) toUpdate.push(tuple)
    else unchanged += 1
  }
  const allowDelete: RelationTuple[] = []
  const denyDelete: RelationTuple[] = []
  const expiredDelete = new Set<RelationTuple>()
  for (const tuple of destTuples) {
    if (residue.has(tuple)) continue
    if (sourceByKey.has(tupleKey({ ...tuple, kind: kindOf(tuple) }))) continue
    if (kindOf(tuple) === 'deny') denyDelete.push(tuple)
    else allowDelete.push(tuple)
    if (!liveInDestination(tuple, now)) expiredDelete.add(tuple)
  }
  const massDelete = prune && allowDelete.length + denyDelete.length > 0 && sourceTuples.length === 0
  const orderContext = [...sourceTuples, ...destByKey.values()].map(orderView)
  // Cierre 2 de D2 · 🟠 N1: la RENOVACIÓN de una membresía que transporta un deny (en el grafo de los DOS estados: los
  // denies del destino siguen vivos hasta el final de la pasada y los del origen se escriben primero) en un destino que
  // renueva con delete + write (sin `atomicRenewal`) dejaría al sujeto SIN el deny entre los dos `Write`. El plan no la
  // renueva: la lista (`renewal-unsafe`, con su receta) y es deriva. Los mismos números en `--dry-run` y en la real.
  const renewalUnsafe: RelationsReconcileDetail[] = []
  const evolves: NonNullable<RelationsPartitionRefusal['evolves']> = []
  /** La caducidad que el DESTINO tiene de una tupla de `toUpdate` (viva). */
  const destExpiry = (tuple: RelationTuple): Date | null => destByKey.get(tupleKey({ ...tuple, kind: kindOf(tuple) }))?.expiresAt ?? null
  /** ¿La renovación ALARGA la caducidad (la del origen es posterior o `null`)? */
  const extends_ = (tuple: RelationTuple): boolean => {
    const old = destExpiry(tuple)
    return tuple.expiresAt == null || (old != null && tuple.expiresAt.getTime() > old.getTime())
  }
  if (!atomicRenewal && toUpdate.length > 0) {
    const carriers = denyCarrierGroups(orderContext)
    for (let i = toUpdate.length - 1; i >= 0; i--) {
      const tuple = toUpdate[i]
      if (tuple.object.type !== RELATION_USERSET_TYPE || !carriers.has(`${tuple.object.type}:${tuple.object.id}`)) continue
      toUpdate.splice(i, 1)
      const old = destExpiry(tuple)
      const newer = tuple.expiresAt ? tuple.expiresAt.toISOString() : 'sin caducidad'
      // Cierre 6 de D2 · ⚪ D5-3 (E3): «como estaba» NO es estático. Si la renovación ALARGA, desde la caducidad vieja el
      // destino ya no transporta los denies del grupo por esta membresía y CONCEDE lo que cortan (si otro camino lo da),
      // cosa que el origen sigue negando: la línea lo dice con fecha y con qué, en vez de dejar que el operador lo deduzca.
      const member = orderView(tuple).user
      const cut = carriedDenies([...destByKey.values()].map(orderView), `${tuple.object.type}:${tuple.object.id}`).map(
        (v) => `${v.relation} sobre ${v.object}`
      )
      if (extends_(tuple) && old !== null && cut.length > 0) evolves.unshift({ at: old.toISOString(), member, cut })
      const grantsLater =
        old !== null && cut.length > 0
          ? ` A partir de ${old.toISOString()} el destino CONCEDERÁ a ${member} lo que cortan esos denies (${cut.join(', ')}) si ` +
            `otro camino se lo da, y el origen lo sigue negando: negar la partición NO congela el tiempo.`
          : ''
      renewalUnsafe.unshift({
        side: 'destino',
        reason: 'renewal-unsafe',
        tuple: describeTuple(tuple),
        message:
          `la membresía cambia de caducidad (destino ${old ? old.toISOString() : 'sin caducidad'}, origen ${newer}) y su grupo ` +
          `TRANSPORTA un deny vivo; el destino renueva con delete + write (no declara atomicRenewal) y entre los dos el deny no ` +
          `alcanzaría al sujeto. No se renueva y la PARTICIÓN ${scopeKey(partition)} queda NEGADA: cero escrituras y cero ` +
          `borrados en ella (su destino queda como estaba, con su deriva a la vista); el resto de particiones migra. ` +
          `${extends_(tuple) ? `Desde ${old ? old.toISOString() : '—'} el destino ya no transporta ese deny por esta membresía.${grantsLater}` : `Hasta ${old ? old.toISOString() : '—'} el destino la conserva más que el origen (${newer}).`} ` +
          `Receta: ${partitionRefusalRecipe(['renewal-unsafe'])}`,
      })
    }
  }
  // **Cierre 5 de D2 (decisión del dueño §2026-10-16 (10), opción A)**: una partición con ≥ 1 `renewal-unsafe` o
  // `deny-conditional` —lo que el destino no puede escribir en una escritura— recibe CERO escrituras y CERO borrados
  // (también con `--prune` y las vencidas): queda EXACTAMENTE como estaba, que es lo único certificable; el resto migra.
  // Sustituye a la retención del cierre 4 (`relationWithheldWrites`, `withheld-by-unsafe-deny`, `carrier-conflict`): retener
  // tupla a tupla no cubría lo que el destino YA concedía (D4-1) y su negativa era global (D4-3).
  const causes: RelationsPartitionRefusal['causes'] = [...denyConditional, ...renewalUnsafe].map((detail) => ({
    reason: detail.reason as 'renewal-unsafe' | 'deny-conditional',
    tuple: detail.tuple,
  }))
  // **Cierre de L11 (🟡 A2 del auditor; criterio del dueño: ante la duda, la opción que nunca concede de más)**: una
  // membresía `foreign`/`unparseable` (origen o destino) en una partición con ALGÚN deny (origen o destino, vivo o no,
  // marcado o no) NIEGA la partición. El servidor puede estar evaluándola VIVA y transportando ese deny; migrarla sin ella
  // —o escribir en el destino alrededor de ella— fabricaba un `check = true` que ningún estado del origen concedía (medido:
  // `.claude/reproducciones/loteRC-L11-auditor-carrier.ts`). Mismo mecanismo que la opción A: cero escrituras en ella.
  const anyDeny = [...enumerated, ...destTuples].some(
    (tuple) => kindOf(tuple) === 'deny' || String(tuple?.relation ?? '').startsWith(RELATION_DENY_PREFIX)
  )
  if (anyDeny) for (const tuple of invalidCarriers) causes.push({ reason: 'invalid-condition', tuple: describeTuple(tuple) })
  const refusal: RelationsPartitionRefusal | undefined =
    causes.length > 0
      ? {
          partition: scopeKey(partition),
          causes,
          pending: {
            write: toWrite.length + denyWrite.length,
            update: toUpdate.length + denyUpdate.length + denyConditional.length + renewalUnsafe.length,
            delete: prune ? allowDelete.length + denyDelete.length : 0,
          },
          recipe: partitionRefusalRecipe(causes.map((cause) => cause.reason)),
          ...(evolves.length > 0 ? { evolves } : {}),
        }
      : undefined
  const shortening = toUpdate.filter((tuple) => !extends_(tuple))
  return {
    partition,
    enumerated: enumerated.length,
    toWrite,
    toUpdate,
    allowDelete,
    unchanged,
    denyWrite,
    denyUpdate,
    denyPresent,
    denyUnchanged,
    denyDelete,
    expiredDelete,
    denyRefusals,
    skipped,
    modelDrift,
    // Una partición NEGADA no borra nada: el seguro de borrado masivo no aplica.
    massDelete: massDelete && !refusal,
    details: [...invalid, ...usersetResidue, ...undeclaredResidue, ...denyConditional, ...renewalUnsafe],
    destResidue: residue.size,
    orderContext,
    shortening,
    denyConditional: denyConditional.length,
    refusal,
  }
}

/**
 * **¿Cuenta una tupla del DESTINO en el plan?** (cierre 3 de D2 · 🟠 C2-1 / 🟡 C2-2): sí si está VIVA en `now` (el mismo
 * `now` de toda la pasada, con el que el origen descarta sus caducadas); una VENCIDA es AUSENTE — no conecta nada en
 * ningún driver—, así que ni se «renueva» ni entra en el contexto del orden. Punto de paso ÚNICO de la regla: lo usa
 * `planPartition` y la fuerza bruta del orden (`tests/helpers/order_bruteforce.ts`, universo con vigencia) deriva con
 * ÉL qué es escritura, renovación y contexto — un mutante que ignore la vigencia aquí pone rojos los dos.
 */
export function liveInDestination(tuple: { expiresAt?: Date | null }, now: Date): boolean {
  return isActiveExpiry(tuple.expiresAt ?? null, now)
}

/**
 * La vista de ORDEN de una tupla ya planificada (cierre 1 de D2 · 🟠 1): objeto `<tipo>:<id>` y sujeto `<tipo>:<uuid>` o
 * `<tipo>:<id>#<rel>` — sin partición: el plan es de UNA partición.
 */
function orderView(tuple: RelationTuple): RelationOrderView {
  const s: any = tuple.subject
  return {
    deny: kindOf(tuple) === 'deny',
    object: `${tuple.object.type}:${tuple.object.id}`,
    user: isRelUserset(s) ? `${s.object.type}:${s.object.id}#${s.relation}` : `${s.type}:${s.uuid}`,
    relation: tuple.relation,
  }
}

/** El `kind` de una tupla enumerada: `deny` solo si el driver lo marca; ausente = `allow` (tipo exportado opcional). */
function kindOf(tuple: RelationTuple): RelationTupleKind {
  return tuple?.kind === 'deny' ? 'deny' : 'allow'
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
 * **El REGISTRO de los 422 del puerto de relaciones, clasificados** (plan 2.5 · lote D · D2; linaje **L9** «clasificación
 * en el punto equivocado», decisión del dueño 2026-10-15 (7): R2-5 → lote B decisión 4 → cierre 3 N9). Propiedad
 * universal: **el PLAN clasifica toda tupla por su motivo ANTES del driver; el driver solo rechaza; ningún catch convierte
 * un 422 en otro bucket que no sea el que este registro dice**. Cada clase 422 que el puerto de relaciones puede lanzar
 * tiene aquí UNA entrada:
 *
 *  - `classified`: el plan la anticipa (`enumeratedKey` / `classifySubject` / `classifyDestinationRow` / `toConfig`) y la
 *    lista con `reason` en `details` (o la cuenta en `skipped`) sin pedírsela al driver; si el driver la lanza igual (sin
 *    `toConfig`, o un driver de terceros que contradice al plan), la capa 2 (`relateOrSkip`/`deleteOrClassify`) la
 *    clasifica con ESTE mismo `reason` y sigue;
 *  - `refused`: el plan NIEGA la pasada (500 `E_AUTHZ_DENY_MIGRATION_REFUSED`, cero escrituras) con ese motivo — la puerta
 *    del deny (`denyGate`, por `denyPhase` del destino);
 *  - `unreachable`: ninguna llamada que el reconcile hace al driver con una tupla PLANIFICADA puede lanzarla, con su porqué.
 *
 * `tests/relations_reconcile_l9.spec.ts` lo cruza POR REFLEXIÓN con las clases 422 de `src/errors.ts` que nombran los
 * ficheros del puerto (`src/relations/`, los dos drivers de relaciones, el doble y `src/identity.ts`): una clase 422 nueva
 * sin entrada nace ROJA con su nombre, una entrada sin clase es rancia, y cada entrada `classified`/`refused` tiene un
 * caso que la ejecuta. `RELATION_422_REASONS` (la tabla de la capa 2, cierre 3 del lote B) se DERIVA de aquí.
 */
export type RelationRejection =
  | { kind: 'classified'; reason: RelationsReconcileDetail['reason']; where: string }
  | { kind: 'refused'; refusal: DenyRefusal['reason']; where: string }
  | { kind: 'unreachable'; why: string }

export const RELATION_REJECTIONS: Readonly<Record<string, RelationRejection>> = Object.freeze({
  [RelationTypeUnknownError.code]: {
    kind: 'classified',
    reason: 'undeclared',
    where: 'planPartition (toConfig: skipped.undeclared en el origen) · classifyDestinationRow (destino) · denyGate (denyPhase ⇒ refusal undeclared)',
  },
  [RelationUnknownError.code]: {
    kind: 'classified',
    reason: 'undeclared',
    where: 'planPartition (toConfig) · classifyDestinationRow · denyGate (denyPhase ⇒ refusal undeclared)',
  },
  [RelationUsersetUnsupportedError.code]: { kind: 'classified', reason: 'userset-unsupported', where: 'classifySubject (origen y destino, con o sin toConfig)' },
  [InvalidIdentityError.code]: { kind: 'classified', reason: 'invalid-identity', where: 'enumeratedKey (origen y destino)' },
  [RelationNotDenyableError.code]: { kind: 'refused', refusal: 'phase', where: "denyGate: denyPhase del DESTINO ≠ 'write' ⇒ 500 antes de escribir" },
  [RelationDenyExpiryError.code]: { kind: 'unreachable', why: 'el reconcile nunca pasa expiresAt a deny/removeDeny (D3: el deny no caduca)' },
  [CheckManyBatchError.code]: { kind: 'unreachable', why: 'el reconcile no llama a checkMany ni a decideMany' },
  [RelationConfigError.code]: { kind: 'unreachable', why: 'se lanza al DEFINIR la config; cuando el reconcile corre los drivers ya están construidos' },
  [RelationConfigUnknownKeyError.code]: { kind: 'unreachable', why: 'se lanza al DEFINIR la config (clave desconocida de la spec, B2)' },
  [InvalidSlugError.code]: { kind: 'unreachable', why: 'gramática de SLUGS del catálogo de roles: ninguna escritura de relaciones la invoca' },
  [ActorRequiredError.code]: { kind: 'unreachable', why: 'solo el RelationsManager exige actor; el reconcile habla con los drivers' },
  // ⚪ 7 (cierre 1 de D2): los 422 que nombra `src/shared/` (que importan los drivers de relaciones).
  [UnknownScopeError.code]: {
    kind: 'unreachable',
    why: 'src/shared/backend_guard.ts: assertKnownScope/canonicalScopeTargets son del árbol de ROLES; los drivers de relaciones solo importan de ahí withDeadline/guardSql/isServerWriteLimit/isTimeoutLike/isDeadlock/isUniqueViolation',
  },
  [NoScopeResolverError.code]: {
    kind: 'unreachable',
    why: 'src/shared/backend_guard.ts: rootOnlyResolver/resolveChain son del árbol de ROLES; ningún driver de relaciones resuelve cadenas de scopes',
  },
})

/**
 * **Los 422 de la FAMILIA de relaciones, clasificados por `code`** (cierre 3 del lote B · 🟠 N9, capa 2) — DERIVADA del
 * registro L9: las entradas `classified`. Por `code` y `status`, no por clase: un driver de terceros lanza su propia
 * clase con el mismo código. Fuera de esta tabla NADA se absorbe.
 */
export const RELATION_422_REASONS: Readonly<Record<string, RelationsReconcileDetail['reason']>> = Object.freeze(
  Object.fromEntries(
    Object.entries(RELATION_REJECTIONS).flatMap(([code, entry]) => (entry.kind === 'classified' ? [[code, entry.reason]] : []))
  )
)

/**
 * **El registro de los RESIDUOS de la pasada, por motivo** (cierre 2 de D2 · ⚪ N6; linaje L9): cada motivo de
 * `RelationsReconcileDetail` dice DÓNDE se clasifica —en el PLAN (antes del driver: los mismos números en `--dry-run` y
 * en la pasada real, punto 2 de L9) o en la PASADA (solo el driver lo sabe: EXCEPCIÓN declarada al punto 2, con su
 * porqué)—. `tests/relations_reconcile_l9.spec.ts` cruza las claves con `RELATIONS_RECONCILE_DETAIL_REASONS` (un motivo
 * nuevo sin entrada nace ROJO) y ejecuta un caso por entrada. Hasta el cierre 2 `deny-conditional` (un `catch` del 500
 * marcado en la pasada) quedaba fuera de la guardia, que solo enumeraba 422.
 */
export const RELATION_RESIDUES: Readonly<
  Record<RelationsReconcileDetailReason, { where: 'plan'; how: string } | { where: 'pass'; how: string; why: string }>
> = Object.freeze({
  'invalid-identity': { where: 'plan', how: 'enumeratedKey (origen y destino); capa 2 por RELATION_REJECTIONS' },
  'invalid-condition': {
    where: 'plan',
    how: 'planPartition (L11): una tupla con RelationTuple.invalidCondition — origen: no se migra (skipped.invalid; un deny NIEGA la pasada); destino: presente e intocable (extra, nunca toDelete) y su clave no se reescribe desde el origen; una membresía de group así en una partición con algún deny NIEGA la partición (partitionsRefused, cierre de L11)',
  },
  'userset-unsupported': { where: 'plan', how: 'classifySubject (origen y destino, con o sin toConfig); capa 2 por RELATION_REJECTIONS' },
  'undeclared': { where: 'plan', how: 'classifyDestinationRow (destino, con toConfig); sin toConfig, capa 2 por RELATION_REJECTIONS' },
  'renewal-unsafe': {
    where: 'plan',
    how: 'planPartition: una membresía de toUpdate cuyo grupo transporta un deny (denyCarrierGroups) y un destino sin capabilities.atomicRenewal — sale de toUpdate y NIEGA su partición (cierre 5: cero escrituras en ella)',
  },
  'deny-conditional': {
    where: 'plan',
    how: 'planPartition (cierre 4 de D2 · C3-2): un deny del destino CON caducidad —vivo con otra o VENCIDO— que el origen tiene, en un destino sin capabilities.atomicRenewal — no se reescribe y NIEGA su partición (cierre 5: cero escrituras en ella)',
  },
})

/** El motivo de la capa 2 para un error del driver, o `undefined` si no es de la familia (por `status` Y `code` PROPIO de la tabla). */
function classifiedReason(error: any): RelationsReconcileDetail['reason'] | undefined {
  // `Object.hasOwn` (repaso del cierre 3 · ⚪ N13): un 422 con un `code` heredado del prototipo no es de la familia.
  const code = String(error?.code)
  return error?.status === 422 && Object.hasOwn(RELATION_422_REASONS, code) ? RELATION_422_REASONS[code] : undefined
}

/**
 * Borra la tupla del destino (`unrelate` un allow, `removeDeny` un deny — jamás al revés); devuelve `null` si se borró
 * (o ya no estaba) y el motivo + porqué si el DRIVER la rechazó con un 422 de la familia (`RELATION_422_REASONS`): la
 * pasada lo clasifica como residuo del destino con `pruned: false` y SIGUE con las demás filas (🟠 N9: nunca un throw a
 * mitad de pasada por una fila que el reporte puede contar). Cualquier otro error se propaga tal cual.
 */
async function deleteOrClassify(
  to: RelationsDriver,
  tuple: RelationTuple,
  op: 'unrelate' | 'removeDeny'
): Promise<{ reason: RelationsReconcileDetail['reason']; message: string } | null> {
  try {
    if (op === 'removeDeny') await to.removeDeny!(tuple.subject, tuple.relation, tuple.object, tuple.partition)
    else await to.unrelate(tuple.subject, tuple.relation, tuple.object, tuple.partition)
    return null
  } catch (error: any) {
    const reason = classifiedReason(error)
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
    // L9: por el registro (capa 2) — SOLO `undeclared` se cuenta aquí (`skipped.undeclared`); el resto de la familia lo
    // clasifica el plan antes y, si el driver lo lanza igual, es una contradicción que se propaga.
    if (classifiedReason(error) === 'undeclared') return false
    throw error
  }
}
