/**
 * **Manifiesto de la guardia de superficie L1** (plan 2.5 · lote 0; CLAUDE.md «Cómo se decide un
 * cambio» punto 6; `linajes.md` L1). Es la TABLA «operaciones × columnas» que `tests/guard_surface.spec.ts`
 * cruza con el INVENTARIO POR REFLEXIÓN de `RelationsManager`, `DatabaseRelationsDriver`,
 * `OpenFgaRelationsDriver` (y sus vistas `withClock`, H11), el doble publicado `makeRelationsDriver`
 * (D13) y los `exports` del paquete. La regla:
 *
 *  - una operación que existe en el código y NO tiene fila aquí ⇒ **rojo** (G-0), con el nombre de lo que falta;
 *  - una fila que existe aquí y NO está en el código ⇒ rojo (la tabla no inventa superficie);
 *  - cada celda es `probe` (sonda + ≥ 1 mutante en `guard_mutants.json`, G-M), `na` (no aplica, con razón de
 *    un conjunto CERRADO **y solo en la celda capa×columna que la matriz `NA_MATRIX` admite**, G-M) o `exempt`
 *    (SOLO las cinco exenciones firmadas por el dueño, D6, cada una atada a SU capa y SU columna; G-X).
 *
 * Columnas (tester §4.2 + D4): `f05` (F-05: tipo/relación declarados), `trx` (puerta `{ transaction }`, L2),
 * `freeze` (barrera del freeze, L3), `write` (invariante 13: `indeterminate: true` al vencer el deadline Y en
 * la escritura PARCIAL —`markPartialWrite`/`isPartialWrite`—), `actor` (`requireActor` + actor validado),
 * `partition` (**partición canónica**, D4 + A2: la gramática de `assertScope` y, desde el lote A, 422 para toda
 * ortografía NO canónica de un uuid — `DASHLESS_PARTITION`; sondas `dashless` y `misdashed` en cada celda
 * del caso), `truncation` (**enumeración que se puede cortar**, plan 2.5 · lote B · B4, linaje L8 ⇒ M8:
 * «toda enumeración que se puede cortar devuelve `truncated` o lanza»; sonda SOLO en `openfga`, el único
 * backend que corta: `listObjects` por tope Y por deadline —reloj monótono inyectado—, y las cinco que entran
 * por `Read` —`listSubjects`, `enumerateRelations(Many)`, las dos purgas— exhaustivas o 503; `database` es
 * `exhaustive` (SQL devuelve el conjunto entero o lanza), el manager `passthrough` y el doble `double`), `denyable`
 * (**la puerta de ESCRITURA del opt-in del deny**, D10/D-17; cierre 1 de D1, 🟡 2 del auditor: hasta entonces solo la
 * juzgaban casos que entraban por el MANAGER, y `manager.driver()` no es una salida —precedente L-5—: `deny` sobre un
 * tipo sin opt-in (`note`), en fase `'read'` (`workspace`) o sobre `group` ⇒ 422 `E_AUTHZ_RELATION_NOT_DENYABLE` con
 * CERO llamadas al backend, en las CUATRO capas y en la vista `withClock`; un mutante por capa; las demás operaciones
 * no tienen esa puerta a propósito —`removeDeny`/`listDenies` aceptan todo tipo declarado, D8— y son `na: notDeny`).
 *
 * **Una fila nueva NO entra tocando solo esta tabla** (cierre del auditor del lote 0, 🟡 7): `checkMany` (A, hecho:
 * nació ROJA en G-0 y en las tres capas hasta tener fila, INVOKE, variantes y mutantes),
 * `deny` / `removeDeny` / `listDenies` / `decideMany` (D), `listObjectsForSubject` (C) necesitan su fila AQUÍ,
 * su clasificación en `PORT_WRITES` o `PORT_READS` (cierre-2, 🟡 E), su entrada en `INVOKE` —que tiene que
 * invocar ESA operación: la sonda corre sobre un Proxy que registra qué método toca (cierre-2, 🟡 A)— y en
 * `F05_VARIANTS` del spec (una sonda F-05 sin variantes es ROJA, no vacía) y sus mutantes en
 * `guard_mutants.json`. Hasta entonces la guardia nace roja con el nombre de lo que falta.
 *
 * **Lo que el inventario ve y lo que NO** (cierre-2, 🟡 C): además de la cadena de prototipos, los campos de
 * instancia que son funciones y los estáticos, ve los ACCESSORS de instancia (`get relateRaw()` definido en el
 * constructor), los objetos-namespace (`admin = { relate }` sale como `admin.relate`, recursivo sobre objetos
 * PLANOS) y rechaza una instancia que sea un Proxy (`util.types.isProxy`: un Proxy devuelto por el constructor
 * puede servir cualquier nombre sin tenerlo). Límite declarado, con caso: un campo público cuyo valor es la
 * INSTANCIA DE UNA CLASE (p. ej. `client`, el SDK de `openfga`) no se recorre —si fuera un namespace de
 * operaciones sería una clase nueva, y si se exporta la ve G-0·exports por su prototipo; si no se exporta, no es
 * superficie publicada del paquete—.
 */

export type GuardLayer = 'manager' | 'database' | 'openfga' | 'double'
export type GuardColumn = 'f05' | 'trx' | 'freeze' | 'write' | 'actor' | 'partition' | 'truncation' | 'denyable' | 'model'
export type GuardKind = 'write' | 'read' | 'platform' | 'view'

/**
 * Las CINCO exenciones firmadas (`decisiones-dueno-2026-08-28.md` §2026-10-14 (2), **D6**), cada una atada a
 * las CAPAS y la COLUMNA en que vale (cierre 🟡 4). Ninguna otra cadena es válida aquí: G-X las cruza con el
 * extracto versionado `tests/fixtures/exemptions_d6.json` (cierre 🟠 1: el fichero de decisiones está fuera de
 * git y en CI no existe) y, en local, el extracto con el texto de la decisión. «Cae la exención si cambia la razón».
 */
export interface SignedExemption {
  operation: string
  layers: readonly GuardLayer[]
  column: GuardColumn
  reason: string
}

export const SIGNED_EXEMPTIONS = {
  'D6-driver': {
    operation: 'driver()',
    layers: ['manager'],
    column: 'f05',
    reason: 'salida documentada de las barreras (plataforma y tests): devuelve el driver crudo, no recibe tupla',
  },
  'D6-capabilities': {
    operation: 'capabilities()',
    layers: ['manager'],
    column: 'f05',
    reason: 'copia congelada de lo que declara el driver; sin backend, sin tupla',
  },
  'D6-enumerateRelations': {
    operation: 'enumerateRelations',
    layers: ['manager', 'database', 'openfga', 'double'],
    column: 'f05',
    reason: 'protegida por la LISTA BLANCA de tipos declarados del driver, no por F-05 (sonda: una fila role_binding sembrada no sale)',
  },
  'D6-enumerateRelationsMany': {
    operation: 'enumerateRelationsMany',
    layers: ['manager', 'database', 'openfga'],
    column: 'f05',
    reason: 'protegida por la LISTA BLANCA de tipos declarados del driver, no por F-05 (sonda: una fila role_binding sembrada no sale)',
  },
  'D6-membersOf-openfga': {
    operation: 'membersOf',
    layers: ['openfga'],
    column: 'f05',
    reason: 'no implementado en openfga: no recibe argumentos y es SIEMPRE 500 E_AUTHZ_UNSUPPORTED (sonda: el 500 con cero llamadas al cliente)',
  },
} as const satisfies Record<string, SignedExemption>

export type ExemptionId = keyof typeof SIGNED_EXEMPTIONS

/** Forma de cada entrada del extracto versionado `tests/fixtures/exemptions_d6.json` (la firma que SÍ viaja a CI). */
export interface ExemptionExtractEntry {
  id: ExemptionId
  operation: string
  layers: GuardLayer[]
  column: GuardColumn
  reason: string
  /** Fecha de la firma del dueño: la sección de `decisiones-dueno-2026-08-28.md` donde está D6 empieza por ella. */
  signedAt: string
  /** Fragmento LITERAL del párrafo D6 que firma esta exención (en local se cruza con el fichero de decisiones). */
  d6: string
}

/** Razones CERRADAS para «no aplica»: una razón nueva es un cambio del manifiesto, no un comentario. */
export const NA_REASONS = {
  /** Lectura: no escribe ni notifica; la cubre la sonda G-R de la fila. */
  read: 'lectura: no escribe ni notifica (G-R)',
  /** La firma de la operación no recibe esa entrada en esa capa (sin `options.actor`, sin eventos, sin argumentos…). */
  signature: 'la firma de esta capa no recibe esa entrada',
  /** Doctrina escrita (CLAUDE.md, auditor 🟠 5 de 3b-7): el freeze NO congela `manager.driver()`; la barrera es del MANAGER. */
  doctrine: 'doctrina: la barrera del freeze es del manager; el driver crudo es la salida documentada',
  /** El doble en memoria de `/testing` es fixture de contrato, no un store: no escribe en transacciones, no tiene freeze y no corta (el tope del contrato lo simula él mismo). */
  double: 'doble en memoria: fixture de contrato, sin transacciones ni freeze, y sin backend que corte',
  /** B4: el manager devuelve la página del driver TAL CUAL; el truncado (o el 503) lo decide el driver y se sondea en su fila. */
  passthrough: 'el manager devuelve la página del driver sin tocarla: el truncado lo señala el driver (sonda en su fila)',
  /** B4: una consulta SQL devuelve el conjunto entero o lanza (deadline de knex, error del motor): no hay corte silencioso que señalar. */
  exhaustive: 'SQL devuelve el conjunto entero o lanza (deadline/error del motor): no hay corte silencioso',
  /** Cierre 1 de D1 · 🟡 2: la puerta del opt-in es SOLO de `deny`; `removeDeny`/`listDenies` aceptan todo tipo declarado (D8: retirar el opt-in es reversible). */
  notDeny: 'solo deny tiene la puerta del opt-in (D10); el resto acepta todo tipo declarado (removeDeny/listDenies a propósito, D8)',
  /**
   * Lote «antes de RC» · L11 (columna `model`): la puerta «el modelo servido es el que genera la config» es del DRIVER
   * `openfga` —el único que evalúa con un modelo—; el manager compone sobre el driver (la sonda vive en la fila del
   * driver), y `database` y el doble no tienen modelo que fijar.
   */
  nomodel: 'sin modelo que fijar: la puerta L11 es del driver openfga (sondeada en su fila); manager, database y el doble no evalúan con un modelo de OpenFGA',
} as const

export type NaReason = keyof typeof NA_REASONS

/**
 * **La matriz CERRADA de «no aplica»** (cierre del auditor del lote 0, 🟠 2; decisión del coordinador
 * 2026-10-14 (4)): una celda `na` solo vale si ALGUNA entrada de esta lista la admite (misma razón, capa,
 * tipo de fila y columna; y operación, si la entrada la restringe). Lo que fija:
 *
 *  - `f05` **NUNCA** admite `na` (solo `probe` o `exempt` firmada) — salvo la vista `withClock`, que no recibe
 *    tupla y se juzga re-corriendo la tabla ENTERA de su capa sobre ella (H11);
 *  - `doctrine` SOLO en `freeze` × driver (`database`/`openfga`): es doctrina de CLAUDE.md (`driver()` se salta
 *    las barreras del manager), no una exención —por eso no está en D6—;
 *  - `double` SOLO en el doble (`trx`/`freeze`); `read` SOLO en lecturas del MANAGER (G-R las cubre);
 *  - `signature` en `write` × `openfga` SOLO para `relate`/`unrelate` (un `Write`: no hay escritura parcial);
 *    las purgas de `openfga` SON multi-request y llevan sonda (cierre 🟡 5);
 *  - `platform` (`driver()`/`capabilities()`) y `view` (`withClock`) son los ÚNICOS tipos de fila sin tupla, y
 *    solo para esas operaciones.
 *
 * Una operación nueva que llegue con `na` donde la matriz no lo admite nace ROJA aunque la fila exista.
 */
export interface NaRule {
  reason: NaReason
  layers: readonly GuardLayer[]
  kinds: readonly GuardKind[]
  columns: readonly GuardColumn[]
  operations?: readonly string[]
  /** Operaciones que la regla NO admite (la columna `denyable` es `na` en todo salvo `deny`). */
  exceptOperations?: readonly string[]
}

export const PLATFORM_OPERATIONS = ['driver', 'capabilities'] as const
export const VIEW_OPERATIONS = ['withClock'] as const

export const NA_MATRIX: readonly NaRule[] = [
  { reason: 'read', layers: ['manager'], kinds: ['read'], columns: ['trx', 'freeze', 'write', 'actor'] },
  { reason: 'signature', layers: ['manager'], kinds: ['platform'], columns: ['trx', 'freeze', 'write', 'actor', 'partition', 'truncation', 'denyable', 'model'], operations: PLATFORM_OPERATIONS },
  { reason: 'signature', layers: ['database', 'openfga', 'double'], kinds: ['view'], columns: ['f05', 'trx', 'freeze', 'write', 'actor', 'partition', 'truncation', 'denyable', 'model'], operations: VIEW_OPERATIONS },
  // L11 · columna `model`: SOLO el driver `openfga` evalúa con un modelo de OpenFGA (sonda en TODAS sus operaciones; las
  // `enumerate*` con la parte `conditions`); `membersOf` de openfga es siempre 500 sin llamar al cliente.
  { reason: 'nomodel', layers: ['manager', 'database', 'double'], kinds: ['write', 'read'], columns: ['model'] },
  { reason: 'signature', layers: ['openfga'], kinds: ['read'], columns: ['model'], operations: ['membersOf'] },
  // Cierre 1 de D1 · 🟡 2: la columna `denyable` es sonda SOLO en `deny` (las cuatro capas); en todo lo demás, `notDeny`.
  { reason: 'notDeny', layers: ['manager', 'database', 'openfga', 'double'], kinds: ['write', 'read'], columns: ['denyable'], exceptOperations: ['deny'] },
  // B4 · `truncation`: solo `openfga` corta. El manager pasa la página (lecturas) o no enumera (escrituras); `database`
  // es exhaustivo; en `openfga` `check`/`checkMany`/`membersOf` no enumeran (booleano / 500) y `relate`/`unrelate` son un `Write`.
  { reason: 'passthrough', layers: ['manager'], kinds: ['read'], columns: ['truncation'] },
  { reason: 'signature', layers: ['manager'], kinds: ['write'], columns: ['truncation'] },
  { reason: 'exhaustive', layers: ['database'], kinds: ['write', 'read'], columns: ['truncation'] },
  // Lote D: `deny`/`removeDeny` de openfga son UN `Write` (sin caducidad, D3: no hay renovación); `decideMany` es un
  // `batchCheck` (booleano por ítem, no enumera).
  { reason: 'signature', layers: ['openfga'], kinds: ['write'], columns: ['truncation'], operations: ['relate', 'unrelate', 'deny', 'removeDeny'] },
  { reason: 'signature', layers: ['openfga'], kinds: ['read'], columns: ['truncation'], operations: ['check', 'checkMany', 'membersOf', 'decideMany', 'denyPhase'] },
  // Lote D · D2: `denyPhase` es CONFIGURACIÓN del driver (la fase del opt-in de un tipo, + D-31 en openfga): no recibe
  // partición ni lee tuplas. F-05 del par sí (sonda).
  { reason: 'signature', layers: ['database', 'openfga', 'double'], kinds: ['read'], columns: ['partition'], operations: ['denyPhase'] },
  { reason: 'signature', layers: ['database', 'openfga', 'double'], kinds: ['write', 'read'], columns: ['actor'] },
  { reason: 'signature', layers: ['database', 'double'], kinds: ['write', 'read'], columns: ['write'] },
  { reason: 'signature', layers: ['openfga'], kinds: ['read'], columns: ['write'] },
  { reason: 'signature', layers: ['openfga'], kinds: ['write'], columns: ['write'], operations: ['relate', 'unrelate', 'deny', 'removeDeny'] },
  { reason: 'signature', layers: ['database', 'openfga'], kinds: ['read'], columns: ['trx'] },
  { reason: 'signature', layers: ['openfga'], kinds: ['read'], columns: ['partition'], operations: ['membersOf'] },
  { reason: 'doctrine', layers: ['database', 'openfga'], kinds: ['write', 'read'], columns: ['freeze'] },
  { reason: 'double', layers: ['double'], kinds: ['write', 'read'], columns: ['trx', 'freeze', 'truncation'] },
]

/** Qué se espera de una partición con uuid NO canónico (D4 + A2): desde el lote A, 422 `E_AUTHZ_INVALID_IDENTITY`. */
export type DashlessExpectation = 'accepted' | { status: 422; code: string }

/**
 * **D4 (plan 2.5 · lote A, decisión del dueño 2026-10-14) + 🟠 A2 (cierre, 2026-10-15)**: toda ortografía NO
 * canónica de un uuid —32 hex sin guiones, y los mismos 32 hex con otra colocación de guiones (`8-4-4-16`…, lo que
 * el `uuid` de PostgreSQL funde)— es **422** en TODA operación que recibe partición — manager, los dos drivers, el
 * doble publicado y `reconcileRelations`—, con la regla en UN sitio (`assertPartition`/`isNonCanonicalUuid`,
 * `src/identity.ts`) y DOS mutantes globales: `identity.dashless.D4` (apaga la regla entera) e
 * `identity.misdashed.A2` (vuelve a «solo 32 hex sin guiones»: lo mata la sonda `misdashed` de cada celda).
 * Hasta el lote 0 la constante afirmaba la rama «se acepta»; los casos cambiaron de expectativa, no de forma.
 * La receta de las filas viejas (detectar, listar, BORRAR; `--rekey` opt-in) está en el README («Upgrading to
 * 2.5.0») y la ejecuta `tests/upgrade_recipe.spec.ts` en los tres motores, con las dos ramas.
 */
export const DASHLESS_PARTITION: DashlessExpectation = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }

export type GuardCell =
  | { probe: true }
  | { na: NaReason }
  | { exempt: ExemptionId; probe: 'whitelist' | 'unsupported' | 'identity' | 'frozen-copy' }

export interface GuardRow {
  layer: GuardLayer
  operation: string
  kind: GuardKind
  cells: Record<GuardColumn, GuardCell>
}

const P = { probe: true } as const
const READ = { na: 'read' } as const
const SIG = { na: 'signature' } as const
const DOC = { na: 'doctrine' } as const
const DBL = { na: 'double' } as const
const PASS = { na: 'passthrough' } as const
const EXH = { na: 'exhaustive' } as const
/** B4: en `openfga` cortan `listObjects` (tope/deadline) y todo lo que entra por `Read` (`listSubjects`, `enumerate*`, las purgas): sonda; lo demás no enumera. */
/** Lote D · D2: `denyPhase` (config del driver, sin partición): F-05 con sonda; la partición no está en la firma. */
const configRead = (layer: 'database' | 'openfga' | 'double', op: string) =>
  row(layer, op, 'read', {
    f05: P,
    trx: layer === 'double' ? DBL : SIG,
    freeze: layer === 'double' ? DBL : DOC,
    write: SIG,
    actor: SIG,
    partition: SIG,
    truncation: layer === 'database' ? EXH : layer === 'double' ? DBL : SIG,
    denyable: NOT_DENY,
    model: layer === 'openfga' ? P : NOMODEL,
  })
const OPENFGA_ENUMERATING = new Set(['listObjects', 'listSubjects', 'listDenies', 'enumerateRelations', 'enumerateRelationsMany', 'purgeObject', 'purgeSubject'])
const fgaTruncation = (op: string): GuardCell => (OPENFGA_ENUMERATING.has(op) ? P : SIG)
/** Cierre 1 de D1 · 🟡 2: la puerta del opt-in solo la tiene `deny`. */
const NOT_DENY = { na: 'notDeny' } as const
const denyable = (op: string): GuardCell => (op === 'deny' ? P : NOT_DENY)

export function row(layer: GuardLayer, operation: string, kind: GuardKind, cells: Record<GuardColumn, GuardCell>): GuardRow {
  return { layer, operation, kind, cells }
}

/** Una escritura del MANAGER: las seis columnas con sonda. */
const NOMODEL = { na: 'nomodel' } as const
const managerWrite = (op: string) =>
  row('manager', op, 'write', { f05: P, trx: P, freeze: P, write: P, actor: P, partition: P, truncation: SIG, denyable: denyable(op), model: NOMODEL })
/** Una lectura del MANAGER: F-05 y partición con sonda; el resto lo cubre G-R. */
const managerRead = (op: string) =>
  row('manager', op, 'read', { f05: P, trx: READ, freeze: READ, write: READ, actor: READ, partition: P, truncation: PASS, denyable: NOT_DENY, model: NOMODEL })
/** Una escritura de un DRIVER: F-05, puerta trx y partición; el freeze es doctrina; actor/eventos no están en la firma. */
const driverWrite = (layer: 'database' | 'openfga', op: string, write: GuardCell = SIG) =>
  row(layer, op, 'write', { f05: P, trx: P, freeze: DOC, write, actor: SIG, partition: P, truncation: layer === 'database' ? EXH : fgaTruncation(op), denyable: denyable(op), model: layer === 'openfga' ? P : NOMODEL })
/** Una lectura de un DRIVER: F-05 y partición. */
const driverRead = (layer: 'database' | 'openfga', op: string) =>
  row(layer, op, 'read', { f05: P, trx: SIG, freeze: DOC, write: SIG, actor: SIG, partition: P, truncation: layer === 'database' ? EXH : fgaTruncation(op), denyable: NOT_DENY, model: layer === 'openfga' ? P : NOMODEL })
/** `enumerateRelations(Many)` en cualquier capa: la exención D6 con su sonda de lista blanca; partición con sonda. */
const enumerateRow = (layer: GuardLayer, op: 'enumerateRelations' | 'enumerateRelationsMany') =>
  row(layer, op, 'read', {
    f05: { exempt: op === 'enumerateRelations' ? 'D6-enumerateRelations' : 'D6-enumerateRelationsMany', probe: 'whitelist' },
    trx: layer === 'manager' ? READ : layer === 'double' ? DBL : SIG,
    freeze: layer === 'manager' ? READ : layer === 'double' ? DBL : DOC,
    write: layer === 'manager' ? READ : SIG,
    actor: layer === 'manager' ? READ : SIG,
    partition: P,
    truncation: layer === 'manager' ? PASS : layer === 'database' ? EXH : layer === 'double' ? DBL : P,
    denyable: NOT_DENY,
    // L11: en `openfga` el ORIGEN de una migración pasa la puerta, pero SOLO la parte `conditions` (la sonda lo afirma
    // en las dos direcciones: deriva de reglas ⇒ responde; deriva de condiciones ⇒ 500).
    model: layer === 'openfga' ? P : NOMODEL,
  })
/** La vista `withClock` (H11): no recibe tupla; se juzga re-corriendo TODAS las filas de su capa sobre la vista. */
const viewRow = (layer: 'database' | 'openfga' | 'double') =>
  row(layer, 'withClock', 'view', { f05: SIG, trx: SIG, freeze: SIG, write: SIG, actor: SIG, partition: SIG, truncation: SIG, denyable: SIG, model: SIG })
/** Una operación del DOBLE publicado (D13): F-05 y partición (⚪ 11) con sonda; trx/freeze no existen en el fixture. */
const doubleOp = (op: string, kind: 'write' | 'read') =>
  row('double', op, kind, { f05: P, trx: DBL, freeze: DBL, write: SIG, actor: SIG, partition: P, truncation: DBL, denyable: denyable(op), model: NOMODEL })

export const GUARD_MANIFEST: GuardRow[] = [
  /* ── RelationsManager ─────────────────────────────────────────────────── */
  managerWrite('relate'),
  managerWrite('unrelate'),
  managerWrite('purgeObject'),
  managerWrite('purgeSubject'),
  managerRead('check'),
  // Plan 2.5 · lote A: `checkMany` (P4) nace con fila, sonda F-05 POR ÍTEM (la variante va en la posición 1) y partición.
  managerRead('checkMany'),
  managerRead('listObjects'),
  managerRead('listSubjects'),
  managerRead('membersOf'),
  // Plan 2.5 · lote D · D1: las cuatro operaciones del deny NACIERON ROJAS en G-0/G-R (13 rojos, informe §0) hasta
  // tener fila, clasificación, INVOKE, variantes F-05 y mutantes. `deny`/`removeDeny` son escrituras con las seis
  // columnas; `listDenies`/`decideMany` lecturas (decideMany: F-05 POR ÍTEM, como checkMany).
  managerWrite('deny'),
  managerWrite('removeDeny'),
  managerRead('listDenies'),
  managerRead('decideMany'),
  enumerateRow('manager', 'enumerateRelations'),
  enumerateRow('manager', 'enumerateRelationsMany'),
  row('manager', 'driver', 'platform', {
    f05: { exempt: 'D6-driver', probe: 'identity' },
    trx: SIG,
    freeze: SIG,
    write: SIG,
    actor: SIG,
    partition: SIG,
    truncation: SIG,
    denyable: SIG,
    model: SIG,
  }),
  row('manager', 'capabilities', 'platform', {
    f05: { exempt: 'D6-capabilities', probe: 'frozen-copy' },
    trx: SIG,
    freeze: SIG,
    write: SIG,
    actor: SIG,
    partition: SIG,
    truncation: SIG,
    denyable: SIG,
    model: SIG,
  }),

  /* ── DatabaseRelationsDriver (y su vista withClock) ───────────────────── */
  driverWrite('database', 'relate'),
  driverWrite('database', 'unrelate'),
  driverWrite('database', 'purgeObject'),
  driverWrite('database', 'purgeSubject'),
  driverRead('database', 'check'),
  driverRead('database', 'checkMany'),
  driverRead('database', 'listObjects'),
  driverRead('database', 'listSubjects'),
  driverRead('database', 'membersOf'),
  driverWrite('database', 'deny'),
  driverWrite('database', 'removeDeny'),
  driverRead('database', 'listDenies'),
  driverRead('database', 'decideMany'),
  // Lote D · D2: nació ROJA en G-0 / 🟡 E / G-R (informe de D2 §0) hasta tener fila, clasificación, INVOKE, variantes y mutantes.
  configRead('database', 'denyPhase'),
  enumerateRow('database', 'enumerateRelations'),
  enumerateRow('database', 'enumerateRelationsMany'),
  viewRow('database'),

  /* ── OpenFgaRelationsDriver (y su vista withClock) ────────────────────── */
  driverWrite('openfga', 'relate'),
  driverWrite('openfga', 'unrelate'),
  // Las purgas de openfga son MULTI-request (invariante 13): la escritura PARCIAL se sondea (cierre 🟡 5).
  driverWrite('openfga', 'purgeObject', P),
  driverWrite('openfga', 'purgeSubject', P),
  driverRead('openfga', 'check'),
  driverRead('openfga', 'checkMany'),
  driverRead('openfga', 'listObjects'),
  driverRead('openfga', 'listSubjects'),
  row('openfga', 'membersOf', 'read', {
    f05: { exempt: 'D6-membersOf-openfga', probe: 'unsupported' },
    trx: SIG,
    freeze: DOC,
    write: SIG,
    actor: SIG,
    // No recibe argumentos: no hay partición que juzgar.
    partition: SIG,
    truncation: SIG,
    denyable: NOT_DENY,
    // L11: siempre 500 E_AUTHZ_UNSUPPORTED sin llamar al cliente: no hay evaluación que guardar.
    model: SIG,
  }),
  driverWrite('openfga', 'deny'),
  driverWrite('openfga', 'removeDeny'),
  driverRead('openfga', 'listDenies'),
  driverRead('openfga', 'decideMany'),
  configRead('openfga', 'denyPhase'),
  enumerateRow('openfga', 'enumerateRelations'),
  enumerateRow('openfga', 'enumerateRelationsMany'),
  viewRow('openfga'),

  /* ── makeRelationsDriver (el doble publicado en /testing, D13) ─────────── */
  doubleOp('relate', 'write'),
  doubleOp('unrelate', 'write'),
  doubleOp('purgeObject', 'write'),
  doubleOp('purgeSubject', 'write'),
  doubleOp('check', 'read'),
  doubleOp('checkMany', 'read'),
  doubleOp('listObjects', 'read'),
  doubleOp('listSubjects', 'read'),
  doubleOp('membersOf', 'read'),
  doubleOp('deny', 'write'),
  doubleOp('removeDeny', 'write'),
  doubleOp('listDenies', 'read'),
  doubleOp('decideMany', 'read'),
  configRead('double', 'denyPhase'),
  enumerateRow('double', 'enumerateRelations'),
  viewRow('double'),
]

/**
 * **Clasificación OBLIGATORIA de las operaciones del puerto `RelationsDriver`** (cierre-2 del lote 0, 🟡 E): toda
 * operación con tupla es ESCRITURA o LECTURA, aquí y en ninguna otra lista. `tests/guard_surface.spec.ts` deriva de
 * esto su `WRITES` (lo que el espía del driver cuenta como escritura en G-R), exige que el inventario POR REFLEXIÓN
 * del manager, de los dos drivers y del doble esté clasificado ENTERO (una operación que no esté en ninguna de las
 * dos listas ⇒ rojo con su nombre: así `deny` del lote D nace rojo hasta que alguien diga qué es), cruza la
 * clasificación con el COMPORTAMIENTO (una escritura ejecuta sentencias de escritura en `database` y llama a
 * `write`/`deleteTuples` en `openfga`; una lectura no) y con el `kind` de cada fila de la tabla.
 */
export const PORT_WRITES = ['relate', 'unrelate', 'purgeObject', 'purgeSubject', 'deny', 'removeDeny'] as const
export const PORT_READS = [
  'check',
  'checkMany',
  'listObjects',
  'listSubjects',
  'membersOf',
  'enumerateRelations',
  'enumerateRelationsMany',
  'listDenies',
  'decideMany',
  // Lote D · D2: la pregunta del plan del reconcile al DESTINO (config del driver; no escribe ni lee tuplas).
  'denyPhase',
] as const

/** Nombres de operación del PUERTO `RelationsDriver` (DERIVADO de la clasificación): una clase exportada con alguno en su prototipo es superficie. */
export const PORT_OPERATIONS = [...PORT_WRITES, ...PORT_READS] as const

/**
 * Clasificación de lo que sale por `exports` (G-0 · exports). Las cuatro superficies se reconocen POR IDENTIDAD
 * (la referencia importada en el spec, no el `name`; cierre ⚪ 9); cualquier OTRA clase con un nombre del puerto en
 * su prototipo o función cuyo nombre contiene «relation» tiene que estar en una de estas listas; si no, rojo.
 * **Límite declarado**: una función exportada SIN «relation» en el nombre y sin prototipo (una arrow en un objeto)
 * que reciba tuplas no se ve por reflexión sin invocarla; la regla de clasificación obliga a nombrar con «relation»
 * lo que toque relaciones, y una clase nueva se ve por su prototipo.
 */
export const SURFACE_CLASSES: Record<GuardLayer, string> = {
  manager: 'RelationsManager',
  database: 'DatabaseRelationsDriver',
  openfga: 'OpenFgaRelationsDriver',
  double: 'makeRelationsDriver',
}

/** Clases del puerto de ROLES que comparten nombres de operación (`listSubjects`…): no son superficie de relaciones. */
export const NON_SURFACE_CLASSES: Record<string, string> = {
  AuthorizationManager: 'puerto de roles (AuthorizationDriver): su listSubjects es por RoleQuery, no una tupla',
  DatabaseAuthorizationDriver: 'driver de roles',
  OpenFgaAuthorizationDriver: 'driver de roles',
}

/** Funciones exportadas con «relation» en el nombre que NO reciben una tupla de relación, con su razón. */
export const NON_SURFACE_FUNCTIONS: Record<string, string> = {
  defineRelationsConfig: 'construye la config (F-05 nace aquí: un tipo reservado no se puede declarar)',
  saveRelationsConfig: 'persiste la config (authz_relations_config)',
  readRelationsConfig: 'lee la config persistida',
  readRelationsConfigSpec: 'lee el spec persistido',
  runRelationsDriverContract: 'runner del juez: recibe un harness, no tuplas',
  registerRelationsDriverContract: 'motor del runner: recibe un harness',
  contractRelationsConfig: 'la config fija del contrato',
  lucidRelationsContractTransactions: 'abre transacciones de Lucid para el runner',
  runRelationsReconcileContract: 'runner del reconcile de relaciones',
  registerRelationsReconcileContract: 'motor del runner del reconcile',
  runRelationsReconcile: 'la vía pública del reconcile (guardia propia en command_flags.spec, cierre alpha.10 · R1)',
  normalizeRelationsCapabilities: 'normaliza el objeto de capacidades',
  isRelUserset: 'predicado de forma sobre un sujeto',
  RelationConfigError: 'clase de error (422 E_AUTHZ_RELATION_CONFIG)',
  RelationConfigUnknownKeyError: 'clase de error (422 E_AUTHZ_RELATION_CONFIG_UNKNOWN_KEY, lote B · B2): una clave desconocida en la spec, no una operación',
  RelationTypeUnknownError: 'clase de error (422 E_AUTHZ_RELATION_TYPE_UNKNOWN): es lo que F-05 LANZA, no una operación',
  RelationUnknownError: 'clase de error (422 E_AUTHZ_RELATION_UNKNOWN): es lo que F-05 LANZA, no una operación',
  RelationUsersetUnsupportedError: 'clase de error (422 E_AUTHZ_RELATION_USERSET_UNSUPPORTED, lote B · B3): lo que lanza assertUsersetSubject, no una operación',
  assertRelationsConfigPublishable: 'valida la config contra el techo del modelo FGA (openfga:provision)',
  factsRelationMap: 'generador del modelo facts (relaciones derivadas de permisos)',
  factsRelationTypeDefinitions: 'generador del modelo facts (type definitions de los tipos declarados)',
  factsRelationsOf: 'generador del modelo facts',
  buildRelationsManager: 'construye el RelationsManager del servicio: lo que devuelve se SONDEA con las filas manager (cierre 🟡 6)',
  AuthzRelationsReconcile: 'comando de ace (clase sin operaciones del puerto): su efecto lo juzga command_flags.spec',
  relationsReconcileLines: 'formatea el reporte del reconcile de relaciones',
  relationsConfigOf: 'resuelve la config de relaciones para openfga:provision',
  relationTupleKey: 'clave PURA de una tupla (plan 2.5 · lote A, P3): sin backend ni driver; no es una operación del puerto',
  contractDenyRelationsConfig: 'la config fija del contrato CON deny (lote D): construye config, no recibe tuplas',
  RelationNotDenyableError: 'clase de error (422 E_AUTHZ_RELATION_NOT_DENYABLE, lote D): lo que lanza assertRelationDenyable, no una operación',
  RelationDenyExpiryError: 'clase de error (422 E_AUTHZ_DENY_EXPIRY_UNSUPPORTED, lote D · D3): lo que lanza assertDenyNoExpiry, no una operación',
  relationSubjectKey: 'clave PURA de un sujeto de relación (parte de relationTupleKey)',
  droppedDenyRelations: 'función PURA de openfga:provision (lote D · D2): compara dos modelos JSON; no recibe tuplas ni driver',
}

/** Título CANÓNICO del caso de una celda: lo que el manifiesto de mutantes nombra en `expectRed`. */
export function cellTitle(layer: GuardLayer, operation: string, column: GuardColumn): string {
  return `GS · ${layer}.${operation} · ${column}`
}

/** Id canónico de una celda (`layer.operation.column`), el que usa `guard_mutants.json`. */
export function cellId(layer: GuardLayer, operation: string, column: GuardColumn): string {
  return `${layer}.${operation}.${column}`
}

export const GUARD_COLUMNS: GuardColumn[] = ['f05', 'trx', 'freeze', 'write', 'actor', 'partition', 'truncation', 'denyable', 'model']

/** Forma de una entrada de `tests/fixtures/guard_mutants.json`. */
export interface GuardMutantEdit {
  /** Fichero del edit si no es el `file` del mutante (p. ej. `src/identity.ts` para `scopeKey`). */
  file?: string
  /** Texto que tiene que aparecer EXACTAMENTE una vez en el fichero (G-M lo verifica en `npm test`). */
  find: string
  replace: string
}

export interface GuardMutant {
  id: string
  /** Celdas que este mutante mata (`layer.operation.column`); todas tienen que ser `probe` o `exempt` con sonda. */
  cells?: string[]
  /**
   * … O las PROPIEDADES de `GUARD_PROPERTIES` que mata (cierre 2 de D1, ⚪ N2). Un mutante nombra celdas o
   * propiedades, nunca las dos ni ninguna (G-M).
   */
  properties?: string[]
  file: string
  /** Un solo edit (`find`/`replace`) … */
  find?: string
  replace?: string
  /** … o varios, cuando la guarda de esa entrada son VARIAS líneas (defensa en profundidad dentro del mismo camino). */
  edits?: GuardMutantEdit[]
  /** Títulos de los casos que tienen que ponerse ROJOS con el mutante aplicado (= `cellTitle` de cada celda, o el `title` de cada propiedad). */
  expectRed: string[]
  /** Razón escrita cuando el mutante no es «quitar UNA línea» (G-M no la exige, el informe sí). */
  note?: string
}

/**
 * **Propiedades de la guardia** (cierre 2 de D1, ⚪ N2 del auditor; linaje **L10 propuesto** «una operación de varios
 * pasos no expone un estado intermedio que conceda lo que no concedían ni el estado inicial ni el final»: 3b-2f · R3 —orden
 * de `purgeScope` en `facts`—, 3b-6 · P1 —el origen del reconcile en dos barridos— y D1 · 🟠 1 —la purga de relaciones
 * cortada—; la 3.ª iteración no se parchea, CLAUDE.md §5 (d)). No son celdas operación × columna: son propiedades de UN
 * punto de paso, juzgadas por un caso PURO de `guard_surface.spec` (sin servidor: corre en el job `guard-mutants` en
 * `:memory:` y `sqlite-file`) cuyas filas son las de la tabla de verdad MEDIDA contra el servidor en
 * `relations_openfga.spec` (grupo «lote D · cierre 1 de D1 · 🟠 1 …»). Cada propiedad NOMBRA sus mutantes y G-M exige la
 * lista CERRADA en los dos sentidos: todos existen en `guard_mutants.json` apuntando a ella y ninguno más la nombra.
 * Hasta el cierre 2 esos mutantes eran «por pieza», fuera de todo corredor, y la mitad «membresías ANTES de los denies»
 * no tenía diente (🟡 N1: el mutante «denies antes que membresías» concedía con los 5 casos del cierre 1 en verde).
 */
export interface GuardProperty {
  id: string
  /** Título CANÓNICO del caso puro que la juzga (lo que los mutantes nombran en `expectRed`). */
  title: string
  /** El punto de paso único que la propiedad juzga. */
  point: string
  /** Los mutantes de `guard_mutants.json` que la matan (lista cerrada). */
  mutants: string[]
}

export const GUARD_PROPERTIES: GuardProperty[] = [
  {
    id: 'openfga.purge.order',
    title: 'GS · P · openfga.purge.order · una purga cortada tras cualquier Write no concede lo que no concedían ni el estado inicial ni el final',
    point:
      'src/relations/tuple_order.ts · relationDeleteOrder → relationTransitionOrder (punto de paso ÚNICO del orden, cierre 2 de D2 · 🟡 N3) vía src/drivers/openfga_relations_driver.ts · purgeWrites (lo usan purgeObject y purgeSubject, holder y userset)',
    mutants: [
      'fga.purge.prefix-only',
      'fga.purge.contiguous',
      'fga.purge.no-single-write',
      'order.phase.deny-deletes-first',
      'order.phase.allow-deletes-late',
    ],
  },
  {
    // Plan 2.5 · lote D · D2 (tester S4/S5, auditor R2-5, analista §4.7): la 4.ª iteración del linaje L10 —el reconcile
    // de relaciones es una operación de VARIAS escrituras—, así que entra estructural: propiedad + punto de paso único +
    // mutantes en el corredor publicado. Cierre 2 de D2 (🟡 N3/🟡 N2): filas del ex-miembro que compone con un allow
    // nuevo, de la composición anidada y del grupo que solo deniega; el mutante «escrituras y luego poda» (el código
    // del cierre 1) muere aquí.
    id: 'relations.reconcile.order',
    title: 'GS · P · relations.reconcile.order · una pasada de reconcile cortada tras cualquier escritura no concede lo que no concedían ni el estado inicial ni el final —salvo el RESIDUO declarado: un ciclo del grafo de precedencias, que la pasada lista en report.orderResidue (cifras en relations.order.exhaustive)—, en los dos órdenes de enumeración del origen (relationTransitionOrder: escrituras, renovaciones y poda en UNA secuencia) — también en el HORIZONTE de las filas que lo declaran (la renovación que acorta; C3-1 y C3-2, cuya PARTICIÓN se niega desde el cierre 5 de D2: cero escrituras)',
    point:
      'src/relations/tuple_order.ts · relationTransitionOrder (punto de paso ÚNICO, compartido con purgeWrites) vía src/relations/reconcile.ts · applyPartition (la usa toda pasada de reconcileRelations, comando y runRelationsReconcile)',
    mutants: [
      'rec.apply.writes-then-prune',
      'rec.plan.vigencia-ignored',
      'rec.apply.expired-deletes-in-order',
      'rec.plan.refusal-off',
      'rec.plan.conditional-in-pass',
      'rec.plan.shortening-not-passed',
      'order.phase.deny-writes-last',
      'order.phase.deny-deletes-first',
      'order.phase.allow-deletes-late',
      'order.phase.allow-writes-early',
      'order.c1.off',
      'order.c2.off',
      'order.c3.off',
      'order.pairs.holder-only',
    ],
  },
  {
    // Cierre 2 de D2 · 🟡 N3 (linaje L10 PROMOVIDO, decisión del dueño §2026-10-15 (8)): la garantía del orden se
    // DEMUESTRA por fuerza bruta y no con tablas a mano. El caso puro recorre TODOS los pares (inicial, final) del
    // universo `E1-reduced` (`tests/helpers/order_bruteforce.ts`: 1 usuario, 2 grupos con 1 nivel de anidamiento, 2
    // objetos, `viewer` con deny; 8 tuplas ⇒ 4^8 pares por modo, con `--prune` y sin él) y CADA prefijo; los universos
    // completos (E1 exhaustivo, U2 y E3 muestreados) están en `tests/relations_order_exhaustive.spec.ts`.
    id: 'relations.order.exhaustive',
    title: 'GS · P · relations.order.exhaustive · fuerza bruta EXHAUSTIVA sobre E1-reduced (131 072 pares; el oráculo cuenta los objetos group:): si el grafo de precedencias no tiene ciclo, ningún prefijo de relationTransitionOrder concede fuera de inicial ∪ final ni a un denegado en los dos; el residuo es el ciclo (cifras fijadas: 1 044 pares con ciclo, 204 conceden, 88 sin ningún orden seguro) — con VIGENCIA y HORIZONTE (ocho estados por tupla, el plan por liveInDestination, la PARTICIÓN negada por renewal-unsafe o deny-conditional como única exclusión —cierre 5 de D2, opción A—, cada prefijo y el estado final en now, +30 min y +1 h; muestra declarada de 50 000 combinaciones por modo, destino atómico y de dos Write: 0 conceden sin residuo) — y los contraejemplos LITERALES de C4 (U2), de C3 con la membresía y de la renovación que acorta (E3)',
    point:
      'src/relations/tuple_order.ts · relationTransitionOrder (punto de paso ÚNICO: applyPartition del reconcile y purgeWrites de las purgas de openfga)',
    mutants: [
      'order.phase.deny-writes-last',
      'order.phase.deny-deletes-first',
      'order.phase.allow-deletes-late',
      'order.phase.allow-writes-early',
      'order.c1.off',
      'order.c2.off',
      'order.c2.no-exclusion',
      'order.c3.off',
      'order.c4.off',
      'order.selfcut.union',
      'order.residue.hidden',
      'order.priority.deletes-first',
      'order.pairs.holder-only',
      'rec.plan.vigencia-ignored',
      'order.renewals.horizon-flat',
      'order.renewals-not-changing',
      'order.c3.membership-needs-allow',
      'order.c4.no-exclusion',
    ],
  },
  {
    // Plan 2.5 · lote D · D2 (addendum del coordinador; linaje L10, la iteración de ROLES — 3b-2f · R3): el orden de
    // `purgeScope` de `openfga` (`facts`) como PROPIEDAD, con el mismo patrón que `openfga.purge.order`. Medido: con
    // los denies AL FINAL ningún estado intermedio concede (la estructura y los hechos se van antes); con los denies
    // primero, la purga cortada CONCEDE lo que el deny negaba (el mutante).
    id: 'openfga.roles.purgeScope.order',
    title: 'GS · P · openfga.roles.purgeScope.order · una purgeScope de roles cortada tras cualquier Write no concede lo que no concedían ni el estado inicial ni el final (estructura → hechos → denies), y el error va marcado PARCIAL si ya borró algo de verdad o PUDO borrarlo —sobre-notificar, nunca sub-— y no si no (cierres 4, 5 y 6 de D2: C3-4, D4-5, D5-4)',
    point: 'src/drivers/openfga_driver.ts · OpenFgaAuthorizationDriver.purgeScope (scopes.detached de roles en facts)',
    mutants: ['roles.purgeScope.denies-first', 'roles.purgeScope.no-partial', 'roles.purgeScope.count-requested', 'roles.purgeScope.unconfirmed-off'],
  },
  {
    // Lote «antes de RC» · L11 (decisión del dueño 2026-10-17 (1); linaje L11, 3.ª+ iteración ⇒ estructural): SUSTITUYE a
    // `openfga.model.drift` (cierre 5 de D2), cuyos tres mutantes se re-anclan aquí. La propiedad universal: el modelo que
    // sirve el driver y el que genera la config son IGUALES, por tipo, en reglas, restricciones de tipo y condiciones —con
    // `P_M` del propio modelo y D8 por TIPO ENTERO—, o 500 con cero llamadas que evalúen; y la lectura se memoriza solo si
    // tiene éxito.
    id: 'openfga.model.equal',
    title:
      'GS · P · openfga.model.equal · el modelo FIJADO y el que genera la config son IGUALES por tipo en reglas, restricciones de tipo y condiciones (relación de más = deriva; D8 por TIPO ENTERO; ruido de proto3 y orden neutros; tipo ajeno fuera): la puerta de relaciones da 500 E_AUTHZ_CONFIG nombrando la ruta, con `group` y los holders en TODA operación y POR TIPO (la deriva de otro tipo de la config no tumba la operación), decideMany pregunta el deny según la forma comparada, y la lectura del modelo se memoriza SOLO si se comparó (un fallo al leer no; una diferencia sí; base y vista withClock comparten UNA lectura)',
    point: 'src/drivers/openfga_facts.ts · factsModelDifferences/canonicalModel vía src/drivers/openfga_relations_driver.ts · #modelGate/#assertModel (y la del driver de roles, propiedad openfga.roles.model.equal)',
    mutants: [
      'fga.model.drift-off',
      'fga.model.d8-denied-unchecked',
      'fga.model.group-own-ops-only',
      'fga.model.canon-drops-condition',
      'fga.model.conditions-unchecked',
      'fga.model.rules-only',
      'fga.model.extra-relation-tolerated',
      'fga.model.canon-drops-empty-object',
      'fga.model.names-only',
      'fga.model.memo-transient',
      'fga.model.group-wide-off',
      'fga.model.slice-wide',
      'fga.model.group-wide-always',
      'fga.model.holders-off',
      'fga.model.decideMany-denyform-ignored',
    ],
  },
  {
    // L11 · injerto 2 del juez + H8 (tabla de consumidores) + F0 · M-a(2)/M-b: la caducidad de una tupla de OpenFGA sale de
    // UNA función (`fgaTupleExpiry`, cuatro estados, `ceil` al ms) y CADA consumidor decide qué hace con `foreign`/
    // `unparseable`, fail-closed. Un mutante por la función y uno POR CONSUMIDOR (la decisión vive en cada uno).
    id: 'fga.tuple.expiry',
    title:
      'GS · P · fga.tuple.expiry · la caducidad de una tupla de OpenFGA sale de fgaTupleExpiry (not_expired SOLO con el contexto exacto {valid_until}, techo al ms, nunca «permanente» por defecto) y cada consumidor trata foreign/unparseable fail-closed: relate y grant ⇒ 409 sin escribir, VIVA donde niega o cuenta (la portadora de un deny, los denies de listScopes, countRoleAssignments), listSubjects/listDenies/listRoles la omiten, enumerate la marca (vencida, nunca permanente) y el plan del reconcile no la migra ni la poda, niega la partición con una membresía ajena y un deny, y el de roles se niega con un deny bloqueado',
    point: 'src/expiry.ts · fgaTupleExpiry/fgaTimestampNs vía storedCondition (los dos drivers openfga) y src/relations/reconcile.ts · planPartition (invalid-condition)',
    mutants: [
      'fga.expiry.name-ignored',
      'fga.expiry.floor',
      'fga.expiry.extra-keys-accepted',
      'fga.expiry.unparseable-permanent',
      'fga.expiry.relate-foreign-noop',
      'fga.expiry.carried-foreign-expired',
      'fga.expiry.listSubjects-includes',
      'fga.expiry.listDenies-includes',
      'fga.expiry.sweep-drops-mark',
      'fga.expiry.grant-foreign-noop',
      'fga.expiry.roles-list-includes',
      'fga.expiry.roles-enumerate-migrates',
      'fga.expiry.plan-origin-migrates',
      'fga.expiry.plan-destination-prunable',
      'fga.expiry.roles-reconcile-destination',
      'fga.expiry.roles-count-omits',
      'fga.expiry.roles-deny-omitted',
      'fga.expiry.read-invalid-never-live',
      'fga.expiry.sweep-permanent',
      'fga.expiry.roles-reconcile-deny-blocked',
      'fga.expiry.roles-maint-self-blocked',
      'fga.expiry.enumerate-deny-unmarked',
      'fga.expiry.plan-carrier-not-refused',
      'fga.expiry.grant-raced-foreign',
    ],
  },
  {
    // L11 · diseño 1.3 D del analista, C12 del tester (condición de aceptación): `openfga:provision` RELEE lo publicado y lo
    // compara ENTERO; distinto ⇒ exit 1 con la letra «publicado, NO lo fijes» y SIN la línea OPENFGA_MODEL_ID=.
    id: 'openfga.provision.reread',
    title:
      'GS · P · openfga.provision.reread · openfga:provision relee el modelo que acaba de publicar y lo compara ENTERO con el que genera la config: igual ⇒ exit 0, «provision RELECTURA OK:» e imprime OPENFGA_MODEL_ID; distinto (condición, solo roles o un tipo de más) ⇒ exit 1 con «provision RELECTURA FALLIDA:» y «NO lo fijes», sin la línea OPENFGA_MODEL_ID= (en las dos ramas: store nuevo y --store-id)',
    point: 'commands/openfga_provision.ts · reread (las dos ramas de run)',
    mutants: ['provision.reread-off', 'provision.reread-store-id-off', 'provision.reread-slice-relations', 'provision.reread-extra-type-tolerated', 'provision.reread-ok-silent'],
  },
  {
    // L11 · cubre ROLES (decisión (1): «incluye roles»; estudio 6b: F4 lo necesita). Por REFLEXIÓN sobre el prototipo de
    // `OpenFgaAuthorizationDriver` —un método nuevo sin clasificar nace rojo—: cada método que llega al store, sobre la
    // base y sobre las dos vistas por prototipo, da 500 con un modelo con deriva de `scope`/`role_binding`/`role`/holders/
    // condiciones y CERO llamadas que no sean la lectura del modelo; `enumerateFacts` solo la parte `conditions`.
    id: 'openfga.roles.model.equal',
    title:
      'GS · P · openfga.roles.model.equal · el driver de ROLES (por reflexión: todo método del prototipo clasificado) no llega al store con un modelo que no es el que genera la config (scope, role, role_binding, holders y condiciones; P_M del propio modelo): 500 E_AUTHZ_CONFIG con cero llamadas que evalúen o escriban, en la base y en las vistas withChainResolver/withClock (memo compartido); enumerateFacts solo la parte conditions; ese 500 va marcado como fallo de DESPLIEGUE (transitorio para el relay) y la lectura se memoriza solo si se comparó (un fallo al leer, de cualquier clase, no; el 500 del generador sí)',
    point: 'src/drivers/openfga_driver.ts · modelGate/assertModel (primera línea tras validar de cada método que llega al store)',
    mutants: [
      'roles.model.scope-excluded',
      'roles.model.memo-transient',
      'roles.model.memo-read-config',
      'roles.model.memo-generator-off',
      'fga.model.deployment-mark-off',
      'fga.model.drift-mark-off',
      'roles.model.authorize',
      'roles.model.authorizeMany',
      'roles.model.grant',
      'roles.model.revoke',
      'roles.model.hasRole',
      'roles.model.deny',
      'roles.model.removeDeny',
      'roles.model.listSubjects',
      'roles.model.listRoles',
      'roles.model.rolesInChain',
      'roles.model.listRoleScopes',
      'roles.model.listScopes',
      'roles.model.listDenies',
      'roles.model.reparent',
      'roles.model.detached',
      'roles.model.purgeScope',
      'roles.model.project',
      'roles.model.purgeRole',
      'roles.model.countRoleAssignments',
      'roles.model.projectCatalogRole',
      'roles.model.reconcile',
      'roles.model.enumerateFacts',
    ],
  },
]
