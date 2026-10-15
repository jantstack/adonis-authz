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
 * del caso).
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
export type GuardColumn = 'f05' | 'trx' | 'freeze' | 'write' | 'actor' | 'partition'
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
  /** El doble en memoria de `/testing` es fixture de contrato, no un store: no escribe en transacciones ni tiene freeze. */
  double: 'doble en memoria: fixture de contrato, sin transacciones ni freeze',
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
}

export const PLATFORM_OPERATIONS = ['driver', 'capabilities'] as const
export const VIEW_OPERATIONS = ['withClock'] as const

export const NA_MATRIX: readonly NaRule[] = [
  { reason: 'read', layers: ['manager'], kinds: ['read'], columns: ['trx', 'freeze', 'write', 'actor'] },
  { reason: 'signature', layers: ['manager'], kinds: ['platform'], columns: ['trx', 'freeze', 'write', 'actor', 'partition'], operations: PLATFORM_OPERATIONS },
  { reason: 'signature', layers: ['database', 'openfga', 'double'], kinds: ['view'], columns: ['f05', 'trx', 'freeze', 'write', 'actor', 'partition'], operations: VIEW_OPERATIONS },
  { reason: 'signature', layers: ['database', 'openfga', 'double'], kinds: ['write', 'read'], columns: ['actor'] },
  { reason: 'signature', layers: ['database', 'double'], kinds: ['write', 'read'], columns: ['write'] },
  { reason: 'signature', layers: ['openfga'], kinds: ['read'], columns: ['write'] },
  { reason: 'signature', layers: ['openfga'], kinds: ['write'], columns: ['write'], operations: ['relate', 'unrelate'] },
  { reason: 'signature', layers: ['database', 'openfga'], kinds: ['read'], columns: ['trx'] },
  { reason: 'signature', layers: ['openfga'], kinds: ['read'], columns: ['partition'], operations: ['membersOf'] },
  { reason: 'doctrine', layers: ['database', 'openfga'], kinds: ['write', 'read'], columns: ['freeze'] },
  { reason: 'double', layers: ['double'], kinds: ['write', 'read'], columns: ['trx', 'freeze'] },
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

export function row(layer: GuardLayer, operation: string, kind: GuardKind, cells: Record<GuardColumn, GuardCell>): GuardRow {
  return { layer, operation, kind, cells }
}

/** Una escritura del MANAGER: las seis columnas con sonda. */
const managerWrite = (op: string) =>
  row('manager', op, 'write', { f05: P, trx: P, freeze: P, write: P, actor: P, partition: P })
/** Una lectura del MANAGER: F-05 y partición con sonda; el resto lo cubre G-R. */
const managerRead = (op: string) =>
  row('manager', op, 'read', { f05: P, trx: READ, freeze: READ, write: READ, actor: READ, partition: P })
/** Una escritura de un DRIVER: F-05, puerta trx y partición; el freeze es doctrina; actor/eventos no están en la firma. */
const driverWrite = (layer: 'database' | 'openfga', op: string, write: GuardCell = SIG) =>
  row(layer, op, 'write', { f05: P, trx: P, freeze: DOC, write, actor: SIG, partition: P })
/** Una lectura de un DRIVER: F-05 y partición. */
const driverRead = (layer: 'database' | 'openfga', op: string) =>
  row(layer, op, 'read', { f05: P, trx: SIG, freeze: DOC, write: SIG, actor: SIG, partition: P })
/** `enumerateRelations(Many)` en cualquier capa: la exención D6 con su sonda de lista blanca; partición con sonda. */
const enumerateRow = (layer: GuardLayer, op: 'enumerateRelations' | 'enumerateRelationsMany') =>
  row(layer, op, 'read', {
    f05: { exempt: op === 'enumerateRelations' ? 'D6-enumerateRelations' : 'D6-enumerateRelationsMany', probe: 'whitelist' },
    trx: layer === 'manager' ? READ : layer === 'double' ? DBL : SIG,
    freeze: layer === 'manager' ? READ : layer === 'double' ? DBL : DOC,
    write: layer === 'manager' ? READ : SIG,
    actor: layer === 'manager' ? READ : SIG,
    partition: P,
  })
/** La vista `withClock` (H11): no recibe tupla; se juzga re-corriendo TODAS las filas de su capa sobre la vista. */
const viewRow = (layer: 'database' | 'openfga' | 'double') =>
  row(layer, 'withClock', 'view', { f05: SIG, trx: SIG, freeze: SIG, write: SIG, actor: SIG, partition: SIG })
/** Una operación del DOBLE publicado (D13): F-05 y partición (⚪ 11) con sonda; trx/freeze no existen en el fixture. */
const doubleOp = (op: string, kind: 'write' | 'read') =>
  row('double', op, kind, { f05: P, trx: DBL, freeze: DBL, write: SIG, actor: SIG, partition: P })

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
  enumerateRow('manager', 'enumerateRelations'),
  enumerateRow('manager', 'enumerateRelationsMany'),
  row('manager', 'driver', 'platform', {
    f05: { exempt: 'D6-driver', probe: 'identity' },
    trx: SIG,
    freeze: SIG,
    write: SIG,
    actor: SIG,
    partition: SIG,
  }),
  row('manager', 'capabilities', 'platform', {
    f05: { exempt: 'D6-capabilities', probe: 'frozen-copy' },
    trx: SIG,
    freeze: SIG,
    write: SIG,
    actor: SIG,
    partition: SIG,
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
  }),
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
export const PORT_WRITES = ['relate', 'unrelate', 'purgeObject', 'purgeSubject'] as const
export const PORT_READS = ['check', 'checkMany', 'listObjects', 'listSubjects', 'membersOf', 'enumerateRelations', 'enumerateRelationsMany'] as const

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
  RelationTypeUnknownError: 'clase de error (422 E_AUTHZ_RELATION_TYPE_UNKNOWN): es lo que F-05 LANZA, no una operación',
  RelationUnknownError: 'clase de error (422 E_AUTHZ_RELATION_UNKNOWN): es lo que F-05 LANZA, no una operación',
  assertRelationsConfigPublishable: 'valida la config contra el techo del modelo FGA (openfga:provision)',
  factsRelationMap: 'generador del modelo facts (relaciones derivadas de permisos)',
  factsRelationTypeDefinitions: 'generador del modelo facts (type definitions de los tipos declarados)',
  factsRelationsOf: 'generador del modelo facts',
  buildRelationsManager: 'construye el RelationsManager del servicio: lo que devuelve se SONDEA con las filas manager (cierre 🟡 6)',
  AuthzRelationsReconcile: 'comando de ace (clase sin operaciones del puerto): su efecto lo juzga command_flags.spec',
  relationsReconcileLines: 'formatea el reporte del reconcile de relaciones',
  relationsConfigOf: 'resuelve la config de relaciones para openfga:provision',
  relationTupleKey: 'clave PURA de una tupla (plan 2.5 · lote A, P3): sin backend ni driver; no es una operación del puerto',
  relationSubjectKey: 'clave PURA de un sujeto de relación (parte de relationTupleKey)',
}

/** Título CANÓNICO del caso de una celda: lo que el manifiesto de mutantes nombra en `expectRed`. */
export function cellTitle(layer: GuardLayer, operation: string, column: GuardColumn): string {
  return `GS · ${layer}.${operation} · ${column}`
}

/** Id canónico de una celda (`layer.operation.column`), el que usa `guard_mutants.json`. */
export function cellId(layer: GuardLayer, operation: string, column: GuardColumn): string {
  return `${layer}.${operation}.${column}`
}

export const GUARD_COLUMNS: GuardColumn[] = ['f05', 'trx', 'freeze', 'write', 'actor', 'partition']

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
  cells: string[]
  file: string
  /** Un solo edit (`find`/`replace`) … */
  find?: string
  replace?: string
  /** … o varios, cuando la guarda de esa entrada son VARIAS líneas (defensa en profundidad dentro del mismo camino). */
  edits?: GuardMutantEdit[]
  /** Títulos de los casos que tienen que ponerse ROJOS con el mutante aplicado (= `cellTitle` de cada celda). */
  expectRed: string[]
  /** Razón escrita cuando el mutante no es «quitar UNA línea» (G-M no la exige, el informe sí). */
  note?: string
}
