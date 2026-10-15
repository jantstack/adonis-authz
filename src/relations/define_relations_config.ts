/**
 * `defineRelationsConfig` — la API declarativa de ReBAC (Fase 4, lote 4-2).
 *
 * Valida la config de relaciones del consumidor y devuelve un objeto
 * CONGELADO que el manager de relaciones consulta para F-05 (`isDeclared`).
 * Es la puerta de entrada, AGNÓSTICA de driver: rige igual en `database` y en
 * `openfga` (paridad ⚪4). El generador del modelo fusionado
 * (`src/drivers/openfga_facts.ts`, lote 4-1) hace la MISMA comprobación de
 * reservados por defensa en profundidad al emitir el modelo —y además la de
 * F-04 (colisión con un permiso del catálogo), que necesita las tuplas del
 * catálogo y por eso vive en la capa del modelo—; las dos comparten la fuente
 * única de tipos reservados (`RESERVED_FACTS_TYPES` en `src/identity.ts`).
 *
 * Pureza (regla 2 de `check_purity.mjs`): este módulo solo depende del puerto
 * (`../types.js`), de los errores y de la gramática compartida
 * (`../identity.js`); JAMÁS de `../manager` ni de `../drivers/*`. Es lo que
 * mantiene `relations/` desacoplado de `roles/`.
 */
import {
  RelationConfigError,
  RelationConfigUnknownKeyError,
  RelationTypeUnknownError,
  RelationUnknownError,
  RelationUsersetUnsupportedError,
} from '../errors.js'
import { RESERVED_FACTS_TYPES, RESERVED_SLUGS, RESERVED_SLUG_PREFIXES } from '../identity.js'
import type { RelObject, RelUserset } from '../types.js'

/**
 * **El ÚNICO userset que el modelo admite como sujeto** (plan 2.5 · lote B · B3):
 * `group#member`. El generador del modelo fusionado emite, para CADA relación de
 * dominio, `[<holders> with not_expired, group#member]` y nada más; `group` es el
 * tipo BUILT-IN (`declared.set('group', …)` abajo) y el consumidor no lo declara.
 */
export const RELATION_USERSET_TYPE = 'group'
export const RELATION_USERSET_RELATION = 'member'

/** La cota de FGA para el nombre de una relación (50). Un tipo de objeto llega a 254. */
const RELATION_NAME_MAX = 50
const OBJECT_TYPE_MAX = 254
/** Nombres FGA: minúsculas, dígitos y `._-`; sin `:`/`#`/`@`/espacios ni `|`. */
const FGA_NAME_FORMAT = /^[a-z0-9][a-z0-9._-]*$/

/**
 * **Listas blancas por nivel de la spec** (plan 2.5 · lote B · B2; linaje L5,
 * propiedad universal «ninguna clave de una spec de config se descarta»).
 * Una clave que no está en la lista de SU nivel es 422
 * `E_AUTHZ_RELATION_CONFIG_UNKNOWN_KEY` nombrando la ruta (`objectTypes[1].deny`)
 * y la lista. Hasta `2.5.0-alpha.1` la config congelada copiaba solo lo que
 * conocía y tiraba el resto en silencio (tester H3, medido: `deny: true` y
 * `denny: 1` desaparecían): un typo era una entrada inerte, y el lote D (deny)
 * habría nacido con la clave `deny` leída por un proceso viejo como «nada».
 * Las claves del lote D entran AQUÍ, en el mismo commit que su efecto.
 */
export const RELATIONS_SPEC_KEYS = Object.freeze({
  root: Object.freeze(['objectTypes', 'holderTypes', 'database'] as const),
  objectType: Object.freeze(['type', 'relations'] as const),
  relation: Object.freeze(['name', 'includes'] as const),
  database: Object.freeze(['membersOf'] as const),
})

/**
 * **Guardia de TIPO en compilación** (cierre 1 del lote B · 🟡 6; L5, la «entrada
 * en la guardia» que el lote B dejó en prosa): cada lista blanca tiene que
 * cubrir EXACTAMENTE las claves de su tipo. `Record<Exclude<keyof T, Known>,
 * never> = {}` solo compila si `Exclude<…>` es `never` — un campo nuevo del tipo
 * (el `deny` del lote D) que no entre en la lista ROMPE `npm run typecheck`; y
 * el `satisfies` de abajo rompe si la lista nombra una clave que el tipo no
 * tiene. No es prosa ni un test por reflexión: es el compilador.
 */
type KnownRelationsSpecRootKey = (typeof RELATIONS_SPEC_KEYS.root)[number]
type KnownRelationsSpecObjectTypeKey = (typeof RELATIONS_SPEC_KEYS.objectType)[number]
type KnownRelationsSpecRelationKey = (typeof RELATIONS_SPEC_KEYS.relation)[number]
type KnownRelationsSpecDatabaseKey = (typeof RELATIONS_SPEC_KEYS.database)[number]
const _exhaustiveRelationsRoot: Record<Exclude<keyof RelationsConfigSpec, KnownRelationsSpecRootKey>, never> = {}
const _exhaustiveRelationsObjectType: Record<Exclude<keyof RelationObjectTypeSpec, KnownRelationsSpecObjectTypeKey>, never> = {}
const _exhaustiveRelationsRelation: Record<Exclude<keyof RelationObjectRelationSpec, KnownRelationsSpecRelationKey>, never> = {}
const _exhaustiveRelationsDatabase: Record<Exclude<keyof RelationsDatabaseOptions, KnownRelationsSpecDatabaseKey>, never> = {}
void _exhaustiveRelationsRoot, _exhaustiveRelationsObjectType, _exhaustiveRelationsRelation, _exhaustiveRelationsDatabase
RELATIONS_SPEC_KEYS.root satisfies readonly (keyof RelationsConfigSpec)[]
RELATIONS_SPEC_KEYS.objectType satisfies readonly (keyof RelationObjectTypeSpec)[]
RELATIONS_SPEC_KEYS.relation satisfies readonly (keyof RelationObjectRelationSpec)[]
RELATIONS_SPEC_KEYS.database satisfies readonly (keyof RelationsDatabaseOptions)[]

/** ⚪ 13: una clave de BLOQUE conocida con un valor que no es un objeto plano (`database: true`) es 422, no silencio. */
function assertObjectBlock(value: unknown, path: string): void {
  if (value === undefined) return
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new RelationConfigError(
      `Config de relaciones inválida: '${path}' tiene que ser un objeto (llegó ${JSON.stringify(value)}). ` +
        `Un valor que no es objeto en una clave conocida no es «nada»: se ignoraría en silencio.`
    )
  }
}

/** Toda clave PROPIA de `value` tiene que estar en `known`; si no, 422 con la ruta y la lista blanca del nivel. */
function assertKnownKeys(value: unknown, known: readonly string[], path: string): void {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return
  for (const key of Object.keys(value as Record<string, unknown>)) {
    if (known.includes(key)) continue
    const where = path === '' ? `'${key}' en la raíz de la spec` : `'${path}.${key}'`
    throw new RelationConfigUnknownKeyError(
      `Config de relaciones inválida: la clave ${where} no existe (claves válidas en ${path === '' ? 'la raíz' : path}: ${known.join(', ')}). ` +
        `Ninguna clave de la spec se descarta en silencio: un typo ('denny') o una clave de otra versión del paquete ` +
        `sería una entrada inerte que el modelo publicado no refleja. Quítala o corrige el nombre.`
    )
  }
}

/**
 * **B1 · ciclos de `includes`** (plan 2.5 · lote B; analista M3 / tester H4,
 * medidos): `editor ⊇ viewer ⊇ editor` se aceptaba — `database` lo SIRVE (la
 * expansión termina por el `Set`) y OpenFGA rechaza CUALQUIER ciclo al
 * publicar el modelo, así que la paridad estaba rota desde el config. Es
 * config, no driver: el mismo 422 vale para los dos ANTES de construir nada.
 * DFS con pila de colores sobre el grafo `relation → includes` del tipo;
 * devuelve el ciclo NOMBRADO (`a → b → a`, desde el nodo que lo cierra, no
 * desde la raíz por la que se entró) o `null`. Un ciclo directo (`a ⊇ a`) es
 * el caso de longitud 1 del mismo recorrido.
 */
function findIncludesCycle(relations: readonly RelationObjectRelationSpec[]): string[] | null {
  const edges = new Map<string, readonly string[]>()
  for (const relation of relations) edges.set(relation.name, relation.includes ?? [])
  const state = new Map<string, 'visiting' | 'done'>()
  const stack: string[] = []
  const visit = (name: string): string[] | null => {
    const mark = state.get(name)
    if (mark === 'done') return null
    if (mark === 'visiting') {
      const start = stack.indexOf(name)
      return [...stack.slice(start), name]
    }
    state.set(name, 'visiting')
    stack.push(name)
    for (const next of edges.get(name) ?? []) {
      const cycle = visit(next)
      if (cycle) return cycle
    }
    stack.pop()
    state.set(name, 'done')
    return null
  }
  for (const relation of relations) {
    const cycle = visit(relation.name)
    if (cycle) return cycle
  }
  return null
}

/** Una relación de un tipo de objeto (`document#viewer`), con sus `includes` de un nivel. */
export interface RelationObjectRelationSpec {
  /** El nombre de la relación (`owner`, `editor`, `viewer`). */
  name: string
  /**
   * Otras relaciones del MISMO tipo que ésta incluye (`viewer or editor`):
   * un `relate(u, editor, doc)` concede también `viewer`. Un nivel, SIN
   * `from` en v1 (la herencia cross-objeto metería un TTU entre tipos y
   * habría que re-medir profundidad — diferido a 2.6+).
   */
  includes?: readonly string[]
}

/** Un tipo de objeto de relaciones (`document`, `folder`, `space`…). */
export interface RelationObjectTypeSpec {
  /** El tipo FGA del objeto. */
  type: string
  /** Sus relaciones, en orden de declaración. */
  relations: readonly RelationObjectRelationSpec[]
}

/** Opciones específicas del driver `database`. */
export interface RelationsDatabaseOptions {
  /**
   * Habilita `membersOf` (membresía TRANSITIVA a través de usersets), que solo
   * el driver `database` resuelve (CTE recursiva). En `openfga` la transitiva
   * sería `ListUsers`, que trunca, así que la opción NO es válida fuera de
   * `database`.
   */
  membersOf?: boolean
}

/** La config que declara el consumidor. */
export interface RelationsConfigSpec {
  /** Los tipos de objeto y sus relaciones. */
  objectTypes: readonly RelationObjectTypeSpec[]
  /**
   * Los holder types del config del consumidor (`user`, `admin`…). Se suman a
   * los tipos reservados: un tipo de objeto de relaciones no puede llamarse
   * como un holder (⚪4).
   */
  holderTypes?: readonly string[]
  /** Opciones del driver `database` (donde vive `membersOf`). */
  database?: RelationsDatabaseOptions
}

/** La config ya validada y CONGELADA que consulta el manager de relaciones. */
export interface RelationsConfig {
  readonly objectTypes: readonly RelationObjectTypeSpec[]
  /** ¿`membersOf` está habilitado (opción de `database`)? */
  readonly membersOf: boolean
  /** ¿Existe el tipo de objeto? (F-05, cara del tipo). */
  hasType(objectType: string): boolean
  /** ¿La relación está declarada para ese tipo? (F-05, cara de la relación). */
  isDeclared(objectType: string, relation: string): boolean
}

function reject(message: string): never {
  throw new RelationConfigError(message)
}

/**
 * **F-05, la función ÚNICA** (L-0): rechaza un `object.type` no declarado
 * (422 `E_AUTHZ_RELATION_TYPE_UNKNOWN`) o una `relation` no declarada para ese
 * tipo (422 `E_AUTHZ_RELATION_UNKNOWN`). La aplican el `RelationsManager`
 * (corta primero) Y los dos drivers de relaciones, ANTES de tocar el backend
 * — la misma función, así que la misma clase, el mismo `code` y el mismo
 * mensaje por cualquier puerta. Hacía falta en el driver (panel `{trx}`, 🔴 2
 * del auditor): `manager.driver()` y `reconcileRelations` (que escribe con
 * `to.relate`) entran por él, y sin la guarda
 * `relate(evil, 'assignee', {type:'role_binding', id:<roleUuid>}, S)` componía
 * en el store COMPARTIDO el id exacto de un binding de roles y
 * `roles.authorize` pasaba de `false` a `true` (medido contra el `:8101`).
 * La gramática de identidad no basta: `role_binding`/`assignee` son
 * gramaticalmente válidos.
 *
 * **Cubre las OCHO operaciones del puerto** (`2.4.0-alpha.3`, cierre del
 * 🔴 1 / 🟠 2 del auditor y cierre-2): hasta alpha.3 solo `relate`/`unrelate`
 * la llamaban, y por `purgeObject({ type: 'role_binding', id: R }, S)` el
 * puerto de relaciones BORRABA el binding real del store compartido
 * (`authorize` pasaba de `true` a `false`, 0 tuplas, evento de auditoría
 * limpio), y `listSubjects('assignee', role_binding)` enumeraba sus asignados
 * sin catálogo ni `within`. **Son DOS funciones, no un opcional** (cierre-2,
 * 🟠 1 del re-ataque): el primer cierre hizo `relation` opcional con un
 * `if (relation === undefined) return` compartido por todas las llamadas, y
 * eso APAGÓ F-05 en `relate`/`unrelate` sin relación (`request.input('relation')`
 * ausente): antes `isDeclared('document', undefined)` era `false` ⇒ 422 con
 * cero llamadas; con el opcional los dobles escribían la tupla, `openfga`
 * devolvía 503 del servidor y `database` lo salvaba su driver (paridad rota),
 * y `listSubjects(undefined)` devolvía la UNIÓN de relaciones del objeto.
 * Esta función es ESTRICTA: la relación es obligatoria (ausente, `undefined`,
 * vacía o no-string ⇒ 422 `E_AUTHZ_RELATION_UNKNOWN`) y la usan `relate`/
 * `unrelate`/`check`/`listSubjects`/`membersOf` (+ `listObjects`, que también
 * nombra una relación) y el userset de un sujeto (`{ object, relation }`).
 * Quien NO nombra relación —`purgeObject`— usa `assertObjectTypeDeclared`.
 */
export function assertRelationDeclared(
  config: RelationsConfig,
  object: RelObject | { type: string },
  relation: string
): void {
  assertObjectTypeDeclared(config, object)
  if (typeof relation !== 'string' || relation.length === 0) {
    throw new RelationUnknownError(
      `La relación de '${object.type}' es obligatoria y llegó ${relation === undefined ? 'undefined' : JSON.stringify(relation)} ` +
        `(F-05): relate/unrelate/check/listObjects/listSubjects/membersOf exigen una relación declarada; ` +
        `sin ella no hay tupla que escribir ni pregunta que responder.`
    )
  }
  if (!config.isDeclared(object.type, relation)) {
    throw new RelationUnknownError(
      `La relación '${String(relation)}' no está declarada para el tipo '${object.type}' en ` +
        `defineRelationsConfig (F-05).`
    )
  }
}

/**
 * **F-05 sobre el TIPO solo** (cierre-2 de alpha.3): la mitad de F-05 que
 * aplican las operaciones que NO nombran relación —`purgeObject`— y la primera
 * comprobación de `assertRelationDeclared`. Un tipo no declarado (o un objeto
 * que no es `{ type }`) ⇒ 422 `E_AUTHZ_RELATION_TYPE_UNKNOWN`. Separada de la
 * estricta a propósito: deducir «solo el tipo» de un `relation === undefined`
 * era lo que apagaba F-05 en `relate`/`unrelate` sin relación (🟠 1 del
 * re-ataque del auditor).
 */
export function assertObjectTypeDeclared(config: RelationsConfig, object: RelObject | { type: string }): void {
  if (!object || typeof object !== 'object' || typeof object.type !== 'string') {
    throw new RelationTypeUnknownError(
      `Objeto de relación inválido: se esperaba { type, id } y llegó ${JSON.stringify(object)}.`
    )
  }
  if (!config.hasType(object.type)) {
    throw new RelationTypeUnknownError(
      `El tipo de objeto '${object.type}' no está declarado en defineRelationsConfig (F-05): ` +
        `relate/unrelate/purgeObject/purgeSubject/check/listObjects/listSubjects/membersOf solo aceptan ` +
        `tipos declarados. En el store compartido un tipo no declarado podría componer el id de un ` +
        `'role_binding' real y escalar a roles.authorize, purgarlo o enumerar sus asignados.`
    )
  }
}

/**
 * **B3 · el userset del SUJETO: F-05 (par) y, además, `group#member` y solo
 * `group#member`** (plan 2.5 · lote B; auditor [N 9] de la ronda 1, analista
 * B(2); patrón F-05 `assertRelationDeclared`: UNA función, misma clase, mismo
 * `code` y mismo mensaje por cualquier puerta). Hasta `2.5.0-alpha.1` un
 * `{ object: document, relation: viewer }` como sujeto pasaba F-05 (tipo y
 * relación declarados) y después: `database` guardaba la fila INERTE (ningún
 * holder la alcanza: la expansión de principales solo baja por `group#member`)
 * y `openfga` componía `document:<key>|<id>#viewer` como `user`, que el modelo
 * fusionado no admite ⇒ 400 del servidor ⇒ 503 mal clasificado (invariante 5:
 * una pregunta inválida es 422, no una caída). La aplican el `RelationsManager`
 * (`#assertSubject`), los DOS drivers (`#subjectColumns` / `#subjectUser`) y el
 * doble publicado, en TODA operación que recibe sujeto —`relate`/`unrelate`/
 * `check`/`checkMany`/`listObjects`/`purgeSubject`—, ANTES de tocar el backend
 * (cero `INSERT`, cero `Write`/`Read`/`Check`). La guardia de superficie lo
 * sondea como variante de F-05 (`usersetUnsupported`) con un mutante por capa.
 */
export function assertUsersetSubject(config: RelationsConfig, subject: RelUserset): void {
  assertRelationDeclared(config, subject.object, subject.relation)
  assertSupportedUserset(subject)
}

/**
 * **La mitad de B3 que no necesita config**: `group#member` y solo `group#member`
 * (cierre 1 del lote B · 🟠 2). Es la regla que `reconcileRelations` aplica en el
 * PLAN a cada tupla ENUMERADA —del origen y del destino— también cuando no hay
 * `toConfig` (sin config no se puede juzgar F-05 del par, pero la forma del
 * userset sí): así un residuo pre-2.5 se clasifica ANTES del driver, con los
 * mismos números en `--dry-run` y en la pasada real. **En el plan la FORMA va
 * ANTES que F-05** (cierre 2 · 🟡 N2): un residuo B3 es inadmisible con
 * cualquier config, así que un userset de tipo/relación no declarados sigue
 * siendo residuo (`usersetUnsupported`, con receta) y nunca `undeclared` (cuyo
 * consejo «decláralo» no lo arreglaría). En la API (`assertUsersetSubject`,
 * la pregunta del llamante) el orden sigue siendo F-05 → forma: los dos son
 * 422 y ninguno escribe.
 */
export function assertSupportedUserset(subject: RelUserset): void {
  if (subject.object.type !== RELATION_USERSET_TYPE || subject.relation !== RELATION_USERSET_RELATION) {
    throw new RelationUsersetUnsupportedError(
      `El userset '${subject.object.type}#${subject.relation}' no vale como SUJETO de una relación (B3): el modelo ` +
        `solo admite '${RELATION_USERSET_TYPE}#${RELATION_USERSET_RELATION}' como sujeto de una relación de dominio. ` +
        `En 'database' esa fila sería inerte (ningún holder la alcanza) y en 'openfga' un 400 del servidor; ` +
        `relaciona al holder o al grupo, no a la relación de otro objeto.`
    )
  }
}

/**
 * **El residuo pre-2.5 de B3 y cómo se borra** (cierre 1 del lote B · 🟠 1/🟠 2,
 * ⚪ 12): una fila de `authz_relations` escrita ANTES de 2.5.0 con un sujeto
 * userset ≠ `group#member`. La API ya no la admite (ni `relate`, ni `unrelate`,
 * ni `purgeSubject(userset)`), el reconcile la LISTA con este motivo y **nunca
 * la borra por vía de plataforma** (decisión del coordinador, 2026-10-15: la
 * misma regla que toda tupla del destino fuera de gramática — se lista, exit
 * ≠ 0, se borra a mano). Las dos sentencias valen en los tres motores
 * (`subject_relation <> ''` excluye los holders, también los `NULL` de antes
 * de L-4b: `NULL <> ''` es NULL ⇒ falso); `upgrade_recipe.spec` las EJECUTA y
 * el README §Upgrading las publica literalmente.
 */
export const RELATION_USERSET_RESIDUE_WHERE =
  `subject_relation <> '' AND NOT (subject_type = '${RELATION_USERSET_TYPE}' AND subject_relation = '${RELATION_USERSET_RELATION}')`
export const RELATION_USERSET_RESIDUE_SELECT =
  `SELECT uuid, partition_key, object_type, object_uuid, relation, subject_type, subject_uuid, subject_relation FROM authz_relations WHERE ${RELATION_USERSET_RESIDUE_WHERE};`
export const RELATION_USERSET_RESIDUE_DELETE = `DELETE FROM authz_relations WHERE ${RELATION_USERSET_RESIDUE_WHERE};`

/**
 * Valida y congela la config de relaciones. Config inválida ⇒ 422
 * `E_AUTHZ_RELATION_CONFIG` (misma clase que el gate del modelo del lote 4-1).
 */
export function defineRelationsConfig(spec: RelationsConfigSpec): RelationsConfig {
  if (!spec || typeof spec !== 'object') {
    reject(`Config de relaciones inválida: se esperaba un objeto y llegó ${JSON.stringify(spec)}.`)
  }
  // ⚪ 13 (cierre 1 del lote B): una config YA DEFINIDA (la salida de esta misma
  // función: `isDeclared`/`hasType` son funciones) pasada como spec —el tipo
  // estructural lo permite, p. ej. `saveRelationsConfig(config.relations.config)`—
  // moría en «'membersOf' en la raíz no existe» sin pista. Se dice lo que es.
  if (typeof (spec as any).isDeclared === 'function' && typeof (spec as any).hasType === 'function') {
    reject(
      `Config de relaciones inválida: parece una config YA DEFINIDA (la salida de defineRelationsConfig: lleva ` +
        `isDeclared/hasType), no la spec. Pasa la spec declarativa ({ objectTypes, holderTypes?, database? }) — ` +
        `también a saveRelationsConfig, que persiste la spec, no la config congelada.`
    )
  }
  // `membersOf` SOLO puede vivir en las opciones de `database` (⚪ del tester):
  // ponerlo en la raíz o en un futuro bloque `openfga` es un error de
  // configuración —`openfga` no puede resolver la transitiva sin truncar—.
  if ('membersOf' in (spec as unknown as Record<string, unknown>)) {
    reject(
      `Config de relaciones inválida: 'membersOf' es una opción del driver 'database' ` +
        `(membresía transitiva por CTE recursiva) y va en 'database.membersOf', no en la raíz. ` +
        `En 'openfga' la transitiva sería 'ListUsers', que trunca al tope del servidor.`
    )
  }

  // B2: la raíz, ANTES de leer nada de ella (un `deny: true` aquí no es «nada»).
  assertKnownKeys(spec, RELATIONS_SPEC_KEYS.root, '')
  // ⚪ 13 (cierre 1 del lote B; L5): un valor que NO es objeto en una clave
  // conocida de bloque (`database: true`) se ignoraba en silencio —`assertKnownKeys`
  // sale si no es objeto y `spec.database?.membersOf` daba `undefined`—. Es 422.
  assertObjectBlock(spec.database, 'database')
  assertKnownKeys(spec.database, RELATIONS_SPEC_KEYS.database, 'database')

  if (!Array.isArray(spec.objectTypes) || spec.objectTypes.length === 0) {
    reject(`Config de relaciones inválida: 'objectTypes' tiene que ser un array no vacío.`)
  }

  // ⚪ N7 (cierre 2 del lote B): una cadena se ITERABA por caracteres y
  // desactivaba la colisión ⚪4 (`holderTypes: 'user'` + `{ type: 'user' }`
  // entraba). L5: ningún valor con forma equivocada cae en un default.
  if (spec.holderTypes !== undefined && !Array.isArray(spec.holderTypes)) {
    reject(`Config de relaciones inválida: 'holderTypes' tiene que ser un array de cadenas (llegó ${JSON.stringify(spec.holderTypes)}).`)
  }
  const holderTypes = spec.holderTypes ?? []
  for (const holder of holderTypes) {
    if (typeof holder !== 'string') {
      reject(`Config de relaciones inválida: un holder type no es una cadena (${JSON.stringify(holder)}).`)
    }
  }
  const reservedTypes = new Set<string>([...RESERVED_FACTS_TYPES, ...holderTypes])

  const seenTypes = new Set<string>()
  for (const [typeIndex, objectType] of spec.objectTypes.entries()) {
    assertKnownKeys(objectType, RELATIONS_SPEC_KEYS.objectType, `objectTypes[${typeIndex}]`)
    const type = objectType?.type
    if (typeof type !== 'string' || !FGA_NAME_FORMAT.test(type) || type.length > OBJECT_TYPE_MAX) {
      reject(
        `Config de relaciones inválida: tipo de objeto ${JSON.stringify(type)} no es un tipo FGA válido ` +
          `(minúsculas, dígitos y '._-'; sin ':'/'#'/'@'/'|'/espacios; 1-${OBJECT_TYPE_MAX} caracteres).`
      )
    }
    if (reservedTypes.has(type)) {
      reject(
        `Config de relaciones inválida: el tipo de objeto '${type}' colisiona con un tipo reservado del ` +
          `modelo compartido (${[...RESERVED_FACTS_TYPES].join(', ')}` +
          `${holderTypes.length ? ', y los holder types ' + holderTypes.join(', ') : ''}). ` +
          `En el store compartido un tipo de relaciones no puede duplicar uno de 'facts' (⚪4): ` +
          `si pudiera declarar 'role_binding', 'relate' compondría el id de un binding real y escalaría a ` +
          `roles.authorize. Renómbralo.`
      )
    }
    if (seenTypes.has(type)) {
      reject(`Config de relaciones inválida: el tipo de objeto '${type}' está declarado dos veces.`)
    }
    seenTypes.add(type)

    if (!Array.isArray(objectType.relations) || objectType.relations.length === 0) {
      reject(`Config de relaciones inválida: el tipo '${type}' no declara ninguna relación.`)
    }

    const own = new Set<string>()
    for (const [relationIndex, relation] of objectType.relations.entries()) {
      assertKnownKeys(relation, RELATIONS_SPEC_KEYS.relation, `objectTypes[${typeIndex}].relations[${relationIndex}]`)
      const name = relation?.name
      if (typeof name !== 'string' || !FGA_NAME_FORMAT.test(name)) {
        reject(
          `Config de relaciones inválida: relación ${JSON.stringify(name)} del tipo '${type}' no es un ` +
            `nombre de relación válido (minúsculas, dígitos y '._-').`
        )
      }
      if (name.length > RELATION_NAME_MAX) {
        reject(
          `Config de relaciones inválida: la relación '${name}' del tipo '${type}' tiene ${name.length} ` +
            `caracteres y FGA admite ${RELATION_NAME_MAX}.`
        )
      }
      if (RESERVED_SLUGS.has(name)) {
        reject(
          `Config de relaciones inválida: la relación '${type}#${name}' usa un nombre reservado del modelo ` +
            `facts (${[...RESERVED_SLUGS].join(', ')}): elegiría una relación propia de 'facts' (⚪4).`
        )
      }
      const family = RESERVED_SLUG_PREFIXES.find((prefix) => name.startsWith(prefix))
      if (family) {
        reject(
          `Config de relaciones inválida: la relación '${type}#${name}' empieza por '${family}', prefijo ` +
            `reservado de las relaciones derivadas del modelo facts (${RESERVED_SLUG_PREFIXES.join(', ')}): ` +
            `pisaría el nombre de un permiso proyectado (⚪4).`
        )
      }
      if (own.has(name)) {
        reject(`Config de relaciones inválida: la relación '${type}#${name}' está declarada dos veces.`)
      }
      own.add(name)
    }

    // Los `includes` refieren relaciones del MISMO tipo (un nivel, SIN `from`).
    for (const relation of objectType.relations) {
      // ⚪ 13 (cierre 1 del lote B): `includes: {}` (o cualquier no-array) era un
      // `TypeError` crudo del `for…of`; es una config inválida, 422 con la ruta.
      if (relation.includes !== undefined && !Array.isArray(relation.includes)) {
        reject(
          `Config de relaciones inválida: 'includes' de '${type}#${relation.name}' tiene que ser un array de nombres ` +
            `de relación (llegó ${JSON.stringify(relation.includes)}).`
        )
      }
      for (const included of relation.includes ?? []) {
        if (typeof included !== 'string') {
          reject(`Config de relaciones inválida: un 'includes' de '${type}#${relation.name}' no es una cadena.`)
        }
        // Un `from` (`viewer from parent`) se escribe con un separador; v1 no lo soporta.
        if (/[:#@|. ]/.test(included) && !own.has(included)) {
          reject(
            `Config de relaciones inválida: '${type}#${relation.name}' incluye '${included}', que parece una ` +
              `herencia cross-objeto ('from'). v1 solo soporta includes de un nivel y del MISMO tipo.`
          )
        }
        if (!own.has(included)) {
          reject(
            `Config de relaciones inválida: '${type}#${relation.name}' incluye '${included}', que no es una ` +
              `relación de '${type}'. Los includes son de un nivel y del mismo tipo (v1 no soporta 'from').`
          )
        }
      }
    }
    // B1: ningún ciclo en el grafo de includes del tipo (directo, de 2, de N).
    const cycle = findIncludesCycle(objectType.relations)
    if (cycle) {
      reject(
        `Config de relaciones inválida: los 'includes' del tipo '${type}' forman un ciclo ` +
          `(${cycle.map((name) => `${type}#${name}`).join(' → ')}). OpenFGA rechaza cualquier ciclo al publicar el ` +
          `modelo y 'database' lo serviría igual: sería una config que un driver acepta y el otro no (paridad rota). ` +
          `Los includes son un orden parcial: quita la arista que lo cierra.`
      )
    }
  }

  const declared = new Map<string, Set<string>>()
  // `group` es el tipo BUILT-IN de las relaciones (el portador de los
  // usersets, `group:g#member`): lo emite SIEMPRE el generador del modelo, no
  // el consumidor —por eso NO se declara en `objectTypes` (arriba se rechaza)
  // pero SÍ es un tipo válido para F-05: `relate(group:g#member, viewer, doc)`
  // y `relate(u, member, group:g)` son legales. `role_binding`/`scope`/`role`
  // siguen fuera: la frontera del 🔴 se mantiene.
  declared.set(RELATION_USERSET_TYPE, new Set([RELATION_USERSET_RELATION]))
  // Desde B2 la copia congelada no «tira» nada: toda clave que llega hasta aquí
  // está en la lista blanca de su nivel (lo demás ya fue 422 arriba).
  const frozenTypes = spec.objectTypes.map((objectType) => {
    const relations = objectType.relations.map((relation: RelationObjectRelationSpec) =>
      Object.freeze({ name: relation.name, includes: relation.includes ? Object.freeze([...relation.includes]) : undefined })
    )
    declared.set(objectType.type, new Set(relations.map((r: RelationObjectRelationSpec) => r.name)))
    return Object.freeze({ type: objectType.type, relations: Object.freeze(relations) })
  })

  return Object.freeze({
    objectTypes: Object.freeze(frozenTypes),
    membersOf: spec.database?.membersOf === true,
    hasType: (objectType: string) => declared.has(objectType),
    isDeclared: (objectType: string, relation: string) => declared.get(objectType)?.has(relation) ?? false,
  }) as RelationsConfig
}
