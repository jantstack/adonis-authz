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
import { RelationConfigError, RelationTypeUnknownError, RelationUnknownError } from '../errors.js'
import { RESERVED_FACTS_TYPES, RESERVED_SLUGS, RESERVED_SLUG_PREFIXES } from '../identity.js'
import type { RelObject } from '../types.js'

/** La cota de FGA para el nombre de una relación (50). Un tipo de objeto llega a 254. */
const RELATION_NAME_MAX = 50
const OBJECT_TYPE_MAX = 254
/** Nombres FGA: minúsculas, dígitos y `._-`; sin `:`/`#`/`@`/espacios ni `|`. */
const FGA_NAME_FORMAT = /^[a-z0-9][a-z0-9._-]*$/

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
 * Valida y congela la config de relaciones. Config inválida ⇒ 422
 * `E_AUTHZ_RELATION_CONFIG` (misma clase que el gate del modelo del lote 4-1).
 */
export function defineRelationsConfig(spec: RelationsConfigSpec): RelationsConfig {
  if (!spec || typeof spec !== 'object') {
    reject(`Config de relaciones inválida: se esperaba un objeto y llegó ${JSON.stringify(spec)}.`)
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

  if (!Array.isArray(spec.objectTypes) || spec.objectTypes.length === 0) {
    reject(`Config de relaciones inválida: 'objectTypes' tiene que ser un array no vacío.`)
  }

  const holderTypes = spec.holderTypes ?? []
  for (const holder of holderTypes) {
    if (typeof holder !== 'string') {
      reject(`Config de relaciones inválida: un holder type no es una cadena (${JSON.stringify(holder)}).`)
    }
  }
  const reservedTypes = new Set<string>([...RESERVED_FACTS_TYPES, ...holderTypes])

  const seenTypes = new Set<string>()
  for (const objectType of spec.objectTypes) {
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
    for (const relation of objectType.relations) {
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
        if (included === relation.name) {
          reject(`Config de relaciones inválida: '${type}#${relation.name}' se incluye a sí misma.`)
        }
      }
    }
  }

  const declared = new Map<string, Set<string>>()
  // `group` es el tipo BUILT-IN de las relaciones (el portador de los
  // usersets, `group:g#member`): lo emite SIEMPRE el generador del modelo, no
  // el consumidor —por eso NO se declara en `objectTypes` (arriba se rechaza)
  // pero SÍ es un tipo válido para F-05: `relate(group:g#member, viewer, doc)`
  // y `relate(u, member, group:g)` son legales. `role_binding`/`scope`/`role`
  // siguen fuera: la frontera del 🔴 se mantiene.
  declared.set('group', new Set(['member']))
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
