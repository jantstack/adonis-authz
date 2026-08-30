import { InvalidIdentityError, InvalidSlugError, ModelTooLargeError, AuthorizationConfigError } from '../errors.js'
import { slugAsRelation } from '../identity.js'
import type { CatalogProjectionRole, HolderTypeMap } from '../types.js'

/**
 * Modo `facts` — el MODELO (c2) y la proyección del catálogo, sin `@openfga/sdk`.
 *
 * Aquí no hay cliente ni decisiones: es la pieza pura que traduce
 * `holderTypes` + los permisos del catálogo al authorization model que el
 * store publica, y los vínculos rol→permiso a las tuplas que lo materializan.
 * Vive aparte del driver para poder juzgarse sin servidor y sin SDK.
 *
 * El modelo es el que fijó el panel 2 (cruce 1, variante **(c2)** del
 * analista, 53/53 invariantes medidos contra OpenFGA v1.19). No se rediseña:
 *
 * ```
 * type user / admin / integration                    # los holderTypes del consumidor
 * type role                                          # id = roleUuid
 *   define permits_<P>: [user:*, admin:*, integration:*]
 * type role_binding                                  # id = <scopeKey>|<roleUuid>
 *   define role: [role]
 *   define assignee: [<holders> with not_expired]
 *   define <P>: assignee and permits_<P> from role
 * type scope                                         # id = 'app' | '<tipo>|<uuid>'
 *   define parent: [scope]
 *   define binding: [role_binding]
 *   define <P>: <P> from binding or <P> from parent
 *   define denied_<P>: [<holders>] or denied_<P> from parent
 *   define can_<P>: <P> but not denied_<P>
 *   define ancestor: parent or ancestor from parent  # isWithin/descendantsOf nativos, 0 tuplas
 * ```
 *
 * Por qué (c2) y no (c1) —catálogo por scope— (cruce 1): un cambio de
 * catálogo son 3 deletes en UN `Write` atómico en vez de O(scopes) requests
 * no atómicos, `attached` escribe 1 tupla en vez de 1+K, y el `verify` del
 * catálogo es O(roles×permisos×holders) en vez de O(scopes×…). Se paga con
 * ~0,8 ms por `authorize` y con un techo de permisos más bajo (~720).
 */

/** Nombre de tipo admitido por FGA (`^[^:#@\s]{1,254}$`). */
const FGA_TYPE_FORMAT = /^[^:#@\s]{1,254}$/

/**
 * `holderTypes` tiene que ser INYECTIVO. Si dos morph names caen en el mismo
 * tipo FGA, para el store son un solo holder: un grant a `users:U` autoriza a
 * `integrations:U`, `listSubjects` devuelve el morph equivocado y un revoke
 * borra al otro (invariante 4, L0.2). El generador del modelo lo "sabía"
 * (deduplicaba con un Set) y publicaba sin quejarse: ahora lanza aquí, al
 * construir el driver y al generar cualquiera de los dos modelos, antes de
 * tocar nada.
 */
export function assertHolderTypes(holderTypes: HolderTypeMap): void {
  if (!holderTypes || typeof holderTypes !== 'object' || Object.keys(holderTypes).length === 0) {
    throw new AuthorizationConfigError(
      'holderTypes vacío: el driver openfga necesita al menos un holder (morph name → tipo FGA)'
    )
  }
  const morphsByFgaType = new Map<string, string[]>()
  for (const [morph, fgaType] of Object.entries(holderTypes)) {
    if (typeof fgaType !== 'string' || !FGA_TYPE_FORMAT.test(fgaType)) {
      throw new AuthorizationConfigError(
        `holderTypes['${morph}'] = ${JSON.stringify(fgaType)} no es un tipo FGA válido ` +
          `(1-254 caracteres, sin ':', '#', '@' ni espacios)`
      )
    }
    morphsByFgaType.set(fgaType, [...(morphsByFgaType.get(fgaType) ?? []), morph])
  }
  const collisions = [...morphsByFgaType.entries()].filter(([, morphs]) => morphs.length > 1)
  if (collisions.length) {
    throw new AuthorizationConfigError(
      `holderTypes no es inyectivo: ` +
        collisions.map(([fga, morphs]) => `${morphs.join(' y ')} → '${fga}'`).join('; ') +
        `. Dos holders con el mismo tipo FGA serían uno solo para el store.`
    )
  }
}

/* ── Cotas del servidor (cruce 9 del panel) ─────────────────────────────── */

/**
 * Longitud máxima de un nombre de relación en FGA. `MAX_SLUG_LENGTH` (42) es
 * justo esto menos el prefijo derivado más largo (`permits_`), así que un
 * slug legal siempre cabe: la comprobación de aquí es la red del generador,
 * que también lo llaman herramientas con listas de permisos que no pasaron
 * por `assertValidSlug` (una base sincronizada por otra versión, un driver
 * de terceros).
 */
export const FGA_MAX_RELATION_NAME = 50

/**
 * Longitud máxima del id de un objeto FGA. Con la gramática publicada nada
 * se acerca (`role_binding:<tipo>|<uuid>|<roleUuid>` son 107 como mucho),
 * pero el id se compone de partes que vienen de la BASE: un catálogo
 * corrupto no puede fabricar un objeto que el store no pueda leer de vuelta.
 */
export const FGA_MAX_OBJECT_ID = 256

/**
 * Techo del authorization model (default de `OPENFGA_MAX_AUTHORIZATION_MODEL_SIZE_IN_BYTES`,
 * medido: ≈720 permisos con el modelo (c2)). Se valida en `syncAuthzCatalog`
 * ANTES de escribir el catálogo: un catálogo que no se puede publicar no se
 * escribe a medias en un entorno y entero en otro.
 */
export const FACTS_MODEL_MAX_BYTES = 262_144

/** Fracción del techo a partir de la cual se avisa (cruce 9: "aviso al 80 %"). */
export const FACTS_MODEL_WARN_RATIO = 0.8

/** El tipo FGA cuyo id es el uuid del rol del catálogo. */
export const FACTS_ROLE_TYPE = 'role'

/** Prefijo de la familia que materializa el catálogo (`role:<uuid>#permits_<P>`). */
export const FACTS_PERMITS_PREFIX = 'permits_'

/* ── Relaciones derivadas de un permiso ─────────────────────────────────── */

/**
 * Relaciones propias del modelo (no derivadas de ningún permiso). Un permiso
 * que produzca uno de estos nombres invalidaría el modelo entero (S14):
 * `assertValidSlug` ya los reserva en el núcleo para AMBOS drivers, y aquí
 * entran en el mismo `Map` que las cuatro familias para que el generador no
 * dependa de que alguien haya validado antes.
 */
const OWN_RELATIONS: ReadonlyArray<[string, string]> = Object.freeze([
  ['role', "relación propia del modelo (role_binding#role)"],
  ['assignee', "relación propia del modelo (role_binding#assignee)"],
  ['parent', "relación propia del modelo (scope#parent)"],
  ['binding', "relación propia del modelo (scope#binding)"],
  ['ancestor', "relación propia del modelo (scope#ancestor)"],
] as ReadonlyArray<[string, string]>)

/** Las CUATRO familias de (c2) para un permiso: `<P>`, `can_<P>`, `denied_<P>`, `permits_<P>`. */
export interface FactsRelations {
  permission: string
  /** `<P>` en `role_binding` y en `scope`. */
  base: string
  /** `can_<P>`: lo que responde `authorize`. */
  can: string
  /** `denied_<P>`: el deny explícito, heredado hacia abajo. */
  denied: string
  /** `permits_<P>`: la proyección del catálogo (qué permisos vincula un rol). */
  permits: string
}

/** Las cuatro relaciones que un permiso genera, sin validar nada. */
export function factsRelationsOf(permission: string): FactsRelations {
  const base = slugAsRelation(permission)
  return {
    permission,
    base,
    can: `can_${base}`,
    denied: `denied_${base}`,
    permits: `${FACTS_PERMITS_PREFIX}${base}`,
  }
}

/**
 * **S4, bloqueante del juez.** Con CUATRO familias, dos permisos distintos
 * pueden generar el mismo nombre de relación: `can_x` sale del permiso
 * `can_x` y también del permiso `x`. El generador de antes las colapsaba en
 * silencio y el modelo publicado anulaba un deny (el auditor lo reprodujo de
 * punta a punta con `allowed: true`). Se detecta con un `Map` nombre→origen
 * y se LANZA: nunca se escribe un modelo ambiguo.
 *
 * Es un espacio de nombres plano a propósito (aunque las relaciones vivan en
 * tipos distintos): las familias tienen prefijos disjuntos, así que dos
 * permisos legales jamás chocan aquí, y lo que sí choca es exactamente lo que
 * `RESERVED_SLUGS`/`RESERVED_SLUG_PREFIXES` prohíben en el núcleo.
 */
export function factsRelationMap(permissions: readonly string[]): FactsRelations[] {
  const origin = new Map<string, string>(OWN_RELATIONS)
  const out: FactsRelations[] = []
  for (const permission of permissions) {
    const relations = factsRelationsOf(permission)
    for (const name of [relations.base, relations.can, relations.denied, relations.permits]) {
      // Cota de nombre de relación (A4): se nombra el permiso y el prefijo
      // que lo desborda, que es lo que el operador tiene que acortar.
      if (name.length > FGA_MAX_RELATION_NAME) {
        const prefix = name.slice(0, name.length - relations.base.length)
        throw new InvalidSlugError(
          `El permiso '${permission}' no es publicable en el modelo facts: su relación ` +
            `'${name}' tiene ${name.length} caracteres y FGA admite ${FGA_MAX_RELATION_NAME} ` +
            `(el prefijo '${prefix || '(ninguno)'}' añade ${name.length - relations.base.length}). Usa un slug más corto.`
        )
      }
      const other = origin.get(name)
      if (other !== undefined) {
        throw new InvalidSlugError(
          `Colisión de relaciones en el modelo facts: '${name}' la generan ${other} y el permiso '${permission}'. ` +
            `Las cuatro familias del modelo (<P>, can_<P>, denied_<P>, permits_<P>) comparten espacio de nombres: ` +
            `renombra uno de los dos permisos.`
        )
      }
      origin.set(name, `el permiso '${permission}'`)
    }
    out.push(relations)
  }
  return out
}

/* ── El modelo (c2) ─────────────────────────────────────────────────────── */

const ttu = (tupleset: string, relation: string) => ({
  tupleToUserset: { tupleset: { relation: tupleset }, computedUserset: { relation } },
})
const computed = (relation: string) => ({ computedUserset: { relation } })
const NO_DIRECT = { directly_related_user_types: [] as unknown[] }

/**
 * El authorization model del modo `facts` en el JSON del API de FGA. El mismo
 * `holderTypes` y el mismo conjunto de permisos deben usarse al construir el
 * driver: si difieren, los checks no encuentran las tuplas y `permits_<P>` de
 * un permiso que el modelo no declara es un 400 del servidor.
 *
 * `permissions` son los slugs del CATÁLOGO (`authz_permissions`), que sigue
 * siendo propiedad local: esto es una proyección derivada y reconstruible, no
 * una fuente de verdad (regla del catálogo reescrita, cruce 7 del panel).
 */
export function openFgaFactsModel(holderTypeMap: HolderTypeMap, permissions: readonly string[]): any {
  assertHolderTypes(holderTypeMap)
  const relations = factsRelationMap(permissions)
  const holderTypes = Object.values(holderTypeMap)
  const direct = holderTypes.map((type) => ({ type }))
  const wildcards = holderTypes.map((type) => ({ type, wildcard: {} }))
  const directWithExpiry = [
    ...direct,
    ...holderTypes.map((type) => ({ type, condition: 'not_expired' })),
  ]

  // type role — el catálogo por tuplas: `role:<uuid>#permits_<P>@<holder>:*`.
  // Un vínculo rol→permiso es UNA tupla global, no una por scope (c2).
  const roleRelations: Record<string, unknown> = {}
  const roleMetadata: Record<string, unknown> = {}
  for (const r of relations) {
    roleRelations[r.permits] = { this: {} }
    roleMetadata[r.permits] = { directly_related_user_types: wildcards }
  }

  // type role_binding — la asignación. `<P>` es la INTERSECCIÓN de "estás
  // asignado aquí" con "tu rol vincula ese permiso": el catálogo se edita en
  // runtime (tuplas) sin tocar los bindings.
  const bindingRelations: Record<string, unknown> = { role: { this: {} }, assignee: { this: {} } }
  const bindingMetadata: Record<string, unknown> = {
    role: { directly_related_user_types: [{ type: 'role' }] },
    assignee: { directly_related_user_types: directWithExpiry },
  }
  for (const r of relations) {
    bindingRelations[r.base] = {
      intersection: { child: [computed('assignee'), ttu('role', r.permits)] },
    }
    bindingMetadata[r.base] = NO_DIRECT
  }

  // type scope — el árbol. `<P>` hereda hacia ABAJO por `parent` (invariante
  // 1), `denied_<P>` también, y `can_<P>` es la resta (invariante 2: el deny
  // explícito gana). `ancestor` da `isWithin`/`descendantsOf` sin una sola
  // tupla extra.
  const scopeRelations: Record<string, unknown> = { parent: { this: {} }, binding: { this: {} } }
  const scopeMetadata: Record<string, unknown> = {
    parent: { directly_related_user_types: [{ type: 'scope' }] },
    binding: { directly_related_user_types: [{ type: 'role_binding' }] },
  }
  for (const r of relations) {
    scopeRelations[r.base] = { union: { child: [ttu('binding', r.base), ttu('parent', r.base)] } }
    scopeRelations[r.denied] = { union: { child: [{ this: {} }, ttu('parent', r.denied)] } }
    scopeRelations[r.can] = { difference: { base: computed(r.base), subtract: computed(r.denied) } }
    scopeMetadata[r.base] = NO_DIRECT
    scopeMetadata[r.denied] = { directly_related_user_types: direct }
    scopeMetadata[r.can] = NO_DIRECT
  }
  scopeRelations.ancestor = { union: { child: [computed('parent'), ttu('parent', 'ancestor')] } }
  scopeMetadata.ancestor = NO_DIRECT

  return {
    schema_version: '1.1',
    type_definitions: [
      ...holderTypes.map((type) => ({ type, relations: {}, metadata: null })),
      { type: 'role', relations: roleRelations, metadata: { relations: roleMetadata } },
      { type: 'role_binding', relations: bindingRelations, metadata: { relations: bindingMetadata } },
      { type: 'scope', relations: scopeRelations, metadata: { relations: scopeMetadata } },
    ],
    conditions: {
      not_expired: {
        name: 'not_expired',
        expression: 'current_time < valid_until',
        parameters: {
          current_time: { type_name: 'TYPE_NAME_TIMESTAMP' },
          valid_until: { type_name: 'TYPE_NAME_TIMESTAMP' },
        },
      },
    },
  }
}

/* ── Cuánto ocupa el modelo PARA EL SERVIDOR ────────────────────────────── */

/**
 * OpenFGA no mide el JSON: mide `proto.Size(AuthorizationModel)` y rechaza
 * por encima de `OPENFGA_MAX_AUTHORIZATION_MODEL_SIZE_IN_BYTES`. Y el JSON no
 * sirve de aproximación: medido contra v1.19, la razón proto/JSON va de 0,33
 * (slugs cortos) a 0,57 (slugs de 40), así que un techo sobre el JSON o deja
 * pasar lo que el servidor rechaza o rechaza catálogos legales por el doble
 * de margen. Se calcula el tamaño protobuf EXACTO, que para este modelo es
 * aritmética de longitudes, y un caso de la suite lo contrasta con el número
 * que el propio servidor reporta al rechazar (delta 0 en cuatro formas de
 * catálogo distintas).
 *
 * Reglas de proto3 que se aplican aquí: campo length-delimited = tag (1 byte,
 * todos los campos del esquema son 1..15) + varint de la longitud + payload;
 * un `string` vacío y un enum 0 no se serializan; un `map<K,V>` es una
 * entrada por par con `key` en el campo 1 y `value` en el 2; un mensaje vacío
 * (`this`, `wildcard`) ocupa tag + longitud 0.
 */
const varintSize = (value: number): number =>
  value < 128 ? 1 : value < 16_384 ? 2 : value < 2_097_152 ? 3 : 4

/** Un campo length-delimited de `bytes` bytes de payload. */
const fieldSize = (bytes: number): number => 1 + varintSize(bytes) + bytes

/** Un `string` de proto3: el vacío no se serializa. */
const stringSize = (value: string): number => {
  const bytes = Buffer.byteLength(value, 'utf8')
  return bytes === 0 ? 0 : fieldSize(bytes)
}

/** Una entrada de `map<string, M>`: mensaje `{ key = 1, value = 2 }`. */
const mapEntrySize = (key: string, value: number): number =>
  fieldSize(stringSize(key) + (value === 0 ? 2 : fieldSize(value)))

/** `ObjectRelation { object = 1, relation = 2 }`. */
const objectRelationSize = (relation: { object?: string; relation?: string }): number =>
  stringSize(relation.object ?? '') + stringSize(relation.relation ?? '')

/** `Userset`: un `oneof` de seis, cada rama un campo length-delimited. */
function usersetSize(userset: any): number {
  if (!userset) return 0
  if (userset.this) return 2
  if (userset.computedUserset) return fieldSize(objectRelationSize(userset.computedUserset))
  if (userset.tupleToUserset) {
    const { tupleset, computedUserset } = userset.tupleToUserset
    return fieldSize(fieldSize(objectRelationSize(tupleset)) + fieldSize(objectRelationSize(computedUserset)))
  }
  const children = userset.union ?? userset.intersection
  if (children) {
    return fieldSize(children.child.reduce((total: number, child: any) => total + fieldSize(usersetSize(child)), 0))
  }
  if (userset.difference) {
    return fieldSize(fieldSize(usersetSize(userset.difference.base)) + fieldSize(usersetSize(userset.difference.subtract)))
  }
  return 0
}

/** `RelationReference { type = 1, relation = 2 | wildcard = 3, condition = 4 }`. */
function relationReferenceSize(reference: any): number {
  let bytes = stringSize(reference.type)
  if (reference.relation) bytes += stringSize(reference.relation)
  if (reference.wildcard) bytes += 2
  if (reference.condition) bytes += stringSize(reference.condition)
  return bytes
}

/**
 * Los bytes que el servidor contará para este modelo. Incluye el id (un ULID
 * de 26 caracteres) porque el servidor lo asigna ANTES de medir: sin él la
 * cuenta se queda 28 bytes corta.
 */
export function factsModelBytes(model: any): number {
  let total = fieldSize(26) + stringSize(model.schema_version)
  for (const definition of model.type_definitions) {
    let bytes = stringSize(definition.type)
    for (const [name, userset] of Object.entries(definition.relations ?? {})) {
      bytes += mapEntrySize(name, usersetSize(userset))
    }
    if (definition.metadata) {
      let metadata = 0
      for (const [name, relation] of Object.entries<any>(definition.metadata.relations ?? {})) {
        const types = (relation.directly_related_user_types ?? []).reduce(
          (sum: number, reference: any) => sum + fieldSize(relationReferenceSize(reference)),
          0
        )
        metadata += mapEntrySize(name, types)
      }
      bytes += fieldSize(metadata)
    }
    total += fieldSize(bytes)
  }
  for (const [name, condition] of Object.entries<any>(model.conditions ?? {})) {
    let bytes = stringSize(condition.name) + stringSize(condition.expression)
    for (const parameter of Object.keys(condition.parameters ?? {})) {
      // `ConditionParamTypeRef { type_name = 1 }` (un enum ≠ 0: 2 bytes).
      bytes += mapEntrySize(parameter, 2)
    }
    total += mapEntrySize(name, bytes)
  }
  return total
}

/**
 * ¿Este catálogo se puede PUBLICAR como modelo `facts`? Se responde ANTES de
 * escribir nada (`syncAuthzCatalog`), no en runtime: un catálogo que rebasa
 * el techo del servidor entra en la base y deja el store sin poder
 * regenerarse, que es la avería silenciosa.
 *
 * Pasado el 80 % del techo se AVISA por el canal de log del driver: quien
 * declara permisos a ese ritmo tiene que enterarse antes de chocar, no el día
 * del deploy que no arranca.
 */
export function assertFactsModelPublishable(
  holderTypeMap: HolderTypeMap,
  permissions: readonly string[],
  warn?: (message: string) => void
): { bytes: number; permissions: number } {
  const model = openFgaFactsModel(holderTypeMap, permissions)
  const bytes = factsModelBytes(model)
  if (bytes > FACTS_MODEL_MAX_BYTES) {
    throw new ModelTooLargeError(
      `El catálogo no cabe en un authorization model de OpenFGA: ${permissions.length} permisos ` +
        `producen ${bytes} bytes y el techo son ${FACTS_MODEL_MAX_BYTES}. ` +
        `Reduce permisos (o sube OPENFGA_MAX_AUTHORIZATION_MODEL_SIZE_IN_BYTES en el servidor, que es del pliego de infraestructura).`
    )
  }
  if (warn && bytes >= FACTS_MODEL_MAX_BYTES * FACTS_MODEL_WARN_RATIO) {
    warn(
      `authz(openfga): el modelo facts va por ${bytes} de ${FACTS_MODEL_MAX_BYTES} bytes ` +
        `(${Math.round((bytes / FACTS_MODEL_MAX_BYTES) * 100)} %, ${permissions.length} permisos). ` +
        `Pasado el techo el catálogo deja de ser publicable.`
    )
  }
  return { bytes, permissions: permissions.length }
}

/** Cota de id de objeto (A4): lo que el store no podría leer de vuelta no se escribe. */
export function assertFgaObjectId(kind: string, id: string): void {
  if (id.length > FGA_MAX_OBJECT_ID) {
    throw new InvalidIdentityError(
      `Id de objeto FGA inválido (${kind}): '${id.slice(0, 60)}…' tiene ${id.length} caracteres ` +
        `y FGA admite ${FGA_MAX_OBJECT_ID}.`
    )
  }
}

/* ── La proyección del catálogo (A5) ────────────────────────────────────── */

/** Una tupla de la proyección: `role:<uuid>#permits_<P>@<holder>:*`. */
export interface FactsCatalogTuple {
  user: string
  relation: string
  object: string
}

/**
 * Las tuplas que materializan los vínculos rol→permiso del catálogo. Una por
 * (rol, permiso, holder): el comodín de USUARIO es lo que hace (c2) barato
 * —quitar un permiso de un rol son `holders` deletes en un solo `Write`, no
 * una escritura por scope—.
 *
 * NO es catálogo: es una proyección derivada, reconstruible desde `authz_*`,
 * que ningún camino de lectura del driver consulta para responder qué
 * permisos tiene un rol (cruce 7 del panel; A6).
 */
export function factsCatalogTuples(
  roles: readonly CatalogProjectionRole[],
  holderTypeMap: HolderTypeMap
): FactsCatalogTuple[] {
  assertHolderTypes(holderTypeMap)
  const holderTypes = Object.values(holderTypeMap)
  const tuples: FactsCatalogTuple[] = []
  for (const role of roles) {
    const object = `${FACTS_ROLE_TYPE}:${role.uuid}`
    assertFgaObjectId(FACTS_ROLE_TYPE, object)
    for (const permission of role.permissions) {
      const { permits } = factsRelationsOf(permission)
      for (const holderType of holderTypes) {
        tuples.push({ user: `${holderType}:*`, relation: permits, object })
      }
    }
  }
  return tuples
}

/** Clave textual de una tupla de la proyección, para comparar conjuntos. */
export function factsTupleId(tuple: FactsCatalogTuple): string {
  return `${tuple.user}#${tuple.relation}@${tuple.object}`
}
