import {
  InvalidIdentityError,
  InvalidSlugError,
  ModelTooLargeError,
  AuthorizationConfigError,
  RelationConfigError,
  markDeploymentFailure,
} from '../errors.js'
import { slugAsRelation, RESERVED_SLUG_PREFIXES, RESERVED_FACTS_TYPES } from '../identity.js'
import { APP_SCOPE_TYPE } from '../types.js'
import { FGA_EXPIRY_CONDITION } from '../expiry.js'
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
 * analista, 53/53 invariantes medidos contra OpenFGA v1.19), con la relación
 * `rooted` que le añadió el diseño **(c2r)** (`fase-3b-diseno-r1.md`, medido
 * contra el `:8101`). No se rediseña:
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
 *   define rooted: [user:*, admin:*, integration:*] or rooted from parent
 *   define can_<P>: (<P> but not denied_<P>) and rooted
 *   define ancestor: parent or ancestor from parent  # isWithin/descendantsOf nativos, 0 tuplas
 * ```
 *
 * Por qué (c2) y no (c1) —catálogo por scope— (cruce 1): un cambio de
 * catálogo son 3 deletes en UN `Write` atómico en vez de O(scopes) requests
 * no atómicos, `attached` escribe 1 tupla en vez de 1+K, y el `verify` del
 * catálogo es O(roles×permisos×holders) en vez de O(scopes×…). Se paga con
 * ~0,8 ms por `authorize` y con un techo de permisos más bajo (**≈450 con
 * slugs realistas**; ver `FACTS_MODEL_MAX_BYTES` para de qué depende esa
 * cifra: no es una propiedad del modelo).
 *
 * **Por qué `rooted`** (3b-2i, cierre del 🔴 1 del auditor R2): sin ella, un
 * scope cuya cadena hasta `app` se rompe —`scopes.detached` de un nodo
 * INTERMEDIO, o un nodo que el consumidor nunca notificó— seguía concediendo
 * lo que tuviera colgado y dejaba de heredar los denies de arriba. O sea que
 * `detached` de un nodo propio funcionaba como un `removeDeny` masivo del
 * subárbol, con las barreras de `within` intactas (medido: `removeDeny` 422,
 * `grant` 422, `detached` OK y después `authorize` = `true` con el deny
 * todavía escrito). `rooted` es la ALCANZABILIDAD DE LA RAÍZ materializada
 * por el propio modelo: solo `scope:app` la tiene directa (el *marcador de
 * raíz*, `factsRootTuples`) y todo lo demás la hereda por `parent`, igual que
 * `denied_<P>`. Al volver `can_<P>` una intersección con ella, un subárbol
 * desgajado deja de conceder **sin enumerar nada y sin una sola tupla por
 * scope**. Medido: `authorize` sigue siendo UN solo `Check`, el techo de
 * profundidad no se mueve (22) y el de tamaño baja un ~4 % (con el catálogo
 * de referencia —3 holder types `user`/`admin`/`integration` y slugs
 * `p0`…`pN`— de 721 a 691 permisos).
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
 * Techo del authorization model (default de
 * `OPENFGA_MAX_AUTHORIZATION_MODEL_SIZE_IN_BYTES`). **El techo son BYTES; el
 * número de permisos que caben NO es una propiedad del modelo** (3b-4 · C3):
 * depende de cuántos holder types declaras, de cuánto miden sus NOMBRES en el
 * modelo y de cuánto miden los slugs de tus permisos. Medido con
 * `factsModelBytes` —que cuenta los mismos bytes que el servidor, contrastado
 * contra un `:8101` real— y fijado por un caso (`3b-4 · C3`):
 *
 * | catálogo | permisos que caben |
 * |---|---|
 * | 1 holder type, slugs `p0`…`pN` | **800** |
 * | 3 holder types (`user`/`admin`/`integration`), slugs `p0`…`pN` | **691** |
 * | 1 holder type, slugs `docs:readN` | **576** |
 * | 3 holder types, slugs `recursoN:accion` (REALISTAS) | **447** |
 * | 3 holder types, slugs de 40 caracteres | **272** |
 *
 * O sea: el «≈691» que se publicó es la cifra de un catálogo cuyos permisos se
 * llaman `p0`, `p1`, `p2`…; **con nombres de permiso normales el techo está en
 * ~450**. Y los mismos tres holder types con nombres más cortos (`bot` en vez
 * de `integration`) dan 721: no basta con decir «tres holder types».
 *
 * Se valida en `syncAuthzCatalog` ANTES de escribir el catálogo: un catálogo
 * que no se puede publicar no se escribe a medias en un entorno y entero en
 * otro. El gate por bytes es exacto y salta antes de escribir, así que
 * equivocarse con la cifra derivada no concede nada: solo sorprende.
 */
export const FACTS_MODEL_MAX_BYTES = 262_144

/**
 * **Profundidad máxima de cadena que el modelo (c2) resuelve** (3b-2e · E5),
 * MEDIDA contra OpenFGA v1.19 con el `--resolve-node-limit` por defecto (25).
 * Con el grant en la RAÍZ y el `Check` a profundidad creciente, 25
 * repeticiones por punto:
 *
 * | saltos `parent` | `can_<P>` |
 * |---|---|
 * | 21 | 25/25 resuelve |
 * | **22** | **25/25 resuelve** ← la cota que se declara |
 * | 23 | resuelve casi siempre y **falla entre un 4 % y un 26 %** de las veces según la carga — el borde NO es nítido |
 * | 24 | 0/25: siempre falla |
 *
 * (Remedido en 3b-4 · C4 sobre 50 hojas a la misma profundidad: a 22, 200 de
 * 200 resuelven en cuatro lotes; a 23, entre 6 y 13 errores por lote de 50, y
 * 15 de 100 en checks sueltos; a 24, 100 de 100 fallan.)
 *
 * Las otras dos ramas del modelo llegan más lejos (`denied_<P>` hasta 25,
 * `ancestor` hasta 26): manda la más baja, y es `can_<P>` porque es una resta
 * (`difference`) sobre una unión con DOS TTU (`binding` y `parent`), o sea dos
 * reescrituras más que las otras.
 *
 * **Lo importante del hallazgo no es el número, es que el borde es
 * PROBABILÍSTICO**: a 23 saltos la misma pregunta responde casi siempre y
 * falla de vez en cuando (el presupuesto de nodos se consume de forma no
 * determinista al resolver la unión). Por eso se declara **22**, que es la
 * profundidad que resuelve SIEMPRE, y no el primer valor que falló. Un caso
 * de la suite apoyado en 23 habría sido flaky en el artefacto publicado —la
 * misma lección que 3G · Y1—, y de hecho lo fue una vez antes de medirlo.
 *
 * **Y por eso la constante se clava con REPETICIONES, no con una tirada**
 * (3b-4 · C4): el par de casos original —positivo en la cota, negativo en la
 * cota + 2— sujetaba el intervalo [22, 23] y no el 22 (con la constante a 23
 * la suite seguía verde 3 corridas de 3, tester Fase 3b · M12b). El caso que
 * lo cierra hace **500 resoluciones por lado** (10 lotes de 50 con
 * `authorizeMany`): en la cota tienen que resolver las 500, y un salto más
 * tiene que fallar al menos una vez. Con la tasa de fallo más baja jamás
 * medida (4 %) un verde falso es 0,96^500 ≈ 1e-9.
 *
 * Los «~23» que citaba el panel (riesgo S9) eran de un modelo MÁS SIMPLE y
 * estaban sin medir sobre (c2).
 *
 * Pasado el techo el servidor responde 400 («resolution required too many
 * rewrite rules») y el paquete lo propaga como 503, **nunca como un `false`**
 * (invariante 5): es fail-closed, pero es un DoS al alcance de quien pueda
 * crear sub-scopes anidados, y `database` no tiene ese techo — el mismo árbol
 * es legal en un driver y una caída en el otro. Sube
 * `OPENFGA_RESOLVE_NODE_LIMIT` en el servidor si tu árbol es más profundo.
 */
export const FACTS_MAX_RESOLVE_DEPTH = 22

/** Tope de checks por `batchCheck` en OpenFGA (el driver trocea en lotes de este tamaño). */
export const FGA_MAX_BATCH_CHECK = 50

/** Fracción del techo a partir de la cual se avisa (cruce 9: "aviso al 80 %"). */
export const FACTS_MODEL_WARN_RATIO = 0.8

/** El tipo FGA cuyo id es el uuid del rol del catálogo. */
export const FACTS_ROLE_TYPE = 'role'

/** Prefijo de la familia que materializa el catálogo (`role:<uuid>#permits_<P>`). */
export const FACTS_PERMITS_PREFIX = 'permits_'

/**
 * **La relación de (c2r)**: «desde este scope se llega a la raíz `app`»
 * (3b-2i). Es una relación PROPIA del modelo, como `parent` o `ancestor`, y
 * la única que se escribe una vez por STORE en vez de por hecho: el marcador
 * de raíz (`factsRootTuples`).
 */
export const FACTS_ROOTED_RELATION = 'rooted'

/**
 * La condición de caducidad del modelo (`current_time < valid_until`): la de
 * `role_binding#assignee` desde el modo `facts`, y desde R-15 también la de
 * cada sujeto de una relación ReBAC (`document#viewer`, `group#member`…).
 */
export const FACTS_EXPIRY_CONDITION = FGA_EXPIRY_CONDITION

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
  ['rooted', "relación propia del modelo (scope#rooted)"],
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
export function openFgaFactsModel(
  holderTypeMap: HolderTypeMap,
  permissions: readonly string[],
  relationsConfig?: FactsRelationsConfig
): any {
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
    // (c2r): lo concedido, menos lo denegado, **y solo si el scope llega a la
    // raíz**. La intersección va aquí y no dentro de `<P>` a propósito:
    // `can_<P>` es exactamente lo que responde `authorize` y nada más, así que
    // «lo que decide» y «lo que se hereda» siguen separados.
    scopeRelations[r.can] = {
      intersection: {
        child: [
          { difference: { base: computed(r.base), subtract: computed(r.denied) } },
          computed(FACTS_ROOTED_RELATION),
        ],
      },
    }
    scopeMetadata[r.base] = NO_DIRECT
    scopeMetadata[r.denied] = { directly_related_user_types: direct }
    scopeMetadata[r.can] = NO_DIRECT
  }
  scopeRelations.ancestor = { union: { child: [computed('parent'), ttu('parent', 'ancestor')] } }
  scopeMetadata.ancestor = NO_DIRECT
  // El marcador de raíz es lo ÚNICO directo de `rooted`: `scope:app` lo lleva
  // (una tupla por holder type en todo el store) y el resto del árbol la
  // hereda por `parent`, exactamente igual que `denied_<P>`. Es una rama
  // PARALELA al `difference`, y más barata que él, por eso no baja el techo
  // de profundidad (medido: 22 sólido en las cinco variantes del diseño).
  scopeRelations[FACTS_ROOTED_RELATION] = {
    union: { child: [{ this: {} }, ttu('parent', FACTS_ROOTED_RELATION)] },
  }
  scopeMetadata[FACTS_ROOTED_RELATION] = { directly_related_user_types: wildcards }

  const typeDefinitions: any[] = [
    ...holderTypes.map((type) => ({ type, relations: {}, metadata: null })),
    { type: 'role', relations: roleRelations, metadata: { relations: roleMetadata } },
    { type: 'role_binding', relations: bindingRelations, metadata: { relations: bindingMetadata } },
    { type: 'scope', relations: scopeRelations, metadata: { relations: scopeMetadata } },
  ]

  // Fase 4-1 · el modelo FUSIONADO: las relaciones ReBAC (`group` + los tipos
  // de objeto declarados) van al MISMO modelo y el MISMO store que `facts`. El
  // generador valida ANTES de emitir que ningún tipo ni relación de relaciones
  // pisa un tipo o una familia reservados de `facts` (⚪4) ni un permiso del
  // catálogo (F-04): en el store compartido los ids viven en el mismo espacio.
  if (relationsConfig) {
    typeDefinitions.push(...factsRelationTypeDefinitions(relations, relationsConfig, holderTypes))
  }

  return {
    schema_version: '1.1',
    type_definitions: typeDefinitions,
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
  warn?: (message: string) => void,
  relationsConfig?: FactsRelationsConfig
): { bytes: number; permissions: number } {
  // El gate mide el modelo FUSIONADO (Fase 4-1): si `relationsConfig` llega,
  // los tipos de relaciones cuentan para el techo. Sin eso, un
  // `defineRelationsConfig` empujaría el modelo por encima de los 262.144 B en
  // SILENCIO —medía solo `facts`— y dejaría el store sin poder regenerarse
  // (el hueco que señaló el auditor).
  const model = openFgaFactsModel(holderTypeMap, permissions, relationsConfig)
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

/* ── El ÁRBOL como hechos (3b-2b) ───────────────────────────────────────── */

/** El tipo FGA cuyo id es la `scopeKey` del paquete (`app` o `<tipo>|<uuid>`). */
export const FACTS_SCOPE_TYPE = 'scope'

/** La arista del árbol: `scope:<hijo>#parent@scope:<padre>` (una por nodo). */
export const FACTS_PARENT_RELATION = 'parent'

/** Una tupla del modo `facts` (misma forma que la del SDK, sin depender de él). */
export interface FactsTuple {
  user: string
  relation: string
  object: string
}

/**
 * El objeto FGA de un scope. La `scopeKey` es la MISMA codificación que ya
 * usan los ids de binding (`identity.ts`), así que el árbol y los hechos
 * hablan del mismo nodo con la misma cadena; el scope tiene que venir ya
 * CANÓNICO (invariante 17: `chain[0]`), o se abriría una segunda rama para
 * el alias del uuid.
 */
export function factsScopeObject(key: string): string {
  const object = `${FACTS_SCOPE_TYPE}:${key}`
  assertFgaObjectId(FACTS_SCOPE_TYPE, object)
  return object
}

/**
 * La arista `hijo → padre` del árbol. Una sola tupla por nodo (c2): mover un
 * subárbol es reescribir ESA tupla, no recorrer nada — por eso el `moved`
 * del cruce 8 cabe en un `Write` atómico.
 */
export function factsParentTuple(childKey: string, parentKey: string): FactsTuple {
  return {
    user: factsScopeObject(parentKey),
    relation: FACTS_PARENT_RELATION,
    object: factsScopeObject(childKey),
  }
}

/**
 * **El marcador de raíz** (3b-2i): `scope:app#rooted@<holder>:*`, una tupla
 * por holder type en TODO el store — cero por scope.
 *
 * Es lo que hace verdadera la premisa de `rooted`: solo la raíz la tiene
 * directa. `attached`/`moved`/`detached` no escriben ni una tupla más por su
 * culpa (la outbox y el relay no llevan entradas nuevas), y a cambio lo
 * escribe quien toca el CATÁLOGO —`projectCatalog`, en cada
 * `syncAuthzCatalog` con proyección, de forma idempotente— porque ése es el
 * momento en el que un holderType nuevo del config aparece.
 *
 * ⚠️ **Modo de fallo que hay que conocer: sin marcador, todo el store
 * DENIEGA** (medido: `can_<P>` es `false` en `app`, en la org y en la unit).
 * Es fail-closed —no es una fuga— y ruidoso a la primera pregunta, pero es
 * una caída total silenciosa desde el punto de vista del log. Por eso el
 * marcador se repone en cada sync y `authz:reconcile` (3b-3) tiene que
 * reportarlo como deriva cuando falte.
 */
export function factsRootTuples(holderTypeMap: HolderTypeMap): FactsTuple[] {
  assertHolderTypes(holderTypeMap)
  return Object.values(holderTypeMap).map((type) => ({
    user: `${type}:*`,
    relation: FACTS_ROOTED_RELATION,
    object: factsScopeObject(APP_SCOPE_TYPE),
  }))
}

/* ── Los HECHOS del modo `facts` (3b-2c) ────────────────────────────────── */

/** El tipo FGA de una asignación: `role_binding:<scopeKey>|<roleUuid>`. */
export const FACTS_BINDING_TYPE = 'role_binding'

/** `scope:<key>#binding@role_binding:…` — qué asignaciones cuelgan del scope. */
export const FACTS_BINDING_RELATION = 'binding'

/** `role_binding:…#role@role:<roleUuid>` — qué rol vincula la asignación. */
export const FACTS_ROLE_RELATION = 'role'

/** `role_binding:…#assignee@<holder>` — quién está asignado (con la caducidad). */
export const FACTS_ASSIGNEE_RELATION = 'assignee'

/**
 * El objeto de una asignación. Mismo id que en el modo `resolver`
 * (`<scopeKey>|<roleUuid>`, 3A · A1: uuid del catálogo, nunca el slug), y por
 * eso el cambio de modelo no renombra un solo binding: lo que (c2) añade son
 * las DOS aristas de abajo, no una identidad nueva.
 */
export function factsBindingObject(scopeKeyValue: string, roleUuid: string): string {
  const object = `${FACTS_BINDING_TYPE}:${scopeKeyValue}|${roleUuid}`
  assertFgaObjectId(FACTS_BINDING_TYPE, object)
  return object
}

/**
 * Las dos aristas que hacen ALCANZABLE una asignación en (c2): el binding
 * cuelga del scope (`scope#binding`) y apunta a su rol (`role_binding#role`).
 * Sin ellas el `assignee` es un hecho huérfano que `can_<P>` no ve — es la
 * diferencia entre el modo `resolver` (donde la cadena la expande el paquete
 * y basta con el `assignee`) y el modo `facts`.
 *
 * Son ESTRUCTURA, no concesión: no llevan caducidad y no dicen quién está
 * asignado. Por eso `revoke` no las borra (otro holder puede seguir usando el
 * mismo binding) y re-escribirlas es idempotente.
 */
export function factsBindingTuples(scopeKeyValue: string, roleUuid: string): FactsTuple[] {
  const object = factsBindingObject(scopeKeyValue, roleUuid)
  const role = `${FACTS_ROLE_TYPE}:${roleUuid}`
  assertFgaObjectId(FACTS_ROLE_TYPE, role)
  return [
    { user: role, relation: FACTS_ROLE_RELATION, object },
    factsScopeBindingTuple(scopeKeyValue, roleUuid),
  ]
}

/**
 * La arista `scope:<key>#binding@role_binding:<key>|<rol>` sola, que es la
 * que hace ALCANZABLE la asignación desde el scope.
 *
 * **Qué significa** (3b-2g · R1, decisión del dueño del 2026-08-30 (2)): desde
 * el barrido, «**el rol es visible aquí**» — no «esta asignación existe». El
 * hecho de la asignación es el `assignee`, que el barrido no toca; esta arista
 * la escribe y la borra el paquete cada vez que la REGLA DE VISIBILIDAD cambia
 * de respuesta para ese `(rol, scope)`: el árbol se mueve y el owner deja de
 * estar en la cadena (`scopes.moved`, 3b-2e · E1) o el catálogo cambia el
 * NIVEL declarado del rol (`projectCatalogRole`, 3b-2g · R1). Es lo que en
 * `database` se evalúa en cada pregunta con `declaredRoleAt`, y aquí hay que
 * materializar porque el modelo (c2) no lleva ni el owner ni el nivel.
 */
export function factsScopeBindingTuple(scopeKeyValue: string, roleUuid: string): FactsTuple {
  return {
    user: factsBindingObject(scopeKeyValue, roleUuid),
    relation: FACTS_BINDING_RELATION,
    object: factsScopeObject(scopeKeyValue),
  }
}

/**
 * El deny explícito de (c2): `scope:<key>#denied_<P>@<holder>`. Ya no existe
 * el tipo `deny_binding` — el deny es una relación DEL SCOPE, que es lo que
 * permite que `denied_<P>` se herede hacia abajo por `parent` dentro del
 * propio modelo y que `can_<P>` sea la resta (invariante 2) en un solo Check.
 */
export function factsDenyTuple(scopeKeyValue: string, permission: string, user: string): FactsTuple {
  return {
    user,
    relation: factsRelationsOf(permission).denied,
    object: factsScopeObject(scopeKeyValue),
  }
}

/** Prefijo de la familia del deny (`denied_<P>`), para leer denies por relación. */
export const FACTS_DENIED_PREFIX = 'denied_'

/* ── Relaciones ReBAC FUSIONADAS en el modelo (Fase 4-1) ─────────────────── */

/**
 * El tipo `group` de las relaciones ReBAC: el portador de los usersets
 * (`group:eng#member`) que hace que un `viewer` valga para todos los miembros
 * de un grupo. Lo emite SIEMPRE el generador de relaciones (no lo declara el
 * consumidor), y por eso es un tipo RESERVADO igual que los de `facts`.
 */
export const FACTS_GROUP_TYPE = 'group'

/** La relación de pertenencia del grupo: `group:<id>#member@<holder>` y `@group:<otro>#member`. */
export const FACTS_GROUP_MEMBER_RELATION = 'member'

/**
 * Los tipos reservados del modelo compartido (⚪4). La fuente única está en
 * `src/identity.ts` (la gramática compartida), porque también la consume
 * `defineRelationsConfig` en `src/relations/`, que la frontera de pureza
 * mantiene disjunto de `drivers/`. Se re-exporta aquí para no romper el
 * subpath `/openfga` (`src/openfga.ts` la publica desde este módulo).
 */
export { RESERVED_FACTS_TYPES } from '../identity.js'

/** Una relación de un tipo de objeto de relaciones (`document#viewer`). */
export interface RelationObjectRelation {
  /** El nombre de la relación (`owner`, `editor`, `viewer`). */
  name: string
  /**
   * Otras relaciones del MISMO tipo que ésta INCLUYE (`viewer or editor`): un
   * `relate(u, editor, doc)` concede también `viewer`. Un nivel, SIN `from` en
   * v1 (la herencia cross-objeto `viewer from parent` metería un TTU entre
   * tipos y habría que re-medir profundidad — diferido a 2.6+).
   */
  includes?: readonly string[]
}

/** Un tipo de objeto de relaciones (`document`, `folder`, `space`…). */
export interface RelationObjectType {
  /** El tipo FGA del objeto. */
  type: string
  /** Sus relaciones, en orden de declaración. */
  relations: readonly RelationObjectRelation[]
  /**
   * Opt-in del deny (plan 2.5 · lote D, D10): con `'read'` o `'write'` el generador emite, por cada relación `X`,
   * `X = <la de hoy> but not denied_X` y `denied_X = this ∨ denied_P` (por cada `P` que incluye a `X`). Ausente ⇒
   * el literal de 2.4.0-alpha.10, byte a byte (D-29).
   */
  deny?: 'read' | 'write'
}

/**
 * La config de relaciones que el generador FUSIONA en el modelo `facts`
 * (Fase 4-1). Es la forma MÍNIMA que consume el generador; el puerto
 * `RelationsDriver` y `defineRelationsConfig` completos son 4-2.
 */
export interface FactsRelationsConfig {
  /** Los tipos de objeto declarados por el consumidor. */
  objectTypes: readonly RelationObjectType[]
}

/**
 * **⚪4 + F-04, a nivel de MODELO.** Antes de emitir un solo `type_definition`
 * de relaciones, el generador comprueba que la config es FUSIONABLE en el
 * modelo compartido:
 *
 * - ningún `objectType` duplica un tipo reservado de `facts`/`group` ni un
 *   holder type (⚪4 · tipo), ni se repite;
 * - ningún NOMBRE de relación (deduplicado entre tipos: `document#viewer` y
 *   `folder#viewer` son la misma relación lógica y se permiten) empieza por
 *   una familia derivada (`can_`/`denied_`/`permits_`) ni coincide con una
 *   relación PROPIA del modelo (`parent`/`rooted`/`assignee`… — ⚪4 · familia)
 *   ni con un permiso del catálogo (F-04);
 * - los `includes` refieren relaciones del MISMO tipo (un nivel).
 *
 * Lanza 422 `E_AUTHZ_RELATION_CONFIG` del PAQUETE (no el 400 opaco del
 * servidor), nombrando qué choca con qué.
 */
export function assertRelationsConfigPublishable(
  permissionRelations: readonly FactsRelations[],
  config: FactsRelationsConfig,
  holderTypes: readonly string[]
): void {
  // El espacio de nombres PLANO de `facts`: relaciones propias del modelo +
  // las cuatro familias de cada permiso. Es el mismo criterio que
  // `factsRelationMap` (A2/S4): aunque las relaciones vivan en tipos distintos,
  // se tratan como un solo espacio para que el namespace de relaciones quede
  // DEMOSTRABLEMENTE disjunto del de `facts` (cierre por construcción).
  const origin = new Map<string, string>(OWN_RELATIONS)
  for (const r of permissionRelations) {
    for (const name of [r.base, r.can, r.denied, r.permits]) {
      origin.set(name, `el permiso '${r.permission}'`)
    }
  }

  const reservedTypes = new Set<string>([...RESERVED_FACTS_TYPES, ...holderTypes])
  const seenTypes = new Set<string>()
  const relationNames = new Set<string>()

  for (const objectType of config.objectTypes) {
    const type = objectType?.type
    if (typeof type !== 'string' || !FGA_TYPE_FORMAT.test(type)) {
      throw new RelationConfigError(
        `Tipo de objeto de relaciones inválido: ${JSON.stringify(type)} no es un tipo FGA válido ` +
          `(1-254 caracteres, sin ':', '#', '@' ni espacios).`
      )
    }
    if (reservedTypes.has(type)) {
      throw new RelationConfigError(
        `El tipo de objeto de relaciones '${type}' colisiona con un tipo reservado del modelo compartido ` +
          `(${[...RESERVED_FACTS_TYPES].join(', ')}${holderTypes.length ? ', y los holder types ' + holderTypes.join(', ') : ''}). ` +
          `En el store compartido un tipo de relaciones no puede duplicar uno de 'facts' (⚪4): renómbralo.`
      )
    }
    if (seenTypes.has(type)) {
      throw new RelationConfigError(`El tipo de objeto de relaciones '${type}' está declarado dos veces.`)
    }
    seenTypes.add(type)

    const own = new Set<string>()
    for (const relation of objectType.relations ?? []) {
      const name = relation?.name
      if (typeof name !== 'string' || !FGA_TYPE_FORMAT.test(name)) {
        throw new RelationConfigError(
          `Relación inválida en el tipo '${type}': ${JSON.stringify(name)} no es un nombre de relación válido.`
        )
      }
      own.add(name)
      relationNames.add(name)
    }
    // D1 (lote D): en un tipo con deny, `denied_<X>` tiene que caber en los 50 de FGA (defensa en profundidad de la
    // cota de 43 que ya aplica `defineRelationsConfig`).
    if (objectType.deny !== undefined) {
      for (const name of own) {
        if (FACTS_DENIED_PREFIX.length + name.length > FGA_MAX_RELATION_NAME) {
          throw new RelationConfigError(
            `La relación '${type}#${name}' tiene ${name.length} caracteres y el tipo declara deny: '${FACTS_DENIED_PREFIX}${name}' ` +
              `no cabe en los ${FGA_MAX_RELATION_NAME} de FGA (una relación denegable mide como mucho ${FGA_MAX_RELATION_NAME - FACTS_DENIED_PREFIX.length}).`
          )
        }
      }
    }
    // Los `includes` refieren relaciones del MISMO tipo (un nivel, sin `from`).
    for (const relation of objectType.relations ?? []) {
      for (const included of relation.includes ?? []) {
        if (!own.has(included)) {
          throw new RelationConfigError(
            `La relación '${type}#${relation.name}' incluye '${included}', que no es una relación de '${type}'. ` +
              `Los includes son de un nivel y del mismo tipo (v1 no soporta 'from').`
          )
        }
      }
    }
  }

  for (const name of relationNames) {
    if (name.length > FGA_MAX_RELATION_NAME) {
      throw new RelationConfigError(
        `La relación '${name}' tiene ${name.length} caracteres y FGA admite ${FGA_MAX_RELATION_NAME}.`
      )
    }
    const family = RESERVED_SLUG_PREFIXES.find((prefix) => name.startsWith(prefix))
    if (family) {
      throw new RelationConfigError(
        `La relación '${name}' empieza por '${family}', prefijo reservado de las relaciones derivadas del modelo ` +
          `facts (${RESERVED_SLUG_PREFIXES.join(', ')}): elegiría el nombre de un permiso proyectado (⚪4).`
      )
    }
    const clash = origin.get(name)
    if (clash !== undefined) {
      throw new RelationConfigError(
        `Colisión de nombres en el modelo compartido: la relación de objeto '${name}' ya la usa ${clash} ` +
          `en 'facts'. El espacio de relaciones de 'relations/' y el de 'facts' tienen que ser disjuntos ` +
          `(⚪4 para una relación propia del modelo, F-04 para un permiso del catálogo): renombra la relación.`
      )
    }
  }
}

/**
 * Los `type_definitions` de relaciones que el generador AÑADE al modelo
 * `facts`: el tipo `group` (usersets) + un tipo por objeto declarado. El
 * literal medido contra el `:8101` está en la §1 del plan de la Fase 4.
 *
 * `group.member` admite holders directos y `group#member` (grupos anidan un
 * nivel); cada relación de objeto admite `[holders, group#member]` directos y,
 * si declara `includes`, se une a las relaciones incluidas del mismo tipo
 * (`viewer or editor`), sin una sola tupla extra.
 *
 * **R-15 (2.4.0-alpha.2) · la caducidad de la tupla de relación**: cada
 * sujeto admitido va ADEMÁS `with not_expired` —los holders Y el userset
 * `group#member`—, la MISMA condición que `role_binding#assignee` (invariante
 * 3: la expiración es una *condition* del modelo, sin scheduler). Así
 * `relate(…, { expiresAt })` escribe la tupla con `valid_until` y el `Check`
 * (con `current_time`) la respeta; una tupla sin condición sigue siendo
 * válida (no caduca). Coste medido en el gate de bytes: la condición añade
 * `(holders + 1) × (tipo + 'not_expired')` bytes por relación declarada.
 */
export function factsRelationTypeDefinitions(
  permissionRelations: readonly FactsRelations[],
  config: FactsRelationsConfig,
  holderTypes: readonly string[]
): any[] {
  assertRelationsConfigPublishable(permissionRelations, config, holderTypes)

  const direct = holderTypes.map((type) => ({ type }))
  const groupMember = { type: FACTS_GROUP_TYPE, relation: FACTS_GROUP_MEMBER_RELATION }
  // `[user, admin, integration, group#member, user with not_expired, …,
  // group#member with not_expired]`: los holders y el userset del grupo, sin
  // condición (no caduca) y con ella (R-15).
  const holdersOrGroup = [
    ...direct,
    groupMember,
    ...holderTypes.map((type) => ({ type, condition: FACTS_EXPIRY_CONDITION })),
    { ...groupMember, condition: FACTS_EXPIRY_CONDITION },
  ]

  const definitions: any[] = [
    {
      type: FACTS_GROUP_TYPE,
      relations: { [FACTS_GROUP_MEMBER_RELATION]: { this: {} } },
      metadata: {
        relations: { [FACTS_GROUP_MEMBER_RELATION]: { directly_related_user_types: holdersOrGroup } },
      },
    },
  ]

  for (const objectType of config.objectTypes) {
    const relations = factsRelationRewrites(objectType)
    // `<rel>` y `denied_<rel>` admiten los MISMOS sujetos (holders y `group#member`, con y sin `not_expired`).
    const metadata: Record<string, unknown> = {}
    for (const name of Object.keys(relations)) metadata[name] = { directly_related_user_types: holdersOrGroup }
    definitions.push({ type: objectType.type, relations, metadata: { relations: metadata } })
  }

  return definitions
}

/**
 * **Las reglas de reescritura (`relations`) de UN tipo de objeto, tal como las genera el paquete** — la fuente ÚNICA
 * del generador (`factsRelationTypeDefinitions`) y de la guarda D-31 del driver (cierre 2 de D1, ⚪ N4: la guarda
 * compara el modelo FIJADO con ESTO, por igualdad estructural, no solo la forma). Pura y sin holders: el `metadata`
 * (qué sujetos admite cada relación) no decide qué concede.
 */
export function factsRelationRewrites(objectType: RelationObjectType): Record<string, unknown> {
  const relations: Record<string, unknown> = {}
  for (const relation of objectType.relations) {
    const includes = relation.includes ?? []
    const base = includes.length
      ? { union: { child: [{ this: {} }, ...includes.map((name) => computed(name))] } }
      : { this: {} }
    if (objectType.deny === undefined) {
      // D-29: sin opt-in, el literal de 2.4.0-alpha.10 byte a byte.
      relations[relation.name] = base
      continue
    }
    // **D5 · corte de camino en el MODELO** (lote D, medido en ronda 1 y 2 contra v1.19.0): `X = base but not
    // denied_X` y `denied_X = this ∨ denied_P` por cada `P` que INCLUYE a `X` (el cierre ASCENDENTE): un deny en
    // `editor` alcanza a `denied_owner`, así que el grant de `owner` deja de valer entero —y con él lo que deriva—.
    // `denied_X` admite los MISMOS sujetos que `X` (holders y `group#member`, con y sin `not_expired`): el deny de
    // relaciones no caduca (D3), pero un deny puede viajar por una membresía de grupo que sí caduca (M6, caso C).
    const denied = `${FACTS_DENIED_PREFIX}${relation.name}`
    const includers = objectType.relations.filter((other) => (other.includes ?? []).includes(relation.name))
    relations[relation.name] = { difference: { base, subtract: computed(denied) } }
    relations[denied] = includers.length
      ? { union: { child: [{ this: {} }, ...includers.map((other) => computed(`${FACTS_DENIED_PREFIX}${other.name}`))] } }
      : { this: {} }
  }
  return relations
}

/**
 * **Forma canónica de una regla de reescritura** para compararla con la que devuelve el servidor (cierre 2 de D1,
 * ⚪ N4). MEDIDO en v1.19.0: `ReadAuthorizationModel` devuelve las relaciones en otro orden de claves y cada
 * `computedUserset` con `object: ""`; ninguna de las dos cosas cambia qué concede. Se ordenan las claves, se quita el
 * `object` vacío y se ordenan los hijos de `union`/`intersection` (conmutativos; `difference` tiene `base`/`subtract`
 * con nombre y no se toca). Cualquier otra diferencia es una regla DISTINTA.
 */
export function canonicalRewrite(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(canonicalRewrite)
  if (node === null || typeof node !== 'object') return node
  const out: Record<string, unknown> = {}
  for (const key of Object.keys(node).sort()) {
    const value = (node as Record<string, unknown>)[key]
    if (value === undefined || (key === 'object' && value === '')) continue
    out[key] = canonicalRewrite(value)
  }
  if (Array.isArray(out.child)) {
    out.child = [...(out.child as unknown[])].sort((a, b) => {
      const x = JSON.stringify(a)
      const y = JSON.stringify(b)
      return x < y ? -1 : x > y ? 1 : 0
    })
  }
  return out
}

/* ── L11 · el modelo SERVIDO y el que genera la config son IGUALES ───────── */

/**
 * Qué tipos compara cada puerta (L11): `roles` (los holders, `role`, `role_binding`, `scope`), `relations` (los holders,
 * `group` y los tipos de la config) y `all` (el modelo ENTERO que generaría la config, más todo tipo que el servido
 * traiga de más: la relectura de `openfga:provision`). Las condiciones y `schema_version` se comparan SIEMPRE.
 */
export type FactsModelSlice = 'roles' | 'relations' | 'all'

/** Una diferencia del modelo servido respecto del generado, por RUTA legible. `type: null` = global (condiciones…). */
export interface FactsModelDifference {
  type: string | null
  path: string
}

export interface FactsModelComparison {
  equal: boolean
  differences: FactsModelDifference[]
  /**
   * La forma con la que el modelo servido trae cada tipo de relaciones de la config: `deny` (con `denied_<rel>`) o
   * `plain`. Con opt-in siempre `deny`; sin él, **D8 por TIPO ENTERO** (cierra P2: un modelo MEZCLADO, unas relaciones
   * con la forma con deny y otras sin ella, no lo genera ninguna config y es diferencia). Lo usa `decideMany`.
   */
  denyForm: ReadonlyMap<string, 'plain' | 'deny'>
  /** P_M: los permisos que declara el propio modelo servido (las bases de `role#permits_*`), ordenados. */
  permissions: string[]
}

/**
 * **Forma canónica de un modelo (o de cualquier trozo) de OpenFGA** para compararlo con el que genera el paquete
 * (L11; extiende `canonicalRewrite`). MEDIDO contra v1.19.0 (`:8090`): el servidor devuelve el ruido de proto3
 * —`module: ""`, `source_info: null`, `condition: ""` en cada restricción, `metadata: null`, `generic_types: []`,
 * `object: ""` en cada `computedUserset`— y otro orden de claves. Se quitan los valores por defecto de proto3 (`""`,
 * `null`, `[]`), **NUNCA un `{}`** (`this: {}` y `wildcard: {}` significan algo), se ordenan las claves y los hijos
 * CONMUTATIVOS (`child` de `union`/`intersection` y `directly_related_user_types`; `difference` tiene `base`/
 * `subtract` con nombre y no se toca). Una restricción DUPLICADA no se funde: es una diferencia.
 */
export function canonicalModel(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(canonicalModel)
  if (node === null || typeof node !== 'object') return node
  // Cierre de L11 (⚪ A3.2 del auditor): SIN prototipo — una relación o condición de más llamada `__proto__` (el servidor
  // v1.19 la acepta, medido) cambiaba el prototipo de un objeto literal en vez de ser una clave, y el comparador decía
  // «igual» (D-L11-3: relación de más = deriva). Con `Object.create(null)` es una clave propia más y se ve.
  const out: Record<string, unknown> = Object.create(null)
  for (const key of Object.keys(node).sort()) {
    const value = (node as Record<string, unknown>)[key]
    if (value === undefined || value === null || value === '') continue
    if (Array.isArray(value) && value.length === 0) continue
    out[key] = canonicalModel(value)
  }
  for (const key of ['child', 'directly_related_user_types']) {
    if (Array.isArray(out[key])) out[key] = sortByJson(out[key] as unknown[])
  }
  return out
}

function sortByJson(items: unknown[]): unknown[] {
  return [...items].sort((a, b) => {
    const x = JSON.stringify(a)
    const y = JSON.stringify(b)
    return x < y ? -1 : x > y ? 1 : 0
  })
}

const sameCanon = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b)

/**
 * **El punto de paso ÚNICO de L11** (lote «antes de RC», decisión del dueño 2026-10-17 (1); linaje L11): compara el
 * modelo que SIRVE el servidor con el que genera la config de este proceso, POR TIPO, en reglas, restricciones de
 * tipo (con su condición) y condiciones. Pura y sin SDK. Determinista: no busca entre combinaciones.
 *
 *  1. `P_M` = los permisos que declara el propio servido (`role#permits_*`): la igualdad es «módulo el catálogo», que
 *     cambia en runtime (el desfase catálogo ↔ modelo lo cuenta el reconcile, `permission-not-in-model`).
 *  2. `D8_M` = los tipos de la config SIN opt-in que el servido trae con la forma con deny (algún `denied_*`): se
 *     generan con `deny` para comparar — por TIPO ENTERO —.
 *  3. Se genera `openFgaFactsModel(holderTypes, P_M, config con D8_M)`; si el generador lanza (un `permits_*` del
 *     servido que no es un nombre publicable), es 500 `E_AUTHZ_CONFIG`, nunca «igual» (H11 d).
 *  4. Diferencias por ruta: `<tipo> (tipo ausente)`, `<tipo>#<rel> (falta)`, `(relación de más)` —una relación EXTRA
 *     es deriva, D-L11-3—, `(regla)`, `(restricciones de tipo)`, `<tipo>.<campo>`, `conditions.<nombre> (…)`,
 *     `schema_version`. Un tipo AJENO al `slice` no se mira (límite declarado y razonado, caso C7); con `all`, sí.
 */
export function factsModelDifferences(
  served: unknown,
  inputs: { holderTypes: HolderTypeMap; relations?: FactsRelationsConfig; slice: FactsModelSlice }
): FactsModelComparison {
  const model = served as { type_definitions?: unknown; conditions?: unknown; schema_version?: unknown } | null
  if (!model || typeof model !== 'object' || !Array.isArray(model.type_definitions)) {
    throw new AuthorizationConfigError(
      'L11: el modelo servido no trae type_definitions; no se puede comparar con el que genera la config (no se toma por igual).'
    )
  }
  const differences: FactsModelDifference[] = []
  const servedTypes = new Map<string, any>()
  for (const definition of model.type_definitions as any[]) {
    const type = definition?.type
    if (typeof type !== 'string' || type === '') {
      differences.push({ type: null, path: 'type_definitions (un tipo sin nombre)' })
      continue
    }
    if (servedTypes.has(type)) differences.push({ type, path: `${type} (tipo duplicado)` })
    servedTypes.set(type, definition)
  }

  const permissions =
    inputs.slice === 'relations'
      ? []
      : Object.keys(servedTypes.get(FACTS_ROLE_TYPE)?.relations ?? {})
          .filter((name) => name.startsWith(FACTS_PERMITS_PREFIX))
          .map((name) => name.slice(FACTS_PERMITS_PREFIX.length))
          .sort()

  const denyForm = new Map<string, 'plain' | 'deny'>()
  let relationsConfig: FactsRelationsConfig | undefined
  if (inputs.relations && inputs.slice !== 'roles') {
    relationsConfig = {
      objectTypes: inputs.relations.objectTypes.map((spec) => {
        if (spec.deny !== undefined) {
          denyForm.set(spec.type, 'deny')
          return spec
        }
        const d8 = Object.keys(servedTypes.get(spec.type)?.relations ?? {}).some((name) => name.startsWith(FACTS_DENIED_PREFIX))
        denyForm.set(spec.type, d8 ? 'deny' : 'plain')
        return d8 ? { ...spec, deny: 'read' as const } : spec
      }),
    }
  }

  let generated: any
  try {
    generated = openFgaFactsModel(inputs.holderTypes, permissions, relationsConfig)
  } catch (error) {
    throw markDeploymentFailure(
      new AuthorizationConfigError(
        `L11: no se puede generar el modelo de la config con los permisos que declara el modelo servido ` +
          `(${(error as Error)?.message ?? String(error)}); no se toma por igual.`,
        { cause: error }
      )
    )
  }
  const generatedTypes = new Map<string, any>(generated.type_definitions.map((definition: any) => [definition.type, definition]))
  const holders = Object.values(inputs.holderTypes)
  const sliceTypes =
    inputs.slice === 'all'
      ? [...generatedTypes.keys()]
      : inputs.slice === 'roles'
        ? [...holders, FACTS_ROLE_TYPE, FACTS_BINDING_TYPE, FACTS_SCOPE_TYPE]
        : [...holders, FACTS_GROUP_TYPE, ...(inputs.relations?.objectTypes ?? []).map((t) => t.type)]
  for (const type of sliceTypes) compareTypeDefinition(type, servedTypes.get(type), generatedTypes.get(type), differences)
  if (inputs.slice === 'all') {
    for (const type of servedTypes.keys()) {
      if (!generatedTypes.has(type)) differences.push({ type, path: `${type} (tipo de más)` })
    }
  }

  const servedConditions = (canonicalModel(model.conditions ?? {}) ?? {}) as Record<string, unknown>
  const generatedConditions = canonicalModel(generated.conditions) as Record<string, unknown>
  for (const name of [...new Set([...Object.keys(servedConditions), ...Object.keys(generatedConditions)])].sort()) {
    if (!(name in servedConditions)) differences.push({ type: null, path: `conditions.${name} (falta)` })
    else if (!(name in generatedConditions)) differences.push({ type: null, path: `conditions.${name} (condición de más)` })
    else if (!sameCanon(servedConditions[name], generatedConditions[name])) differences.push({ type: null, path: `conditions.${name} (distinta)` })
  }
  if (!sameCanon(canonicalModel(model.schema_version), generated.schema_version)) {
    differences.push({ type: null, path: `schema_version (${JSON.stringify(model.schema_version ?? null)})` })
  }
  for (const key of Object.keys(model).sort()) {
    if (['id', 'schema_version', 'type_definitions', 'conditions'].includes(key)) continue
    const value = (model as Record<string, unknown>)[key]
    if (value === undefined || value === null || value === '' || (Array.isArray(value) && value.length === 0)) continue
    differences.push({ type: null, path: `modelo.${key}` })
  }
  return { equal: differences.length === 0, differences, denyForm, permissions }
}

function compareTypeDefinition(type: string, served: unknown, generated: unknown, out: FactsModelDifference[]): void {
  if (generated === undefined) return
  if (served === undefined) {
    out.push({ type, path: `${type} (tipo ausente del modelo)` })
    return
  }
  const s = canonicalModel(served) as Record<string, any>
  const g = canonicalModel(generated) as Record<string, any>
  const sRelations: Record<string, unknown> = s.relations ?? {}
  const gRelations: Record<string, unknown> = g.relations ?? {}
  const reported = new Set<string>()
  for (const name of [...new Set([...Object.keys(sRelations), ...Object.keys(gRelations)])].sort()) {
    if (!(name in sRelations)) out.push({ type, path: `${type}#${name} (falta)` })
    else if (!(name in gRelations)) out.push({ type, path: `${type}#${name} (relación de más)` })
    else if (!sameCanon(sRelations[name], gRelations[name])) out.push({ type, path: `${type}#${name} (regla)` })
    else continue
    reported.add(name)
  }
  const sMeta: Record<string, unknown> = s.metadata?.relations ?? {}
  const gMeta: Record<string, unknown> = g.metadata?.relations ?? {}
  for (const name of [...new Set([...Object.keys(sMeta), ...Object.keys(gMeta)])].sort()) {
    if (reported.has(name)) continue
    if (!sameCanon(sMeta[name], gMeta[name])) out.push({ type, path: `${type}#${name} (restricciones de tipo)` })
  }
  const rest = (definition: Record<string, any>) => {
    const { type: _t, relations: _r, metadata, ...others } = definition
    const { relations: _mr, ...metaOthers } = (metadata ?? {}) as Record<string, unknown>
    return { others, metaOthers }
  }
  const sr = rest(s)
  const gr = rest(g)
  for (const key of [...new Set([...Object.keys(sr.others), ...Object.keys(gr.others)])].sort()) {
    if (!sameCanon(sr.others[key], gr.others[key])) out.push({ type, path: `${type}.${key}` })
  }
  for (const key of [...new Set([...Object.keys(sr.metaOthers), ...Object.keys(gr.metaOthers)])].sort()) {
    if (!sameCanon(sr.metaOthers[key], gr.metaOthers[key])) out.push({ type, path: `${type}.metadata.${key}` })
  }
}

/** Cuántas rutas nombra como mucho la letra del 500 de L11 (el resto se cuenta). */
export const FACTS_MODEL_DRIFT_LISTED = 20

/**
 * **La LETRA del 500 de la puerta L11**, la MISMA en los dos drivers `openfga`: qué driver, qué operación, qué
 * `modelId`, las diferencias por ruta y la receta. Cero llamadas que evalúen o escriban.
 */
export function factsModelDriftError(
  driver: string,
  operation: string,
  modelId: string | undefined,
  differences: readonly FactsModelDifference[]
): AuthorizationConfigError & { modelDifferences: string[] } {
  const paths = differences.map((d) => d.path)
  const listed = paths.slice(0, FACTS_MODEL_DRIFT_LISTED).join('; ')
  const more = paths.length > FACTS_MODEL_DRIFT_LISTED ? ` … y ${paths.length - FACTS_MODEL_DRIFT_LISTED} más` : ''
  const error = new AuthorizationConfigError(
    `${driver}.${operation}: el modelo que sirve este driver (modelId ${modelId ?? '(ninguno)'}) NO es el que genera la ` +
      `config de este proceso (L11: reglas, restricciones de tipo y condiciones, por tipo) — ${listed}${more}. Con ese ` +
      'modelo el servidor decide con reglas o condiciones que la config no declara: puede conceder lo que la config —y ' +
      'database con la misma config— niega, o leer caducidades con otra condición. Republica el modelo desde la config ' +
      'actual (node ace openfga:provision --store-id=…) y fija el modelId nuevo (OPENFGA_MODEL_ID) en TODA la flota antes ' +
      'de desplegar. No se ha llamado al servidor para evaluar ni escribir nada.'
  ) as AuthorizationConfigError & { modelDifferences: string[] }
  error.modelDifferences = paths
  // Cierre de L11 (🟠 A1): fallo del DESPLIEGUE ⇒ transitorio para el relay (no consume intento ni aparca).
  return markDeploymentFailure(error)
}

/**
 * **El token del opt-in de `openfga` EXPERIMENTAL en 2.5.x** (estrategia 2.5.0, firma 4 del dueño 2026-10-21, «(b) con
 * candado»). Lleva la VERSIÓN a propósito (auditor B1/B7, tester E1): con `true` nada obligaría a releer los límites NUEVOS
 * cuando cambien; con `'openfga@2.5'` la 2.6 cambiará el token y un `^2.5.0` que se actualice hace ruido (500) en vez de
 * colarse. NO se exporta por `/openfga`: el consumidor escribe el LITERAL, que es lo que demuestra que leyó «Limits».
 */
export const OPENFGA_EXPERIMENTAL_TOKEN = 'openfga@2.5'

/**
 * **La puerta del opt-in experimental, en los DOS constructores `openfga`** (firma 4; mismo patrón que
 * `E_AUTHZ_SCOPE_DRIFT_UNGUARDED`: «una recomendación no es un mecanismo»). En 2.5.x `openfga` tiene límites declarados
 * en README «Limits» (carreras entre escritores, árbol con outbox sin medir, el gemelo `permits_*`…) que se cierran en
 * 2.6, así que construirlo exige escribir `experimental: 'openfga@2.5'`. Cualquier otra cosa —ausente, `true`,
 * `'acknowledged'`, otra versión, el token con espacios— es 500 `E_AUTHZ_CONFIG` al CONSTRUIR, como PRIMERA línea del
 * constructor: ni se valida lo demás ni se crea el cliente, así que hay CERO llamadas al servidor. Va en el constructor
 * y no en el stub ni en el registro de la factory: `manager.driver()` (y con él `authz:catalog:sync`),
 * `authz:reconcile --to=openfga`, `authz:relations:reconcile`, el provider y la construcción directa pasan todos por
 * aquí, y un config solo-`database` que REGISTRA la factory `openfga` sin usarla arranca (las factories son perezosas).
 * `openfga:provision` NO construye un driver (crea el store y publica el modelo con el SDK): corre sin la marca, y el
 * primer driver que sirva con ese store, no.
 */
export function assertExperimentalOptIn(driver: string, value: unknown): void {
  if (typeof value === 'string' && value === OPENFGA_EXPERIMENTAL_TOKEN) return
  throw new AuthorizationConfigError(experimentalOptInMessage(driver, describeOptInValue(value)))
}

/**
 * Qué llegó, SIN tocar el valor (cierre 1 del candado, ⚪ 5 del auditor): `String(value)` de un `Object.create(null)` o de
 * un objeto cuyo `toString` lanza sustituía el 500 por un `TypeError` o por el error del consumidor. Solo `typeof` y, para
 * un string, `JSON.stringify` (que no invoca nada del valor).
 */
function describeOptInValue(value: unknown): string {
  if (value === undefined) return 'nada'
  if (value === null) return 'null'
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'boolean' || typeof value === 'number' || typeof value === 'bigint') return `${typeof value} ${value}`
  return `un ${Array.isArray(value) ? 'array' : typeof value}`
}

function experimentalOptInMessage(driver: string, got: string): string {
  return (
    `${driver}: el driver openfga es EXPERIMENTAL en 2.5.x y NO es apto para producción: tiene límites declarados ` +
      '(README «Limits»: carreras entre escritores del driver de roles, el árbol con outbox sin medir, el gemelo ' +
      'permits_*…) que se cierran en 2.6. Para usarlo igualmente (CI, ensayo, desarrollo) opta de forma EXPLÍCITA con ' +
      `experimental: '${OPENFGA_EXPERIMENTAL_TOKEN}' en las opciones del driver (llegó ${got}). El token lleva la versión ` +
      'a propósito: true u otra versión no valen; el token y el comportamiento experimental de openfga pueden cambiar en ' +
      '2.6 (una minor) sin major. ' +
      'En producción usa database; para MIGRAR a database desde openfga (authz:reconcile --to=database, con openfga como ' +
      'ORIGEN) la factory openfga también necesita la marca: leer el store para salir de él es construir este driver. ' +
      'No se ha creado el cliente ni se ha llamado al servidor.'
  )
}

/**
 * **`modelId` OBLIGATORIO en los dos drivers `openfga`** (lote «antes de RC» · L11, decisión del dueño 2026-10-17 (2);
 * D14 ampliado: siempre, con o sin deny). Sin el pin la puerta L11 compara el modelo que el driver lee al arrancar y el
 * servidor evalúa cada petición con el ÚLTIMO del store: un `openfga:provision` desde otro proceso cambiaría lo que se
 * concede sin que ninguna comparación lo vea. 500 al CONSTRUIR, con la receta.
 */
export function assertPinnedModel(driver: string, modelId: unknown): void {
  if (typeof modelId === 'string' && modelId.trim() !== '') return
  throw new AuthorizationConfigError(
    `${driver}: falta modelId (llegó ${JSON.stringify(modelId ?? null)}). Desde 2.5.0-alpha.4 el modelo FIJADO es ` +
      'obligatorio en los dos drivers openfga, con o sin deny (L11): el driver comprueba UNA vez que ese modelo es el que ' +
      'genera tu config y el servidor evalúa con ESE modelo; sin el pin evaluaría con el último del store. Receta: ' +
      '`node ace openfga:provision` (o `--store-id=$OPENFGA_STORE_ID` sobre un store existente) imprime OPENFGA_MODEL_ID; ' +
      'ponlo en el .env de TODA la flota y pásalo como modelId (el stub de config/authorization.ts lo hace con ' +
      "env.get('OPENFGA_MODEL_ID'))."
  )
}
