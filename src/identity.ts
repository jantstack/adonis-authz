import { InvalidIdentityError, InvalidSlugError } from './errors.js'
import { APP_SCOPE_TYPE } from './types.js'
import type { NormalizedRoleQuery, RoleQuery, ScopeRef, SubjectRef } from './types.js'

/**
 * Validación de identidad del motor: holder, scope, rol y permiso.
 *
 * Vive en un solo sitio y la aplican el manager (una vez por llamada) Y los
 * drivers (defensa en profundidad: el juez del contrato habla con el driver
 * directamente, y un driver de terceros puede usarse sin manager). Nadie
 * duplica la regla: se importa.
 *
 * Por qué es 422 y no "se acepta lo que venga":
 *  - `uuid: undefined` en el driver openfga escribía `user:undefined`, y a
 *    partir de ahí CUALQUIER holder sin uuid heredaba ese permiso (L0.5).
 *  - `{ type: 'app', uuid: 'X' }` colapsaba a la raíz global en openfga y no
 *    en database: escalada de tenant a plataforma en un driver y `false` en
 *    el otro (L0.10).
 *  - `#`, `:`, `|`, `~`, `*` y espacios son sintaxis de FGA o separadores de
 *    los ids de binding: un componente que los contenga puede fabricar un
 *    userset, un comodín o la clave de OTRO scope (L0.5, L0.8). Desde 3A
 *    (2.2) el slug ya NO viaja en los ids de FGA (van por uuid de catálogo),
 *    pero los tipos y uuids de scope sí, y los slugs serán relaciones del
 *    modelo `facts` (3b): la lista blanca se mantiene entera.
 *  - Las longitudes son las de las columnas `authz_*`: lo que no cabe se
 *    truncaría o fallaría con un error de SQL ilegible.
 */

/**
 * Longitudes de columna del esquema publicado (`stubs/migration.stub`) que
 * la identidad aplica tal cual. El slug NO está aquí: su límite es
 * `MAX_SLUG_LENGTH` (42), más estricto que la columna (100) para que el
 * catálogo sea publicable en FGA (E2).
 */
export const IDENTITY_LIMITS = Object.freeze({
  holderType: 50,
  scopeType: 20,
  uuid: 36,
})

/**
 * Centinela con el que el driver `database` almacena el uuid del scope `app`
 * (NOT NULL + unique). Fuera de `app` sería una identidad de scope que
 * colisiona con la raíz: se rechaza (L0.15).
 */
export const SENTINEL_UUID = '00000000-0000-0000-0000-000000000000'

/**
 * UUID del CATÁLOGO (rol o permiso): la columna `uuid` de `authz_roles` y
 * `authz_permissions` es `uuid` real, y desde 3A (2.2) es lo que viaja en
 * los ids de binding de FGA (`role_binding:<scopeKey>|<roleUuid>`). Se exige
 * canónico y en MINÚSCULAS (RFC 9562, 8-4-4-4-12 hex): PostgreSQL lo
 * normaliza así y MySQL/SQLite lo guardan tal cual, así que un uuid en
 * mayúsculas del spec produciría dos identidades para el mismo rol según el
 * motor, y un id de binding que el propio driver no leería de vuelta. Es más
 * estricto que la gramática de los uuids de holder/scope (esos son del
 * consumidor, `[a-z0-9._-]{1,36}`): un id 1.x con slug (`app|editor`) no
 * puede parecer un id 2.2 (`app|<uuid>`).
 */
const CATALOG_UUID_FORMAT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** El uuid de un rol o permiso del catálogo (opcional en el spec): canónico y en minúsculas, o 422. */
export function assertCatalogUuid(kind: string, value: unknown): asserts value is string {
  if (typeof value !== 'string' || !CATALOG_UUID_FORMAT.test(value)) {
    throw new InvalidIdentityError(
      `UUID del ${kind} inválido: se esperaba un UUID canónico en minúsculas (8-4-4-4-12 hex) y llegó ${describe(value)}`
    )
  }
}

/** Versión booleana para caminos de LECTURA (ids que vienen del backend): no lanza. */
export function isCatalogUuid(value: unknown): value is string {
  return typeof value === 'string' && CATALOG_UUID_FORMAT.test(value)
}

/**
 * Un componente de identidad: MINÚSCULAS, dígitos, `_`, `.` y `-`. Lista
 * blanca y no negra: lo que no está aquí no se serializa a ningún backend.
 * Excluye por construcción `#`, `:`, `|`, `~`, `*`, `@`, espacios y control.
 *
 * Los TIPOS (de holder y de scope) van en minúsculas desde E4 (auditor H14):
 * en un motor SQL con collation `*_ci` `Users` y `users` serían la misma fila
 * y en FGA dos holders distintos. Los UUIDs también desde 2.5-B · K1
 * (auditor 🔴 1): el árbol del consumidor (tipo `uuid` de PG, `char(36)`
 * `*_ci` de MySQL) fundía `BBBB…` con `bbbb…`, la cadena resolvía con el
 * alias y el deny —escrito canónico en `authz_*`, `utf8mb4_bin`— no casaba.
 * La cadena canónica del resolutor cierra el alias por guiones; el alias por
 * mayúsculas muere aquí, en la puerta, antes de tocar nada. Un id en
 * mayúsculas del consumidor se pasa en minúsculas (`uuid.toLowerCase()`) en
 * su borde: un UUID es el mismo id en cualquier caja.
 */
const COMPONENT_FORMAT = /^[a-z0-9_.-]+$/
const TYPE_FORMAT = COMPONENT_FORMAT

function assertComponent(
  kind: string,
  value: unknown,
  maxLength: number,
  format: RegExp = COMPONENT_FORMAT
): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new InvalidIdentityError(
      `${kind} inválido: se esperaba una cadena no vacía y llegó ${describe(value)}`
    )
  }
  if (value.length > maxLength) {
    throw new InvalidIdentityError(
      `${kind} inválido: '${value}' supera los ${maxLength} caracteres de la columna`
    )
  }
  if (!format.test(value)) {
    throw new InvalidIdentityError(
      `${kind} inválido: '${value}'. Solo se admiten minúsculas, dígitos y . _ - ` +
        `(ni mayúsculas, '#', ':', '|', '~', '*', espacios ni caracteres de control)`
    )
  }
}

function describe(value: unknown): string {
  if (value === undefined) return 'undefined'
  if (value === null) return 'null'
  if (typeof value === 'string') return `'${value}'`
  return typeof value
}

/** `SubjectRef` bien formado: type y uuid presentes, con formato y longitud. */
export function assertSubject(subject: SubjectRef): void {
  if (!subject || typeof subject !== 'object') {
    throw new InvalidIdentityError(`Holder inválido: llegó ${describe(subject)}`)
  }
  assertComponent('Tipo de holder', subject.type, IDENTITY_LIMITS.holderType, TYPE_FORMAT)
  assertComponent(`UUID del holder '${subject.type}'`, subject.uuid, IDENTITY_LIMITS.uuid)
}

/**
 * `ScopeRef` bien formado. `app` es la raíz y NO admite uuid (L0.10): un
 * `{ app, 'X' }` no es "otro app", es una identidad que un driver colapsaría
 * a la global. Fuera de `app` el uuid es obligatorio y no puede ser el
 * centinela con el que `database` representa la raíz (L0.15).
 */
export function assertScope(scope: ScopeRef): void {
  if (!scope || typeof scope !== 'object') {
    throw new InvalidIdentityError(`Scope inválido: llegó ${describe(scope)}`)
  }
  assertComponent('Tipo de scope', scope.type, IDENTITY_LIMITS.scopeType, TYPE_FORMAT)
  if (scope.type === APP_SCOPE_TYPE) {
    if (scope.uuid !== null) {
      throw new InvalidIdentityError(
        `Scope inválido: el scope '${APP_SCOPE_TYPE}' es la raíz y no admite uuid ` +
          `(llegó ${describe(scope.uuid)}). Usa APP_SCOPE.`
      )
    }
    return
  }
  assertComponent(`UUID del scope '${scope.type}'`, scope.uuid, IDENTITY_LIMITS.uuid)
  if (scope.uuid === SENTINEL_UUID) {
    throw new InvalidIdentityError(
      `Scope inválido: '${SENTINEL_UUID}' está reservado para la raíz y no puede ` +
        `identificar un scope de tipo '${scope.type}'`
    )
  }
}

/** Tipo de scope suelto (el de `listRoleScopes`). */
export function assertScopeType(scopeType: string): void {
  assertComponent('Tipo de scope', scopeType, IDENTITY_LIMITS.scopeType, TYPE_FORMAT)
}

/* ── Clave de scope ─────────────────────────────────────────────────────── */

/**
 * Clave textual de un scope: `app` para la raíz, `<tipo>|<uuid>` para el
 * resto (≤ 57 caracteres). Es la MISMA en todo el paquete: el id de los
 * bindings de FGA (`role_binding:<scopeKey>|<roleUuid>`) y el owner de un
 * rol local (`authz_roles.owner_scope_key`, 3B · B1). `|` es el separador:
 * como ningún componente lo admite (`assertScope`), dos scopes distintos no
 * pueden producir la misma clave, y la clave reservada `global` (el catálogo
 * del config) no la produce ningún scope — la raíz da `app` y todo lo demás
 * lleva `|`. Un scope mal formado (`{app, uuid}`, centinela, mayúsculas) es
 * 422 aquí, antes de serializarse a nada.
 */
export function scopeKey(scope: ScopeRef): string {
  assertScope(scope)
  if (scope.type === APP_SCOPE_TYPE) return APP_SCOPE_TYPE
  return `${scope.type}|${scope.uuid}`
}

/** Un uuid canónico escrito SIN guiones: 32 dígitos hexadecimales. */
const DASHLESS_UUID = /^[0-9a-f]{32}$/

/**
 * **Las ORTOGRAFÍAS de un scope con las que hay que limpiar cuando ya no hay
 * cadena con la que canonizar** (3b-2h · 🟠 3, auditor R2).
 *
 * La identidad de un scope es la canónica que devuelve el resolutor
 * (invariante 17) y el paquete la usa para TODOS los hechos… mientras la fila
 * del consumidor existe. `scopes.detached` es justo la operación que admite
 * que ya NO exista (3F · S1: se purga igual, con el scope tal cual), y ahí no
 * hay con qué canonizar: se usa la ortografía del llamante. Medido contra
 * PostgreSQL: el tipo `uuid` funde `01a0…-…` con el mismo uuid SIN guiones,
 * así que el `DELETE` del controlador acierta con el alias, el `detached`
 * llega con el alias, `purgeScope` demuestra cero sobre un objeto que no
 * existe y el scope REAL conserva su `parent` y su `binding`: en modo
 * `facts`, **concede para siempre**. En lectura el mismo alias es
 * fail-closed; en escritura era fail-OPEN.
 *
 * La salida es no elegir: una purga sin cadena limpia la ortografía del
 * llamante **y** la canónica de la que puede ser alias. Solo se expande el
 * alias SIN guiones (32 hex ⇒ también la forma 8-4-4-4-12), que es la única
 * que un motor produce fundiendo —PostgreSQL canoniza CON guiones; el alias
 * por mayúsculas ya muere en la puerta (`assertScope`)—; así el consumidor
 * que guarda sus uuids con guiones (el caso normal) no paga NADA, y el que
 * los guarda sin guiones sigue purgando su clave y, además, una que nunca
 * tiene hechos. Normalizar en vez de expandir no vale: sin la fila no se sabe
 * cuál de las dos es la buena, y elegir mal deja los hechos vivos, que es el
 * fallo que se está cerrando.
 */
export function scopeSpellings(scope: ScopeRef): ScopeRef[] {
  assertScope(scope)
  const uuid = scope.uuid
  if (uuid === null || !DASHLESS_UUID.test(uuid)) return [scope]
  const dashed = `${uuid.slice(0, 8)}-${uuid.slice(8, 12)}-${uuid.slice(12, 16)}-${uuid.slice(16, 20)}-${uuid.slice(20)}`
  return [scope, { type: scope.type, uuid: dashed }]
}

/**
 * La inversa de `scopeKey` para claves que vienen de la BASE (el owner de un
 * rol): `app` ⇒ la raíz; `<tipo>|<uuid>` ⇒ el scope; cualquier otra forma
 * (incluida `global`, que no es un scope) ⇒ `null`. No lanza: es camino de
 * lectura, y una clave que no es un scope simplemente no resuelve.
 */
export function scopeFromKey(key: string): ScopeRef | null {
  if (key === APP_SCOPE_TYPE) return { type: APP_SCOPE_TYPE, uuid: null }
  const parts = key.split('|')
  if (parts.length !== 2) return null
  const scope: ScopeRef = { type: parts[0], uuid: parts[1] }
  return isValidScope(scope) ? scope : null
}

/* ── Slugs del catálogo ─────────────────────────────────────────────────── */

/**
 * Gramática de un slug: minúsculas, dígitos y . _ - ; los permisos admiten UN
 * `:` (`recurso:accion`), los roles ninguno.
 */
const PERMISSION_FORMAT = /^[a-z0-9][a-z0-9_.-]*(:[a-z0-9][a-z0-9_.-]*)?$/
const ROLE_FORMAT = /^[a-z0-9][a-z0-9_.-]*$/

/**
 * Nombres que el modelo FGA del modo `facts` usa como relaciones propias
 * (`scope#parent`, `role_binding#assignee`, `scope#denied_<P>`…). Un
 * permiso llamado `parent` invalidaría el modelo entero (S14): se rechaza en
 * el núcleo, para ambos drivers, no el día de la migración.
 */
export const RESERVED_SLUGS: ReadonlySet<string> = new Set([
  'parent',
  'binding',
  'ancestor',
  'rooted',
  'role',
  'assignee',
  'denied',
])

/**
 * Familias de relaciones derivadas del modelo (`can_<P>`, `denied_<P>`,
 * `permits_<P>`). Un slug que EMPIECE por una de ellas colisiona con la
 * relación derivada de otro permiso y el generador la colapsaría en silencio
 * (S4: `can_docs_write` anulaba el deny de `docs:write`).
 */
export const RESERVED_SLUG_PREFIXES: readonly string[] = Object.freeze(['can_', 'denied_', 'permits_'])

/**
 * **Los TIPOS de objeto que el modelo `facts` (y el `group` de relaciones) YA
 * declaran** (Fase 4 · ⚪4). Un tipo de objeto de relaciones que se llame como
 * uno de estos DUPLICARÍA un tipo del store compartido: `role_binding` sobre
 * todo —si el driver de relaciones pudiera declararlo, podría componer el id
 * de un binding real y `relate` sería una escalada a `roles.authorize`—. Vive
 * en `identity.ts` (la gramática compartida) porque lo consumen DOS módulos
 * que la frontera de pureza mantiene disjuntos: el generador del modelo
 * (`src/drivers/openfga_facts.ts`, que no puede depender de `relations/`) y
 * `defineRelationsConfig` (`src/relations/`, que no puede depender de
 * `drivers/`). `deny_binding` sigue reservado aunque el modelo (c2r) ya no lo
 * emita: un catálogo migrado del modo `resolver` no puede resucitarlo.
 */
export const RESERVED_FACTS_TYPES: ReadonlySet<string> = Object.freeze(
  new Set(['scope', 'role', 'role_binding', 'deny_binding', 'group'])
) as ReadonlySet<string>

/**
 * Longitud máxima de un slug. Un nombre de relación en FGA admite 50
 * caracteres y el modelo deriva `permits_<slug>` (el prefijo más largo, 8):
 * 42 es lo que cabe con cualquier prefijo. Es más estricto que la columna
 * (100) a propósito: un catálogo legal en `database` tiene que ser publicable
 * en `openfga` (S13), o el cambio de driver no es una migración de hechos.
 */
export const MAX_SLUG_LENGTH = 50 - Math.max(...RESERVED_SLUG_PREFIXES.map((p) => p.length))

export type SlugKind = 'rol' | 'permiso'

/** Slug de rol o permiso válido para AMBOS drivers (formato, longitud, reservados). */
export function assertValidSlug(kind: SlugKind, slug: unknown): asserts slug is string {
  if (typeof slug !== 'string' || slug.length === 0) {
    throw new InvalidSlugError(
      `Slug de ${kind} inválido: se esperaba una cadena no vacía y llegó ${describe(slug)}`
    )
  }
  if (slug.length > MAX_SLUG_LENGTH) {
    // 3b-2a · A4: se nombra el prefijo que lo desborda y la relación que
    // saldría. La cota es del modo `facts`, y quien lee el error tiene que
    // saber por qué 42 y no 100 (que es lo que admite la columna).
    const longest = RESERVED_SLUG_PREFIXES.reduce((a, b) => (a.length >= b.length ? a : b))
    throw new InvalidSlugError(
      `Slug de ${kind} inválido: '${slug}' supera los ${MAX_SLUG_LENGTH} caracteres ` +
        `(50 de una relación FGA menos el prefijo derivado más largo, '${longest}': ` +
        `'${longest}${slug}' serían ${longest.length + slug.length})`
    )
  }
  const format = kind === 'permiso' ? PERMISSION_FORMAT : ROLE_FORMAT
  if (!format.test(slug)) {
    throw new InvalidSlugError(
      `Slug de ${kind} inválido: '${slug}'. Formato: minúsculas/dígitos/._-` +
        (kind === 'permiso' ? " con ':' único opcional (recurso:accion)" : ' (sin ":")') +
        "; '~', '|', '#', '*' y espacios están prohibidos"
    )
  }
  if (RESERVED_SLUGS.has(slug)) {
    throw new InvalidSlugError(
      `Slug de ${kind} inválido: '${slug}' es un nombre reservado del modelo ` +
        `(${[...RESERVED_SLUGS].join(', ')})`
    )
  }
  const family = RESERVED_SLUG_PREFIXES.find((prefix) => slug.startsWith(prefix))
  if (family) {
    throw new InvalidSlugError(
      `Slug de ${kind} inválido: '${slug}' empieza por '${family}', prefijo reservado ` +
        `de las relaciones derivadas (${RESERVED_SLUG_PREFIXES.join(', ')})`
    )
  }
}

/**
 * Cómo se proyecta un slug a un nombre de relación FGA (`:` → `_`). Dos slugs
 * distintos con la misma proyección (`docs:write` / `docs_write`) serían UNA
 * relación: el catálogo los rechaza juntos (L0.8a).
 */
export function slugAsRelation(slug: string): string {
  return slug.replaceAll(':', '_')
}

/** Ningún par de slugs del conjunto colisiona tras proyectarse a relación. */
export function assertNoSlugCollisions(kind: SlugKind, slugs: Iterable<string>): void {
  const seen = new Map<string, string>()
  for (const slug of slugs) {
    const relation = slugAsRelation(slug)
    const other = seen.get(relation)
    if (other !== undefined && other !== slug) {
      throw new InvalidSlugError(
        `Slugs de ${kind} en colisión: '${other}' y '${slug}' se proyectan a la misma ` +
          `relación '${relation}' (':' y '_' son equivalentes en el modelo)`
      )
    }
    seen.set(relation, slug)
  }
}

/** Versiones booleanas para caminos de LECTURA que no deben lanzar (ids que vienen del backend). */
export function isValidScope(scope: ScopeRef): boolean {
  try {
    assertScope(scope)
    return true
  } catch {
    return false
  }
}

export function isValidScopeType(scopeType: unknown): scopeType is string {
  try {
    assertScopeType(scopeType as string)
    return true
  } catch {
    return false
  }
}

export function isValidSlug(kind: SlugKind, slug: string): boolean {
  try {
    assertValidSlug(kind, slug)
    return true
  } catch {
    return false
  }
}

/**
 * La pregunta de `hasRole`, validada: string ⇒ `{ slug }`; objeto ⇒
 * `{ slug, scopeType }` (ambos con la gramática del motor).
 */
export function normalizeRoleQuery(role: RoleQuery): NormalizedRoleQuery {
  if (typeof role === 'string') {
    assertValidSlug('rol', role)
    return { slug: role }
  }
  if (!role || typeof role !== 'object') {
    throw new InvalidIdentityError(`Rol inválido: llegó ${describe(role)}`)
  }
  // 3D · M1(c): `{ uuid }` es la forma EXACTA (sin ambigüedad posible). No se
  // mezcla con `{ slug, scopeType }`: la pregunta es por identidad o por
  // nombre, nunca por las dos a la vez (un `{ uuid, slug }` que no casaran
  // sería una pregunta con dos respuestas).
  if ('uuid' in (role as object)) {
    const query = role as { uuid: unknown; slug?: unknown; scopeType?: unknown }
    if (query.slug !== undefined || query.scopeType !== undefined) {
      throw new InvalidIdentityError(
        `Rol inválido: { uuid } es la forma exacta y no se combina con 'slug'/'scopeType' (llegó ${describe(role)})`
      )
    }
    assertCatalogUuid('rol', query.uuid)
    return { uuid: query.uuid }
  }
  assertValidSlug('rol', (role as any).slug)
  assertScopeType((role as any).scopeType)
  return { slug: (role as any).slug, scopeType: (role as any).scopeType }
}

/**
 * Las claves de la cadena desde cada nivel hacia la raíz (3B · B2; movida
 * aquí en 3D · N5 para que exista UNA sola codificación de clave de scope):
 * `keysFrom[i]` = `chain.slice(i).map(scopeKey)`. Un rol es visible en el
 * nivel `i` si es global o su owner está en `keysFrom[i]` — el owner tiene
 * que ser ancestro-o-igual del scope de la ASIGNACIÓN, no de la pregunta.
 */
export function chainKeysFrom(chain: ScopeRef[]): string[][] {
  const keys = chain.map(scopeKey)
  return keys.map((_, i) => keys.slice(i))
}

/* ── Punto de entrada único ─────────────────────────────────────────────── */

/**
 * `expiresAt` de un `grant`, en sus tres estados legales: omitido, `null` o
 * una `Date` válida. Una cadena, un número o un `Invalid Date` no son una
 * caducidad: un driver lanzaba un TypeError al serializar y el otro persistía
 * basura (D7). Se rechaza como identidad mal formada (422).
 */
export function assertExpiresAt(value: unknown): asserts value is Date | null | undefined {
  if (value === undefined || value === null) return
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new InvalidIdentityError(
      `expiresAt inválido: se esperaba una Date válida, null (sin caducidad) u omitido ` +
        `(preservar la vigente) y llegó ${value instanceof Date ? 'Invalid Date' : describe(value)}`
    )
  }
}

export interface IdentityParts {
  subject?: SubjectRef
  scope?: ScopeRef
  scopeType?: string
  /** Pregunta de `hasRole`: string u objeto `{ slug, scopeType }`. */
  role?: RoleQuery
  /**
   * Slug de rol donde el contrato pide un string (`grant`, `revoke`,
   * `listSubjects`): un `RoleQuery` objeto aquí es 422, no un 503 ni un
   * TypeError (D11).
   */
  roleSlug?: unknown
  permission?: string
  /** Caducidad de un `grant`: `undefined` | `null` | `Date` válida. */
  expiresAt?: unknown
}

/**
 * Valida en un solo paso los componentes que recibe una operación. Se llama
 * ANTES de tocar catálogo, árbol o backend: una pregunta mal formada no
 * cuesta una consulta ni deja rastro.
 */
export function assertIdentity(parts: IdentityParts): void {
  if ('subject' in parts) assertSubject(parts.subject as SubjectRef)
  if ('scope' in parts) assertScope(parts.scope as ScopeRef)
  if ('scopeType' in parts) assertScopeType(parts.scopeType as string)
  if ('role' in parts) normalizeRoleQuery(parts.role as RoleQuery)
  if ('roleSlug' in parts) assertValidSlug('rol', parts.roleSlug)
  if ('permission' in parts) assertValidSlug('permiso', parts.permission)
  if ('expiresAt' in parts) assertExpiresAt(parts.expiresAt)
}
