import { InvalidIdentityError, InvalidSlugError } from './errors.js'
import { APP_SCOPE_TYPE } from './types.js'
import type { ScopeRef, SubjectRef } from './types.js'

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
 *    userset, un comodín o la clave de OTRO scope (L0.5, L0.8).
 *  - Las longitudes son las de las columnas `authz_*`: lo que no cabe se
 *    truncaría o fallaría con un error de SQL ilegible.
 */

/** Longitudes de columna del esquema publicado (`stubs/migration.stub`). */
export const IDENTITY_LIMITS = Object.freeze({
  holderType: 50,
  scopeType: 20,
  uuid: 36,
  slug: 100,
})

/**
 * Centinela con el que el driver `database` almacena el uuid del scope `app`
 * (NOT NULL + unique). Fuera de `app` sería una identidad de scope que
 * colisiona con la raíz: se rechaza (L0.15).
 */
export const SENTINEL_UUID = '00000000-0000-0000-0000-000000000000'

/**
 * Un componente de identidad: letras, dígitos, `_`, `.` y `-`. Lista blanca y
 * no negra: lo que no está aquí no se serializa a ningún backend. Excluye por
 * construcción `#`, `:`, `|`, `~`, `*`, `@`, espacios y control.
 */
const COMPONENT_FORMAT = /^[A-Za-z0-9_.-]+$/

function assertComponent(kind: string, value: unknown, maxLength: number): asserts value is string {
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
  if (!COMPONENT_FORMAT.test(value)) {
    throw new InvalidIdentityError(
      `${kind} inválido: '${value}'. Solo se admiten letras, dígitos y . _ - ` +
        `(ni '#', ':', '|', '~', '*', espacios ni caracteres de control)`
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
  assertComponent('Tipo de holder', subject.type, IDENTITY_LIMITS.holderType)
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
  assertComponent('Tipo de scope', scope.type, IDENTITY_LIMITS.scopeType)
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
  assertComponent('Tipo de scope', scopeType, IDENTITY_LIMITS.scopeType)
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
 * (`scope#parent`, `role_binding#assignee`, `deny_binding#denied`…). Un
 * permiso llamado `parent` invalidaría el modelo entero (S14): se rechaza en
 * el núcleo, para ambos drivers, no el día de la migración.
 */
export const RESERVED_SLUGS: ReadonlySet<string> = new Set([
  'parent',
  'binding',
  'ancestor',
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
    throw new InvalidSlugError(
      `Slug de ${kind} inválido: '${slug}' supera los ${MAX_SLUG_LENGTH} caracteres ` +
        `(50 de una relación FGA menos el prefijo derivado más largo)`
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

export function isValidSlug(kind: SlugKind, slug: string): boolean {
  try {
    assertValidSlug(kind, slug)
    return true
  } catch {
    return false
  }
}

/* ── Punto de entrada único ─────────────────────────────────────────────── */

export interface IdentityParts {
  subject?: SubjectRef
  scope?: ScopeRef
  scopeType?: string
  role?: string
  permission?: string
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
  if ('role' in parts) assertValidSlug('rol', parts.role)
  if ('permission' in parts) assertValidSlug('permiso', parts.permission)
}
