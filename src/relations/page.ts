/**
 * **La página de relaciones, en UN sitio** (lote «antes de RC» · 7.4, opción 4 del juez —`loteRC-74-paginacion-juez.md`,
 * 88,5/100—, decisión del dueño 2026-10-17 (7.4)). Dos reglas, compartidas por el manager, los dos drivers y el doble:
 *
 *  1. **Los `list*` no paginan en 2.5.** `listObjects`/`listSubjects`/`listDenies`/`membersOf` ya no tienen `page` en
 *     la firma. `undefined` (ausente o explícito) es «sin página»; CUALQUIER otro valor —`null`, `{}`, `{ after: '' }`,
 *     `{ limit: 0 }`…— que llegue por JS o `as any` ⇒ 500 `E_AUTHZ_UNSUPPORTED` nombrando la operación, con CERO
 *     llamadas al backend (`assertNoListPage`). Se mira `!== undefined`, jamás `arguments.length` (RC74-3: quien reenvía
 *     un opcional vacío no se rompe). Orden de las guardas (RC74-5): F-05 y partición ANTES; la página, la última.
 *  2. **`enumerate*` valida su página** (`assertEnumeratePage`): `limit` entero ≥ 1 o 422 `E_AUTHZ_INVALID_PAGE`
 *     (`NaN` generaba una consulta SIN `LIMIT`, tester H2), por encima de `RELATIONS_ENUMERATE_MAX_LIMIT` se RECORTA
 *     (`enumerateLimit`: con cursor, sin pérdida; declarado en «Limits»); `after` cadena no vacía o 422, y según el
 *     cursor que el driver emite: `uuid` (`database`: el uuid canónico de la fila; un cursor ajeno era un 503 en PG y
 *     un fin silencioso en MySQL/SQLite, H3), `none` (`openfga` y el doble no emiten cursor ⇒ 500) u `opaque` (el
 *     manager, que no sabe qué emite el driver: solo la forma).
 *
 * Lo que NO hace (H3 a medias, a propósito): atar el cursor a su partición —un cursor de A reutilizado en B salta
 * filas— exige un sobre de cursor; es del lote C / 2.6.
 */
import { InvalidRelationPageError, UnsupportedOperationError } from '../errors.js'
import { isCanonicalUuid } from '../identity.js'
import type { RelationPage } from '../types.js'

/** Tamaño de página de `enumerate*` en `database` cuando no se pide `limit`. */
export const RELATIONS_ENUMERATE_DEFAULT_LIMIT = 100
/** Techo de `limit` en `enumerate*` de `database`: por encima se RECORTA (con cursor, sin pérdida), no es un error. */
export const RELATIONS_ENUMERATE_MAX_LIMIT = 1_000

/** Regla 1: un `list*` de relaciones con página (cualquier valor distinto de `undefined`) ⇒ 500 sin tocar el backend. */
export function assertNoListPage(operation: string, page: unknown, driver: string): void {
  if (page !== undefined) throw UnsupportedOperationError.listPage(operation, driver)
}

/** Qué cursor emite quien valida: `uuid` (database), `none` (openfga, el doble), `opaque` (el manager). */
export type EnumerateCursorKind = 'uuid' | 'none' | 'opaque'

/**
 * Regla 2: la forma de la página de `enumerate*`. `undefined` = sin página. Devuelve una COPIA de lo validado (cada campo
 * se lee UNA vez: un getter que cambia entre la validación y el uso no cuela un `NaN` como `limit`, ⚪ 1 del auditor 7.x);
 * quien consulta usa la copia, jamás la página original.
 */
export function assertEnumeratePage(
  operation: string,
  page: unknown,
  cursor: EnumerateCursorKind,
  driver: string
): RelationPage | undefined {
  if (page === undefined) return undefined
  if (page === null || typeof page !== 'object' || Array.isArray(page)) {
    throw new InvalidRelationPageError(`${operation}: la página tiene que ser un objeto { limit?, after? } (llegó ${describe(page)}).`)
  }
  const { limit, after } = page as { limit?: unknown; after?: unknown }
  if (limit !== undefined && !(typeof limit === 'number' && Number.isInteger(limit) && limit >= 1)) {
    throw new InvalidRelationPageError(
      `${operation}: page.limit tiene que ser un entero ≥ 1 (llegó ${describe(limit)}); por encima de ` +
        `${RELATIONS_ENUMERATE_MAX_LIMIT} se recorta, no es un error.`
    )
  }
  if (after === undefined) return limit === undefined ? {} : { limit }
  if (typeof after !== 'string' || after.length === 0) {
    throw new InvalidRelationPageError(`${operation}: page.after tiene que ser el cursor que devolvió la página anterior (llegó ${describe(after)}).`)
  }
  if (cursor === 'none') throw UnsupportedOperationError.enumerateCursor(operation, driver)
  if (cursor === 'uuid' && !isCanonicalUuid(after)) {
    throw new InvalidRelationPageError(
      `${operation}: page.after no es un cursor de este driver ('${driver}' emite el uuid canónico de la última fila leída); ` +
        `pasa el cursor que devolvió la página anterior, sin tocarlo.`
    )
  }
  return limit === undefined ? { after } : { limit, after }
}

/** El `limit` efectivo de `enumerate*` (tras `assertEnumeratePage`): el default, o el pedido recortado al techo. */
export function enumerateLimit(page: { limit?: number } | undefined): number {
  return Math.min(page?.limit ?? RELATIONS_ENUMERATE_DEFAULT_LIMIT, RELATIONS_ENUMERATE_MAX_LIMIT)
}

function describe(value: unknown): string {
  if (typeof value === 'string') return `'${value.slice(0, 40)}'`
  if (typeof value === 'number') return String(value)
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'un array'
  return typeof value
}
