import db from '@adonisjs/lucid/services/db'
import { AuthorizationConfigError, TooManyScopesError, UnsupportedDialectError } from './errors.js'
import { assertScope, assertScopeType } from './identity.js'
import { guardSql } from './drivers/backend_guard.js'
import { APP_SCOPE_TYPE } from './types.js'
import type { ScopeDescendantsResolver, ScopeRef } from './types.js'

/**
 * `descendantsOf` opt-in sobre una tabla del consumidor con columna padre
 * (2.1, B2). Genera UNA CTE recursiva (`WITH RECURSIVE`), la misma para
 * PostgreSQL, SQLite y MySQL 8 (2.5 · J3: solo cambia el carácter con el que
 * se citan los identificadores); cualquier otro dialecto lanza 500
 * `E_AUTHZ_UNSUPPORTED_DIALECT` en la primera llamada hasta que la suite lo
 * observe. El paquete sigue sin conocer el árbol del consumidor: aquí solo
 * se le dice qué tabla y qué columnas lo guardan.
 *
 *   scopes: {
 *     resolveAncestors,
 *     descendantsOf: sqlDescendantsOf({
 *       table: 'organization_nodes', uuidColumn: 'uuid', parentColumn: 'parent_uuid', typeColumn: 'kind',
 *     }),
 *   }
 *
 * Cotas: la consulta lee como mucho `maxNodes + 1` filas (`LIMIT`) y no baja
 * más de `maxNodes + 1` niveles, así que un ciclo en la tabla termina Y se
 * nota: un ciclo alcanzable produce al menos una fila por nivel, es decir
 * más de `maxNodes` ⇒ 422 `E_AUTHZ_TOO_MANY_SCOPES` con «posible ciclo» en
 * el mensaje (con `depth < maxNodes` un ciclo de dos nodos devolvía
 * `maxNodes - 1` filas duplicadas en silencio). No hay segunda barrera por
 * uuid repetido: con esta profundidad un ciclo NUNCA cabe en `maxNodes`
 * filas, así que era código muerto (G1, CR6). Nunca una lista parcial. Un
 * scope que no está en la tabla ⇒ `null`. `scopeType` pasa por la gramática
 * de identidad al construir (auditor 11).
 */
export interface SqlDescendantsOptions {
  table: string
  uuidColumn: string
  /** Columna con el uuid del padre; `NULL` = el nodo cuelga de `app`. */
  parentColumn: string
  /** Columna con el `ScopeRef.type` de cada fila. Excluyente con `scopeType`. */
  typeColumn?: string
  /** Tipo fijo de todos los nodos de la tabla (sin columna de tipo). Excluyente con `typeColumn`. */
  scopeType?: string
  /** Cota propia del helper: se aplica `min(maxNodes del llamante, esta)`. */
  maxNodes?: number
  /** Nombre de la conexión Lucid (default: la primaria). */
  connection?: string
  /** Deadline de cada consulta en ms (default 5000): vencido ⇒ 503. */
  timeoutMs?: number
}

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/
/** Dialecto → carácter con el que cita identificadores (MySQL: backtick; el resto: comilla doble ANSI). */
const QUOTE_BY_DIALECT: Record<string, '"' | '`'> = {
  'postgres': '"',
  'sqlite3': '"',
  'better-sqlite3': '"',
  'mysql': '`',
  'mysql2': '`',
}
const DEFAULT_TIMEOUT_MS = 5_000

function identifier(kind: string, value: unknown): string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    throw new AuthorizationConfigError(
      `sqlDescendantsOf: ${kind} '${String(value)}' no es un identificador SQL simple (letras, dígitos y _); ` +
        `nada que no lo sea se interpola en la consulta.`
    )
  }
  return value
}

/** Lo que necesita del `db` de Lucid; inyectable para probar el dialecto sin servidor. */
interface DatabaseLike {
  connection(name?: string): any
}

export function sqlDescendantsOf(
  options: SqlDescendantsOptions,
  database: DatabaseLike = db
): ScopeDescendantsResolver {
  const table = identifier('table', options.table)
  const uuidCol = identifier('uuidColumn', options.uuidColumn)
  const parentCol = identifier('parentColumn', options.parentColumn)
  if ((options.typeColumn === undefined) === (options.scopeType === undefined)) {
    throw new AuthorizationConfigError(
      'sqlDescendantsOf: declara exactamente uno de typeColumn (el tipo viene de la fila) o scopeType (tipo fijo).'
    )
  }
  const typeCol = options.typeColumn === undefined ? null : identifier('typeColumn', options.typeColumn)
  const fixedType = options.scopeType ?? null
  if (fixedType !== null) {
    // Es identidad de scope (minúsculas, ≤ 20, sin separadores) y nunca la
    // raíz: `app` no tiene fila ni uuid.
    try {
      assertScopeType(fixedType)
    } catch (error) {
      throw new AuthorizationConfigError(`sqlDescendantsOf: scopeType inválido: ${(error as Error).message}`)
    }
    if (fixedType === APP_SCOPE_TYPE) {
      throw new AuthorizationConfigError("sqlDescendantsOf: scopeType no puede ser 'app' (la raíz no tiene fila)")
    }
  }
  if (options.maxNodes !== undefined && !(Number.isInteger(options.maxNodes) && options.maxNodes >= 1)) {
    throw new AuthorizationConfigError(
      `sqlDescendantsOf: maxNodes debe ser un entero >= 1 (llegó ${String(options.maxNodes)})`
    )
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const connectionName = options.connection

  /** El SQL por carácter de cita (se construye una vez por dialecto). */
  const statements = new Map<string, { exists: string; walk: string }>()
  function statementsFor(quote: '"' | '`'): { exists: string; walk: string } {
    let built = statements.get(quote)
    if (built) return built
    const q = (name: string) => `${quote}${name}${quote}`
    const typeSelect = typeCol ? `t.${q(typeCol)}` : 'NULL'
    // MySQL corta una CTE recursiva a `cte_max_recursion_depth` iteraciones
    // (1000 por defecto) con el error 3636: con una cota mayor, un ciclo
    // salía como 503 «backend caído» en vez del 422 «posible ciclo» del
    // contrato (2.5 · J3, hallazgo). El hint `SET_VAR` sube el tope SOLO para
    // esta sentencia, a la cota + 1 que la propia consulta ya impone con
    // `depth < ?`; el placeholder `%DEPTH%` se rellena con ese entero (nunca
    // con entrada del consumidor). Los demás dialectos no tienen tope.
    const hint = quote === '`' ? '/*+ SET_VAR(cte_max_recursion_depth = %DEPTH%) */ ' : ''
    built = {
      exists: `SELECT 1 AS ${q('ok')} FROM ${q(table)} t WHERE %WHERE% LIMIT 1`,
      walk:
        `WITH RECURSIVE ${q('authz_descendants')}(${q('uuid')}, ${q('type')}, ${q('depth')}) AS (` +
        ` SELECT t.${q(uuidCol)}, ${typeSelect}, 1 FROM ${q(table)} t WHERE ` +
        `%ANCHOR%` +
        ` UNION ALL` +
        ` SELECT t.${q(uuidCol)}, ${typeSelect}, d.${q('depth')} + 1 FROM ${q(table)} t` +
        ` JOIN ${q('authz_descendants')} d ON t.${q(parentCol)} = d.${q('uuid')} WHERE d.${q('depth')} < ?` +
        `) SELECT ${hint}${q('uuid')}, ${q('type')} FROM ${q('authz_descendants')} LIMIT ?`,
    }
    statements.set(quote, built)
    return built
  }

  return async (scope, { maxNodes }) => {
    assertScope(scope)
    const cap = Math.min(maxNodes, options.maxNodes ?? Infinity)
    if (!(Number.isInteger(cap) && cap >= 1)) {
      throw new AuthorizationConfigError(`sqlDescendantsOf: maxNodes debe ser un entero >= 1 (llegó ${String(maxNodes)})`)
    }
    const connection = database.connection(connectionName)
    const dialect: string = connection?.dialect?.name ?? connection?.client?.driverName ?? 'desconocido'
    const quote = QUOTE_BY_DIALECT[dialect]
    if (!quote) {
      throw new UnsupportedDialectError(
        `sqlDescendantsOf: dialecto '${dialect}' sin observación en la suite (hoy: PostgreSQL, MySQL 8 y SQLite). ` +
          `Implementa scopes.descendantsOf a mano para este motor.`
      )
    }
    const q = (name: string) => `${quote}${name}${quote}`
    const sql = statementsFor(quote)
    const query = (operation: string, text: string, bindings: unknown[]) =>
      guardSql('sqlDescendantsOf', operation, timeoutMs, () => connection.rawQuery(text, bindings))
    // Forma del resultado crudo por cliente: pg `{ rows }`, sqlite `rows[]`,
    // mysql2 `[rows[], fields[]]` (2.5 · J3).
    const rowsOf = (result: any): any[] => {
      if (Array.isArray(result)) {
        return result.length === 2 && Array.isArray(result[0]) && Array.isArray(result[1]) ? result[0] : result
      }
      return result?.rows ?? []
    }

    let anchor: string
    let bindings: unknown[]
    if (scope.type === APP_SCOPE_TYPE) {
      anchor = `t.${q(parentCol)} IS NULL`
      bindings = []
    } else {
      if (fixedType !== null && scope.type !== fixedType) return null
      const where = `t.${q(uuidCol)} = ?` + (typeCol ? ` AND t.${q(typeCol)} = ?` : '')
      const args = typeCol ? [scope.uuid, scope.type] : [scope.uuid]
      const exists = rowsOf(await query('descendantsOf.exists', sql.exists.replace('%WHERE%', where), args))
      if (exists.length === 0) return null
      anchor = `t.${q(parentCol)} = ?`
      bindings = [scope.uuid]
    }
    const walk = sql.walk.replace('%ANCHOR%', anchor).replace('%DEPTH%', String(cap + 2))
    const rows = rowsOf(await query('descendantsOf', walk, [...bindings, cap + 1, cap + 1]))
    if (rows.length > cap) {
      throw new TooManyScopesError(
        `sqlDescendantsOf: ${scope.type}:${scope.uuid ?? ''} tiene más de ${cap} descendientes — o la tabla tiene un ` +
          `posible ciclo (un ciclo alcanzable produce una fila por nivel hasta la cota); no se devuelve una lista parcial.`
      )
    }
    return rows.map((row: any): ScopeRef => ({ type: typeCol ? row.type : fixedType!, uuid: row.uuid }))
  }
}
