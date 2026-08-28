import db from '@adonisjs/lucid/services/db'
import { AuthorizationConfigError, ScopeCycleError, TooManyScopesError, UnsupportedDialectError } from './errors.js'
import { assertScope } from './identity.js'
import { guardSql } from './drivers/backend_guard.js'
import { APP_SCOPE_TYPE } from './types.js'
import type { ScopeDescendantsResolver, ScopeRef } from './types.js'

/**
 * `descendantsOf` opt-in sobre una tabla del consumidor con columna padre
 * (2.1, B2). Genera UNA CTE recursiva (`WITH RECURSIVE`), la misma para
 * PostgreSQL y SQLite; MySQL (y cualquier otro dialecto) lanza 500
 * `E_AUTHZ_UNSUPPORTED_DIALECT` en la primera llamada hasta que la suite lo
 * observe (Fase 2.5). El paquete sigue sin conocer el árbol del consumidor:
 * aquí solo se le dice qué tabla y qué columnas lo guardan.
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
 * más de `maxNodes` ⇒ 422 `E_AUTHZ_TOO_MANY_SCOPES` (con `depth < maxNodes`
 * un ciclo de dos nodos devolvía `maxNodes - 1` filas duplicadas en
 * silencio). Un uuid repetido en el resultado es la segunda barrera (422
 * `E_AUTHZ_SCOPE_CYCLE`). Nunca una lista parcial. Un scope que no está en
 * la tabla ⇒ `null`.
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
const SUPPORTED_DIALECTS = new Set(['postgres', 'sqlite3', 'better-sqlite3'])
const DEFAULT_TIMEOUT_MS = 5_000

function identifier(kind: string, value: unknown): string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    throw new AuthorizationConfigError(
      `sqlDescendantsOf: ${kind} '${String(value)}' no es un identificador SQL simple (letras, dígitos y _); ` +
        `nada que no lo sea se interpola en la consulta.`
    )
  }
  return `"${value}"`
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
  if (options.maxNodes !== undefined && !(Number.isInteger(options.maxNodes) && options.maxNodes >= 1)) {
    throw new AuthorizationConfigError(
      `sqlDescendantsOf: maxNodes debe ser un entero >= 1 (llegó ${String(options.maxNodes)})`
    )
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const connectionName = options.connection

  const typeSelect = typeCol ? `t.${typeCol}` : 'NULL'
  const sql =
    `WITH RECURSIVE "authz_descendants"("uuid", "type", "depth") AS (` +
    ` SELECT t.${uuidCol}, ${typeSelect}, 1 FROM ${table} t WHERE ` +
    `%ANCHOR%` +
    ` UNION ALL` +
    ` SELECT t.${uuidCol}, ${typeSelect}, d."depth" + 1 FROM ${table} t` +
    ` JOIN "authz_descendants" d ON t.${parentCol} = d."uuid" WHERE d."depth" < ?` +
    `) SELECT "uuid", "type" FROM "authz_descendants" LIMIT ?`

  return async (scope, { maxNodes }) => {
    assertScope(scope)
    const cap = Math.min(maxNodes, options.maxNodes ?? Infinity)
    if (!(Number.isInteger(cap) && cap >= 1)) {
      throw new AuthorizationConfigError(`sqlDescendantsOf: maxNodes debe ser un entero >= 1 (llegó ${String(maxNodes)})`)
    }
    const connection = database.connection(connectionName)
    const dialect: string = connection?.dialect?.name ?? connection?.client?.driverName ?? 'desconocido'
    if (!SUPPORTED_DIALECTS.has(dialect)) {
      throw new UnsupportedDialectError(
        `sqlDescendantsOf: dialecto '${dialect}' sin observación en la suite (hoy: PostgreSQL y SQLite). ` +
          `Implementa scopes.descendantsOf a mano para este motor.`
      )
    }
    const query = (operation: string, text: string, bindings: unknown[]) =>
      guardSql('sqlDescendantsOf', operation, timeoutMs, () => connection.rawQuery(text, bindings))
    const rowsOf = (result: any): any[] => (Array.isArray(result) ? result : (result?.rows ?? []))

    let anchor: string
    let bindings: unknown[]
    if (scope.type === APP_SCOPE_TYPE) {
      anchor = `t.${parentCol} IS NULL`
      bindings = []
    } else {
      if (fixedType !== null && scope.type !== fixedType) return null
      const where = `t.${uuidCol} = ?` + (typeCol ? ` AND t.${typeCol} = ?` : '')
      const args = typeCol ? [scope.uuid, scope.type] : [scope.uuid]
      const exists = rowsOf(
        await query('descendantsOf.exists', `SELECT 1 AS "ok" FROM ${table} t WHERE ${where} LIMIT 1`, args)
      )
      if (exists.length === 0) return null
      anchor = `t.${parentCol} = ?`
      bindings = [scope.uuid]
    }
    const rows = rowsOf(await query('descendantsOf', sql.replace('%ANCHOR%', anchor), [...bindings, cap + 1, cap + 1]))
    if (rows.length > cap) {
      throw new TooManyScopesError(
        `sqlDescendantsOf: ${scope.type}:${scope.uuid ?? ''} tiene más de ${cap} descendientes (o la tabla tiene un ciclo); ` +
          `no se devuelve una lista parcial.`
      )
    }
    const seen = new Set<string>()
    for (const row of rows) {
      if (seen.has(row.uuid) || row.uuid === scope.uuid) {
        throw new ScopeCycleError(
          `sqlDescendantsOf: el uuid '${row.uuid}' aparece dos veces bajo ${scope.type}:${scope.uuid ?? ''}: la tabla tiene un ciclo.`
        )
      }
      seen.add(row.uuid)
    }
    return rows.map((row: any): ScopeRef => ({ type: typeCol ? row.type : fixedType!, uuid: row.uuid }))
  }
}
