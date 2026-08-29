import db from '@adonisjs/lucid/services/db'
import { AuthorizationInternalError } from '../errors.js'
import { toExpiryDate } from '../expiry.js'

/**
 * Cómo viaja `expires_at` entre el driver `database` y cada motor SQL
 * (2.5-B · K2, auditor 🟠 2).
 *
 * El problema: en MySQL `expires_at` es `DATETIME(3)`, que NO guarda zona, y
 * `mysql2` serializa y parsea los `Date` con el `TZ` del proceso (`timezone:
 * 'local'`, su default). Un proceso en UTC escribía `12:00:00` para
 * `12:00Z`; uno en Caracas leía ese `12:00:00` como `16:00Z`: la asignación
 * caducaba 4 h tarde para él (y 9 h antes para uno en Tokio). Dentro de un
 * solo proceso el ida y vuelta era exacto, que es lo único que el juez podía
 * ver; el defecto solo aparece con dos procesos, que es el despliegue normal.
 *
 * La decisión: el driver NO depende de la config de la conexión. En MySQL
 * escribe la caducidad como CADENA UTC explícita (`YYYY-MM-DD HH:mm:ss.SSS`),
 * compara con `now` formateado igual y la LEE con `DATE_FORMAT(…)` (una
 * cadena, que se parsea como UTC), así que `timezone`, `dateStrings` o el
 * `TZ` del proceso no intervienen. En PostgreSQL la columna es
 * `timestamptz(3)` (instante absoluto: el `Date` basta) y en SQLite un
 * número; ahí el codec es la identidad. Lo fija `tests/expiry_timezone.spec`
 * con procesos hijos reales en `TZ` distinta sobre la misma base.
 */
export interface ExpiryCodec {
  /** Valor con el que se ESCRIBE la columna (`insert`/`update`). */
  toDb(expiresAt: Date | null): unknown
  /** Valor con el que se COMPARA (`expires_at > ?`) para un instante dado. */
  bind(at: Date): unknown
  /** Expresión de SELECT que devuelve la columna de forma que `fromDb` la lea sin depender del cliente. */
  select(column: string, alias?: string): unknown
  /** Lo que devuelve el SELECT de `select(...)` → `Date | null`. */
  fromDb(value: unknown): Date | null
}

const MYSQL_DIALECTS = new Set(['mysql', 'mysql2'])

/** Nombre del dialecto de una conexión de Lucid (`dialect.name`; fallback: el driver de knex). */
export function dialectOf(connection: any): string {
  return connection?.dialect?.name ?? connection?.client?.driverName ?? 'desconocido'
}

/** `2030-06-15T12:00:00.000Z` → `2030-06-15 12:00:00.000` (UTC, con milisegundos). */
export function formatUtcDatetime(at: Date): string {
  return at.toISOString().slice(0, 23).replace('T', ' ')
}

/** `2030-06-15 12:00:00.000000` (UTC, hasta microsegundos) → `Date`, o `null` si no es una fecha. */
export function parseUtcDatetime(value: string): Date | null {
  const match = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?$/.exec(value.trim())
  if (!match) return null
  const millis = (match[3] ?? '').padEnd(3, '0').slice(0, 3)
  const date = new Date(`${match[1]}T${match[2]}.${millis}Z`)
  return Number.isNaN(date.getTime()) ? null : date
}

const identityCodec: ExpiryCodec = {
  toDb: (expiresAt) => expiresAt,
  bind: (at) => at,
  select: (column, alias) => (alias && alias !== column ? `${column} as ${alias}` : column),
  fromDb: toExpiryDate,
}

function mysqlCodec(connection: any): ExpiryCodec {
  const raw = (sql: string, bindings: unknown[]) =>
    typeof connection?.raw === 'function' ? connection.raw(sql, bindings) : db.raw(sql, bindings)
  return {
    toDb: (expiresAt) => (expiresAt ? formatUtcDatetime(expiresAt) : null),
    bind: (at) => formatUtcDatetime(at),
    select: (column, alias) => raw(`DATE_FORMAT(??, '%Y-%m-%d %H:%i:%s.%f') as ??`, [column, alias ?? column.split('.').pop()!]),
    fromDb: (value) => {
      if (value === null || value === undefined || value === '') return null
      if (typeof value === 'string') return parseUtcDatetime(value)
      // Un `Date` aquí es que la lectura no pasó por `select(...)` y el
      // cliente ya la interpretó con SU zona: eso es exactamente lo que este
      // codec existe para impedir. Ruidoso, nunca una caducidad corrida.
      throw new AuthorizationInternalError(
        `expires_at llegó como ${value instanceof Date ? 'Date' : typeof value} en MySQL: la lectura tiene que pasar por ExpiryCodec.select(...) (DATE_FORMAT) para no depender de la zona del cliente`
      )
    },
  }
}

/**
 * El codec para una conexión de Lucid (default: la primaria). Se decide por
 * dialecto una vez por driver; MySQL es el único que necesita algo distinto
 * de la identidad.
 */
export function sqlExpiryCodec(connection: any = db.connection()): ExpiryCodec {
  return MYSQL_DIALECTS.has(dialectOf(connection)) ? mysqlCodec(connection) : identityCodec
}
