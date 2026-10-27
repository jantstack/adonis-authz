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
  /** Lo que devuelve el SELECT de `select(...)` → `Date | null` (`null` = columna NULL); presente e ilegible LANZA (RR-2). */
  fromDb(value: unknown): Date | null
}

const MYSQL_DIALECTS = new Set(['mysql', 'mysql2'])

/** ¿Es MySQL? (el mismo conjunto que decide el codec). */
export function isMysqlDialect(connection: any): boolean {
  return MYSQL_DIALECTS.has(dialectOf(connection))
}

/** Nombre del dialecto de una conexión de Lucid (`dialect.name`; fallback: el driver de knex). */
export function dialectOf(connection: any): string {
  return connection?.dialect?.name ?? connection?.client?.driverName ?? 'desconocido'
}

/**
 * ¿Es SQLite? (3E · Q5) Lucid nombra su dialecto `better-sqlite3` —no
 * empieza por `sqlite`—, así que un `startsWith('sqlite')` no reconocía el
 * SQLite real de esta máquina ni el de CI. Donde eso decide una BARRERA (el
 * cerrojo del catálogo, que SQLite no necesita porque ya serializa sus
 * escrituras) el fallo es silencioso: solo era inocuo porque knex compila
 * `forUpdate` a vacío en sqlite3.
 */
export function isSqliteDialect(connection: any): boolean {
  const name = dialectOf(connection)
  return name.startsWith('sqlite') || name === 'better-sqlite3'
}

/** `2030-06-15T12:00:00.000Z` → `2030-06-15 12:00:00.000` (UTC, con milisegundos). */
export function formatUtcDatetime(at: Date): string {
  return at.toISOString().slice(0, 23).replace('T', ' ')
}

/**
 * Una caducidad PRESENTE que no se puede leer (rotación 3 · cierre 2, RR-2 del re-ataque): es un error, nunca «sin
 * caducidad». Hasta aquí `parseUtcDatetime` y el codec identidad devolvían `null` para una fecha que no lo es —la fecha
 * cero `0000-00-00` que MySQL deja con un `sql_mode` no estricto, un `-infinity` de PostgreSQL, un texto en SQLite—, y
 * `null` es PERMANENTE para quien lo consume: el re-grant la conservaba como «sin caducidad», `reconcile --to=openfga`
 * y el export de `relations:reconcile` escribían una tupla permanente para una fila que en SQL ya no concede. Ahora es
 * 500 `E_AUTHZ_INTERNAL` en la lectura: lo que lee la caducidad para reescribirla o migrarla se para antes de escribir
 * (`reconcile --to=database` incluido, que antes la reescribía con la del origen: E1, declarado en «Limits»). La DECISIÓN
 * de SQL (`expires_at > now`) NO pasa por aquí y no es fail-closed para todo valor (re-ataque 2 · C1, corregido): no
 * concede con la fecha cero de MySQL ni con `-infinity`, pero SÍ concede —para siempre— con `+infinity` en PostgreSQL y
 * con un TEXTO en SQLite (`TEXT > INTEGER` es verdadero), aunque sea una fecha pasada. El paquete nunca escribe esos
 * valores; está declarado en «Limits» con su receta (revoke + grant) y el arreglo de fondo va a 2.6. `null`/`undefined` siguen siendo «sin
 * caducidad»: es lo que guarda una columna NULL.
 */
function unreadableExpiry(value: unknown): AuthorizationInternalError {
  const shown = value instanceof Date ? 'Invalid Date' : JSON.stringify(typeof value === 'string' ? value.slice(0, 40) : String(value))
  return new AuthorizationInternalError(
    `expires_at ilegible (${shown}): una caducidad presente que no es un instante es un error, nunca «sin caducidad». ` +
      'Corrige la fila (o bórrala) antes de releerla, migrarla o reescribirla.'
  )
}

/**
 * `2030-06-15 12:00:00.000000` (UTC, hasta microsegundos) → `Date`. Lo que no es una fecha REAL lanza
 * `unreadableExpiry` (RR-2): la fecha cero, un mes 13, un 31 de febrero o un `24:00:00` (que `Date` desbordaría en
 * silencio al día o al mes siguiente) no se leen como nada.
 */
export function parseUtcDatetime(value: string): Date {
  const match = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?$/.exec(value.trim())
  if (!match) throw unreadableExpiry(value)
  const [, year, month, day, hour, minute, second, fraction] = match
  const wall = `${year}-${month}-${day}T${hour}:${minute}:${second}`
  const date = new Date(`${wall}.${(fraction ?? '').padEnd(3, '0').slice(0, 3)}Z`)
  // Ida y vuelta: `Date` acepta `2030-02-31` (⇒ 3 de marzo) y `24:00:00` (⇒ día siguiente); una fecha real vuelve igual.
  if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 19) !== wall) throw unreadableExpiry(value)
  return date
}

const identityCodec: ExpiryCodec = {
  toDb: (expiresAt) => expiresAt,
  bind: (at) => at,
  select: (column, alias) => (alias && alias !== column ? `${column} as ${alias}` : column),
  // RR-2: `toExpiryDate` da `null` para lo que no es fecha (y deja pasar un `Date` inválido); aquí eso es un error.
  fromDb: (value) => {
    const date = toExpiryDate(value)
    if (date === null ? !(value === null || value === undefined || value === '') : Number.isNaN(date.getTime())) {
      throw unreadableExpiry(value)
    }
    return date
  },
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
