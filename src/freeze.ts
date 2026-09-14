import db from '@adonisjs/lucid/services/db'
import { guardSql, withDeadline } from './shared/backend_guard.js'
import {
  AuthorizationBackendError,
  AuthorizationBackendTimeoutError,
  AuthorizationFrozenError,
  UnsupportedDialectError,
} from './errors.js'
import { CATALOG_VERSION_TABLE } from './catalog/catalog_cache.js'
import { dialectOf, isMysqlDialect, isSqliteDialect } from './shared/sql_expiry.js'

/**
 * El **freeze DURABLE** (3b-7; decisión del dueño del 2026-08-31 (3b):
 * B + E-analista). Primitivas SQL puras; la policy (quién congela, el
 * anidado, el contexto del operador) vive en el manager.
 *
 * El freeze cuelga de la fila `id = 2` de `authz_catalog_version` — la señal
 * entre procesos que el paquete ya usa (invariante 14). La colocación está
 * MEDIDA (panel 3, analista §4.1): en la fila `id = 1` la renovación del
 * lease espera al `FOR UPDATE` de `withAuthzCatalogWrite` (816 ms en PG /
 * 805 en MySQL con un sync de 800 ms); en su propia fila, 10-12 ms. Y la
 * consulta de la barrera es PROPIA y sin memo (juez C2): colgarse del memo
 * del catálogo haría del freeze «una ventana acotada de freeze que todavía
 * no aplica» con `catalogRevalidate: { everyMs }`. El coste que se publica
 * es el medido: +0,14 ms p50 por escritura (PG; +0,11 MySQL), 0 por
 * `authorize`.
 *
 * Las tres reglas del protocolo:
 *  - **Token de dueño** (`fence` + `holder`): `acquire` sube el fence y solo
 *    hay UN freeze vivo a la vez; `release`/`renew` son condicionales por
 *    token, así que un `unfreeze` ajeno o rezagado es un no-op (auditor
 *    A1.3: el `finally` de una ventana interior ya no puede levantar la
 *    barrera de otra).
 *  - **Lease**: `untilMs` en ms de PARED (el reloj del config, el mismo que
 *    decide caducidades). Vencido ⇒ el freeze deja de estar vivo y la flota
 *    vuelve a escribir SOLA — tras un `SIGKILL` nadie limpia nada (medido:
 *    2 527 ms con lease de 3 000). `untilMs: null` = sin caducidad (la
 *    ventana del operador).
 *  - **Fence publicado**: la renovación exige `freeze_until_ms > now`; una
 *    renovación que toca 0 filas significa que el lease se PERDIÓ a mitad
 *    (pausa de GC, base caída más tiempo que el lease) y quien lo sostiene
 *    lo marca `lapsed` — la pasada no se certifica (juez C4).
 *
 * La fila ausente (o las columnas: una base migrada con el stub < 2.3) es
 * **503 «migración 2.0 no aplicada»** en toda escritura, jamás «no
 * congelado»: el mismo patrón que la fila `id = 1` del memo. Un upsert
 * perezoso desde la barrera sería una escritura en el camino de lectura,
 * fuera de `withAuthzCatalogWrite`, y una carrera gratis.
 *
 * **La barrera se lee SIEMPRE por la conexión del motor, nunca por un
 * cliente del llamante** (L-1 · 🟠 8, dictamen del juez del panel `{trx}`).
 * Hasta L-1 `readFreezeRow` aceptaba `client` —la transacción del consumidor,
 * «para no interbloquear un pool de 1»— y eso convertía la AUTORIDAD en una
 * decisión del llamante: un cliente que responde «no congelado», o el
 * snapshot REPEATABLE READ de una transacción abierta ANTES del freeze, dejaba
 * entrar la escritura (medido: auditor C1 en SQLite; MySQL/PG en
 * `freeze.spec.ts`). La regla: *la escritura va por tu transacción; la
 * autoridad que decide si puedes escribir, nunca*. El precio, decidido por el
 * dueño: `{ transaction }` exige pool ≥ 2 — con pool 1 la lectura de la
 * barrera espera una conexión que el llamante sostiene y sale **503
 * `E_AUTHZ_BACKEND_TIMEOUT` al vencer SU deadline** (`withDeadline`, porque
 * el `timeout()` de knex NO cubre la espera del pool: medido, 60 s), jamás
 * un cuelgue ni un bypass.
 */

/** La fila del freeze durable (la `id = 1` es la versión del catálogo). */
export const FREEZE_ROW_ID = 2

/** Lease por defecto (analista §2.3): 15 s renovados cada 5 s cubren cualquier pausa razonable y acotan la parada tras un `SIGKILL`. */
export const DEFAULT_FREEZE_LEASE_MS = 15_000

const DEFAULT_FREEZE_TIMEOUT_MS = 5_000

/** Quién congela: el dueño va escrito en la fila (`<kind>:<pid>:<hex>`). */
export type FreezeKind = 'operator' | 'reconcile' | 'platform'

/** El token del dueño: lo devuelve `freeze()` y es lo ÚNICO que levanta o renueva ese freeze. */
export interface FreezeToken {
  /** Número de generación: sube en cada `acquire`, nunca se reutiliza. */
  fence: number
  /** `<kind>:<pid>:<hex>`: identifica al proceso que congeló. */
  holder: string
}

/** La fila del freeze, tal como está en la base. */
export interface FreezeRow {
  reason: string | null
  holder: string | null
  untilMs: number | null
  fence: number
}

export interface FreezeSqlOptions {
  /** Etiqueta del driver en los errores 503 (default `freeze`). */
  driver?: string
  /**
   * Deadline TOTAL de cada consulta (default 5000), espera del pool incluida:
   * vencido ⇒ 503 `E_AUTHZ_BACKEND_TIMEOUT`. No hay opción para leer por otro
   * cliente: la barrera es autoridad y va por la conexión del motor (L-1).
   */
  timeoutMs?: number
}

function opts(options: FreezeSqlOptions): { driver: string; timeoutMs: number } {
  return { driver: options.driver ?? 'freeze', timeoutMs: options.timeoutMs ?? DEFAULT_FREEZE_TIMEOUT_MS }
}

/**
 * Una consulta del freeze con deadline TOTAL. `guardSql` fija el `timeout()`
 * de knex, que solo cuenta desde que la consulta tiene conexión: si el pool
 * está agotado (el llamante sostiene la única conexión de `:memory:`), la
 * espera la gobierna `acquireConnectionTimeout` (60 s por defecto) — medido,
 * L-1. `withDeadline` cubre también esa espera, así que con pool 1 la
 * barrera responde 503 en `timeoutMs`, no en un minuto.
 */
function freezeSql<T>(driver: string, operation: string, timeoutMs: number, fn: () => Promise<T>): Promise<T> {
  return withDeadline(
    guardSql(driver, operation, timeoutMs, fn),
    timeoutMs,
    () => new AuthorizationBackendTimeoutError(driver, operation, timeoutMs)
  )
}

function missingRow(driver: string): AuthorizationBackendError {
  const error = new AuthorizationBackendError(
    driver,
    'freeze.row',
    new Error(`no hay fila id = ${FREEZE_ROW_ID} en ${CATALOG_VERSION_TABLE}`)
  )
  error.message =
    `${driver}: no se puede leer el freeze compartido (${CATALOG_VERSION_TABLE}, id = ${FREEZE_ROW_ID}). ` +
    `Probablemente la migración 2.0 no está aplicada (la siembra el stub publicado; la receta está en el CHANGELOG). ` +
    `Sin la fila las escrituras NO proceden: tratarla como «no congelado» sería fail-open.`
  return error
}

function toMs(raw: unknown): number | null {
  if (raw === null || raw === undefined) return null
  const value = typeof raw === 'number' ? raw : Number(raw)
  return Number.isFinite(value) ? value : null
}

/**
 * Lee la fila del freeze **por la conexión del motor** (503 clasificado si la
 * base no responde o el pool no da una conexión en `timeoutMs`; 503 «migración
 * no aplicada» si no existe). No acepta cliente: es la autoridad (L-1 · 🟠 8).
 */
export async function readFreezeRow(options: FreezeSqlOptions = {}): Promise<FreezeRow> {
  const { driver, timeoutMs } = opts(options)
  const rows: any[] = await freezeSql(driver, 'freeze.read', timeoutMs, () =>
    db
      .from(CATALOG_VERSION_TABLE)
      .where('id', FREEZE_ROW_ID)
      .select('freeze_reason', 'freeze_holder', 'freeze_until_ms', 'freeze_fence')
  )
  if (rows.length === 0) throw missingRow(driver)
  const row = rows[0]
  const fence = toMs(row.freeze_fence)
  if (fence === null) throw missingRow(driver)
  return {
    reason: row.freeze_reason === null || row.freeze_reason === undefined ? null : String(row.freeze_reason),
    holder: row.freeze_holder === null || row.freeze_holder === undefined ? null : String(row.freeze_holder),
    untilMs: toMs(row.freeze_until_ms),
    fence,
  }
}

/** ¿Está VIVO este freeze en el instante `nowMs`? (motivo puesto y lease sin vencer; `untilMs: null` no vence). */
export function freezeIsLive(row: FreezeRow, nowMs: number): boolean {
  if (row.reason === null) return false
  return row.untilMs === null || row.untilMs > nowMs
}

export interface FreezeBarrierOptions extends FreezeSqlOptions {
  /** Milisegundos de PARED del reloj del config (el mismo que decide caducidades). */
  nowMs: number
}

/**
 * **La barrera del freeze**, la MISMA para los dos motores (roles y
 * relations, L-1 · J1): lee la fila por la conexión del motor y lanza 503
 * `E_AUTHZ_FROZEN` (reintentable) si hay un freeze vivo en `nowMs`. Va
 * delante de TODA escritura, antes de validar identidades o tocar el driver:
 * durante una ventana una escritura no se valida a medias, se rechaza entera.
 * Nunca recibe un cliente del llamante — ver el docblock del módulo.
 */
export async function assertNotFrozenRow(operation: string, options: FreezeBarrierOptions): Promise<void> {
  const row = await readFreezeRow(options)
  if (!freezeIsLive(row, options.nowMs)) return
  const lift = freezeKindOf(row.holder) === 'operator' ? ' (la levanta authz:unfreeze)' : ''
  throw new AuthorizationFrozenError(
    `${operation}: el motor de autorización está congelado (${row.reason})${lift} y no acepta escrituras. ` +
      `Las lecturas siguen funcionando; reintenta esta escritura cuando la ventana termine.`
  )
}

/** El holder con el que se publica una fila con motivo y SIN holder (legada o a mano); también es su token. */
export const UNKNOWN_HOLDER = '?'

/** Prefijo del holder de la ventana del OPERADOR (`freeze()` con `kind: 'operator'`). */
export const OPERATOR_HOLDER_PREFIX = 'operator:'

/**
 * `isOperatorHolder` en SQL, por motor (cierre-2 de alpha.10 · C3): los
 * `OPERATOR_HOLDER_PREFIX.length` primeros CARACTERES de `freeze_holder` igual a
 * `operator:`, sensible a mayúsculas y acentos. SQLite: `substr()` no hereda
 * collation ⇒ `BINARY`. PostgreSQL: `COLLATE "C"` (byte a byte aunque la base
 * declare otra). MySQL: la collation de la columna es la de la tabla (`_ai_ci` por
 * defecto: `OPERATOR:` y `opérator:` serían iguales), así que se compara como
 * BINARIO. El prefijo es ASCII, así que «9 caracteres» y «9 unidades UTF-16» (JS)
 * coinciden siempre que la comparación sea verdadera. Sin `LIKE`: ni comodines ni
 * collation. Cualquier otro dialecto ⇒ 500 `E_AUTHZ_UNSUPPORTED_DIALECT` ANTES de
 * tocar la fila (re-ataque del cierre-2 · ⚪ 3: el `substr` de SQLite en MSSQL
 * sería un error del motor envuelto como 503, que invita a reintentar para siempre).
 */
export function operatorHolderSql(connection: any = db.connection()): { sql: string; bindings: unknown[] } {
  const length = OPERATOR_HOLDER_PREFIX.length
  if (isMysqlDialect(connection)) {
    return { sql: `CAST(SUBSTRING(freeze_holder, 1, ${length}) AS BINARY) = CAST(? AS BINARY)`, bindings: [OPERATOR_HOLDER_PREFIX] }
  }
  if (dialectOf(connection).startsWith('postgres')) {
    return { sql: `substr(freeze_holder, 1, ${length}) COLLATE "C" = ?`, bindings: [OPERATOR_HOLDER_PREFIX] }
  }
  if (isSqliteDialect(connection)) {
    return { sql: `substr(freeze_holder, 1, ${length}) = ?`, bindings: [OPERATOR_HOLDER_PREFIX] }
  }
  throw new UnsupportedDialectError(
    `freeze: dialecto '${dialectOf(connection)}' sin observación en la suite (hoy: PostgreSQL, MySQL 8 y SQLite)`
  )
}

/**
 * Qué pasó al intentar tomar el freeze: `acquired` (con el token), `held` (hay
 * un freeze VIVO de otro dueño) o `expired-operator` (la fila es una ventana de
 * OPERADOR con el lease vencido, que no se pisa). `row` es la fila releída para
 * REDACTAR el error; la decisión ya la tomó el UPDATE.
 */
export type FreezeAcquireOutcome =
  | { status: 'acquired'; token: FreezeToken }
  | { status: 'held'; row: FreezeRow }
  | { status: 'expired-operator'; row: FreezeRow }

/**
 * Toma el freeze si NADIE lo sostiene vivo (condicional y atómico: dos
 * `acquire` a la vez acaban en exactamente uno). Una fila con el lease VENCIDO
 * se toma encima (el dueño murió: la flota vuelve sola) **salvo que sea una
 * ventana de OPERADOR** (cierre del auditor de alpha.10 · R2): esa exclusión va
 * DENTRO del `WHERE` del mismo `UPDATE`, en los tres motores. Hasta el cierre
 * vivía en `freeze()` como «leo la fila, compruebo, tomo», y con un reloj que
 * cruzaba el vencimiento entre la comprobación y el UPDATE la pasada pisaba la
 * ventana del operador sin 503 — el TOCTOU que el atómico existe para cerrar.
 */
export async function acquireFreezeOutcome(
  input: { reason: string; holder: string; untilMs: number | null; nowMs: number },
  options: FreezeSqlOptions = {},
  attempt = 0
): Promise<FreezeAcquireOutcome> {
  const { driver, timeoutMs } = opts(options)
  // Fuera de `freezeSql`: un dialecto no soportado es config (500), no un backend caído (503).
  const operator = operatorHolderSql()
  const updated = await freezeSql(driver, 'freeze.acquire', timeoutMs, () =>
    db
      .from(CATALOG_VERSION_TABLE)
      .where('id', FREEZE_ROW_ID)
      .where((q: any) => {
        // Libre, o con el lease VENCIDO (un dueño muerto no bloquea la toma)…
        q.whereNull('freeze_reason').orWhere((expired: any) => {
          expired
            .whereNotNull('freeze_until_ms')
            .andWhere('freeze_until_ms', '<=', input.nowMs)
            // …salvo la ventana del OPERADOR vencida: es evidencia, no espacio libre (R2).
            .andWhere((notOperator: any) => {
              // La regla ÚNICA (`isOperatorHolder`), sin `LIKE`: comparación EXACTA de prefijo (cierre-2 · C3).
              notOperator.whereNull('freeze_holder').orWhereRaw(`NOT (${operator.sql})`, operator.bindings)
            })
        })
      })
      .update({
        freeze_reason: input.reason,
        freeze_holder: input.holder,
        freeze_until_ms: input.untilMs,
        freeze_fence: db.raw('freeze_fence + 1'),
        updated_at: new Date(input.nowMs),
      })
  )
  if (Number(updated) === 0) {
    // O hay un freeze vivo, o una ventana de operador vencida, o la fila no existe: distinguirlo es leerla.
    const row = await readFreezeRow(options)
    if (freezeIsLive(row, input.nowMs)) return { status: 'held', row }
    if (row.reason !== null && freezeKindOf(row.holder) === 'operator') return { status: 'expired-operator', row }
    // Carrera minúscula (se liberó entre el UPDATE y el SELECT): reintenta UNA vez.
    // Cierre-2 · C3: tras el reintento, una fila que NO está viva no es `held` (su
    // letra dice «VIVO»). Con la regla única del prefijo esta rama solo la alcanza
    // una fila que cambió dos veces entre UPDATE y SELECT: 503 reintentable que lo dice.
    if (attempt >= 1) {
      const error = new AuthorizationBackendError(
        driver,
        'freeze.acquire',
        new Error('la fila del freeze cambió entre el UPDATE condicional y su relectura dos veces seguidas')
      )
      error.message =
        `${driver}: no se pudo tomar el freeze: la fila (${row.holder ?? 'sin holder'}, fence ${row.fence}) NO está viva ` +
        `y aun así el UPDATE condicional no casó dos veces seguidas — otro proceso la está cambiando a la vez ` +
        `(rama «contención tras reintento», no «freeze VIVO»). Reintenta.`
      throw error
    }
    return acquireFreezeOutcome(input, options, attempt + 1)
  }
  const row = await readFreezeRow(options)
  // Otro acquire ganó justo después (no debería: el nuestro dejó la fila viva).
  if (row.holder !== input.holder) return { status: 'held', row }
  return { status: 'acquired', token: { fence: row.fence, holder: input.holder } }
}

/** `acquireFreezeOutcome` reducido a «el token o `null`» (lo usan los casos que siembran una fila ajena). */
export async function acquireFreeze(
  input: { reason: string; holder: string; untilMs: number | null; nowMs: number },
  options: FreezeSqlOptions = {}
): Promise<FreezeToken | null> {
  const outcome = await acquireFreezeOutcome(input, options)
  return outcome.status === 'acquired' ? outcome.token : null
}

/**
 * Renueva el lease, CONDICIONAL por token y solo si aún no venció
 * (`freeze_until_ms > now`). `false` = el lease se PERDIÓ (caducó a mitad, o
 * otro dueño tomó el freeze): el llamante lo marca `lapsed` y deja de
 * renovar — nunca «recupera» un freeze que ya no es suyo.
 */
export async function renewFreeze(
  token: FreezeToken,
  input: { untilMs: number; nowMs: number },
  options: FreezeSqlOptions = {}
): Promise<boolean> {
  const { driver, timeoutMs } = opts(options)
  const updated = await freezeSql(driver, 'freeze.renew', timeoutMs, () =>
    db
      .from(CATALOG_VERSION_TABLE)
      .where('id', FREEZE_ROW_ID)
      .where('freeze_fence', token.fence)
      .where('freeze_holder', token.holder)
      .where('freeze_until_ms', '>', input.nowMs)
      .update({ freeze_until_ms: input.untilMs, updated_at: new Date(input.nowMs) })
  )
  return Number(updated) > 0
}

/**
 * Levanta el freeze de ESTE token (condicional: uno ajeno o rezagado no toca
 * nada). Devuelve además `lapsed`: si en el instante de cerrar el lease ya
 * estaba vencido o el token ya no era el de la fila, hubo una ventana en la
 * que otros procesos pudieron escribir — es lo que el reporte publica.
 */
export async function releaseFreeze(
  token: FreezeToken,
  input: { nowMs: number },
  options: FreezeSqlOptions = {}
): Promise<{ released: boolean; lapsed: boolean }> {
  const { driver, timeoutMs } = opts(options)
  const row = await readFreezeRow(options)
  // La fila SIN holder (legada o escrita a mano) se publica como `UNKNOWN_HOLDER`
  // en `freezeStatus()`/`lastFreezeStatus()`, así que ese es su token: sin esto
  // `authz:unfreeze` no casaba nunca y repetía su aviso para siempre (cierre del
  // auditor de alpha.10 · ⚪ 5). `freeze()` jamás escribe ese holder.
  // Cierre-2 · C4: `'?'` publica DOS filas —holder NULL y holder LITERAL `'?'` (a
  // mano)—, así que el token casa las dos (`IS NULL OR = '?'`); casar solo NULL
  // dejaba la literal sin salida y `authz:unfreeze` en bucle con exit 1. Sigue
  // atado al fence y nunca casa un holder real.
  const unknownHolder = token.holder === UNKNOWN_HOLDER
  const mine =
    row.fence === token.fence && (unknownHolder ? row.holder === null || row.holder === UNKNOWN_HOLDER : row.holder === token.holder)
  const lapsed = !mine || (row.untilMs !== null && row.untilMs <= input.nowMs)
  if (!mine) return { released: false, lapsed }
  const updated = await freezeSql(driver, 'freeze.release', timeoutMs, () =>
    db
      .from(CATALOG_VERSION_TABLE)
      .where('id', FREEZE_ROW_ID)
      .where('freeze_fence', token.fence)
      .where((q: any) =>
        unknownHolder ? q.whereNull('freeze_holder').orWhere('freeze_holder', UNKNOWN_HOLDER) : q.where('freeze_holder', token.holder)
      )
      .update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null, updated_at: new Date(input.nowMs) })
  )
  return { released: Number(updated) > 0, lapsed }
}

/**
 * **La regla ÚNICA del prefijo de operador** (cierre-2 de alpha.10 · C3): los
 * `OPERATOR_HOLDER_PREFIX.length` primeros caracteres del holder son EXACTAMENTE
 * `operator:` — sensible a mayúsculas y a acentos, sin comodines. La MISMA
 * comparación va en el `WHERE` de `acquireFreezeOutcome` (`operatorHolderSql`) y
 * aquí; hasta el cierre-2 el SQL usaba `LIKE` (insensible a mayúsculas en SQLite y
 * en MySQL `_ci`) y JS partía por `:`, así que un holder `OPERATOR:…` caducado era
 * «de operador» para el UPDATE y `unknown` para JS ⇒ 423 «VIVO» sobre una fila
 * caducada, distinto por motor.
 */
export function isOperatorHolder(holder: string | null): boolean {
  return typeof holder === 'string' && holder.slice(0, OPERATOR_HOLDER_PREFIX.length) === OPERATOR_HOLDER_PREFIX
}

/** El `kind` que el holder lleva escrito (`operator:123:ab…` → `operator`); el de operador, por `isOperatorHolder`. */
export function freezeKindOf(holder: string | null): FreezeKind | 'unknown' {
  if (isOperatorHolder(holder)) return 'operator'
  if (typeof holder !== 'string' || !holder.includes(':')) return 'unknown'
  const prefix = holder.slice(0, holder.indexOf(':'))
  return prefix === 'reconcile' || prefix === 'platform' ? prefix : 'unknown'
}
