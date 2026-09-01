import db from '@adonisjs/lucid/services/db'
import { guardSql } from './shared/backend_guard.js'
import { AuthorizationBackendError } from './errors.js'
import { CATALOG_VERSION_TABLE } from './catalog/catalog_cache.js'

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
  /** Deadline de cada consulta (default 5000): vencido ⇒ 503. */
  timeoutMs?: number
  /**
   * Cliente sobre el que leer (la TRANSACCIÓN del llamante, si la escritura
   * llegó con una — `ScopeTreeWriteOptions.transaction`). Sin esto, la
   * barrera necesitaría una SEGUNDA conexión del pool mientras el consumidor
   * sostiene la suya, y con un pool de 1 (SQLite `:memory:`) eso es un
   * interbloqueo, no una lectura. El precio, declarado: en un motor cuyo
   * aislamiento por defecto congela la foto de las lecturas (InnoDB
   * REPEATABLE READ), un freeze puesto DESPUÉS de abrir esa transacción
   * puede no verse desde dentro — la misma ventana que una escritura que ya
   * pasó su barrera (tester A4), y por eso la promesa publicada es «otro
   * proceso recibe 503», no «ninguna escritura entra».
   */
  client?: { from: (table: string) => any }
}

function opts(options: FreezeSqlOptions): { driver: string; timeoutMs: number } {
  return { driver: options.driver ?? 'freeze', timeoutMs: options.timeoutMs ?? DEFAULT_FREEZE_TIMEOUT_MS }
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

/** Lee la fila del freeze (503 clasificado si la base no responde; 503 «migración no aplicada» si no existe). */
export async function readFreezeRow(options: FreezeSqlOptions = {}): Promise<FreezeRow> {
  const { driver, timeoutMs } = opts(options)
  const client = options.client ?? db
  const rows: any[] = await guardSql(driver, 'freeze.read', timeoutMs, () =>
    client
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

/**
 * Toma el freeze si NADIE lo sostiene vivo (condicional y atómico: dos
 * `acquire` a la vez acaban en exactamente uno). Devuelve el token, o `null`
 * si hay un freeze vivo de otro dueño (el llamante decide si eso es 423 o un
 * contexto que reconoce).
 */
export async function acquireFreeze(
  input: { reason: string; holder: string; untilMs: number | null; nowMs: number },
  options: FreezeSqlOptions = {}
): Promise<FreezeToken | null> {
  const { driver, timeoutMs } = opts(options)
  const updated = await guardSql(driver, 'freeze.acquire', timeoutMs, () =>
    db
      .from(CATALOG_VERSION_TABLE)
      .where('id', FREEZE_ROW_ID)
      .where((q: any) => {
        // Libre, o con el lease VENCIDO (un dueño muerto no bloquea la toma).
        q.whereNull('freeze_reason').orWhere((expired: any) => {
          expired.whereNotNull('freeze_until_ms').andWhere('freeze_until_ms', '<=', input.nowMs)
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
    // O hay un freeze vivo, o la fila no existe: distinguirlo es leerla.
    const row = await readFreezeRow(options)
    if (freezeIsLive(row, input.nowMs)) return null
    // Carrera minúscula (se liberó entre el UPDATE y el SELECT): reintenta una vez.
    return acquireFreeze(input, options)
  }
  const row = await readFreezeRow(options)
  if (row.holder !== input.holder) return null // otro acquire ganó justo después (no debería: el nuestro dejó la fila viva)
  return { fence: row.fence, holder: input.holder }
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
  const updated = await guardSql(driver, 'freeze.renew', timeoutMs, () =>
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
  const mine = row.fence === token.fence && row.holder === token.holder
  const lapsed = !mine || (row.untilMs !== null && row.untilMs <= input.nowMs)
  if (!mine) return { released: false, lapsed }
  const updated = await guardSql(driver, 'freeze.release', timeoutMs, () =>
    db
      .from(CATALOG_VERSION_TABLE)
      .where('id', FREEZE_ROW_ID)
      .where('freeze_fence', token.fence)
      .where('freeze_holder', token.holder)
      .update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null, updated_at: new Date(input.nowMs) })
  )
  return { released: Number(updated) > 0, lapsed }
}

/** El `kind` que el holder lleva escrito (`operator:123:ab…` → `operator`). */
export function freezeKindOf(holder: string | null): FreezeKind | 'unknown' {
  const prefix = holder?.split(':', 1)[0]
  return prefix === 'operator' || prefix === 'reconcile' || prefix === 'platform' ? prefix : 'unknown'
}
