import type { GrantOutcome } from './types.js'
import { systemClock } from './clock.js'

/**
 * Semántica de `expiresAt` en un re-grant (L0.4), compartida por los drivers
 * para que ambos respondan igual:
 *
 *   omitido (`undefined`) → no tocar una caducidad VIGENTE; si la asignación
 *                            ya expiró, revive sin caducidad (es un grant nuevo)
 *   `null`                → quitar la caducidad, explícitamente
 *   `Date`                → fijarla (también a un instante pasado: expira)
 *
 * El defecto que cierra: "asegúrate de que tiene el rol" (grant sin opciones,
 * idempotente por naturaleza) convertía un acceso temporal en permanente.
 */
export function resolveGrantExpiry(
  previous: Date | null,
  requested: Date | null | undefined,
  now: Date = systemClock()
): Date | null {
  if (requested !== undefined) return requested
  return isActiveExpiry(previous, now) ? previous : null
}

/** Vigente: sin caducidad o con caducidad futura. */
export function isActiveExpiry(expiresAt: Date | null, now: Date = systemClock()): boolean {
  return expiresAt === null || expiresAt.getTime() > now.getTime()
}

/**
 * ¿Mismo instante? Compara el tiempo, no la referencia ni la cadena:
 * `2026-01-01T00:00:00Z` y `…00.000Z` son el mismo momento y no justifican
 * una reescritura (que en openfga es delete+write con ventana de denegación).
 */
export function sameInstant(a: Date | null | undefined, b: Date | null | undefined): boolean {
  if (!a && !b) return true
  if (!a || !b) return false
  return a.getTime() === b.getTime()
}

/**
 * Lo que devuelve el backend SQL como caducidad (número, ISO, Date) → Date | null. **Solo SQL** (`sql_expiry.ts`): una
 * tupla de OpenFGA se lee con `fgaTupleExpiry` (L11), nunca con esto — aquí una cadena ilegible es `null` =
 * PERMANENTE, que para una tupla del store era fail-open (C6-1/C6-2).
 */
export function toExpiryDate(value: unknown): Date | null {
  if (value === null || value === undefined || value === '') return null
  if (value instanceof Date) return value
  const date = new Date(value as any)
  return Number.isNaN(date.getTime()) ? null : date
}

/** ¿El outcome de un grant cambió la caducidad de una asignación que ya existía? */
export function expiryChanged(outcome: GrantOutcome): boolean {
  return (
    outcome.existed &&
    outcome.previousExpiresAt !== undefined &&
    !sameInstant(outcome.previousExpiresAt, outcome.expiresAt)
  )
}

/* ── L11 · la caducidad de una TUPLA de OpenFGA, en UN sitio ───────────── */

/**
 * El nombre de la condición de caducidad que escribe el paquete (`current_time < valid_until`). Es la MISMA cadena que
 * `FACTS_EXPIRY_CONDITION` del generador del modelo (`openfga_facts.ts` la re-exporta desde aquí: una sola fuente).
 */
export const FGA_EXPIRY_CONDITION = 'not_expired'

/**
 * **Lo que dice la condición de una tupla LEÍDA de OpenFGA** (lote «antes de RC» · L11, decisión del dueño 2026-10-17
 * (1); injerto 2 del juez; F0 · M-a(2)/M-b). Cuatro estados, y ninguno es «permanente» por defecto:
 *
 *  - `none`: la tupla no lleva condición. Con el modelo GENERADO toda relación la admite así y el servidor la evalúa
 *    PERMANENTE (medido, F0 · M-a(2)); la puerta L11 garantiza que el modelo que sirve el driver es ése.
 *  - `expiry`: `not_expired` con el contexto EXACTAMENTE `{ valid_until }` y una marca RFC3339 de la gramática que
 *    acepta el servidor. `at` es el milisegundo SIGUIENTE a la fracción (techo al ms: el servidor compara en ns y el
 *    paquete manda `current_time` en ms, así que `now < at` ⇔ `ns(now) < trunc9(ns(valid_until))`; medido 58/58, el
 *    `floor` de `new Date()` fallaba 30/60 — F0 · M-b).
 *  - `foreign`: otra condición (`inverted`…), o `not_expired` con un contexto que trae MÁS que `valid_until` (un
 *    `current_time` congelado en la tupla gana al de la petición: medido por el auditor, H2). El paquete no la
 *    escribe y no sabe qué concede.
 *  - `unparseable`: `not_expired` sin contexto o sin `valid_until` (el servidor responde 400 al evaluarla), o una marca
 *    que el servidor acepta y este parser no reproduce. Hasta L11 eso era `null` = PERMANENTE (`toExpiryDate`).
 *
 * Qué hace cada consumidor con `foreign`/`unparseable` lo decide él, siempre fail-closed (tabla en el README): VIVA
 * donde la tupla NIEGA o transporta un deny, AUSENTE donde CONCEDE, intocable en el destino de un reconcile, 409 con
 * receta si una escritura del paquete tendría que reemplazarla, borrada igual en una purga.
 */
export type FgaTupleExpiry =
  | { kind: 'none' }
  | { kind: 'expiry'; at: Date }
  | { kind: 'foreign'; detail: string }
  | { kind: 'unparseable'; detail: string }

const NONE: FgaTupleExpiry = Object.freeze({ kind: 'none' })

export function fgaTupleExpiry(condition: unknown): FgaTupleExpiry {
  if (condition === undefined || condition === null) return NONE
  if (typeof condition !== 'object' || Array.isArray(condition)) {
    return { kind: 'unparseable', detail: `la condición no es un objeto (${JSON.stringify(condition)})` }
  }
  const { name, context } = condition as { name?: unknown; context?: unknown }
  if (typeof name !== 'string' || name === '') {
    return { kind: 'unparseable', detail: `condición sin nombre (${JSON.stringify(condition)})` }
  }
  if (name !== FGA_EXPIRY_CONDITION) return { kind: 'foreign', detail: `condición '${name}'` }
  if (context === undefined || context === null || typeof context !== 'object' || Array.isArray(context)) {
    return { kind: 'unparseable', detail: `${FGA_EXPIRY_CONDITION} sin contexto (sin valid_until el servidor responde 400 al evaluarla)` }
  }
  const keys = Object.keys(context)
  if (!keys.includes('valid_until')) {
    return { kind: 'unparseable', detail: `${FGA_EXPIRY_CONDITION} sin valid_until en el contexto (${keys.join(', ') || 'vacío'})` }
  }
  if (keys.length !== 1) {
    return {
      kind: 'foreign',
      detail: `${FGA_EXPIRY_CONDITION} con contexto {${keys.sort().join(', ')}}: el paquete solo escribe {valid_until} (un current_time en la tupla gana al de la petición)`,
    }
  }
  const raw = (context as { valid_until?: unknown }).valid_until
  const ns = typeof raw === 'string' ? fgaTimestampNs(raw) : null
  if (ns === null) return { kind: 'unparseable', detail: `valid_until ilegible (${JSON.stringify(raw)})` }
  return { kind: 'expiry', at: new Date(Number(ceilDiv(ns, 1_000_000n))) }
}

/**
 * **La gramática de marca de tiempo que acepta OpenFGA v1.19 en `valid_until`, en nanosegundos desde la época**
 * (F0 · M-b, medido): `YYYY-MM-DDTHH:MM:SS[(.|,)d+](Z|±hh:mm)`, fracción de cualquier longitud TRUNCADA a 9 dígitos
 * (sin redondeo), coma decimal admitida, desfase con `hh` de 0 a 24 y `mm` de 0 a 59 (`+24:00`/`-24:00`/`+24:01` se
 * aceptan; `+99:00` no; 25–98 sin medir ⇒ aquí `null`, fail-closed), fecha y hora válidas del calendario gregoriano
 * proléptico (año 0000–9999; `02-30`, `T24:00:00`, minuto/segundo 60 ⇒ `null`). Todo lo demás ⇒ `null`.
 */
export function fgaTimestampNs(value: string): bigint | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?(?:(Z)|([+-])(\d{2}):(\d{2}))$/.exec(value)
  if (!match) return null
  const [, ys, mos, ds, hs, mis, ss, fraction, zulu, sign, ohs, oms] = match
  const year = Number(ys)
  const month = Number(mos)
  const day = Number(ds)
  const hour = Number(hs)
  const minute = Number(mis)
  const second = Number(ss)
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) return null
  if (hour > 23 || minute > 59 || second > 59) return null
  let offsetSeconds = 0
  if (!zulu) {
    const offsetHours = Number(ohs)
    const offsetMinutes = Number(oms)
    if (offsetHours > 24 || offsetMinutes > 59) return null
    offsetSeconds = (sign === '-' ? -1 : 1) * (offsetHours * 3600 + offsetMinutes * 60)
  }
  const seconds = BigInt(daysFromCivil(year, month, day)) * 86_400n + BigInt(hour * 3600 + minute * 60 + second - offsetSeconds)
  const nanos = fraction ? BigInt(fraction.slice(0, 9).padEnd(9, '0')) : 0n
  return seconds * 1_000_000_000n + nanos
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0 ? 29 : 28
  return [4, 6, 9, 11].includes(month) ? 30 : 31
}

/** Días desde 1970-01-01 de una fecha del gregoriano proléptico (H. Hinnant, `days_from_civil`). */
function daysFromCivil(year: number, month: number, day: number): number {
  const y = month <= 2 ? year - 1 : year
  const era = Math.floor(y / 400)
  const yoe = y - era * 400
  const doy = Math.floor((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5) + day - 1
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy
  return era * 146_097 + doe - 719_468
}

/** Techo de una división entera de BigInt (la de BigInt trunca hacia cero). */
function ceilDiv(n: bigint, d: bigint): bigint {
  const q = n / d
  return n % d !== 0n && n > 0n ? q + 1n : q
}
