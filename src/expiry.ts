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

/** Lo que devuelve el backend como caducidad (número, ISO, Date) → Date | null. */
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
