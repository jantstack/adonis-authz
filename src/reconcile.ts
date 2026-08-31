/**
 * Piezas COMPARTIDAS de `authz:reconcile` (3b-3b): lo que las dos
 * direcciones —`--to=openfga` (3b-3a) y `--to=database`— tienen que decidir
 * igual o el reporte deja de significar lo mismo según hacia dónde se migre.
 *
 * Vive aquí y no en un driver porque el driver `database` no puede importar
 * del `openfga` (arrastraría el SDK, que es una peer dependency opcional) y
 * porque duplicar la normalización de `batchSize`, la cota del volcado o la
 * suma de fases es la forma más barata de que las dos direcciones cuenten
 * distinto. Módulo puro: sin base de datos, sin red y sin `#aliases` del
 * consumidor (`check:purity`).
 */

import { AuthorizationConfigError } from './errors.js'
import { DEFAULT_RECONCILE_MAX_TUPLES } from './types.js'
import type { ReconcileCounts } from './types.js'

/** Filas por lote en el ORIGEN y operaciones por escritura en el destino. */
export const RECONCILE_BATCH = 100

/**
 * Cómo se NOMBRA el origen cuando los hechos son las tablas del paquete
 * (3b-5). No es un driver: es el esquema PUBLICADO, y por eso tiene nombre
 * propio en el reporte —«de dónde salieron los hechos» es la diferencia
 * entre una migración y una pasada contra el driver activo—.
 */
export const AUTHZ_TABLES_ORIGIN = 'authz_assignments/authz_denies'

/** Tope de filas del reporte que se nombran una a una (el resto solo se cuenta). */
export const RECONCILE_MAX_DETAILS = 200

/** Las cuatro fases de una pasada; en `--to=database` las tres primeras son cero. */
export type ReconcileFamily = 'root' | 'catalog' | 'tree' | 'facts'

export function reconcileBatchSize(value: number | undefined): number {
  if (value === undefined) return RECONCILE_BATCH
  if (!Number.isInteger(value) || value < 1) {
    throw new AuthorizationConfigError(`authz:reconcile: batchSize debe ser un entero >= 1 (llegó ${String(value)})`)
  }
  return value
}

/**
 * La cota DECLARADA del volcado (3b-3b · B5). No es una promesa de memoria:
 * es el número por encima del cual la pasada se niega con
 * `E_AUTHZ_RECONCILE_TOO_LARGE` en vez de intentarlo y morir a medias.
 */
export function reconcileMaxTuples(value: number | undefined): number {
  if (value === undefined) return DEFAULT_RECONCILE_MAX_TUPLES
  if (!Number.isInteger(value) || value < 1) {
    throw new AuthorizationConfigError(`authz:reconcile: maxTuples debe ser un entero >= 1 (llegó ${String(value)})`)
  }
  return value
}

export function emptyReconcileCounts(): ReconcileCounts {
  return { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 }
}

export function emptyReconcilePhases(): Record<ReconcileFamily, ReconcileCounts> {
  return {
    root: emptyReconcileCounts(),
    catalog: emptyReconcileCounts(),
    tree: emptyReconcileCounts(),
    facts: emptyReconcileCounts(),
  }
}

export function sumReconcilePhases(phases: Record<ReconcileFamily, ReconcileCounts>): ReconcileCounts {
  const total = emptyReconcileCounts()
  for (const counts of Object.values(phases)) {
    total.written += counts.written
    total.updated += counts.updated
    total.unchanged += counts.unchanged
    total.extra += counts.extra
    total.deleted += counts.deleted
  }
  return total
}
