/**
 * **El modelo que sirve un cliente FALSO de OpenFGA** (lote «antes de RC» · L11). Desde L11 los dos drivers `openfga`
 * leen el modelo FIJADO (`readAuthorizationModel`, una vez por proceso) y lo comparan con el que genera su config antes
 * de la primera llamada de cada operación; y el `modelId` es OBLIGATORIO al construir. Un caso unitario con un cliente
 * falso (o con el real apuntando a un puerto muerto y métodos sustituidos) tiene que servir ese modelo para llegar a lo
 * que juzga — y lo hace por la PUERTA REAL, no saltándosela: `serveModel` sustituye solo `readAuthorizationModel`.
 */
import { openFgaFactsModel } from '../../src/drivers/openfga_facts.js'
import type { FactsRelationsConfig } from '../../src/drivers/openfga_facts.js'

/** Un ULID válido de modelo para los casos sin servidor (el pin es obligatorio; el falso no lo mira). */
export const TEST_MODEL_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAW'

/** El modelo (c2r) que genera la config: el que la puerta L11 acepta. */
export function generatedModel(
  holderTypes: Record<string, string>,
  permissions: readonly string[] = [],
  relations?: FactsRelationsConfig
): any {
  return openFgaFactsModel(holderTypes, permissions, relations)
}

/** Sustituye `readAuthorizationModel` del cliente del driver (o de un cliente falso) para que sirva `model`. */
export function serveModel<T extends object>(target: T, model: unknown): T {
  const client = 'client' in target ? (target as any).client : target
  client.readAuthorizationModel = async () => ({ authorization_model: model })
  return target
}

/** `serveModel` con el modelo que genera la config (`holderTypes` + permisos + relaciones). */
export function serveGeneratedModel<T extends object>(
  target: T,
  holderTypes: Record<string, string>,
  permissions: readonly string[] = [],
  relations?: FactsRelationsConfig
): T {
  return serveModel(target, generatedModel(holderTypes, permissions, relations))
}
