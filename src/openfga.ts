/**
 * Entrada del subpath `@jantstack/adonis-authz/openfga` — TODO lo que tira de
 * `@openfga/sdk` (peer opcional) vive detrás de esta puerta (D9):
 *
 *   const { OpenFgaAuthorizationDriver } = await import('@jantstack/adonis-authz/openfga')
 *
 * La entrada principal (`@jantstack/adonis-authz`) no importa este módulo ni
 * el driver: un consumidor solo-database arranca sin el SDK instalado, y
 * `scripts/check_purity.mjs` (regla 3) lo vigila en cada build.
 */
export {
  OpenFgaAuthorizationDriver,
  openFgaAuthorizationModel,
  provisionOpenFgaStore,
  importAuthzFactsToOpenFga,
  assertHolderTypes,
  parseBindingId,
  correlateBatchResults,
  isDuplicateWrite,
  DEFAULT_TIMEOUT_MS,
} from './drivers/openfga_driver.js'
export type {
  HolderTypeMap,
  OpenFgaDriverOptions,
  ImportFactsOptions,
  ImportFactsResult,
} from './drivers/openfga_driver.js'
