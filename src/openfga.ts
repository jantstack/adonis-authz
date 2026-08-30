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

/**
 * Modo `facts` (3b-2a): el generador del modelo (c2) y la proyección del
 * catálogo. Sin `@openfga/sdk` —es JSON y cadenas—, pero se publica por esta
 * misma puerta: es material de OpenFGA y solo lo usa quien lo elige.
 */
export {
  openFgaFactsModel,
  factsRelationsOf,
  factsRelationMap,
  factsCatalogTuples,
  factsTupleId,
  factsModelBytes,
  assertFactsModelPublishable,
  assertFgaObjectId,
  FACTS_MODEL_MAX_BYTES,
  FACTS_MODEL_WARN_RATIO,
  FGA_MAX_RELATION_NAME,
  FGA_MAX_OBJECT_ID,
  factsScopeObject,
  factsParentTuple,
  FACTS_SCOPE_TYPE,
  FACTS_PARENT_RELATION,
} from './drivers/openfga_facts.js'
export type { FactsRelations, FactsCatalogTuple, FactsTuple } from './drivers/openfga_facts.js'
