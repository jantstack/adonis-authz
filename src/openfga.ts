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
  provisionOpenFgaStore,
  assertHolderTypes,
  parseBindingId,
  correlateBatchResults,
  isDuplicateWrite,
  DEFAULT_TIMEOUT_MS,
} from './drivers/openfga_driver.js'
export type { HolderTypeMap, OpenFgaDriverOptions } from './drivers/openfga_driver.js'

/**
 * El driver `openfga` del puerto `RelationsDriver` (Fase 4, lote 4-4): ReBAC
 * sobre el MISMO store y `modelId` que el driver `facts` de roles. Vive detrás
 * de esta puerta como el resto de lo que toca `@openfga/sdk`.
 */
export { OpenFgaRelationsDriver } from './drivers/openfga_relations_driver.js'
export type { OpenFgaRelationsDriverOptions } from './drivers/openfga_relations_driver.js'

/**
 * El modelo (c2r) y la proyección del catálogo (3b-2a; desde 3b-2k · K2 es
 * el ÚNICO modelo: `openFgaAuthorizationModel` —el del modo `resolver`— y
 * `importAuthzFactsToOpenFga` se borraron con él). Sin `@openfga/sdk` —es
 * JSON y cadenas—, pero se publica por esta misma puerta: es material de
 * OpenFGA y solo lo usa quien lo elige.
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
  FACTS_MAX_RESOLVE_DEPTH,
  FGA_MAX_BATCH_CHECK,
  factsScopeObject,
  factsParentTuple,
  FACTS_SCOPE_TYPE,
  FACTS_PARENT_RELATION,
  factsRootTuples,
  FACTS_ROOTED_RELATION,
  factsRelationTypeDefinitions,
  assertRelationsConfigPublishable,
  RESERVED_FACTS_TYPES,
  FACTS_GROUP_TYPE,
  FACTS_GROUP_MEMBER_RELATION,
} from './drivers/openfga_facts.js'
export type {
  FactsRelations,
  FactsCatalogTuple,
  FactsTuple,
  FactsRelationsConfig,
  RelationObjectType,
  RelationObjectRelation,
} from './drivers/openfga_facts.js'
