/**
 * Suite de contrato del paquete — el juez de cualquier driver.
 *
 *   import { runAuthorizationDriverContract, memoryScopeTree } from '@jantstack/adonis-authz/testing'
 *
 * Requiere Japa en el proyecto consumidor (es donde vive la base de datos
 * real contra la que tiene sentido ejecutarla).
 */
export { runAuthorizationDriverContract, lucidContractTransactions } from './contract.js'
export type { DriverContractHarness, DriverCapabilities, ContractLevel, ContractTransactions } from './contract.js'
export { memoryScopeTree, resolveChainFrom, descendantsFrom } from './scope_tree.js'
export {
  runMigrationContract,
  registerMigrationContract,
  runMigrationDirection,
  makeMigrationSeed,
  migrationQuestions,
  plantMigrationFacts,
  plantMigrationTree,
  MIGRATION_CATALOG,
  MIGRATION_PERMISSIONS,
  MIGRATION_ROLES,
  MIGRATION_QUESTION_COUNT,
} from './migration_contract.js'
export type {
  MigrationContractHarness,
  MigrationDirection,
  MigrationQuestion,
  MigrationSeed,
  MigrationVerdict,
  ExpectedLoss,
} from './migration_contract.js'
export type { ContractScopeTree } from './scope_tree.js'
export {
  runRelationsDriverContract,
  registerRelationsDriverContract,
  makeRelationsDriver,
  contractRelationsConfig,
  RELATIONS_HOLDER_TYPES,
  lucidRelationsContractTransactions,
} from './relations_contract.js'
export type {
  RelationsDriverContractHarness,
  RelationsContractTransactions,
  MakeRelationsDriverOptions,
} from './relations_contract.js'
export {
  runRelationsReconcileContract,
  registerRelationsReconcileContract,
} from './relations_reconcile_contract.js'
export type { RelationsReconcileHarness } from './relations_reconcile_contract.js'
