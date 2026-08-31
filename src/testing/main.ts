/**
 * Suite de contrato del paquete — el juez de cualquier driver.
 *
 *   import { runAuthorizationDriverContract, memoryScopeTree } from '@jantstack/adonis-authz/testing'
 *
 * Requiere Japa en el proyecto consumidor (es donde vive la base de datos
 * real contra la que tiene sentido ejecutarla).
 */
export { runAuthorizationDriverContract } from './contract.js'
export type { DriverContractHarness, DriverCapabilities, ContractLevel } from './contract.js'
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
