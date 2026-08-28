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
export { memoryScopeTree, resolveAncestorsFrom } from './scope_tree.js'
export type { ContractScopeTree } from './scope_tree.js'
