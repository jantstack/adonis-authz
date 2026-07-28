/**
 * Suite de contrato del paquete — el juez de cualquier driver.
 *
 *   import { runAuthorizationDriverContract } from '@jantstack/adonis-authz/testing'
 *
 * Requiere Japa en el proyecto consumidor (es donde vive la base de datos
 * real contra la que tiene sentido ejecutarla).
 */
export { runAuthorizationDriverContract } from './contract.js'
export type { DriverContractHarness } from './contract.js'
