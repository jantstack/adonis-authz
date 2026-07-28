/**
 * Entrada pública del paquete.
 *   import { AuthorizationManager, APP_SCOPE } from '@jantstack/adonis-authz'
 */
export { AuthorizationManager } from './src/manager.js'
export { defineConfig } from './src/define_config.js'
export type { AuthorizationConfig } from './src/define_config.js'
export { syncAuthzCatalog } from './src/catalog.js'

export { DatabaseAuthorizationDriver, APP_SCOPE_DB_UUID } from './src/drivers/database_driver.js'
export {
  OpenFgaAuthorizationDriver,
  openFgaAuthorizationModel,
  provisionOpenFgaStore,
  importAuthzFactsToOpenFga,
} from './src/drivers/openfga_driver.js'
export type { HolderTypeMap, OpenFgaDriverOptions } from './src/drivers/openfga_driver.js'

export { APP_SCOPE, APP_SCOPE_TYPE } from './src/types.js'
export type {
  AuthorizationDriver,
  AuthorizationDriverFactory,
  AuthzWriteEvent,
  CatalogRoleSpec,
  CatalogSpec,
  GrantOptions,
  ScopeAncestorsResolver,
  ScopeRef,
  ScopeType,
  SubjectRef,
} from './src/types.js'

export { default as AuthzRole } from './src/models/authz_role.js'
export { default as AuthzPermission } from './src/models/authz_permission.js'
export { default as AuthzRolePermission } from './src/models/authz_role_permission.js'
export { default as AuthzAssignment } from './src/models/authz_assignment.js'
export { default as AuthzDeny } from './src/models/authz_deny.js'

export { withAuthzScopes } from './src/traits/authz_scopes.js'
export { hasUuid } from './src/traits/has_uuid.js'
