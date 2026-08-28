/**
 * Entrada pública del paquete.
 *   import { AuthorizationManager, APP_SCOPE } from '@jantstack/adonis-authz'
 */
export { AuthorizationManager } from './src/manager.js'
export { defineConfig } from './src/define_config.js'
export type { AuthorizationConfig } from './src/define_config.js'
export { syncAuthzCatalog } from './src/catalog.js'

/**
 * El backend de autorización no respondió (503). Tipo PROPIO a propósito: sin
 * él escaparía el error del SDK del driver, y distinguir "backend caído"
 * obligaría a importar ese SDK — acoplando el call-site al backend que este
 * paquete existe para abstraer.
 */
export {
  AuthorizationBackendError,
  AuthorizationBackendTimeoutError,
  ScopeResolverError,
  InvalidIdentityError,
  InvalidSlugError,
  AuthorizationConfigError,
  AuthorizationInternalError,
} from './src/errors.js'

/**
 * Validación de identidad y de slugs (422). La aplica el manager en cada
 * llamada y los drivers por defensa en profundidad; se exporta para que un
 * consumidor valide en su borde (un formulario, un importador) con la MISMA
 * regla y no con una copia.
 */
export {
  assertIdentity,
  assertSubject,
  assertScope,
  assertValidSlug,
  assertNoSlugCollisions,
  IDENTITY_LIMITS,
  MAX_SLUG_LENGTH,
  RESERVED_SLUGS,
  RESERVED_SLUG_PREFIXES,
} from './src/identity.js'
export type { IdentityParts, SlugKind } from './src/identity.js'

export { DatabaseAuthorizationDriver, APP_SCOPE_DB_UUID } from './src/drivers/database_driver.js'
export type { DatabaseDriverOptions } from './src/drivers/database_driver.js'
export {
  OpenFgaAuthorizationDriver,
  openFgaAuthorizationModel,
  provisionOpenFgaStore,
  importAuthzFactsToOpenFga,
  assertHolderTypes,
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
