/**
 * Entrada pública del paquete.
 *   import { AuthorizationManager, APP_SCOPE } from '@jantstack/adonis-authz'
 */
export { AuthorizationManager, DEFAULT_MAX_SCOPES, DEFAULT_MAX_DESCENDANTS, MAX_SCOPE_BOUND, DEFAULT_VIEW_MAX_AGE_MS, expandExcludedSubtrees } from './src/manager.js'
export type { AuthorizationView, ForRequestOptions } from './src/manager.js'
export { defineConfig } from './src/define_config.js'
export type { AuthorizationConfig } from './src/define_config.js'
export {
  syncAuthzCatalog,
  diffAuthzCatalog,
  catalogInSync,
  formatCatalogDiff,
  formatScopedRoles,
  formatShadowedRoles,
  runCatalogDiff,
  syncCatalogs,
} from './src/catalog.js'
export type { SyncCatalogOptions, CatalogDiff, CatalogLinkRef, CatalogSource } from './src/catalog.js'

/**
 * Memo del catálogo (2.1): se revalida contra la versión compartida
 * `authz_catalog_version`, que `syncAuthzCatalog` sube como última sentencia
 * de su transacción. Quien escriba `authz_*` por fuera lo hace con
 * `withAuthzCatalogWrite(async (trx) => …)` (misma transacción, bump al
 * final: todos los procesos lo ven) — `bumpAuthzCatalogVersion(trx)` exige
 * ese trx; `invalidateAuthzCatalog()` solo alcanza a este proceso.
 */
export {
  CatalogCache,
  invalidateAuthzCatalog,
  bumpAuthzCatalogVersion,
  withAuthzCatalogWrite,
  readAuthzCatalogVersion,
  CATALOG_VERSION_TABLE,
  GLOBAL_OWNER_KEY,
} from './src/catalog_cache.js'
export type {
  CatalogCacheOptions,
  CatalogRevalidate,
  CatalogView,
  CatalogRoleRef,
  CatalogPermission,
  AuthzCatalogWriteOptions,
  CatalogVersionClient,
  CatalogVersionTransaction,
} from './src/catalog_cache.js'

/**
 * Memo de ancestros de una instancia (2.1), solo para el camino de lectura.
 * `authorization.forRequest()` ya lo aplica por ti.
 */
export { memoizeAncestors } from './src/memoize_ancestors.js'

/**
 * Arbol del consumidor (2.1): `hierarchicalScopeResolver` construye el
 * resolutor de ancestros desde un `parentOf`; `sqlDescendantsOf` genera el
 * `descendantsOf` opt-in (CTE recursiva, PG y SQLite) para `authorizedScopes`.
 */
export { hierarchicalScopeResolver } from './src/hierarchical_resolver.js'
export type { HierarchicalResolverOptions, NodeOf, ScopeNode } from './src/hierarchical_resolver.js'
export { sqlDescendantsOf } from './src/sql_descendants.js'
export type { SqlDescendantsOptions } from './src/sql_descendants.js'

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
  UnknownScopeError,
  NoScopeResolverError,
  UnknownRoleError,
  UnknownPermissionError,
  CatalogConflictError,
  RoleIsNotAccessError,
  ScopeCycleError,
  PurgeIncompleteError,
  StoreNotEmptyError,
  ActorRequiredError,
  NotWithinError,
  WithinRequiredError,
  WithinRootForbiddenError,
  TooManyScopesError,
  TooManyLocalRolesError,
  MassPurgeRefusedError,
  PruneInterruptedError,
  UnsupportedDialectError,
  ScopeTooDeepError,
  UnsupportedOperationError,
  NoDescendantsResolverError,
  ViewExpiredError,
  RoleNotVisibleError,
  AmbiguousRoleError,
  RoleImmutableError,
  RoleLevelAboveOwnerError,
  RoleNotAssignableAtError,
  PermissionNotDelegableError,
  RankExceededError,
  ModelTooLargeError,
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
  assertExpiresAt,
  assertNoSlugCollisions,
  normalizeRoleQuery,
  scopeKey,
  scopeFromKey,
  IDENTITY_LIMITS,
  MAX_SLUG_LENGTH,
  RESERVED_SLUGS,
  RESERVED_SLUG_PREFIXES,
} from './src/identity.js'
export type { IdentityParts, SlugKind } from './src/identity.js'
export { resolveGrantExpiry, isActiveExpiry, sameInstant } from './src/expiry.js'

export { DatabaseAuthorizationDriver, APP_SCOPE_DB_UUID } from './src/drivers/database_driver.js'
export type { DatabaseDriverOptions } from './src/drivers/database_driver.js'

/**
 * El driver `openfga` NO se exporta desde aquí: vive en el subpath
 * `@jantstack/adonis-authz/openfga`, que es lo único que importa el peer
 * opcional `@openfga/sdk`. Un consumidor solo-database arranca sin él (D9).
 */

export { APP_SCOPE, APP_SCOPE_TYPE } from './src/types.js'
export type {
  AuthorizationDriver,
  AuthorizationDriverFactory,
  AuthorizedScopes,
  AuthzWriteEvent,
  AuthzCatalogWriteEvent,
  CatalogPermissionSpec,
  CatalogRole,
  CatalogRoleSpec,
  CatalogSpec,
  ScopedRoleChanges,
  ScopedRoleSpec,
  DenyOptions,
  DenyRef,
  ExcludedSubtree,
  GrantOptions,
  GrantOutcome,
  HolderTypeMap,
  RoleQuery,
  ScopeChainResolver,
  ScopeDescendantsResolver,
  ScopedWriteOptions,
  ScopeRef,
  ScopeType,
  SubjectRef,
  WriteOptions,
} from './src/types.js'

export { default as AuthzRole } from './src/models/authz_role.js'
export { default as AuthzPermission } from './src/models/authz_permission.js'
export { default as AuthzRolePermission } from './src/models/authz_role_permission.js'
export { default as AuthzAssignment } from './src/models/authz_assignment.js'
export { default as AuthzDeny } from './src/models/authz_deny.js'

export { withAuthzScopes } from './src/traits/authz_scopes.js'
export { hasUuid } from './src/traits/has_uuid.js'
