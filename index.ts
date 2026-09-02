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
} from './src/catalog/catalog.js'
export type { SyncCatalogOptions, CatalogDiff, CatalogLinkRef, CatalogSource } from './src/catalog/catalog.js'

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
} from './src/catalog/catalog_cache.js'
export type {
  CatalogCacheOptions,
  CatalogRevalidate,
  CatalogView,
  CatalogRoleRef,
  CatalogPermission,
  AuthzCatalogWriteOptions,
  CatalogVersionClient,
  CatalogVersionTransaction,
} from './src/catalog/catalog_cache.js'

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
export { sqlDescendantsOf, sqlScopeEdges } from './src/sql_descendants.js'
export type { SqlDescendantsOptions, SqlScopeEdgesOptions } from './src/sql_descendants.js'

/**
 * **La outbox del árbol** (3b-2d): `sqlScopeOutbox` implementa el puerto
 * `ScopeOutbox` sobre Lucid, con la tabla de
 * `stubs/scopes_outbox_migration.stub` (cópiala a tus migraciones:
 * `configure` no la publica, porque la outbox es opt-in). Con
 * `scopes.outbox` declarada, `authorization.scopes.attached/moved/detached`
 * ENCOLAN el cambio en tu transacción en vez de escribir en el backend, y lo
 * aplica `node ace authz:scopes:relay`. Cualquier implementación del puerto
 * vale: el paquete no impone tabla.
 */
export { sqlScopeOutbox } from './src/scope_outbox.js'
export type { SqlScopeOutboxOptions } from './src/scope_outbox.js'

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
  WriteConflictError,
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
  RelationConfigError,
  RelationTypeUnknownError,
  RelationUnknownError,
  ScopeTreeDriftError,
  ScopeDriftUnguardedError,
  AuthorizationFrozenError,
  FreezeHeldError,
  MassReconcileRefusedError,
  ReconcileTooLargeError,
  // Cierre de alpha.3 (invariante 13 en purgas multi-request): un driver de
  // relaciones de terceros marca con `markPartialWrite` el fallo que llega
  // DESPUÉS de haber borrado parte; el manager notifica `indeterminate: true`.
  markPartialWrite,
  isPartialWrite,
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
  RESERVED_FACTS_TYPES,
} from './src/identity.js'
export type { IdentityParts, SlugKind } from './src/identity.js'

/**
 * ReBAC genérico (Fase 4, `relations/`). El puerto `RelationsDriver` vive en
 * `./src/types.js` (el contrato); aquí salen la API declarativa
 * `defineRelationsConfig`, la fachada `RelationsManager` (F-05 + `assertWrite`
 * + `actor`) y los tipos de la config.
 */
export { defineRelationsConfig } from './src/relations/define_relations_config.js'
export type {
  RelationsConfig,
  RelationsConfigSpec,
  RelationsDatabaseOptions,
  RelationObjectTypeSpec,
  RelationObjectRelationSpec,
} from './src/relations/define_relations_config.js'
export { RelationsManager } from './src/relations/manager.js'
export type { RelationsManagerOptions } from './src/relations/manager.js'
export { reconcileRelations } from './src/relations/reconcile.js'
export type { RelationsReconcileOptions, RelationsReconcileReport } from './src/relations/reconcile.js'
// La config de relaciones PERSISTIDA (🟡3): API de PLATAFORMA (bajo el gate de
// versión, invariante 14). La CONSUME `authz:relations:reconcile` (config del
// destino, para la deriva del modelo fusionado en --dry-run).
export {
  saveRelationsConfig,
  readRelationsConfig,
  readRelationsConfigSpec,
} from './src/relations_config_store.js'
export type { RelationsConfigStoreOptions } from './src/relations_config_store.js'
// El driver `database` de relaciones (el consumidor lo cablea en
// `relations.drivers` de config/authorization.ts). El driver `openfga` de
// relaciones NO sale de aquí: vive en el subpath `/openfga` (peer opcional).
export { DatabaseRelationsDriver } from './src/drivers/database_relations_driver.js'
export type { DatabaseRelationsDriverOptions } from './src/drivers/database_relations_driver.js'
export { resolveGrantExpiry, isActiveExpiry, sameInstant } from './src/expiry.js'

export { DatabaseAuthorizationDriver, APP_SCOPE_DB_UUID } from './src/drivers/database_driver.js'
export type { DatabaseDriverOptions } from './src/drivers/database_driver.js'

/**
 * El driver `openfga` NO se exporta desde aquí: vive en el subpath
 * `@jantstack/adonis-authz/openfga`, que es lo único que importa el peer
 * opcional `@openfga/sdk`. Un consumidor solo-database arranca sin él (D9).
 */

export { APP_SCOPE, APP_SCOPE_TYPE, DEFAULT_RECONCILE_MAX_TUPLES } from './src/types.js'
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
  ReconcileCounts,
  ReconcileFact,
  ReconcileFactPage,
  ReconcileFactsEnumerator,
  ReconcileOptions,
  ReconcileReport,
  ReconcileSkip,
  ReconcileSource,
  RoleQuery,
  ScopeChainResolver,
  ScopeDescendantsResolver,
  ScopeEdge,
  ScopeEdgePage,
  ScopeEdgesEnumerator,
  ScopedWriteOptions,
  ScopeRef,
  ScopeType,
  SubjectRef,
  WriteOptions,
  RelationsDriver,
  RelationsDriverCapabilities,
  RelObject,
  RelSubject,
  RelUserset,
  RelationRef,
  RelationWriteEvent,
  RelationWriteOptions,
  RelationTransactionOptions,
  RelationPurgeOptions,
  RelationPage,
  RelationObjectsPage,
  RelationSubjectsPage,
  RelationTuple,
  RelationTuplePage,
} from './src/types.js'
export { isRelUserset } from './src/types.js'

/**
 * **¿De quién es esta transacción?** (L-1 · 🟠 9, regla del puerto `{trx}`):
 * la ÚNICA comprobación con la que una escritura del paquete —la outbox de
 * `scopes.*` hoy; `grant`/`relate` de un driver con `transactionalWrites:
 * true`— se inscribe en `{ transaction }`: tiene que ser una transacción
 * ABIERTA de Lucid de la conexión de quien escribe (otra conexión, un
 * `QueryClient` o el `db` entero son 500 `E_AUTHZ_CONFIG`). Un driver de
 * terceros que declare `transactionalWrites: true` la llama con SU conexión.
 */
export { assertCallerTransaction } from './src/shared/transaction_guard.js'
export type { CallerTransaction, CallerTransactionOwner } from './src/shared/transaction_guard.js'

export { default as AuthzRole } from './src/models/authz_role.js'
export { default as AuthzPermission } from './src/models/authz_permission.js'
export { default as AuthzRolePermission } from './src/models/authz_role_permission.js'
export { default as AuthzAssignment } from './src/models/authz_assignment.js'
export { default as AuthzDeny } from './src/models/authz_deny.js'

export { withAuthzScopes } from './src/traits/authz_scopes.js'
export { hasUuid } from './src/traits/has_uuid.js'
