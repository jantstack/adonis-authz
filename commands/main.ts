/**
 * Comandos ace del paquete. Se registran con:
 *   node ace configure @jantstack/adonis-authz
 */
export { default as OpenFgaProvision } from './openfga_provision.js'
export { default as AuthzCatalogDiff } from './authz_catalog_diff.js'
export { default as AuthzCatalogSync } from './authz_catalog_sync.js'
export { default as AuthzCatalogPruneOrphans } from './authz_catalog_prune_orphans.js'
export { default as AuthzScopesRelay } from './authz_scopes_relay.js'
export { default as AuthzReconcile } from './authz_reconcile.js'
export { default as AuthzFreeze } from './authz_freeze.js'
export { default as AuthzUnfreeze } from './authz_unfreeze.js'
