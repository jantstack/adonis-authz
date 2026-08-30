/**
 * Comandos ace del paquete. Se registran con:
 *   node ace configure @jantstack/adonis-authz
 */
export { default as OpenFgaProvision } from './openfga_provision.js'
export { default as OpenFgaImport } from './openfga_import.js'
export { default as AuthzCatalogDiff } from './authz_catalog_diff.js'
export { default as AuthzCatalogSync } from './authz_catalog_sync.js'
export { default as AuthzCatalogPruneOrphans } from './authz_catalog_prune_orphans.js'
