/**
 * **El loader de ace de los comandos del paquete** (2.4.0-alpha.4). Se
 * registra con `node ace configure @jantstack/adonis-authz`, que escribe en el
 * `adonisrc.ts` del consumidor:
 *
 *   commands: [() => import('@jantstack/adonis-authz/commands')]
 *
 * y ace trata **el módulo importado como el loader**: `Kernel.boot()` llama
 * `getMetaData()` y `getCommand(meta)` sobre el namespace del módulo, sin
 * desenvolver `default` (mismo contrato que `@adonisjs/core/commands` y
 * `@adonisjs/lucid/commands`, que leen un `commands.json` generado por el
 * assembler; aquí no hay assembler, así que el loader es un `ListLoader`
 * sobre las diez clases (nueve hasta alpha.4) y no hay índice que generar).
 *
 * Hasta alpha.3 este fichero re-exportaba las nueve clases y NADA más, de
 * modo que en un consumidor configurado con `node ace configure` **`node ace`
 * entero reventaba** al arrancar (`TypeError: loaderInstance.getMetaData is
 * not a function`), no solo `openfga:provision`. Ningún caso lo vio porque
 * ninguno registraba el barrel como lo registra `createAceKernel`
 * (`tests/commands.spec.ts` · C-1 lo hace desde alpha.4).
 *
 * Las re-exportaciones con nombre se MANTIENEN (quien importe una clase
 * suelta sigue funcionando). Lo que NO vale desde alpha.4 es envolver el
 * módulo en un `ListLoader(Object.values(m))`: `Object.values` incluye ahora
 * las dos funciones y `ListLoader.getMetaData()` llama `serialize()` sobre
 * cada valor. Se registra el módulo directamente, como escribe `configure`.
 * Y NO se exporta `default`: ace no lo cargaría.
 */
import { ListLoader } from '@adonisjs/core/ace'
import type { CommandMetaData } from '@adonisjs/core/types/ace'
import OpenFgaProvision from './openfga_provision.js'
import AuthzCatalogDiff from './authz_catalog_diff.js'
import AuthzCatalogSync from './authz_catalog_sync.js'
import AuthzCatalogPruneOrphans from './authz_catalog_prune_orphans.js'
import AuthzScopesRelay from './authz_scopes_relay.js'
import AuthzScopesRequeue from './authz_scopes_requeue.js'
import AuthzReconcile from './authz_reconcile.js'
import AuthzRelationsReconcile from './authz_relations_reconcile.js'
import AuthzFreeze from './authz_freeze.js'
import AuthzUnfreeze from './authz_unfreeze.js'

export {
  OpenFgaProvision,
  AuthzCatalogDiff,
  AuthzCatalogSync,
  AuthzCatalogPruneOrphans,
  AuthzScopesRelay,
  AuthzScopesRequeue,
  AuthzReconcile,
  AuthzRelationsReconcile,
  AuthzFreeze,
  AuthzUnfreeze,
}

/** Los diez (nueve hasta alpha.4; `authz:scopes:requeue` desde alpha.5), en el orden en que `node ace list` los enseña. */
const loader = new ListLoader([
  OpenFgaProvision,
  AuthzCatalogDiff,
  AuthzCatalogSync,
  AuthzCatalogPruneOrphans,
  AuthzScopesRelay,
  AuthzScopesRequeue,
  AuthzReconcile,
  AuthzRelationsReconcile,
  AuthzFreeze,
  AuthzUnfreeze,
] as any)

/** Contrato de loader de ace (`LoadersContract.getMetaData`). */
export function getMetaData(): Promise<CommandMetaData[]> {
  return loader.getMetaData()
}

/** Contrato de loader de ace (`LoadersContract.getCommand`): la clase, o `null` si el nombre no es nuestro. */
export function getCommand(metaData: CommandMetaData): Promise<any> {
  return loader.getCommand(metaData)
}
