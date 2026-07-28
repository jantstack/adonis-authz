import type { AuthorizationDriverFactory, AuthzWriteEvent } from './types.js'
import type { HolderTypeMap } from './drivers/openfga_driver.js'

/**
 * Config del sistema de autorización. Todo lo específico del consumidor
 * entra por aquí: qué drivers existen, cuál está activo, cómo se llaman sus
 * holders y qué hacer cuando el motor escribe.
 *
 *   export default defineConfig({
 *     default: env.get('AUTHZ_DRIVER', 'database'),
 *     holderTypes: { users: 'user', admins: 'admin' },
 *     drivers: {
 *       database: () => new DatabaseAuthorizationDriver({ resolveAncestors }),
 *       'mi-driver': () => new MiDriver(),
 *     },
 *     hooks: { onWrite: auditarEscritura },
 *   })
 *
 * Todo driver debe pasar la suite de contrato que publica el paquete
 * (`@jantstack/adonis-authz/testing`).
 */
export interface AuthorizationConfig {
  /** Nombre del driver activo (debe existir como key en `drivers`). */
  default: string
  drivers: Record<string, AuthorizationDriverFactory>

  /**
   * Holders del consumidor: morph name (`@MorphMap` del modelo) → tipo del
   * modelo FGA. Lo necesitan el driver `openfga` y los comandos
   * `openfga:provision` / `openfga:import`; el driver `database` lo ignora.
   */
  holderTypes?: HolderTypeMap

  /**
   * Conexión al servidor OpenFGA para las herramientas de línea de comandos
   * (el driver recibe estos mismos valores en su factory).
   */
  openfga?: {
    url?: string
    storeId?: string
    modelId?: string
    /** Nombre del store al provisionar. */
    storeName?: string
  }

  /**
   * Hooks del consumidor. `onWrite` se llama tras cada escritura del motor
   * (grant/revoke/deny/removeDeny) — el sitio natural para auditar o emitir
   * eventos. No debe lanzar: una escritura ya aplicada no se revierte por un
   * side-effect fallido.
   */
  hooks?: {
    onWrite?: (event: AuthzWriteEvent) => Promise<void>
  }
}

export function defineConfig<T extends AuthorizationConfig>(config: T): T {
  return config
}
