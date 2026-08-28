import type {
  AuthorizationDriverFactory,
  AuthzWriteEvent,
  HolderTypeMap,
  ScopeAncestorsResolver,
} from './types.js'
import type { CatalogSource } from './catalog.js'

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
   * El árbol de scopes del consumidor: la ÚNICA costura entre su dominio y el
   * motor. `resolveAncestors(scope)` devuelve los ancestros del más cercano a
   * la raíz, o `null` si el scope no existe. El mismo resolutor se pasa a los
   * drivers; aquí lo usa el manager para validar `scopes.attached/moved`
   * (padre existente, sin ciclos) antes de tocar el driver.
   */
  scopes?: {
    resolveAncestors: ScopeAncestorsResolver
  }

  /**
   * Catálogos de roles/permisos del consumidor (uno por módulo: plataforma,
   * tenant…). Los usan `authz:catalog:sync` (los sincroniza en orden, con
   * poda de vínculos) y `authz:catalog:diff` (falla en CI si la base no
   * coincide con el config). Funciones y no valores: un catálogo puede vivir
   * en otro archivo y cargarse perezosamente.
   */
  catalogs?: CatalogSource[]

  /**
   * Hooks del consumidor. `onWrite` se llama tras cada escritura del motor
   * (grant/extended/revoke/deny/removeDeny/scope_purged) — el sitio natural
   * para auditar o emitir eventos. No debe lanzar: una escritura ya aplicada no se revierte por un
   * side-effect fallido.
   */
  hooks?: {
    onWrite?: (event: AuthzWriteEvent) => Promise<void>
  }
}

export function defineConfig<T extends AuthorizationConfig>(config: T): T {
  return config
}
