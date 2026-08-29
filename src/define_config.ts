import type {
  AuthorizationDriverFactory,
  AuthzWriteEvent,
  HolderTypeMap,
  ScopeAncestorsResolver,
  ScopeDescendantsResolver,
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
    /**
     * Descendientes de un scope (2.1, B2). Solo lo usa `authorizedScopes`;
     * sin él esa primitiva lanza 500 `E_AUTHZ_NO_DESCENDANTS_RESOLVER` (nunca
     * una lista incompleta). `sqlDescendantsOf(...)` lo genera para una tabla
     * con columna padre (PG y SQLite).
     */
    descendantsOf?: ScopeDescendantsResolver
    /**
     * Tope de scopes que `authorizedScopes` devuelve (default 1000); superado
     * ⇒ 422 `E_AUTHZ_TOO_MANY_SCOPES`, nunca parcial. Se puede bajar por
     * llamada (`{ maxScopes }`).
     */
    maxScopes?: number
    /**
     * Tope de nodos por llamada a `descendantsOf` (default 10 000): es el
     * `maxNodes` que recibe el resolutor, y si devuelve más el manager lanza
     * 422 `E_AUTHZ_TOO_MANY_SCOPES`.
     */
    maxDescendants?: number
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
   * Toda escritura (`grant`, `revoke`, `deny`, `removeDeny`, `scopes.*`)
   * tiene que llevar `actor` (2.1, B7); sin él, 422 `E_AUTHZ_ACTOR_REQUIRED`
   * antes de tocar el driver. Default `false`: opt-in, y el manager lo avisa
   * al construirse (ver `warnOnOptInSecurity`).
   */
  requireActor?: boolean

  /**
   * Las SEIS escrituras (`grant`, `revoke`, `deny`, `removeDeny`,
   * `scopes.attached/moved/detached`) tienen que declarar `within` (2.1, B1;
   * 2D · F2; en `moved`/`attached` contra destino Y origen, 2E · H1): sin él,
   * 422 `E_AUTHZ_WITHIN_REQUIRED`. `within` se toma de la SESIÓN (tenant
   * autenticado), nunca de la misma entrada que el scope. `'non-root'` exige
   * además que `within` no sea `APP_SCOPE` (422 `E_AUTHZ_WITHIN_ROOT_FORBIDDEN`):
   * la raíz contiene todo y como contención no dice nada; la plataforma, que
   * sí escribe en la raíz, usa `manager.driver()` o una config sin el flag.
   * Default `false` (auditor E2, aceptado y nombrado): la contención es
   * opt-in en 2.1; con `false` un call-site que no la declare escribe donde
   * le digan. Ponlo en `true`/`'non-root'` en cuanto todos los call-sites de
   * tenant la pasen.
   */
  requireWithin?: boolean | 'non-root'

  /**
   * El manager avisa por `console.warn` UNA vez por config cuando
   * `requireWithin`/`requireActor` no están en `true` (seguridad opt-in).
   * `false` lo silencia: es la forma de decir "lo sé y lo asumo".
   */
  warnOnOptInSecurity?: boolean

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
