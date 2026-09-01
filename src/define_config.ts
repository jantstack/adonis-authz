import type {
  AuthorizationDriverFactory,
  AuthzCatalogWriteEvent,
  AuthzWriteEvent,
  HolderTypeMap,
  RelationsDriverFactory,
  ScopeChainResolver,
  ScopeDescendantsResolver,
  ScopeEdgesEnumerator,
  ScopeOutbox,
} from './types.js'
import type { CatalogSource } from './catalog/catalog.js'
import type { RelationsConfig } from './relations/define_relations_config.js'

/**
 * Config del sistema de autorización. Todo lo específico del consumidor
 * entra por aquí: qué drivers existen, cuál está activo, cómo se llaman sus
 * holders y qué hacer cuando el motor escribe.
 *
 *   export default defineConfig({
 *     default: env.get('AUTHZ_DRIVER', 'database'),
 *     holderTypes: { users: 'user', admins: 'admin' },
 *     drivers: {
 *       database: () => new DatabaseAuthorizationDriver({ resolveChain }),
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
   * `openfga:provision`; el driver `database` lo ignora.
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
   * motor. `resolveChain(scope)` devuelve la cadena canónica `[scope tal
   * como está en tu tabla, ...ancestros]` (del más cercano a la raíz, `app`
   * al final), o `null` si el scope no existe (2.5-B · K1: la identidad de un
   * scope es la que devuelve el resolutor, nunca la forma con la que lo
   * escribió el llamante). El mismo resolutor se pasa a los drivers; aquí lo
   * usa el manager para validar `scopes.attached/moved` (padre existente,
   * sin ciclos) antes de tocar el driver.
   */
  scopes?: {
    resolveChain: ScopeChainResolver
    /**
     * Descendientes de un scope (2.1, B2). Solo lo usa `authorizedScopes`;
     * sin él esa primitiva lanza 500 `E_AUTHZ_NO_DESCENDANTS_RESOLVER` (nunca
     * una lista incompleta). `sqlDescendantsOf(...)` lo genera para una tabla
     * con columna padre (PG y SQLite).
     */
    descendantsOf?: ScopeDescendantsResolver
    /**
     * **El árbol entero, paginado** (3b-3a): lo que `authz:reconcile` usa
     * para reconstruir —y para PODAR— el árbol de un driver que lo guarda
     * como hechos propios (`openfga` en modo `facts`). `resolveChain`
     * responde por un scope; esto los enumera todos.
     *
     *   scopes: {
     *     resolveChain,
     *     enumerateEdges: sqlScopeEdges({
     *       table: 'organization_nodes', uuidColumn: 'uuid',
     *       parentColumn: 'parent_uuid', typeColumn: 'kind',
     *     }),
     *   }
     *
     * Solo lo usa `authz:reconcile`: sin él la migración del ÁRBOL no se
     * hace y el comando lo dice (500 `E_AUTHZ_CONFIG`) en vez de suponer que
     * el árbol del backend ya está bien.
     */
    enumerateEdges?: ScopeEdgesEnumerator
    /**
     * Tope de scopes que `authorizedScopes` devuelve (default 1000); superado
     * ⇒ 422 `E_AUTHZ_TOO_MANY_SCOPES`, nunca parcial. Se puede bajar por
     * llamada (`{ maxScopes }`).
     */
    maxScopes?: number
    /**
     * Tope de nodos por llamada a `descendantsOf` (default 10 000): es el
     * `maxNodes` que recibe el resolutor, y si devuelve más el manager lanza
     * 422 `E_AUTHZ_TOO_MANY_SCOPES`. Ni esta cota ni `maxScopes` pueden
     * superar `MAX_SCOPE_BOUND` (10 000 000; 500 `E_AUTHZ_CONFIG` si lo
     * hacen, 2.5-B · ⚪6).
     */
    maxDescendants?: number
    /**
     * **La outbox del árbol** (3b-2d, panel 2 cruce 4 · S5). Con ella,
     * `manager.scopes.attached/moved/detached` NO escriben en el backend:
     * ENCOLAN el cambio —pásale tu transacción en
     * `{ transaction }`— y lo aplica después `node ace authz:scopes:relay`.
     *
     * Sin ella, el paquete escribe en el backend dentro de TU transacción y
     * un `rollback` posterior no lo deshace: el árbol del backend queda
     * adelantado al tuyo y, en `hierarchy: 'facts'` (donde FGA es el PDP),
     * eso es una escalada persistente e invisible desde tu base. Por eso el
     * driver `facts` se niega a construirse sin outbox y sin
     * `acceptScopeDriftRisk: true`.
     *
     * El paquete no impone tabla: `sqlScopeOutbox(...)` implementa el puerto
     * sobre Lucid y `stubs/scopes_outbox_migration.stub` es la migración que
     * puedes copiar, pero cualquier implementación del puerto vale.
     *
     * Lo que la outbox NO arregla: durante el lag del relay (segundos) el
     * backend decide con el árbol VIEJO. Es un fail-open temporal —el tenant
     * antiguo conserva acceso tras un `moved`, los denies heredados no
     * aplican tras un `attached`—. No hay 2PC.
     */
    outbox?: ScopeOutbox
    /**
     * «Sé que sin outbox un `rollback` de mi transacción deja el árbol del
     * backend adelantado al mío, y lo asumo» (3b-2e · E3). Es la salida
     * explícita del gate del MANAGER, que es quien encola: declarar la outbox
     * solo en el driver dejaba el gate del driver contento y la mitigación
     * APAGADA. Tiene que ser el booleano `true`: un valor «truthy» no es una
     * aceptación.
     */
    acceptScopeDriftRisk?: boolean
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
   * Reloj de pared del motor (2.5 · J1): el `now()` con el que TODO driver
   * resuelto por este manager decide la caducidad (`expires_at` en SQL,
   * `current_time` de FGA, filtros en cliente, los tres estados del
   * re-grant). Default: `new Date()` en el driver. El manager lo aplica al
   * resolver el driver (`driver.withClock(clock)`) y todas sus vistas de
   * `forRequest()` lo comparten; un driver sin `withClock` con `clock`
   * declarado es 500 `E_AUTHZ_CONFIG` (nunca un reloj ignorado en silencio).
   * Para tests del consumidor y para un reloj corregido (NTP en el proceso);
   * NO es el reloj monótono de `forRequest({ maxAgeMs })`.
   */
  clock?: () => Date

  /**
   * Deadline TOTAL (ms, default 5000) de la lectura de la **barrera del
   * freeze** que precede a toda escritura (fila `id = 2` de
   * `authz_catalog_version`, 2.3). La barrera se lee SIEMPRE por la conexión
   * del motor, nunca por la transacción del llamante (L-1 · 🟠 8: la
   * autoridad no comparte snapshot con quien escribe), así que
   * `{ transaction }` en `scopes.*` exige **pool ≥ 2**: con pool 1 (SQLite
   * `:memory:`) la barrera no consigue conexión mientras el llamante sostiene
   * la suya y la escritura sale 503 `E_AUTHZ_BACKEND_TIMEOUT` al vencer este
   * deadline — fail-closed, jamás un cuelgue ni un bypass. El mismo valor lo
   * hereda el `RelationsManager` del provider.
   */
  freezeTimeoutMs?: number

  /**
   * Toda escritura (`grant`, `revoke`, `deny`, `removeDeny`, `scopes.*`)
   * tiene que llevar `actor` (2.1, B7); sin él, 422 `E_AUTHZ_ACTOR_REQUIRED`
   * antes de tocar el driver. Default `false`: opt-in, y el manager lo avisa
   * al construirse (ver `warnOnOptInSecurity`).
   */
  requireActor?: boolean

  /**
   * **Puerta 2 de `{ transaction }`** (L-2, opt-in): con `true`, el driver
   * ACTIVO tiene que declarar `capabilities.transactionalWrites: true` o el
   * manager falla **al resolverlo** (500 `E_AUTHZ_CONFIG`) — toda lectura y
   * escritura, `manager.driver()` incluido: el despliegue no arranca. Es lo
   * que convierte «`{ transaction }` a un driver `openfga` es 500 por
   * llamada» (puerta 1, siempre activa) en un fallo en toda la flota en vez
   * de en una ruta poco transitada. Default `false`: el roadmap decía «el
   * manager falla al construirse si el driver no la soporta» y eso haría
   * `openfga` inconstruible en cualquier app que solo lo tenga registrado;
   * quien quiera fallar al arrancar, lo pide. Lo hereda el `RelationsManager`
   * del provider salvo `relations.requireTransactionalWrites`.
   */
  requireTransactionalWrites?: boolean

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
   * Lista BLANCA de permisos que la API de delegación puede meter en un rol
   * local (3B · B3): `defineScopedRole`/`updateScopedRole` rechazan (422
   * `E_AUTHZ_PERMISSION_NOT_DELEGABLE`) cualquier permiso fuera de ella,
   * aunque el actor lo tenga. Default `[]`: nadie delega nada hasta que la
   * plataforma declare qué se puede delegar (los permisos de plataforma
   * —`app:*`, ajustes de organización— no deberían estar). Además el actor
   * tiene que tener cada permiso EFECTIVO en el owner (sin deny).
   */
  delegablePermissions?: string[]

  /**
   * **ReBAC genérico** (Fase 4, `relations/`). Los drivers del puerto
   * `RelationsDriver`, por clave, análogos a `drivers` de roles, más la CONFIG
   * de relaciones (`defineRelationsConfig`) que declara los tipos y sus
   * relaciones. La factory del driver `openfga` de relaciones entra por el
   * subpath `/openfga` DENTRO de ella, como la de roles, así que ningún comando
   * importa el SDK.
   *
   *   const relationsConfig = defineRelationsConfig({
   *     objectTypes: [{ type: 'document', relations: [{ name: 'viewer' }] }],
   *     holderTypes: ['user'],
   *   })
   *   relations: {
   *     config: relationsConfig,
   *     default: env.get('AUTHZ_DRIVER', 'database'),
   *     drivers: {
   *       database: () => new DatabaseRelationsDriver(relationsConfig),
   *       openfga: () => new OpenFgaRelationsDriver(relationsConfig, { ... }),
   *     },
   *   }
   *
   * Con `config` declarado, el paquete cablea el `RelationsManager` como
   * singleton (servicio `@jantstack/adonis-authz/services/relations`, análogo
   * al de roles) y `openfga:provision` incluye los tipos de relación en el
   * modelo `facts` que publica (así un store recién aprovisionado ya acepta
   * tuplas de relación sin un `authz:catalog:sync` previo). `drivers` los usa
   * además `authz:relations:reconcile` para el ORIGEN y el DESTINO de una
   * migración de tuplas.
   */
  relations?: {
    /**
     * La config de relaciones (`defineRelationsConfig(...)`): los tipos de
     * objeto y sus relaciones. Es lo que el `RelationsManager` de servicio usa
     * para F-05 (rechazar un tipo/relación no declarado) y lo que
     * `openfga:provision` mete en el modelo `facts`. Es la MISMA instancia que
     * las factories de `drivers` capturan para construir sus drivers.
     */
    config?: RelationsConfig
    /**
     * Clave del driver de relaciones ACTIVO (en `drivers`) que el singleton de
     * servicio resuelve. Default: el `default` de roles (los drivers de
     * relaciones se nombran igual que los de roles).
     */
    default?: string
    drivers?: Record<string, RelationsDriverFactory>
    /**
     * La puerta 2 de `{ transaction }` para el puerto de RELACIONES (L-2):
     * con `true`, el driver de relaciones activo tiene que declarar
     * `transactionalWrites: true` o `buildRelationsManager` falla al
     * resolverlo (500 `E_AUTHZ_CONFIG`). Default: el
     * `requireTransactionalWrites` del raíz (una sola política, como
     * `requireActor`); `false` aquí lo anula solo para este puerto.
     */
    requireTransactionalWrites?: boolean
  }

  /**
   * Hooks del consumidor. `onWrite` se llama tras cada escritura del motor
   * (grant/extended/revoke/deny/removeDeny/scope_purged) — el sitio natural
   * para auditar o emitir eventos. `onCatalogWrite` (3B · B3) tras cada
   * escritura del CATÁLOGO por la API de delegación (`role_defined`,
   * `role_updated`, `role_purged`), siempre con actor. Ninguno debe lanzar:
   * una escritura ya aplicada no se revierte por un side-effect fallido (se
   * registra y se sigue).
   */
  hooks?: {
    onWrite?: (event: AuthzWriteEvent) => Promise<void>
    onCatalogWrite?: (event: AuthzCatalogWriteEvent) => Promise<void>
  }
}

export function defineConfig<T extends AuthorizationConfig>(config: T): T {
  return config
}
