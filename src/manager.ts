import { Exception } from '@adonisjs/core/exceptions'
import { v7 as uuidv7 } from 'uuid'
import { activeRelationsDriverKey, assertAuthorizationConfigShape, type AuthorizationConfig } from './define_config.js'
import {
  assertCatalogUuid,
  assertIdentity,
  assertScope,
  assertScopeType,
  assertSubject,
  assertValidSlug,
  chainKeysFrom,
  normalizeRoleQuery,
  scopeFromKey,
  scopeKey,
} from './identity.js'
import { expiryChanged } from './expiry.js'
import { randomBytes } from 'node:crypto'
import {
  DEFAULT_FREEZE_LEASE_MS,
  acquireFreezeOutcome,
  UNKNOWN_HOLDER,
  freezeIsLive,
  freezeKindOf,
  readFreezeRow,
  assertNotFrozenRow,
  releaseFreeze,
  renewFreeze,
} from './freeze.js'
import type { FreezeKind, FreezeToken } from './freeze.js'
import { assertKnownScope, canonicalScopeTargets, isAuthzError, resolveChain, rootOnlyResolver } from './shared/backend_guard.js'
import { CatalogCache, GLOBAL_OWNER_KEY, invalidateAuthzCatalog, isRoleVisibleWith, readLocalRoles, withAuthzCatalogWrite } from './catalog/catalog_cache.js'
import type { CatalogView } from './catalog/catalog_cache.js'
import { assertAssignableAt } from './catalog/catalog.js'
import { systemClock } from './clock.js'
import {
  ActorRequiredError,
  AuthorizationBackendError,
  AuthorizationBackendTimeoutError,
  isPartialWrite,
  AuthorizationFrozenError,
  AuthorizationConfigError,
  AuthorizationInternalError,
  CatalogConflictError,
  InvalidIdentityError,
  MassPurgeRefusedError,
  PruneInterruptedError,
  NoDescendantsResolverError,
  NotWithinError,
  PermissionNotDelegableError,
  RankExceededError,
  RoleImmutableError,
  RoleLevelAboveOwnerError,
  ScopeCycleError,
  ScopeResolverError,
  TooManyScopesError,
  UnknownPermissionError,
  UnknownRoleError,
  FreezeHeldError,
  UnsupportedOperationError,
  ViewExpiredError,
  WithinRequiredError,
  WithinRootForbiddenError,
  ScopeDriftUnguardedError,
  ScopeDepthLimitError,
  ScopeRequeueRefusedError,
  StaleSourceRefusedError,
  OperatorWindowExpiredError,
  isDeploymentFailure,
  isTransientRelayFailure,
} from './errors.js'
import { APP_SCOPE_TYPE, normalizeAuthorizationCapabilities } from './types.js'
import { memoizeAncestors } from './memoize_ancestors.js'
import { AUTHZ_TABLES_ORIGIN } from './reconcile.js'
import type {
  AuthorizationDriver,
  AuthorizationDriverCapabilities,
  AuthorizationDriverFactory,
  AuthorizedScopes,
  AuthzCatalogWriteEvent,
  AuthzWriteEvent,
  CatalogRole,
  CatalogRoleRef,
  DenyOptions,
  DenyRef,
  ExcludedSubtree,
  GrantOptions,
  GrantOutcome,
  RoleQuery,
  ScopeChainResolver,
  ScopeDescendantsResolver,
  ScopedRoleChanges,
  ScopedRoleSpec,
  PendingScopeTreeChange,
  ReconcileFactsEnumerator,
  ReconcileOptions,
  ReconcileReport,
  ReconcileSource,
  RelayedScopeChange,
  ScopeEdgesEnumerator,
  ScopedWriteOptions,
  ScopeEnqueueReceipt,
  ScopeOutbox,
  ScopeOutboxLease,
  ScopeRelayBlockOrigin,
  ScopeRelayEntry,
  ScopeRequeueConflict,
  ScopeRequeueReport,
  ScopeRelayFailure,
  ScopeRelayQueue,
  ScopeRelayReport,
  ScopeRef,
  ScopeTreeChange,
  ScopeTreeWriteOptions,
  ScopeType,
  SubjectRef,
  WriteOptions,
  RelationsDriverFactory,
} from './types.js'

/** Longitudes de `authz_roles.name`/`description` (el esquema publicado). */
const ROLE_NAME_MAX = 100
const ROLE_DESCRIPTION_MAX = 500

/** Descripción corta de una respuesta inválida de `authorizeMany`, para el mensaje del 500. */
function describeAnswer(answer: unknown): string {
  if (!Array.isArray(answer)) return `${answer === null ? 'null' : typeof answer} (no es un array)`
  for (let i = 0; i < answer.length; i++) {
    if (!(i in answer)) return `un array de ${answer.length} con un HUECO en la posición ${i}`
    if (typeof answer[i] !== 'boolean') return `un array de ${answer.length} con un elemento que no es boolean en la posición ${i} (${typeof answer[i]})`
  }
  return `un array de ${answer.length}`
}

/**
 * ¿Cada POSICIÓN del array es un boolean? Por índice, nunca con `some`/`every`
 * (que saltan los huecos de un array disperso: 🟡 A3 del auditor del lote A;
 * gemelo de `checkMany` en `src/relations/manager.ts`).
 */
function everyPositionBoolean(answers: unknown[]): answers is boolean[] {
  for (let i = 0; i < answers.length; i++) {
    if (typeof answers[i] !== 'boolean') return false
  }
  return true
}

/**
 * Configs que ya recibieron el aviso de seguridad opt-in (B7/B1): una vez
 * por config, no por instancia — `forRequest()` construye managers hijos con
 * la misma config y no debe repetirlo en cada request.
 */
const warnedConfigs = new WeakSet<object>()

/**
 * Lo que devuelve `AuthorizationManager.forRequest()`: la misma API que el
 * manager (lecturas, escrituras, `scopes.*`), con los ancestros memoizados
 * SOLO en las lecturas. Es un tipo, no otra clase: la vista es un manager
 * hijo que comparte config, driver y hooks con su padre.
 */
export type AuthorizationView = Pick<
  AuthorizationManager,
  | 'authorize'
  | 'hasRole'
  | 'listSubjects'
  | 'listScopes'
  | 'listRoles'
  | 'listRoleScopes'
  | 'grant'
  | 'revoke'
  | 'deny'
  | 'removeDeny'
  | 'scopes'
  | 'driver'
  | 'capabilities'
  | 'forRequest'
  | 'isWithin'
  | 'listDenies'
  | 'effectivePermissions'
  | 'authorizeMany'
  | 'authorizedScopes'
  | 'expandExcludedSubtrees'
  | 'defineScopedRole'
  | 'updateScopedRole'
  | 'deleteScopedRole'
>

/**
 * Expande los `excludedSubtrees` de un `all` (2D · F10) a la lista plana de
 * scopes que hay que restar: cada scope denegado y TODOS sus descendientes,
 * con el `descendantsOf` del config. Es la forma correcta del `NOT IN`;
 * restar solo los scopes con deny dejaría dentro sus subárboles.
 */
export function expandExcludedSubtrees(view: AuthorizationView, excluded: ExcludedSubtree[]): Promise<ScopeRef[]> {
  return view.expandExcludedSubtrees(excluded)
}

/** Cotas por defecto de `authorizedScopes` (config `scopes.maxScopes` / `scopes.maxDescendants`). */
export const DEFAULT_MAX_SCOPES = 1_000
export const DEFAULT_MAX_DESCENDANTS = 10_000
/**
 * Tope sano de `maxScopes`/`maxDescendants` (2.5-B, auditor ⚪6): por encima
 * de ~4,29e9 el hint `SET_VAR(cte_max_recursion_depth)` de MySQL sale de
 * rango y un ciclo en la tabla deja de ser el 422 «posible ciclo» del
 * contrato (503); y ya con 1e6 un ciclo cuesta segundos de CPU por llamada.
 * Una cota mayor es config rota (500), nunca una pregunta.
 */
export const MAX_SCOPE_BOUND = 10_000_000
/**
 * Cotas por defecto de `authz:scopes:relay` (3b-2d). El lote es el tamaño de
 * cada `pending()`; el límite, cuántos cambios aplica una pasada antes de
 * volver (lo que quede sigue pendiente: drenar es reanudable por diseño y
 * una pasada eterna no es reanudable).
 */
export const DEFAULT_RELAY_BATCH = 100
export const DEFAULT_RELAY_LIMIT = 10_000
/** Páginas que `authz:reconcile` pasea para MEDIR la ventana del relay (3b-3a). */
const RELAY_WINDOW_MAX_PAGES = 1_000
/**
 * **Saltos que la sonda de `only` sigue hacia atrás para heredar el ORIGEN de
 * un bloqueo** (2.4.0-alpha.6). Cada salto es una consulta `earlierPending`
 * (0,69 ms) sobre una entrada NO pedida; la cadena es de ids estrictamente
 * decrecientes, así que termina sola — la cota solo acota el coste dentro de
 * una petición inline. Pasada la cota el origen se toma por FALLO (la purga se
 * aplaza a la pasada completa): degrada hacia lo seguro, nunca aplica sin saber.
 */
export const RELAY_ORIGIN_MAX_HOPS = 100
/**
 * **Cota PROPIA del censo de aparcadas** (alpha.5 · cierre, auditor 🟠 2). Las
 * claves de `dead()` que taponan `attached`/`moved` se leen COMPLETAS en cada
 * pasada, sean cuales sean `limit` y `batchSize` (con `--limit 50` o la receta
 * inline `{ only, limit: 1 }` un censo acotado por `limit` dejaba a la aparcada
 * 101 sin taponar y el `attached` colgaba del padre VIEJO — y la sonda de
 * `only` no la ve porque `earlierPending` excluye lo aparcado). Si hay más
 * aparcadas que esto, la pasada se NIEGA (500) en vez de aplicar con un tapón
 * incompleto: una cola así es un incidente, no un lote.
 */
export const PARKED_CENSUS_MAX = 50_000
/** Vida por defecto de una vista de `forRequest()` para LEER (F9): un request, no un módulo. */
export const DEFAULT_VIEW_MAX_AGE_MS = 30_000

/**
 * Cada cuánto reintenta `acquire()` una pasada con `waitForLeaseMs` (2.4.0-alpha.8;
 * panel relay 2, cuestión 7). Medido en PG: 0,29 ms por sondeo ocupado, y el
 * sondeo no retiene conexión entre intentos (la transacción del intento fallido
 * se revierte). El default de `waitForLeaseMs` es 0: el `busy` inmediato de
 * siempre.
 */
export const RELAY_LEASE_POLL_MS = 25
/**
 * Tope de `waitForLeaseMs` (cierre alpha.8, 🟡 1 del auditor): una espera sin tope
 * cuelga la petición de un tenant; por encima es 500 `E_AUTHZ_CONFIG`. Y la espera
 * se cuenta en SONDEOS (`waitForLeaseMs / RELAY_LEASE_POLL_MS`), no solo con el
 * reloj de pared: con `config.clock` fijo el sondeo por reloj no terminaba nunca.
 */
export const RELAY_WAIT_LEASE_MAX_MS = 60_000
/** Las opciones que `relayScopeChanges` conoce (2.4.0-alpha.8 · X-1: cualquier otra es 500). */
const RELAY_OPTIONS = ['limit', 'batchSize', 'dryRun', 'only', 'waitForLeaseMs', 'deadDetail'] as const
/** Precedencia de los orígenes de un bloqueo por clave (2.4.0-alpha.8): un fallo real pisa todo; una pendiente pisa a un aparcado. */
const BLOCK_RANK: Record<ScopeRelayBlockOrigin, number> = { parked: 0, pending: 1, failed: 2 }
/** Las opciones que `requeueScopeChanges` conoce (2.4.0-alpha.8 · X-1: cualquier otra es 500). */
const REQUEUE_OPTIONS = ['force', 'apply', 'waitForLeaseMs'] as const

export interface ForRequestOptions {
  /**
   * Milisegundos durante los que la vista puede LEER (default 30 000).
   * Después, cualquier lectura es 500 `E_AUTHZ_VIEW_EXPIRED`: el memo de
   * ancestros solo es correcto mientras dura el request y una vista guardada
   * por error serviría la cadena vieja para siempre. `0` = sin límite, a
   * sabiendas. Las escrituras e `isWithin` no caducan (resuelven en fresco).
   * Se mide con un reloj MONÓTONO (`performance.now()`, 2E · H3): un salto
   * del reloj de pared hacia atrás no resucita una vista caducada.
   */
  maxAgeMs?: number
  /**
   * SOLO TESTS: fuente del reloj monótono, en ms (default `performance.now`).
   * Sirve para fijar la frontera exacta de `maxAgeMs` sin dormir; en
   * producción no se toca.
   */
  now?: () => number
}

/** Reloj monótono del proceso: inmune a NTP, snapshots y `Date.now` parcheado. */
const monotonicNow = (): number => performance.now()

/** El lado del DUEÑO de un freeze durable (3b-7): token, renovador y si el lease se perdió a mitad. */
interface HeldFreeze {
  token: FreezeToken
  reason: string
  kind: FreezeKind
  /** `null` = sin caducidad (la ventana del operador). */
  leaseMs: number | null
  timer: NodeJS.Timeout | null
  lapsed: boolean
}

/** Lo que `freezeStatus()` responde de un freeze VIVO (la fila, legible por cualquiera). */
export interface FreezeStatus {
  reason: string
  holder: string
  kind: FreezeKind | 'unknown'
  /** Instante (ms de pared) en el que el lease vence, o `null` si no caduca. */
  untilMs: number | null
  fence: number
}

/**
 * Lo que `withFrozenWrites` le cuenta a la pasada que corre dentro (L-1 · J1):
 * el fence de la ventana, su lease y si se PERDIÓ a mitad (`lapsed`), para
 * que una pasada de plataforma ajena al manager publique la garantía en vez
 * de suponerla (`report.frozen`).
 */
export interface FrozenWindow {
  fence: number
  /**
   * El lease de la ventana. En la ventana del OPERADOR adoptada
   * (2.4.0-alpha.10) es lo que le QUEDABA al adoptarla (`untilMs − ahora`);
   * `null` solo si la ventana no caduca.
   */
  leaseMs: number | null
  /**
   * Solo en la ventana del OPERADOR adoptada (2.4.0-alpha.10, 🟡 3 del sexto
   * informe de COGNITIV): el instante (ms de pared) en el que caduca, de la
   * fila, o `null` si no caduca. Quien adopta la ventana no la renueva: si
   * caduca a mitad, `lapsed` lo dice; esto dice que PUEDE caducar.
   */
  untilMs?: number | null
  /**
   * EN QUÉ ventana corrió (2.4.0-alpha.10, S2): la del OPERADOR adoptada, una
   * PROPIA tomada para la pasada, o la que ya sostenía este manager
   * (`enclosing`). La salida de los comandos lo dice siempre: «corrí dentro del
   * cutover» y «tomé mi ventana porque no había ninguna» eran letra a letra
   * iguales.
   */
  window?: 'operator' | 'own' | 'enclosing'
  /** ¿Se perdió la ventana en algún momento? (renovación fallida, fila ajena o vencida). */
  lapsed: () => Promise<boolean>
}

/** El contexto de una ventana congelada (`#durableFreezeContext`): cómo se cierra y cómo se audita. */
interface FrozenWindowContext extends FrozenWindow {
  release: () => Promise<void>
}

/**
 * Manager de autorización — la fachada que usan middleware, services y
 * seeders. Resuelve el driver activo del config y notifica cada escritura
 * al hook `onWrite` del consumidor (el chasis lo usa para auditar + SSE).
 *
 * Pieza del "paquete" de autorización: NO conoce config files, modelos ni
 * módulos del consumidor — recibe todo por constructor. El singleton de la
 * app vive en `main.ts` (el único archivo de wiring, fuera del paquete).
 */
export class AuthorizationManager {
  #config: AuthorizationConfig
  #driver: AuthorizationDriver | null = null
  /** Manager del que esta vista toma el driver (solo en vistas de `forRequest`). */
  #parent: AuthorizationManager | null = null
  /** Resolutor memoizado de ESTA vista; `null` = leer con el driver tal cual. */
  #readResolver: ScopeChainResolver | null = null
  #readDriver: AuthorizationDriver | null = null
  /** Memo del catálogo propio, solo si el driver no expone el suyo (composición sin puerto). */
  #ownCatalog: CatalogCache | null = null
  /** Instante (reloj monótono, `#clock`) a partir del cual esta vista ya no puede leer; `null` = sin límite / no es vista. */
  #readsUntil: number | null = null
  /** Reloj monótono con el que se mide `#readsUntil` (inyectable solo en tests). */
  #clock: () => number = monotonicNow
  /**
   * El freeze que ESTE manager sostiene (su token, su renovador), o `null`.
   * Vive en el manager RAÍZ —una vista de `forRequest()` no es otro motor—
   * pero desde 3b-7 el ESTADO del freeze es la fila `id = 2` de
   * `authz_catalog_version`: esto es solo el lado del dueño (quién renueva y
   * qué token puede levantarlo). Que la barrera alcance a las vistas y al
   * resto de la FLOTA lo garantiza la fila, no esta referencia.
   */
  #heldFreeze: HeldFreeze | null = null

  constructor(config: AuthorizationConfig) {
    // Cierre 1 del lote B · 🟡 6 (L5): la FORMA del config se valida aquí también —
    // el provider construye con `new AuthorizationManager(config)` y un consumidor
    // puede saltarse `defineConfig`; un typo (`requireWithing`) no puede entrar en
    // silencio por ninguna puerta.
    assertAuthorizationConfigShape(config)
    this.#config = config
    if (config.clock !== undefined && typeof config.clock !== 'function') {
      throw new AuthorizationConfigError(
        `AuthorizationManager: config.clock debe ser una función () => Date (llegó ${typeof config.clock})`
      )
    }
    this.#warnOptInSecurity()
  }

  /**
   * `requireWithin` y `requireActor` son opt-in en 2.1 (auditor E2, aceptado
   * y nombrado): con los defaults, un call-site que no pase `within` concede
   * donde le digan y una escritura sin `actor` se audita sin autor. Se avisa
   * UNA vez por config al construir el manager; `warnOnOptInSecurity: false`
   * es la forma explícita de asumirlo.
   */
  #warnOptInSecurity(): void {
    const config = this.#config
    if (config.warnOnOptInSecurity === false) return
    const missing = (['requireWithin', 'requireActor'] as const).filter((flag) => !config[flag])
    if (missing.length === 0 || warnedConfigs.has(config)) return
    warnedConfigs.add(config)
    const consequences: Record<(typeof missing)[number], string> = {
      requireWithin: "las escrituras sin 'within' van al scope que les digan, sea de quien sea",
      requireActor: 'las escrituras se auditan sin autor',
    }
    console.warn(
      `authz: seguridad opt-in sin activar — ${missing.join(', ')}: ` +
        `${missing.map((flag) => consequences[flag]).join('; ')}. ` +
        `Actívalo en config/authorization.ts o silencia este aviso con warnOnOptInSecurity: false.`
    )
  }

  /**
   * Vista por request (2A/A3): las LECTURAS (`authorize`, `hasRole`, `list*`)
   * resuelven ancestros con `memoizeAncestors(config.scopes.resolveChain)`
   * —una llamada al árbol por scope durante la vida de la vista—; las
   * ESCRITURAS (`grant`, `revoke`, `deny`, `removeDeny`, `scopes.*`) siguen
   * resolviendo en fresco, porque una lectura obsoleta caduca sola y un
   * grant sobre una cadena que ya cambió queda escrito para siempre (auditor
   * C3/E3). El memo es de ANCESTROS, nunca de decisiones: un deny escrito
   * entre dos `authorize` de la misma vista cambia la segunda respuesta.
   *
   * Patrón en Adonis: un middleware hace `ctx.authz = authorization.forRequest()`
   * y controladores y policies leen de `ctx.authz`. Sin `AsyncLocalStorage`:
   * la vista es un objeto explícito con la vida que le des. Sin
   * `config.scopes.resolveChain`, o con un driver de terceros sin
   * `withChainResolver`, la vista lee con el driver tal cual (sin memo)
   * y sigue siendo correcta.
   */
  forRequest(options: ForRequestOptions = {}): AuthorizationView {
    const maxAgeMs = options.maxAgeMs ?? DEFAULT_VIEW_MAX_AGE_MS
    if (!Number.isInteger(maxAgeMs) || maxAgeMs < 0) {
      throw new AuthorizationConfigError(
        `forRequest: maxAgeMs debe ser un entero >= 0 (0 = sin límite; llegó ${String(maxAgeMs)})`
      )
    }
    if (options.now !== undefined && typeof options.now !== 'function') {
      throw new AuthorizationConfigError(`forRequest: now debe ser una función (llegó ${typeof options.now})`)
    }
    const view = new AuthorizationManager(this.#config)
    view.#parent = this.#parent ?? this
    const resolver = this.#config.scopes?.resolveChain
    view.#readResolver = resolver ? memoizeAncestors(resolver) : null
    view.#clock = options.now ?? monotonicNow
    view.#readsUntil = maxAgeMs === 0 ? null : view.#clock() + maxAgeMs
    return view
  }

  /**
   * El driver activo, TAL CUAL. Es la salida explícita de las barreras del
   * manager (2D · G4, auditor 8): lo que escribas por aquí no pasa por
   * `actor`/`requireActor`, `within`/`requireWithin` ni `onWrite`, y lo que
   * leas no pasa por el memo de ancestros. Está pensado para el código de
   * PLATAFORMA (seeders, comandos, la escritura en la raíz con
   * `requireWithin: 'non-root'`) y para tests; un call-site de tenant nunca
   * debería llamarlo. No se ofrece nada más por aquí a propósito.
   *
   * Lo único que el manager le aplica al resolverlo es el reloj del config
   * (`clock`, 2.5 · J1) vía `withClock`: no es una barrera, es la hora con
   * la que el driver decide, y vale igual para la plataforma, los tests y
   * cada vista de `forRequest()` (todas leen el driver del padre). Un driver
   * sin `withClock` con `clock` declarado es 500 `E_AUTHZ_CONFIG`.
   */
  async driver(): Promise<AuthorizationDriver> {
    if (this.#parent) return this.#parent.driver()
    if (this.#driver) return this.#driver
    const registry: Record<string, AuthorizationDriverFactory> = this.#config.drivers
    const factory = registry[this.#config.default]
    if (!factory) {
      throw new Exception(
        `Driver de autorización '${this.#config.default}' no registrado. ` +
          `Registrados: ${Object.keys(this.#config.drivers).join(', ')}`,
        { status: 500 }
      )
    }
    let driver = await factory()
    const clock = this.#config.clock
    if (clock !== undefined) {
      if (typeof driver.withClock !== 'function') {
        throw new AuthorizationConfigError(
          `config.clock está declarado pero el driver '${this.#config.default}' no implementa withClock(now): ` +
            `el reloj no llegaría a ninguna decisión. Implementa withClock en el driver o quita clock del config.`
        )
      }
      driver = driver.withClock(clock)
    }
    this.#assertTransactionalWritesRequired(driver)
    this.#assertScopeDriftGuarded(driver)
    this.#driver = driver
    return driver
  }

  /**
   * **Lo que el driver ACTIVO declara, de solo lectura** (2.4.0-alpha.4;
   * pregunta 1 de COGNITIV, panel alpha.4). Para que el código de tenant
   * pueda ramificar —`if ((await authorization.capabilities()).transactionalWrites)
   * grant(…, { transaction }) else grant(…)`— sin llamar a `driver()`, que
   * sigue siendo API de PLATAFORMA (el grep del README sigue significando lo
   * que significa).
   *
   * Es `(await this.driver()).capabilities` y NADA más, a propósito:
   *  - las capacidades son de la INSTANCIA (`database` decide
   *    `transactionalWrites` desde sus opciones), así que hay que resolver;
   *  - y se resuelve POR `driver()`, con sus dos puertas
   *    (`requireTransactionalWrites` y el gate de deriva del árbol) y su
   *    caché. Resolverlo por otro camino «para que la lectura no lance» y
   *    guardarlo en `#driver` dejaría `driver()` sirviendo un driver que
   *    nunca pasó por las puertas: un bypass permanente del gate de deriva
   *    (🔴 1 del auditor). Por eso hereda los 500 de las puertas
   *    (`E_AUTHZ_CONFIG`, `E_AUTHZ_SCOPE_DRIFT_UNGUARDED`) y la factory del
   *    consumidor: llámalo al arrancar (un hook `booted`/`ready`), no por
   *    request en un endpoint de metadatos.
   *
   * Devuelve una copia CONGELADA y NORMALIZADA: todas las claves de
   * `AuthorizationDriverCapabilities` presentes, solo `true` es `true`
   * (la misma lectura que la puerta 1), nunca `undefined`; mutarla no toca
   * el objeto que leen las puertas. La vista de `forRequest()` delega en el
   * padre (por `driver()`).
   */
  async capabilities(): Promise<Readonly<AuthorizationDriverCapabilities>> {
    const driver = await this.driver()
    return normalizeAuthorizationCapabilities(driver.capabilities)
  }

  /**
   * **Puerta 2 de `{ transaction }`** (L-2, opt-in): con
   * `requireTransactionalWrites: true` el driver activo tiene que declarar
   * `transactionalWrites: true` o el manager falla AL RESOLVERLO — antes de
   * cachearlo, así que toda lectura, toda escritura y `driver()` fallan igual:
   * el despliegue no arranca. Es la forma honesta de «fallar al construirse»:
   * el roadmap lo pedía incondicional y eso haría `openfga` inconstruible en
   * cualquier app que solo lo tenga registrado (y el driver se resuelve
   * perezosamente y por nombre, así que al construir no se sabe si alguien
   * pasará `{ transaction }`). Quien quiera fallar al arrancar, lo pide.
   */
  #assertTransactionalWritesRequired(driver: AuthorizationDriver): void {
    if (this.#config.requireTransactionalWrites !== true) return
    if (driver.capabilities?.transactionalWrites === true) return
    throw new AuthorizationConfigError(
      `config.requireTransactionalWrites está en true y el driver '${this.#config.default}' declara ` +
        `transactionalWrites: ${driver.capabilities ? String(driver.capabilities.transactionalWrites) : 'nada (sin capabilities)'}: ` +
        `no puede inscribir grant/revoke/deny/removeDeny en la transacción del consumidor («los dos o ninguno»), así ` +
        `que el manager no se resuelve. Usa un driver que la declare (database) o quita requireTransactionalWrites.`
    )
  }

  /**
   * **Puerta 1 de `{ transaction }`** (L-2, siempre activa): una escritura de
   * HECHOS con `{ transaction }` a un driver que no declara
   * `transactionalWrites: true` es 500 `E_AUTHZ_UNSUPPORTED` nombrando driver
   * y operación, ANTES de la barrera, de la identidad y del driver (cero
   * llamadas). Nunca se ignora, nunca un `logger.warn`: aceptarla y no
   * cumplirla sería publicar con nuestra firma la fuga del cruce 4 · S5.
   * `scopes.*` NO pasa por aquí: su `transaction` ENCOLA (encolar ≠ escribir).
   */
  async #assertTransactionalWrite(options: WriteOptions | undefined, operation: string): Promise<void> {
    if (options?.transaction === undefined || options.transaction === null) return
    const driver = await this.driver()
    if (driver.capabilities?.transactionalWrites === true) return
    throw UnsupportedOperationError.transactional(operation, this.#config.default, 'roles')
  }

  /**
   * La marca del evento de una escritura inscrita en la transacción del
   * llamante (L-3): `onWrite` se dispara cuando el DRIVER vuelve, y en ese
   * momento la fila existe solo dentro de esa transacción — es un hecho si y
   * solo si el llamante confirma, cosa que el paquete nunca ve. Quien audita
   * lo necesita para no registrar como firme lo que un rollback deshace.
   */
  #transactional(options: WriteOptions | undefined): { transactional?: true } {
    return options?.transaction === undefined || options.transaction === null ? {} : { transactional: true }
  }

  /** La API de delegación no admite `{ transaction }` (§1.4 del veredicto `{trx}`): 500 antes de tocar nada. */
  #assertNoTransaction(options: WriteOptions | undefined, operation: string): void {
    if (options?.transaction === undefined || options.transaction === null) return
    throw UnsupportedOperationError.transactionalCatalog(operation)
  }

  /**
   * **El gate de deriva del árbol, en el MANAGER** (3b-2e · E3; cierra el
   * agujero que declaró el 3b-2d).
   *
   * El driver `facts` ya se niega a construirse sin `outbox` ni firma, pero
   * ese gate mira SU opción `outbox` — y quien ENCOLA es el manager, que lee
   * `config.scopes.outbox`. Pasarle la instancia solo al driver dejaba el
   * gate contento y la mitigación apagada: `manager.scopes.*` seguía
   * escribiendo en el backend dentro de la transacción del consumidor, que
   * es exactamente S5. Aquí se cierra, y se cierra porque el driver DECLARA
   * su `hierarchy` (`capabilities.hierarchyFacts`, la pieza de capacidades de
   * este lote).
   *
   * Un driver sin `capabilities` (2.x, o de terceros) se trata como
   * `hierarchyFacts: false`: no hay dos árboles y no hay deriva que mitigar.
   */
  #assertScopeDriftGuarded(driver: AuthorizationDriver): void {
    if (!driver.capabilities?.hierarchyFacts) return
    if (this.#config.scopes?.outbox) return
    if (this.#config.scopes?.acceptScopeDriftRisk === true) return
    throw new ScopeDriftUnguardedError(
      `El driver '${this.#config.default}' declara el árbol como hechos propios (hierarchy: 'facts') y ` +
        "config/authorization.ts no trae 'scopes.outbox': el manager escribiría el árbol en el backend DENTRO de tu " +
        'transacción, y un rollback posterior no lo deshace (el backend queda adelantado a tu base y esa escalada no ' +
        "se ve desde ella). Declarar la outbox solo en el driver NO basta: quien encola es el manager. Pon la MISMA " +
        "instancia en scopes.outbox, o firma el riesgo con scopes.acceptScopeDriftRisk: true."
    )
  }

  /**
   * **Congela las ESCRITURAS del motor, DURABLE** (3b-7; decisión del dueño
   * del 2026-08-31 (3b): B + E-analista). Operación de PLATAFORMA, como
   * `driver()`: no se expone por HTTP.
   *
   * El estado ya NO vive en el proceso: vive en la fila `id = 2` de
   * `authz_catalog_version`, así que alcanza a **todos los procesos que
   * comparten las tablas `authz_*`** (invariante 14: el comando ace y los
   * workers hablan con la misma base). Mientras el freeze está vivo, toda
   * escritura del manager —las cuatro de hechos, las tres de árbol, la API
   * de delegación, `pruneOrphanRoles({force})` y `relayScopeChanges`—
   * responde 503 `E_AUTHZ_FROZEN` **reintentable** y no llega al driver; las
   * LECTURAS siguen respondiendo con normalidad (la asimetría deliberada:
   * `authorize` no se congela ni un milisegundo).
   *
   * Devuelve el **token del dueño** (`{ fence, holder }`): `unfreeze(token)`
   * solo levanta el freeze cuyo token coincide — el `finally` de una ventana
   * ajena o rezagada no puede levantar la tuya (auditor A1.3). Un freeze
   * VIVO de otro dueño ⇒ 423 `E_AUTHZ_FREEZE_HELD`, nunca dos dueños.
   *
   * El **lease** (default 15 s) se renueva solo (`leaseMs / 3`, `unref()`)
   * mientras este proceso vive; si el proceso muere (`SIGKILL`, OOM), el
   * lease vence y la flota vuelve a escribir SOLA en ≤ `leaseMs` — nadie
   * limpia nada a mano. `leaseMs: null` = sin caducidad: la ventana del
   * OPERADOR (`authz:freeze`), que dura hasta su `authz:unfreeze`.
   *
   * Lo que el freeze **NO congela**, a propósito y documentado (auditor
   * 🟠 5): `syncAuthzCatalog` (función libre que no ve al manager),
   * `manager.driver()` (la salida documentada de TODAS las barreras) y el
   * árbol SQL del consumidor (sus tablas, su SQL). Y lo que no puede
   * prometer: una escritura que ya pasó su barrera cuando el freeze aterriza
   * ENTRA (no hay atomicidad entre una fila SQL y un backend externo) — la
   * promesa publicada es «otro proceso recibe 503», jamás «ninguna escritura
   * entra en la ventana».
   */
  async freeze(reason?: string, options: { leaseMs?: number | null; kind?: FreezeKind } = {}): Promise<FreezeToken> {
    const root = this.#root()
    if (root.#heldFreeze) {
      throw new FreezeHeldError(
        `freeze: este manager ya sostiene el freeze (fence ${root.#heldFreeze.token.fence}, ` +
          `motivo: ${root.#heldFreeze.reason}). Una ventana dentro de otra corre DENTRO (withFrozenWrites/reconcile); ` +
          `si quieres otra ventana, levanta antes la tuya con unfreeze(token).`
      )
    }
    const kind: FreezeKind = options.kind ?? 'platform'
    const leaseMs = options.leaseMs === undefined ? DEFAULT_FREEZE_LEASE_MS : options.leaseMs
    if (leaseMs !== null && (!Number.isInteger(leaseMs) || leaseMs < 1)) {
      throw new AuthorizationConfigError(`freeze: leaseMs debe ser un entero >= 1 o null (llegó ${String(leaseMs)})`)
    }
    const finalReason = reason ?? 'una operación de plataforma'
    const holder = `${kind}:${process.pid}:${randomBytes(4).toString('hex')}`
    const nowMs = root.#wallMs()
    // alpha.10 · S2 (+ cierre del auditor · R2): una ventana de OPERADOR
    // caducada no se pisa en silencio. Una fila con el lease vencido se toma
    // encima (así la flota vuelve sola tras un SIGKILL de una pasada), pero la
    // del operador es EVIDENCIA: pisarla y soltarla después la deja a NULL y
    // borra el único rastro de que las escrituras volvieron a entrar a mitad
    // del cutover. La exclusión vive DENTRO del UPDATE de `acquireFreezeOutcome`
    // (atómica): aquí solo se lee el veredicto y la fila para redactarlo — un
    // «compruebo y luego tomo» con dos lecturas del reloj era un TOCTOU.
    const outcome = await acquireFreezeOutcome(
      { reason: finalReason, holder, untilMs: leaseMs === null ? null : nowMs + leaseMs, nowMs },
      { driver: this.#config.default }
    )
    if (outcome.status === 'expired-operator') {
      const row = outcome.row
      const when = row.untilMs === null ? '?' : new Date(row.untilMs).toISOString()
      throw new OperatorWindowExpiredError(
        `freeze (${reason ?? kind}): la ventana del OPERADOR (${row.holder ?? '?'}, ${row.reason}, fence ` +
          `${row.fence}) CADUCÓ el ${when} y nadie la cerró: desde entonces las escrituras volvieron a entrar en ` +
          `toda la flota. No se toma una ventana propia encima —borraría ese rastro al soltarla y la pasada se ` +
          `certificaría como si hubiera corrido dentro del cutover—. Reconócela con authz:unfreeze (dice cuánto ` +
          `tiempo estuvo abierta y limpia la fila) y reabre la ventana con authz:freeze antes de repetir.`
      )
    }
    if (outcome.status === 'held') {
      const row = outcome.row
      throw new FreezeHeldError(
        `freeze: ya hay un freeze VIVO de otro dueño (${row.holder ?? '?'}, fence ${row.fence}, motivo: ${row.reason ?? '?'}). ` +
          `Espera a que termine, o levántalo con authz:unfreeze si su proceso murió sin lease.`
      )
    }
    const token = outcome.token
    const held: HeldFreeze = { token, reason: finalReason, kind, leaseMs, timer: null, lapsed: false }
    if (leaseMs !== null) {
      const interval = Math.max(250, Math.floor(leaseMs / 3))
      held.timer = setInterval(() => void root.#renewHeldFreeze(held), interval)
      held.timer.unref?.()
    }
    root.#heldFreeze = held
    return token
  }

  /**
   * Renovación CONDICIONAL del lease (fence + holder + «aún no venció»).
   * 0 filas ⇒ el lease se PERDIÓ a mitad (pausa de GC más larga que el
   * lease, base caída, otro dueño): se marca `lapsed`, se deja de renovar y
   * NUNCA se «recupera» — la pasada que lo sostenía no se certifica.
   */
  async #renewHeldFreeze(held: HeldFreeze): Promise<void> {
    if (held.lapsed || held.leaseMs === null) return
    const nowMs = this.#wallMs()
    try {
      const renewed = await renewFreeze(held.token, { untilMs: nowMs + held.leaseMs, nowMs }, { driver: this.#config.default })
      if (!renewed) {
        held.lapsed = true
        if (held.timer) clearInterval(held.timer)
      }
    } catch {
      // Base caída: transitorio. Los escritores tampoco pueden escribir (su
      // barrera es la misma base, fail-closed); si la caída dura más que el
      // lease, la SIGUIENTE renovación toca 0 filas y marca lapsed.
    }
  }

  /**
   * Levanta el freeze de ESTE token; uno ajeno o rezagado no toca nada (esa
   * es toda la garantía del fence). Devuelve si de verdad lo levantó.
   */
  async unfreeze(token: FreezeToken): Promise<boolean> {
    if (!token || typeof token.fence !== 'number' || typeof token.holder !== 'string') {
      throw new AuthorizationConfigError(
        'unfreeze: hace falta el token que devolvió freeze() ({ fence, holder }). Levantar el freeze de otro es authz:unfreeze.'
      )
    }
    const root = this.#root()
    const { released, lapsed } = await releaseFreeze(token, { nowMs: root.#wallMs() }, { driver: this.#config.default })
    const held = root.#heldFreeze
    if (held && held.token.fence === token.fence && held.token.holder === token.holder) {
      if (held.timer) clearInterval(held.timer)
      held.lapsed = held.lapsed || lapsed
      root.#heldFreeze = null
    }
    return released
  }

  /**
   * ¿SOSTIENE este manager un freeze? (proceso-local: su token vive aquí.)
   * Para saber si el MOTOR está congelado —por quien sea— pregunta
   * `freezeStatus()`: eso es la fila, no la memoria.
   */
  get frozen(): boolean {
    return this.#root().#heldFreeze !== null
  }

  /**
   * La clave (en `relations.drivers`) del driver de RELACIONES activo:
   * `relations.default ?? default` (2.4.0-alpha.10). La lee el guard de la
   * dirección rancia de `runRelationsReconcile`; desde el cierre del auditor
   * (R4) el llamante ya no puede contradecirla con un `activeKey` propio.
   */
  relationsDriverKey(): string {
    return activeRelationsDriverKey(this.#root().#config)
  }

  /** Las claves registradas en `relations.drivers` del config de ESTE manager (vacío si no hay relaciones). */
  relationsDriverKeys(): string[] {
    return Object.keys(this.#root().#config.relations?.drivers ?? {})
  }

  /**
   * La factory registrada bajo `key` en `relations.drivers` de ESTE manager, o
   * `undefined` (cierre del auditor de alpha.10 · R4). `runRelationsReconcile`
   * resuelve el origen y el destino por aquí —del MISMO config que decide el
   * activo— y juzga la identidad por la factory resuelta, no por la etiqueta:
   * dos claves con la misma factory son el mismo driver (y dos factories DISTINTAS
   * sobre el mismo backend NO: límite declarado, cierre-2 · C1).
   *
   * **API de PLATAFORMA, junto a `driver()`** (cierre-2 · C6): con esta factory
   * cualquier código que tenga el manager —vistas de `forRequest()` incluidas—
   * construye un driver de relaciones NO activo y escribe en él sin `assertWrite`,
   * `requireActor`, freeze ni `onRelationWrite`. No añade capacidad (el config ya
   * da las factories), pero es otra cosa que buscar en una revisión.
   */
  relationsDriverFactory(key: string): RelationsDriverFactory | undefined {
    const drivers = this.#root().#config.relations?.drivers
    if (drivers === undefined || !Object.prototype.hasOwnProperty.call(drivers, key)) return undefined
    return drivers[key]
  }

  /** El freeze VIVO de la fila compartida, o `null`. Lo lee cualquiera; solo el token lo levanta. */
  async freezeStatus(): Promise<FreezeStatus | null> {
    const row = await readFreezeRow({ driver: this.#config.default })
    if (!freezeIsLive(row, this.#root().#wallMs())) return null
    return {
      reason: row.reason as string,
      holder: row.holder ?? UNKNOWN_HOLDER,
      kind: freezeKindOf(row.holder),
      untilMs: row.untilMs,
      fence: row.fence,
    }
  }

  /**
   * **La ÚLTIMA ventana de la fila, también la CADUCADA** (2.4.0-alpha.10, 🟠 2
   * del sexto informe de COGNITIV). `freezeStatus()` responde solo lo VIVO —y
   * así lo siguen usando la barrera y los comandos—, de modo que una ventana
   * cuyo lease venció era indistinguible de «nunca hubo»: `authz:unfreeze`
   * decía éxito y el último paso del cutover no delataba que las escrituras
   * habían vuelto a entrar a mitad. Se distingue por la fila: `releaseFreeze`
   * pone el motivo a `null` al levantar, así que motivo puesto + `untilMs` en
   * el pasado es una ventana que CADUCÓ sin que nadie la cerrase.
   *
   * `null` = nunca hubo o ya se levantó; `expired: false` = viva (lo mismo que
   * `freezeStatus()`); `expired: true` = caducada. `checkedAtMs` es el instante
   * del reloj del config con el que se decidió.
   */
  async lastFreezeStatus(): Promise<(FreezeStatus & { expired: boolean; checkedAtMs: number }) | null> {
    const row = await readFreezeRow({ driver: this.#config.default })
    if (row.reason === null) return null
    const nowMs = this.#root().#wallMs()
    return {
      reason: row.reason,
      holder: row.holder ?? UNKNOWN_HOLDER,
      kind: freezeKindOf(row.holder),
      untilMs: row.untilMs,
      fence: row.fence,
      expired: !freezeIsLive(row, nowMs),
      // El instante (reloj del config) con el que se decidió `expired`.
      checkedAtMs: nowMs,
    }
  }

  /**
   * `freeze()` + `finally unfreeze(token)`. El `finally` es la parte que
   * importa: una migración que revienta a la mitad no puede dejar la
   * aplicación sin poder escribir (y si además el proceso muere sin
   * `finally`, el lease vence solo). **El anidado corre DENTRO** (auditor
   * A1.1/A1.3): si este manager ya sostiene el freeze, la ventana interior
   * no toma otro ni lo levanta al salir — la exterior sigue en pie.
   */
  async withFrozenWrites<T>(
    reason: string,
    fn: (window: FrozenWindow) => Promise<T>,
    options: { kind?: FreezeKind; operatorAsContext?: boolean } = {}
  ): Promise<T> {
    // L-1 · J1: una pasada que quiera correr DENTRO de la ventana del
    // operador (el cutover) y publicar su `lapsed` —`authz:relations:reconcile`,
    // que vive fuera de este manager— pide `kind: 'reconcile'` y
    // `operatorAsContext: true`, lo mismo que hace `reconcile` de roles.
    const context = await this.#durableFreezeContext(reason, options.kind ?? 'platform', {
      operatorAsContext: options.operatorAsContext === true,
    })
    try {
      return await fn({
        fence: context.fence,
        leaseMs: context.leaseMs,
        lapsed: context.lapsed,
        ...(context.untilMs === undefined ? {} : { untilMs: context.untilMs }),
        ...(context.window === undefined ? {} : { window: context.window }),
      })
    } finally {
      await context.release()
    }
  }

  /**
   * El contexto de una ventana congelada: quién la sostiene, cómo se cierra
   * y cómo se sabe si el lease se perdió a mitad (`lapsed`). Tres formas:
   *
   *  1. Este manager YA sostiene un freeze ⇒ la ventana corre DENTRO y el
   *     `release` es un no-op (la exterior manda).
   *  2. Hay un freeze de OPERADOR vivo y `operatorAsContext` ⇒ el cutover:
   *     `reconcile` corre dentro de la ventana del operador, no la renueva
   *     ni la levanta, y su `lapsed` es «¿seguía la MISMA ventana viva al
   *     terminar?».
   *  3. Nadie ⇒ se toma uno propio (lease renovado) y se suelta al salir.
   *     Un freeze vivo de otro dueño ⇒ 423 (lo lanza `freeze()`).
   */
  async #durableFreezeContext(
    reason: string,
    kind: FreezeKind,
    options: { operatorAsContext: boolean }
  ): Promise<FrozenWindowContext> {
    const root = this.#root()
    const outer = root.#heldFreeze
    if (outer) {
      return {
        fence: outer.token.fence,
        leaseMs: outer.leaseMs,
        window: 'enclosing',
        release: async () => {},
        lapsed: () => root.#tokenLapsed(outer.token, outer.lapsed),
      }
    }
    if (options.operatorAsContext) {
      const status = await this.freezeStatus()
      if (status !== null && status.kind === 'operator') {
        const token: FreezeToken = { fence: status.fence, holder: status.holder }
        // alpha.10 · 3: la caducidad REAL de la ventana adoptada. Hasta alpha.9
        // `leaseMs: null` fijo — el reporte decía «sin caducidad» de una ventana
        // abierta con `--lease-ms` (la certificación sí leía la fila).
        return {
          fence: status.fence,
          leaseMs: status.untilMs === null ? null : Math.max(0, status.untilMs - root.#wallMs()),
          untilMs: status.untilMs,
          window: 'operator',
          release: async () => {},
          lapsed: () => root.#tokenLapsed(token, false),
        }
      }
    }
    const token = await this.freeze(reason, { kind })
    const held = root.#heldFreeze!
    return {
      fence: token.fence,
      leaseMs: held.leaseMs,
      window: 'own',
      release: async () => {
        try {
          await this.unfreeze(token)
        } catch (error) {
          // La base no respondió al soltar: el lease vence solo en <= leaseMs
          // y los escritores ya están recibiendo 503 de esa misma base.
          console.warn('authz: no se pudo soltar el freeze al cerrar la ventana (el lease vencerá solo)', error)
        }
      },
      lapsed: () => root.#tokenLapsed(token, held.lapsed),
    }
  }

  /** ¿Se perdió la ventana de ESTE token en algún momento? (la renovación fallida, o la fila ya no es suya / venció). */
  async #tokenLapsed(token: FreezeToken, alreadyLapsed: boolean): Promise<boolean> {
    if (alreadyLapsed) return true
    const row = await readFreezeRow({ driver: this.#config.default })
    const mine = row.fence === token.fence && row.holder === token.holder
    return !mine || (row.untilMs !== null && row.untilMs <= this.#wallMs())
  }

  /** Milisegundos de PARED con el reloj del config (el mismo que decide caducidades). */
  #wallMs(): number {
    return (this.#config.clock ?? systemClock)().getTime()
  }

  /** El manager raíz: el de una vista de `forRequest()` es su padre. */
  #root(): AuthorizationManager {
    return this.#parent ?? this
  }

  /**
   * La barrera del freeze, delante de TODA escritura del manager. Va antes
   * de validar identidades y de tocar el árbol: durante la migración una
   * escritura no se valida a medias, se rechaza entera. Desde 3b-7 es la
   * FILA compartida (consulta propia por PK, sin memo: +0,14 ms p50 por
   * escritura, medidos; 0 en `authorize`) — un freeze cacheado 30 s no es un
   * freeze, y con `catalogRevalidate: { everyMs }` la fila del memo ni se
   * lee.
   */
  async #assertNotFrozen(operation: string): Promise<void> {
    const root = this.#root()
    const held = root.#heldFreeze
    if (held) {
      throw new AuthorizationFrozenError(
        `${operation}: el motor de autorización está congelado (${held.reason}) y no acepta escrituras. ` +
          `Las lecturas siguen funcionando; reintenta esta escritura cuando la operación termine.`
      )
    }
    // La fila se lee SIEMPRE por la conexión del motor (L-1 · 🟠 8). Hasta
    // L-1 se leía por la transacción del consumidor si la escritura llegaba
    // con una —«para no interbloquear un pool de 1»—, y eso era el agujero:
    // la barrera la decidía el snapshot del llamante (medido en SQLite, MySQL
    // y PG). Con pool 1 el precio es un 503 con deadline, no un bypass.
    await assertNotFrozenRow(operation, {
      driver: this.#config.default,
      nowMs: root.#wallMs(),
      timeoutMs: this.#config.freezeTimeoutMs,
    })
  }

  /** Solo tests: fuerza re-resolución del driver. */
  clearCachedDriver(): void {
    this.#driver = null
    this.#readDriver = null
  }

  /**
   * El driver para LEER: en una vista de `forRequest`, el driver con el
   * resolutor memoizado (si el driver sabe darlo); fuera de una vista, el
   * driver tal cual. Las escrituras nunca pasan por aquí.
   */
  /**
   * Una vista caducada no lee (F9): su memo de ancestros puede describir un
   * árbol que ya cambió. Ruidoso a propósito. Lo mide el reloj monótono (H3).
   * Pasan por aquí TODAS las lecturas, `expandExcludedSubtrees` incluida (I2).
   */
  #assertReadable(): void {
    if (this.#readsUntil !== null && this.#clock() >= this.#readsUntil) {
      throw new ViewExpiredError(
        `La vista de forRequest() superó su maxAgeMs y ya no puede leer: su memo de ancestros puede estar obsoleto. ` +
          `Crea la vista por request (un middleware) o pasa forRequest({ maxAgeMs: 0 }) a sabiendas.`
      )
    }
  }

  async #reader(): Promise<AuthorizationDriver> {
    this.#assertReadable()
    const driver = await this.driver()
    if (!this.#readResolver) return driver
    if (this.#readDriver) return this.#readDriver
    this.#readDriver = driver.withChainResolver?.(this.#readResolver) ?? driver
    return this.#readDriver
  }

  /**
   * El árbol de scopes es un hecho del contrato: el consumidor notifica sus
   * cambios aquí, en TODOS los drivers, y el PAQUETE valida antes de tocar
   * el driver — la raíz no cuelga de nada, el padre tiene que existir y no
   * puede haber ciclos. FGA acepta un ciclo de `parent` y lo evalúa (un grant
   * en cualquier nodo concede en la raíz, S2), así que la barrera es esta.
   * Espía: si la validación falla, cero llamadas al driver.
   */
  readonly scopes = {
    // `within` (2D · F2; origen y destino desde 2E · H1) se contrasta con el
    // PADRE —colgar o mover algo bajo un scope es escribir en ese scope— Y con
    // la cadena ACTUAL del hijo cuando ya está en el árbol: llevarse un
    // subárbol de otro tenant es peor que purgarlo (se hereda todo lo robado).
    // Por eso el consumidor notifica ANTES de recolgar su fila: la cadena que
    // se contrasta es la de origen, resuelta en fresco.
    attached: async (
      child: ScopeRef,
      parent: ScopeRef,
      options?: ScopeTreeWriteOptions
    ): Promise<ScopeEnqueueReceipt> => {
      const actor = await this.#writeOptions(options, 'scopes.attached')
      const edge = await this.#assertEdge(child, parent, 'scopes.attached')
      this.#assertWithinChain(parent, edge.chain, options, 'scopes.attached')
      // Un hijo que el árbol ya conoce se está MOVIENDO (el `attach` de un
      // nodo existente es un `move`): su origen también tiene que estar dentro.
      await this.#assertWithinOrigin(child, options, 'scopes.attached', 'if-known')
      const outbox = this.#outbox()
      if (outbox) {
        const receipt = await outbox.enqueue(
          { op: 'attached', child: edge.child, parent: edge.chain[0] },
          { transaction: options?.transaction, ...actor }
        )
        return AuthorizationManager.#receiptOf([receipt])
      }
      await (await this.driver()).onScopeAttached?.(child, parent)
      return { queued: [] }
    },
    /**
     * `moved` NO vuelve a juzgar el catálogo, y no tiene por qué (3b-1 · D3,
     * auditor 3G): mover un scope es un hecho del árbol, no una escritura de
     * catálogo. Lo que hay que tener escrito es la consecuencia: la relación
     * «A ensombrece a B» es función del árbol de HOY, así que un `moved` que
     * mete un subárbol bajo un scope que ya tiene el homónimo **crea la
     * sombra sin que se juzgue ningún rango en ninguna parte** — y el dueño
     * del subárbol movido puede no poder repararla (su rango se mide en la
     * cadena del owner de la sombra). Por eso «sobre un rol solo actúa quien
     * lo supera en rango» (3G · W3) es una comprobación de ESCRITURA y no un
     * invariante del sistema. Es ruidosa: `authz:catalog:diff` la lista como
     * `shadowedByAncestor` (y `--fail-on-shadows` la cuenta como deriva).
     */
    moved: async (
      child: ScopeRef,
      newParent: ScopeRef,
      options?: ScopeTreeWriteOptions
    ): Promise<ScopeEnqueueReceipt> => {
      const actor = await this.#writeOptions(options, 'scopes.moved')
      const edge = await this.#assertEdge(child, newParent, 'scopes.moved')
      this.#assertWithinChain(newParent, edge.chain, options, 'scopes.moved')
      await this.#assertWithinOrigin(child, options, 'scopes.moved', 'required')
      const outbox = this.#outbox()
      if (outbox) {
        const receipt = await outbox.enqueue(
          { op: 'moved', child: edge.child, parent: edge.chain[0] },
          { transaction: options?.transaction, ...actor }
        )
        return AuthorizationManager.#receiptOf([receipt])
      }
      await (await this.driver()).onScopeMoved?.(child, newParent)
      return { queued: [] }
    },
    /**
     * Hechos primero (el driver demuestra cero o lanza), arista después
     * (S6): si la purga muere a medias, el subárbol sigue colgado y los
     * denies heredados siguen valiendo. Sin `within` no comprueba que el
     * scope exista (el consumidor puede haber borrado ya su fila); con
     * `within` (2D · F2) el hijo tiene que seguir en el árbol para
     * contrastar su cadena: purga ANTES de borrar la fila.
     *
     * **Purga HECHOS y solo hechos** (invariante 11; 3b-0 · Z1). Entre 3D y
     * 3G esta operación arrastraba además los roles LOCALES cuyo owner era
     * ese scope (y, con `descendantsOf`, los de todo el subárbol), con su
     * propia policy de rango, su degradación y un valor de retorno que
     * contaba lo purgado. Cinco lotes la tocaron y TRES de las cuatro
     * regresiones de la Fase 3 nacieron ahí, siempre por COMPOSICIÓN de
     * piezas correctas por separado (3E · P3 + 3F · S1/S2 ⇒ 3G · W1). El
     * requisito que lo pedía —un rol cuyo owner desaparece queda
     * indeleteable y ocupa su `(slug, nivel)`— se resuelve más simple y
     * fuera del camino de un tenant: el rol queda DORMIDO (no concede, no es
     * membresía, no se asigna) y la PLATAFORMA lo retira con
     * `authz:catalog:prune-orphans` (Z2). Así `scopes.detached` vuelve a ser
     * O(1), sin rango que medir, sin árbol que enumerar y sin nada que
     * declarar a medias.
     */
    detached: async (child: ScopeRef, options?: ScopeTreeWriteOptions): Promise<ScopeEnqueueReceipt> => {
      const actor = await this.#writeOptions(options, 'scopes.detached')
      this.#resolver('scopes.detached')
      assertScope(child)
      if (child.type === APP_SCOPE_TYPE) {
        throw new InvalidIdentityError('scopes.detached: la raíz `app` no se puede borrar ni purgar')
      }
      await this.#assertWithin(child, options, 'scopes.detached')
      // La identidad CANÓNICA (3E · P2, auditor A2): hasta 3D los hechos se
      // canonizaban dentro del driver, así que un alias del uuid del scope
      // —el mismo uuid sin guiones, que el tipo `uuid` de PostgreSQL
      // resuelve a la misma fila y `assertScope` acepta— purgaba unas cosas
      // y dejaba otras. Se resuelve UNA vez, aquí, y vale para todo.
      //
      // Y cuando NO hay cadena —la fila ya no existe, que es el orden
      // soportado de `detached` (3F · S1)— no hay con qué canonizar: se
      // purgan las ortografías de las que el uuid del llamante puede ser
      // alias (`scopeSpellings`, 3b-2h · 🟠 3: lo que PG funde,
      // `pgFusedSpellings`) MENOS las que el resolutor reconozca como un
      // scope VIVO distinto del pedido (cierre-3 del lote A · 🟡 C2-2: con
      // ids de texto, la canónica de un alias puede ser la unit viva de otro
      // tenant, y `purgeScope` en `database` le borraría los denies). Con la
      // fila viva esto es exactamente una, la de la tabla. El punto de paso
      // es ÚNICO y compartido con `revoke`/`removeDeny` de los dos drivers
      // (`canonicalScopeTargets`); un resolutor que falla al contrastar es
      // 503, nunca «purgar por si acaso». Antes se usaba la del llamante a
      // secas: `purgeScope` demostraba cero sobre un objeto que no existe,
      // devolvía OK, y el scope real seguía concediendo para siempre.
      const targets = await canonicalScopeTargets(this.#freshResolver(), child, 'scopes.detached')
      const outbox = this.#outbox()
      if (outbox) {
        // La identidad se resuelve AQUÍ, con la fila del consumidor todavía
        // viva si la hay: al relevar el cambio ya no resolvería. Y no se
        // audita `scope_purged` todavía, porque todavía no ha pasado nada.
        // El recibo es PLURAL por esto mismo: una fila por ortografía.
        const receipts: Array<void | { id: string | number }> = []
        for (const target of targets) {
          receipts.push(
            await outbox.enqueue({ op: 'detached', child: target }, { transaction: options?.transaction, ...actor })
          )
        }
        return AuthorizationManager.#receiptOf(receipts)
      }
      const driver = await this.driver()
      for (const purged of targets) {
        const event: AuthzWriteEvent = { action: 'scope_purged', scope: purged, ...actor }
        await this.#write(event, () => driver.purgeScope(purged))
        await driver.onScopeDetached?.(purged)
        await this.#notify(event)
      }
      return { queued: [] }
    },
  }

  /**
   * El recibo del encolado (alpha.5 · R1): los ids que la outbox devolvió,
   * en orden. Una outbox que devuelve `void` (terceros anteriores a alpha.5)
   * no deja id, y el recibo sale vacío: nunca se inventa uno.
   */
  static #receiptOf(receipts: Array<void | { id: string | number }>): ScopeEnqueueReceipt {
    const queued: Array<string | number> = []
    for (const receipt of receipts) {
      if (receipt && typeof receipt === 'object' && (typeof receipt.id === 'number' || typeof receipt.id === 'string')) {
        queued.push(receipt.id)
      }
    }
    return { queued }
  }

  /**
   * **Drena la outbox del árbol y aplica los cambios al driver** (3b-2d).
   * Es lo que hay detrás de `node ace authz:scopes:relay`.
   *
   * Operación de PLATAFORMA, como `pruneOrphanRoles`: se salta `requireActor`
   * y `requireWithin` a propósito —la policy ya se juzgó al ENCOLAR, con el
   * árbol y la sesión de aquel momento— así que **no se expone por HTTP**.
   * Aquí solo se propaga lo que ya se validó.
   *
   * Reanudable y nunca silenciosa: el reporte dice QUÉ se aplicó (no un
   * contador: la pasada no es atómica), qué falló, qué se aplazó y si queda
   * trabajo.
   *
   * **El orden del árbol importa, pero solo entre cambios que se tocan**
   * (3b-2h · 🔴 2, auditor R2). Hasta el 2h la pasada PARABA en el primer
   * fallo, y eso convertía una entrada que ya no se puede aplicar —el padre
   * del `attached` encolado se borró antes del relevo, la arista cerraría
   * ahora un ciclo, el nodo acabó con dos padres— en un **tapón permanente
   * para todos los tenants**: `pending()` devuelve lo no aplicado ordenado
   * por id, así que la envenenada era la cabecera de la cola en TODAS las
   * pasadas siguientes y ningún cambio del árbol volvía a llegar al store
   * (medido: una unit nueva nunca recibía su arista `parent`, el deny de su
   * organization nunca la alcanzaba y un `detached` posterior nunca purgaba).
   * Ahora un fallo **contamina los scopes que nombra**: los cambios
   * posteriores que tocan alguno de ellos se APLAZAN sin intentarse (y
   * contaminan a su vez, así que la dependencia es transitiva), y los demás
   * se aplican. El par ordenado que importaba —`attached(P, org)` antes que
   * `attached(C, P)`, `moved` antes que `detached`— sigue respetado porque
   * comparten scope; lo que ya no pasa es que el tenant A congele el árbol
   * del tenant B.
   *
   * **Escritor ÚNICO** (3b-2h · 🟠 4): si la outbox sabe dar un lease
   * (`acquire`), la pasada lo toma y una segunda pasada simultánea no hace
   * nada y lo dice (`busy`). Sin lease, dos pasadas trabajan sobre el mismo
   * lote —`pending()` no reserva y el lote no se relee— y la rezagada
   * re-aplica cambios viejos sobre el árbol nuevo.
   *
   * Lo que esta pieza NO arregla, y va escrito en el README con estas
   * palabras: entre el commit del consumidor y esta pasada hay un lag
   * (segundos) durante el cual el backend decide con el árbol VIEJO. Es un
   * **fail-open temporal** —el tenant antiguo conserva acceso tras un
   * `moved`, los denies heredados no aplican tras un `attached`—. No hay
   * 2PC; es el precio de tener el árbol en dos sitios.
   *
   * **`only` (2.4.0-alpha.5 · R1)**: relevar SOLO estas entradas —los ids del
   * recibo de `scopes.*` que ESTE proceso acaba de recibir, jamás del cuerpo
   * de una petición— sin leer la cola de los demás (medido: 4 507 ms → 19 ms
   * con 500 entradas ajenas por delante). El orden por clave NO se relaja:
   * antes de aplicar cada entrada pedida se sondea la cola ENTERA
   * (`earlierPending`, o paginando `pending()` si la outbox no lo tiene) y,
   * si hay una pendiente ANTERIOR que comparte clave de scope con ella, sale
   * `deferred` con `depends-on:<id>` — nunca aplicada fuera de orden (el 🔴 1
   * del panel relay, medido: un `attached(child, unit)` aplicado antes que su
   * `moved(unit → orgB)` dejaba al editor de la org VIEJA autorizando sobre el
   * hijo). `remaining` y `dead` siguen siendo GLOBALES. `only: []` es 500
   * (un `filter` vacío del consumidor no puede acabar en drenaje ni en un
   * reporte vacío en verde), y una outbox que no honre el filtro también.
   *
   * **Lo aparcado tapona por clave (alpha.5 · R2a)**: las claves de `dead()`
   * siembran el bloqueo al inicio de la pasada para lo que CONCEDE o recuelga
   * (`attached`/`moved`, `deferred` con `parked:<id>`) y dejan pasar lo que
   * RETIRA (`detached`: una purga nunca queda bloqueada, invariante 11). Y un
   * 503 del backend NO consume intento (`markFailed(..., { transient })`).
   */
  async relayScopeChanges(
    options: {
      limit?: number
      batchSize?: number
      dryRun?: boolean
      only?: Array<string | number>
      waitForLeaseMs?: number
      /**
       * Bajo `only`, `dead[]` va SIN `error` por DEFECTO (2.4.0-alpha.8): la
       * causa la escribe el backend sobre el árbol de OTRO tenant; `'full'`
       * la devuelve (lo de hasta alpha.7). Sin `only` no cambia nada.
       */
      deadDetail?: 'full'
    } = {}
  ): Promise<ScopeRelayReport> {
    AuthorizationManager.#assertKnownOptions('relayScopeChanges', options, RELAY_OPTIONS)
    // El relay ESCRIBE el árbol en el driver: durante una migración se aplaza
    // como cualquier otra escritura (lo que quede en la cola sigue ahí).
    await this.#assertNotFrozen('authz:scopes:relay')
    const outbox = this.#outbox()
    if (!outbox) {
      throw new AuthorizationConfigError(
        "authz:scopes:relay necesita 'scopes.outbox' en config/authorization.ts: sin cola no hay nada que drenar " +
          '(y sin cola tampoco hay mitigación: el manager estaría escribiendo en el backend dentro de tu transacción).'
      )
    }
    const limit = AuthorizationManager.#positive(options.limit, DEFAULT_RELAY_LIMIT, 'limit')
    const batchSize = AuthorizationManager.#positive(options.batchSize, DEFAULT_RELAY_BATCH, 'batchSize')
    const dryRun = options.dryRun === true
    const waitForLeaseMs = AuthorizationManager.#waitMs(options.waitForLeaseMs)
    if (options.deadDetail !== undefined && options.deadDetail !== 'full') {
      throw new AuthorizationConfigError(
        `authz:scopes:relay: deadDetail solo admite 'full' (llegó ${JSON.stringify(options.deadDetail)}); sin él, bajo only, dead[] va sin error.`
      )
    }
    const inputs = await AuthorizationManager.#relayInputs(outbox, options.only, batchSize, options.deadDetail)
    const { only, filter, dead, deadCount, deadEntries, unseenOf } = inputs

    if (dryRun) {
      const batch = await outbox.pending(limit, undefined, filter)
      AuthorizationManager.#assertOnlyHonoured(batch, only)
      const extra = batch.length >= limit ? true : false
      const seen = new Set<string>([...batch.map((b) => String(b.id)), ...deadEntries.map((d) => String(d.id))])
      const unseen = await unseenOf(seen)
      // La edad es GLOBAL: sin filtro la cabeza es `batch[0]`; con `only` hay que mirar la cola entera.
      const queue = filter === undefined ? this.#queueOf(batch[0]) : (await this.#queueStatus(outbox)).queue
      return {
        applied: [],
        failed: null,
        failures: [],
        deferred: [],
        dead,
        deadCount,
        queue,
        busy: false,
        remaining: batch.length > 0 || extra,
        dryRun: true,
        wouldApply: batch.map((item) => ({ id: item.id, change: item.change, attempts: item.attempts })),
        entries: deadEntries,
        ...unseen,
      }
    }

    // El lease del escritor ÚNICO. Una outbox que no sabe darlo se comporta
    // como hasta ahora (y el README dice que entonces el relay tiene que
    // correr de uno en uno). Con `waitForLeaseMs` se reintenta hasta el tope.
    const lease = await this.#acquireLease(outbox, waitForLeaseMs)
    if (outbox.acquire && lease === null) return this.#busyReport(outbox, inputs)
    try {
      return await this.#drainScopeChanges(outbox, { limit, batchSize, ...inputs })
    } finally {
      await lease?.release()
    }
  }

  /**
   * Lo que una pasada necesita saber de la cola antes de tomar el lease
   * (`only` normalizado, el filtro para el puerto, lo APARCADO —siempre
   * global— y sus entradas para el reporte). Compartido por `relayScopeChanges`
   * y por `requeueScopeChanges({ apply })` (2.4.0-alpha.8), que releva bajo
   * el MISMO lease y necesita releer lo aparcado DESPUÉS de reencolar.
   */
  static async #relayInputs(
    outbox: ScopeOutbox,
    onlyIds: Array<string | number> | undefined,
    batchSize: number,
    deadDetail?: 'full'
  ): Promise<{
    only: Set<string> | undefined
    filter: { ids: Array<string | number> } | undefined
    dead: RelayedScopeChange[]
    /** El CENSO completo de aparcadas (= `dead` si cabe en un lote); lo consumen `#parkedKeys` y `deadCount`. */
    census: RelayedScopeChange[]
    deadCount: number
    deadEntries: ScopeRelayEntry[]
    unseenOf: (seen: Set<string>) => Promise<{ missing: Array<string | number>; notEvaluated: Array<string | number> }>
  }> {
    const only = AuthorizationManager.#onlyOf(onlyIds)
    // Al puerto van los ids TAL CUAL los dio el llamante (el recibo); el
    // conjunto de cadenas es solo para comparar sin depender del tipo.
    const filter = only === undefined ? undefined : { ids: [...onlyIds!] }
    /** Lo aparcado por la outbox, si sabe aparcar: se reporta SIEMPRE, y GLOBAL. */
    const read = await AuthorizationManager.#deadLetters(outbox, batchSize)
    // Bajo `only` (2.4.0-alpha.8, coordinador): la lista sigue siendo global
    // —ids, `change`, `attempts`— pero SIN `error` salvo `deadDetail: 'full'`:
    // la causa es texto del backend sobre el árbol de otro tenant, y la receta
    // inline corre dentro de una petición. Lo pedido (`deadEntries`) sí la
    // lleva: es lo suyo.
    const dead =
      only === undefined || deadDetail === 'full' ? read : read.map(({ error: _error, ...safe }) => safe)
    // El censo COMPLETO (cierre alpha.5, 🟠 2): lo que `#parkedKeys` siembra y,
    // desde 2.4.0-alpha.8, lo que cuenta `deadCount` (`dead.length` miente al
    // llegar a `batchSize`). Una sola lectura de más, y solo si no cabía.
    const census = dead.length < batchSize ? dead : await AuthorizationManager.#deadLetters(outbox, PARKED_CENSUS_MAX)
    const deadCount = census.length
    /**
     * Lo aparcado que se pidió (con `only`) o todo lo aparcado, para `entries`.
     * Cierre-2 · C2 (gemelo): con `only` sale del CENSO completo si la lectura se
     * cortó en `batchSize` — si no, un id pedido aparcado más allá del primer lote
     * era `missing` («no estaba ni pendiente ni aparcado») estando aparcado.
     */
    const deadSource: Array<RelayedScopeChange & { error?: string }> = only !== undefined && read.length >= batchSize ? census : read
    const deadEntries: ScopeRelayEntry[] = deadSource
      .filter((item) => only === undefined || only.has(String(item.id)))
      .map((item) => ({
        id: item.id,
        change: item.change,
        status: 'dead' as const,
        attempts: item.attempts,
        ...(item.error === undefined ? {} : { reason: item.error }),
      }))
    /**
     * **Qué fue de los ids pedidos que la pasada NO vio** (cierre-2 de alpha.10 ·
     * C2). Hasta el cierre-2 todos eran `missing`; pero un id fuera del lote porque
     * la pasada alcanzó `limit` sigue PENDIENTE. Se pregunta a la cola —filtrada por
     * esos ids, sin límite propio, UNA lectura y solo si hay alguno sin ver—: lo que
     * sigue pendiente es `notEvaluated`; el resto, `missing` (no está en la cola: lo
     * aparcado ya está en `seen`).
     */
    const unseenOf = async (
      seen: Set<string>
    ): Promise<{ missing: Array<string | number>; notEvaluated: Array<string | number> }> => {
      if (only === undefined) return { missing: [], notEvaluated: [] }
      const unseen = [...only.values()].filter((id) => !seen.has(id)).map((id) => AuthorizationManager.#rawId(onlyIds!, id))
      if (unseen.length === 0) return { missing: [], notEvaluated: [] }
      const stillPending = await outbox.pending(unseen.length, undefined, { ids: unseen })
      AuthorizationManager.#assertOnlyHonoured(stillPending, new Set(unseen.map(String)))
      const pendingIds = new Set(stillPending.map((item) => String(item.id)))
      return {
        missing: unseen.filter((id) => !pendingIds.has(String(id))),
        notEvaluated: unseen.filter((id) => pendingIds.has(String(id))),
      }
    }
    return { only, filter, dead, census, deadCount, deadEntries, unseenOf }
  }

  /** El reporte de una pasada que NO entró: otra tiene el lease. Nada aplicado, nada tocado. */
  async #busyReport(
    outbox: ScopeOutbox,
    inputs: { dead: RelayedScopeChange[]; deadCount: number; deadEntries: ScopeRelayEntry[] }
  ): Promise<ScopeRelayReport> {
    const { remaining, queue } = await this.#queueStatus(outbox)
    return {
      applied: [],
      failed: null,
      failures: [],
      deferred: [],
      dead: inputs.dead,
      deadCount: inputs.deadCount,
      queue,
      busy: true,
      remaining,
      dryRun: false,
      wouldApply: [],
      entries: inputs.deadEntries,
      missing: [],
      notEvaluated: [],
    }
  }

  /**
   * **La cabeza GLOBAL de la cola y su edad** (2.4.0-alpha.8; panel relay 2,
   * cuestión 5). Es el `pending(1)` que la pasada ya hacía al final para
   * `remaining` —cero consultas nuevas—, leído SIN filtro aunque haya `only`:
   * la edad, como `remaining` y `dead`, es de la cola entera. La edad la mide
   * el reloj INYECTABLE del manager (`#wallMs`), nunca `Date.now()`.
   */
  async #queueStatus(outbox: ScopeOutbox): Promise<{ remaining: boolean; queue: ScopeRelayQueue }> {
    const head = await outbox.pending(1)
    return { remaining: head.length > 0, queue: this.#queueOf(head[0]) }
  }

  /**
   * La edad de una cabeza: `Math.max(0, ahora − createdAt)` —nunca negativa:
   * el sello lo puso el reloj de OTRA réplica, con su skew—; sin cabeza o sin
   * `createdAt` (una outbox de terceros que no lo trae) ⇒ `null` en los dos
   * campos, jamás `0` ni «ahora».
   */
  #queueOf(head: PendingScopeTreeChange | undefined): ScopeRelayQueue {
    const createdAt = head?.createdAt
    if (!(createdAt instanceof Date) || Number.isNaN(createdAt.getTime())) return { oldestPendingAt: null, pendingAgeMs: null }
    return { oldestPendingAt: createdAt, pendingAgeMs: Math.max(0, this.#root().#wallMs() - createdAt.getTime()) }
  }

  /**
   * **El lease del escritor único, con espera acotada** (2.4.0-alpha.8;
   * `waitForLeaseMs`, panel relay 2, cuestión 7). Con `0` (el default) es
   * UN intento y `null` = `busy`, como siempre — el caso «dos pasadas a la vez
   * ⇒ busy» no cambia. Con un tope, reintenta `acquire()` cada
   * `RELAY_LEASE_POLL_MS` hasta vencerlo: `busy` al vencer, jamás un cuelgue.
   * El reloj es el inyectable del manager (nunca `Date.now()` en `src/`).
   * Exige pool ≥ 2 (README): con pool 1 el que espera puede estar reteniendo
   * la única conexión que necesita el que tiene el lease.
   */
  async #acquireLease(outbox: ScopeOutbox, waitForLeaseMs: number): Promise<ScopeOutboxLease | null> {
    if (!outbox.acquire) return null
    let lease = await outbox.acquire()
    if (lease !== null || waitForLeaseMs <= 0) return lease
    const deadline = this.#root().#wallMs() + waitForLeaseMs
    // Dos topes a la vez: el reloj de pared (inyectable) y el NÚMERO de sondeos —
    // con un reloj fijo el primero no vence jamás (medido por el auditor de alpha.8).
    const maxPolls = Math.ceil(waitForLeaseMs / RELAY_LEASE_POLL_MS)
    for (let polls = 0; lease === null && polls < maxPolls && this.#root().#wallMs() < deadline; polls++) {
      await new Promise<void>((resolve) => setTimeout(resolve, RELAY_LEASE_POLL_MS))
      lease = await outbox.acquire()
    }
    return lease
  }

  /** `waitForLeaseMs` normalizado: entero >= 0 (500 si no); ausente = 0. */
  static #waitMs(value: number | undefined): number {
    if (value === undefined) return 0
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      throw new AuthorizationConfigError(`authz:scopes:relay: waitForLeaseMs debe ser un entero >= 0 en milisegundos (llegó ${String(value)})`)
    }
    if (value > RELAY_WAIT_LEASE_MAX_MS) {
      throw new AuthorizationConfigError(
        `authz:scopes:relay: waitForLeaseMs = ${value} supera el tope RELAY_WAIT_LEASE_MAX_MS (${RELAY_WAIT_LEASE_MAX_MS} ms): ` +
          `una espera sin tope cuelga la petición del tenant; acorta la pasada (only/limit) en vez de esperar más.`
      )
    }
    return value
  }

  /**
   * **La pasada, ya con el lease tomado**: lo que hasta 2.4.0-alpha.7 era el
   * cuerpo de `relayScopeChanges`. Compartida con `requeueScopeChanges({
   * apply })`, que la llama bajo SU lease con `only` = los ids reencolados
   * (auditor 🟠 5: tomar el lease dos veces era `busy` en verde).
   */
  async #drainScopeChanges(
    outbox: ScopeOutbox,
    input: {
      limit: number
      batchSize: number
      only: Set<string> | undefined
      filter: { ids: Array<string | number> } | undefined
      dead: RelayedScopeChange[]
      census: RelayedScopeChange[]
      deadCount: number
      deadEntries: ScopeRelayEntry[]
      unseenOf: (seen: Set<string>) => Promise<{ missing: Array<string | number>; notEvaluated: Array<string | number> }>
    }
  ): Promise<ScopeRelayReport> {
    const { limit, batchSize, only, filter, dead, census, deadCount, deadEntries, unseenOf } = input
      const driver = await this.driver()
      const applied: RelayedScopeChange[] = []
      const deferred: RelayedScopeChange[] = []
      const failures: ScopeRelayFailure[] = []
      const entries: ScopeRelayEntry[] = []
      /**
       * Claves de scope contaminadas ⇒ el id que las contaminó y el ORIGEN del
       * bloqueo (alpha.5 · cierre, auditor 🟠 1). `parked: true` = la causa
       * raíz (transitiva) es una entrada APARCADA: tapona solo lo que concede
       * o recuelga (`attached`/`moved`), NUNCA un `detached` — si no, un
       * `attached` aplazado por aparcado congelaba la purga del nodo que el
       * tenant ya borró, para siempre (medido: el scope conservaba sus hechos
       * y su arista, y seguía concediendo; invariante 11). `parked: false` =
       * un FALLO real de esta pasada (o una pendiente anterior no pedida):
       * contamina todo, `detached` incluido — el orden entre un `attached`
       * que falló y la purga de ese mismo nodo sigue importando (3b-2h).
       */
      const blocked = new Map<string, { id: string | number; origin: ScopeRelayBlockOrigin }>()
      /** Origen ya sondeado de entradas NO pedidas (alpha.6): `parked` = retenida solo por un aparcado. Se olvida en cuanto la pasada registra un bloqueo que no es de aparcado (podría contaminar una clave ya sondeada). */
      const origins = new Map<string, ScopeRelayBlockOrigin>()
      const block = (key: string, id: string | number, origin: ScopeRelayBlockOrigin) => {
        const current = blocked.get(key)
        // Precedencia `failed > pending > parked` (2.4.0-alpha.8; desde el
        // cierre de alpha.5: un fallo real pisa a un aparcado, nunca al revés).
        if (current === undefined || BLOCK_RANK[origin] > BLOCK_RANK[current.origin]) blocked.set(key, { id, origin })
        if (origin !== 'parked') origins.clear()
      }
      /**
       * **Las claves de lo APARCADO** (alpha.5 · R2a): taponan lo que concede
       * o recuelga y dejan pasar lo que retira. El censo es COMPLETO —no
       * depende de `limit` ni de `batchSize` (cierre, 🟠 2)— con su propia
       * cota; el reporte sigue enseñando las primeras `batchSize`.
       */
      const parkedKeys = AuthorizationManager.#parkedKeys(census)
      // Una outbox que no marca lo aplicado devolvería el mismo pendiente
      // para siempre: el relay no puede quedarse dando vueltas ni
      // "arreglarlo" por su cuenta, así que lo denuncia (500) en cuanto
      // vuelve a ver un id que YA aplicó.
      const done = new Set<string>()
      /** Ids que esta pasada dejó a propósito (fallo o aplazo): reaparecen. */
      const parked = new Set<string>()
      /** El último id visto: la outbox pagina desde ahí (lo saltado se queda). */
      let after: string | number | undefined

      const defer = (item: PendingScopeTreeChange, keys: string[], reason: string, error: string, origin: ScopeRelayBlockOrigin) => {
        for (const key of keys) block(key, item.id, origin)
        parked.add(String(item.id))
        deferred.push({ id: item.id, change: item.change, attempts: item.attempts, error })
        // `origin` se DERIVA del bloqueo (2.4.0-alpha.8), jamás del prefijo de `reason`.
        entries.push({ id: item.id, change: item.change, status: 'deferred', reason, attempts: item.attempts, origin })
      }

      outer: while (applied.length < limit) {
        // **La barrera del freeze se RE-AFIRMA por lote** (3b-8 · B3). La
        // mirada única de la entrada dejaba hasta `DEFAULT_RELAY_LIMIT`
        // (10.000) escrituras de árbol colándose DESPUÉS de que otra pasada
        // adquiriera el freeze durable: escrituras que no salen en ningún
        // contador de la pasada certificada y que pueden invalidar su
        // resultado. El trade-off documentado en freeze.ts cubre «una
        // escritura que ya pasó su barrera», no una pasada entera. El coste
        // (una lectura de la fila `id=2` por lote; 0,14 ms/escritura ya
        // medidos y aceptados) va fuera del camino caliente. Un freeze
        // adquirido a mitad corta AQUÍ con el 503 reintentable de siempre:
        // lo ya aplicado está marcado en la outbox (la pasada es reanudable)
        // y el resto sigue pendiente para después de la ventana.
        await this.#assertNotFrozen('authz:scopes:relay')
        const batch = await outbox.pending(Math.min(batchSize, limit - applied.length), after, filter)
        if (batch.length === 0) break
        AuthorizationManager.#assertOnlyHonoured(batch, only)
        let progress = false
        for (const item of batch) {
          const id = String(item.id)
          if (done.has(id)) {
            throw new AuthorizationConfigError(
              `authz:scopes:relay: la outbox sigue devolviendo el cambio ${id} como pendiente después de markApplied. ` +
                'Tu implementación de ScopeOutbox no marca lo aplicado; el relay para antes de dar vueltas para siempre.'
            )
          }
          if (parked.has(id)) continue
          progress = true
          after = item.id
          if (applied.length >= limit) break outer
          const keys = AuthorizationManager.#changeKeys(item.change)
          // Una purga solo la frena un bloqueo cuyo origen sea un FALLO real;
          // el que nace de un aparcado la deja pasar (invariante 11).
          const collision = keys.find((key) => {
            const hit = blocked.get(key)
            return hit !== undefined && !(item.change.op === 'detached' && hit.origin === 'parked')
          })
          if (collision !== undefined) {
            const by = blocked.get(collision)!
            defer(
              item,
              keys,
              `depends-on:${by.id}`,
              `aplazado: depende de ${collision}, que quedó sin aplicar en esta pasada (#${by.id})`,
              by.origin
            )
            continue
          }
          // Lo aparcado tapona lo que CONCEDE o recuelga; una purga pasa.
          if (item.change.op !== 'detached') {
            const parkedKey = keys.find((key) => parkedKeys.has(key))
            if (parkedKey !== undefined) {
              const by = parkedKeys.get(parkedKey)!
              defer(
                item,
                keys,
                `parked:${by}`,
                `aplazado: depende de ${parkedKey}, que nombra la entrada APARCADA #${by} (parked:${by}); no se aplica hasta que alguien la mire`,
                'parked'
              )
              continue
            }
          }
          // Con `only`, la sonda contra la cola ENTERA: una pendiente anterior
          // que comparta clave y no se pidió ⇒ aplazado, nunca fuera de orden.
          // **Y la sonda hereda el ORIGEN de esa anterior** (alpha.6, auditor 🟡 A
          // de alpha.5): si la anterior está —transitivamente— retenida solo por
          // un APARCADO, es el mismo bloqueo `parked:` que en la pasada completa
          // deja pasar la purga (invariante 11): el `detached` SE APLICA. Si la
          // anterior es un `attached`/`moved` pendiente de verdad (aplicable, o
          // retenido por un FALLO real), el `detached` sigue `deferred`: aplicarlo
          // antes que un `moved` pendiente del mismo scope dejaría deriva.
          if (only !== undefined) {
            const earlier = await this.#dependencyOf(outbox, item, batchSize)
            if (earlier !== null) {
              const origin = await this.#blockOriginOf(outbox, earlier, blocked, parkedKeys, batchSize, origins)
              if (!(item.change.op === 'detached' && origin === 'parked')) {
                const shared = AuthorizationManager.#changeKeys(earlier.change).find((key) => keys.includes(key)) ?? keys[0]
                defer(
                  item,
                  keys,
                  `depends-on:${earlier.id}`,
                  `aplazado: depende de ${shared}, que nombra la entrada anterior #${earlier.id} todavía sin aplicar (depends-on:${earlier.id}); ` +
                    (origin === 'parked' ? 'espera a una entrada APARCADA; mira dead()' : 'corre el relay completo'),
                  origin
                )
                continue
              }
            }
          }
          try {
            await this.#applyScopeChange(driver, item)
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            const transient = isTransientRelayFailure(error)
            const code = typeof (error as { code?: unknown } | null)?.code === 'string' ? (error as { code: string }).code : undefined
            await outbox.markFailed(item.id, message, { transient })
            for (const key of keys) block(key, item.id, 'failed')
            parked.add(id)
            failures.push({
              id: item.id,
              change: item.change,
              error: message,
              transient,
              ...(code !== undefined ? { code } : {}),
              ...(isDeploymentFailure(error) ? { deployment: true as const } : {}),
            })
            entries.push({ id: item.id, change: item.change, status: 'failed', reason: message, attempts: item.attempts })
            continue
          }
          await outbox.markApplied(item.id)
          done.add(id)
          applied.push({ id: item.id, change: item.change, attempts: item.attempts })
          entries.push({ id: item.id, change: item.change, status: 'applied', attempts: item.attempts })
        }
        // Una outbox que ignora `after` devuelve el mismo lote atascado: la
        // pasada termina aquí en vez de dar vueltas (lo que quede, y lo que
        // haya detrás, sigue pendiente para la siguiente).
        if (!progress) break
      }

      entries.push(...deadEntries)
      // La cabeza global de la cola: `remaining` y, desde alpha.8, su EDAD.
      const { remaining, queue } = await this.#queueStatus(outbox)
      return {
        applied,
        failed: failures[0] ?? null,
        failures,
        deferred,
        dead,
        deadCount,
        queue,
        busy: false,
        remaining,
        dryRun: false,
        wouldApply: [],
        entries,
        ...(await unseenOf(new Set(entries.map((e) => String(e.id))))),
      }
  }

  /**
   * `only` normalizado (alpha.5 · R1): un conjunto de ids como cadena (el id
   * de `sqlScopeOutbox` es un entero que según el motor y el driver llega
   * como `number` o como `string`; comparar con `===` sería un no-op
   * silencioso). `undefined` = sin filtro. **`[]` es 500**, nunca «sin
   * filtro»: un `filter` vacío del consumidor —o una outbox de terceros sin
   * recibo, que deja `queued: []`— no puede acabar drenando la cola entera
   * bajo el lease de una petición HTTP, ni en un reporte vacío en verde.
   */
  static #onlyOf(only: Array<string | number> | undefined): Set<string> | undefined {
    if (only === undefined) return undefined
    if (!Array.isArray(only) || only.some((id) => typeof id !== 'number' && typeof id !== 'string')) {
      throw new AuthorizationConfigError(
        `authz:scopes:relay: 'only' debe ser una lista de ids (number | string); llegó ${JSON.stringify(only)}`
      )
    }
    if (only.length === 0) {
      throw new AuthorizationConfigError(
        "authz:scopes:relay: 'only' está vacío. Un recibo vacío significa que no hay nada que relevar (sin outbox el cambio ya " +
          'se aplicó en línea; con una outbox de terceros sin recibo no hay `only`): relevar «nada» no es relevar «todo». ' +
          'Quita `only` para drenar la cola entera.'
      )
    }
    return new Set(only.map(String))
  }

  /** El id tal como lo pasó el llamante en `only` (para `missing`). */
  static #rawId(only: Array<string | number>, key: string): string | number {
    return only.find((id) => String(id) === key) ?? key
  }

  /**
   * Una outbox que IGNORA `filter.ids` devuelve lo que no se pidió: el
   * backlog ajeno se aplicaría dentro de la petición del consumidor, en
   * silencio. Se detecta y se para (500), como el `markApplied` no honrado.
   */
  static #assertOnlyHonoured(batch: PendingScopeTreeChange[], only: Set<string> | undefined): void {
    if (only === undefined) return
    const stranger = batch.find((item) => !only.has(String(item.id)))
    if (stranger !== undefined) {
      throw new AuthorizationConfigError(
        `authz:scopes:relay: la outbox devolvió el cambio ${String(stranger.id)}, que no está en 'only'. ` +
          'Tu implementación de ScopeOutbox no honra `pending(limit, after, { ids })`: el relay para antes de aplicar ' +
          'lo que no se pidió (filtra en el puerto, no en memoria).'
      )
    }
  }

  /**
   * Las claves de scope de lo APARCADO ⇒ el id aparcado que las nombra
   * (alpha.5 · R2a). El censo lo lee `#relayInputs`: el `dead` ya leído si
   * cabe entero en un lote (menos de `batchSize` filas = no hay más); si no,
   * la cola ENTERA hasta `PARKED_CENSUS_MAX` — nunca acotado por `limit`
   * (cierre, 🟠 2: con `--limit 50` o `{ only, limit: 1 }` la aparcada 101 no
   * taponaba y el `attached` colgaba del padre viejo)—, y si la cota se
   * alcanza la pasada se niega (500): un tapón incompleto no es un tapón.
   */
  static #parkedKeys(census: RelayedScopeChange[]): Map<string, string | number> {
    if (census.length >= PARKED_CENSUS_MAX) {
      throw new AuthorizationConfigError(
        `authz:scopes:relay: la outbox tiene ${PARKED_CENSUS_MAX} o más entradas APARCADAS y el censo de sus claves no cabe ` +
          `(PARKED_CENSUS_MAX): sin el censo entero el tapón por clave sería ciego y un attached podría colgarse del padre ` +
          `VIEJO. No se ha aplicado nada. Mira dead(), reencola o reconcilia antes de volver a relevar.`
      )
    }
    const keys = new Map<string, string | number>()
    for (const item of census) {
      // **Solo la clave del HIJO** (2.4.0-alpha.8 · variante B; dueño: sí).
      // Una aparcada dice que la POSICIÓN DE SU HIJO en el store es
      // incorrecta; no dice nada de su padre nuevo: un `attached(otraUnit,
      // orgA)` detrás de un `moved(unit → orgA)` aparcado escribe otra arista
      // y conmuta (medido, `m7-tapon.ts`: se aplazaba sin motivo y el store
      // conservaba el padre VIEJO de todo lo que colgara de orgA). Lo que SÍ
      // nombra al hijo —`attached(child, unit)`, `moved(unit → orgC)`— sigue
      // taponado. Vive SOLO aquí, en la siembra: al COMPARAR (`#changeKeys`
      // en `blocked`, el respaldo de la sonda) van siempre las dos claves, o
      // el caso 1136 se pierde (trampa medida por el juez).
      const key = scopeKey(item.change.child)
      if (!keys.has(key)) keys.set(key, item.id)
    }
    return keys
  }

  /**
   * **La sonda de dependencia de `only`** (alpha.5 · R1): la pendiente más
   * antigua ANTERIOR a `item` que comparta clave de scope con ella, o `null`.
   * Con `earlierPending` es una consulta de existencia (0,69 ms medidos);
   * sin ella se pagina `pending()` desde el principio hasta `item.id` —
   * correcto, O(cola)— y si la cola no se deja recorrer en
   * `RELAY_WINDOW_MAX_PAGES` lotes se para (500 nombrando el método), nunca
   * se aplica sin saber.
   */
  async #dependencyOf(
    outbox: ScopeOutbox,
    item: PendingScopeTreeChange,
    batchSize: number
  ): Promise<PendingScopeTreeChange | null> {
    const keys = AuthorizationManager.#changeKeys(item.change)
    if (typeof outbox.earlierPending === 'function') {
      // La misma lista que `#changeKeys` (la raíz exenta, alpha.8): el SQL del
      // puerto sí sabe casar `parent_type = 'app'`; el manager no se lo pide.
      return outbox.earlierPending(item.id, AuthorizationManager.#changeScopes(item.change))
    }
    const mine = String(item.id)
    let after: string | number | undefined
    for (let page = 0; page < RELAY_WINDOW_MAX_PAGES; page++) {
      const batch = await outbox.pending(batchSize, after)
      for (const earlier of batch) {
        if (String(earlier.id) === mine) return null
        if (AuthorizationManager.#changeKeys(earlier.change).some((key) => keys.includes(key))) return earlier
      }
      if (batch.length < batchSize) return null
      after = batch[batch.length - 1].id
    }
    throw new AuthorizationConfigError(
      `authz:scopes:relay: no se pudo sondear si el cambio ${mine} depende de una entrada anterior: la cola tiene más de ` +
        `${RELAY_WINDOW_MAX_PAGES * batchSize} pendientes por delante y tu ScopeOutbox no implementa earlierPending(). ` +
        'Implementa la sonda, o releva sin `only`.'
    )
  }

  /**
   * **El ORIGEN del bloqueo de una entrada NO pedida** (2.4.0-alpha.6): ¿en la
   * pasada COMPLETA saldría `deferred` por un APARCADO —directo (`parked:`) o
   * heredado (`depends-on:` de otra que lo está)— y no por un fallo real ni
   * porque simplemente se aplicaría? `true` = retenida solo por un aparcado.
   * Es la misma regla que aplica `block`/`defer` a lo que la pasada SÍ procesa,
   * simulada hacia atrás sobre lo que no procesa:
   *  1. una clave suya en `blocked` (esta pasada) con origen FALLO ⇒ fallo;
   *  2. `attached`/`moved` con una clave en `parkedKeys`, o en `blocked` con
   *     origen aparcado ⇒ aparcado;
   *  3. si no, su propia anterior con clave compartida (`earlierPending`):
   *     ninguna ⇒ se aplicaría ⇒ NO es aparcado (la pedida espera su turno);
   *     alguna ⇒ el origen de ESA (recursivo, ids decrecientes, memoizado,
   *     `RELAY_ORIGIN_MAX_HOPS`; pasada la cota ⇒ fallo, hacia lo seguro).
   * Un `detached` anterior nunca es «aparcado» (una purga pasa; si sigue
   * pendiente es porque se aplicará): la pedida espera detrás.
   */
  async #blockOriginOf(
    outbox: ScopeOutbox,
    entry: PendingScopeTreeChange,
    blocked: Map<string, { id: string | number; origin: ScopeRelayBlockOrigin }>,
    parkedKeys: Map<string, string | number>,
    batchSize: number,
    memo: Map<string, ScopeRelayBlockOrigin>,
    hops = 0
  ): Promise<ScopeRelayBlockOrigin> {
    const id = String(entry.id)
    const known = memo.get(id)
    if (known !== undefined) return known
    const decide = (origin: ScopeRelayBlockOrigin) => {
      memo.set(id, origin)
      return origin
    }
    // Pasada la cota, hacia lo seguro: como un fallo real.
    if (hops >= RELAY_ORIGIN_MAX_HOPS) return decide('failed')
    const keys = AuthorizationManager.#changeKeys(entry.change)
    const hits = keys.map((key) => blocked.get(key)).filter((hit) => hit !== undefined)
    // Desde 2.4.0-alpha.8 el origen es TRI-estado (`failed > pending > parked`):
    // la decisión aplicar/aplazar no cambia (solo `parked` exime a la purga);
    // lo que cambia es que el reporte distingue «espera a una pendiente de
    // verdad» de «bloqueada por un fallo».
    if (hits.some((hit) => hit!.origin === 'failed')) return decide('failed')
    if (hits.some((hit) => hit!.origin === 'pending')) return decide('pending')
    if (entry.change.op !== 'detached') {
      if (hits.length > 0 || keys.some((key) => parkedKeys.has(key))) return decide('parked')
    }
    const earlier = await this.#dependencyOf(outbox, entry, batchSize)
    // Ninguna anterior: se aplicaría en la pasada completa ⇒ la pedida espera a una PENDIENTE de verdad.
    if (earlier === null) return decide('pending')
    return decide(await this.#blockOriginOf(outbox, earlier, blocked, parkedKeys, batchSize, memo, hops + 1))
  }

  /**
   * **Devuelve entradas APARCADAS a la cola** (2.4.0-alpha.5 · R2b; panel
   * relay, cuestión 2). Es lo que hay detrás de `node ace authz:scopes:requeue
   * --id`. Operación de PLATAFORMA como `relayScopeChanges` y `driver()`: sin
   * actor, sin `within`, **no se expone por HTTP**.
   *
   * **La sonda anti-reversión vive AQUÍ, no en la outbox**: reaplicar una
   * entrada ANTERIOR a otra ya APLICADA sobre la misma clave de scope
   * reescribe el árbol del store en un orden que nunca existió — el `moved`
   * viejo tras el nuevo deja el padre VIEJO con UN solo padre, así que
   * `assertOneParent` no lo delata y el tenant antiguo recupera el acceso
   * (auditor 🔴 2, `relay-auditor-5.ts`, medido). Por eso, antes de tocar la
   * cola, cada aparcada pedida se compara contra las aplicadas posteriores
   * que compartan clave (`outbox.laterApplied`, espejo de `earlierPending`)
   * y si hay alguna se NIEGA con 500 `E_AUTHZ_REQUEUE_REFUSED` nombrándola —
   * todo o nada, cero filas tocadas—. El remedio correcto es
   * `authz:reconcile --to=<driver>`, que recalcula con el árbol de HOY. La
   * sonda es del manager porque necesita las claves del cambio
   * (`#changeKeys`); `outbox.requeue` queda mecánico y una outbox de
   * terceros la hereda gratis.
   *
   * **`force`** salta la sonda y devuelve el diff en `overrides`. Existe para
   * el comando ace —que lo imprime y exige el flag explícito (decisión del
   * dueño del 2026-09-09 (2))— y para nada más: llamarlo con `force: true`
   * desde un endpoint es policy en una API sin policy.
   *
   * `attempts` queda en `maxAttempts − 1` (lo hace la outbox): si la causa
   * sigue rota la entrada vuelve a aparcarse en UNA pasada y contamina su
   * clave solo en esa pasada —un requeue automatizado de lo irreparable no
   * es un grifo de aplazamiento permanente (auditor 🔴 2, segunda mitad)—; si
   * el operador la arregló, entra a la primera. No hay bucle: lo aparcado no
   * vuelve solo a `pending()`.
   *
   * Exige `dead`, `requeue` y `laterApplied` en el puerto (500
   * `E_AUTHZ_UNSUPPORTED` nombrando el que falte): sin censo no se sabe qué
   * se reencola y sin sonda no hay requeue. Sin `apply` no pasa por la
   * barrera del freeze: no escribe en el backend; la pasada que aplique la
   * entrada sí la pasa.
   *
   * **`apply: true` — reencolar Y relevar en la misma llamada** (2.4.0-alpha.8;
   * panel relay 2, cuestión 4; decisión del dueño 2026-09-10 (4)). Medido
   * (tester P14): la reencolada vuelve con su id ORIGINAL (menor) y la
   * siguiente pasada `only` del tenant salía `deferred · depends-on:` — el
   * incidente no se cerraba con un comando. Con `apply`, tras reencolar se
   * releva SOLO eso (`only` = exactamente los ids reencolados: los
   * dependientes NO se arrastran, quedan `deferred`/pendientes y el reporte lo
   * dice —«`only` es mi recibo»—) y el reporte del relay viaja en
   * `report.relay`. Cuatro condiciones, todas fijadas con caso: (1) **un solo
   * lease** para toda la llamada (tomarlo dos veces era `busy` en verde,
   * auditor 🟠 5) — se toma PRIMERO, y si está ocupado es `relay.busy` con
   * CERO filas reencoladas (reencolar y decir `busy` dejaba `attempts = max −
   * 1` y la entrada se volvía a aparcar contaminando su clave); (2) **pasa la
   * barrera del freeze** ANTES de tocar nada (con `apply` escribe el árbol);
   * (3) **excluyente con `force`** (500 juntos: con las dos, revertir el árbol
   * pasaba de dos llamadas de plataforma a una, auditor 🟠 6); (4) la sonda
   * anti-reversión corre ANTES de reencolar, como siempre. `waitForLeaseMs`
   * (solo con `apply`) es la misma espera acotada que en el relay, para que
   * el comando que cierra el incidente no pierda siempre contra el cron.
   */
  async requeueScopeChanges(
    ids: Array<string | number>,
    options: { force?: boolean; apply?: boolean; waitForLeaseMs?: number } = {}
  ): Promise<ScopeRequeueReport> {
    AuthorizationManager.#assertKnownOptions('requeueScopeChanges', options, REQUEUE_OPTIONS)
    const apply = options.apply === true
    if (apply && options.force === true) {
      throw new AuthorizationConfigError(
        'authz:scopes:requeue: apply y force no se combinan: con las dos, revertir el árbol del store por encima de lo ya ' +
          'aplicado sería UNA sola llamada. Reencola con --force y releva después a sabiendas, o usa --apply sin --force. ' +
          'No se ha hecho nada.'
      )
    }
    if (!apply && options.waitForLeaseMs !== undefined) {
      throw new AuthorizationConfigError('authz:scopes:requeue: waitForLeaseMs solo tiene sentido con apply (sin apply no se toma ningún lease). No se ha hecho nada.')
    }
    const waitForLeaseMs = AuthorizationManager.#waitMs(options.waitForLeaseMs)
    // Con `apply` se ESCRIBE el árbol: la barrera del freeze va antes de nada.
    if (apply) await this.#assertNotFrozen('authz:scopes:requeue --apply')
    const outbox = this.#outbox()
    if (!outbox) {
      throw new AuthorizationConfigError(
        "authz:scopes:requeue necesita 'scopes.outbox' en config/authorization.ts: sin cola no hay nada aparcado que reencolar."
      )
    }
    const wanted = AuthorizationManager.#requeueIds(ids)
    for (const method of ['dead', 'requeue', 'laterApplied'] as const) {
      if (typeof outbox[method] !== 'function') {
        throw new UnsupportedOperationError(
          method,
          'authz:scopes:requeue',
          'scopes.outbox',
          method === 'laterApplied'
            ? 'Sin la sonda anti-reversión (laterApplied: las entradas APLICADAS posteriores que comparten clave) no hay ' +
                'requeue: reaplicar una entrada vieja por encima de una nueva revierte el árbol del store en silencio.'
            : method === 'dead'
              ? 'Sin dead() no se sabe qué está aparcado, y solo lo aparcado se reencola.'
              : 'Devuelve la entrada aparcada a pending() con attempts = maxAttempts − 1, todo o nada.'
        )
      }
    }
    // Con `apply`, el lease PRIMERO (una vez para toda la llamada): ocupado ⇒
    // `busy` con cero filas tocadas. Sin `apply` no hay lease que tomar.
    const lease = apply ? await this.#acquireLease(outbox, waitForLeaseMs) : null
    if (apply && outbox.acquire && lease === null) {
      const inputs = await AuthorizationManager.#relayInputs(outbox, [...wanted], DEFAULT_RELAY_BATCH)
      return { requeued: [], overrides: [], forced: false, relay: await this.#busyReport(outbox, inputs) }
    }
    try {
      return await this.#requeueHeld(outbox, wanted, options.force === true, apply)
    } finally {
      await lease?.release()
    }
  }

  /** `requeueScopeChanges` con el lease (si `apply`) ya tomado: censo, sonda anti-reversión, requeue y —con `apply`— el relay de esos ids. */
  async #requeueHeld(outbox: ScopeOutbox, wanted: Array<string | number>, force: boolean, apply: boolean): Promise<ScopeRequeueReport> {
    // El censo de lo aparcado (acotado como el del relay): solo eso se reencola.
    const parked = await outbox.dead!(DEFAULT_RELAY_LIMIT)
    const byId = new Map<string, PendingScopeTreeChange>()
    for (const item of parked) byId.set(String(item.id), item)
    const unknown = wanted.filter((id) => !byId.has(String(id)))
    if (unknown.length > 0) {
      throw new AuthorizationConfigError(
        `authz:scopes:requeue: ${unknown.map(String).join(', ')} no está(n) aparcada(s) —no existe, ya se aplicó, o sigue ` +
          `pendiente con intentos por gastar—: no se ha reencolado NADA (todo o nada). Solo se reencola lo que sale por ` +
          `dead(); una entrada aplicada no revive jamás.`
      )
    }
    const conflicts: ScopeRequeueConflict[] = []
    for (const id of wanted) {
      const item = byId.get(String(id))!
      // La misma lista que `#changeKeys` (la raíz exenta, alpha.8): dos altas de
      // tenant no se revierten entre sí, y el conflicto que salía era falso.
      const scopes: ScopeRef[] = AuthorizationManager.#changeScopes(item.change)
      // Se pide UNA de más para saber si el diff que va a leer el operador está cortado (cierre, ⚪ 6).
      const later = await outbox.laterApplied!(item.id, scopes, DEFAULT_RELAY_BATCH + 1)
      const applied = later.slice(0, DEFAULT_RELAY_BATCH)
      if (applied.length > 0) {
        conflicts.push({ parked: item, applied, ...(later.length > DEFAULT_RELAY_BATCH ? { truncated: true } : {}) })
      }
    }
    if (conflicts.length > 0 && !force) {
      const detail = conflicts
        .map((conflict) => {
          const keys = AuthorizationManager.#changeKeys(conflict.parked.change)
          const shared = conflict.applied.map((entry) => {
            const key = AuthorizationManager.#changeKeys(entry.change).find((k) => keys.includes(k)) ?? keys[0]
            return `#${entry.id} (${entry.change.op}, clave ${key})`
          })
          return `#${conflict.parked.id} (${conflict.parked.change.op}) revertiría ${shared.join(', ')}`
        })
        .join('; ')
      throw new ScopeRequeueRefusedError(
        `authz:scopes:requeue: reencolar reaplicaría un cambio ANTERIOR a otro ya APLICADO sobre la misma clave de scope, ` +
          `y el árbol del store quedaría en un orden que nunca existió: ${detail}. No se ha reencolado nada. ` +
          `Para recalcular con el árbol de HOY: authz:reconcile --to=<driver>. Si de verdad quieres revertir, el comando ` +
          `ace admite --force (imprime este diff y entra igual).`,
        conflicts
      )
    }
    await outbox.requeue!([...wanted])
    const report: ScopeRequeueReport = { requeued: wanted.map((id) => byId.get(String(id))!), overrides: conflicts, forced: force }
    if (!apply) return report
    // Bajo el MISMO lease: solo los ids reencolados, con lo aparcado releído
    // (las reencoladas ya no salen por `dead()`); la barrera del freeze se
    // re-afirma por lote dentro, como en toda pasada.
    const inputs = await AuthorizationManager.#relayInputs(outbox, [...wanted], DEFAULT_RELAY_BATCH)
    report.relay = await this.#drainScopeChanges(outbox, { limit: DEFAULT_RELAY_LIMIT, batchSize: DEFAULT_RELAY_BATCH, ...inputs })
    return report
  }

  /** Los ids de `requeue`: lista NO vacía de números o cadenas, sin repetidos (500 si no). */
  static #requeueIds(ids: Array<string | number>): Array<string | number> {
    if (!Array.isArray(ids) || ids.length === 0 || ids.some((id) => typeof id !== 'number' && typeof id !== 'string')) {
      throw new AuthorizationConfigError(
        `authz:scopes:requeue: 'ids' debe ser una lista NO vacía de ids (number | string); llegó ${JSON.stringify(ids)}. ` +
          'Sin ids no se reencola nada: «nada» no es «todo».'
      )
    }
    const seen = new Set<string>()
    return ids.filter((id) => (seen.has(String(id)) ? false : (seen.add(String(id)), true)))
  }

  /**
   * **`authz:reconcile --to=<driver>`** (3b-3a): la ÚNICA primitiva de
   * migración y verificación del paquete, y el motivo de la fase entera —
   * «todo en un driver o todo en otro, con una migración idempotente y
   * bidireccional». Sustituye a `openfga:import`, que el 2k borró.
   *
   * Operación de PLATAFORMA, como `driver()` y `relayScopeChanges`: no lleva
   * actor, no mide rangos y **no se expone por HTTP**.
   *
   * El driver de destino se resuelve **por nombre del registro**
   * (`config.drivers[to]`), no por `config.default`: la migración de verdad
   * es «el motor sigue corriendo con `database` mientras se llena el store de
   * `openfga`», y con el default no habría forma de nombrar al destino. Un
   * driver que no sabe reconstruirse lo dice (500 `E_AUTHZ_UNSUPPORTED`
   * nombrando `reconcile`); el driver `database` es ese caso: sus tablas SON
   * el origen y llenarlas desde un store es la otra dirección (3b-3b).
   *
   * Durante la pasada que ESCRIBE, las escrituras del motor están CONGELADAS
   * (`withFrozenWrites`): un `grant` que aterrizara entre la lectura del
   * origen y la escritura del destino no llegaría al destino y no aparecería
   * en ningún contador. Las lecturas siguen. El `finally` descongela pase lo
   * que pase.
   *
   * **`--dry-run` NO congela** (3b-6, panel 3 · juez §3). El verificador es
   * read-only por contrato: no escribe nada, así que no tiene NADA que
   * proteger, y congelar ahí sería apagar las escrituras a cambio de cero.
   * Está publicado para correrlo en CI y en un cron, o sea justo el sitio
   * desde el que un mecanismo de indisponibilidad se dispara solo — hoy
   * contra el proceso del job, y contra la flota entera el día que el freeze
   * sea durable. El único contraargumento posible —que congelar estabiliza
   * sus números— no vale: los números de un verificador read-only no son una
   * garantía de nada.
   *
   * Lo que añade el manager al reporte del driver es lo único que el driver
   * no puede ver: **la ventana del relay** —los cambios del árbol encolados y
   * sin aplicar, que son la deriva que el store todavía no conoce (decisión
   * del dueño del 2026-08-30, consecuencia 4)— y las entradas APARCADAS, que
   * no son una ventana sino una divergencia permanente.
   */
  async reconcile(
    options: { to: string; from?: string } & ReconcileOptions
  ): Promise<ReconcileReport> {
    const name = options.to
    const factory: AuthorizationDriverFactory | undefined = this.#config.drivers?.[name]
    if (!factory) {
      throw new AuthorizationConfigError(
        `authz:reconcile --to=${name}: ese driver no está registrado en config/authorization.ts ` +
          `(registrados: ${Object.keys(this.#config.drivers ?? {}).join(', ') || 'ninguno'}). ` +
          `El destino se nombra por su clave en 'drivers', no por el driver activo: migrar es llenar el ` +
          `destino mientras el motor sigue corriendo con el otro.`
      )
    }
    let target = await factory()
    const clock = this.#config.clock
    if (clock !== undefined) {
      if (typeof target.withClock !== 'function') {
        throw new AuthorizationConfigError(
          `config.clock está declarado pero el driver '${name}' no implementa withClock(now): la migración ` +
            `escribiría caducidades decididas con otro reloj que el motor.`
        )
      }
      target = target.withClock(clock)
    }
    if (typeof target.reconcile !== 'function') {
      throw new UnsupportedOperationError(
        'reconcile',
        `authz:reconcile --to=${name}`,
        name,
        `El driver '${name}' no sabe reconstruirse desde 'authz_*' + el árbol del consumidor. ` +
          `El driver 'database' es ese caso a propósito: sus tablas son el ORIGEN.`
      )
    }
    // **La dirección RANCIA** (2.4.0-alpha.10; 🔴 4 del sexto informe de
    // COGNITIV y cuarta iteración del LINAJE «origen rancio del reconcile»:
    // 3b-5 cerró la pasada por defecto, el primer guard de alpha.10 cerró
    // `--from`, y quedaba abierto el origen elegido POR DESCARTE). Regla del
    // dueño: el tercer defecto de un linaje se arregla estructuralmente, así
    // que el guard NO mira la bandera, mira el ORIGEN RESUELTO — con la MISMA
    // decisión que `#factsOrigin` (`#isMaintenancePass`), no con una copia:
    // si `to` es el driver ACTIVO, el único origen legítimo es `to` mismo (la
    // pasada de MANTENIMIENTO); cualquier otro —`--from`, el driver elegido por
    // descarte o las tablas `authz_*`— dejó de ver los hechos en el cutover y la
    // pasada re-escribiría lo revocado después (con o sin --prune; el seguro de
    // borrado masivo no salta: el origen no está vacío). Se decide por `to`,
    // nunca por `from`: el cutover inicial y la vuelta atrás ANTES de cambiar
    // `default` tienen `to` ≠ activo y pasan. Antes de resolver el origen y de
    // congelar. `--dry-run` no lanza (es el verificador): lo marca y
    // `reconcileLines` lo hace deriva. `from === to` sigue siendo el 500
    // E_AUTHZ_CONFIG de 3b-3b.
    const stale =
      this.#sameDriver(name, this.#config.default) &&
      (options.from === undefined || !this.#sameDriver(options.from, name)) &&
      !this.#isMaintenancePass(name, target, options.from)
    const allowStale = options.allowStaleSource === true
    if (stale && !allowStale && options.dryRun !== true) {
      const how = options.from !== undefined ? `--from=${options.from}` : 'sin --from'
      // Cierre del auditor (⚪ 8): con UN solo driver registrado no hay descarte que
      // hacer; la letra no puede hablar de un origen que no existe.
      const others = Object.keys(this.#config.drivers ?? {}).filter((key) => !this.#sameDriver(key, name))
      const originLabel =
        options.from !== undefined
          ? `el origen '${options.from}' no lo es`
          : others.length === 0
            ? `no hay ningún otro driver registrado ni pasada de mantenimiento para él (no guarda sus hechos en su ` +
              `backend: no declara hierarchyFacts), así que no hay nada de dónde reconciliar hacia '${name}'`
            : `sin --from el origen se elegiría POR DESCARTE (las tablas authz_* u otro driver registrado: ` +
              `${others.join(', ')}), y no es '${name}'`
      throw new StaleSourceRefusedError(
        `authz:reconcile --to=${name} ${how}: '${name}' es el driver ACTIVO (config.default` +
          `${name === this.#config.default ? '' : `: la clave resuelve la MISMA factory que '${this.#config.default}'`}) y ${originLabel}. ` +
          `Esa dirección re-escribiría en el driver activo hechos que el origen ya no refleja: resucitaría las ` +
          `revocaciones hechas desde el cutover (y con --prune borraría lo concedido después). No se ha leído, ` +
          `congelado ni escrito nada. Hacia el driver activo el único origen es él mismo: la pasada de mantenimiento ` +
          `(authz:reconcile --to=${name} [--dry-run], sin --from) si su driver guarda sus hechos; y si lo que quieres ` +
          `es volver atrás, migra en la otra dirección ANTES de cambiar config.default. Si de verdad el origen sigue ` +
          `siendo la fuente de verdad (el motor aún no ha escrito desde '${name}'), la decisión humana es ` +
          `--allow-stale-source (allowStaleSource: true).`
      )
    }
    // **De dónde salen los HECHOS** (3b-5): la decisión que faltaba, y la que
    // el destino no puede tomar por su cuenta. Ver `#factsOrigin`.
    const origin = await this.#factsOrigin(name, target, options.from)
    const source: ReconcileSource = {
      enumerateEdges: this.#edgesEnumerator(),
      resolveChain: this.#freshResolver(),
      // Los hechos del ORIGEN, **perezosos** (3b-3b): la dirección que lee
      // `authz_*` no construye ningún driver de más. Y el origen se resuelve
      // UNA vez.
      facts: origin.enumerate,
      factsOrigin: { name: origin.name, authzTables: origin.authzTables, ...(origin.self ? { self: true } : {}) },
      // El techo de profundidad del consumidor, si lo declaró (alpha.5 · R0):
      // el mismo mando que el gate de `scopes.*`.
      ...(this.#config.scopes?.maxDepth === undefined ? {} : { maxDepth: this.#config.scopes.maxDepth }),
      // **Los tipos del OTRO subsistema del mismo backend** (alpha.9 · B · S4),
      // si el consumidor declaró relaciones. Es SOLO para el reporte: parte lo
      // ajeno en «declarado» y «no lo reclama nadie». La decisión de BORRAR no
      // lo mira —la toma la lista blanca congelada del destino—, porque el
      // proceso que corre un cutover puede no tener esta config y aun así
      // tiene que respetar las tuplas de quien sí la tiene.
      ...(this.#config.relations?.config === undefined
        ? {}
        : { relationTypes: this.#config.relations.config.objectTypes.map((type) => type.type) }),
    }
    const pass = async (): Promise<ReconcileReport> => {
      const report = await target.reconcile!(source, options)
      const { pending, dead } = await this.#relayWindow()
      report.drift.pendingRelay = pending
      report.drift.deadRelay = dead
      // Quién fue el origen se DICE, siempre: es la diferencia entre una
      // migración y una pasada de mantenimiento contra el driver activo.
      report.factsFrom = origin.resolved()
      if (stale) report.staleSource = { to: name, from: origin.resolved(), allowed: allowStale }
      return report
    }
    // La pasada que escribe congela; el verificador NO (ver el docblock).
    if (options.dryRun === true) return pass()
    // El freeze de la pasada es DURABLE y con dueño (3b-7): si este manager
    // ya sostiene uno, la pasada corre DENTRO; si hay una ventana de
    // OPERADOR viva (`authz:freeze`, el cutover), la pasada la reconoce como
    // contexto propio —no la toma, no la renueva, no la levanta—; si el
    // freeze vivo es de otro `reconcile`, 423: dos pasadas no se pisan. Y el
    // reporte publica la garantía en vez de suponerla: `frozen.lapsed=true`
    // significa que el lease se perdió a mitad y la pasada NO se certifica
    // (el comando sale distinto de cero).
    const window = await this.#durableFreezeContext(`authz:reconcile --to=${name}`, 'reconcile', {
      operatorAsContext: true,
    })
    try {
      const report = await pass()
      report.frozen = {
        durable: true,
        lapsed: await window.lapsed(),
        leaseMs: window.leaseMs,
        fence: window.fence,
        ...(window.untilMs === undefined ? {} : { untilMs: window.untilMs }),
        ...(window.window === undefined ? {} : { window: window.window }),
      }
      return report
    } finally {
      await window.release()
    }
  }

  /**
   * **Quién es la FUENTE DE VERDAD de los hechos de esta pasada** (3b-5, los
   * dos 🔴 del auditor final de la Fase 3b). Es la pregunta que
   * `authz:reconcile --to=openfga` no se hacía: leía `authz_assignments`/
   * `authz_denies` SIEMPRE, y en un despliegue `hierarchy: 'facts'` esas
   * tablas no son la fuente de verdad de los hechos —lo son las tuplas del
   * store—, así que la pasada resucitaba lo revocado después del cutover,
   * `--prune` borraba los denies vivos y el barrido de visibilidad del
   * invariante 18 no se aplicaba nunca (`forbidden` salía vacío porque
   * `wanted.facts` salía vacío).
   *
   * Las tres respuestas, en este orden:
   *
   *  1. **El destino es el driver ACTIVO y sus hechos son SUYOS**
   *     (`to === config.default` y `capabilities.hierarchyFacts`): entonces
   *     `authz_*` no puede ser su origen —el motor lleva desde el cutover
   *     escribiendo los hechos en el destino— y la pasada es de
   *     MANTENIMIENTO: los hechos se leen del propio destino por el puerto
   *     (`enumerateFacts`), se rehace lo DERIVADO (marcador, catálogo, árbol)
   *     y se aplica el barrido de visibilidad del invariante 18 con el árbol
   *     y el catálogo de HOY. No se inventa ningún hecho; con `--prune` se
   *     borran los que ya no respaldan nada (scopes que ya no resuelven,
   *     caducados, roles/permisos retirados, y los que sobran). Un
   *     destino activo con `hierarchyFacts` que no sepa enumerar sus hechos
   *     es 500 `E_AUTHZ_UNSUPPORTED`: leerle `authz_*` sería justo el defecto.
   *  2. **`--from=<nombre>` manda**, y por eso se resuelve YA: de la
   *     naturaleza de ese driver depende de dónde salen los hechos (si sabe
   *     `enumerateFacts`, del puerto; si no, es un driver cuyos hechos son
   *     `authz_*` —el `database` del paquete— y los lee el destino).
   *  3. **Sin `--from` y sin ser el activo**: la MIGRACIÓN de siempre. Los
   *     hechos son `authz_*`, el esquema PUBLICADO del paquete, y el destino
   *     los lee él mismo; si el destino los pide por el puerto (`--to=database`)
   *     el origen se resuelve entonces, perezosamente y con la regla ruidosa
   *     de 3b-3b (`#factsEnumerator`).
   */
  async #factsOrigin(
    to: string,
    target: AuthorizationDriver,
    from: string | undefined
  ): Promise<{
    name: string
    authzTables: boolean
    /** F-R1 (plan 2.5 · lote A): el origen ES el destino (mantenimiento). */
    self?: boolean
    enumerate: ReconcileFactsEnumerator
    resolved: () => string
  }> {
    if (this.#isMaintenancePass(to, target, from)) {
      if (typeof target.enumerateFacts !== 'function') {
        throw new UnsupportedOperationError(
          'enumerateFacts',
          `authz:reconcile --to=${to}`,
          to,
          `El motor SIRVE desde '${to}' y ese driver declara que el árbol y los hechos viven en su backend ` +
            `(hierarchyFacts), así que 'authz_assignments'/'authz_denies' NO son la fuente de verdad de sus ` +
            `hechos: reconstruirlo desde ellas reescribiría lo que hayas revocado desde el cutover. Para poder ` +
            `verificarlo y repararlo hace falta que sepa entregar sus hechos (enumerateFacts).`
        )
      }
      return {
        name: to,
        authzTables: false,
        self: true,
        enumerate: (page) => target.enumerateFacts!(page),
        resolved: () => to,
      }
    }
    if (from !== undefined) {
      const driver = await this.#originDriver(from, to)
      return {
        name: from,
        authzTables: typeof driver.enumerateFacts !== 'function',
        enumerate: async (page) => {
          if (typeof driver.enumerateFacts !== 'function') {
            throw new UnsupportedOperationError(
              'enumerateFacts',
              `authz:reconcile --from=${from}`,
              from,
              `El driver '${from}' no sabe entregar sus hechos. El driver 'database' es ese caso a propósito: ` +
                `sus hechos son 'authz_assignments'/'authz_denies' y el destino los lee de ahí.`
            )
          }
          return driver.enumerateFacts(page)
        },
        resolved: () => from,
      }
    }
    let resolvedName = AUTHZ_TABLES_ORIGIN
    const enumerate = await this.#factsEnumerator(to, (name) => {
      resolvedName = name
    })
    return { name: AUTHZ_TABLES_ORIGIN, authzTables: true, enumerate, resolved: () => resolvedName }
  }

  /**
   * **¿Es la pasada de MANTENIMIENTO?** (3b-5; punto ÚNICO desde alpha.10): el
   * destino es el driver ACTIVO, sus hechos viven en su backend
   * (`hierarchyFacts`) y nadie nombró otro origen. Es la ÚNICA forma en la que
   * el origen resuelto de una pasada hacia el driver activo es el propio
   * destino, y la usan los dos que la necesitan: `#factsOrigin` (de dónde se
   * leen los hechos) y el guard de la dirección rancia de `reconcile` (si ese
   * origen es legítimo). Dos copias de esta condición eran dos respuestas.
   */
  #isMaintenancePass(to: string, target: AuthorizationDriver, from: string | undefined): boolean {
    return from === undefined && this.#sameDriver(to, this.#config.default) && target.capabilities?.hierarchyFacts === true
  }

  /**
   * **¿Dos claves de `drivers` son el MISMO driver?** (cierre del auditor de
   * alpha.10 · R4, gemelo de roles): misma clave o la MISMA factory registrada
   * bajo dos claves. El guard de la dirección rancia, el mantenimiento, el
   * `from === to` y el descarte juzgan la identidad RESUELTA, no la etiqueta:
   * con `drivers: { openfga: f, fga: f }` y `default: 'openfga'`, `--to=fga
   * --from=database` es la misma dirección rancia que `--to=openfga`.
   *
   * **Límite DECLARADO (cierre-2 · C1)**: la identidad es la REFERENCIA de la
   * factory, no el backend. Dos factories distintas que construyen el mismo
   * store (`openfga: () => new OpenFga…(…)`, `fga: () => new OpenFga…(…)`) NO son
   * el mismo driver para este predicado y el alias pasa el guard. Identidad de
   * backend declarada por el driver ⇒ roadmap 2.5.
   */
  #sameDriver(a: string, b: string): boolean {
    if (a === b) return true
    const drivers = this.#config.drivers ?? {}
    const own = (key: string) => (Object.prototype.hasOwnProperty.call(drivers, key) ? drivers[key] : undefined)
    const fa = own(a)
    return fa !== undefined && fa === own(b)
  }

  /** El driver que `--from` nombra, con los dos errores de 3b-3b intactos. */
  async #originDriver(from: string, to: string): Promise<AuthorizationDriver> {
    const registered = Object.keys(this.#config.drivers ?? {})
    if (this.#sameDriver(from, to)) {
      throw new AuthorizationConfigError(
        `authz:reconcile --from=${from} --to=${to}: el origen y el destino son el mismo driver. ` +
          `Si lo que quieres es VERIFICAR y reparar lo derivado del driver activo, no lo digas con --from: ` +
          `la pasada ya lee sus hechos de él cuando es el driver por defecto.`
      )
    }
    const factory = this.#config.drivers?.[from]
    if (!factory) {
      throw new AuthorizationConfigError(
        `authz:reconcile --from=${from}: ese driver no está registrado en config/authorization.ts ` +
          `(registrados: ${registered.join(', ') || 'ninguno'}).`
      )
    }
    return factory()
  }

  /**
   * **Quién es el ORIGEN de `authz:reconcile --to=<destino>`** (3b-3b), y su
   * enumerador de hechos — perezoso: se resuelve la PRIMERA vez que el
   * destino lo pide, así que la dirección que lee `authz_*` (`--to=openfga`)
   * no construye ningún driver de más.
   *
   * La regla es determinista y RUIDOSA, nunca «el que haya» (`--from` lo
   * resuelve antes `#factsOrigin`, 3b-5):
   *  - se busca entre los drivers registrados distintos del
   *    destino los que sepan ser origen (`capabilities.enumerateFacts` o el
   *    método): **exactamente uno** ⇒ ése; **ninguno** ⇒ 500
   *    `E_AUTHZ_UNSUPPORTED` nombrando `enumerateFacts`; **más de uno** ⇒ 500
   *    pidiendo `--from`, porque elegir por ti es elegir de dónde sale lo que
   *    va a quedar escrito.
   *
   * Nunca «cero hechos» en silencio: un origen que no responde y un `--prune`
   * detrás vacían el destino, y eso no puede depender de adivinar.
   */
  async #factsEnumerator(
    to: string,
    onResolved?: (name: string) => void
  ): Promise<ReconcileFactsEnumerator> {
    let resolved: AuthorizationDriver | null = null
    const build = async (): Promise<AuthorizationDriver> => {
      const registered = Object.keys(this.#config.drivers ?? {})
      const candidates: Array<{ name: string; driver: AuthorizationDriver }> = []
      for (const candidate of registered) {
        if (this.#sameDriver(candidate, to)) continue
        const driver = await this.#config.drivers![candidate]!()
        if (typeof driver.enumerateFacts === 'function') candidates.push({ name: candidate, driver })
      }
      if (candidates.length === 1) {
        onResolved?.(candidates[0].name)
        return candidates[0].driver
      }
      if (candidates.length === 0) {
        throw new UnsupportedOperationError(
          'enumerateFacts',
          `authz:reconcile --to=${to}`,
          to,
          `Ningún driver registrado (${registered.join(', ') || 'ninguno'}) sabe ser el ORIGEN de esta ` +
            `migración. Sin hechos que leer, la pasada escribiría cero y con --prune vaciaría el destino.`
        )
      }
      throw new AuthorizationConfigError(
        `authz:reconcile --to=${to}: hay más de un origen posible ` +
          `(${candidates.map((c) => c.name).join(', ')}). Dilo con --from=<driver>: de dónde salen los ` +
          `hechos decide lo que va a quedar escrito, y eso no se adivina.`
      )
    }
    return async (page) => {
      resolved ??= await build()
      return resolved.enumerateFacts!(page)
    }
  }

  /**
   * `scopes.enumerateEdges` o 500: sin el árbol del consumidor no se puede
   * reconstruir el del backend, y suponerlo plano sería inventar una
   * jerarquía (y con ella una concesión).
   */
  #edgesEnumerator(): ScopeEdgesEnumerator {
    const enumerate = this.#config.scopes?.enumerateEdges
    if (typeof enumerate !== 'function') {
      throw new AuthorizationConfigError(
        "authz:reconcile necesita 'scopes.enumerateEdges' en config/authorization.ts: es el árbol ENTERO, " +
          'paginado, y es lo que se migra (y lo que dice qué aristas del backend ya no respalda nadie). ' +
          'sqlScopeEdges(...) lo implementa sobre una tabla con columna padre.'
      )
    }
    return enumerate
  }

  /**
   * **La ventana del relay, medida** (decisión del dueño del 2026-08-30,
   * consecuencia 4): cuántos cambios del árbol están encolados sin aplicar
   * —el backend decide con el árbol viejo mientras tanto— y cuántos están
   * APARCADOS, que ya no es una ventana sino una divergencia permanente.
   *
   * Se mide con las escrituras congeladas, así que la cola no crece durante
   * la cuenta. Sin outbox no hay ventana (el manager escribe en línea) y los
   * dos números son cero.
   */
  async #relayWindow(): Promise<{ pending: number; dead: number }> {
    const outbox = this.#outbox()
    if (!outbox) return { pending: 0, dead: 0 }
    let pending = 0
    let after: string | number | undefined
    for (let page = 0; page < RELAY_WINDOW_MAX_PAGES; page++) {
      const batch = await outbox.pending(DEFAULT_RELAY_BATCH, after)
      pending += batch.length
      if (batch.length < DEFAULT_RELAY_BATCH) break
      after = batch[batch.length - 1].id
    }
    const dead = typeof outbox.dead === 'function' ? (await outbox.dead(DEFAULT_RELAY_BATCH)).length : 0
    return { pending, dead }
  }

  /**
   * Los scopes que un cambio del árbol NOMBRA: son las claves con las que se
   * decide si otro cambio depende de él (3b-2h · 🔴 2). Dos cambios que no
   * comparten ninguna no pueden interactuar en el árbol —toda dependencia
   * (recolgar, cerrar un ciclo, purgar) viaja por un nodo nombrado—, así que
   * el orden RELATIVO que hay que conservar es exactamente este.
   *
   * **La raíz `app` NO es clave** (2.4.0-alpha.8; panel relay 2, cuestión 1;
   * decisión del dueño 2026-09-10 (4)). La raíz no se mueve, no se purga y
   * nunca es hijo (los tres 422 de `#assertEdge`/`scopes.detached`), así que
   * dos cambios cuyo ÚNICO cruce sea `app` conmutan: ningún orden que
   * conservar (el auditor lo buscó y no lo encontró; `m2-orden.ts`). Con
   * `[hijo, app]` toda alta de tenant compartía clave con todas las demás:
   * una aparcada bajo la raíz congelaba el registro entero (5 pasadas con
   * `applied = []`, medido en un consumidor), dos altas concurrentes con la
   * receta inline dejaban la segunda `deferred` SIN nada aparcado, y
   * `requeue` se negaba con un conflicto falso. Se decide por REF
   * (`#isRootRef`), nunca por la cadena `'app'`, y en los TRES sitios que
   * construyen la lista: aquí, `#dependencyOf` y `requeueScopeChanges` (los
   * dos por `#changeScopes`); también para el bloqueo por FALLO (una sola
   * regla). La lista nunca queda vacía: el hijo siempre va.
   */
  static #changeKeys(change: ScopeTreeChange): string[] {
    return AuthorizationManager.#changeScopes(change).map((scope) => scopeKey(scope))
  }

  /**
   * Los scopes de `#changeKeys` como REFERENCIAS: la lista que va al puerto
   * (`earlierPending`/`laterApplied`). Es la misma decisión que
   * `#changeKeys` y vive en un solo sitio a propósito (auditor 🟠 3 del panel
   * relay 2: exentar la raíz solo en las claves dejaba el mutex vivo bajo
   * `only`, porque el SQL de la sonda sí casa `parent_type = 'app'`).
   */
  static #changeScopes(change: ScopeTreeChange): ScopeRef[] {
    if (change.op === 'detached') return [change.child]
    if (AuthorizationManager.#isRootRef(change.parent)) return [change.child]
    return [change.child, change.parent]
  }

  /** ¿Es la raíz? Por REF (`type === 'app' && uuid === null`), jamás comparando la cadena `'app'`. */
  static #isRootRef(scope: ScopeRef): boolean {
    return scope.type === APP_SCOPE_TYPE && (scope.uuid ?? null) === null
  }

  /** Lo aparcado por la outbox (si sabe aparcar), listo para el reporte. */
  static async #deadLetters(outbox: ScopeOutbox, limit: number): Promise<RelayedScopeChange[]> {
    if (typeof outbox.dead !== 'function') return []
    const rows = await outbox.dead(limit)
    return rows.map((item) => ({
      id: item.id,
      change: item.change,
      attempts: item.attempts,
      ...(item.lastError === undefined ? {} : { error: item.lastError }),
    }))
  }

  /**
   * Aplica UN cambio del árbol al driver. Es el mismo camino que
   * `scopes.*` sin outbox, incluido el orden de `detached`: **hechos primero
   * —el driver demuestra cero o lanza—, arista al final** (S6). Al revés,
   * una purga muerta a medias dejaría grants vivos en un scope sin ancestro,
   * los denies heredados dejarían de aplicar y esos permisos serían
   * INDENEGABLES (invariante 2).
   */
  async #applyScopeChange(driver: AuthorizationDriver, item: PendingScopeTreeChange): Promise<void> {
    const change = item.change
    if (change.op === 'attached') {
      await driver.onScopeAttached?.(change.child, change.parent)
      return
    }
    if (change.op === 'moved') {
      await driver.onScopeMoved?.(change.child, change.parent)
      return
    }
    // La auditoría no pierde al autor por haber pasado por una cola.
    const event: AuthzWriteEvent = {
      action: 'scope_purged',
      scope: change.child,
      ...(item.actor ? { actor: item.actor } : {}),
    }
    await this.#write(event, () => driver.purgeScope(change.child))
    await driver.onScopeDetached?.(change.child)
    await this.#notify(event)
  }

  /** Cota entera positiva de las opciones del relay (500 si llega otra cosa). */
  /**
   * **Una opción desconocida es 500, nunca silencio** (2.4.0-alpha.8 · X-1;
   * tester del panel relay 2, §10-d). Medido en alpha.7: `requeueScopeChanges(ids,
   * { apply: true })` y `relayScopeChanges({ waitForLeaseMs })` se IGNORABAN
   * —el objeto de opciones no se validaba— y un consumidor en JS (o con
   * `as any`) creía que aplicaba o esperaba cuando no; el síntoma era un
   * `busy` o un `deferred` achacado a otra cosa. Se comprueban las CLAVES
   * (un valor `undefined` en una clave conocida vale: es lo que pasan los
   * comandos ace), y el objeto tiene que serlo.
   */
  static #assertKnownOptions(operation: string, options: unknown, known: readonly string[]): void {
    if (options === undefined) return
    if (options === null || typeof options !== 'object' || Array.isArray(options)) {
      throw new AuthorizationConfigError(
        `${operation}: las opciones deben ser un objeto { ${known.join(', ')} }; llegó ${Array.isArray(options) ? 'una lista' : String(options)}.`
      )
    }
    const unknown = Object.keys(options).filter((key) => !known.includes(key))
    if (unknown.length > 0) {
      throw new AuthorizationConfigError(
        `${operation}: opción(es) desconocida(s): ${unknown.join(', ')}. Las conocidas son ${known.join(', ')}. ` +
          'Una opción que no existe no se ignora: en JS creerías que aplica (o espera) cuando no. No se ha hecho nada.'
      )
    }
  }

  static #positive(value: number | undefined, fallback: number, name: string): number {
    if (value === undefined) return fallback
    if (!Number.isInteger(value) || value < 1) {
      throw new AuthorizationConfigError(
        `authz:scopes:relay: ${name} debe ser un entero >= 1 (llegó ${String(value)})`
      )
    }
    return value
  }

  /**
   * Valida las opciones comunes de una escritura (B7) ANTES de identidad,
   * catálogo, árbol y driver: `actor` bien formado si viene; obligatorio con
   * `requireActor`. Devuelve `{ actor }` listo para fundir en el evento (o
   * `{}` si no hay actor: el evento no inventa autores).
   */
  async #writeOptions(options: WriteOptions | undefined, operation: string): Promise<{ actor?: SubjectRef }> {
    // Sin cast sobre `transaction` (L-1 · 🟠 8): la barrera no lee nada del
    // llamante, y `transaction` solo lo consumen los tipos que lo declaran
    // (`ScopeTreeWriteOptions`, para ENCOLAR — nunca para decidir).
    await this.#assertNotFrozen(operation)
    if (options?.actor !== undefined) assertSubject(options.actor)
    if (this.#config.requireActor === true && !options?.actor) {
      throw new ActorRequiredError(
        `${operation}: el config exige 'actor' en toda escritura (requireActor: true) y no llegó ninguno.`
      )
    }
    return options?.actor ? { actor: options.actor } : {}
  }

  /** El resolutor con el que LEE este manager: el memo de la vista, o el fresco. */
  #readResolverOrFresh(): ScopeChainResolver {
    return this.#readResolver ?? this.#freshResolver()
  }

  /**
   * El catálogo para las composiciones (B5/B3): el memo del driver si lo
   * expone (`driver.catalog`, ambos drivers del paquete: una sola carga por
   * proceso) y, si no, uno propio del manager. El catálogo es propiedad
   * local siempre (`authz_*`), así que leerlo desde el manager no acopla a
   * ningún driver.
   */
  #catalogFor(driver: AuthorizationDriver): CatalogCache {
    const shared = (driver as { catalog?: unknown }).catalog
    if (shared instanceof CatalogCache) return shared
    if (this.#parent) return this.#parent.#catalogFor(driver)
    this.#ownCatalog ??= new CatalogCache({ driver: this.#config.default })
    return this.#ownCatalog
  }

  /** Un método opcional del puerto, o 500 `E_AUTHZ_UNSUPPORTED` nombrándolo. */
  #optional<K extends keyof AuthorizationDriver>(
    driver: AuthorizationDriver,
    method: K,
    primitive: string,
    hint?: string
  ): NonNullable<AuthorizationDriver[K]> {
    const fn = driver[method]
    if (typeof fn !== 'function') {
      throw new UnsupportedOperationError(method, primitive, this.#config.default, hint)
    }
    return fn.bind(driver) as NonNullable<AuthorizationDriver[K]>
  }

  /** El resolutor FRESCO del config (o solo-raíz): el de las escrituras y de `isWithin`. */
  #freshResolver(): ScopeChainResolver {
    return this.#config.scopes?.resolveChain ?? rootOnlyResolver
  }

  static #sameScope(a: ScopeRef, b: ScopeRef): boolean {
    return a.type === b.type && (a.uuid ?? null) === (b.uuid ?? null)
  }

  /**
   * ¿`outer` contiene a `inner`? = `outer ∈ chain(inner)`, inclusive: un scope
   * se contiene a sí mismo y `APP_SCOPE` contiene todo. Un `inner` que el
   * árbol no conoce no está dentro de nada (`false`). Siempre con el resolutor
   * fresco (nunca el memo por request): la contención decide escrituras.
   */
  async isWithin(inner: ScopeRef, outer: ScopeRef): Promise<boolean> {
    assertScope(inner)
    assertScope(outer)
    const chain = await resolveChain(this.#freshResolver(), inner, 'isWithin')
    if (!chain) return false
    return chain.some((s) => AuthorizationManager.#sameScope(s, outer))
  }

  /**
   * Contención de una escritura (B1; las seis desde 2D · F2). El scope tiene
   * que existir (422 `E_AUTHZ_UNKNOWN_SCOPE`, la misma regla que el driver
   * aplicará después) y `within`, si viene, estar en su cadena (422
   * `E_AUTHZ_NOT_WITHIN`). Con `requireWithin`, omitirlo es 422
   * `E_AUTHZ_WITHIN_REQUIRED`; con `'non-root'`, `APP_SCOPE` como `within`
   * es 422 `E_AUTHZ_WITHIN_ROOT_FORBIDDEN`. Todo antes del driver: nada se
   * escribe. Siempre con el resolutor fresco (nunca el memo por request).
   */
  async #assertWithin(scope: ScopeRef, options: ScopedWriteOptions | undefined, operation: string): Promise<void> {
    const within = this.#requiredWithin(scope, options, operation)
    if (!within) return
    const chain = await assertKnownScope(this.#freshResolver(), scope, operation)
    this.#assertWithinChain(scope, chain, options, operation)
  }

  /**
   * Contención del ORIGEN de un movimiento (2E · H1, auditor 1): la cadena
   * ACTUAL del hijo, resuelta en fresco, también tiene que contener `within`.
   * Con `'required'` (`scopes.moved`) el hijo tiene que existir en el árbol
   * (422 `E_AUTHZ_UNKNOWN_SCOPE`: sin cadena no hay origen que contrastar);
   * con `'if-known'` (`scopes.attached`) un hijo nuevo (`null`) no tiene
   * origen y pasa, y uno ya colgado se trata como un `move`. Solo cuando hay
   * `within` que contrastar: sin él no se consulta el árbol de más.
   */
  async #assertWithinOrigin(
    child: ScopeRef,
    options: ScopedWriteOptions | undefined,
    operation: string,
    presence: 'required' | 'if-known'
  ): Promise<void> {
    const within = this.#requiredWithin(child, options, operation)
    if (!within) return
    const resolver = this.#freshResolver()
    const chain =
      presence === 'required'
        ? await assertKnownScope(resolver, child, operation)
        : await resolveChain(resolver, child, operation)
    if (!chain) return
    this.#assertWithinChain(child, chain, options, operation)
  }

  /** Lo mismo con una cadena ya resuelta (en fresco) por el llamante. */
  #assertWithinChain(scope: ScopeRef, chain: ScopeRef[], options: ScopedWriteOptions | undefined, operation: string): void {
    const within = this.#requiredWithin(scope, options, operation)
    if (!within) return
    if (!chain.some((s) => AuthorizationManager.#sameScope(s, within))) {
      throw new NotWithinError(
        `${operation}: ${scope.type}:${scope.uuid ?? ''} no está dentro de ` +
          `${within.type}:${within.uuid ?? ''} (la cadena es ${chain.map((s) => `${s.type}:${s.uuid ?? ''}`).join(' → ')}); ` +
          `no se escribe fuera del scope declarado.`
      )
    }
  }

  /** El `within` a contrastar, validado y exigido según `requireWithin`; `null` si no hay que contrastar nada. */
  #requiredWithin(scope: ScopeRef, options: ScopedWriteOptions | undefined, operation: string): ScopeRef | null {
    const within = options?.within
    const policy = this.#config.requireWithin
    if (within === undefined) {
      if (policy === true || policy === 'non-root') {
        throw new WithinRequiredError(
          `${operation}: el config exige 'within' (requireWithin: ${JSON.stringify(policy)}) y la escritura sobre ` +
            `${scope.type}:${scope.uuid ?? ''} no lo declara.`
        )
      }
      return null
    }
    assertScope(within)
    if (policy === 'non-root' && within.type === APP_SCOPE_TYPE) {
      throw new WithinRootForbiddenError(
        `${operation}: el config exige un 'within' que acote (requireWithin: 'non-root') y llegó la raíz 'app', ` +
          `que contiene todo. Declara el tenant; la plataforma escribe en la raíz con manager.driver() o con una config sin el flag.`
      )
    }
    return within
  }

  /**
   * La outbox del árbol, si el consumidor la declaró (3b-2d). Con ella,
   * `scopes.attached/moved/detached` NO tocan el driver: encolan el cambio
   * en la transacción del consumidor y lo aplica `authz:scopes:relay`.
   *
   * Por qué no es una recomendación sino un mecanismo (panel 2, cruce 4 ·
   * S5): sin outbox, el paquete escribe en el backend DENTRO de la
   * transacción del consumidor y un `rollback` posterior no lo deshace. El
   * árbol del backend queda adelantado al de la base del consumidor y en
   * modo `facts` eso es una escalada persistente e invisible —el backend es
   * el PDP, y la aplicación lista y audita contra su propia base—.
   *
   * Lo que la outbox NO arregla: el lag del relay. Durante esos segundos el
   * backend decide con el árbol VIEJO, y eso es un **fail-open temporal**
   * (el tenant antiguo conserva acceso tras un `moved`; los denies heredados
   * no aplican tras un `attached`). No hay 2PC.
   */
  #outbox(): ScopeOutbox | undefined {
    return this.#config.scopes?.outbox
  }

  #resolver(operation: string): ScopeChainResolver {
    const resolver = this.#config.scopes?.resolveChain
    if (!resolver) {
      throw new AuthorizationConfigError(
        `${operation} necesita 'scopes.resolveChain' en config/authorization.ts: ` +
          `sin el árbol del consumidor no se puede validar la arista.`
      )
    }
    return resolver
  }

  /**
   * Valida la arista y devuelve la cadena (fresca) del padre y el HIJO
   * CANÓNICO (invariante 17). El hijo canónico se devuelve desde 3b-2d
   * porque la outbox lo encola: lo que se guarda en la cola es la fila del
   * árbol, no lo que escribió el llamante — si no, el relay abriría días
   * después una rama nueva en el store por un alias del uuid.
   */
  async #assertEdge(
    child: ScopeRef,
    parent: ScopeRef,
    operation: string
  ): Promise<{ chain: ScopeRef[]; child: ScopeRef }> {
    const resolver = this.#resolver(operation)
    assertScope(child)
    assertScope(parent)
    if (child.type === APP_SCOPE_TYPE) {
      throw new InvalidIdentityError(`${operation}: la raíz \`app\` no puede colgar de nada`)
    }
    // 422 E_AUTHZ_UNKNOWN_SCOPE si el padre no existe.
    const chain = await assertKnownScope(resolver, parent, operation)
    // El hijo, si el árbol ya lo conoce, con su identidad canónica (K1): un
    // alias del uuid no puede colarse por debajo de la comprobación de ciclo.
    const known = await resolveChain(resolver, child, operation)
    const canonicalChild = known ? known[0] : child
    const childKey = AuthorizationManager.#scopeKey(canonicalChild)
    if (chain.some((s) => AuthorizationManager.#scopeKey(s) === childKey)) {
      throw new ScopeCycleError(
        `${operation}: ${parent.type}:${parent.uuid} desciende de ${childKey.replace('\u001f', ':')} (o es él mismo); ` +
          `colgarlo cerraría un ciclo y la herencia dejaría de ser solo hacia abajo.`
      )
    }
    this.#assertDepth(chain, canonicalChild, parent, operation)
    return { chain, child: canonicalChild }
  }

  /**
   * **El gate de profundidad, opt-in** (2.4.0-alpha.5 · R0; `scopes.maxDepth`).
   * La cadena del padre incluye `app`, así que su longitud ES la profundidad
   * a la que quedaría el hijo (saltos `parent` hasta la raíz): cero I/O de
   * más. Se juzga ANTES de escribir o encolar. PARCIAL a propósito: no ve la
   * altura del subárbol que un `moved` arrastra (ver `define_config.ts`).
   */
  #assertDepth(chain: ScopeRef[], child: ScopeRef, parent: ScopeRef, operation: string): void {
    const maxDepth = this.#config.scopes?.maxDepth
    if (maxDepth === undefined) return
    if (typeof maxDepth !== 'number' || !Number.isInteger(maxDepth) || maxDepth < 1) {
      throw new AuthorizationConfigError(
        `${operation}: scopes.maxDepth debe ser un entero >= 1 (llegó ${String(maxDepth)}); quítalo si no quieres techo.`
      )
    }
    if (chain.length > maxDepth) {
      // El `message` es para el TENANT (2.4.0-alpha.8, cuestión 7.2): sin el
      // nombre del backend ni sus constantes; eso va en `details`, para el log.
      throw new ScopeDepthLimitError(
        `${operation}: colgar ${child.type}:${child.uuid} de ${parent.type}:${parent.uuid ?? ''} lo dejaría a ${chain.length} ` +
          `saltos de la raíz y el techo es scopes.maxDepth=${maxDepth}. No se ha escrito ni encolado nada. Aplana el árbol ` +
          `(o pide al operador que suba el techo).`,
        {
          depth: chain.length,
          maxDepth,
          why: 'el modelo facts del driver openfga no resuelve de forma fiable más allá de FACTS_MAX_RESOLVE_DEPTH: pasado él, authorize es 503 para todo ese subárbol',
          server: 'para subir el techo hay que subir también OPENFGA_RESOLVE_NODE_LIMIT en el servidor',
        }
      )
    }
  }

  // La identidad se valida AQUÍ, antes de resolver siquiera el driver: una
  // pregunta mal formada (uuid ausente, `{app, uuid}`, slug con `~`) es 422
  // sin tocar catálogo, árbol ni backend, y sin que el hook `onWrite` audite
  // una escritura que no ocurrió. Los drivers repiten la misma función por
  // defensa en profundidad (el juez y un driver suelto no pasan por aquí).

  async authorize(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, permission, scope })
    return (await this.#reader()).authorize(subject, permission, scope)
  }

  async hasRole(subject: SubjectRef, role: RoleQuery, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, role, scope })
    return (await this.#reader()).hasRole(subject, role, scope)
  }

  /**
   * `authorize` sobre varios scopes, un booleano por posición (2.1, B6).
   * Delegado al driver si trae `authorizeMany` (openfga: un batchCheck);
   * si no, `Promise.all` de `authorize` sobre una vista con los ancestros
   * memoizados (una llamada al árbol por scope distinto, aunque se repita).
   * Idéntico a N `authorize`: duplicados por posición, desconocido ⇒ false,
   * y si una posición no se puede responder, lanza entero. Vacío ⇒ `[]`
   * sin tocar backend ni árbol.
   */
  async authorizeMany(subject: SubjectRef, permission: string, scopes: ScopeRef[]): Promise<boolean[]> {
    assertIdentity({ subject, permission })
    if (!Array.isArray(scopes)) {
      throw new InvalidIdentityError(`authorizeMany: se esperaba un array de scopes y llegó ${typeof scopes}`)
    }
    for (const scope of scopes) assertIdentity({ scope })
    if (scopes.length === 0) return []
    // Fuera de una vista, la composición abre una propia para que los N
    // scopes compartan el memo de ancestros durante esta llamada.
    const view = this.#readResolver ? this : (this.forRequest() as AuthorizationManager)
    const driver = await view.#reader()
    if (typeof driver.authorizeMany === 'function') {
      const answer: unknown = await driver.authorizeMany(subject, permission, scopes)
      // Un `boolean[]` desalineado se leería por posición (F5, CR3): es un
      // bug del driver, no una decisión. 500 nombrando al culpable.
      if (!Array.isArray(answer) || answer.length !== scopes.length || !everyPositionBoolean(answer)) {
        throw new AuthorizationInternalError(
          `authorizeMany: el driver '${this.#config.default}' devolvió ${describeAnswer(answer)} para ${scopes.length} scopes; ` +
            `el puerto exige un boolean[] con exactamente una posición por scope.`
        )
      }
      return answer as boolean[]
    }
    return Promise.all(scopes.map((scope) => driver.authorize(subject, permission, scope)))
  }

  /** Holders con asignación vigente del rol en ese scope exacto. `{ uuid }` es la forma exacta (3D · M1). */
  async listSubjects(role: RoleQuery, scope: ScopeRef): Promise<SubjectRef[]> {
    assertIdentity({ role, scope })
    return (await this.#reader()).listSubjects(role, scope)
  }

  async listScopes(subject: SubjectRef, permission: string): Promise<ScopeRef[]> {
    assertIdentity({ subject, permission })
    return (await this.#reader()).listScopes(subject, permission)
  }

  async listRoles(subject: SubjectRef, scope: ScopeRef): Promise<string[]> {
    assertIdentity({ subject, scope })
    return (await this.#reader()).listRoles(subject, scope)
  }

  async listRoleScopes(subject: SubjectRef, scopeType: ScopeType): Promise<ScopeRef[]> {
    assertIdentity({ subject, scopeType })
    return (await this.#reader()).listRoleScopes(subject, scopeType)
  }

  /** Denies directos del holder (scope exacto, o todos). 500 `E_AUTHZ_UNSUPPORTED` si el driver no lo implementa. */
  async listDenies(subject: SubjectRef, scope?: ScopeRef): Promise<DenyRef[]> {
    assertIdentity(scope ? { subject, scope } : { subject })
    const driver = await this.#reader()
    return this.#optional(driver, 'listDenies', 'listDenies')(subject, scope)
  }

  /**
   * Permisos efectivos del holder en un scope (2.1, B5): la unión de lo que
   * conceden sus roles vigentes en toda la cadena (`listRoles` por nivel +
   * catálogo) MENOS lo denegado en cualquier nivel de la cadena
   * (`listDenies` por nivel). Es exactamente el conjunto `{ p | authorize(p) }`,
   * calculado sin preguntar permiso a permiso. Scope desconocido ⇒ `[]`.
   * Prerrequisito de `catalog/` (Fase 3).
   */
  async effectivePermissions(subject: SubjectRef, scope: ScopeRef): Promise<string[]> {
    assertIdentity({ subject, scope })
    const driver = await this.#reader()
    this.#optional(driver, 'listDenies', 'effectivePermissions')
    const chain = await resolveChain(this.#readResolverOrFresh(), scope, 'effectivePermissions')
    if (!chain) return []
    const catalog = await this.#catalogFor(driver).view()
    const { granted } = await this.#rolesAlong(driver, subject, chain, catalog)
    const denied = await this.#deniedAlong(driver, subject, chain, 'effectivePermissions')
    return [...granted].filter((permission) => !denied.has(permission))
  }

  /**
   * Lo que los roles VIGENTES del holder conceden a lo largo de una cadena
   * (ya resuelta), y el rank más alto entre ellos (3B · B3). Roles de toda la
   * cadena en UNA lectura (`rolesInChain`, G5) o, sin el método opcional, N
   * `listRoles`.
   *
   * **Por UUID, nunca por slug (3D · M1).** `rolesInChain` devuelve
   * `CatalogRoleRef`, así que aquí se lee el rol EXACTO que el holder tiene
   * y sus permisos por uuid. El ida y vuelta por slug —resolver otra vez con
   * `roleVisible`— atribuía al holder los permisos de un homónimo: el
   * auditor lo llevó hasta una escalada completa (V1, `effectivePermissions`
   * decía `billing:write` mientras `authorize` decía `false`, y
   * `defineScopedRole` delegaba lo que el actor no tenía). Se conserva la
   * defensa en profundidad: el rol tiene que seguir en el catálogo,
   * declarado para el nivel de la asignación y visible desde ese nivel.
   *
   * Un driver de terceros sin `rolesInChain` solo sabe hablar en slugs: la
   * composición pasa por `roleVisible`, que desde M1 falla CERRADA (422
   * `E_AUTHZ_AMBIGUOUS_ROLE`) si hay homónimos visibles. Nunca elige uno.
   */
  async #rolesAlong(
    driver: AuthorizationDriver,
    subject: SubjectRef,
    chain: ScopeRef[],
    catalog: CatalogView
  ): Promise<{ granted: Set<string>; rank: number }> {
    const keysFrom = chainKeysFrom(chain)
    const levelIndex = new Map(chain.map((s, i) => [scopeKey(s), i]))
    const roles: Array<{ scope: ScopeRef; role: CatalogRoleRef | null }> =
      typeof driver.rolesInChain === 'function'
        ? await driver.rolesInChain(subject, chain)
        : await this.#rolesFromSlugs(driver, subject, chain, keysFrom, catalog)
    const granted = new Set<string>()
    let rank = 0
    for (const { scope: level, role } of roles) {
      if (!role) continue
      const index = levelIndex.get(scopeKey(level))
      if (index === undefined) continue
      const declared = catalog.roleByUuid(role.uuid)
      if (!declared || declared.scopeType !== level.type) continue
      if (!isRoleVisibleWith(declared, keysFrom[index])) continue
      if (declared.rank > rank) rank = declared.rank
      for (const permission of catalog.rolePermissionsOf(declared.uuid)) granted.add(permission)
    }
    return { granted, rank }
  }

  /**
   * La composición por defecto de `#rolesAlong` cuando el driver NO trae
   * `rolesInChain` (opcional en el puerto): `listRoles` devuelve slugs y hay
   * que volver del slug al catálogo. Es el camino de un driver de terceros
   * escrito para 2.0/2.1, y hasta 3E tenía dos defectos (tester 3D · R3):
   *
   *  - usaba `roleVisible`, que desde M1 LANZA 422 `E_AUTHZ_AMBIGUOUS_ROLE`
   *    con dos homónimos visibles: `effectivePermissions` —una LECTURA que
   *    promete una lista— explotaba con un 422 en cuanto un `scopes.moved`
   *    legítimo juntaba dos roles del mismo nombre;
   *  - y elegir uno sería la escalada del auditor V1 (atribuir al holder los
   *    permisos del homónimo que NO tiene).
   *
   * La salida es no elegir NI adivinar: con homónimos visibles se pregunta
   * al driver por `{ uuid }` —resolución exacta, parte del puerto desde 3D ·
   * M1— cuál tiene de verdad. Cuesta una consulta más por slug ambiguo (que
   * es deriva y el diff la reporta), y solo en drivers sin `rolesInChain`.
   */
  async #rolesFromSlugs(
    driver: AuthorizationDriver,
    subject: SubjectRef,
    chain: ScopeRef[],
    keysFrom: string[][],
    catalog: CatalogView
  ): Promise<Array<{ scope: ScopeRef; role: CatalogRoleRef | null }>> {
    const roles: Array<{ scope: ScopeRef; role: CatalogRoleRef | null }> = []
    for (const [index, level] of chain.entries()) {
      for (const slug of await driver.listRoles(subject, level)) {
        const visible = catalog.rolesNamed(slug, level.type).filter((role) => isRoleVisibleWith(role, keysFrom[index]))
        if (visible.length === 1) {
          roles.push({ scope: level, role: visible[0] })
          continue
        }
        for (const role of visible) {
          if (await driver.hasRole(subject, { uuid: role.uuid }, level)) roles.push({ scope: level, role })
        }
      }
    }
    return roles
  }

  /**
   * El/los rol(es) a los que apunta un `RoleQuery` en un scope, para el
   * EVENTO de auditoría (3E · Q7). Best-effort a propósito: NUNCA cambia el
   * resultado de la escritura —lo que decide es el driver, con su catálogo y
   * su árbol—, solo enriquece lo que se notifica. Si algo no cuadra (scope
   * que el árbol no conoce, rol fuera del catálogo, ambigüedad en un grant)
   * el evento sale sin `roles` y el driver dirá lo que corresponda.
   *
   * Solo se calcula si hay un `onWrite` que lo vaya a leer: sin hook no
   * cuesta ni una consulta.
   */
  async #resolvedRoles(role: RoleQuery, scope: ScopeRef, operation: 'grant' | 'revoke'): Promise<CatalogRoleRef[] | undefined> {
    if (!this.#config.hooks?.onWrite) return undefined
    try {
      const driver = await this.driver()
      const chain = await resolveChain(this.#freshResolver(), scope, operation)
      if (!chain) return undefined
      const catalog = await this.#catalogFor(driver).view()
      const target = chain[0]
      const keys = chainKeysFrom(chain)[0]
      const query = normalizeRoleQuery(role)
      if (query.uuid !== undefined) {
        const declared = catalog.roleByUuid(query.uuid)
        if (!declared || declared.scopeType !== target.type || !isRoleVisibleWith(declared, keys)) return undefined
        return [declared]
      }
      if (query.scopeType !== undefined && query.scopeType !== target.type) return undefined
      const visible = catalog.rolesNamed(query.slug, target.type).filter((r) => isRoleVisibleWith(r, keys))
      if (visible.length === 0) return undefined
      // Un `revoke` por slug quita los hechos de TODOS los homónimos del
      // scope, así que el evento los lleva todos; un `grant` ambiguo no
      // llega a escribir (422), y el evento no elige por él.
      return operation === 'revoke' || visible.length === 1 ? visible : undefined
    } catch {
      return undefined
    }
  }

  /** Permisos DENEGADOS al holder en algún scope de la cadena: `listDenies` en UNA lectura (500 `E_AUTHZ_UNSUPPORTED` sin él). */
  async #deniedAlong(driver: AuthorizationDriver, subject: SubjectRef, chain: ScopeRef[], primitive: string): Promise<Set<string>> {
    const listDenies = this.#optional(driver, 'listDenies', primitive)
    const key = AuthorizationManager.#scopeKey
    const chainKeys = new Set(chain.map(key))
    const denied = new Set<string>()
    for (const deny of await listDenies(subject)) {
      if (chainKeys.has(key(deny.scope))) denied.add(deny.permission)
    }
    return denied
  }

  // ── Roles locales a un scope (3B · B3): la API de DELEGACIÓN ─────────
  // Un administrador de un scope (el actor) define roles que solo existen
  // dentro de ese scope (owner) con permisos que él mismo tiene efectivos
  // ahí y que la plataforma declaró delegables, por debajo de su rank. Es
  // policy de ESCRITURA (composición): `authorize` no cambia (invariantes
  // 1, 2, 8). Todo se resuelve en FRESCO (auditor C3): una vista de
  // `forRequest` con la cadena vieja no puede delegar en una unit que ya
  // cambió de tenant. Escribe con `withAuthzCatalogWrite`: la versión
  // compartida sube como última sentencia y los demás procesos ven el rol
  // en su siguiente pregunta (B7).

  /**
   * Define un rol LOCAL a `ownerScope`. Policy, en este orden y antes de
   * escribir nada: `actor` obligatorio y bien formado; `ownerScope` válido,
   * no la raíz (los roles de la raíz son globales: config + sync) y conocido
   * por el árbol (fresco); `spec` bien formado (slug, nivel ≠ `app`, rank
   * entero, permisos); cada permiso en `config.delegablePermissions`, en el
   * catálogo, componible en ese nivel (`assignableAt`, B5) y EFECTIVO para
   * el actor en el owner (lo concede un rol suyo de la cadena y no lo tiene
   * denegado en ella — C2); `0 < rank < min(rank del actor, rank máximo
   * global)`; y ningún rol `(slug, scopeType)` visible en el owner (global,
   * o local a un ancestro) ni local a un descendiente (colisión, 422
   * `E_AUTHZ_CATALOG_CONFLICT`, re-comprobada dentro de la transacción
   * serializada — 3D · M2). `options.within` contiene la escritura contra el
   * OWNER y `requireWithin` la exige, como en las otras ocho (3D · M3).
   * Devuelve el rol y notifica `role_defined`.
   */
  async defineScopedRole(
    actor: SubjectRef,
    ownerScope: ScopeRef,
    spec: ScopedRoleSpec,
    options?: ScopedWriteOptions
  ): Promise<CatalogRole> {
    this.#assertNoTransaction(options, 'defineScopedRole')
    const who = await this.#requireActor(actor, 'defineScopedRole')
    this.#assertOwnerScope(ownerScope, 'defineScopedRole')
    const parsed = this.#parseScopedRoleSpec(spec)
    const driver = await this.driver()
    // 3E · P4 (code-review): un rol local que este driver no sabrá purgar es
    // estado que NADA puede borrar — `deleteScopedRole` responde 500 y
    // `scopes.detached` de ese scope (y de cualquier ancestro que lo
    // arrastre) queda muerto para siempre, hechos incluidos. Se dice ANTES
    // de crear nada, no al intentar deshacerlo.
    this.#optional(
      driver,
      'purgeRole',
      'defineScopedRole',
      'Los roles locales a un scope necesitan poder purgarse; en el driver openfga llegan con el modo `facts` (fase 3b).'
    )
    const chain = await assertKnownScope(this.#freshResolver(), ownerScope, 'defineScopedRole')
    // Contención (3D · M3, auditor V4): es la SÉPTIMA escritura y hasta 3C no
    // la cubría `requireWithin`, así que un holder con un rol en la RAÍZ
    // creaba roles dentro de cualquier tenant (squatting de slugs incluido)
    // con el `ownerScope` que le llegara en el cuerpo de la petición. La
    // cadena ya está resuelta en fresco: se contrasta contra ella.
    this.#assertWithinChain(ownerScope, chain, options, 'defineScopedRole')
    const owner = chain[0]
    const ownerKey = scopeKey(owner)
    const catalog = await this.#catalogFor(driver).view()
    // Composición y lista blanca antes de leer hechos: lo barato primero.
    this.#assertComposable(parsed.permissions, parsed, catalog)
    await this.#assertLevelUnderOwner(parsed.scopeType, chain, 'defineScopedRole')
    const { granted, rank: actorRank } = await this.#rolesAlong(driver, who, chain, catalog)
    const denied = await this.#deniedAlong(driver, who, chain, 'defineScopedRole')
    this.#assertDelegable(parsed.permissions, granted, denied, owner)
    this.#assertRank(parsed.rank, actorRank, catalog.topGlobalRank)
    const shadowedByAncestor = await this.#assertNoRoleCollision(parsed.slug, parsed.scopeType, owner, chain, catalog.rolesNamed(parsed.slug, parsed.scopeType))
    this.#assertAboveShadowed(actorRank, shadowedByAncestor, 'defineScopedRole')

    const uuid = uuidv7()
    const permissionUuids = parsed.permissions.map((slug) => catalog.permission(slug)!.uuid)
    await this.#writeCatalog(async (trx) => {
      // La colisión, OTRA VEZ, dentro de la transacción SERIALIZADA (M2) y
      // contra la BASE: entre el chequeo de arriba y este hubo un
      // `resolveChain` y dos lecturas al driver —cientos de ms con un árbol
      // SQL— y el memo no ve lo que otro proceso confirmó en esa ventana.
      const rows: any[] = await trx
        .from('authz_roles')
        .where('slug', parsed.slug)
        .where('scope_type', parsed.scopeType)
        .select('owner_scope_key')
      const known = new Set(catalog.rolesNamed(parsed.slug, parsed.scopeType).map((r) => r.owner))
      const fresh = [...new Set(rows.map((r) => String(r.owner_scope_key)).filter((o) => !known.has(o)))]
      if (fresh.length) {
        // Los homónimos que el memo no tenía son de una escritura confirmada
        // mientras validábamos. Los que se pueden juzgar SIN salir de la
        // transacción (global, o un ancestro-o-igual del owner: la cadena ya
        // está resuelta) dan el 422 preciso; el resto se rechaza igual —
        // resolver su cadena aquí dentro pediría otra conexión mientras se
        // sostiene el cerrojo del catálogo (con un pool de 1, un abrazo
        // mortal). Reintentar es correcto: el memo ya está invalidado y el
        // segundo intento valida con la foto buena.
        await this.#assertNoRoleCollision(parsed.slug, parsed.scopeType, owner, chain, fresh.map((o) => ({ owner: o })), 'sin-árbol')
        throw new CatalogConflictError(
          `El catálogo cambió mientras se validaba '${parsed.slug}@${parsed.scopeType}': apareció un rol con ese nombre ` +
            `(owner ${fresh.join(', ')}) que no estaba en la foto con la que se comprobaron las colisiones. ` +
            `No se escribe a ciegas; reintenta la operación.`
        )
      }
      const now = systemClock()
      await trx.table('authz_roles').insert({
        uuid,
        slug: parsed.slug,
        name: parsed.name,
        description: parsed.description,
        scope_type: parsed.scopeType,
        rank: parsed.rank,
        owner_scope_key: ownerKey,
        created_at: now,
        updated_at: now,
      })
      for (const permissionUuid of permissionUuids) {
        await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: uuid, permission_uuid: permissionUuid, created_at: now })
      }
    })
    const role: CatalogRole = Object.freeze({ uuid, slug: parsed.slug, scopeType: parsed.scopeType, owner: ownerKey, rank: parsed.rank })
    // La proyección derivada del driver, si la tiene (3b-2e · E4): en el modo
    // `facts` lo que un rol concede son TUPLAS, así que un rol definido sin
    // proyectar no concedería nada — un no-op silencioso. Va después del
    // commit del catálogo y antes de notificar.
    await driver.projectCatalogRole?.(uuid)
    await this.#notifyCatalog({
      action: 'role_defined',
      actor: who,
      role,
      owner,
      permissions: [...parsed.permissions].sort(),
      ...(shadowedByAncestor.length ? { shadowedByAncestor } : {}),
    })
    return role
  }

  /**
   * Cambia `name`/`description`/`rank`/`permissions` de un rol LOCAL (nunca
   * su slug, nivel ni owner). Un global es 422 `E_AUTHZ_ROLE_IMMUTABLE`. El
   * actor tiene que tener, en el owner del rol, rank MAYOR que el del rol
   * (no se toca un rol de rango ≥ al propio) y la misma policy que al
   * definir para lo que cambia: los permisos nuevos delegables/efectivos y
   * componibles, el rank nuevo por debajo del suyo. Sin cambios reales no
   * escribe ni notifica (idempotente). Notifica `role_updated`.
   */
  async updateScopedRole(
    actor: SubjectRef,
    roleUuid: string,
    changes: ScopedRoleChanges,
    options?: ScopedWriteOptions
  ): Promise<CatalogRole> {
    this.#assertNoTransaction(options, 'updateScopedRole')
    const who = await this.#requireActor(actor, 'updateScopedRole')
    assertCatalogUuid('rol', roleUuid)
    const parsed = this.#parseScopedRoleChanges(changes)
    const driver = await this.driver()
    const catalog = await this.#catalogFor(driver).view()
    const role = this.#localRoleOrFail(catalog, roleUuid)
    const owner = this.#ownerOf(role)
    const chain = await assertKnownScope(this.#freshResolver(), owner, 'updateScopedRole')
    // El scope contrastado es el OWNER del rol (3D · M3): editar un rol es
    // escribir dentro de su contenedor.
    this.#assertWithinChain(owner, chain, options, 'updateScopedRole')
    const current = [...catalog.rolePermissionsOf(role.uuid)].sort()
    const next = {
      name: parsed.name ?? null,
      description: parsed.description,
      rank: parsed.rank ?? role.rank,
      permissions: parsed.permissions ?? current,
    }
    if (parsed.permissions) this.#assertComposable(parsed.permissions, role, catalog)
    // 3E · P1: el nivel no cambia por esta API, pero un rol cuyo nivel está
    // POR ENCIMA de su owner (creado antes de 3E o a mano) no se perpetúa:
    // es una mina de slug y lo que toca es purgarlo, no editarlo.
    await this.#assertLevelUnderOwner(role.scopeType, chain, 'updateScopedRole')
    const { granted, rank: actorRank } = await this.#rolesAlong(driver, who, chain, catalog)
    this.#assertAboveRole(actorRank, role)
    // 3G · W3: este rol puede estar ENSOMBRECIENDO al homónimo de un
    // descendiente (3F · S3). Cambiarle rank o permisos es seguir ejerciendo
    // esa autoridad, así que exige lo mismo que crearlo: superarlo en rango.
    this.#assertAboveShadowed(
      actorRank,
      await this.#shadowedBelow(
        scopeKey(owner),
        new Set(chain.map(scopeKey)),
        catalog.rolesNamed(role.slug, role.scopeType).filter((other) => other.uuid !== role.uuid),
        'updateScopedRole'
      ),
      'updateScopedRole'
    )
    if (parsed.permissions) {
      const denied = await this.#deniedAlong(driver, who, chain, 'updateScopedRole')
      this.#assertDelegable(parsed.permissions, granted, denied, owner)
    }
    if (parsed.rank !== undefined) this.#assertRank(parsed.rank, actorRank, catalog.topGlobalRank)

    const nextPermissions = [...next.permissions].sort()
    const permissionsChanged = nextPermissions.join('\u001f') !== current.join('\u001f')
    const wanted = new Set(nextPermissions.map((slug) => catalog.permission(slug)!.uuid))
    const changed = await this.#writeCatalog(async (trx) => {
      const row: any = (await trx.from('authz_roles').where('uuid', role.uuid).select('name', 'description', 'rank'))[0]
      if (!row) throw new UnknownRoleError(role.uuid)
      const patch: Record<string, unknown> = {}
      if (next.name !== null && next.name !== row.name) patch.name = next.name
      if (next.description !== undefined && (next.description ?? null) !== (row.description ?? null)) patch.description = next.description
      if (next.rank !== Number(row.rank)) patch.rank = next.rank
      let touched = false
      if (Object.keys(patch).length) {
        await trx.from('authz_roles').where('uuid', role.uuid).update({ ...patch, updated_at: systemClock() })
        touched = true
      }
      if (permissionsChanged) {
        const links: any[] = await trx.from('authz_role_permissions').where('role_uuid', role.uuid).select('uuid', 'permission_uuid')
        const linked = new Set(links.map((l) => l.permission_uuid as string))
        const stale = links.filter((l) => !wanted.has(l.permission_uuid))
        if (stale.length) {
          await trx
            .from('authz_role_permissions')
            .whereIn(
              'uuid',
              stale.map((l) => l.uuid)
            )
            .delete()
        }
        for (const permissionUuid of wanted) {
          if (linked.has(permissionUuid)) continue
          await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: role.uuid, permission_uuid: permissionUuid, created_at: systemClock() })
        }
        touched = true
      }
      return touched
    }, { skipIfNoop: true })
    const updated: CatalogRole = Object.freeze({ ...role, rank: next.rank })
    // 3b-2e · E4: quitarle un permiso a un rol tiene que dejar de conceder
    // también en el driver que proyecta el catálogo como tuplas. Sin esto la
    // tupla `permits_<P>` sobrevive al vínculo y el rol sigue concediendo lo
    // que ya no vincula: fail-open.
    if (changed && permissionsChanged) await driver.projectCatalogRole?.(role.uuid)
    if (changed) await this.#notifyCatalog({ action: 'role_updated', actor: who, role: updated, owner, permissions: nextPermissions })
    return updated
  }

  /**
   * Purga un rol LOCAL: sus asignaciones en todos los scopes, sus vínculos y
   * el rol (`driver.purgeRole`, B4; 500 `E_AUTHZ_UNSUPPORTED` en un driver
   * que no lo trae, sin tocar nada). Un global es 422
   * `E_AUTHZ_ROLE_IMMUTABLE`; el actor necesita rank MAYOR que el del rol en
   * su owner. Notifica `role_purged`. No necesita `listDenies`.
   */
  async deleteScopedRole(actor: SubjectRef, roleUuid: string, options?: ScopedWriteOptions): Promise<void> {
    this.#assertNoTransaction(options, 'deleteScopedRole')
    const who = await this.#requireActor(actor, 'deleteScopedRole')
    assertCatalogUuid('rol', roleUuid)
    const driver = await this.driver()
    const purgeRole = this.#optional(driver, 'purgeRole', 'deleteScopedRole')
    const catalog = await this.#catalogFor(driver).view()
    const role = this.#localRoleOrFail(catalog, roleUuid)
    const owner = this.#ownerOf(role)
    const chain = await assertKnownScope(this.#freshResolver(), owner, 'deleteScopedRole')
    this.#assertWithinChain(owner, chain, options, 'deleteScopedRole')
    const { rank: actorRank } = await this.#rolesAlong(driver, who, chain, catalog)
    this.#assertAboveRole(actorRank, role)
    const permissions = [...catalog.rolePermissionsOf(role.uuid)].sort()
    try {
      await purgeRole(role.uuid)
    } finally {
      invalidateAuthzCatalog()
    }
    await this.#notifyCatalog({ action: 'role_purged', actor: who, role, owner, permissions })
  }

  /**
   * Los roles LOCALES cuyo owner el árbol YA NO conoce, y —con `force`— su
   * purga. Es el motor de `authz:catalog:prune-orphans` (3b-0 · Z2).
   *
   * Un rol así está DORMIDO, y «dormido» significa **exactamente** esto
   * (3b-0b · AA1, auditor 3b-0): no es visible desde ningún scope vivo cuya
   * cadena NO pase por su owner. No significa que no conceda. La regla única
   * de visibilidad (invariante 18) pide que el owner esté en la cadena del
   * scope preguntado, y **un descendiente vivo cuya ruta materializada sigue
   * pasando por el owner la cumple**: ahí el rol concede, es membresía por
   * los seis caminos de lectura y se puede ASIGNAR, por slug y por uuid.
   * Ocurre en cuanto el consumidor borra la fila del owner sin borrar (o sin
   * notificar) la de sus descendientes — el borrado en dos pasos y las rutas
   * materializadas son lo normal. Por eso este barrido es destructivo de
   * verdad y por eso `--dry-run` es el default: puede estar revocando
   * permisos VIVOS, no recogiendo basura inerte. Lo que sí es seguro decir:
   * un rol huérfano SIN asignaciones vigentes no concede nada, y ninguno
   * concede en un scope cuya cadena no pase por el owner.
   *
   * Cada huérfano viene con `assignments` (hechos vigentes) y
   * `stillGranting` (`assignments > 0`), que es la marca CONSERVADORA de
   * «esto no es basura inerte»: cuenta hechos, no comprueba si el scope de
   * cada uno sigue resolviendo. Falso ⇒ no concede seguro; verdadero ⇒
   * míralo antes de `--force`.
   *
   * **Y esos hechos se los cuenta el DRIVER** (3b-2j, decisión del dueño del
   * 2026-08-31 (3)), con `countRoleAssignments` del puerto. Hasta aquí los
   * contaba el propio barrido en `authz_assignments` —la tabla del driver
   * `database`—, así que con `openfga` en modo `facts`, donde los hechos
   * viven en el store, `stillGranting` era SIEMPRE `false`: el barrido
   * declaraba basura inerte, justo antes de un borrado destructivo, un rol
   * que estaba concediendo (medido en el lote 2i). Un driver que no traiga
   * el método deja los DOS campos en **`undefined`**, nunca en `false`: «no
   * lo sé» no puede degradar a «no concede», que es exactamente el bug. Con
   * `undefined` el rol no es demostrablemente inerte y el comando lo lista
   * APARTE, igual que a los que sí conceden.
   *
   * Lo que el rol dormido sí hace en todo caso es ocupar su `(slug, nivel)`
   * dentro del subárbol donde todavía se le vea, y `deleteScopedRole` no lo
   * alcanza (resuelve el owner en fresco y responde 422
   * `E_AUTHZ_UNKNOWN_SCOPE`). Hasta 3G esa limpieza la arrastraba
   * `scopes.detached`, y ahí es donde nacieron tres de las cuatro
   * regresiones de la Fase 3: la operación la dispara un TENANT, sobre un
   * scope que ya no resuelve, así que hubo que inventarle una policy de
   * rango sin cadena donde medirla, una enumeración del subárbol y una
   * degradación — tres piezas que compuestas destruían roles de
   * descendientes VIVOS. Aquí no hay nada de eso: es una operación de
   * PLATAFORMA (una tarea de mantenimiento con acceso al catálogo, como
   * `authz:catalog:sync`), no lleva actor y no mide rangos, exactamente como
   * el `purgeRole` de último recurso que el README ya prometía. Es, junto a
   * `driver()`, **API de plataforma**: se salta `requireActor` y
   * `requireWithin` a propósito, así que no se expone a un controlador.
   *
   * `force: false` (el default, y el del comando: `--dry-run`) NO escribe:
   * devuelve la lista para que un humano la mire. Con `force: true` cada rol
   * se purga con `purgeRole` —atómico: asignaciones + vínculos + fila +
   * versión del catálogo— y se notifica `role_purged` (sin `actor`). El
   * conjunto no es atómico, y por eso el reporte dice QUÉ se purgó
   * (`purged: CatalogRoleRef[]`, 3b-0b · AB3) y no cuántos: si un
   * `purgeRole` falla a mitad, lo anterior ya está borrado —con el hallazgo
   * de AA1 eso puede ser revocación parcial de permisos vivos— y quien
   * recoge el 503 necesita la lista, no un contador. Una pasada
   * interrumpida la recoge la siguiente (el orden es estable por uuid).
   *
   * **Dos seguros contra el barrido a ciegas**, que es el riesgo real
   * (auditor 3b-0):
   *
   *  - **Cota de purga masiva** (AA2): si TODOS los owners distintos
   *    resultan huérfanos, o si los huérfanos superan el 50 % de los roles
   *    locales, `force` es 500 `E_AUTHZ_MASS_PURGE_REFUSED` **antes de
   *    borrar nada**. Esa es la firma de un `resolveChain` filtrado por el
   *    tenant de la petición o corriendo sin contexto (comando, réplica
   *    atrasada): devuelve `null` para todo y la pasada se lleva el catálogo
   *    local de TODOS los tenants (medido: 2 de 2 roles vivos). Una poda
   *    grande de verdad pasa con `allowMassPurge: true`
   *    (`--allow-mass-purge`), que es una decisión humana. El `--dry-run` no
   *    lanza —es justo el diagnóstico que hay que poder mirar— pero lo
   *    marca en `massPurge`.
   *  - **Re-resolución justo antes de cada purga** (AA3): entre la lectura y
   *    el borrado cabe un `scopes.attached`/restore concurrente, y la
   *    ventana es TODA la pasada (N roles + N `resolveChain`), no un
   *    instante. Cada owner se vuelve a resolver en FRESCO inmediatamente
   *    antes de su `purgeRole`; si ha vuelto, el rol se salta y se cuenta en
   *    `skipped` con `reason: 'owner-came-back'`.
   *
   * Coste: una lectura del catálogo local + un `resolveChain` por OWNER
   * DISTINTO (memoizado) + UNA llamada a `countRoleAssignments` con los
   * uuids de los huérfanos (ninguna si no hay) + un `resolveChain` más por
   * rol purgado (el de AA3). Es O(owners con roles locales) para mirar y
   * O(roles purgados) para borrar, y corre en un comando, no en el camino de
   * una petición.
   */
  async pruneOrphanRoles(options: { force?: boolean; allowMassPurge?: boolean } = {}): Promise<{
    orphans: Array<{ role: CatalogRole; owner: ScopeRef; permissions: string[]; assignments: number | undefined; stillGranting: boolean | undefined }>
    purged: CatalogRoleRef[]
    skipped: Array<{ role: CatalogRoleRef; reason: 'owner-came-back' }>
    /** ¿La pasada tiene la firma de un resolutor ciego? Con `force` exige `allowMassPurge`. */
    massPurge: boolean
    dryRun: boolean
  }> {
    const force = options.force === true
    this.#resolver('authz:catalog:prune-orphans')
    const driver = await this.driver()
    // Antes de leer nada: un driver que no sabe purgar lo dice, no se
    // descubre a mitad de la pasada (3E · P4). Y antes que la barrera del
    // freeze (3b-7): «no sé purgar» es permanente y se dice sin consultar
    // NADA (la promesa medida en 3b-1); «estás congelado» es transitorio.
    const purgeRole = this.#optional(driver, 'purgeRole', 'pruneOrphanRoles')
    if (force) await this.#assertNotFrozen('authz:catalog:prune-orphans')
    const resolver = this.#freshResolver()
    const locals = await readLocalRoles({ driver: this.#config.default })
    const resolved = new Map<string, boolean>()
    const orphans: Array<{ role: CatalogRole; owner: ScopeRef; permissions: string[]; assignments: number | undefined; stillGranting: boolean | undefined }> = []
    for (const { role, permissions } of locals) {
      const owner = this.#ownerOf(role)
      if (!resolved.has(role.owner)) {
        resolved.set(role.owner, (await resolveChain(resolver, owner, 'pruneOrphanRoles')) !== null)
      }
      if (resolved.get(role.owner)) continue
      orphans.push({ role, owner, permissions, assignments: undefined, stillGranting: undefined })
    }
    // Los hechos son del DRIVER, no de una tabla (3b-2j). Sin el método del
    // puerto los dos campos se quedan en `undefined`: el barrido no lo sabe y
    // lo dice, en vez de degradar a «no concede».
    if (orphans.length > 0 && typeof driver.countRoleAssignments === 'function') {
      const counts = await driver.countRoleAssignments(orphans.map(({ role }) => role.uuid))
      if (!Array.isArray(counts) || counts.length !== orphans.length) {
        throw new AuthorizationInternalError(
          `countRoleAssignments: el driver '${this.#config.default}' respondió ${Array.isArray(counts) ? counts.length : typeof counts} ` +
            `valor(es) para ${orphans.length} rol(es). La respuesta es POR POSICIÓN y esto se lee antes de borrar: no se ` +
            `adivina cuál era de quién.`
        )
      }
      counts.forEach((total, i) => {
        if (!Number.isInteger(total) || total < 0) {
          throw new AuthorizationInternalError(
            `countRoleAssignments: el driver '${this.#config.default}' respondió '${total}' para el rol ` +
              `'${orphans[i].role.slug}' (${orphans[i].role.uuid}); se espera un entero ≥ 0.`
          )
        }
        orphans[i].assignments = total
        orphans[i].stillGranting = total > 0
      })
    }
    const owners = new Set(locals.map(({ role }) => role.owner))
    const orphanOwners = new Set(orphans.map(({ role }) => role.owner))
    const massPurge =
      orphans.length > 0 && (orphanOwners.size === owners.size || orphans.length * 2 > locals.length)
    if (!force) return { orphans, purged: [], skipped: [], massPurge, dryRun: true }
    if (massPurge && options.allowMassPurge !== true) {
      throw new MassPurgeRefusedError(
        `pruneOrphanRoles: ${orphans.length} de ${locals.length} roles locales (${orphanOwners.size} de ${owners.size} ` +
          `owners distintos) tienen el owner fuera del árbol. Esa es la firma de un 'scopes.resolveChain' ciego —filtrado ` +
          `por el tenant de la petición, o sin contexto— que devuelve null para todo: una pasada así borra el catálogo ` +
          `local de todos los tenants. No se ha borrado nada. Comprueba el resolutor y, si la poda es real, repite con ` +
          `allowMassPurge: true (--allow-mass-purge).`
      )
    }
    const purged: CatalogRoleRef[] = []
    const skipped: Array<{ role: CatalogRoleRef; reason: 'owner-came-back' }> = []
    for (const { role, owner, permissions } of orphans) {
      // AA3: la ventana entre leer y borrar es toda la pasada. El owner se
      // vuelve a resolver EN FRESCO aquí mismo; si ha vuelto (un
      // `scopes.attached`, un restore, una réplica que se pone al día) este
      // rol ya no es huérfano y no se toca.
      if ((await resolveChain(this.#freshResolver(), owner, 'pruneOrphanRoles')) !== null) {
        skipped.push({ role, reason: 'owner-came-back' })
        continue
      }
      try {
        // 3b-8 · B3 (mismo patrón que el relay): la ventana de la pasada es
        // larga (N roles × resolveChain) y la mirada única de la entrada
        // dejaba purgas destructivas DESPUÉS de un freeze adquirido a mitad.
        // Se re-afirma por rol, ANTES de cada borrado; el 503 sale envuelto
        // en PruneInterruptedError para que viaje la lista de lo YA purgado.
        await this.#assertNotFrozen('authz:catalog:prune-orphans')
        await purgeRole(role.uuid)
      } catch (error) {
        // La purga no es transaccional ENTRE roles: lo ya borrado está
        // borrado. El valor de retorno no llega a producirse, así que la
        // lista viaja en el error (tester 3b-1 §6.2) y el del driver va como
        // `cause`: la abstracción no filtra.
        throw new PruneInterruptedError(
          `pruneOrphanRoles: '${role.slug}' (nivel '${role.scopeType}') no se pudo purgar. ` +
            `Los ${purged.length} rol(es) anteriores YA están borrados y no se deshacen; el resto sigue vivo. ` +
            `La lista de lo purgado va en 'error.purged' y también en los eventos 'role_purged' ya emitidos; ` +
            `la siguiente pasada recoge lo que queda.`,
          purged,
          skipped,
          { cause: error }
        )
      } finally {
        invalidateAuthzCatalog()
      }
      purged.push(role)
      await this.#notifyCatalog({ action: 'role_purged', role, owner, permissions })
    }
    return { orphans, purged, skipped, massPurge, dryRun: false }
  }

  /** El actor de la API de delegación: obligatorio SIEMPRE (sin él no hay policy que evaluar) y bien formado. */
  async #requireActor(actor: SubjectRef | undefined, operation: string): Promise<SubjectRef> {
    await this.#assertNotFrozen(operation)
    if (actor === undefined || actor === null) {
      throw new ActorRequiredError(`${operation}: el actor es obligatorio (es quien delega; sin él no hay policy que evaluar).`)
    }
    assertSubject(actor)
    return actor
  }

  /** El owner de un rol local: un scope válido que no sea la raíz (sus roles son globales y se declaran en el config). */
  #assertOwnerScope(ownerScope: ScopeRef, operation: string): void {
    assertScope(ownerScope)
    if (ownerScope.type === APP_SCOPE_TYPE) {
      throw new InvalidIdentityError(
        `${operation}: la raíz 'app' no puede ser owner de un rol local; los roles de la raíz son globales y se declaran ` +
          `en el catálogo del config (syncAuthzCatalog).`
      )
    }
  }

  #parseScopedRoleSpec(spec: ScopedRoleSpec): { slug: string; scopeType: ScopeType; name: string; description: string | null; rank: number; permissions: string[] } {
    if (!spec || typeof spec !== 'object') throw new InvalidIdentityError(`Spec de rol local inválido: llegó ${spec === null ? 'null' : typeof spec}`)
    assertValidSlug('rol', spec.slug)
    assertScopeType(spec.scopeType)
    if (spec.scopeType === APP_SCOPE_TYPE) {
      throw new InvalidIdentityError(`Spec de rol local inválido: un rol local no puede ser de nivel 'app' (la raíz no está dentro de ningún owner).`)
    }
    const rank = this.#parseRank(spec.rank)
    if (rank === undefined) throw new InvalidIdentityError(`Spec de rol local inválido: 'rank' es obligatorio (entero).`)
    const name = this.#parseName(spec.name) ?? spec.slug
    const description = this.#parseDescription(spec.description) ?? null
    const permissions = this.#parsePermissions(spec.permissions)
    // 3D · N3 (auditor V7): un rol sin permisos no concede nada y ocupa el
    // `(slug, nivel)` del owner —y del subárbol— para siempre. Es squatting
    // con forma de spec: 422.
    if (permissions.length === 0) {
      throw new InvalidIdentityError(
        `Spec de rol local inválido: 'permissions' está vacío. Un rol que no concede nada solo ocupa el ` +
          `(slug, nivel) de su owner; si lo que quieres es reservarlo, hazlo con un permiso real.`
      )
    }
    return { slug: spec.slug, scopeType: spec.scopeType, name, description, rank, permissions }
  }

  #parseScopedRoleChanges(changes: ScopedRoleChanges): { name?: string; description?: string | null; rank?: number; permissions?: string[] } {
    if (!changes || typeof changes !== 'object') throw new InvalidIdentityError(`Cambios de rol local inválidos: llegó ${changes === null ? 'null' : typeof changes}`)
    // 3D · N2 (tester H6): `slug`, `scopeType` y `owner` NO se cambian por
    // esta API —el README lo promete— y hasta aquí se ignoraban EN SILENCIO:
    // quien pasaba `{ slug: 'otro' }` creía haber renombrado el rol. Lo que
    // no se puede hacer se dice.
    const allowed = new Set(['name', 'description', 'rank', 'permissions'])
    const unknown = Object.keys(changes).filter((key) => !allowed.has(key))
    if (unknown.length) {
      throw new InvalidIdentityError(
        `Cambios de rol local inválidos: '${unknown.join("', '")}' no se puede${unknown.length > 1 ? 'n' : ''} cambiar ` +
          `(un rol local no cambia de slug, nivel ni owner: purga y define otro). Campos admitidos: ${[...allowed].join(', ')}.`
      )
    }
    return {
      name: this.#parseName(changes.name),
      description: this.#parseDescription(changes.description),
      rank: this.#parseRank(changes.rank),
      permissions: changes.permissions === undefined ? undefined : this.#parsePermissions(changes.permissions),
    }
  }

  #parseRank(rank: unknown): number | undefined {
    if (rank === undefined) return undefined
    if (typeof rank !== 'number' || !Number.isInteger(rank)) {
      throw new InvalidIdentityError(`rank inválido: se esperaba un entero y llegó ${typeof rank === 'number' ? rank : typeof rank}`)
    }
    return rank
  }

  #parseName(name: unknown): string | undefined {
    if (name === undefined) return undefined
    if (typeof name !== 'string' || name.length === 0 || name.length > ROLE_NAME_MAX) {
      throw new InvalidIdentityError(`name inválido: se esperaba una cadena de 1 a ${ROLE_NAME_MAX} caracteres`)
    }
    return name
  }

  #parseDescription(description: unknown): string | null | undefined {
    if (description === undefined) return undefined
    if (description === null) return null
    if (typeof description !== 'string' || description.length > ROLE_DESCRIPTION_MAX) {
      throw new InvalidIdentityError(`description inválida: se esperaba una cadena de hasta ${ROLE_DESCRIPTION_MAX} caracteres, o null`)
    }
    return description
  }

  #parsePermissions(permissions: unknown): string[] {
    if (!Array.isArray(permissions)) throw new InvalidIdentityError(`permissions inválido: se esperaba una lista de slugs y llegó ${typeof permissions}`)
    for (const slug of permissions) assertValidSlug('permiso', slug)
    return [...new Set(permissions as string[])]
  }

  /** Lista blanca, existencia en el catálogo y composición por nivel (B5), en ese orden. */
  #assertComposable(permissions: string[], role: { slug: string; scopeType: ScopeType }, catalog: CatalogView): void {
    const delegable = new Set(this.#config.delegablePermissions ?? [])
    for (const slug of permissions) {
      if (!delegable.has(slug)) {
        throw new PermissionNotDelegableError(
          `'${slug}' no se puede delegar: no está en config.delegablePermissions ` +
            `(${delegable.size ? [...delegable].join(', ') : 'vacía: nadie delega nada hasta declararla'}).`
        )
      }
      const permission = catalog.permission(slug)
      if (!permission) throw new UnknownPermissionError(slug)
      assertAssignableAt(role, slug, permission.assignableAt)
    }
  }

  /** Cada permiso tiene que ser EFECTIVO para el actor en el owner: concedido por un rol suyo de la cadena y no denegado en ella (C2). */
  #assertDelegable(permissions: string[], granted: Set<string>, denied: Set<string>, owner: ScopeRef): void {
    for (const slug of permissions) {
      if (denied.has(slug)) {
        throw new PermissionNotDelegableError(
          `'${slug}' no se puede delegar: el actor lo tiene DENEGADO en ${owner.type}:${owner.uuid ?? ''} (o en un ancestro); ` +
            `un deny no se lava componiendo un rol para otro.`
        )
      }
      if (!granted.has(slug)) {
        throw new PermissionNotDelegableError(
          `'${slug}' no se puede delegar: el actor no lo tiene efectivo en ${owner.type}:${owner.uuid ?? ''} ` +
            `(ningún rol vigente suyo en esa cadena lo concede).`
        )
      }
    }
  }

  /** `0 < rank < min(rank del actor, rank máximo global)`: policy de escritura, no de evaluación (invariante 8). */
  #assertRank(rank: number, actorRank: number, topGlobalRank: number): void {
    const ceiling = Math.min(actorRank, topGlobalRank)
    if (!(rank > 0 && rank < ceiling)) {
      throw new RankExceededError(
        `rank ${rank} fuera de la policy: tiene que cumplir 0 < rank < ${ceiling} (min(rank del actor = ${actorRank}, rank máximo global = ${topGlobalRank})).`
      )
    }
  }

  /**
   * El nivel de un rol local nunca está POR ENCIMA de su owner (3E · P1,
   * auditor A1). La regla es mínima a propósito y se decide con la cadena
   * que ya está resuelta, sin pedirle nada más al consumidor:
   *
   *  - `scopeType === owner.type` ⇒ vale (el caso propio).
   *  - `scopeType` es el nivel de un ANCESTRO del owner (`app` incluida,
   *    que está en toda cadena) ⇒ 422 `E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER`. Es
   *    la mina: un `operador@organization` cuyo owner es una unit jamás es
   *    visible —no concede, no es membresía, nadie lo puede asignar— y lo
   *    único que hace es OCUPAR ese `(slug, nivel)` para el dueño del árbol
   *    y para el catálogo GLOBAL; el actor de menor privilegio del sistema
   *    bloqueando a la plataforma (y, hasta 3E, su deploy entero).
   *  - Cualquier otro tipo se presume DESCENDIENTE y vale: es el caso común
   *    (`lead@unit` con owner una organization) y exigir `descendantsOf`
   *    para él rompía a todo consumidor con el stub publicado, que no lo
   *    declara.
   *  - Con `scopes.descendantsOf` declarado se ENDURECE: el tipo tiene que
   *    aparecer de verdad bajo el owner en el árbol de HOY; si no, 422.
   *
   * **Lo que cuesta la degradación, dicho** (3G · X1, auditor P4): si el
   * subárbol no se puede enumerar (cota superada o `descendantsOf` caído) la
   * regla vuelve a ser la MÍNIMA — y el propio actor puede provocarlo
   * creando más hijos de su scope que `maxDescendants`, porque crear scopes
   * es una función normal del producto. Es un control que el vigilado apaga.
   * Se acepta a sabiendas: la regla mínima no concede NADA (es la que corre
   * en todo consumidor con el stub publicado), y el daño residual —ocupar un
   * `(slug, nivel)`— es reparable por AUTORIDAD + RANGO: un ancestro define
   * el suyo y lo ensombrece (3F · S3 + 3G · W3) **si supera en rango al
   * squatter** — `rank` es metadata del consumidor (invariante 8) y nada
   * obliga a que decrezca con la profundidad, así que con un reparto no
   * monótono (rank 60 en una unit bajo el org-admin rank 50 que es dueño de
   * ese árbol) el dueño se lleva 422 por las dos puertas y el recurso es la
   * PLATAFORMA (3b-1 · D1): el techo global acota todo rank local, y
   * `purgeRole` no mide rango. Quien no acepte ese trato deja
   * `maxDescendants` por encima de su subárbol mayor (3b-0b · AB1: la
   * degradación ya no se anuncia en ningún retorno —`truncated` se borró con
   * `ScopeDetachOutcome` en 3b-0 · Z1—, así que la cota es lo único que hay
   * que vigilar; `authz:catalog:diff --fail-on-shadows` es el gate de CI).
   *
   * (Un `scopeType` de nivel `app` muere antes, en `#parseScopedRoleSpec`:
   * la raíz no cuelga de ningún owner. Si llegara aquí sería un ancestro.)
   */
  async #assertLevelUnderOwner(scopeType: ScopeType, chain: ScopeRef[], operation: string): Promise<void> {
    const owner = chain[0]
    if (scopeType === owner.type) return
    const above = chain.slice(1).find((scope) => scope.type === scopeType)
    if (above) {
      throw new RoleLevelAboveOwnerError(
        `${operation}: un rol local de nivel '${scopeType}' está POR ENCIMA de su owner ${owner.type}:${owner.uuid ?? ''} ` +
          `('${scopeType}' es el nivel de ${above.type}:${above.uuid ?? ''}, un ancestro suyo en la cadena). Un rol así no ` +
          `sería visible en ninguna parte: no concedería nada y solo ocuparía ese (slug, nivel) para el resto del árbol y ` +
          `para el catálogo global. Defínelo en el nivel del owner o en uno por debajo.`
      )
    }
    // Lo demás se presume por debajo; con el árbol del consumidor a mano, se comprueba.
    const { below, enumerated } = await this.#descendantsOrDegrade(owner, operation)
    if (!enumerated) return
    if (below.some((scope) => scope.type === scopeType)) return
    const levels = [...new Set(below.map((scope) => scope.type))].sort()
    throw new RoleLevelAboveOwnerError(
      `${operation}: un rol local de nivel '${scopeType}' no cuelga de ${owner.type}:${owner.uuid ?? ''} ` +
        `(bajo él hoy hay ${levels.length ? `niveles ${levels.join(', ')}` : 'ningún scope'}), así que no sería visible en ` +
        `ninguna parte: no concedería nada y solo ocuparía ese (slug, nivel) para el resto del árbol y para el catálogo global. ` +
        `Define el rol en el nivel del owner o en uno que cuelgue de él.`
    )
  }

  /**
   * Solo se toca un rol de rango MENOR que el propio.
   *
   * El mensaje solo nombra el rol cuando el actor tiene ALGO en esa cadena
   * (rank > 0): con rank 0 no tiene ningún rol vigente ahí, así que el rol
   * pertenece a un árbol que no es suyo y decirle su slug y su rank
   * convertía el 422 en una sonda de catálogo ajeno —`scopes.detached` de la
   * unit de otro tenant, sin `within`, enumeraba sus roles locales sin
   * escribir nada (3G · X5, auditor P7)—. Es la misma regla que ya se aplicó
   * a `E_AUTHZ_AMBIGUOUS_ROLE` (3E · Q2): se nombra lo que el llamante ya
   * puede ver, nada más.
   */
  #assertAboveRole(actorRank: number, role: CatalogRole): void {
    if (actorRank > role.rank) return
    if (actorRank === 0) {
      throw new RankExceededError(
        `El actor no tiene ningún rol vigente en la cadena de ese scope (rank 0), así que no puede tocar los roles ` +
          `locales que hay ahí: hace falta rank mayor que el del rol.`
      )
    }
    throw new RankExceededError(
      `El actor (rank ${actorRank} en el owner del rol) no puede tocar '${role.slug}' (rank ${role.rank}): hace falta rank mayor que el del rol.`
    )
  }

  /** El rol por uuid, y LOCAL: un global es inmutable por esta API. */
  #localRoleOrFail(catalog: CatalogView, roleUuid: string): CatalogRole {
    const role = catalog.roleByUuid(roleUuid)
    if (!role) throw new UnknownRoleError(roleUuid)
    if (role.owner === GLOBAL_OWNER_KEY) {
      throw new RoleImmutableError(
        `El rol '${role.slug}@${role.scopeType}' es GLOBAL (catálogo del config): se cambia en el config y se sincroniza; ` +
          `por la API de delegación es inmutable.`
      )
    }
    return role
  }

  /** El scope owner de un rol local (de su clave). Una clave que no es un scope es catálogo corrupto (500). */
  #ownerOf(role: CatalogRole): ScopeRef {
    const owner = scopeFromKey(role.owner)
    if (!owner || owner.type === APP_SCOPE_TYPE) {
      throw new AuthorizationInternalError(`El owner del rol '${role.slug}' (${role.uuid}) no es una clave de scope: '${role.owner}'`)
    }
    return owner
  }

  /**
   * La colisión se decide por AUTORIDAD (3F · S3, auditor N1): *una
   * definición más autorizada gana y ensombrece a la menos autorizada* —
   * global > local de un ancestro > local de un descendiente—, que es la
   * regla que 3E ya tomó para los globales frente a los locales.
   *
   *  - Un homónimo GLOBAL, o local a un ancestro-o-igual del owner, es 422
   *    `E_AUTHZ_CATALOG_CONFLICT`: hacia ARRIBA no se ensombrece a nadie.
   *  - Un homónimo local a un DESCENDIENTE del owner ya NO colisiona: el
   *    nuevo se crea —si el actor SUPERA EN RANGO al que va a ensombrecer
   *    (3G · W3, `#assertAboveShadowed`: la autoridad no es solo posición)—
   *    y el del descendiente queda ENSOMBRECIDO (se devuelve para el evento
   *    `role_defined` y el diff lo lista como `shadowedByAncestor`). Hasta 3E era 422, y con eso el actor de menor
   *    privilegio del sistema le ocupaba el nombre al DUEÑO del árbol —para
   *    siempre, salvo purga rol a rol— y dejaba `authz:catalog:diff` en rojo,
   *    que es el gate de CI del deploy. Ahora la mina solo se ensombrece a sí
   *    misma: dentro de SU subárbol el slug pasa a 422 `E_AUTHZ_AMBIGUOUS_ROLE`
   *    (M1, fail-closed) y se opera por `{ uuid }`, exactamente como con un
   *    global. No concede nada de más: el hecho apunta al uuid del rol.
   *
   * Los owners de los homónimos se resuelven en fresco; uno que el árbol ya
   * no conoce no colisiona ni se ensombrece (no es visible en ningún sitio).
   *
   * `others` son los homónimos a contrastar: la foto del memo en el chequeo
   * BARATO (antes de abrir la transacción, para no pagar una transacción por
   * una colisión evidente) y las filas leídas de la BASE dentro de la
   * transacción serializada (3D · M2), que es el que manda. Con solo el
   * primero, dos `define` en paralelo —o un `define` contra un `sync`—
   * insertaban los dos homónimos y el estado era permanente (auditor V2).
   * En modo `sin-árbol` (dentro de la transacción, con el cerrojo sostenido)
   * no se resuelve ninguna cadena: el llamante rechaza igual lo que no puede
   * juzgar y pide reintentar.
   */
  async #assertNoRoleCollision(
    slug: string,
    scopeType: ScopeType,
    owner: ScopeRef,
    ownerChain: ScopeRef[],
    others: ReadonlyArray<{ owner: string }>,
    mode: 'con-árbol' | 'sin-árbol' = 'con-árbol'
  ): Promise<CatalogRole[]> {
    const ownerKey = scopeKey(owner)
    const ancestors = new Set(ownerChain.map(scopeKey))
    // Lo que se juzga SIN tocar el árbol, primero: un 422 evidente no paga
    // un `resolveChain` por homónimo.
    for (const other of others) {
      let where: string | null = null
      if (other.owner === GLOBAL_OWNER_KEY) where = 'global (catálogo del config)'
      else if (ancestors.has(other.owner)) where = other.owner === ownerKey ? 'este mismo scope' : `un ancestro (${other.owner})`
      if (where) {
        throw new CatalogConflictError(
          `Ya existe un rol '${slug}' de nivel '${scopeType}' visible desde ${owner.type}:${owner.uuid ?? ''}: es ${where}. ` +
            `Dentro de un scope un (slug, nivel) identifica un solo rol; elige otro slug.`
        )
      }
    }
    if (mode === 'sin-árbol') return []
    return this.#shadowedBelow(ownerKey, ancestors, others, 'defineScopedRole')
  }

  /**
   * Los homónimos LOCALES a un DESCENDIENTE del owner: los que una
   * definición en `ownerKey` ENSOMBRECE (3F · S3). Los owners se resuelven
   * en fresco; uno que el árbol ya no conoce no ensombrece a nadie. Lo usan
   * `defineScopedRole` (la colisión) y `updateScopedRole` (que no crea
   * sombras nuevas, pero tampoco deja tocar un rol que ya ensombrece a otro
   * de más rango — 3G · W3).
   *
   * **La VENTANA, dicha** (3b-1 · D2, auditor 3G): `chain === null` es «no
   * demostrable», y aquí se trata como «no hay sombra». Mientras el árbol no
   * responda por el owner de la víctima —soft-delete, réplica atrasada, un
   * scope en «pending»: los mismos estados que el resto del paquete admite
   * como normales— un actor de rank bajo en un ancestro crea el homónimo sin
   * pasar por `#assertAboveShadowed`, y al volver el árbol la sombra es real
   * y permanente. **No se rechaza, a propósito**: desde 3b-0 · Z1 un rol cuyo
   * owner no resuelve está DORMIDO y la salida es `prune-orphans`, así que
   * rechazar aquí convertiría un rol dormido en un BLOQUEO de `(slug, nivel)`
   * —exactamente la mina que Z1 quitó— y lo haría por una condición que el
   * llamante no puede ni ver ni corregir. Lo que acota el daño: (a) el mismo
   * atacante consigue la misma denegación **yendo primero**, sin trampa
   * ninguna (W3 solo protege a los roles que YA existen; ocupar el nombre
   * antes siempre fue gratis); (b) nadie pierde permisos —`authorize` no
   * direcciona por slug— y la sombra sale en `authz:catalog:diff` como
   * `shadowedByAncestor`; (c) el dueño del árbol con rango la borra, y la
   * plataforma siempre (3b-1 · D1).
   */
  async #shadowedBelow(
    ownerKey: string,
    ancestors: ReadonlySet<string>,
    others: ReadonlyArray<{ owner: string }>,
    operation: string
  ): Promise<CatalogRole[]> {
    const shadowed: CatalogRole[] = []
    for (const other of others) {
      if (other.owner === GLOBAL_OWNER_KEY || ancestors.has(other.owner)) continue
      if (!('uuid' in other) || !('rank' in other)) continue
      const otherOwner = scopeFromKey(other.owner)
      const chain = otherOwner ? await resolveChain(this.#freshResolver(), otherOwner, operation) : null
      if (chain && chain.some((s) => scopeKey(s) === ownerKey)) shadowed.push(other as CatalogRole)
    }
    return shadowed
  }

  /**
   * Sobre un rol solo actúa quien lo SUPERA EN RANGO — también para
   * ensombrecerlo (3G · W3, auditor P3′). **Es una comprobación de
   * ESCRITURA, no un invariante** (3b-1 · D3): quién ensombrece a quién es
   * función del árbol de HOY y el árbol se mueve sin preguntar aquí
   * (`scopes.moved` crea sombras sin juzgar ningún rango), y el propio
   * chequeo tiene su ventana (`#shadowedBelow` con `chain === null`, D2) y
   * su límite honesto: solo protege a los roles que YA existen —ocupar el
   * nombre primero siempre fue gratis—. Ensombrecer es tan destructivo
   * como borrar: dentro del subárbol del ensombrecido toda ruta por slug
   * pasa a 422 `E_AUTHZ_AMBIGUOUS_ROLE` para TODOS, y la víctima no puede
   * repararlo (su rango se mide en la cadena del owner del rol que
   * ensombrece, donde no vale nada). Hasta 3F la autoridad era solo POSICIÓN
   * y un actor de rank 3 en la organization inutilizaba por slug un rol de
   * rank 40 de una unit, en toda su cadena y para siempre.
   *
   * El mensaje NO nombra el rank ni el owner del ensombrecido: un ancestro
   * no ve los roles de sus descendientes (la visibilidad solo baja), así que
   * el 422 no puede ser una sonda del catálogo de abajo (misma regla que
   * `E_AUTHZ_AMBIGUOUS_ROLE`, 3E · Q2).
   */
  #assertAboveShadowed(actorRank: number, shadowed: readonly CatalogRole[], operation: string): void {
    for (const role of shadowed) {
      if (actorRank > role.rank) continue
      throw new RankExceededError(
        `${operation}: por debajo de este owner ya hay un rol local '${role.slug}' de nivel '${role.scopeType}' con rank ` +
          `MAYOR O IGUAL al tuyo (tu rank aquí es ${actorRank}). Definir el tuyo lo ensombrecería —dentro de su subárbol ` +
          `ese slug pasaría a ser ambiguo para todos y su dueño no podría repararlo—, y sobre un rol solo actúa quien lo ` +
          `supera en rango, igual que en deleteScopedRole. Elige otro slug.`
      )
    }
  }

  /**
   * LA escritura del catálogo por el manager: `withAuthzCatalogWrite` (la
   * versión compartida sube como última sentencia, dentro) y, al salir
   * —bien o mal—, se invalidan los memos de este proceso (como el sync). Con
   * `skipIfNoop`, un `fn` que devuelve `false` no ha escrito nada y la
   * versión no se toca (se revierte la transacción vacía).
   */
  async #writeCatalog<T>(fn: (trx: any) => Promise<T>, options: { skipIfNoop?: boolean } = {}): Promise<T> {
    const noop = Symbol('noop')
    try {
      return await withAuthzCatalogWrite(
        async (trx) => {
          const result = await fn(trx)
          if (options.skipIfNoop && result === false) throw noop
          return result
        },
        { driver: this.#config.default }
      )
    } catch (error) {
      if (error === noop) return false as T
      throw error
    } finally {
      invalidateAuthzCatalog()
    }
  }

  async #notifyCatalog(event: AuthzCatalogWriteEvent): Promise<void> {
    try {
      await this.#config.hooks?.onCatalogWrite?.(event)
    } catch (error) {
      const context = `authz: el hook onCatalogWrite falló tras '${event.action}' (la escritura sí se aplicó)`
      try {
        const { default: logger } = await import('@adonisjs/core/services/logger')
        logger.error({ err: error, event }, context)
      } catch {
        console.error(context, error)
      }
    }
  }

  /**
   * Asigna un rol al holder en un scope. `role` es un `RoleQuery` (3D · M1):
   * un slug, `{ slug, scopeType }` o `{ uuid }` — esta última es la forma
   * exacta, la única que responde cuando dos roles locales homónimos son
   * visibles en la misma cadena (las otras dos son 422
   * `E_AUTHZ_AMBIGUOUS_ROLE`, nunca «el más cercano gana»).
   */
  async grant(
    subject: SubjectRef,
    role: RoleQuery,
    scope: ScopeRef,
    options?: GrantOptions
  ): Promise<GrantOutcome> {
    await this.#assertTransactionalWrite(options, 'grant')
    const actor = await this.#writeOptions(options, 'grant')
    assertIdentity({ subject, role, scope, expiresAt: options?.expiresAt })
    await this.#assertWithin(scope, options, 'grant')
    // 3E · Q7: el evento lleva el rol RESUELTO (uuid + slug + nivel + owner),
    // no la pregunta cruda. Solo se resuelve si hay hook que lo vaya a leer.
    const roles = await this.#resolvedRoles(role, scope, 'grant')
    const transactional = this.#transactional(options)
    const outcome: GrantOutcome =
      (await this.#write(
        { action: 'granted', subject, scope, roles, expiresAt: options?.expiresAt ?? null, ...actor, ...transactional },
        async () => (await this.driver()).grant(subject, role, scope, options)
      )) ??
      // Un driver de terceros que aún devuelva `void`: la firma promete un
      // `GrantOutcome` y no miente (E1). Sin lectura previa no hay caducidad
      // anterior que contar: es lo que pidió el llamante, y `existed: false`.
      { existed: false, expiresAt: options?.expiresAt ?? null }
    // Un re-grant que cambia la caducidad de una asignación existente es un
    // evento distinto (L0.4): quien audita necesita ver de cuál a cuál.
    if (expiryChanged(outcome)) {
      await this.#notify({
        action: 'extended',
        subject,
        scope,
        roles,
        expiresAt: outcome.expiresAt,
        previousExpiresAt: outcome.previousExpiresAt,
        ...actor,
        ...transactional,
      })
    } else {
      await this.#notify({
        action: 'granted',
        subject,
        scope,
        roles,
        expiresAt: outcome.expiresAt,
        ...actor,
        ...transactional,
      })
    }
    return outcome
  }

  /**
   * Quita la asignación del rol en ese scope exacto. Por slug se quitan las
   * de TODOS los homónimos `(slug, nivel)` (3B; quitar nunca concede, y el
   * scope puede no existir ya para el árbol); por `{ uuid }`, solo la de ese
   * rol.
   */
  async revoke(subject: SubjectRef, role: RoleQuery, scope: ScopeRef, options?: ScopedWriteOptions): Promise<void> {
    await this.#assertTransactionalWrite(options, 'revoke')
    const actor = await this.#writeOptions(options, 'revoke')
    assertIdentity({ subject, role, scope })
    await this.#assertWithin(scope, options, 'revoke')
    const event: AuthzWriteEvent = {
      action: 'revoked',
      subject,
      scope,
      roles: await this.#resolvedRoles(role, scope, 'revoke'),
      ...actor,
      ...this.#transactional(options),
    }
    // L-2: las opciones viajan al driver (`transaction`, si la puerta la dejó pasar) — como en `grant`.
    await this.#write(event, async () => (await this.driver()).revoke(subject, role, scope, options))
    await this.#notify(event)
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef, options?: DenyOptions): Promise<void> {
    await this.#assertTransactionalWrite(options, 'deny')
    const actor = await this.#writeOptions(options, 'deny')
    assertIdentity({ subject, permission, scope })
    await this.#assertWithin(scope, options, 'deny')
    const event: AuthzWriteEvent = { action: 'denied', subject, scope, permission, ...actor, ...this.#transactional(options) }
    await this.#write(event, async () => (await this.driver()).deny(subject, permission, scope, options))
    await this.#notify(event)
  }

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef, options?: ScopedWriteOptions): Promise<void> {
    await this.#assertTransactionalWrite(options, 'removeDeny')
    const actor = await this.#writeOptions(options, 'removeDeny')
    assertIdentity({ subject, permission, scope })
    await this.#assertWithin(scope, options, 'removeDeny')
    const event: AuthzWriteEvent = { action: 'deny_removed', subject, scope, permission, ...actor, ...this.#transactional(options) }
    await this.#write(event, async () => (await this.driver()).removeDeny(subject, permission, scope, options))
    await this.#notify(event)
  }

  /**
   * Scopes de un tipo donde el holder tiene el permiso (2.1, B3). La ÚNICA
   * API del paquete que enumera descendientes — excepción explícita al
   * invariante 7 (`list*` siguen siendo directos) — y lo hace con el
   * `descendantsOf` del consumidor, nunca con N+1 `resolveChain` a ciegas.
   *
   * Regla:
   *  1. `listScopes(subject, permission)`: los scopes DIRECTOS que conceden,
   *     ya sin los bloqueados por un deny en su cadena y sin los que el árbol
   *     no conoce. Vacío ⇒ `none`.
   *  2. Si la raíz está entre ellos ⇒ `all`, con `excludedSubtrees` = todos
   *     los scopes con deny vivo del permiso (`listDenies`), como subárboles
   *     (F10). Nunca `all` sin esa lista (juez cruce 5): un deny vivo tiene
   *     que verse.
   *  3. Si no: candidatos = directos ∪ sus descendientes (`descendantsOf`).
   *     Cada candidato se contrasta con `resolveChain` (memoizado por
   *     request, F3): su cadena tiene que contener el scope concedente —si
   *     no, los dos resolutores del consumidor describen árboles distintos y
   *     se lanza 503 `E_AUTHZ_RESOLVER_FAILED`, nunca una lista con cruces—
   *     y no puede contener un scope denegado (es EXACTAMENTE la regla de
   *     `authorize`: deny en la cadena ⇒ false). Se filtran por `scopeType`.
   *  4. Más de `maxScopes` ⇒ 422 `E_AUTHZ_TOO_MANY_SCOPES`, nunca parcial, y
   *     se corta en cuanto se sabe (F8): los directos del tipo antes de bajar
   *     y el conteo del tipo dentro del bucle. `options.maxScopes` solo puede
   *     BAJAR la cota del config.
   * Sin `scopes.descendantsOf` ⇒ 500 `E_AUTHZ_NO_DESCENDANTS_RESOLVER`
   * (antes de mirar nada: un `none` sin árbol sería mentira).
   */
  async authorizedScopes(
    subject: SubjectRef,
    permission: string,
    scopeType: ScopeType,
    options: { maxScopes?: number } = {}
  ): Promise<AuthorizedScopes> {
    assertIdentity({ subject, permission, scopeType })
    const descendantsOf = this.#descendantsResolver('authorizedScopes')
    const { maxScopes, maxNodes } = this.#scopeBounds('authorizedScopes', options)
    // Una vista propia para la llamada: los scopes que se resuelvan se
    // resuelven una vez.
    const view = this.#readResolver ? this : (this.forRequest() as AuthorizationManager)
    const driver = await view.#reader()
    const listDenies = this.#optional(driver, 'listDenies', 'authorizedScopes')
    const key = AuthorizationManager.#scopeKey

    const direct = await driver.listScopes(subject, permission)
    if (direct.length === 0) return { kind: 'none' }
    const denied = (await listDenies(subject)).filter((d) => d.permission === permission).map((d) => d.scope)

    if (direct.some((s) => s.type === APP_SCOPE_TYPE)) {
      if (denied.length > maxScopes) {
        throw new TooManyScopesError(
          `authorizedScopes: ${denied.length} subárboles excluidos superan maxScopes=${maxScopes}; no se devuelve una lista parcial.`
        )
      }
      return { kind: 'all', excludedSubtrees: denied.map((scope) => ({ scope, includesDescendants: true })) }
    }

    const tooMany = (count: number) =>
      new TooManyScopesError(
        `authorizedScopes: más de ${maxScopes} scopes de tipo '${scopeType}' (${count} ya contados, maxScopes); ` +
          `acota la pregunta o sube la cota. No se devuelve una lista parcial.`
      )
    const deniedKeys = new Set(denied.map(key))
    const result = new Map<string, ScopeRef>()
    // Los directos del tipo (ya sin denies por encima: `listScopes`) cuentan
    // antes de bajar a ningún subárbol (F8).
    for (const granted of direct) {
      if (granted.type === scopeType) result.set(key(granted), granted)
    }
    if (result.size > maxScopes) throw tooMany(result.size)

    const resolver = view.#readResolverOrFresh()
    for (const granted of direct) {
      const grantedKey = key(granted)
      for (const candidate of await view.#descendants(descendantsOf, granted, maxNodes)) {
        const candidateKey = key(candidate)
        if (result.has(candidateKey)) continue
        // Pertenencia (F3): la cadena del candidato, según `resolveChain`,
        // tiene que pasar por el scope concedente. Si no (o si el árbol de
        // ancestros no lo conoce), los dos resolutores discrepan: 503.
        const chain = await resolveChain(resolver, candidate, 'authorizedScopes')
        if (!chain || !chain.some((s) => key(s) === grantedKey)) {
          throw new ScopeResolverError(
            'authorizedScopes',
            new Error(
              `descendantsOf(${grantedKey.replace('\u001f', ':')}) devolvió ${candidateKey.replace('\u001f', ':')} pero ` +
                `resolveChain no lo cuelga de ahí: los dos resolutores describen árboles distintos y no se puede responder.`
            )
          )
        }
        // Deny en la cadena ⇒ no concede, como en `authorize`.
        if (chain.some((s) => deniedKeys.has(key(s)))) continue
        if (candidate.type !== scopeType) continue
        result.set(candidateKey, candidate)
        if (result.size > maxScopes) throw tooMany(result.size)
      }
    }
    const scopes = [...result.values()]
    return scopes.length ? { kind: 'some', scopes } : { kind: 'none' }
  }

  /**
   * Los `excludedSubtrees` de un `all` (F10) expandidos: cada scope denegado
   * y todos sus descendientes, con el `descendantsOf` del config. Un scope
   * que `descendantsOf` no conoce (`null`) es 503: restarlo a medias
   * dejaría su subárbol dentro (fail-open). Cotas: `maxDescendants` por
   * subárbol y `maxScopes` (config o por llamada, nunca por encima del
   * config) sobre el total ⇒ 422, nunca parcial.
   */
  async expandExcludedSubtrees(
    excluded: ExcludedSubtree[],
    options: { maxScopes?: number } = {}
  ): Promise<ScopeRef[]> {
    if (!Array.isArray(excluded)) {
      throw new InvalidIdentityError(`expandExcludedSubtrees: se esperaba un array y llegó ${typeof excluded}`)
    }
    for (const item of excluded) assertScope(item?.scope)
    // Es una lectura de la vista como las demás (I2, auditor 10): caduca con ella.
    this.#assertReadable()
    const descendantsOf = this.#descendantsResolver('expandExcludedSubtrees')
    const { maxScopes, maxNodes } = this.#scopeBounds('expandExcludedSubtrees', options)
    const key = AuthorizationManager.#scopeKey
    const result = new Map<string, ScopeRef>()
    for (const { scope } of excluded) {
      result.set(key(scope), scope)
      const below = await this.#descendants(descendantsOf, scope, maxNodes, 'strict')
      for (const d of below) result.set(key(d), d)
      if (result.size > maxScopes) {
        throw new TooManyScopesError(
          `expandExcludedSubtrees: más de ${maxScopes} scopes excluidos (maxScopes); no se devuelve una lista parcial.`
        )
      }
    }
    return [...result.values()]
  }

  /**
   * Clave LAXA de un scope, solo para agrupar/deduplicar candidatos dentro
   * de una operación (`authorizedScopes`, el anti-ciclo de `#assertEdge`).
   * NO es `scopeKey` de `identity.ts` —esa valida la gramática y es la que
   * identifica hechos, owners e ids de binding, y es la que usa
   * `#rolesAlong` (3D · N5)—: aquí los scopes vienen del `descendantsOf` del
   * consumidor y no se les exige gramática para compararlos entre sí.
   */
  static #scopeKey(s: ScopeRef): string {
    return `${s.type}\u001f${s.uuid ?? ''}`
  }

  #descendantsResolver(operation: string): ScopeDescendantsResolver {
    const descendantsOf = this.#config.scopes?.descendantsOf
    if (!descendantsOf) {
      throw new NoDescendantsResolverError(
        `${operation} necesita 'scopes.descendantsOf' en config/authorization.ts (p. ej. sqlDescendantsOf(...)): ` +
          `sin el árbol de descendientes no se puede enumerar sin mentir.`
      )
    }
    return descendantsOf
  }

  /**
   * Cotas de una enumeración: `maxScopes` del config (default 1000), que
   * una llamada solo puede BAJAR (F8: subirla por llamada era una escalada
   * silenciosa de la cota global), y `maxDescendants` del config.
   */
  #scopeBounds(operation: string, options: { maxScopes?: number }): { maxScopes: number; maxNodes: number } {
    const configured = this.#config.scopes?.maxScopes ?? DEFAULT_MAX_SCOPES
    const maxNodes = this.#config.scopes?.maxDescendants ?? DEFAULT_MAX_DESCENDANTS
    for (const [name, value] of [
      ['maxScopes', configured],
      ['maxDescendants', maxNodes],
      ['maxScopes (por llamada)', options.maxScopes ?? configured],
    ] as const) {
      if (!Number.isInteger(value) || value < 1 || value > MAX_SCOPE_BOUND) {
        throw new AuthorizationConfigError(
          `${operation}: ${name} debe ser un entero entre 1 y ${MAX_SCOPE_BOUND} (llegó ${String(value)})`
        )
      }
    }
    return { maxScopes: Math.min(options.maxScopes ?? configured, configured), maxNodes }
  }

  /**
   * El subárbol del consumidor para la pieza que lo camina por SEGURIDAD y
   * no por enumeración —la regla de nivel de `defineScopedRole`/
   * `updateScopedRole`—, DEGRADANDO en vez de tumbar la operación (3F · S2,
   * auditor N3).
   *
   * Regla: *declarar `scopes.descendantsOf` nunca puede dejarte peor que no
   * declararlo*. Hasta 3E, una org con más units que `maxDescendants` —la
   * cota sale del config y una llamada no la puede subir (F8)— dejaba al
   * tenant grande sin poder delegar hacia abajo: la configuración que el
   * invariante 18 recomienda EMPEORABA el caso grande. Ahora, si el subárbol
   * no se puede enumerar (más nodos que la cota, o un `descendantsOf` que
   * falla), se sigue con `enumerated: false` y la regla de nivel cae a la
   * MÍNIMA (rechazar solo los tipos de un ancestro), que es la que corre en
   * todo consumidor con el stub publicado y no concede nada.
   * Pero no es gratis y está escrito donde toca (3G · X1, auditor P4): es un
   * control que el propio vigilado puede apagar creando hijos. Lo que NO
   * degrada es ensombrecer, que sigue pidiendo rango aunque la regla de
   * nivel haya caído a la mínima (3G · W3).
   *
   * (Desde 3b-0 · Z1 `scopes.detached` ya no llama aquí: purga los hechos
   * del scope EXACTO y no toca el catálogo, así que no tiene subárbol que
   * enumerar ni degradación que declarar.)
   *
   * Lo que NO se degrada es un error de CONFIG (`maxDescendants` fuera de
   * rango): eso es un bug del consumidor y sigue siendo 500.
   */
  async #descendantsOrDegrade(
    scope: ScopeRef,
    operation: string
  ): Promise<{ below: ScopeRef[]; enumerated: boolean }> {
    const descendantsOf = this.#config.scopes?.descendantsOf
    if (!descendantsOf) return { below: [], enumerated: false }
    const { maxNodes } = this.#scopeBounds(operation, {})
    try {
      return { below: await this.#descendants(descendantsOf, scope, maxNodes), enumerated: true }
    } catch (error) {
      if (error instanceof TooManyScopesError || error instanceof ScopeResolverError) {
        return { below: [], enumerated: false }
      }
      throw error
    }
  }

  /**
   * `descendantsOf` del consumidor, clasificado como `resolveChain` clasifica
   * `resolveChain`: lanza ⇒ 503 `E_AUTHZ_RESOLVER_FAILED`; no-array o
   * scope mal formado ⇒ 503; más de `maxNodes` ⇒ 422 `E_AUTHZ_TOO_MANY_SCOPES`;
   * `null` (desconocido para ese árbol) ⇒ nada debajo para un scope
   * CONCEDENTE (conservador: no se lista lo que no se puede enumerar) y 503
   * en modo `strict` (un subárbol EXCLUIDO que no se puede enumerar no se
   * puede restar: fail-open, F3/F10).
   */
  async #descendants(
    descendantsOf: ScopeDescendantsResolver,
    scope: ScopeRef,
    maxNodes: number,
    unknown: 'empty' | 'strict' = 'empty'
  ): Promise<ScopeRef[]> {
    let result: ScopeRef[] | null
    try {
      result = await descendantsOf(scope, { maxNodes })
    } catch (error) {
      if (isAuthzError(error)) throw error
      throw new ScopeResolverError('descendantsOf', error)
    }
    if (result === null || result === undefined) {
      if (unknown === 'strict') {
        throw new ScopeResolverError(
          'descendantsOf',
          new Error(`descendantsOf no conoce ${scope.type}:${scope.uuid ?? ''}: su subárbol no se puede restar.`)
        )
      }
      return []
    }
    if (!Array.isArray(result)) {
      throw new ScopeResolverError(
        'descendantsOf',
        new TypeError(`descendantsOf devolvió ${typeof result} en vez de ScopeRef[] | null`)
      )
    }
    for (const s of result) {
      try {
        assertScope(s)
      } catch (error) {
        throw new ScopeResolverError('descendantsOf', error)
      }
    }
    if (result.length > maxNodes) {
      throw new TooManyScopesError(
        `descendantsOf(${scope.type}:${scope.uuid ?? ''}) devolvió ${result.length} nodos, más que maxDescendants=${maxNodes}.`
      )
    }
    return result
  }

  /**
   * Ejecuta una escritura del driver. Si vence el deadline (503
   * `E_AUTHZ_BACKEND_TIMEOUT`) el resultado es DESCONOCIDO: el SDK o el
   * servidor pueden aplicarla después de que el llamante reciba el error
   * (D2, auditor H1). Antes de propagar se notifica el mismo evento con
   * `indeterminate: true`, para que quien audita registre "puede haber
   * ocurrido" en vez de nada. Lo mismo si el driver marcó el error como
   * escritura PARCIAL (`markPartialWrite`; cierre 3 de D2 · C2-5: `openfga`
   * renueva un grant con delete + write y el 2.º falló). Cualquier otro fallo
   * (422, conexión rechazada) significa que la escritura no ocurrió y se
   * propaga sin evento.
   *
   * **Dentro de la transacción del llamante (L-3) el deadline sigue siendo
   * `indeterminate: true`**, y el evento lleva además `transactional: true`.
   * El auditor del panel `{trx}` (🟡 12) objetó que ahí «el rollback la
   * determina»; pero lo que determina el rollback lo determina el LLAMANTE
   * y el paquete no lo ve: en el instante del 503 la sentencia puede haber
   * aterrizado en la transacción (SQLite no cancela; en PG la transacción
   * queda abortada y ya no puede confirmar; en MySQL la sentencia se mata y
   * la transacción sigue viva) y el llamante puede confirmar o no. Lo
   * honesto es el mismo «no lo sé» de siempre más la marca de que la última
   * palabra es su commit. Medido por motor en `database_transaction.spec.ts`.
   */
  async #write<T>(event: AuthzWriteEvent, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn()
    } catch (error) {
      // Cierre 3 de D2 · ⚪ C2-5: una escritura PARCIAL (el driver la marca con `markPartialWrite`: `openfga` renueva un
      // grant con delete + write y el 2.º falló) también es indeterminada — la misma rama que el `RelationsManager`.
      if (error instanceof AuthorizationBackendTimeoutError || isPartialWrite(error)) {
        await this.#notify({ ...event, indeterminate: true })
      }
      throw error
    }
  }

  /**
   * Notifica al consumidor. El hook es un side-effect (auditar, emitir un
   * evento): cuando falla, la escritura YA está aplicada, así que propagar su
   * error le daría al llamante un fallo por una operación que sí ocurrió —
   * y le invitaría a reintentar algo ya hecho. Se registra y se sigue.
   *
   * El contrato ("el hook no debe lanzar") pasa así de comentario a garantía.
   */
  async #notify(event: AuthzWriteEvent): Promise<void> {
    try {
      await this.#config.hooks?.onWrite?.(event)
    } catch (error) {
      await this.#logHookFailure(event, error)
    }
  }

  async #logHookFailure(event: AuthzWriteEvent, error: unknown): Promise<void> {
    const context = `authz: el hook onWrite falló tras '${event.action}' (la escritura sí se aplicó)`
    try {
      const { default: logger } = await import('@adonisjs/core/services/logger')
      logger.error({ err: error, event }, context)
    } catch {
      // Fuera de una app booteada (tests, scripts sueltos) no hay logger.
      console.error(context, error)
    }
  }
}
