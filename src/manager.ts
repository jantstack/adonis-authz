import { Exception } from '@adonisjs/core/exceptions'
import { v7 as uuidv7 } from 'uuid'
import type { AuthorizationConfig } from './define_config.js'
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
  scopeSpellings,
} from './identity.js'
import { expiryChanged } from './expiry.js'
import { randomBytes } from 'node:crypto'
import {
  DEFAULT_FREEZE_LEASE_MS,
  acquireFreeze,
  freezeIsLive,
  freezeKindOf,
  readFreezeRow,
  assertNotFrozenRow,
  releaseFreeze,
  renewFreeze,
} from './freeze.js'
import type { FreezeKind, FreezeToken } from './freeze.js'
import { assertKnownScope, isAuthzError, resolveChain, rootOnlyResolver } from './shared/backend_guard.js'
import { CatalogCache, GLOBAL_OWNER_KEY, invalidateAuthzCatalog, isRoleVisibleWith, readLocalRoles, withAuthzCatalogWrite } from './catalog/catalog_cache.js'
import type { CatalogView } from './catalog/catalog_cache.js'
import { assertAssignableAt } from './catalog/catalog.js'
import { systemClock } from './clock.js'
import {
  ActorRequiredError,
  AuthorizationBackendTimeoutError,
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
} from './errors.js'
import { APP_SCOPE_TYPE } from './types.js'
import { memoizeAncestors } from './memoize_ancestors.js'
import { AUTHZ_TABLES_ORIGIN } from './reconcile.js'
import type {
  AuthorizationDriver,
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
  ScopeOutbox,
  ScopeRelayReport,
  ScopeRef,
  ScopeTreeChange,
  ScopeTreeWriteOptions,
  ScopeType,
  SubjectRef,
  WriteOptions,
} from './types.js'

/** Longitudes de `authz_roles.name`/`description` (el esquema publicado). */
const ROLE_NAME_MAX = 100
const ROLE_DESCRIPTION_MAX = 500

/** Descripción corta de una respuesta inválida de `authorizeMany`, para el mensaje del 500. */
function describeAnswer(answer: unknown): string {
  if (!Array.isArray(answer)) return `${answer === null ? 'null' : typeof answer} (no es un array)`
  const offending = answer.find((b) => typeof b !== 'boolean')
  if (offending !== undefined || answer.some((b) => typeof b !== 'boolean')) {
    return `un array de ${answer.length} con un elemento que no es boolean (${typeof offending})`
  }
  return `un array de ${answer.length}`
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
/** Vida por defecto de una vista de `forRequest()` para LEER (F9): un request, no un módulo. */
export const DEFAULT_VIEW_MAX_AGE_MS = 30_000

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
  leaseMs: number | null
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
    const token = await acquireFreeze(
      { reason: finalReason, holder, untilMs: leaseMs === null ? null : nowMs + leaseMs, nowMs },
      { driver: this.#config.default }
    )
    if (token === null) {
      const row = await readFreezeRow({ driver: this.#config.default })
      throw new FreezeHeldError(
        `freeze: ya hay un freeze VIVO de otro dueño (${row.holder ?? '?'}, fence ${row.fence}, motivo: ${row.reason ?? '?'}). ` +
          `Espera a que termine, o levántalo con authz:unfreeze si su proceso murió sin lease.`
      )
    }
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

  /** El freeze VIVO de la fila compartida, o `null`. Lo lee cualquiera; solo el token lo levanta. */
  async freezeStatus(): Promise<FreezeStatus | null> {
    const row = await readFreezeRow({ driver: this.#config.default })
    if (!freezeIsLive(row, this.#root().#wallMs())) return null
    return {
      reason: row.reason as string,
      holder: row.holder ?? '?',
      kind: freezeKindOf(row.holder),
      untilMs: row.untilMs,
      fence: row.fence,
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
      return await fn({ fence: context.fence, leaseMs: context.leaseMs, lapsed: context.lapsed })
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
        release: async () => {},
        lapsed: () => root.#tokenLapsed(outer.token, outer.lapsed),
      }
    }
    if (options.operatorAsContext) {
      const status = await this.freezeStatus()
      if (status !== null && status.kind === 'operator') {
        const token: FreezeToken = { fence: status.fence, holder: status.holder }
        return {
          fence: status.fence,
          leaseMs: null,
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
    attached: async (child: ScopeRef, parent: ScopeRef, options?: ScopeTreeWriteOptions): Promise<void> => {
      const actor = await this.#writeOptions(options, 'scopes.attached')
      const edge = await this.#assertEdge(child, parent, 'scopes.attached')
      this.#assertWithinChain(parent, edge.chain, options, 'scopes.attached')
      // Un hijo que el árbol ya conoce se está MOVIENDO (el `attach` de un
      // nodo existente es un `move`): su origen también tiene que estar dentro.
      await this.#assertWithinOrigin(child, options, 'scopes.attached', 'if-known')
      const outbox = this.#outbox()
      if (outbox) {
        await outbox.enqueue(
          { op: 'attached', child: edge.child, parent: edge.chain[0] },
          { transaction: options?.transaction, ...actor }
        )
        return
      }
      await (await this.driver()).onScopeAttached?.(child, parent)
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
    moved: async (child: ScopeRef, newParent: ScopeRef, options?: ScopeTreeWriteOptions): Promise<void> => {
      const actor = await this.#writeOptions(options, 'scopes.moved')
      const edge = await this.#assertEdge(child, newParent, 'scopes.moved')
      this.#assertWithinChain(newParent, edge.chain, options, 'scopes.moved')
      await this.#assertWithinOrigin(child, options, 'scopes.moved', 'required')
      const outbox = this.#outbox()
      if (outbox) {
        await outbox.enqueue(
          { op: 'moved', child: edge.child, parent: edge.chain[0] },
          { transaction: options?.transaction, ...actor }
        )
        return
      }
      await (await this.driver()).onScopeMoved?.(child, newParent)
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
    detached: async (child: ScopeRef, options?: ScopeTreeWriteOptions): Promise<void> => {
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
      // purgan TODAS las ortografías de las que el uuid del llamante puede
      // ser alias (`scopeSpellings`, 3b-2h · 🟠 3). Con la fila viva esto es
      // exactamente una, la de la tabla; sin ella, la del llamante y la
      // canónica que un motor pudo fundir con la suya. Antes se usaba la del
      // llamante a secas: `purgeScope` demostraba cero sobre un objeto que no
      // existe, devolvía OK, y el scope real seguía concediendo para siempre.
      const chain = await resolveChain(this.#freshResolver(), child, 'scopes.detached')
      const targets = chain ? [chain[0]] : scopeSpellings(child)
      const outbox = this.#outbox()
      if (outbox) {
        // La identidad se resuelve AQUÍ, con la fila del consumidor todavía
        // viva si la hay: al relevar el cambio ya no resolvería. Y no se
        // audita `scope_purged` todavía, porque todavía no ha pasado nada.
        for (const target of targets) {
          await outbox.enqueue(
            { op: 'detached', child: target },
            { transaction: options?.transaction, ...actor }
          )
        }
        return
      }
      const driver = await this.driver()
      for (const purged of targets) {
        const event: AuthzWriteEvent = { action: 'scope_purged', scope: purged, ...actor }
        await this.#write(event, () => driver.purgeScope(purged))
        await driver.onScopeDetached?.(purged)
        await this.#notify(event)
      }
    },
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
   */
  async relayScopeChanges(
    options: { limit?: number; batchSize?: number; dryRun?: boolean } = {}
  ): Promise<ScopeRelayReport> {
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
    /** Lo aparcado por la outbox, si sabe aparcar: se reporta SIEMPRE. */
    const dead = await AuthorizationManager.#deadLetters(outbox, batchSize)

    if (dryRun) {
      const batch = await outbox.pending(limit)
      const extra = batch.length >= limit ? true : false
      return {
        applied: [],
        failed: null,
        failures: [],
        deferred: [],
        dead,
        busy: false,
        remaining: batch.length > 0 || extra,
        dryRun: true,
        wouldApply: batch.map((item) => ({ id: item.id, change: item.change, attempts: item.attempts })),
      }
    }

    // El lease del escritor ÚNICO. Una outbox que no sabe darlo se comporta
    // como hasta ahora (y el README dice que entonces el relay tiene que
    // correr de uno en uno).
    const lease = outbox.acquire ? await outbox.acquire() : null
    if (outbox.acquire && lease === null) {
      return {
        applied: [],
        failed: null,
        failures: [],
        deferred: [],
        dead,
        busy: true,
        remaining: (await outbox.pending(1)).length > 0,
        dryRun: false,
        wouldApply: [],
      }
    }

    try {
      const driver = await this.driver()
      const applied: RelayedScopeChange[] = []
      const deferred: RelayedScopeChange[] = []
      const failures: ScopeRelayReport['failures'] = []
      /** Claves de scope contaminadas: lo que las toque se aplaza. */
      const blocked = new Set<string>()
      // Una outbox que no marca lo aplicado devolvería el mismo pendiente
      // para siempre: el relay no puede quedarse dando vueltas ni
      // "arreglarlo" por su cuenta, así que lo denuncia (500) en cuanto
      // vuelve a ver un id que YA aplicó.
      const done = new Set<string>()
      /** Ids que esta pasada dejó a propósito (fallo o aplazo): reaparecen. */
      const parked = new Set<string>()
      /** El último id visto: la outbox pagina desde ahí (lo saltado se queda). */
      let after: string | number | undefined

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
        const batch = await outbox.pending(Math.min(batchSize, limit - applied.length), after)
        if (batch.length === 0) break
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
          const collision = keys.find((key) => blocked.has(key))
          if (collision !== undefined) {
            for (const key of keys) blocked.add(key)
            parked.add(id)
            deferred.push({
              id: item.id,
              change: item.change,
              attempts: item.attempts,
              error: `aplazado: depende de ${collision}, que quedó sin aplicar en esta pasada`,
            })
            continue
          }
          try {
            await this.#applyScopeChange(driver, item)
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            await outbox.markFailed(item.id, message)
            for (const key of keys) blocked.add(key)
            parked.add(id)
            failures.push({ id: item.id, change: item.change, error: message })
            continue
          }
          await outbox.markApplied(item.id)
          done.add(id)
          applied.push({ id: item.id, change: item.change, attempts: item.attempts })
        }
        // Una outbox que ignora `after` devuelve el mismo lote atascado: la
        // pasada termina aquí en vez de dar vueltas (lo que quede, y lo que
        // haya detrás, sigue pendiente para la siguiente).
        if (!progress) break
      }

      return {
        applied,
        failed: failures[0] ?? null,
        failures,
        deferred,
        dead,
        busy: false,
        remaining: (await outbox.pending(1)).length > 0,
        dryRun: false,
        wouldApply: [],
      }
    } finally {
      await lease?.release()
    }
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
      factsOrigin: { name: origin.name, authzTables: origin.authzTables },
    }
    const pass = async (): Promise<ReconcileReport> => {
      const report = await target.reconcile!(source, options)
      const { pending, dead } = await this.#relayWindow()
      report.drift.pendingRelay = pending
      report.drift.deadRelay = dead
      // Quién fue el origen se DICE, siempre: es la diferencia entre una
      // migración y una pasada de mantenimiento contra el driver activo.
      report.factsFrom = origin.resolved()
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
   *     y el catálogo de HOY. No se inventa ni se borra un solo hecho. Un
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
    enumerate: ReconcileFactsEnumerator
    resolved: () => string
  }> {
    if (from === undefined && to === this.#config.default && target.capabilities?.hierarchyFacts === true) {
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

  /** El driver que `--from` nombra, con los dos errores de 3b-3b intactos. */
  async #originDriver(from: string, to: string): Promise<AuthorizationDriver> {
    const registered = Object.keys(this.#config.drivers ?? {})
    if (from === to) {
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
        if (candidate === to) continue
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
   */
  static #changeKeys(change: ScopeTreeChange): string[] {
    return change.op === 'detached'
      ? [scopeKey(change.child)]
      : [scopeKey(change.child), scopeKey(change.parent)]
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
    return { chain, child: canonicalChild }
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
      if (!Array.isArray(answer) || answer.length !== scopes.length || answer.some((b) => typeof b !== 'boolean')) {
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
    const outcome: GrantOutcome =
      (await this.#write(
        { action: 'granted', subject, scope, roles, expiresAt: options?.expiresAt ?? null, ...actor },
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
      })
    } else {
      await this.#notify({
        action: 'granted',
        subject,
        scope,
        roles,
        expiresAt: outcome.expiresAt,
        ...actor,
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
    const event: AuthzWriteEvent = { action: 'revoked', subject, scope, roles: await this.#resolvedRoles(role, scope, 'revoke'), ...actor }
    // L-2: las opciones viajan al driver (`transaction`, si la puerta la dejó pasar) — como en `grant`.
    await this.#write(event, async () => (await this.driver()).revoke(subject, role, scope, options))
    await this.#notify(event)
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef, options?: DenyOptions): Promise<void> {
    await this.#assertTransactionalWrite(options, 'deny')
    const actor = await this.#writeOptions(options, 'deny')
    assertIdentity({ subject, permission, scope })
    await this.#assertWithin(scope, options, 'deny')
    const event: AuthzWriteEvent = { action: 'denied', subject, scope, permission, ...actor }
    await this.#write(event, async () => (await this.driver()).deny(subject, permission, scope, options))
    await this.#notify(event)
  }

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef, options?: ScopedWriteOptions): Promise<void> {
    await this.#assertTransactionalWrite(options, 'removeDeny')
    const actor = await this.#writeOptions(options, 'removeDeny')
    assertIdentity({ subject, permission, scope })
    await this.#assertWithin(scope, options, 'removeDeny')
    const event: AuthzWriteEvent = { action: 'deny_removed', subject, scope, permission, ...actor }
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
   * ocurrido" en vez de nada. Cualquier otro fallo (422, conexión rechazada)
   * significa que la escritura no ocurrió y se propaga sin evento.
   */
  async #write<T>(event: AuthzWriteEvent, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn()
    } catch (error) {
      if (error instanceof AuthorizationBackendTimeoutError) {
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
