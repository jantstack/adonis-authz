/**
 * Contrato del sistema de autorización del chasis (puerto + drivers).
 *
 * El chasis NO condena a un backend concreto: todo call-site (middleware,
 * services, seeders) habla con este contrato a través del manager
 * (`#services/authorization/main`). El driver `database` (motor propio sobre
 * las tablas `authz_*`) es el default autosuficiente; un driver `openfga` u
 * otro custom se registra en `config/authorization.ts` sin tocar call-sites.
 *
 * ── Semántica que TODO driver debe respetar ──────────────────────────────
 * La verifica `tests/contracts/authorization_driver_contract.ts` (la misma
 * suite corre contra cada driver — es el juez del contrato):
 *
 * 1. **Scopes jerárquicos, herencia SOLO hacia abajo.** La cadena de un scope
 *    es `[scope, ...ancestros]` (`app` es la raíz: su cadena es él mismo).
 *    Un grant en un scope autoriza en ese scope y en TODOS sus descendientes;
 *    nunca en hermanos ni ancestros. En T1 solo opera `app` (los ancestros de
 *    `organization`/`unit` se completan en T2/T3 vía `resolveAncestors`).
 * 2. **Deny explícito gana.** Un deny de un permiso en cualquier scope de la
 *    cadena bloquea `authorize`, aunque un rol lo conceda (el deny también
 *    hereda hacia abajo). Quitar el deny restaura el permiso.
 * 3. **Expiración observable.** Una asignación con `expiresAt` en el pasado
 *    no concede nada; con `expiresAt` futuro concede normalmente.
 * 4. **Holder polimórfico.** `SubjectRef.type` es el morph name del modelo
 *    (`users` | `admins` | `integrations` | los del consumidor). Dos holders
 *    con el mismo uuid y distinto type JAMÁS se cruzan.
 * 5. **Denegación por defecto.** Permiso desconocido, rol sin el permiso o
 *    holder sin asignación vigente → `false`, nunca throw en `authorize`.
 *    En cambio `grant`/`deny` con rol/permiso fuera del catálogo → throw
 *    (error de programación, no de autorización).
 * 6. **Idempotencia de escritura.** Re-`grant` no duplica (`expiresAt` en
 *    tres estados: omitido preserva, `null` quita, `Date` fija);
 *    re-`revoke`/re-`deny`/re-`removeDeny` son no-ops seguros.
 * 7. **El árbol es un hecho del contrato.** Un scope que el resolutor no
 *    conoce (`null`) deniega, no lista y no admite escrituras; `purgeScope`
 *    borra los hechos del scope exacto (los del catálogo) y demuestra cero.
 */

/** Referencia polimórfica al holder: morph name + uuid. */
export interface SubjectRef {
  type: string
  uuid: string
}

/**
 * Nivel de scope. El motor solo conoce la raíz (`app`, uuid null); los demás
 * niveles los define el CONSUMIDOR — `organization`/`unit` en este chasis,
 * pero podrían ser `project`, `site`, `case`… El árbol lo declara el
 * `ScopeAncestorsResolver` que se inyecta a los drivers, así que el motor no
 * necesita conocer la taxonomía.
 *
 * Un consumidor que quiera seguridad de tipos define su propia unión:
 *   type MyScope = 'app' | 'organization' | 'unit'
 */
export type ScopeType = string

/** Nombre reservado del scope raíz. */
export const APP_SCOPE_TYPE = 'app'

export interface ScopeRef {
  type: ScopeType
  /** `null` solo para `app` (scope global sin entidad). */
  uuid: string | null
}

/** El scope raíz de aplicación (nivel plataforma). */
export const APP_SCOPE: ScopeRef = Object.freeze({ type: 'app', uuid: null })

export interface GrantOptions {
  /**
   * Caducidad de la asignación, en TRES estados (L0.4):
   *  - omitido: no tocar una caducidad vigente (si la asignación ya había
   *    expirado, revive sin caducidad);
   *  - `null`: quitar la caducidad;
   *  - `Date`: fijarla.
   * Antes "omitido" borraba la caducidad: un "asegúrate de que tiene el rol"
   * convertía un acceso temporal en permanente.
   */
  expiresAt?: Date | null
}

/** Lo que un `grant` hizo, para que el manager audite y el juez lo observe. */
export interface GrantOutcome {
  /** Ya había una asignación de ese rol en ese scope exacto. */
  existed: boolean
  /** Caducidad que tenía antes (solo si `existed` y se pudo leer). */
  previousExpiresAt?: Date | null
  /** Caducidad con la que queda tras la escritura. */
  expiresAt: Date | null
}

/**
 * Rol por el que pregunta `hasRole`. Con string, en cada nivel de la cadena
 * solo cuenta el rol de ESE nivel (el `owner` de app casa en app y hereda
 * hacia abajo; un `owner` de organization jamás casa en app). Con
 * `{ slug, scopeType }` se pregunta por el rol de un nivel concreto: solo
 * los scopes de la cadena de ese tipo cuentan (L0.6).
 */
export type RoleQuery = string | { slug: string; scopeType: ScopeType }

export interface AuthorizationDriver {
  /**
   * ¿El holder tiene el permiso en el scope? Evalúa la cadena completa:
   * sin deny en la cadena Y alguna asignación vigente cuyo rol concede el
   * permiso. Nunca lanza: desconocido = false.
   */
  authorize(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<boolean>

  /**
   * Asigna un rol al holder en un scope. El rol debe existir en el catálogo
   * para `scope.type` (422 si no) y el scope para el resolutor (422 si no).
   * Idempotente: re-grant no duplica; `expiresAt` sigue los tres estados de
   * `GrantOptions`. Devuelve qué hizo (`GrantOutcome`).
   */
  grant(
    subject: SubjectRef,
    role: string,
    scope: ScopeRef,
    options?: GrantOptions
  ): Promise<GrantOutcome>

  /**
   * Quita la asignación del rol en ese scope exacto. El rol debe existir en
   * el catálogo para `scope.type` (422 si no, como `grant`); la asignación
   * puede no existir (no-op).
   */
  revoke(subject: SubjectRef, role: string, scope: ScopeRef): Promise<void>

  /**
   * ¿El holder tiene el rol (vigente) en el scope o en un ancestro?
   * Misma regla de herencia hacia abajo que `authorize`. Es MEMBRESÍA: el
   * deny no la gobierna, así que nunca decide acceso (para eso, `authorize`).
   */
  hasRole(subject: SubjectRef, role: RoleQuery, scope: ScopeRef): Promise<boolean>

  /**
   * Deny explícito de UN permiso al holder en un scope (y sus descendientes).
   * El permiso debe existir en el catálogo (throw si no). Idempotente.
   */
  deny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void>

  /**
   * Levanta el deny en ese scope exacto. El permiso debe existir en el
   * catálogo (422 si no, como `deny`); el deny puede no existir (no-op).
   */
  removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void>

  /** Holders con asignación VIGENTE del rol en ese scope exacto (sin herencia). */
  listSubjects(role: string, scope: ScopeRef): Promise<SubjectRef[]>

  /** Roles (slugs) con asignación DIRECTA vigente del holder en ese scope exacto. */
  listRoles(subject: SubjectRef, scope: ScopeRef): Promise<string[]>

  /**
   * Scopes del tipo dado donde el holder tiene alguna asignación DIRECTA
   * vigente de rol. Base de "membresía" (¿de qué organizations es miembro?).
   */
  listRoleScopes(subject: SubjectRef, scopeType: ScopeType): Promise<ScopeRef[]>

  /**
   * Scopes con asignación DIRECTA vigente que concede el permiso, excluyendo
   * los bloqueados por deny. No enumera descendientes heredados (sería
   * abierto): el caller consulta `authorize` sobre un scope concreto.
   */
  listScopes(subject: SubjectRef, permission: string): Promise<ScopeRef[]>

  /**
   * Borra TODAS las asignaciones y denies del scope EXACTO cuyo rol/permiso
   * está en el catálogo (no de sus descendientes: hasta que exista
   * `descendantsOf`, Fase 2, el consumidor purga cada nodo del subárbol que
   * borra). No consulta el árbol: el scope puede ya no existir para el
   * resolutor. Debe demostrar que ESE conjunto quedó a cero o lanzar (500
   * `E_AUTHZ_PURGE_INCOMPLETE`): un borrado parcial silencioso deja hechos
   * huérfanos e indenegables. Los hechos de roles/permisos retirados del
   * catálogo no son membresía ni conceden nada (las lecturas filtran por el
   * catálogo, D5) y los recoge `authz:reconcile` (3b). La raíz no se purga
   * (422).
   */
  purgeScope(scope: ScopeRef): Promise<void>

  /**
   * Notificaciones del árbol del consumidor (`manager.scopes.*`), ya
   * validadas por el paquete (raíz, existencia del padre, ciclos). Un driver
   * que materializa el árbol como hechos propios (modo facts) las necesita;
   * `database` no (lee el árbol vía `resolveAncestors`). Opcionales.
   */
  onScopeAttached?(child: ScopeRef, parent: ScopeRef): Promise<void>
  onScopeMoved?(child: ScopeRef, newParent: ScopeRef): Promise<void>
  /** Se llama DESPUÉS de `purgeScope` (hechos primero, arista al final: S6). */
  onScopeDetached?(child: ScopeRef): Promise<void>
}

/**
 * Mapa morph name → tipo del modelo FGA (`users` → `user`). Lo consume el
 * driver `openfga` (subpath `@jantstack/adonis-authz/openfga`); vive en el
 * puerto para que `defineConfig` lo tipe sin importar el driver (D9).
 */
export type HolderTypeMap = Record<string, string>

/** Factory registrable en `config/authorization.ts`. */
export type AuthorizationDriverFactory = () => AuthorizationDriver | Promise<AuthorizationDriver>

/**
 * Resolutor de ancestros de un scope (del más cercano a la raíz). El paquete
 * NO conoce el dominio del consumidor: el chasis inyecta el suyo (que sabe de
 * organizations/organization_units) al construir cada driver y el manager.
 *
 * `null` significa "este scope no existe": el motor deniega (`authorize`/
 * `hasRole` → false) y rechaza escribir sobre él (`grant`/`deny` → 422
 * `E_AUTHZ_UNKNOWN_SCOPE`). Ya no hay default plano: un driver sin resolutor
 * solo conoce la raíz `app`, y cualquier otro tipo es 422
 * `E_AUTHZ_NO_SCOPE_RESOLVER` (L0.3). Un resolutor que devuelva `[APP_SCOPE]`
 * para lo que no conoce vuelve a abrir el defecto: es su responsabilidad no
 * hacerlo, y el vocabulario para no hacerlo es `null`. La raíz nunca se
 * pregunta: sus ancestros son `[]` por definición.
 */
export type ScopeAncestorsResolver = (scope: ScopeRef) => Promise<ScopeRef[] | null>

/**
 * Escritura del motor, notificada al hook `onWrite` del config. El chasis lo
 * usa para auditar/emitir SSE; un consumidor puede loguear, notificar, etc.
 */
export interface AuthzWriteEvent {
  /**
   * `extended`: un re-grant cambió la caducidad de una asignación que ya
   * existía (alargada, acortada o quitada) — lleva `previousExpiresAt`. Un
   * re-grant que no cambia nada sigue siendo `granted` (idempotente).
   * `scope_purged`: `scopes.detached` borró todos los hechos del scope; no
   * lleva `subject` (afecta a todos los holders del scope).
   */
  action: 'granted' | 'extended' | 'revoked' | 'denied' | 'deny_removed' | 'scope_purged'
  /** Ausente solo en `scope_purged`. */
  subject?: SubjectRef
  scope: ScopeRef
  /** Presente en granted/extended/revoked. */
  role?: string
  /** Presente en denied/deny_removed. */
  permission?: string
  /** Caducidad con la que queda la asignación (granted/extended). */
  expiresAt?: Date | null
  /** Caducidad que tenía antes (solo extended). */
  previousExpiresAt?: Date | null
  /**
   * `true` cuando la escritura venció el deadline (503 `E_AUTHZ_BACKEND_TIMEOUT`)
   * y el paquete NO sabe si el backend la aplicó: la petición puede aterrizar
   * después de que el llamante recibiera el error. Se notifica ANTES de
   * propagar el 503 para que la auditoría registre un resultado desconocido
   * en vez de un silencio (que se lee como "no pasó nada"). Un 503 que no es
   * timeout (conexión rechazada) no lo lleva: esa escritura no ocurrió.
   */
  indeterminate?: boolean
}

/* ── Catálogo (metadata compartida entre drivers) ─────────────────────────
 * Roles/permisos/vínculos viven en las tablas `authz_*` del chasis sea cual
 * sea el driver: con un backend externo (p.ej. OpenFGA) solo los HECHOS
 * (assignments/denies) se trasladan; el catálogo sigue siendo metadata local.
 */

export interface CatalogRoleSpec {
  /** UUID fijo opcional (mismo patrón que organization_acl: estable entre entornos). */
  uuid?: string
  slug: string
  /** Nivel al que este rol es asignable. */
  scopeType: ScopeType
  name?: string
  description?: string | null
  /**
   * Rango del rol (mayor = más privilegio). Lo usa la POLICY de asignación
   * del consumidor ("no puedes otorgar/quitar un rol de rango ≥ al tuyo");
   * el motor lo almacena como metadata pero no lo evalúa en authorize().
   */
  rank?: number
  /** Slugs de permisos (`recurso:accion`) que el rol concede. */
  permissions: string[]
}

export interface CatalogSpec {
  /** Todos los permisos del catálogo (formato `recurso:accion`). */
  permissions: Array<{ slug: string; description?: string | null }>
  roles: CatalogRoleSpec[]
}
