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
 *    es `[scope canónico, ...ancestros]` (`app` es la raíz: su cadena es él
 *    mismo); la identidad de un scope es la que devuelve el resolutor, nunca
 *    la forma con la que lo escribió el llamante (2.5-B · K1).
 *    Un grant en un scope autoriza en ese scope y en TODOS sus descendientes;
 *    nunca en hermanos ni ancestros. En T1 solo opera `app` (los ancestros de
 *    `organization`/`unit` se completan en T2/T3 vía `resolveChain`).
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
 * `ScopeChainResolver` que se inyecta a los drivers, así que el motor no
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

/**
 * Opciones comunes a TODA escritura del manager (`grant`, `revoke`, `deny`,
 * `removeDeny`, `scopes.*`) — 2.1, B7.
 */
export interface WriteOptions {
  /**
   * Quién ordena la escritura. Se valida como identidad (422 si está mal
   * formado) y viaja en `AuthzWriteEvent.actor` para que la auditoría del
   * consumidor no dependa de un `AsyncLocalStorage` que el paquete no tiene.
   * Con `requireActor: true` en el config, omitirlo es 422
   * `E_AUTHZ_ACTOR_REQUIRED` antes de tocar el driver. El motor NO lo evalúa:
   * quién puede conceder qué es policy del consumidor (invariante 8).
   */
  actor?: SubjectRef
}

/**
 * Opciones de las NUEVE escrituras del manager (`grant`, `revoke`, `deny`,
 * `removeDeny`, `scopes.attached/moved/detached` y, desde 3D · M3, la API de
 * delegación `defineScopedRole`/`updateScopedRole`/`deleteScopedRole`) —
 * 2.1, B1; 2D · F2.
 */
export interface ScopedWriteOptions extends WriteOptions {
  /**
   * Contención: el scope de la escritura tiene que estar DENTRO de `within`
   * (`within ∈ chain(scope)`, inclusive; `APP_SCOPE` contiene todo). Si no,
   * 422 `E_AUTHZ_NOT_WITHIN` y nada se escribe. Es lo que impide que el
   * administrador de la organización A conceda en una unit de B pasando un
   * uuid ajeno: el call-site declara "dentro de MI tenant" y el motor lo
   * comprueba contra el árbol, en fresco (nunca con el memo por request).
   * Qué scope se contrasta: el de `grant`/`revoke`/`deny`/`removeDeny`; el
   * PADRE (nuevo) Y la cadena ACTUAL del hijo en `scopes.moved` (origen y
   * destino, 2E · H1: notifica ANTES de recolgar tu fila), lo mismo en
   * `scopes.attached` cuando el hijo ya existe (es un move; un nodo nuevo
   * solo contrasta el padre); el propio hijo en `scopes.detached`; el OWNER
   * del rol en `defineScopedRole`/`updateScopedRole`/`deleteScopedRole`. Con
   * `requireWithin: true` en el config, omitirlo es 422
   * `E_AUTHZ_WITHIN_REQUIRED`; con `'non-root'`, además `APP_SCOPE` como
   * `within` es 422 `E_AUTHZ_WITHIN_ROOT_FORBIDDEN` (no acota nada).
   * `within` viene de la SESIÓN (el tenant autenticado), nunca del cuerpo
   * de la petición: `within = scope` satisface siempre por definición.
   */
  within?: ScopeRef
}

export interface GrantOptions extends ScopedWriteOptions {
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

/** Opciones de `deny` (2.1): contención y actor; sin caducidad (un deny que caduca es fail-open por reloj). */
export type DenyOptions = ScopedWriteOptions

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
 * Cómo se direcciona un rol en el puerto (`grant`, `revoke`, `hasRole`,
 * `listSubjects`).
 *
 *  - **string** (slug): en cada nivel de la cadena solo cuenta el rol de ESE
 *    nivel (el `owner` de app casa en app y hereda hacia abajo; un `owner` de
 *    organization jamás casa en app).
 *  - **`{ slug, scopeType }`**: el rol de un nivel concreto; solo los scopes
 *    de la cadena de ese tipo cuentan (L0.6).
 *  - **`{ uuid }`** (3D · M1): la forma EXACTA. Desde que un rol puede ser
 *    local a un scope (3B), el slug NO identifica un rol —dos tenants definen
 *    `lead@unit`— y un `scopes.moved` legítimo puede juntar dos homónimos en
 *    la misma cadena: entonces las dos formas por slug fallan cerradas con
 *    422 `E_AUTHZ_AMBIGUOUS_ROLE` y esta es la única que responde. El uuid
 *    tiene que estar en el catálogo (422 `E_AUTHZ_UNKNOWN_ROLE`) y ser
 *    visible en el scope de la operación —declarado para su nivel y global o
 *    con el owner en la cadena— (422 `E_AUTHZ_ROLE_NOT_VISIBLE`).
 */
export type RoleQuery = string | { slug: string; scopeType: ScopeType } | { uuid: string }

/** `RoleQuery` ya validado (`normalizeRoleQuery`): o nombre, o identidad; nunca las dos. */
export type NormalizedRoleQuery =
  | { slug: string; scopeType?: ScopeType; uuid?: undefined }
  | { uuid: string; slug?: undefined; scopeType?: undefined }

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
    role: RoleQuery,
    scope: ScopeRef,
    options?: GrantOptions
  ): Promise<GrantOutcome>

  /**
   * Quita la asignación del rol en ese scope exacto. El rol debe existir en
   * el catálogo para `scope.type` (422 si no, como `grant`); la asignación
   * puede no existir (no-op).
   */
  revoke(subject: SubjectRef, role: RoleQuery, scope: ScopeRef): Promise<void>

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
  listSubjects(role: RoleQuery, scope: ScopeRef): Promise<SubjectRef[]>

  /**
   * Roles (slugs) con asignación DIRECTA vigente del holder en ese scope
   * exacto. Es API de MEMBRESÍA y habla en slugs: desde 3B dos roles pueden
   * compartir `(slug, nivel)` con owners distintos, así que un slug de esta
   * lista puede no bastar para volver a direccionar el rol (`grant`/`hasRole`
   * responderían 422 `E_AUTHZ_AMBIGUOUS_ROLE`). La forma sin ambigüedad es
   * `{ uuid }`, y los uuids de la cadena los da `rolesInChain`.
   */
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
   * `database` no (lee el árbol vía `resolveChain`). Opcionales.
   */
  onScopeAttached?(child: ScopeRef, parent: ScopeRef): Promise<void>
  onScopeMoved?(child: ScopeRef, newParent: ScopeRef): Promise<void>
  /** Se llama DESPUÉS de `purgeScope` (hechos primero, arista al final: S6). */
  onScopeDetached?(child: ScopeRef): Promise<void>

  /**
   * Vista del driver que resuelve la CADENA con OTRO resolutor y comparte
   * todo lo demás (conexión, memo del catálogo, deadline). Opcional (2.1):
   * `AuthorizationManager.forRequest()` la usa para leer con un resolutor
   * memoizado por request; un driver que no la implemente sigue funcionando
   * (la vista lee con el driver tal cual, sin memo). Solo el camino de
   * lectura pasa por aquí: las escrituras del manager van al driver original.
   */
  withChainResolver?(resolveChain: ScopeChainResolver): AuthorizationDriver

  /**
   * Vista del driver que evalúa el TIEMPO con otro reloj (2.5 · J1) y
   * comparte todo lo demás. `now()` es el instante de pared con el que se
   * decide la caducidad —`expires_at > now` en SQL, `current_time` de cada
   * check de FGA, el filtro de caducidad de las enumeraciones y los tres
   * estados de `resolveGrantExpiry`—. Los sellos de auditoría (`created_at`)
   * NO lo usan (2.5-B · K5): no son decisiones.
   * Opcional: el manager lo aplica si el config trae `clock` (500
   * `E_AUTHZ_CONFIG` si el driver no lo implementa: un reloj que no llega al
   * driver mentiría). El juez lo usa con `injectableClock: true` para fijar
   * la caducidad exacta sin dormir.
   */
  withClock?(now: () => Date): AuthorizationDriver

  /**
   * Denies DIRECTOS vigentes del holder (2.1, B5): con `scope`, los de ese
   * scope exacto (sin herencia, invariante 7; scope desconocido ⇒ `[]`); sin
   * él, todos los del holder con su scope (los de scopes que el árbol ya no
   * conoce no se listan, D8). Solo permisos del catálogo (D5). Opcional:
   * ambos drivers del paquete lo implementan; sin él, `effectivePermissions`
   * y `authorizedScopes` lanzan 500 `E_AUTHZ_UNSUPPORTED` (nunca un `[]`
   * que significaría "sin denies": fail-open).
   */
  listDenies?(subject: SubjectRef, scope?: ScopeRef): Promise<DenyRef[]>

  /**
   * `authorize` sobre varios scopes, un booleano por posición (2.1, B6).
   * Opcional: el manager compone `Promise.all` de `authorize` sobre una
   * vista memoizada si el driver no lo trae; `openfga` lo implementa con UN
   * batchCheck para todos los scopes, correlacionado por id (L0.14). Misma
   * respuesta que N `authorize`; si una posición no se puede responder
   * (503), no se responde ninguna. Lista vacía ⇒ `[]` sin tocar el backend.
   */
  authorizeMany?(subject: SubjectRef, permission: string, scopes: ScopeRef[]): Promise<boolean[]>

  /**
   * Purga un ROL del catálogo con sus hechos (3B · B4): revoca TODAS sus
   * asignaciones en TODOS los scopes, borra sus vínculos rol→permiso y la
   * fila del rol, atómicamente, y sube la versión compartida del catálogo
   * (`withAuthzCatalogWrite`). Es lo que `deleteScopedRole` necesita: un rol
   * borrado sin sus asignaciones dejaría hechos huérfanos que resucitarían
   * al recrear el slug. `uuid` mal formado ⇒ 422 `E_AUTHZ_INVALID_IDENTITY`;
   * desconocido ⇒ 422 `E_AUTHZ_UNKNOWN_ROLE`. No distingue global de local
   * (esa barrera es del manager). Un driver que no pueda purgar (openfga
   * hasta 3b: sus bindings no se enumeran por rol) lo DICE con 500
   * `E_AUTHZ_UNSUPPORTED` y no toca nada — capacidad `purgeRole: false`.
   *
   * OPCIONAL en el puerto (3E · Q4): el manager ya lo trata como opcional
   * (`#optional` ⇒ 500 `E_AUTHZ_UNSUPPORTED` nombrándolo) y declararlo
   * obligatorio rompía al COMPILAR a todo driver de terceros escrito para
   * 2.0/2.1. Un driver que no lo trae no puede tener roles locales:
   * `defineScopedRole` lo dice antes de escribir nada (3E · P4).
   */
  purgeRole?(roleUuid: string): Promise<void>

  /**
   * Roles DIRECTOS vigentes del holder en cada scope de `chain` (2D · G5),
   * como pares `{ scope, role }`; solo roles que EXISTEN en ese scope (D5 +
   * 3B · B2: declarados para su nivel y visibles por owner desde ese nivel).
   * Opcional: es lo que `effectivePermissions` usa para leer los roles de
   * toda la cadena en UNA lectura; sin él, el manager compone N `listRoles`.
   * La cadena llega ya resuelta y validada.
   *
   * Devuelve `CatalogRoleRef` (uuid + slug + nivel + owner), no un slug (3D ·
   * M1): el manager usa el uuid tal cual y NUNCA vuelve del slug al catálogo
   * en el camino de policy. Volver del slug hacía que `effectivePermissions`
   * y `defineScopedRole` atribuyeran al holder los permisos de un homónimo
   * (auditor V1: escalada reproducida).
   */
  rolesInChain?(subject: SubjectRef, chain: ScopeRef[]): Promise<Array<{ scope: ScopeRef; role: CatalogRoleRef }>>
}

/**
 * Un subárbol excluido de un `all` (2.1, B3; tipo nominal desde 2D · F10):
 * el scope con el deny vivo Y todos sus descendientes. No es una lista de
 * scopes: un `NOT IN (uuids)` con solo `scope` seguiría listando las units
 * de una organización denegada. Expándelo con
 * `authorization.expandExcludedSubtrees(excluded)` (usa tu `descendantsOf`)
 * o resta el subárbol en tu propia consulta (CTE recursiva, `path LIKE`…).
 */
export interface ExcludedSubtree {
  scope: ScopeRef
  /** Siempre `true`: recuerda que lo excluido es el subárbol entero. */
  includesDescendants: true
}

/**
 * Respuesta de `authorizedScopes(subject, permission, scopeType)` (2.1, B3):
 *  - `none`: ningún scope de ese tipo;
 *  - `some`: exactamente estos (directos del tipo + descendientes vía
 *    `descendantsOf`, menos los que tienen un deny en su cadena), nunca más
 *    de `maxScopes`. Coherente con `authorize` scope a scope cuando
 *    `descendantsOf` y `resolveChain` describen el mismo árbol; si
 *    discrepan, lanza 503 `E_AUTHZ_RESOLVER_FAILED` (2D · F3);
 *  - `all`: hay un grant vigente en la raíz `app` (ancestro común de todo el
 *    tipo) — MENOS `excludedSubtrees`: los scopes con deny vivo del permiso,
 *    cada uno con su subárbol entero. Nunca `all` a secas con denies vivos
 *    (juez cruce 5, auditor E1): quien liste "todo" tiene que restar esto.
 */
export type AuthorizedScopes =
  | { kind: 'none' }
  | { kind: 'some'; scopes: ScopeRef[] }
  | { kind: 'all'; excludedSubtrees: ExcludedSubtree[] }

/** Un deny directo, tal como lo enumera `listDenies` (2.1). */
export interface DenyRef {
  permission: string
  scope: ScopeRef
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
 * Resolutor de la CADENA de un scope (2.5-B · K1): `[scope canónico,
 * ...ancestros]`, del más cercano a la raíz, con `app` al final. El paquete
 * NO conoce el dominio del consumidor: el chasis inyecta el suyo (que sabe de
 * organizations/organization_units) al construir cada driver y el manager.
 *
 * El elemento 0 es el PROPIO scope tal como está en la tabla del consumidor
 * (la fila leída), no tal como lo escribió el llamante: es la identidad con
 * la que el paquete lee y escribe todos los hechos. Un motor que canoniza
 * ids (el tipo `uuid` de PostgreSQL, una collation `*_ci`) puede encontrar
 * la fila para un alias (mayúsculas, guiones quitados); devolverla canónica es
 * lo que hace que el deny escrito con la forma real siga casando. Devolver
 * otro scope como elemento 0 es 503 `E_AUTHZ_RESOLVER_FAILED`.
 *
 * `null` significa "este scope no existe": el motor deniega (`authorize`/
 * `hasRole` → false) y rechaza escribir sobre él (`grant`/`deny` → 422
 * `E_AUTHZ_UNKNOWN_SCOPE`). Ya no hay default plano: un driver sin resolutor
 * solo conoce la raíz `app`, y cualquier otro tipo es 422
 * `E_AUTHZ_NO_SCOPE_RESOLVER` (L0.3). Un resolutor que devuelva `[scope,
 * APP_SCOPE]` para lo que no conoce vuelve a abrir el defecto: es su
 * responsabilidad no hacerlo, y el vocabulario para no hacerlo es `null`. La
 * raíz nunca se pregunta: su cadena es `[APP_SCOPE]` por definición.
 */
export type ScopeChainResolver = (scope: ScopeRef) => Promise<ScopeRef[] | null>

/**
 * Resolutor de DESCENDIENTES de un scope (2.1, B2): todos los nodos del
 * subárbol (cualquier tipo, cualquier profundidad), sin el propio scope y
 * sin orden exigido. Lo implementa el consumidor (o `sqlDescendantsOf`, el
 * helper opt-in del paquete): el paquete NO lo suple con N+1 llamadas a
 * `resolveChain`. `null` = scope desconocido. Más de `maxNodes` nodos ⇒
 * el consumidor lanza; si devuelve de más, lanza el manager (422
 * `E_AUTHZ_TOO_MANY_SCOPES`). Nunca se llama desde `authorize`/`hasRole`/
 * `list*` (test de arquitectura): solo desde `authorizedScopes`.
 */
/**
 * El árbol del consumidor hacia ABAJO (2.1): todos los descendientes de
 * `scope`, en cualquier orden y sin incluirlo. `null` = «este árbol no conoce
 * ese scope».
 *
 * Contrato con un scope que `resolveChain` YA NO conoce (3G · W2, auditor
 * pregunta 2): **el consumidor es la autoridad sobre su tabla y puede
 * devolver los hijos** (una ruta materializada, o un `where parent_id = X`,
 * no necesitan la fila del padre) **o `null`**; el paquete no asume ninguna
 * de las dos. La consecuencia está en `scopes.detached`: si el scope no
 * resuelve y por debajo no llega nada, la purga NO se puede declarar
 * completa (`ScopeDetachOutcome.truncated: true`). Y lo que se devuelva se
 * trata como el subárbol real: los roles de esos owners se purgan con la
 * policy de rango medida en la cadena de CADA owner (3G · W1), nunca en la
 * del scope notificado.
 *
 * Más de `maxNodes` nodos ⇒ el resolutor puede devolver la lista larga (el
 * paquete la caza con 422 `E_AUTHZ_TOO_MANY_SCOPES`) o lanzar; en
 * `authorizedScopes` eso es un 422 y en `scopes.detached`/`defineScopedRole`
 * DEGRADA (3F · S2, y ver el aviso de `#assertLevelUnderOwner`).
 */
export type ScopeDescendantsResolver = (
  scope: ScopeRef,
  options: { maxNodes: number }
) => Promise<ScopeRef[] | null>

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
  /**
   * Quién ordenó la escritura (2.1, B7): lo que el llamante pasó en
   * `WriteOptions.actor`, ya validado. Ausente si no lo pasó.
   */
  actor?: SubjectRef
  /**
   * Presente en granted/extended/revoked: el/los rol(es) RESUELTOS (3E · Q7,
   * auditor A8), con `uuid`, `slug`, nivel y owner — no la pregunta cruda.
   *
   * En 1.x era `role: string` (el slug) y en 3D pasó a `RoleQuery`: un sink
   * de auditoría que filtraba por slug dejó de casar EN SILENCIO, que es una
   * pérdida de auditoría, no solo de tipos. Con la forma resuelta el sink
   * vuelve a tener el slug —`event.roles.some((r) => r.slug === 'admin')`— y
   * además el uuid, que es lo único que identifica un rol desde 3A.
   *
   * Es una LISTA porque un `revoke` por slug quita los hechos de TODOS los
   * homónimos visibles en el scope (3B); un `grant` resuelve exactamente uno
   * (con dos sería 422 `E_AUTHZ_AMBIGUOUS_ROLE`). Ausente si el rol no se
   * pudo resolver (scope que el árbol no conoce, rol fuera del catálogo): el
   * driver decidirá el resultado, y el evento no inventa.
   */
  roles?: CatalogRoleRef[]
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
  /**
   * Solo en `scope_purged`: el árbol ya NO conoce el scope notificado —el
   * consumidor borró su fila y avisa después, que es el orden que el paquete
   * admite— o alguno de los roles purgados tenía un owner que tampoco
   * resuelve (3F · S1; 3G · W1/W2). `'owner-detached-unknown'` significa dos
   * cosas a la vez, y las dos importan a quien audita: (a) la purga procede
   * igual —bloquearla dejaba vivos el rol, sus asignaciones y los denies de
   * un scope borrado (auditor N2), sin ninguna salida con `requireActor:
   * true`— y (b) para ESOS roles —los que no tienen dónde medir el rango— la
   * policy de 3E · P3 no se pudo evaluar. Para los demás sí se evalúa: el
   * rango se mide en la cadena del OWNER de cada rol (3G · W1), así que un
   * `detached` de un ancestro desconocido ya NO destruye los roles de
   * descendientes vivos. Sale también con `purgedRoles: 0`.
   */
  reason?: 'owner-detached-unknown'
  /**
   * Solo en `scope_purged`: la purga de roles se acotó al scope EXACTO
   * porque el subárbol no se pudo enumerar (3F · S2). Ver
   * `ScopeDetachOutcome.truncated`.
   */
  truncated?: true
}

/**
 * Lo que devuelve `scopes.detached` (3F · S1/S2). Hasta 3E era `void` y no
 * había forma de saber si la purga alcanzó a todo el subárbol ni si la
 * policy de rango se llegó a evaluar.
 */
export interface ScopeDetachOutcome {
  /** Roles LOCALES purgados (los del scope y, con `descendantsOf`, los del subárbol). */
  purgedRoles: number
  /**
   * `true` cuando el subárbol NO se pudo enumerar (más de `maxDescendants`,
   * o un `descendantsOf` que falló) y la purga se acotó al scope EXACTO
   * (3F · S2). Degradar en vez de tumbar la operación es la regla: declarar
   * `scopes.descendantsOf` nunca puede dejarte peor que no declararlo, y
   * hasta 3E un subárbol grande dejaba el `detached` en 503 sin purgar ni
   * los roles ni los hechos (auditor N3). Los roles que quedan abajo no son
   * visibles en ninguna parte —su owner ya no cuelga del árbol—, pero siguen
   * ocupando su `(slug, nivel)`: hay que volver a notificar nodo a nodo o
   * subir la cota.
   *
   * También es `true` cuando el árbol ya NO conoce el scope y `descendantsOf`
   * no devolvió nada debajo (3G · W2, auditor P2): el puerto no le exige
   * responder por un scope que `resolveChain` desconoce —puede devolver sus
   * hijos o `null`, ver `ScopeDescendantsResolver`—, así que un vacío ahí no
   * demuestra que debajo no quedara nada. Decir `truncated: false` era
   * afirmar «purga completa» con el rol de la unit hija vivo y concediendo.
   */
  truncated: boolean
  /**
   * Igual que en `AuthzWriteEvent`: el scope notificado (o el owner de algún
   * rol purgado) ya no está en el árbol, así que para esos roles la policy
   * de rango no se pudo evaluar. Presente aunque `purgedRoles` sea 0.
   */
  reason?: 'owner-detached-unknown'
}

/* ── Catálogo (metadata compartida entre drivers) ─────────────────────────
 * Roles/permisos/vínculos viven en las tablas `authz_*` del chasis sea cual
 * sea el driver: con un backend externo (p.ej. OpenFGA) solo los HECHOS
 * (assignments/denies) se trasladan; el catálogo sigue siendo metadata local.
 *
 * Desde 3B (2.2) un rol tiene un OWNER: `global` (declarado en el config y
 * sincronizado con `syncAuthzCatalog`) o la clave del scope que lo definió
 * con `defineScopedRole` (`<tipo>|<uuid>`). Regla única de visibilidad: una
 * asignación en el scope S del rol R cuenta si y solo si R es global o su
 * owner está en chain(S) (S inclusive). Un rol local solo existe dentro de
 * su owner: fuera no concede, no es membresía y no se puede asignar (422
 * `E_AUTHZ_ROLE_NOT_VISIBLE`).
 */

/** Un rol del catálogo tal como lo ve el motor (3A · A2/A3, 3B · B2). */
export interface CatalogRole {
  /** Identidad interna: lo que llevan `authz_assignments.role_uuid` y los ids de binding de FGA. */
  uuid: string
  slug: string
  scopeType: ScopeType
  /** `'global'` o `scopeKey(owner)` (`<tipo>|<uuid>`): el contenedor fuera del cual el rol no existe. */
  owner: string
  /** Metadata de policy (invariante 8): el motor no lo evalúa en `authorize`. */
  rank: number
}

/**
 * La IDENTIDAD pública de un rol sin su metadata de policy (3D · M1): lo que
 * devuelve `rolesInChain` y lo que el memo usa para filtrar por owner. El
 * uuid manda; el slug viaja como etiqueta legible.
 */
export interface CatalogRoleRef {
  slug: string
  uuid: string
  scopeType: ScopeType
  /** `'global'` o `scopeKey(owner)`. */
  owner: string
}

export interface CatalogPermissionSpec {
  /** Formato `recurso:accion`. */
  slug: string
  description?: string | null
  /**
   * Niveles (scope types) cuyos roles PUEDEN llevar este permiso (3B · B5):
   * omitido = cualquiera. Es un control de COMPOSICIÓN: `syncAuthzCatalog`,
   * `defineScopedRole`/`updateScopedRole` y `grant` rechazan (422
   * `E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT`) un rol de otro nivel que lo lleve;
   * `authorize` NO lo mira (invariante 1: lo ya asignado sigue concediendo).
   * Es lo que cubre «un rol de unit no puede llevar org:settings» sin romper
   * la herencia hacia abajo (panel 2026-08-28, H).
   */
  assignableAt?: ScopeType[]
}

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
  permissions: CatalogPermissionSpec[]
  /** Roles GLOBALES (owner `global`): un spec nunca declara roles locales. */
  roles: CatalogRoleSpec[]
}

/**
 * Un rol LOCAL a un scope, tal como lo define `defineScopedRole(actor,
 * ownerScope, spec)` (3B · B3). Sin `uuid` (lo genera el motor) y con `rank`
 * OBLIGATORIO: `0 < rank < min(rank del actor, rank máximo global)`.
 */
export interface ScopedRoleSpec {
  slug: string
  /** Nivel al que el rol es asignable (dentro del owner). Nunca `app`. */
  scopeType: ScopeType
  name?: string
  description?: string | null
  rank: number
  /** Slugs de permisos: ⊆ `config.delegablePermissions` ∩ efectivos del actor en el owner. */
  permissions: string[]
}

/** Lo que `updateScopedRole` puede cambiar de un rol local: nunca su slug, nivel ni owner. */
export interface ScopedRoleChanges {
  name?: string
  description?: string | null
  rank?: number
  permissions?: string[]
}

/**
 * Escritura del CATÁLOGO por la API de delegación (3B · B3), notificada al
 * hook `onCatalogWrite` del config. Siempre lleva `actor` (la API lo exige)
 * y el rol tal como queda (`role_purged`: tal como estaba).
 */
export interface AuthzCatalogWriteEvent {
  action: 'role_defined' | 'role_updated' | 'role_purged'
  /**
   * Quién lo ordenó. La API de delegación lo exige siempre; ausente solo en
   * los `role_purged` que arrastra `scopes.detached` (3D · M4), donde el
   * actor es el `WriteOptions.actor` de esa notificación del árbol y puede
   * no venir.
   */
  actor?: SubjectRef
  role: CatalogRole
  /** El scope owner del rol (`scopeFromKey(role.owner)`). */
  owner: ScopeRef
  /** Permisos con los que queda el rol (o tenía, si se purga). */
  permissions: string[]
  /**
   * Solo en `role_defined` (3F · S3): los roles LOCALES de un DESCENDIENTE
   * del owner con ese mismo `(slug, nivel)` que el nuevo acaba de
   * ENSOMBRECER. La autoridad manda —global > local de un ancestro > local
   * de un descendiente—, así que el dueño del árbol siempre puede definir su
   * rol aunque alguien de abajo le haya ocupado el nombre; dentro del
   * subárbol de esos owners toda ruta por slug pasa a 422
   * `E_AUTHZ_AMBIGUOUS_ROLE` (se opera por `{ uuid }`) hasta que se purgue
   * uno. Es el mismo trato que `shadowedByGlobal` en el sync, y como allí:
   * se REPORTA, nunca en silencio.
   */
  shadowedByAncestor?: CatalogRoleRef[]
}
