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
  /**
   * **La transacción ABIERTA del consumidor** (`TransactionClientContract` de
   * Lucid: el `trx` de `db.transaction()`), para que la escritura del paquete
   * confirme o revierta CON la tuya — L-2, panel `{trx}` (C).
   *
   * **Encolar ≠ escribir.** Son dos promesas distintas y este campo hace UNA
   * u OTRA según la operación:
   *
   *  - En `grant`/`revoke`/`deny`/`removeDeny` (los HECHOS) significa
   *    **ESCRIBIR en tu transacción**: «los dos o ninguno» entre el hecho y
   *    tus filas, en el mismo motor transaccional. Solo lo cumple un driver
   *    que declare `capabilities.transactionalWrites: true` (`database`, con el
   *    `trx` de SU conexión: otra conexión, un `QueryClient` o el `db` entero
   *    son 500 `E_AUTHZ_CONFIG`, `assertCallerTransaction`). Con un driver
   *    que declare `false` —`openfga`: una tupla no entra en una transacción
   *    SQL, no hay 2PC— la llamada es **500 `E_AUTHZ_UNSUPPORTED`** nombrando
   *    driver y operación, **antes de tocar el driver** (cero llamadas):
   *    nunca se ignora, nunca un aviso. Quien quiera fallar al ARRANCAR en
   *    vez de en una ruta poco transitada declara `requireTransactionalWrites:
   *    true` en el config (500 `E_AUTHZ_CONFIG` al resolver el driver).
   *  - En `scopes.attached/moved/detached` significa **ENCOLAR en tu
   *    transacción** (3b-2d, `ScopeTreeWriteOptions.transaction`): el INSERT
   *    de la outbox cae dentro de ella; el backend NO se toca dentro de tu
   *    transacción y no pasa por la puerta de la capacidad.
   *  - En la API de delegación (`defineScopedRole`/`updateScopedRole`/
   *    `deleteScopedRole`) **no se admite** (500 `E_AUTHZ_UNSUPPORTED`): esas
   *    escriben el catálogo por `withAuthzCatalogWrite`, que ES el
   *    serializador entre procesos (cerrojo + bump como última sentencia,
   *    invariante 14); moverlas al commit del consumidor lo anularía.
   *
   * Lo que NUNCA viaja por ella, en ninguna de las tres: **la autoridad**
   * (L-1 · 🟠 8) — la barrera del freeze, el catálogo y `resolveChain` se leen
   * por la conexión del motor, así que `{ transaction }` exige **pool ≥ 2**.
   */
  transaction?: unknown
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

/**
 * Opciones de las TRES notificaciones del árbol (`scopes.attached/moved/
 * detached`) — 3b-2d. Añaden la transacción del consumidor, que solo se usa
 * cuando hay `scopes.outbox` declarada: es lo que hace que el cambio del
 * árbol y su encolado confirmen (o se vayan) juntos.
 */
export interface ScopeTreeWriteOptions extends ScopedWriteOptions {
  /**
   * La transacción ABIERTA del consumidor (`TransactionClientContract` de
   * Lucid, o lo que use su outbox). El paquete no la interpreta: se la pasa
   * tal cual a `scopes.outbox.enqueue` para que el INSERT del encolado caiga
   * dentro de ella — **ENCOLAR, no escribir**: el backend no se toca dentro
   * de tu transacción. Sin outbox declarada no hace nada; con outbox declarada
   * y sin transacción, el encolado se confirma solo y vuelve a haber dos
   * confirmaciones distintas (la outbox lo avisa si puede).
   *
   * **Lo que NUNCA viaja por ella: la autoridad** (L-1 · 🟠 8). La barrera
   * del freeze se lee por la conexión del motor, jamás por esta transacción
   * (su snapshot puede ser anterior al freeze). Por eso exige **pool ≥ 2**:
   * con pool 1 (SQLite `:memory:`) la barrera no consigue conexión mientras
   * tú sostienes la única y la notificación sale 503 `E_AUTHZ_BACKEND_TIMEOUT`
   * (`freezeTimeoutMs`) — fail-closed, nunca un bypass. Y `sqlScopeOutbox`
   * exige que sea una transacción ABIERTA de SU conexión: otra conexión, un
   * `QueryClient` o el `db` entero son 500 `E_AUTHZ_CONFIG` (🟠 9).
   *
   * **Encolar ≠ escribir** (L-2): aquí la transacción ENCOLA; en
   * `grant`/`revoke`/`deny`/`removeDeny` (`WriteOptions.transaction`) ESCRIBE
   * el hecho dentro de ella y pasa por la puerta de `transactionalWrites`.
   * Esta notificación no pasa por esa puerta: un driver `openfga` la acepta.
   */
  transaction?: unknown
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

/**
 * **Lo que un driver DECLARA de sí mismo** (3b-2e · E2). No es documentación:
 * el manager lo LEE (el gate de deriva del árbol, E3) y la suite de contrato
 * exige a cada capacidad su caso —el del valor declarado, nunca un `skip`—.
 *
 * Todas son opcionales de declarar (un driver de 2.x que no traiga
 * `capabilities` se trata como todo `false`), pero declarar `true` lo que no
 * se cumple es una promesa sin juez: el contrato lanza al registrarse.
 */
export interface AuthorizationDriverCapabilities {
  /**
   * El ÁRBOL de scopes vive como hechos del backend y el backend es el PDP
   * (`openfga` con `hierarchy: 'facts'`). Con `true` el manager exige la
   * mitigación de la deriva (`scopes.outbox` o la firma explícita): el árbol
   * está en dos sitios y un `rollback` del consumidor deja al backend
   * adelantado (cruce 4 · S5).
   */
  hierarchyFacts: boolean
  /**
   * `authorize` es UNA sola llamada al backend: no consulta el árbol del
   * consumidor (`resolveChain`) y el catálogo solo a través del memo.
   */
  singleCheckAuthorize: boolean
  /**
   * El backend resuelve la MEMBRESÍA por sí mismo. **`false` en los dos
   * drivers del paquete, también en `facts`** (panel 2, cruce 6): `hasRole`,
   * `listRoles`, `listRoleScopes`, `listSubjects` y `listScopes` siguen
   * usando `resolveChain`. Por eso el titular «sin SQL en el camino caliente»
   * está PROHIBIDO a secas: lo cierto es «sin SQL por request en `authorize`».
   */
  roleInheritanceNative: boolean
  /**
   * Los `list*` enumeran también lo HEREDADO. **`false` siempre en este
   * paquete** (invariante 7): enumerar descendientes sería abierto, y en
   * `openfga` además obligaría a `ListObjects`, que trunca al tope del
   * servidor sin ninguna señal (S16). Los `list*` devuelven hechos DIRECTOS.
   */
  listObjectsInherited: boolean
  /** El driver implementa `purgeRole` de verdad (sin él no hay roles locales). */
  purgeRole: boolean
  /**
   * El driver sabe CONTAR los hechos vigentes de un rol
   * (`countRoleAssignments`, 3b-2j). Es lo que hace verdadero el
   * `stillGranting` de `pruneOrphanRoles`, que se lee justo antes de un
   * borrado destructivo. Con `false` el barrido no lo sabe y lo dice
   * (`undefined`), nunca `false`: «no lo sé» no puede degradar a «no
   * concede».
   */
  countRoleAssignments: boolean
  /**
   * Las LECTURAS canonizan la ortografía del scope contra el árbol del
   * consumidor antes de buscar los hechos (3b-2k · K1 · R2 (c)). Con `true`
   * (driver `database`) `authorize` resuelve la cadena y usa `chain[0]`, la
   * identidad canónica (invariante 17), así que un alias del uuid que TU
   * tabla funde con la fila real —una columna `uuid` de PostgreSQL, una
   * collation `*_ci` de MySQL— encuentra los mismos hechos. Con `false`
   * (`openfga` en modo `facts`) la decisión no pasa por el árbol —es la
   * contrapartida de `singleCheckAuthorize`— y el objeto del store se compone
   * con la ortografía del LLAMANTE: un alias responde `false` donde la forma
   * canónica concede. Es fail-CLOSED y no evade ningún deny, pero no es la
   * misma respuesta: **pasa los uuids exactamente como los guarda tu tabla**.
   * La ESCRITURA canoniza en los dos (3b-2h · 🟠 3).
   */
  canonicalScopeReads: boolean
  /**
   * El driver sabe ser el **ORIGEN** de una migración: implementa
   * `enumerateFacts` y entrega sus hechos paginados, sin filtrar y con su
   * caducidad (3b-3b). Con `true` es lo que `authz:reconcile --to=<otro>`
   * pasa como `source.facts`. Con `false` el driver no puede ser origen por
   * el puerto y `authz:reconcile` lo DICE (500 `E_AUTHZ_UNSUPPORTED`
   * nombrando `enumerateFacts`), nunca una migración vacía en silencio — que
   * es exactamente el fail-dangerous que se evita: un origen que devuelve
   * cero hechos y un `--prune` detrás borran el destino entero.
   *
   * **`false` en el driver `database` a propósito**: sus hechos son
   * `authz_assignments`/`authz_denies`, el esquema publicado del paquete, y
   * el destino los lee de ahí directamente (`openfga.reconcile`).
   */
  enumerateFacts: boolean
  /**
   * El driver puede inscribir sus escrituras en la transacción del consumidor
   * (`{ transaction }` en `grant`/`revoke`/`deny`/`removeDeny`). `true`
   * significa EXACTAMENTE «los dos o ninguno con TU transacción», nunca «no
   * se pierde». `database` = true (con el `trx` de SU conexión; L-3).
   * `openfga` = false, y no puede ser otra cosa: una tupla no entra en una
   * transacción SQL — el store es otro servicio y no hay 2PC. No hay valor
   * intermedio y no se publica ninguno (panel `{trx}`, veredicto (C)).
   *
   * Dos puertas la hacen verdad: con `false`, `{ transaction }` es 500
   * `E_AUTHZ_UNSUPPORTED` por llamada, con cero llamadas al driver; y con
   * `requireTransactionalWrites: true` en el config un driver `false` es 500
   * `E_AUTHZ_CONFIG` al RESOLVER (el despliegue no arranca). **Mismo nombre
   * en `RelationsDriverCapabilities`**: un driver de terceros no aprende dos.
   *
   * `database` la cumple desde L-3: la ESCRITURA (y la lectura «¿ya existe?»
   * que forma parte de ella) va por la transacción ABIERTA del llamante
   * (`assertCallerTransaction` contra la conexión primaria de Lucid); la
   * AUTORIDAD (barrera del freeze, catálogo, `resolveChain`) nunca — por eso
   * exige pool ≥ 2, y un despliegue con pool 1 declara `false` en las opciones
   * del driver. Un choque del UNIQUE dentro de la transacción del llamante es
   * 409 `E_AUTHZ_WRITE_CONFLICT` («envenena tu transacción»); un deadline
   * vencido ahí sigue siendo `indeterminate: true` y el evento lleva
   * `transactional: true`.
   */
  transactionalWrites: boolean
}

export interface AuthorizationDriver {
  /** Lo que este driver declara poder hacer (3b-2e · E2). Ver `AuthorizationDriverCapabilities`. */
  readonly capabilities?: AuthorizationDriverCapabilities

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
  revoke(subject: SubjectRef, role: RoleQuery, scope: ScopeRef, options?: WriteOptions): Promise<void>

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
  deny(subject: SubjectRef, permission: string, scope: ScopeRef, options?: WriteOptions): Promise<void>

  /**
   * Levanta el deny en ese scope exacto. El permiso debe existir en el
   * catálogo (422 si no, como `deny`); el deny puede no existir (no-op).
   */
  removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef, options?: WriteOptions): Promise<void>

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
   * Cuántos hechos VIGENTES tiene cada rol, en TODOS los scopes (3b-2j,
   * decisión del dueño del 2026-08-31 (3)). Un hecho es una asignación del
   * rol a un holder que no ha caducado (`expiresAt` nulo o futuro, con el
   * reloj del driver); el rol se identifica por su uuid y la respuesta va
   * POR POSICIÓN, como `authorizeMany`. Un rol sin hechos —o que el backend
   * no conoce— es `0`; `uuid` mal formado ⇒ 422 `E_AUTHZ_INVALID_IDENTITY`.
   *
   * Es lo que `pruneOrphanRoles` (`authz:catalog:prune-orphans`) necesita
   * para decir si un rol huérfano TODAVÍA CONCEDE, y es una pregunta del
   * PUERTO porque los hechos son del driver: hasta 3b-2j el barrido contaba
   * filas de `authz_assignments` —la tabla del driver `database`— y con
   * `openfga` en modo `facts`, donde viven en el store, decía siempre que
   * no. El campo se lee justo antes de un borrado destructivo y su contrato
   * publicado es «falso ⇒ este rol seguro que no concede», así que ese
   * `false` era fail-dangerous.
   *
   * Es CONSERVADOR a propósito: cuenta hechos, no comprueba si el scope de
   * cada uno sigue resolviendo. Cero ⇒ no concede seguro; más de cero ⇒
   * míralo antes de purgar.
   *
   * OPCIONAL en el puerto (**breaking para un driver de 2.2 que no lo
   * traiga**, y por eso opcional y no obligatorio): sin él
   * `pruneOrphanRoles` deja `assignments` y `stillGranting` en `undefined`
   * —jamás en `false`— y el comando lista esos roles APARTE, como los que sí
   * conceden. Capacidad `countRoleAssignments`.
   */
  countRoleAssignments?(roleUuids: string[]): Promise<number[]>

  /**
   * Rehace la **proyección derivada** del catálogo para UN rol (3b-2e · E4).
   * Opcional: solo la implementa un driver que mantenga esa proyección (el
   * `openfga` en modo `facts`, donde lo que un rol concede son tuplas y no
   * el catálogo local). El manager la llama después de `defineScopedRole` y
   * `updateScopedRole` —las dos escrituras de catálogo que cambian los
   * vínculos de un rol fuera de `syncAuthzCatalog`—, porque si no un rol
   * recién definido no concedería NADA y un rol al que se le quita un permiso
   * lo seguiría concediendo (fail-open). En `database` no existe: el catálogo
   * es la fuente y no hay espejo que rehacer.
   */
  projectCatalogRole?(roleUuid: string): Promise<void>

  /**
   * La **proyección derivada del catálogo entero** de este driver (3b-2a ·
   * A5), para inyectarla en `syncAuthzCatalog`/`syncCatalogs`. Opcional por
   * el mismo motivo que `projectCatalogRole`: solo la trae un driver que
   * mantenga un espejo del catálogo en su backend (el `openfga` en modo
   * `facts`).
   *
   * Está en el PUERTO porque el camino de recuperación documentado —«un
   * `authz:catalog:sync` reescribe la proyección»— lo ejecuta un comando que
   * solo ve `AuthorizationDriver` (3b-8 · A1): sin esto, el CLI sincronizaba
   * `authz_*` y dejaba el espejo del store SIN TOCAR, o sea que en `facts`
   * un permiso quitado del catálogo seguía concediendo y un rol nuevo no
   * concedía nada.
   */
  catalogProjection?(): CatalogProjection

  /**
   * **Reconstruye el estado de ESTE driver desde `authz_*` + el árbol del
   * consumidor** (3b-3a). Es lo que hay detrás de `authz:reconcile --to=<este
   * driver>`: hechos, árbol y proyección del catálogo, idempotente
   * (la segunda pasada escribe cero), reanudable por lotes con cursor y
   * **nunca silenciosa** (el reporte cuenta lo escrito, lo actualizado, lo
   * igual, lo que sobra, lo borrado y lo que NO se migró con su motivo).
   *
   * `dryRun` es el VERIFICADOR: mismo recorrido, cero escrituras. Es
   * **read-only por contrato** (panel 2, cruce 4 · S18) — un `--fix` sería un
   * mecanismo de concesión y queda PROHIBIDO.
   *
   * Opcional en el puerto: un driver que no lo trae dice «no sé
   * reconstruirme» y el manager responde 500 `E_AUTHZ_UNSUPPORTED` nombrando
   * el método, nunca una migración a medias en silencio. El driver
   * `database` NO lo implementa: sus tablas SON el origen, y llenarlas desde
   * un store es la otra dirección (3b-3b).
   */
  reconcile?(source: ReconcileSource, options: ReconcileOptions): Promise<ReconcileReport>

  /**
   * **Los hechos de ESTE driver, paginados, para que otro se reconstruya
   * desde ellos** (3b-3b). Es la otra mitad de `reconcile`: `reconcile` es
   * ser el DESTINO de `authz:reconcile`, `enumerateFacts` es ser el ORIGEN.
   *
   * Contrato: como mucho `limit` hechos por página (más ⇒ 500), orden total
   * y estable, cursor opaco que tiene que AVANZAR (repetirlo ⇒ 500, jamás un
   * bucle), y **nada se filtra**: una asignación caducada sale con su
   * `expiresAt` para que el destino la cuente en `skipped` con su motivo. Lo
   * que el origen no sabe expresar como hecho del puerto sale en `skipped`
   * de la página, nunca descartado en silencio.
   *
   * Opcional: capacidad `enumerateFacts`. El driver `database` **no lo
   * trae** a propósito — sus hechos son `authz_assignments`/`authz_denies`,
   * el esquema publicado del paquete, y el destino los lee de ahí (es lo que
   * hace `openfga.reconcile`). Un driver de terceros que quiera migrar
   * DESDE otro sitio sí lo necesita.
   */
  enumerateFacts?(page: { limit: number; after?: string }): Promise<ReconcileFactPage>

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
/* ── `authz:reconcile` (3b-3a) ──────────────────────────────────────────── */

/**
 * Lo que el manager le presta al driver para reconciliar: el árbol del
 * consumidor (entero y paginado) y su resolutor. El driver pone lo suyo —qué
 * hechos guarda y cómo—; el paquete no le dice cómo migrar, le da la FUENTE.
 */
export interface ReconcileSource {
  enumerateEdges: ScopeEdgesEnumerator
  resolveChain: ScopeChainResolver
  /**
   * Los HECHOS del origen, paginados (3b-3b). Solo hace falta en la
   * dirección en la que el origen NO es `authz_*`: `--to=database` los lee
   * del store con este enumerador, mientras que `--to=openfga` lee las
   * tablas del paquete directamente (son su propio esquema publicado, no el
   * secreto de un driver).
   *
   * Es **perezoso a propósito**: el manager solo resuelve el driver de
   * ORIGEN cuando el destino lo pide, así que una migración que no necesita
   * hechos del puerto no construye nada. Sin origen que lo implemente, la
   * primera llamada es 500 `E_AUTHZ_UNSUPPORTED` nombrando `enumerateFacts`.
   */
  facts?: ReconcileFactsEnumerator
  /**
   * **Quién es la FUENTE DE VERDAD de los hechos en esta pasada** (3b-5, los
   * dos 🔴 del auditor final). Lo decide el MANAGER, que es el único que sabe
   * qué driver está sirviendo (`config.default`) y qué declara cada uno
   * (`capabilities.hierarchyFacts`), y el destino lo OBEDECE.
   *
   * Sin esto, `--to=openfga` leía siempre `authz_assignments`/`authz_denies`,
   * y en un despliegue `hierarchy: 'facts'` esas tablas **no son** la fuente
   * de verdad de los hechos —lo son las tuplas del store—: la pasada
   * reescribía lo revocado después del cutover, `--prune` borraba los denies
   * vivos y el barrido de visibilidad del invariante 18 no se aplicaba nunca
   * (`forbidden` salía vacío porque `wanted.facts` salía vacío).
   *
   *  - `authzTables: true` ⇒ los hechos son las tablas del paquete y el
   *    destino las lee él mismo (es la MIGRACIÓN `database` → `openfga`);
   *  - `authzTables: false` ⇒ los hechos llegan por el PUERTO (`facts`,
   *    `enumerateFacts`) del origen `name`, que puede ser **el propio
   *    destino** cuando el destino es el driver ACTIVO y sus hechos son
   *    suyos (la pasada de MANTENIMIENTO: rehace lo derivado —marcador,
   *    catálogo, árbol y visibilidad— y no inventa ni borra un solo hecho).
   *
   * Ausente = `{ name: 'authz_*', authzTables: true }`: el comportamiento de
   * 3b-3a, que es el que vale cuando el origen es el esquema publicado.
   */
  factsOrigin?: ReconcileFactsOrigin
}

/** Ver `ReconcileSource.factsOrigin` (3b-5). */
export interface ReconcileFactsOrigin {
  /** Cómo se NOMBRA el origen en el reporte (clave de `drivers`, o `authz_*`). */
  name: string
  /** `true` ⇒ los hechos son `authz_assignments`/`authz_denies` y los lee el destino. */
  authzTables: boolean
}

/**
 * Un hecho del ORIGEN en el vocabulario del PUERTO, no en el del backend
 * (3b-3b). Es lo que un driver entrega cuando le toca ser el origen de una
 * migración: el destino no sabe si detrás hay tuplas, filas o un fichero.
 *
 * La identidad del rol es el **uuid** (3D · M1), nunca el slug: dos owners
 * definen `lead@unit` y el slug no identifica nada. La del permiso es el
 * **slug**, que es lo que el catálogo local sabe traducir a uuid.
 */
export interface ReconcileFact {
  kind: 'assignment' | 'deny'
  holder: SubjectRef
  /** El scope tal como lo guarda el ORIGEN; el destino lo canoniza con SU árbol. */
  scope: ScopeRef
  /** `assignment`: uuid del rol. */
  roleUuid?: string
  /** `deny`: slug del permiso. */
  permission?: string
  /**
   * `assignment`: la caducidad tal como está guardada, **sin filtrar**. Una
   * caducada tiene que LLEGAR para poder contarse en `skipped` con su motivo;
   * un origen que la filtre por su cuenta la haría desaparecer en silencio,
   * que es justo lo que la migración no puede hacer.
   */
  expiresAt?: Date | null
  /** Cómo lo nombra el origen (para `details`): un motivo sin la fila no se arregla. */
  detail: string
}

/**
 * Una página de hechos del origen. `cursor` es opaco y tiene que AVANZAR
 * (repetirlo ⇒ 500, nunca un bucle); `skipped` es lo que el ORIGEN no supo
 * expresar como hecho del puerto (basura de otra versión, un holder type que
 * el config no declara…) y que el destino suma a su reporte.
 */
export interface ReconcileFactPage {
  facts: ReconcileFact[]
  skipped?: ReconcileSkip[]
  cursor?: string
}

export type ReconcileFactsEnumerator = (page: {
  limit: number
  after?: string
}) => Promise<ReconcileFactPage>

export interface ReconcileOptions {
  /** Mismo recorrido, CERO escrituras. Es el verificador (read-only por contrato). */
  dryRun?: boolean
  /**
   * Borra del destino los HECHOS que el origen no respalda: los de un scope
   * que ya no resuelve (3b-0b · AA4, «resurrección») y los que sobran (un
   * store escrito por una versión anterior). Sin él se REPORTAN y no se
   * borran. Lo derivado —marcador de raíz, proyección del catálogo y árbol—
   * se rehace siempre: es un espejo de datos locales que nadie más escribe.
   */
  prune?: boolean
  /** La salida humana de `E_AUTHZ_MASS_RECONCILE_REFUSED`. */
  allowMassDelete?: boolean
  /** Filas por lote en las lecturas del origen y por `Write` en el destino (default 100). */
  batchSize?: number
  /**
   * **La cota del volcado del destino** (3b-3b · B5). Reconciliar exige
   * comparar contra el estado ENTERO del destino, y ese volcado entra en
   * memoria: el ORIGEN se lee por lotes con cursor, el destino no. En vez de
   * dejarlo como una sorpresa (un OOM en producción), se declara: pasar de
   * `maxTuples` es 500 `E_AUTHZ_RECONCILE_TOO_LARGE` **antes de escribir
   * nada**, nombrando la cota y cómo subirla. Default
   * `DEFAULT_RECONCILE_MAX_TUPLES`.
   */
  maxTuples?: number
}

/**
 * Cuántas tuplas/filas del destino caben en una pasada de `authz:reconcile`
 * (3b-3b · B5). No es una garantía de memoria: es la cota DECLARADA por
 * encima de la cual la pasada se niega en vez de intentarlo.
 */
export const DEFAULT_RECONCILE_MAX_TUPLES = 1_000_000

/**
 * Algo que la pasada NO migró (una fila del origen) o NO tocó (una tupla del
 * destino), con su motivo. Nunca un contador a secas: un motivo sin la fila
 * no se puede arreglar.
 */
export interface ReconcileSkip {
  kind: 'assignment' | 'deny' | 'edge' | 'tuple'
  reason: string
  detail: string
}

/** Los cinco números de una fase (o del total). */
export interface ReconcileCounts {
  /** Tuplas nuevas en el destino. */
  written: number
  /** Tuplas que estaban con OTRA caducidad y se han rehecho (delete + write). */
  updated: number
  /** Tuplas que ya estaban exactamente igual. */
  unchanged: number
  /** Tuplas del destino que el origen NO respalda. */
  extra: number
  /** De las anteriores, las que la pasada borra (las que sobran de lo derivado, y con `prune` también los hechos). */
  deleted: number
}

/**
 * Lo que movió una pasada de `authz:reconcile`. Los contadores describen el
 * PLAN: con `dryRun` son exactamente los mismos números y no se escribe nada
 * (lo dice `dryRun: true`), que es lo que hace del verificador un simulacro
 * fiel y no una segunda implementación.
 */
export interface ReconcileReport extends ReconcileCounts {
  /** El driver de destino (`--to`). */
  to: string
  /**
   * **De dónde salieron los HECHOS de esta pasada** (3b-5): el nombre del
   * driver ORIGEN, o `authz_*` si fueron las tablas del paquete. No es
   * decoración: es la diferencia entre una migración y una pasada de
   * mantenimiento contra el driver activo, y el comando la imprime — una
   * pasada que lee los hechos del sitio equivocado no puede ser silenciosa.
   */
  factsFrom?: string
  /**
   * **La garantía del freeze, publicada en vez de supuesta** (3b-7, juez C4).
   * Solo en la pasada que ESCRIBE (el `--dry-run` no congela). `lapsed: true`
   * significa que el lease se perdió a mitad —una pausa más larga que el
   * lease, la base caída, otro dueño— y hubo una ventana en la que otros
   * procesos pudieron escribir: la pasada NO se certifica y el comando sale
   * distinto de cero. `leaseMs: null` = ventana sin renovación (el freeze de
   * OPERADOR dentro del que corrió la pasada, o un lease infinito). Lo pone
   * el MANAGER: el driver no sabe de ventanas.
   */
  frozen?: { durable: boolean; lapsed: boolean; leaseMs: number | null; fence: number }
  dryRun: boolean
  prune: boolean
  /** Los mismos números por fase: qué es catálogo, qué es árbol y qué son hechos. */
  phases: Record<'root' | 'catalog' | 'tree' | 'facts', ReconcileCounts>
  /**
   * Motivo → cuántas cosas se quedaron fuera: filas del origen que no se
   * migraron y tuplas del destino que esta pasada no tocó (`extra-fact`, las
   * que solo se van con `--prune`).
   */
  skipped: Record<string, number>
  /** Y cuáles (acotado por `maxSkipDetails`): un contador no permite arreglar nada. */
  details: ReconcileSkip[]
  /** Ciclos del árbol del ORIGEN: sus aristas NO se escriben (FGA los evalúa y son fail-open). */
  cycles: string[][]
  drift: {
    /** Faltaba el marcador de raíz: sin él el store entero DENIEGA (3b-2i). */
    rootMarker: boolean
    /** Scopes con más de un padre en el destino (3b-2h · 🟠 4): cruce de tenants. */
    multiParent: string[]
    /**
     * Aristas `scope#binding` que el destino tenía mal (invariante 18): la
     * escritura de visibilidad que `scopes.moved`/`projectCatalogRole`
     * pudieron perder si el relay no pasó.
     */
    roleVisibility: number
    /** Cambios del árbol encolados y sin relevar: la VENTANA del relay, medida. */
    pendingRelay: number
    /** Entradas APARCADAS de la outbox: divergencia permanente, no una ventana. */
    deadRelay: number
  }
  /** La pasada tiene la firma de un origen ciego (ver `E_AUTHZ_MASS_RECONCILE_REFUSED`). */
  massDelete: boolean
}

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
 * Una arista del árbol del consumidor: «`child` cuelga de `parent`» (3b-3a).
 * `parent` puede ser `APP_SCOPE`; `child` nunca es la raíz.
 */
export interface ScopeEdge {
  child: ScopeRef
  parent: ScopeRef
}

/** Una página de `scopes.enumerateEdges`. Sin `cursor` = no queda nada más. */
export interface ScopeEdgePage {
  edges: ScopeEdge[]
  /**
   * Continuación OPACA para la siguiente llamada (`after`). Ausente o
   * `undefined` significa «se acabó»: devolver siempre un cursor es un bucle
   * infinito, y el llamante lo denuncia (500) si el cursor no avanza.
   */
  cursor?: string
}

/**
 * **El árbol ENTERO, paginado** (3b-3a). Es la otra mitad de
 * `resolveChain`: aquel responde «¿de qué cuelga ESTE scope?» y este
 * «¿cuáles son todas las aristas?», que es lo que hace falta para
 * reconstruir el árbol de un backend que lo guarda como hechos propios
 * (`authz:reconcile --to=openfga`) y para ver las que sobran (las que el
 * consumidor ya no respalda).
 *
 * Contrato:
 *  - devuelve **como mucho `limit`** aristas por página (más ⇒ 500: el
 *    llamante no puede paginar lo que no cabe en su lote);
 *  - el orden tiene que ser TOTAL y ESTABLE entre llamadas (la clave
 *    primaria vale): si no, una pasada reanudada se salta nodos;
 *  - `cursor` es opaco para el paquete y vuelve tal cual en `after`; que no
 *    avance es 500, nunca un bucle;
 *  - una arista cuyo padre no existe en la tabla NO se emite (es un nodo que
 *    `resolveChain` tampoco resuelve): el destino la ve como sobrante y
 *    `authz:reconcile` la cuenta y la reporta.
 *
 * Sin él, `authz:reconcile --to=openfga` no puede migrar el árbol y lo dice
 * (500 `E_AUTHZ_CONFIG`): NO se inventa un árbol plano.
 * `sqlScopeEdges(...)` lo implementa sobre una tabla con columna padre.
 */
export type ScopeEdgesEnumerator = (options: {
  limit: number
  after?: string
}) => Promise<ScopeEdgePage>

/**
 * Un cambio del ÁRBOL, tal como lo encola la outbox (3b-2d). Es exactamente
 * lo que el consumidor notifica por `manager.scopes.*`, con la identidad ya
 * CANÓNICA (invariante 17): se resuelve al encolar, mientras la fila del
 * consumidor todavía existe, no al relevarla.
 */
export type ScopeTreeChange =
  | { op: 'attached'; child: ScopeRef; parent: ScopeRef }
  | { op: 'moved'; child: ScopeRef; parent: ScopeRef }
  | { op: 'detached'; child: ScopeRef }

/** Un cambio pendiente en la outbox, con la identidad de su registro. */
export interface PendingScopeTreeChange {
  /** Identificador estable del registro; el relay lo devuelve al marcarlo. */
  id: string | number
  change: ScopeTreeChange
  /** Intentos fallidos previos, si la outbox los lleva (el reporte los muestra). */
  attempts?: number
  /** La última causa de fallo, si la outbox la guarda (`dead()` la enseña). */
  lastError?: string
  /**
   * Quién ordenó el cambio, si el call-site lo declaró y la outbox lo
   * guarda. El relay lo pone en el `AuthzWriteEvent` del `scope_purged` que
   * dispara un `detached`: la auditoría no debe perder al autor por pasar
   * por una cola.
   */
  actor?: SubjectRef
}

/** Lo que el relay aplicó (o aplicaría), pieza a pieza. */
export interface RelayedScopeChange {
  id: string | number
  change: ScopeTreeChange
  attempts?: number
  /** La causa, en lo que FALLÓ, se APARCÓ o se APLAZÓ (nunca en lo aplicado). */
  error?: string
}

/**
 * Reporte de `authz:scopes:relay` (3b-2d; 3b-2h · 🔴 2). Dice QUÉ se aplicó,
 * no un contador: la pasada no es atómica y un número no permite retomar nada.
 */
export interface ScopeRelayReport {
  /** Aplicados en esta pasada, en orden. Vacío en `dryRun`. */
  applied: RelayedScopeChange[]
  /**
   * El PRIMER cambio que falló, con la causa (`failures[0]`). Se conserva
   * porque es lo que mira un supervisor; la lista completa está en
   * `failures`.
   */
  failed: { id: string | number; change: ScopeTreeChange; error: string } | null
  /**
   * TODO lo que falló en esta pasada (3b-2h · 🔴 2). Un fallo ya no para la
   * pasada entera: para lo que DEPENDE de él —los cambios que nombran alguno
   * de sus scopes, que salen en `deferred`— y el resto sigue.
   */
  failures: Array<{ id: string | number; change: ScopeTreeChange; error: string }>
  /**
   * Lo que NO se intentó porque toca un scope contaminado por un fallo o por
   * otro aplazado de esta misma pasada. Es lo que mantiene el ORDEN del árbol
   * (aplicar un `moved` antes que el `attached` de su padre da un árbol que
   * nunca existió) sin dejar que una fila envenenada bloquee a los demás.
   */
  deferred: RelayedScopeChange[]
  /**
   * Entradas APARCADAS por la outbox tras agotar sus intentos (`dead()`), si
   * la implementación lo soporta. No se van a aplicar solas: el árbol del
   * backend está permanentemente divergente en esos nodos y hay que mirarlas.
   */
  dead: RelayedScopeChange[]
  /**
   * Otra pasada tenía el lease de la cola y esta no ha hecho NADA (3b-2h ·
   * 🟠 4). No es un error: el relay es escritor ÚNICO.
   */
  busy: boolean
  /** Quedan cambios sin aplicar tras la pasada (vuelve a ejecutar). */
  remaining: boolean
  dryRun: boolean
  /** Solo con `dryRun`: lo que se aplicaría, en orden. */
  wouldApply: RelayedScopeChange[]
}

/**
 * El lease de una pasada del relay (3b-2h · 🟠 4). Lo devuelve
 * `ScopeOutbox.acquire()` y lo suelta el manager en un `finally`.
 */
export interface ScopeOutboxLease {
  release(): Promise<void>
}

/** Contexto del encolado: la transacción del consumidor y quién lo ordena. */
export interface ScopeOutboxContext {
  /**
   * Lo que el llamante pasó en `ScopeTreeWriteOptions.transaction`: para
   * Lucid, el `TransactionClientContract` de la transacción en curso. El
   * manager no lo interpreta —no conoce la BD del consumidor—: lo pasea.
   * `sqlScopeOutbox` SÍ lo juzga (L-1 · 🟠 9, `assertCallerTransaction`):
   * tiene que ser una transacción ABIERTA de la conexión de la cola, o 500
   * `E_AUTHZ_CONFIG` antes del INSERT. Una outbox propia hereda el deber.
   */
  transaction?: unknown
  actor?: SubjectRef
}

/**
 * **El puerto de la outbox del árbol** (3b-2d, panel 2 cruce 4 · S5).
 *
 * Sin él, `manager.scopes.attached/moved/detached` escribe en el backend
 * DENTRO de la transacción del consumidor y un `rollback` posterior deja el
 * árbol de FGA diciendo una cosa y la BD del consumidor otra —una escalada
 * persistente e invisible, porque la aplicación lista y audita contra SQL—.
 * Con él, el manager no toca el driver: ENCOLA el cambio con la transacción
 * del consumidor, así que el cambio del árbol y su intención de propagación
 * confirman o se van juntos. Lo aplica después `authz:scopes:relay`.
 *
 * El paquete no impone tabla: define este puerto y publica un stub de
 * migración (`stubs/scopes_outbox_migration.stub`) y una implementación
 * sobre Lucid (`sqlScopeOutbox`) para quien no quiera escribir la suya.
 *
 * Lo que NO arregla, y hay que leerlo así: durante el lag del relay
 * (segundos) FGA decide con el árbol VIEJO. Es un fail-open temporal — el
 * tenant antiguo conserva acceso tras un `moved`, y los denies heredados no
 * aplican tras un `attached`—. No hay 2PC; es el precio de tener el árbol en
 * dos sitios.
 */
export interface ScopeOutbox {
  /**
   * Encola el cambio en la transacción del consumidor. Debe escribir y
   * volver: nada de aplicarlo aquí. Si lanza, la escritura del manager falla
   * (y la transacción del consumidor se lleva las dos cosas).
   */
  enqueue(change: ScopeTreeChange, context: ScopeOutboxContext): Promise<void>
  /**
   * Los pendientes MÁS ANTIGUOS primero: el orden del árbol es el del
   * encolado. `after` (3b-2h · 🔴 2) es el id del último registro que el
   * relay ya vio en ESTA pasada: como una entrada que falla ya no para la
   * pasada, se queda pendiente y volvería a salir la primera para siempre.
   * Una implementación que lo ignore sigue siendo válida —el relay detecta
   * que no avanza y termina la pasada—, pero solo drenará hasta el primer
   * lote atascado.
   */
  pending(limit: number, after?: string | number): Promise<PendingScopeTreeChange[]>
  /** Aplicado en el backend: no se vuelve a relevar. */
  markApplied(id: string | number): Promise<void>
  /** Falló al aplicarse: se queda pendiente, con la causa a la vista. */
  markFailed(id: string | number, error: string): Promise<void>
  /**
   * **Las entradas APARCADAS** (3b-2h · 🔴 2), opcional. Una entrada que ya
   * no se puede aplicar —su scope padre se borró antes de la pasada— no se
   * arregla sola: la outbox puede dejar de ofrecerla en `pending()` tras N
   * intentos y enseñarla aquí. El relay las REPORTA en cada pasada y el
   * comando sale ≠ 0 mientras haya alguna: un aparcado es una divergencia
   * permanente del árbol del backend, no un incidente resuelto.
   */
  dead?(limit: number): Promise<PendingScopeTreeChange[]>
  /**
   * **El lease del escritor ÚNICO** (3b-2h · 🟠 4), opcional. `pending()` no
   * reserva nada, así que dos pasadas a la vez (un `CronJob` con
   * `concurrencyPolicy: Allow`, dos réplicas, una pasada más larga que su
   * intervalo) trabajan sobre el MISMO lote: la rezagada re-aplica un
   * `attached` viejo después de que la otra aplicara el `moved` nuevo y deja
   * el árbol del store REVERTIDO —con un solo padre, así que nada lo
   * delata— (medido). Con `acquire`, la segunda pasada no hace nada y lo
   * dice (`busy`). `null` = otra pasada lo tiene.
   *
   * CONTRATO: el lease se toma UNA vez al inicio de la pasada y se sostiene
   * hasta el `finally`; el relay NO lo re-verifica ni lo renueva dentro del
   * bucle (a diferencia del freeze durable, que sí se re-afirma por lote).
   * Por eso la implementación DEBE ser un cerrojo SOSTENIDO mientras dura la
   * pasada, no un TTL que pueda vencer a mitad: los que trae el paquete lo
   * cumplen (`pg_try_advisory_xact_lock` vive con la transacción; `get_lock`
   * de MySQL con la sesión; SQLite en proceso). Un `acquire` con TTL
   * reabriría la ventana del doble escritor que este lease cierra.
   */
  acquire?(): Promise<ScopeOutboxLease | null>
}

/**
 * El árbol del consumidor hacia ABAJO (2.1, B2): todos los descendientes de
 * `scope` (cualquier tipo, cualquier profundidad), en cualquier orden y sin
 * incluirlo. Lo implementa el consumidor (o `sqlDescendantsOf`, el helper
 * opt-in del paquete): el paquete NO lo suple con N+1 llamadas a
 * `resolveChain`. `null` = «este árbol no conoce ese scope».
 *
 * Más de `maxNodes` nodos ⇒ el resolutor puede devolver la lista larga (el
 * paquete la caza con 422 `E_AUTHZ_TOO_MANY_SCOPES`) o lanzar; en
 * `authorizedScopes` eso es un 422 y en `defineScopedRole`/`updateScopedRole`
 * DEGRADA a la regla de nivel mínima (3F · S2, y ver el aviso de
 * `#assertLevelUnderOwner`).
 *
 * Solo se llama desde `authorizedScopes`/`expandExcludedSubtrees` y desde la
 * regla de nivel de la delegación; NUNCA desde `authorize`/`hasRole`/`list*`
 * (test de arquitectura) ni desde `scopes.detached`, que purga hechos del
 * scope EXACTO y no baja por el árbol (invariante 11; 3b-0 · Z1).
 *
 * (D7: hasta 3G había DOS docblocks seguidos aquí y el viejo contradecía al
 * nuevo sobre qué se espera al pasarse de `maxNodes`. Queda uno.)
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
   *
   * **Con `{ transaction }` (L-3) sigue siendo `true` en el deadline**, junto
   * a `transactional: true`: la sentencia puede haber aterrizado DENTRO de la
   * transacción del llamante (SQLite no cancela; MySQL la mata y la
   * transacción sigue; PostgreSQL deja la transacción abortada) y confirmar
   * o no es del llamante, que el paquete no ve. Invariante 13 intacto.
   */
  indeterminate?: boolean
  /**
   * `true` cuando la escritura se inscribió en la transacción del llamante
   * (`{ transaction }`, L-3): en el momento del evento la fila existe SOLO
   * dentro de esa transacción, y es un hecho si y solo si el llamante
   * confirma — cosa que el paquete no ve. Un sink que registre esto como
   * firme registra algo que un rollback deshace; si necesita la última
   * palabra, que se cuelgue del commit (`trx.after('commit', …)` en Lucid).
   * Ausente en el resto (encolar en `scopes.*` no es escribir y no lo lleva).
   */
  transactional?: boolean
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
   * Quién lo ordenó. La API de delegación lo exige siempre; ausente en los
   * `role_purged` de `authz:catalog:prune-orphans` (3b-0 · Z2), que es una
   * operación de PLATAFORMA y no de un actor del árbol.
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

/* ── Proyección derivada del catálogo (3b-2a · A5) ──────────────────────── */

/**
 * Un rol del catálogo tal como lo ve la PROYECCIÓN: su uuid (la identidad, 3A
 * · A1) y los slugs de los permisos que vincula.
 */
export interface CatalogProjectionRole {
  uuid: string
  permissions: string[]
}

/**
 * Foto del catálogo confirmado que un driver puede materializar en su
 * backend. Se lee de `authz_*` dentro de la transacción del sync: es
 * DERIVADA, y por eso se puede reconstruir entera (`authz:reconcile`).
 */
export interface CatalogProjectionSnapshot {
  /** Todos los slugs de permiso del catálogo (no solo los del spec que se sincroniza). */
  permissions: string[]
  /** Todos los roles con sus vínculos rol→permiso. */
  roles: CatalogProjectionRole[]
}

/** Lo que una pasada de proyección movió. Nunca un booleano: una proyección silenciosa no se vigila. */
export interface CatalogProjectionReport {
  /** Tuplas nuevas escritas. */
  written: number
  /** Tuplas que sobraban (el catálogo ya no las respalda) y se han borrado. */
  deleted: number
  /** Tuplas que ya estaban exactamente igual. */
  unchanged: number
}

/**
 * **Proyección derivada del catálogo en el backend de un driver** (regla del
 * catálogo reescrita — panel 2, cruce 7; decisión del dueño 2026-08-28).
 *
 * El catálogo es propiedad LOCAL siempre: roles y permisos viven en `authz_*`
 * y ningún driver es su fuente de verdad. Un driver PUEDE mantener una
 * proyección (el modo `facts` de openfga: permisos como relaciones del modelo
 * + vínculos rol→permiso como tuplas `role:<uuid>#permits_<P>@<holder>:*`) si
 * y solo si: (a) es reconstruible desde `authz_*`, (b) `authz:reconcile` la
 * vigila y (c) NUNCA se lee como catálogo.
 *
 * Se inyecta en `syncAuthzCatalog` en vez de importarse: `src/catalog.ts` es
 * la ruta de un consumidor solo-database y no puede tirar del SDK de OpenFGA
 * (regla 3 de `check_purity.mjs`).
 */
export interface CatalogProjection {
  /**
   * ¿El catálogo que va a quedar es publicable en este backend? Se llama
   * ANTES de escribir nada (cotas de nombre y techo del modelo, A3/A4): un
   * catálogo que no se puede proyectar no se escribe a medias.
   */
  assertPublishable(permissions: readonly string[]): void
  /** Rehace la proyección del catálogo ya confirmado: escribe lo que falta y BORRA lo que sobra. */
  project(snapshot: CatalogProjectionSnapshot): Promise<CatalogProjectionReport>
}

/* ─────────────────────────────────────────────────────────────────────────
 * El puerto `RelationsDriver` — ReBAC genérico (Fase 4, lote 4-2)
 *
 * Un puerto SEPARADO de `AuthorizationDriver` (higiene «todo en un driver o
 * todo en otro»): un `RelationsDriver` es completo por sí mismo (tuplas de
 * relación + su resolución). Convive con `roles/` en el MISMO store (modelo
 * fusionado, lote 4-1), pero su namespace de ids es DISJUNTO por construcción
 * (⚪4 + F-05): un tipo de objeto de relaciones no puede llamarse como un tipo
 * de `facts`, y `relate`/`unrelate` rechazan todo tipo/relación no declarado
 * en `defineRelationsConfig` ANTES de tocar el driver.
 * ──────────────────────────────────────────────────────────────────────── */

/** Un objeto de relaciones: `document:<id>`, `folder:<id>`, `group:<id>`… */
export interface RelObject {
  /** El tipo FGA del objeto (`document`, `folder`, `space`…), declarado en `defineRelationsConfig`. */
  type: string
  /** El id del objeto dentro de su partición. Sin `|`/`#`/`:` (los pone el driver al componer). */
  id: string
}

/**
 * Un userset como sujeto: `group:eng#member` (todos los miembros del grupo).
 * Es lo que hace que un `relate(group:g#member, viewer, doc)` conceda `viewer`
 * a todo el que sea `member` de `g` (`usersetsOf`, un nivel).
 */
export interface RelUserset {
  object: RelObject
  relation: string
}

/**
 * El sujeto de una relación: un HOLDER (`{type,uuid}`, como `SubjectRef`) o un
 * USERSET (`{object, relation}`). El puerto lo tipa explícito porque los dos
 * viajan por `relate`/`listSubjects`/`check`; un userset de OTRA partición se
 * corta por comparación de string en el driver (nunca cruza).
 */
export type RelSubject = SubjectRef | RelUserset

/** Discriminador: ¿este sujeto es un userset (`group:g#member`) y no un holder? */
export function isRelUserset(subject: RelSubject): subject is RelUserset {
  return typeof (subject as RelUserset).object === 'object' && (subject as RelUserset).object !== null
}

/**
 * La referencia COMPLETA a una tupla de relación, tal como la ve `assertWrite`
 * (R-13) y `onRelationWrite`: sujeto + relación + objeto + partición, más la
 * operación. Es puro dato: quien lo recibe decide (auditar, rechazar), nunca
 * muta el store.
 */
export interface RelationRef {
  operation: 'relate' | 'unrelate'
  subject: RelSubject
  relation: string
  object: RelObject
  partition: ScopeRef
  /**
   * La caducidad pedida en `relate` (R-15), en sus tres estados: omitida
   * (preserva la vigente), `null` (la quita) o `Date` (la fija). Solo viaja en
   * `relate`; `assertWrite` puede rechazar una compartición sin plazo.
   */
  expiresAt?: Date | null
}

/** El evento de escritura de relaciones (auditoría del consumidor, sin `AsyncLocalStorage`). */
export interface RelationWriteEvent extends RelationRef {
  /** Quién ordenó la escritura (`RelationWriteOptions.actor`), ya validado. Ausente si no lo pasó. */
  actor?: SubjectRef
}

/**
 * Opciones de `purgeObject`/`purgeSubject` (L-2): solo la transacción del
 * consumidor. Ver `RelationTransactionOptions.transaction`.
 */
export interface RelationTransactionOptions {
  /**
   * **La transacción ABIERTA del consumidor** (`TransactionClientContract` de
   * Lucid), para que la escritura de la tupla confirme o revierta CON la tuya
   * — L-2, panel `{trx}` (C). Aquí significa **ESCRIBIR en tu transacción**
   * («los dos o ninguno» en el mismo motor transaccional) — **encolar ≠
   * escribir**: no es la outbox de `scopes.*`, que solo ENCOLA. Solo lo
   * cumple un driver con `capabilities.transactionalWrites: true` (`database`,
   * con el `trx` de SU conexión, L-4); con `false` (`openfga`: una tupla no
   * entra en una transacción SQL) la llamada es **500 `E_AUTHZ_UNSUPPORTED`**
   * nombrando driver y operación, antes de tocar el driver. Con
   * `requireTransactionalWrites: true` (`config.relations`, o heredado del
   * raíz) un driver `false` es 500 `E_AUTHZ_CONFIG` al resolver. La
   * AUTORIDAD (barrera del freeze) nunca viaja por ella: pool ≥ 2.
   */
  transaction?: unknown
}

/** Opciones comunes a `relate`/`unrelate`. */
export interface RelationWriteOptions extends RelationTransactionOptions {
  /** Quién ordena la escritura; viaja en `RelationWriteEvent.actor`. */
  actor?: SubjectRef
  /**
   * **Caducidad de la tupla de relación** (R-15, 2.4.0-alpha.2) — los MISMOS
   * tres estados que `grant` (invariante 10): omitida ⇒ preserva una caducidad
   * VIGENTE (una ya caducada revive sin caducidad: es una relación nueva);
   * `null` ⇒ la quita; `Date` ⇒ la fija (también a un instante pasado: caduca).
   * Caducidad ESTRICTA: lo que vence AHORA ya no cuenta (`expires_at > now`;
   * `current_time < valid_until`). Solo la lee `relate`; `unrelate` la ignora.
   * Cualquier otro valor ⇒ 422 `E_AUTHZ_INVALID_IDENTITY` antes del driver.
   */
  expiresAt?: Date | null
}

/** Una página de una enumeración de relaciones (cursor opaco que AVANZA, no filtra herencia). */
export interface RelationPage {
  limit?: number
  after?: string
}

/**
 * Lo que un `RelationsDriver` DECLARA que puede hacer. Cada valor lleva su par
 * de casos `{ whenTrue, whenFalse }` en `runRelationsDriverContract` — nunca
 * un `skip` (3b-2e · E2). El runner FALLA si una capacidad declarada no tiene
 * poblada la cara que corresponde a su valor.
 */
export interface RelationsDriverCapabilities {
  /** `check` es UNA sola llamada al backend (`openfga`: un `Check`). */
  singleCheckRelations: boolean
  /**
   * Los `listObjects` enumeran también lo HEREDADO. **`false` siempre** en
   * este paquete (invariante 7): en `openfga` obligaría a `ListObjects`, que
   * trunca al tope del servidor. Devuelven hechos DIRECTOS + lo derivado.
   */
  listObjectsInherited: boolean
  /** `listSubjects` devuelve también sujetos USERSET (`group:g#member`), no solo holders. */
  usersetSubjects: boolean
  /**
   * El driver implementa `membersOf` (membresía TRANSITIVA a través de
   * usersets). Solo `database` (CTE recursiva); `openfga` es `false` (la
   * transitiva sería `ListUsers`, que trunca) ⇒ `membersOf` es 500
   * `E_AUTHZ_UNSUPPORTED`.
   */
  membersOfNative: boolean
  /** El driver sabe ser ORIGEN de `authz:reconcile` de relaciones (`enumerateRelations`). */
  enumerateRelations: boolean
  /**
   * `listObjects` SEÑALA el truncamiento cuando el backend corta al tope
   * (`openfga` con `ListObjects`): la página devuelve `truncated: true`, nunca
   * una lista parcial muda (S16). Capacidad NUEVA, distinta del
   * `truncationSignal` de los `list*` de roles.
   */
  listObjectsTruncation: boolean
  /**
   * El driver acepta un reloj inyectado (R-15, paridad con el par
   * `injectableClock` de roles, 2.5 · J1): `withClock(now)` devuelve una
   * vista del driver cuyo `now()` decide la caducidad de las tuplas. Con
   * `true` el juez observa la caducidad EXACTA (T−1 ms concede, T no) y los
   * tres estados de `expiresAt` sin dormir; con `false` solo puede observarlos
   * en tiempo real (y el driver NO debe traer `withClock`: declara lo que se
   * observa).
   */
  injectableClock: boolean
  /**
   * El driver puede inscribir sus escrituras en la transacción del consumidor
   * (`{ transaction }` en `relate`/`unrelate`/`purgeObject`/`purgeSubject`).
   * `true` significa EXACTAMENTE «los dos o ninguno con TU transacción»,
   * nunca «no se pierde». `database` = true (con el `trx` de SU conexión;
   * L-4). `openfga` = false, y no puede ser otra cosa: una tupla no entra en
   * una transacción SQL — el store es otro servicio y no hay 2PC. **Mismo
   * nombre que en `AuthorizationDriverCapabilities`**. Con `false`,
   * `{ transaction }` es 500 `E_AUTHZ_UNSUPPORTED` por llamada (cero llamadas
   * al driver); con `requireTransactionalWrites: true` un driver `false` es
   * 500 `E_AUTHZ_CONFIG` al resolver. Hasta L-4 los dos drivers declaran `false`.
   */
  transactionalWrites: boolean
}

/**
 * Una página de `listObjects`/`listSubjects`/`enumerateRelations`. `truncated`
 * dice si el backend cortó al tope (solo con `listObjectsTruncation`): un
 * consumidor que lo ve sabe que hay MÁS y no toma la lista por completa.
 */
export interface RelationObjectsPage {
  objects: RelObject[]
  cursor?: string
  truncated?: boolean
}

export interface RelationSubjectsPage {
  subjects: RelSubject[]
  cursor?: string
  truncated?: boolean
}

/** Una tupla de relación tal como la enumera `enumerateRelations` (origen de reconcile). */
export interface RelationTuple {
  subject: RelSubject
  relation: string
  object: RelObject
  partition: ScopeRef
  /**
   * La caducidad de la tupla tal como está ESCRITA (R-15): `null`/ausente = no
   * caduca. `enumerateRelations` NO filtra la caducada: tiene que LLEGAR al
   * destino de `reconcile` con su `expiresAt` para contarse en `skipped`
   * (la lección de la 3b); filtrarla en el origen la haría desaparecer sin rastro.
   */
  expiresAt?: Date | null
}

export interface RelationTuplePage {
  tuples: RelationTuple[]
  cursor?: string
}

/**
 * El puerto de ReBAC. `partition: ScopeRef` es OBLIGATORIA en TODA operación
 * (`APP_SCOPE` es válida para mono-tenant): el aislamiento de tenant se corta
 * por la partición, y el driver la serializa en el id del objeto y del
 * userset. La whitelist de tipo/relación (F-05) la aplica el manager ANTES de
 * llamar al driver, pero el driver la re-valida por defensa en profundidad:
 * `relate`/`unrelate` de `database` y de `openfga` rechazan 422
 * (`E_AUTHZ_RELATION_TYPE_UNKNOWN` / `E_AUTHZ_RELATION_UNKNOWN`, la MISMA
 * función y el mismo `code` que el manager, `assertRelationDeclared`) un
 * `object.type` no declarado o una `relation` no declarada para ese tipo,
 * ANTES de tocar el backend (cero `Write`, cero INSERT). Es la red para quien
 * entra por `manager.driver()` o por `reconcileRelations` (L-0): hasta
 * entonces esta frase era falsa en los dos drivers y, en el store compartido,
 * `driver.relate(evil, 'assignee', {type:'role_binding', id:<roleUuid>}, S)`
 * escalaba a `roles.authorize` (medido).
 */
export interface RelationsDriver {
  readonly capabilities?: RelationsDriverCapabilities

  /** Crea la relación `subject —relation→ object` en `partition`. Idempotente. */
  relate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    options?: RelationWriteOptions
  ): Promise<void>

  /** Retira la relación. No-op seguro si no existe (invariante 6). */
  unrelate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    options?: RelationWriteOptions
  ): Promise<void>

  /** ¿`subject` tiene `relation` sobre `object` en `partition` (directo o derivado por includes/userset)? */
  check(subject: RelSubject, relation: string, object: RelObject, partition: ScopeRef): Promise<boolean>

  /** Los objetos de tipo `objectType` sobre los que `subject` tiene `relation`. Directos + derivados, sin herencia abierta. */
  listObjects(
    subject: RelSubject,
    relation: string,
    objectType: string,
    partition: ScopeRef,
    page?: RelationPage
  ): Promise<RelationObjectsPage>

  /** Los sujetos DIRECTOS de `relation` sobre `object` (holders y usersets). Nunca la membresía transitiva (eso es `membersOf`). */
  listSubjects(
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    page?: RelationPage
  ): Promise<RelationSubjectsPage>

  /** Borra todas las tuplas cuyo OBJETO es `object` y demuestra cero, o lanza 500 `E_AUTHZ_PURGE_INCOMPLETE` (invariante 11). */
  purgeObject(object: RelObject, partition: ScopeRef, options?: RelationTransactionOptions): Promise<void>

  /** Borra todas las tuplas cuyo SUJETO es `subject` y demuestra cero, o lanza 500. */
  purgeSubject(subject: RelSubject, partition: ScopeRef, options?: RelationTransactionOptions): Promise<void>

  /**
   * La membresía TRANSITIVA de un objeto-grupo: todos los holders que son
   * `member` directa o a través de grupos anidados. DISTINTO de
   * `listSubjects(member, group)`, que devuelve solo los hechos DIRECTOS. Solo
   * lo trae el driver con `membersOfNative: true`.
   */
  membersOf?(object: RelObject, relation: string, partition: ScopeRef, page?: RelationPage): Promise<RelationSubjectsPage>

  /** ORIGEN de `authz:reconcile` de relaciones: las tuplas paginadas, sin filtrar (la caducada LLEGA con su `expiresAt`). Solo con `enumerateRelations: true`. */
  enumerateRelations?(partition: ScopeRef, page?: RelationPage): Promise<RelationTuplePage>

  /**
   * Vista de este driver con OTRO reloj de pared (R-15, paridad con
   * `AuthorizationDriver.withClock`, 2.5 · J1): mismo backend, solo cambia el
   * `now()` que decide la caducidad (`expires_at > now` en SQL; el
   * `current_time` del `Check` en FGA; el filtro en cliente de `listSubjects`).
   * Opcional: el `RelationsManager` lo aplica si recibe `clock` (500
   * `E_AUTHZ_CONFIG` si el driver no lo trae) y el juez lo usa con
   * `injectableClock: true`.
   */
  withClock?(now: () => Date): RelationsDriver
}

/**
 * Factory de un `RelationsDriver` (Fase 4, lote 4-6) — el análogo de
 * `AuthorizationDriverFactory` para el puerto de relaciones. El consumidor la
 * declara en `config.relations.drivers`, y `authz:relations:reconcile` la
 * invoca para construir el ORIGEN y el DESTINO de una migración de tuplas. El
 * driver `openfga` de relaciones entra por el subpath `/openfga` DENTRO de la
 * factory (como el de roles), así que el comando nunca toca el SDK (pureza).
 */
export type RelationsDriverFactory = () => RelationsDriver | Promise<RelationsDriver>
