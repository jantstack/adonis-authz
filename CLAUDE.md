# @jantstack/adonis-authz — guía para agentes

Motor de autorización driver-based para AdonisJS 7 + Lucid. Paquete npm publicado (`2.4.0-alpha.2`,
2026-09-02, dist-tag `alpha`; `latest` sigue en `1.1.0`), ESM, Node ≥ 20.6. Autor: José Antonio (jantstack). Idioma de trabajo: **español**
(código y comentarios ya están en español; el README y CHANGELOG en inglés).

## Invariantes del contrato (innegociables)

Todo driver debe cumplirlos; los verifica `src/testing/contract.ts` (la misma suite
corre contra `database` y `openfga`). Cualquier plan que rompa uno de estos sin
discusión explícita es un plan rechazado.

1. **Scopes jerárquicos, herencia SOLO hacia abajo, DESDE LA RAÍZ.** Un grant en un scope vale en él
   y en todos sus descendientes; nunca en hermanos ni ancestros. El motor solo
   conoce la raíz `app` (`APP_SCOPE`, uuid null); el árbol lo inyecta el consumidor
   vía `resolveChain`. **Y "descendiente" significa descendiente DE `app`** (3b-2i): un subárbol
   desgajado —cuya cadena no llega a la raíz— no concede nada, ni siquiera dentro de sí mismo. En
   `database` lo dice `resolveChain` (invariante 9); en `facts` lo dice el MODELO (`can_<P>` exige
   `rooted`), que es lo que impide que romper la cadena sea una forma de conceder.
2. **Deny explícito gana.** Un deny en cualquier punto de la cadena bloquea aunque un
   rol conceda. Quitar el deny restaura.
3. **Expiración observable sin scheduler.** `expiresAt` pasado ⇒ no concede. En SQL
   para `database`, con *condition* FGA para `openfga`. **También en la tupla de relación**
   (R-15, 2.4.0-alpha.2): `relate(…, { expiresAt })` con los tres estados del invariante 10,
   caducidad ESTRICTA, `authz_relations.expires_at` (DATETIME(3), mismo codec) y `with not_expired`
   en cada sujeto de relación del modelo fusionado; `withClock` en los dos drivers de relaciones
   (par `injectableClock` del runner de relaciones). Renovar en `database` es delete+insert
   (INSERT/DELETE-ONLY), y `enumerateRelations` NO filtra la caducada (llega y se cuenta en
   `skipped.expired` de `reconcileRelations`).
4. **Holders polimórficos.** `SubjectRef = { type: morphName, uuid }`. Mismo uuid con
   distinto type JAMÁS se cruzan.
5. **Denegación por defecto y tres estados distinguibles:**
   - sin permiso / permiso desconocido / sin asignación vigente / scope desconocido → `false` (nunca throw)
   - pregunta inválida (rol/permiso fuera del catálogo en `grant`/`deny`/`revoke`/`removeDeny`,
     identidad o slug mal formados, `RoleQuery` objeto donde va un slug, `expiresAt` que no es
     `Date` válida/`null`/omitido, escritura sobre scope desconocido) → Exception 422 con `code`
   - backend no responde (SQL en ambos drivers, FGA, el resolutor del consumidor que lanza o
     responde un ancestro mal formado, un `error` por check dentro de un `batchCheck`) →
     `AuthorizationBackendError`/`ScopeResolverError` (503). **Nunca** se traduce una caída a un
     `false` silencioso.
6. **Escrituras idempotentes.** Re-grant actualiza `expiresAt`, no duplica.
   Re-revoke / re-deny / re-removeDeny son no-ops seguros. **Y una escritura es UNA escritura**
   (3b-2f · R3): en `openfga` con `hierarchy: 'facts'` las TRES tuplas de un `grant` (`assignee`,
   `role_binding#role`, `scope#binding`) van en el MISMO `Write` —transaccional en FGA—, porque un
   `assignee` sin sus aristas es una asignación que `listRoles`/`hasRole` enumeran y `authorize` no
   honra, que es peor que perder la escritura; y `purgeScope` borra en `facts` con un orden fijo
   —estructura, hechos, denies— para que ningún entrelazado con un `grant` concurrente deje ese
   estado, y para que una purga que muere a medias deje denies de MÁS, nunca de menos. El choque de
   dos escrituras a la vez no es una caída del backend: FGA lo dice con un `Aborted` (409) o con un
   «cannot write a tuple which already exists» (400), el driver relee y re-aplica (gana el último
   escritor), y una contención que no cede sale como **409 `E_AUTHZ_WRITE_CONFLICT`**, jamás como
   un 503. **Y con `{ transaction }` la escritura va por la transacción del LLAMANTE; la autoridad,
   nunca** (2.4.0-alpha.2, panel `{trx}`, veredicto (C)): `database` —roles L-3 y relaciones L-4—
   escribe la fila (y su «¿ya existe?») por la trx abierta de SU conexión (`assertCallerTransaction`:
   otra conexión, un `QueryClient` o el `db` entero ⇒ 500 `E_AUTHZ_CONFIG` sin una sentencia), y es
   «los dos o ninguno» juzgado por CENSO en pool ≥ 2; el freeze, el catálogo, `resolveChain`, F-05 y
   `assertWrite` se leen por la conexión del motor ANTES de la primera sentencia por la trx. Dentro
   de la trx un choque del UNIQUE o un deadlock NO se relee (PG ya la abortó; en REPEATABLE READ la
   relectura no vería al ganador): 409 `E_AUTHZ_WRITE_CONFLICT` que ENVENENA la trx del llamante
   (PG abortada, MySQL viva, sqlite-file `SQLITE_BUSY` 503), medido por motor. `openfga` declara
   `transactionalWrites: false` y rechaza `{ transaction }` con 500 `E_AUTHZ_UNSUPPORTED` en el
   manager Y en el driver (una tupla no entra en una trx SQL; no hay 2PC); lo que ofrece es la receta
   por dirección del README, que no compone y el paquete no automatiza (L-6, con caso).
7. **Los `list*` no enumeran herencia.** `listSubjects`/`listRoles`/`listRoleScopes`/
   `listScopes`/`listDenies` devuelven hechos DIRECTOS vigentes. Enumerar descendientes
   sería abierto; el caller pregunta `authorize` sobre un scope concreto. **Excepción explícita
   (2.1):** `authorizedScopes(subject, permission, scopeType)` SÍ enumera descendientes, solo con
   el `descendantsOf` del consumidor, acotado (`maxScopes` ⇒ lanza, nunca parcial) y nunca `all`
   con denies vivos (`all{excludedSubtrees}`); `descendantsOf` está prohibido en `authorize`/`list*`.
8. **`rank` es metadata.** El motor lo almacena pero NO lo evalúa en `authorize`; la
   policy de "no puedes dar un rol de rango ≥ al tuyo" es del consumidor.
9. **Scope desconocido = no existe.** `resolveChain` ⇒ `null` deniega (`authorize`/`hasRole`),
   no lista (`listRoles`/`listRoleScopes`/`listScopes`) y rechaza escribir (422
   `E_AUTHZ_UNKNOWN_SCOPE`). Sin resolutor solo existe `app`. Jamás un fallback a `[APP_SCOPE]`.
   **En `facts` esto NO lo hace `resolveChain`** —`authorize` es un solo `Check` y no lo llama—:
   lo hace el modelo (c2r) (3b-2i). `can_<P> = (<P> but not denied_<P>) and rooted`, y `rooted` solo
   la tiene directa `scope:app` (el *marcador de raíz*, `scope:app#rooted@<holder>:*`, una tupla por
   holder type en todo el store y CERO por scope): **un scope que no alcanza `app` EN EL STORE
   deniega, tenga los bindings que tenga**. Consecuencias que van con ello: sin marcador el store
   entero deniega (fail-closed, ruidoso, total), y durante el lag del relay un `attached` sin relevar
   deniega en vez de conceder (**fail-CLOSED**, decisión del dueño del 2026-08-31 (2), breaking).
10. **`expiresAt` en tres estados.** Omitido preserva una caducidad vigente (expirada ⇒ revive sin
    caducidad), `null` la quita, `Date` la fija; `grant` devuelve `GrantOutcome` y un cambio se
    audita como `extended` con `previousExpiresAt`.
11. **Purga con demostración de cero.** `scopes.detached` ⇒ `purgeScope` borra los hechos del
    scope exacto cuyo rol/permiso está en el catálogo y demuestra que ESE conjunto quedó a cero
    o lanza 500 `E_AUTHZ_PURGE_INCOMPLETE`; nada resucita; la raíz no se purga (422). Los hechos
    de roles retirados no conceden ni son membresía (las lecturas filtran por catálogo) y los
    recoge `authz:reconcile` (3b). **El orden S6 —hechos primero, arista al final— NO cambia con
    (c2r), pero su MOTIVO sí** (3b-2i): ya no es «un scope sin ancestro dejaría de heredar los denies
    y sus permisos serían indenegables» —eso era el 🔴 1, y hoy ese scope no concede nada—, sino que
    una purga a medias tiene que dejar denies de MÁS y no un nodo con hechos vivos que ya nadie
    purga. Y los HIJOS de un nodo detachado, mientras nadie los recuelga, **deniegan** en vez de
    conceder de más.
12. **El catálogo manda y se poda.** `syncAuthzCatalog` poda por defecto los vínculos que el spec
    ya no lista (roles del spec); un rol `(slug, scopeType)` y un permiso pertenecen a exactamente
    un catálogo (422 `E_AUTHZ_CATALOG_CONFLICT`); la membresía (`hasRole`/`list*`) es lo que dice
    el catálogo en ambos drivers.
13. **Una escritura que vence el deadline es indeterminada.** El manager notifica `onWrite` con
    `indeterminate: true` antes de propagar el 503 `E_AUTHZ_BACKEND_TIMEOUT`; el driver openfga no
    deja al SDK reintentar por su cuenta (`maxRetry: 0`). **Con `{ transaction }` el evento lleva
    además `transactional: true`** (L-3; todos los eventos de una escritura inscrita en la trx del
    llamante, no el encolado de `scopes.*`): `indeterminate` se MANTIENE —el rollback del llamante
    determina el resultado, pero es suyo y el paquete no lo ve; un sink que quiera la última palabra
    se cuelga de `trx.after('commit')`—. Medido: PG cancela y deja la trx abortada, MySQL mata la
    consulta y la deja viva, SQLite no puede vencer un deadline (`SQLITE_BUSY`). **Y vale igual en el
    puerto de RELACIONES** (`2.4.0-alpha.3`): `RelationsManager` envuelve las CUATRO escrituras
    (`relate`/`unrelate`/`purgeObject`/`purgeSubject`) con el MISMO `#write` y notifica
    `onRelationWrite` con `indeterminate: true` antes del 503 (y `transactional: true` si iba en la trx);
    en `openfga` el deadline es el `timeout` del SDK con `maxRetry: 0` (medido contra un socket mudo, sin
    servidor) y el evento nunca lleva `transactional`. Hasta alpha.3 `grep -c indeterminate
    src/relations/manager.ts` daba 0. **Y una escritura PARCIAL también es indeterminada** (cierre de
    alpha.3, 🟡 6 del auditor): la purga de `openfga` es multi-request (ortografías × tipos, cada una
    `Read`+`deleteTuples`+`Read`), así que un 503 no-timeout —o el 500 `E_AUTHZ_PURGE_INCOMPLETE`— puede
    llegar DESPUÉS de haber borrado parte; el driver propaga el error marcado con `markPartialWrite`
    (`src/errors.ts`, exportado: una propiedad, la clase y el `code` no cambian) si ya borró ≥ 1, y `#write`
    notifica `indeterminate: true` para timeout O parcial. «Esa escritura no ocurrió y no hay evento» vale
    para 422/`assertWrite`/freeze, para un 503 no-timeout en `relate`/`unrelate` y en cualquier escritura de
    `database` (una sentencia), y en las purgas de `openfga` solo si aún no se había borrado nada (medido
    contra el `:8101` con un espía que hace fallar la request siguiente a un `deleteTuples`, y su control).
    Un driver de terceros con purga multi-request tiene el mismo deber. **Ningún runner publicado juzga el
    invariante 13** (⚪ 11 del auditor; roles tampoco): registrado en `roadmap-2.0.md` (Diferido 2.6+) como
    lote propio; hasta entonces un driver de terceros debe lanzar `AuthorizationBackendTimeoutError` en su
    deadline y marcar su purga parcial para cumplirlo.
14. **El catálogo que decide es el de la BD (versión compartida).** `authz_catalog_version` sube como ÚLTIMA
    sentencia de la transacción que escribe `authz_*` — la de `syncAuthzCatalog` y la de cualquier escritura a
    mano, ambas por `withAuthzCatalogWrite(async (trx) => …)`; `bumpAuthzCatalogVersion(trx)` exige ese trx (500
    `E_AUTHZ_CONFIG` sin él: un bump que se confirma antes que su escritura envenena el memo de los demás procesos
    para siempre). El memo la contrasta antes de servir (default `'always'`, un SELECT por PK por pregunta;
    `{ everyMs }` es una ventana acotada opt-in medida con reloj MONÓTONO) y **nunca sirve una decisión con una
    versión distinta de la de la base**. Un sync en otro proceso se ve en la siguiente pregunta de todos. Sin
    fila de versión legible (tabla, fila o número ausentes) ⇒ 503 «migración 2.0 no aplicada», nunca versión 0
    ni el memo viejo. **La fila del freeze (`id=2`) la lee el MOTOR por su conexión, jamás por la
    transacción del llamante** (L-1, 🟠 8 del auditor `{trx}`; revierte el atajo de 3b-7 «por el pool de
    1»): un snapshot anterior al freeze (InnoDB REPEATABLE READ, PG a ese nivel, SQLite WAL) diría «no
    congelado» y era un bypass medido en los tres motores. Con pool 1 la barrera es **503
    `E_AUTHZ_BACKEND_TIMEOUT` a `freezeTimeoutMs`** (deadline TOTAL con la espera del pool; el `timeout()`
    de knex solo cuenta con conexión y `acquireConnectionTimeout` eran 60 s medidos), nunca un cuelgue ni un
    bypass ⇒ **`{ transaction }` exige pool ≥ 2** (decisión del dueño 2026-09-01 (3)).
15. **La contención cubre las NUEVE escrituras, contra origen y destino** (3D · M3). `within` vale en
    `grant`/`revoke`/`deny`/`removeDeny` (contra el scope), `scopes.moved` (contra el padre nuevo Y la cadena
    ACTUAL del hijo, en fresco: se notifica ANTES de recolgar la fila), `scopes.attached` (contra el padre y, si el
    hijo ya existe, también su cadena: es un move), `scopes.detached` (contra el hijo) y la API de delegación
    `defineScopedRole`/`updateScopedRole`/`deleteScopedRole` (contra el OWNER del rol); `requireWithin: true` las
    exige todas y `'non-root'` rechaza además `within: APP_SCOPE` (`E_AUTHZ_WITHIN_ROOT_FORBIDDEN`). `within` viene
    de la SESIÓN (tenant autenticado), nunca del cuerpo de la petición: `within = scope` satisface por definición.
    Lo mismo el `actor` de la delegación, que ahí SÍ se evalúa (es toda la policy): sesión, jamás cuerpo.
    `manager.driver()` es la salida documentada de todas las barreras (plataforma y tests).
17. **La identidad de un scope es la CANÓNICA que devuelve el resolutor; el llamante nunca la fija** (2.5-B · K1).
    `resolveChain(scope)` ⇒ `[scope tal como está en la tabla del consumidor, ...ancestros, APP_SCOPE] | null`; el
    paquete usa `chain[0]` para TODOS los hechos (grant/deny/revoke/removeDeny, `list*`, `purgeScope`, bindings de
    FGA, ciclo de `scopes.attached/moved`). Un elemento 0 que no sea el scope pedido (otro tipo; uuid distinto salvo
    mayúsculas/guiones), una cadena vacía o un elemento mal formado ⇒ 503 `E_AUTHZ_RESOLVER_FAILED`. Los uuids van en
    MINÚSCULAS (422 `E_AUTHZ_INVALID_IDENTITY` si no): el alias por mayúsculas muere en la puerta y el alias por
    guiones (tipo `uuid` de PG) lo cierra la cadena canónica — **y donde NO hay cadena con la que canonizar (el
    `detached` de una fila ya borrada, 3F · S1) lo cierra `scopeSpellings`** (3b-2h · 🟠 3, auditor R2): la purga
    cubre la ortografía del llamante Y la canónica de la que puede ser alias (32 hex ⇒ también 8-4-4-4-12) — **y
    desde 3b-8 · A4 `revoke`/`removeDeny` hacen el MISMO fan-out en los dos drivers**
    (`canonicalScopeTargets`, `backend_guard.ts`): con la ortografía del llamante a secas +
    `onMissingDeletes: Ignore`, un alias hacía del delete un no-op SILENCIOSO y el hecho canónico volvía a
    conceder si el scope se restauraba. Antes
    se usaba la del llamante a secas y eso era fail-OPEN en escritura —`purgeScope` demostraba cero sobre un objeto
    que no existe y el scope real seguía concediendo para siempre—, justo al revés que en lectura. El juez lo observa con `memoryScopeTree` Y con el
    árbol SQL del harness (`sqlScopeTree`, PG/MySQL), que es donde estaba el bypass.
18. **Un rol local solo existe dentro de su owner** (3B). `authz_roles.owner_scope_key` es `global` (catálogo
    del config, `syncAuthzCatalog`) o `scopeKey(owner)` (`<tipo>|<uuid>`; `defineScopedRole`; la raíz nunca es
    owner y `global` no lo produce ningún scope). Regla única en ambos drivers: **una asignación en el scope S del
    rol R cuenta si y solo si R es global o su owner está en chain(S)** (S inclusive), decidida con el árbol de HOY
    (mover la unit fuera del owner retira lo concedido; volverla lo restaura). **Cómo se retira
    depende del driver** (3b-2e · E1, decisión del dueño del 2026-08-30, **breaking**): en
    `database` **sin escribir** (la regla se evalúa en cada pregunta); en `openfga` con
    `hierarchy: 'facts'` **con una escritura** —el modelo (c2) no tiene `owner`, así que un
    `role_binding` seguiría concediendo mientras su scope sea alcanzable: fail-open—, de modo que
    `scopes.moved` **barre** las aristas `scope#binding` de los roles LOCALES cuyo owner ya no está
    en la cadena, **por SUBÁRBOL movido** y no por nodo, y las reescribe cuando el owner vuelve a
    estarlo. Un rol GLOBAL no se toca; un local cuyo owner sigue siendo ancestro, tampoco. Esa
    escritura va por el mismo camino que cualquier cambio de árbol: con `scopes.outbox` la aplica
    `authz:scopes:relay`, así que hereda el fail-open temporal del lag del relay, y
    `authz:reconcile --to=<el driver desde el que sirves>` la reconcilia si el relay se perdió
    —**la pasada de MANTENIMIENTO de 3b-5**: lee los hechos del PROPIO store (`enumerateFacts`),
    recalcula `declaredRoleAt` con el árbol y el catálogo de HOY, borra las `scope#binding` que la
    regla prohíbe, escribe las que exige y las cuenta en `drift.roleVisibility`. Hasta 3b-5 esa
    pasada reconstruía desde `authz_*`, que en un despliegue `facts` no tienen NI UN hecho: el
    barrido no se aplicaba nunca (`forbidden` vacío) mientras el árbol sí se rehacía, o sea que de
    un `moved` perdido se aplicaba la mitad que CONCEDE y no la que retira, con
    `drift.roleVisibility: 0` (🔴 1 del auditor final)—. El criterio de aceptación es un caso de
    **paridad entre drivers** (el mismo `moved` ⇒ la misma respuesta de `authorize`), no el detalle
    de implementación. Coste: cero requests si el catálogo no tiene roles locales.
    **Y el NIVEL se barre igual** (3b-2g · R1, decisión del dueño del 2026-08-30 (2)): (c2) tampoco
    lleva el `scope_type` del rol, así que cambiar el nivel de un rol retiraba lo concedido en
    `database` y **seguía concediendo** en `facts`. Lo barre `projectCatalogRole`, que es el hook de
    «una escritura de catálogo cambió este rol» (el manager lo llama tras `defineScopedRole`/
    `updateScopedRole`, y un escritor «a mano» de `authz_*` tiene el mismo deber que ya tenía con el
    espejo de permisos): rehace las DOS proyecciones del rol, lo que concede (`permits_<P>`) y dónde
    es VISIBLE. Las dos caras usan la MISMA regla, `declaredRoleAt` —nivel declarado + owner en la
    cadena—, de modo que el barrido del owner no puede resucitar una arista que el nivel prohíbe.
    **Consecuencia conceptual, documentada y no escondida**: la arista `scope#binding` significa
    **«el rol es visible aquí»**, no «esta asignación existe» — el hecho de la asignación es el
    `assignee`, que ningún barrido toca (por eso `listRoles`/`hasRole`/`listSubjects` siguen
    enumerando por `assignee` + catálogo y no cambian de respuesta). Coste del barrido de nivel: una
    lectura por `projectCatalogRole` (los bindings del rol) y, solo si el rol es LOCAL y tiene
    bindings, la cadena del store de cada scope distinto; un rol sin bindings —todo
    `defineScopedRole`— son 0 escrituras. El coste de `moved` NO cambia (sigue siendo cero requests
    sin roles locales). Fuera del owner el rol
    no concede, no es membresía (`hasRole`/`list*`/`rolesInChain`/`effectivePermissions`/`authorizedScopes`) ni se
    asigna (422 `E_AUTHZ_ROLE_NOT_VISIBLE`). El slug no identifica un rol (dos tenants definen `lead@unit`); el uuid
    sí. `defineScopedRole/updateScopedRole/deleteScopedRole` son policy de ESCRITURA (actor obligatorio,
    `delegablePermissions` ∩ efectivos del actor en el owner sin deny —C2—, `0 < rank < min(actor, techo global)`,
    colisión hacia ARRIBA (global o ancestro-o-igual) ⇒ 422 y hacia ABAJO ensombrecimiento por AUTORIDAD **con
    rango** (3F · S3 + 3G · W3), globales inmutables, owner resuelto en FRESCO —C3—) y
    `assignableAt` de un permiso es control de COMPOSICIÓN (sync, define/update, `grant`); `authorize` no mira
    owner-policy, `rank` ni `assignableAt`: lo asignado concede lo que su rol vincula (invariantes 1, 2 y 8).
    `purgeRole(uuid)` en el puerto: todo o nada (`database`); en `openfga` es SOPORTADO desde 3b-2e · E4
    (con `role_binding#role` y `scope#binding` los bindings de un rol SÍ se enumeran; hasta 3b-2k el
    constructor lo retiraba en el modo `resolver`, que era la forma documentada de decir «no sé
    purgar» — ese modo ya no existe), con hechos primero y catálogo después y demostración de cero — no hay transacción que
    abarque FGA y SQL. Y **una escritura de catálogo que cambia los vínculos de un rol tiene que rehacer
    la proyección derivada**: `projectCatalogRole(uuid)` es opcional en el puerto y el manager lo llama
    tras `defineScopedRole`/`updateScopedRole` — sin él, en `facts` un rol recién definido no concedería
    NADA y quitarle un permiso seguiría concediéndolo (fail-open).
    Antes de 3b-2e `openfga` lo decía con 500 (`purgeRole: false`);
    sin él no hay `deleteScopedRole` ni `prune-orphans` (y por eso `defineScopedRole` es 500 ANTES de escribir),
    pero `scopes.detached` NO lo necesita: purga hechos.
    **La identidad del rol es el uuid también en el PUERTO** (3D · M1): `RoleQuery` admite `{ uuid }` en
    `grant`/`revoke`/`hasRole`/`listSubjects` y `rolesInChain` devuelve `CatalogRoleRef` (uuid+slug+nivel+owner),
    así que el manager nunca vuelve del slug al catálogo en policy. **La ambigüedad es un ERROR, no una regla de
    resolución**: si en la cadena hay más de un rol visible con ese `(slug, nivel)`, toda ruta por slug es 422
    `E_AUTHZ_AMBIGUOUS_ROLE` nombrando uuids y owners (se acabó «el owner más cercano gana», que convertía un
    homónimo en escalada); `authorize` no direcciona por slug y sigue respondiendo, `revoke` por slug quita los
    hechos de TODOS los homónimos del scope exacto. La unicidad `(slug, nivel)` **del MISMO owner** se DEFIENDE (3D · M2):
    `withAuthzCatalogWrite` bloquea la fila de `authz_catalog_version` (PG/MySQL; SQLite ya serializa) y
    `defineScopedRole` re-comprueba la colisión dentro de esa transacción leyendo la BASE — dos `define` del mismo
    owner acaban en exactamente uno y 422 para el perdedor. Con owners en relación ANCESTRO→DESCENDIENTE la regla de
    autoridad NO es conmutativa y la carrera tiene DOS finales legales (3G · Y1, tester 3F): si confirma primero el
    del ancestro, el del descendiente choca (1 rol); si confirma primero el del descendiente, el del ancestro entra y
    lo ENSOMBRECE (2 roles y el slug ambiguo ahí abajo). Los dos son ruidosos y nadie escribe dos veces por owner;
    exigir «exactamente un ganador» ahí era una aserción flaky en el artefacto publicado (2 ms de jitter la voltean
    en PG y en MySQL); `authz:catalog:diff`
    reporta los homónimos visibles (`ambiguousRoles`; desde 3F · S3 solo son deriva —exit ≠ 0— los que la autoridad no ordena). **Un rol cuyo owner sale del árbol queda DORMIDO, y lo
    barre la PLATAFORMA** (3b-0 · Z1/Z2; sustituye a 3D · M4, 3E · P2/P3, 3F · S1/S2 y 3G · W1/W2):
    `scopes.detached` purga **hechos y solo hechos** (invariante 11) —con la identidad CANÓNICA (`chain[0]`)—,
    NO escribe el catálogo, no mide rango, no enumera el subárbol y no devuelve nada. **DORMIDO significa
    exactamente «no visible desde ningún scope vivo cuya cadena NO pase por su owner», no «inerte»** (3b-0b · AA1,
    auditor 3b-0, medido): la regla única de visibilidad no cambia, y **un descendiente vivo cuya ruta
    materializada siga pasando por el owner la cumple**, así que ahí el rol CONCEDE, es membresía por los seis
    caminos y SE PUEDE ASIGNAR (por slug y por uuid). Es lo normal con rutas materializadas o con un borrado en
    dos pasos. Lo que sí vale siempre: no concede en un scope cuya cadena ya no alcanza al owner, y un huérfano
    sin asignaciones vigentes no concede nada. Lo que ocupa en todo caso es su `(slug, nivel)` allí donde todavía
    se le vea, y `deleteScopedRole` no lo alcanza (422 `E_AUTHZ_UNKNOWN_SCOPE`: resuelve el owner en fresco). La
    salida es `authz:catalog:prune-orphans` (`manager.pruneOrphanRoles`; `--dry-run` por defecto, `--force` para
    borrar): operación de PLATAFORMA —**API de plataforma junto a `driver()`**: se salta `requireActor` y
    `requireWithin` a propósito, así que no se expone por HTTP—, sin actor ni rango, que lee la BASE (no el memo
    con ventana, cota `maxLocalRoles` = 10 000 ⇒ 500 `E_AUTHZ_TOO_MANY_LOCAL_ROLES`), purga con `purgeRole` y
    notifica `role_purged` en orden estable por uuid. Como puede estar revocando permisos VIVOS, cada huérfano
    lleva `assignments` y `stillGranting` (conservador: cuenta hechos vigentes, no re-resuelve el scope de cada
    uno) y el comando los lista aparte con aviso. **Esos hechos los cuenta el DRIVER, no el barrido** (3b-2j,
    decisión del dueño del 2026-08-31 (3), **breaking del puerto**): `countRoleAssignments(uuids)` es opcional en
    `AuthorizationDriver` y devuelve, por posición, los hechos VIGENTES de cada rol. Contarlos en
    `authz_assignments` —la tabla del driver `database`— hacía que en `openfga` con `facts`, donde viven en el
    store, `stillGranting` fuese SIEMPRE `false`, y su contrato publicado es «falso ⇒ este rol seguro que no
    concede», leído justo ANTES de un borrado destructivo: fail-dangerous. Un driver que no lo traiga deja
    `assignments` y `stillGranting` en **`undefined`, jamás en `false`** («no lo sé» no puede degradar a «no
    concede», que es exactamente el bug) y el comando lista esos roles APARTE, como a los que sí conceden;
    capacidad `countRoleAssignments`, con su par de casos en la suite publicada; el reporte dice QUÉ se purgó (`purged: CatalogRoleRef[]`, no un
    contador: la pasada no es atómica). **Dos seguros contra el resolutor ciego** (3b-0b · AA2/AA3): con `force`,
    si TODOS los owners distintos salen huérfanos o los huérfanos pasan del 50 % de los roles locales ⇒ 500
    `E_AUTHZ_MASS_PURGE_REFUSED` antes de borrar nada, salvo `allowMassPurge: true` (`--allow-mass-purge`) —esa
    es la firma de un `resolveChain` filtrado por tenant o sin contexto, que se lleva el catálogo local entero; el
    `--dry-run` no lanza, lo marca en `massPurge`—; y cada owner se re-resuelve EN FRESCO justo antes de su
    `purgeRole` (la ventana es toda la pasada), de modo que un `attached`/restore concurrente lo salta y lo
    reporta (`skipped`, `reason: 'owner-came-back'`). **Los hechos de un DESCENDIENTE vivo sobreviven al
    `detached` del ancestro y vuelven a conceder si el scope se restaura con el mismo uuid** (3b-0b · AA4): la
    purga es del scope EXACTO (invariante 11) y decide el árbol de HOY; entre 3D y 3G el rol se llevaba sus
    asignaciones consigo, así que es un cambio de comportamiento; limpiarlos es notificar `detached` por nodo o,
    en 3b-3, `authz:reconcile --prune`. **Por qué se quitó de `detached`**: era una escritura de CATÁLOGO al final de una
    operación que dispara un TENANT, sobre un scope que ya no resuelve, así que hubo que inventarle una policy de
    rango sin cadena donde medirla, una enumeración del subárbol y una degradación; cinco lotes la tocaron y TRES
    de las cuatro regresiones de la Fase 3 nacieron ahí, siempre por COMPOSICIÓN de piezas correctas por separado
    (la última destruía roles locales de descendientes VIVOS, auditor P1). Con Z1 ninguna de esas piezas existe.
    Cae con ellas la premisa falsa del auditor D4 —«un rol cuyo owner no resuelve no es visible en ninguna parte»,
    que es falsa desde cualquier descendiente vivo cuya ruta materializada siga pasando por el owner—: ya no
    decide qué se ESCRIBE desde el árbol. Lo que no cae es la frase: `pruneOrphanRoles` es un consumidor NUEVO de
    esa premisa —es quien borra—, así que la premisa se corrige (arriba) en vez de declararse irrelevante, y el
    barrido MARCA los huérfanos que todavía conceden en vez de suponer que no existen (3b-0b · AA1). La colisión de `defineScopedRole` no cambia y no hacía falta tocarla: bloquea solo el homónimo
    VISIBLE desde el owner nuevo (global, o con su owner en la cadena YA resuelta), así que un rol dormido no
    bloquea ningún `(slug, nivel)` que no ocupara ya.
    **Ensombrecer exige RANGO, no solo posición** (3G · W3, auditor P3′): `define`/
    `update` que ensombrecen al homónimo de un descendiente piden `rank(actor) > rank(ensombrecido)` (422
    `E_AUTHZ_RANK_EXCEEDED` que NO nombra el rank ni el owner del de abajo); si no, un rank 3 de una organization
    inutilizaba por slug un rol rank 40 de una unit, en toda su cadena y sin que la víctima pudiera repararlo.
    **«Sobre un rol solo actúa quien lo supera en rango» es una COMPROBACIÓN DE ESCRITURA, no un invariante**
    (3b-1 · D3, auditor 3G): «ensombrece» es función del árbol de HOY y el árbol se mueve sin preguntarle al
    catálogo — `scopes.moved` puede meter un subárbol bajo una organization que ya tiene el homónimo y la sombra
    aparece **sin que se juzgue ningún rango en ninguna parte** (y el dueño del subárbol movido puede no poder
    repararla: su rango se mide en la cadena del owner de la sombra, donde no vale nada; ahí solo la plataforma).
    Lo mismo, en una ventana más estrecha, en la propia escritura: si `resolveChain` no responde por el owner de la
    víctima en ese instante la sombra no se demuestra y el `define` entra (3b-1 · D2) — **a propósito**: rechazar
    convertiría un rol DORMIDO en un bloqueo de `(slug, nivel)`, que es la mina que 3b-0 · Z1 quitó, y por una
    condición que el llamante no ve. Las dos son ruidosas (`shadowedByAncestor` en el diff, `--fail-on-shadows`),
    ninguna concede nada (`authorize` no direcciona por slug) y el límite honesto de la comprobación es que **solo
    protege a los roles que YA existen**: el mismo atacante logra la misma denegación yendo PRIMERO, sin trampa.
    **La degradación de `descendantsOf` (ya solo la regla de NIVEL) la relaja a la MÍNIMA y el propio actor puede provocarla**
    creando hijos (o una réplica caída): está aceptado y acotado —la regla mínima no concede nada, es la que corre
    con el stub publicado— y la mina residual la repara autoridad+rango (3G · X1). **Reparar ensombreciendo exige
    superar el rango DEL SQUATTER** (3b-1 · D1, auditor 3G): `rank` es metadata del consumidor (invariante 8) y nada
    obliga a que decrezca con la profundidad, así que con un reparto NO monótono —un rank 60 en una unit bajo el
    org-admin rank 50 que es DUEÑO de ese árbol— el dueño se lleva 422 `E_AUTHZ_RANK_EXCEEDED` por las DOS puertas
    (definir su homónimo y `deleteScopedRole`) y `scopes.detached` tampoco es una tercera (desde 3b-0 purga hechos y
    no mira el catálogo). El recurso es entonces la **plataforma**, y lo tiene siempre: `#assertRank` acota todo rank
    local por debajo del techo global, así que quien lleva el rol global de mayor rank supera a cualquier squatter, y
    `manager.driver().purgeRole(uuid)` no mide rango. `authz:catalog:diff
    --fail-on-shadows` es el gate opt-in para quien sí quiera enterarse por CI (3G · X3).
    **Un scope que el árbol YA NO conoce se purga igual** (3F · S1): `detached` limpia DESPUÉS de borrar la fila
    y no necesita cadena para nada —purga los hechos del scope tal cual (`canonicalScope`)—.
    **Declarar `descendantsOf` nunca deja peor que no declararlo** (3F · S2): si el subárbol no se puede enumerar
    (más de `maxDescendants`, o un `descendantsOf` que falla) la regla de NIVEL cae a la mínima en vez de tumbar
    la operación con un 503.
    **El nivel de un rol local nunca está POR ENCIMA de su owner** (3E · P1): si `scopeType` es el nivel de un
    ANCESTRO del owner (`app` incluida, que está en toda cadena) ⇒ 422 `E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER` en
    `defineScopedRole` Y en `updateScopedRole` — un rol así no es visible en ninguna parte y solo ocupa el nombre:
    era la mina de slug del auditor (A1). Se decide con la cadena YA resuelta, sin `descendantsOf`: el nivel del
    owner vale y cualquier otro se presume descendiente (delegar hacia abajo —`lead@unit` con owner una org— es el
    caso común y funciona con el stub publicado). **Con `scopes.descendantsOf` declarado se endurece**: el tipo
    tiene que aparecer de verdad bajo el owner en el árbol de hoy.
    **La colisión se decide por AUTORIDAD** (3F · S3): *una definición más autorizada gana y ensombrece a la
    menos autorizada* —global > local de un ancestro > local de un descendiente—. `defineScopedRole` desde un
    ANCESTRO del owner de un homónimo ya NO es 422: crea el suyo y ensombrece al del descendiente
    (`shadowedByAncestor` en el evento `role_defined` y en el diff), así que el dueño del árbol siempre puede
    definir su rol y la mina solo se ensombrece a sí misma; hacia ARRIBA (global, o ancestro-o-igual) sigue
    siendo 422 `E_AUTHZ_CATALOG_CONFLICT`. El `diff` NO cuenta como deriva lo ensombrecido por autoridad
    (`shadowedByGlobal`/`shadowedByAncestor` se listan, exit 0: un tenant no puede dejar en rojo el gate de CI
    de la plataforma) y `ambiguousRoles` solo conserva lo que la autoridad no ordena (dos owners que se declaran
    ancestro el uno del otro), que sí es deriva.
    **Los globales GANAN y nada es silencioso** (3E · P1 b / P6): `syncAuthzCatalog` ya NO aborta por un
    local homónimo (un tenant de rank 2 paraba el deploy entero): escribe el global y lo REPORTA (`shadowedByGlobal`),
    y revalida TODOS los roles vivos contra el `assignableAt` nuevo reportando los vínculos que ya no admite
    (`assignableAtViolations`, sin borrarlos: lo asignado sigue concediendo); solo `assignableAtViolations` es deriva en
    `authz:catalog:diff` (exit ≠ 0). **`purgeRole` es OPCIONAL en el puerto** (3E · Q4) y no traerlo es la forma de
    decir «no sé purgar»: entonces `defineScopedRole` es 500 `E_AUTHZ_UNSUPPORTED` ANTES de escribir (3E · P4), porque
    un rol local que nada podría borrar deja muertos `deleteScopedRole` y `scopes.detached` de ese scope para siempre.
    `owner_scope_key` solo puede ser `global` o `<tipo>|<uuid>` de un scope que no es la raíz: `app` a mano es catálogo corrupto (500).
16. **`authorizedScopes` es coherente con `authorize` o lanza.** Cada candidato se contrasta con
    `resolveChain` (el deny se aplica por su cadena; si no cuelga del scope concedente ⇒ 503
    `E_AUTHZ_RESOLVER_FAILED`); la cota se corta antes de pasear; `excludedSubtrees` son subárboles
    (`ExcludedSubtree`, `expandExcludedSubtrees`). Coste O(descendientes × `resolveChain`), acotado por
    `maxDescendants` (documentado, no cambiado). Una vista de `forRequest()` caduca para leer —
    `expandExcludedSubtrees` incluida— (`maxAgeMs`, default 30 s, reloj monótono ⇒ 500 `E_AUTHZ_VIEW_EXPIRED`).

## Reglas de higiene del paquete

- **Pureza**: `scripts/check_purity.mjs` falla el build si `src/`, `providers/`,
  `services/`, `commands/`, `index.ts` o `configure.ts` importan aliases de un
  consumidor (`#config`, `#models`, `#services`, `#start`…). Todo entra por config
  o inyección.
- **El catálogo es propiedad local siempre.** Roles/permisos viven en tablas `authz_*` y
  ningún driver puede ser su fuente de verdad. Un driver PUEDE mantener una **proyección
  derivada** del catálogo (driver `openfga`: permisos como relaciones del modelo + vínculos
  rol→permiso como tuplas) si y solo si: (a) es reconstruible desde `authz_*` con
  `authz:reconcile`, (b) `reconcile --dry-run` la vigila, (c) nunca se lee como catálogo.
- **Todo en un driver o todo en otro.** Cada driver es completo por sí mismo (hechos + árbol
  + proyección del catálogo) y la migración entre drivers es `authz:reconcile` (**3b**):
  idempotente, bidireccional, reanudable, nunca silenciosa (reporta written/deleted/updated/skipped).
  **`openfga:import` se borró en 3b-2k · K2**: escribía las tuplas del modo `resolver` (`role_binding#assignee`,
  `deny_binding#denied`), que el modelo (c2r) ni siquiera declara, así que llenaba un store que no concede nada.
  **La dirección DB → FGA existe desde 3b-3a**: `authz:reconcile --to=openfga [--dry-run] [--prune]`
  (`manager.reconcile({ to })`, API de PLATAFORMA junto a `driver()`; el DESTINO se nombra por su clave
  en `config.drivers`, no por el activo: migrar es llenar el destino mientras el motor sirve desde el
  otro). Migra las CUATRO cosas —marcador de raíz, proyección del catálogo, árbol (desde
  `scopes.enumerateEdges`, puerto nuevo del config; `sqlScopeEdges` lo implementa) y hechos de
  `authz_*`—, lee el origen por lotes de 100 con cursor sobre la PK y el destino ENTERO (`Read` sin
  filtro: es la única forma de ver lo que sobra, incluida la basura de un modelo anterior, que se lee
  y se borra aunque ya no se pueda escribir). Reglas que NO se negocian: **`--dry-run` es el
  verificador y es read-only por contrato** —mismos números, cero escrituras, y **un `--fix` queda
  PROHIBIDO** (S18): sería un mecanismo de concesión—; **lo DERIVADO se rehace siempre** (marcador,
  catálogo y árbol son espejos de datos locales: ahí se borra lo que sobra, que es lo que repara un
  nodo con dos padres y lo que exige S7 para las aristas que `enumerateEdges` no respalda) y **los
  HECHOS solo con `--prune`** (los del scope que ya no resuelve —cierra AA4— y los sobrantes), **con
  una excepción a propósito**: la arista `scope#binding` que el origen respalda y la regla de
  visibilidad niega (invariante 18) se borra SIN `--prune` y se cuenta en `drift.roleVisibility`,
  porque dejarla es fail-OPEN y es justo la escritura que el relay pudo perder; **los ciclos se
  REPORTAN** y ninguna arista de un ciclo se escribe (cruce 3, parte ii: FGA lo evalúa y la herencia
  se vuelve bidireccional), así que esos nodos dejan de alcanzar la raíz y DENIEGAN; **la ventana del
  relay** (encolado sin relevar) y lo APARCADO van en `drift`; **nada de `Ignore` a ciegas** (S7: el
  importador viejo se quedaba la caducidad vieja y la contaba como escrita — aquí el destino se lee
  entero, una diferencia de caducidad es delete+write y los contadores salen del diff). Durante la
  pasada que ESCRIBE, el freeze — que desde 3b-7 es **DURABLE, con dueño y con lease** (decisión del dueño del
  2026-08-31 (3b): B + E-analista): vive en la fila `id=2` de `authz_catalog_version` (colocación MEDIDA: en
  `id=1` la renovación esperaba al `FOR UPDATE` del catálogo 805-816 ms; en su fila, 10-12), la lee TODA
  escritura del manager con una consulta PROPIA y sin memo (+0,14 ms p50 por escritura en PG, +0,11 en MySQL,
  **0 en `authorize`** — colgarse del memo la convertía en «freeze que todavía no aplica» con `{ everyMs }`),
  y alcanza a **todos los procesos que comparten `authz_*`** (invariante 14): escrituras 503 `E_AUTHZ_FROZEN`
  **reintentable** en toda la flota, lecturas normales. `freeze()` devuelve un TOKEN (`{fence, holder}`) y
  `unfreeze(token)` solo levanta el suyo (un freeze vivo ajeno ⇒ **423 `E_AUTHZ_FREEZE_HELD`**: dos pasadas no
  se pisan, y el anidado corre DENTRO sin levantar la ventana exterior — A1.1/A1.3 del auditor). El lease
  (default 15 s, renovación condicional cada `leaseMs/3`, `unref()`) hace que tras un `SIGKILL` la flota
  vuelva a escribir SOLA en ≤ `leaseMs`; y la garantía se DEMUESTRA, no se supone: la pasada publica
  `report.frozen = { durable, lapsed, leaseMs, fence }` y `lapsed: true` (el lease se perdió a mitad) ⇒ la
  pasada NO se certifica y el comando sale ≠ 0. **La fila `id=2` ausente ⇒ 503 «migración 2.0 no aplicada» en
  toda escritura, jamás «no congelado»** (mismo patrón que la fila `id=1`). **Lo que el freeze NO congela, por
  su nombre** (auditor 🟠 5, medido): `syncAuthzCatalog`, `manager.driver()` y el árbol SQL del consumidor; y
  la promesa publicada es «otro proceso recibe 503», jamás «ninguna escritura entra en la ventana» (no hay
  atomicidad entre una fila SQL y un backend externo). La garantía es del MANAGER de este paquete: la suite de
  contrato publicada no la verifica para drivers de terceros, y va escrito en el README. **El CUTOVER tiene
  comandos** (3b-7 · F6, condición del juez): `authz:freeze --reason=… [--lease-ms]` abre la ventana del
  operador (kind `operator`, **sin caducidad por defecto** — la duración del cutover y la tolerancia a la
  parada son magnitudes independientes; `--lease-ms` es el opt-in de caducidad sin renovación, con su contra
  declarada) y `authz:unfreeze` la cierra (se niega a levantar el freeze de una pasada viva salvo `--fence=N`);
  `reconcile` reconoce una ventana de operador viva como CONTEXTO propio: corre dentro, no la renueva ni la
  levanta, y su `lapsed` dice si la ventana aguantó la pasada entera. La garantía multiproceso solo es
  observable donde otro proceso puede abrir la base (pg/mysql/sqlite-file, `freeze_multiprocess.spec.ts`): en
  `:memory:` el mutante `modulo` (el «durable» como global de módulo) deja `npm test` VERDE — por eso los jobs
  de motor de CI no son opcionales. **`--dry-run` NO congela** (3b-6): el
  verificador es read-only por contrato, no tiene nada que proteger, y está publicado para correrlo en CI y en
  un cron — o sea el sitio desde el que un mecanismo de indisponibilidad se dispara solo (hoy el proceso del
  job; la flota entera ahora que el freeze ES durable).
  **El ORIGEN se lee en UNA foto consistente** (3b-6, 🔴 3 del panel 3): los dos barridos de `readSourceFacts`
  (`authz_assignments` y `authz_denies`) van en la MISMA transacción de lectura repetible. Sueltos, el hueco
  entre ambos —pasear la primera tabla entera por lotes— partía las operaciones COMPUESTAS: un offboarding
  (`revoke` + `removeDeny`) que cayera ahí dejaba el destino con **el rol sin su deny**, concediendo algo que ni
  el estado anterior ni el posterior concedían, con `written=13 extra=0 skipped={} clean=true`. No es una
  pérdida: es una ESCALADA fabricada. Con la foto, el peor resultado de la ventana es «el estado consistente de
  `t0`», deriva recuperable que repara la pasada siguiente. **Lo que garantiza cada motor se DECLARA**: PG
  `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ`; MySQL/InnoDB con `SET TRANSACTION ISOLATION LEVEL
  REPEATABLE READ` explícito (es su default, pero un ajuste del servidor no es una promesa del paquete); SQLite
  **sin** nivel (knex avisa y lo ignora: su transacción de lectura ya es una foto). **Y lo que NO cubre va
  escrito**: cubre la dirección cuyo origen es `authz_*`; donde la fuente de verdad es el STORE
  (`enumerateFacts`: `--to=database` y la pasada de mantenimiento) las páginas de `Read` tampoco son una foto y
  no hay REPEATABLE READ que valga — esa dirección queda ABIERTA, y el testigo posible
  (`readChanges({startTime})`) no está implementado. `--prune` con `authz_*` sin una sola
  fila de hechos es 500 `E_AUTHZ_MASS_RECONCILE_REFUSED` (mismo patrón que AA2; `--allow-mass-delete`
  es la salida humana y `--dry-run` no lanza, lo marca).
  **De dónde salen los HECHOS lo decide QUIÉN ES SU FUENTE DE VERDAD** (3b-5, los dos 🔴 del
  auditor final; `ReconcileSource.factsOrigin`, lo pone el manager y el driver obedece):
  si `--to` es el driver **ACTIVO** (`config.default`) y declara `hierarchyFacts`, sus hechos son
  SUYOS y se leen de él por `enumerateFacts` —pasada de **mantenimiento**: rehace lo derivado
  (marcador, catálogo, árbol) y el barrido de visibilidad, y no escribe ni borra un solo hecho—;
  con `--from=<driver>` manda el operador (si sus hechos son `authz_*`, es la MIGRACIÓN de un solo
  sentido de siempre); en cualquier otro caso, `authz_*`. El reporte lo DICE (`factsFrom`, primera
  línea del comando). Leer `authz_*` siempre era la raíz de los dos 🔴: tras el cutover a `facts`
  esas tablas quedan congeladas, así que la pasada por DEFECTO —sin ninguna bandera— resucitaba un
  `revoke` posterior y con `--prune` borraba los `denied_<P>` vivos, y el seguro
  `E_AUTHZ_MASS_RECONCILE_REFUSED` era ciego a eso (miraba el conteo CRUDO del origen, no si
  aportaba algo: una sola fila vieja lo desarmaba). **Desde 3b-8 · B1 el seguro cuenta hechos
  UTILIZABLES**: un origen que devuelve N filas y las N se descartan (caducadas, scopes que ya
  no resuelven) también se niega, en las dos direcciones, y el error dice cuántos se leyeron y
  descartaron. Y **`expired` no es deriva para `reconcileLines`** (3b-8 · B2): es la pérdida
  DECLARADA de la migración, se sigue contando pero no clava el exit 1; las caducadas que
  SOBRAN en el destino sí (`extra-fact`), y su barrido es `--prune`.
  **La dirección FGA → DB existe desde 3b-3b**: `authz:reconcile --to=database [--from=<driver>]`.
  Migra **los HECHOS y solo los hechos**: el ÁRBOL no se migra —el driver `database` lo lee de las
  tablas del CONSUMIDOR en cada pregunta, que son su fuente de verdad, y copiarlo sería inventar una
  segunda copia y con ella una deriva que hoy no existe— y el CATÁLOGO tampoco (propiedad local
  siempre). Por eso las fases `root`/`catalog`/`tree` son CERO en esa dirección: es una respuesta, no
  un hueco. El árbol sí se USA, para decidir qué hecho es migrable (`unknown-scope`) y bajo qué
  identidad CANÓNICA se escribe cada fila (invariante 17). Los hechos llegan por
  **`enumerateFacts({limit, after})`**, método opcional del puerto con **capacidad `enumerateFacts`**
  (la entrada de contrato que el 3a dejó pendiente): como mucho `limit` por página, orden total y
  estable, cursor opaco que tiene que AVANZAR, y **no filtra nada** —una asignación caducada tiene
  que LLEGAR con su `expiresAt` para que el destino la cuente en `skipped`; filtrarla en el origen la
  haría desaparecer sin rastro—. `openfga` lo implementa (sus hechos son tuplas); `database` declara
  `false` a propósito (sus hechos SON `authz_assignments`/`authz_denies`, el esquema PUBLICADO, y el
  destino los lee de ahí). **Quién es el ORIGEN se decide en voz alta**: con dos drivers registrados
  es el que no es `--to`; con más de un candidato, 500 `E_AUTHZ_CONFIG` pidiendo `--from` (de dónde
  salen los hechos decide lo que queda escrito); sin ninguno, 500 `E_AUTHZ_UNSUPPORTED` nombrando
  `enumerateFacts` — jamás leer cero hechos y vaciar el destino con `--prune`. La resolución es
  PEREZOSA: `--to=openfga` no construye ningún origen. Y **dos hechos del origen que colapsan en UNA
  fila** (S15: el store distingue `scope:unit|aaa…` de `scope:unit|aaa-…` y la tabla del consumidor
  no puede tener las dos) se cuentan como `folded-scope` y la fila se queda con la caducidad que MÁS
  dura (el origen concedía mientras cualquiera siguiera viva).
  **La cota del volcado es DECLARADA** (3b-3b · B5): reconciliar exige la foto ENTERA del destino en
  memoria —sin ella no se sabe qué sobra, que es la mitad del trabajo—, así que `maxTuples`
  (`--max-tuples`, default 1 000 000) la acota y pasarse es 500 `E_AUTHZ_RECONCILE_TOO_LARGE`
  **antes de escribir nada**. No hay migración por particiones, y «reanudable» sigue significando
  *idempotente y se repite*, no un cursor persistido: las dos cosas escritas, no descubiertas en
  producción.
- **La migración NO es sin pérdida, y las pérdidas se DECLARAN** (3b-3b · B3; panel 2, requisito 3
  del dueño: *«posible con pérdidas declaradas y con ventana»*). Lo hace ejecutable
  **`runMigrationContract`**, publicado en `/testing` junto al resto de la suite porque un driver de
  TERCEROS tiene que poder correrlo: siembra FIJA (7 nodos, 6 holders, 4 roles, 14 grants, 5
  caducidades, 6 denies, escritos con la API del driver) → **448 preguntas idénticas** en origen y
  destino (168 `authorize` + 168 `hasRole` + 42 `listRoles` + 24 `listScopes` + 28 `listSubjects` +
  18 `listRoleScopes`) → **tres combinaciones** (ida, vuelta e ida-y-vuelta con `--prune`). Corta por
  TRES sitios: una respuesta que cambia sin pérdida declarada que la explique **falla**; **todo
  motivo que la pasada CUENTA en `report.skipped` y no está declarado falla también**; y una pérdida
  declarada que NUNCA ocurre falla igual (es una línea falsa en el README). **Esas dos últimas caras
  cruzan lo que el driver se AUTO-DECLARA**, así que cierran las omisiones descuidadas y no las
  silenciosas: un driver que tira un hecho sin contarlo no puebla `skipped` (tester Fase 3b, medido).
  Lo que sí cierra las silenciosas es el **CENSO** (3b-4 · C1): el contrato mira el destino **hecho a
  hecho** —los 20 de la siembra, por el camino DIRECTO del puerto: `listRoles` y `listDenies`— y una
  ausencia sin motivo declarado **y contado** falla, se mueva o no alguna de las 448. Sin el censo,
  un deny reubicado a otro scope de la misma cadena pasaba las tres combinaciones en verde (medido,
  con caso). `listDenies` es OPCIONAL en el puerto: un driver que no lo traiga deja sus 6 denies
  observados solo por `authorize`, y el veredicto lo dice en `censusLimits` en vez de callárselo.
  El **cruce de CADUCIDADES** es la tercera pieza: ninguna de las 448 devuelve un `expiresAt` y el
  contrato no adelanta ningún reloj, así que perder la caducidad de un grant vivo (fail-OPEN) era
  invisible; se cruza con `grant` y `expiresAt` OMITIDO ⇒ `previousExpiresAt` (invariante 10), en el
  destino y —en `a→b→a`— también en el intermedio. **Del par del paquete la lista declarada es UNA: `expired`.** Las
  otras tres que el panel había listado se MIDIERON y no son pérdidas de la migración: la precisión
  sub-segundo en MySQL la cierra el esquema publicado (`expires_at` es `DATETIME(3)` y el codec
  escribe y lee milisegundos), los hechos sobre scopes fantasma son `unknown-scope` con caso en las
  dos direcciones, y la collation `*_ci` es una divergencia de LECTURA (el par `canonicalScopeReads`),
  no algo que la migración pierda — salvo el colapso de dos hechos en una fila, que sí se cuenta
  (`folded-scope`).
- **El árbol de scopes es un hecho del contrato.** El consumidor notifica sus cambios con
  `authorization.scopes.attached/moved/detached` en TODOS los drivers (en `database` es casi
  no-op salvo `purgeScope`). `resolveChain` sigue existiendo para validar escrituras y
  para reconcile. Anti-ciclos y validación de existencia son del paquete, nunca del backend.
- **Y esas tres notificaciones NO se deshacen con un `rollback`** (3b-2d; panel 2, cruce 4 · S5).
  El paquete escribe en el backend dentro de la transacción del consumidor; si esa transacción se
  cae después, SQL dice un padre y el backend otro, y en `hierarchy: 'facts'` —donde FGA es el PDP—
  eso es una **escalada persistente e invisible desde la base del consumidor**. No es mal uso: el uso
  correcto fuga. Mitigación: el puerto **`scopes.outbox`** (`ScopeOutbox`: `enqueue`/`pending`/
  `markApplied`/`markFailed`, más `dead?`/`acquire?` desde 3b-2h), con el que `scopes.*` ENCOLA en la
  transacción del consumidor
  (`{ transaction }`) en vez de tocar el driver, y **`authz:scopes:relay`** (`manager.relayScopeChanges`,
  API de PLATAFORMA junto a `driver()`) que drena: reanudable y reportando QUÉ aplicó.
  **Un fallo APLAZA lo que depende de él y deja pasar el resto** (3b-2h · 🔴 2, auditor R2): parar en
  el primer fallo conservaba el orden del árbol pero convertía una entrada irreparable —el padre del
  `attached` encolado borrado antes del relevo— en un **tapón permanente para todos los tenants**
  (medido: la unit nueva nunca recibía su arista y el deny de su org nunca la alcanzaba). El orden se
  conserva igual porque dos cambios que pueden interactuar comparten siempre un scope: la
  contaminación va por clave de scope y es transitiva. Y la cola CONVERGE: `sqlScopeOutbox` APARCA
  una entrada tras `maxAttempts` (default 5) —sale por `dead()`, el relay la reporta en TODAS las
  pasadas y el comando sale ≠ 0 mientras exista—. **El relay es escritor ÚNICO** (3b-2h · 🟠 4):
  `pending()` no reserva nada y dos pasadas sobre el mismo lote dejan el árbol del store REVERTIDO
  con un solo padre (medido, y sin `assertOneParent` que lo delate); `acquire()` da el lease
  (cerrojo de servidor en PG/MySQL, de proceso en SQLite) y la segunda pasada no hace nada (`busy`). El paquete NO impone tabla: publica el puerto,
  `sqlScopeOutbox` sobre Lucid y `stubs/scopes_outbox_migration.stub` (que `configure` NO publica:
  es opt-in). **El driver `facts` se niega a construirse** sin `outbox` y sin
  `acceptScopeDriftRisk: true` (500 `E_AUTHZ_SCOPE_DRIFT_UNGUARDED`): una recomendación no es un
  mecanismo. **Riesgo 🟠 que queda, aceptado y escrito literal en el README**: el lag del relay
  (segundos) durante el cual FGA decide con el árbol VIEJO. **Los dos signos, desde (c2r)**
  (3b-2i, decisión del dueño del 2026-08-31 (2), **breaking**): tras un `moved`/`detached` es
  **fail-open temporal** (el tenant antiguo conserva acceso; el scope borrado se purga cuando pasa
  el relay), y tras un `attached` es **fail-CLOSED temporal** —*un scope recién creado no concede
  NADA hasta que pasa el relay*, porque su cadena todavía no llega a la raíz en el store—. Antes
  concedía y no heredaba los denies de arriba, que era el fail-open que (c2r) cierra. La receta es
  **drenar la cola en la misma petición, tras el commit** (`relayScopeChanges()`), y **sin outbox la
  ventana es CERO** (el manager llama al driver en línea). No
  hay 2PC — y **un ciclo más corto solo acorta la ventana de lo que la cola PUEDE aplicar**: lo que
  falla no está acotado por el ciclo y lo aparcado no se aplica nunca (la frase del README corregida
  en 3b-2h, con caso). Y `verify` (3b-3) es **read-only por contrato**: un `--fix` sería un mecanismo de
  concesión (S18) y queda prohibido.
- **`{ transaction }` es una CAPACIDAD declarada con dos puertas, exige pool ≥ 2 y `openfga` la rechaza**
  (2.4.0-alpha.2, panel `{trx}` → veredicto (C); decisiones del dueño 2026-09-01 (3)). `transactionalWrites`
  —MISMO nombre en `AuthorizationDriverCapabilities` y `RelationsDriverCapabilities`— significa EXACTAMENTE
  «los dos o ninguno con TU transacción», jamás «no se pierde»; sin valor intermedio. **Puerta 1**, por
  llamada y siempre: `{ transaction }` a un driver `false` (o sin `capabilities`) ⇒ 500 `E_AUTHZ_UNSUPPORTED`
  nombrando driver, operación y las DOS salidas (`database`, o `requireTransactionalWrites` para fallar al
  arrancar), cero llamadas al driver; 500 y no 422 por precedente (`membersOf`, `purgeRole`). **Puerta 2**,
  opt-in: `requireTransactionalWrites: true` (raíz; `relations.requireTransactionalWrites` lo anula para ese
  puerto) ⇒ 500 `E_AUTHZ_CONFIG` al RESOLVER el driver (lecturas incluidas: el despliegue no arranca) sin
  inutilizar un driver que solo está REGISTRADO — NO «falla al construirse» (tumbado por los dos panelistas).
  `{ transaction }` significa TRES cosas y el docblock lo dice: ESCRIBE en `grant/revoke/deny/removeDeny` y
  `relate/unrelate/purge*`; ENCOLA en `scopes.*` (no pasa por la puerta: encolar ≠ escribir); se RECHAZA en
  la delegación (`withAuthzCatalogWrite` es el serializador, invariante 14). `openfga` = `false` explícito y
  **re-valida en el driver** (`rejectTransaction`, L-5: `manager.driver()` no es salida; espía sobre el
  cliente FGA real = 0 llamadas); **no hay outbox de hechos ni de relaciones** — la opción (A) del panel se
  descartó con número (fail-open 1,16 s mediana / 2,28 s cola durante el lag, 131,5 entradas/s no
  paralelizables ⇒ 38 s para 5.000, aparcado irreparable, resurrección medida) y la (B) porque en `facts`
  una escritura toca cero filas SQL. Un caso de PARIDAD fija la asimetría a propósito (200 en `database`,
  500 en `openfga`: la respuesta correcta). Los DOS runners exigen las DOS caras de este par
  (`BOTH_FACES_REQUIRED`/`uncoveredCapabilities`): la `true` (rollback ⇒ censo cero, hook `transactions`)
  corre solo en pool ≥ 2 (`sqlite-file`/PG/MySQL) y `:memory:` declara `false` (opción `transactionalWrites`
  del driver: el DRIVER declara lo que su despliegue puede, el paquete no adivina el pool). La garantía es del
  driver `database` del paquete; para un driver de terceros el runner exige el censo pero no puede probar lo
  que hace por dentro (README, «Third-party drivers»). **Docs con dientes** (L-6): `tests/trx_docs.spec.ts`
  (el README no dice «atomic» de `openfga` con la trx del consumidor; la LETRA del 500; las frases del freeze
  ampliado, de `resolveChain` y de terceros) y el grupo L-6 de `contract.spec.ts` (la receta por dirección
  MEDIDA contra el `:8101`: no compone, el paquete no la automatiza, Lucid TRAGA lo que lanza un
  `after('commit')`, «dentro» exige pool ≥ 2 también con `openfga` porque la barrera es SQL).
- **Un driver DECLARA lo que puede hacer, y cada valor declarado tiene un caso** (3b-2e · E2).
  `AuthorizationDriverCapabilities` en el puerto (`driver.capabilities`): `hierarchyFacts`,
  `singleCheckAuthorize`, `roleInheritanceNative`, `listObjectsInherited`, `purgeRole`,
  `countRoleAssignments` (3b-2j) y `canonicalScopeReads` (3b-2k · K1). Las dos del
  medio son **`false` en los dos drivers del paquete, también en `facts`** (panel 2, cruce 6): los
  cinco `list*`/`hasRole` siguen usando `resolveChain` y ningún `list*` enumera herencia. Por eso el
  titular **«sin SQL en el camino caliente» está PROHIBIDO** a secas: lo cierto es «sin SQL por
  request en `authorize`», y el README lleva el literal aprobado palabra por palabra (con un caso que
  lo fija). No es documentación: **el manager LEE `capabilities.hierarchyFacts`** para el gate de
  deriva (abajo), y la suite de contrato lanza al registrarse si se declara `true` algo sin caso.
- **Las DOS divergencias de `facts` que quedan están DECLARADAS, no arregladas** (3b-2k · K1;
  decisión del dueño del 2026-08-30 (2), R2 (b) y (c), con la CORRECCIÓN del 2026-08-31 que dejó
  fuera (a) —cerrada por (c2r) en 2i— y la cara de ESCRITURA de (c) —cerrada en 2h—). Cada una es un
  **par de capacidad con caso negativo**, jamás un `skip`:
  **(b) con el resolutor del consumidor caído, `facts` es *grant-only*** — `authorize`/`authorizeMany`
  responden con el árbol del store (y responden `true` a lo concedido) mientras `revoke`/`deny`/
  `removeDeny`/`purgeScope`/`hasRole`/`list*` son 503: **concede y no se puede revocar** (auditor R2 ·
  🟡 5). Es la propiedad que el dueño compró (PDP autónomo); cerrarla sería meter `resolveChain` en el
  camino caliente de `authorize` y deshacer la fase. Lo juzga el par `hierarchyFacts` (la cara `false`
  conserva el «lanza entero» que el caso general de `authorizeMany` afirmaba para todos).
  **(c) un alias del uuid del scope no encuentra sus hechos en LECTURA** — `authorize` compone el
  objeto del store con la ortografía del LLAMANTE, así que un uuid sin guiones (la MISMA fila para una
  columna `uuid` de PG o una collation `*_ci` de MySQL) responde `false` donde `database` responde
  `true`. Es fail-**CLOSED** y no evade ningún deny, pero no es la misma respuesta. Capacidad
  `canonicalScopeReads` (`true` en `database` y en `resolver`, `false` en `facts`), cuya cara `false`
  fija además que la ESCRITURA sí canoniza en los dos drivers.
- **El gate de la deriva del árbol está en el MANAGER, no solo en el driver** (3b-2e · E3; cierra el
  agujero que el 3b-2d declaró). El gate del driver mira SU opción `outbox`, pero quien ENCOLA es el
  manager, que lee `config.scopes.outbox`: declararla solo en el driver dejaba el gate contento y la
  mitigación apagada. Con un driver que declara `hierarchyFacts`, el manager exige `scopes.outbox` o
  `scopes.acceptScopeDriftRisk: true` **en el config** (500 `E_AUTHZ_SCOPE_DRIFT_UNGUARDED` al
  resolver el driver). Un driver sin `capabilities` se trata como `hierarchyFacts: false`.
- **Cotas del modo `facts`, MEDIDAS** (3b-2e · E5): profundidad de cadena que `can_<P>` resuelve =
  **22 saltos** (`FACTS_MAX_RESOLVE_DEPTH`) con el `--resolve-node-limit` por defecto; a 23 el borde
  es **probabilístico** (falla entre un 4 % y un 26 % según la carga) y a 24 falla siempre;
  `denied_<P>` llega a 25 y `ancestor` a 26. La propiedad publicada es **«la mayor profundidad que
  resuelve DE FORMA FIABLE»** y se clava con REPETICIONES, no con una tirada (3b-4 · C4): 500
  resoluciones por lado —10 lotes de 50 con `authorizeMany`—, las 500 tienen que resolver en la cota
  y un salto más tiene que fallar al menos una vez. Antes el par de casos sujetaba el intervalo
  [22, 23] y la constante a 23 dejaba la suite verde 3 de 3.
  Pasado el techo es 503, nunca `false`. Techo del modelo **262.144 BYTES** — y *cuántos permisos son
  esos bytes NO es una propiedad del modelo* (3b-4 · C3): depende de cuántos holder types declaras,
  de cuánto miden sus NOMBRES en el modelo y de cuánto miden los slugs. Medido y fijado con un caso:
  **800** (1 holder, slugs `p0`…`pN`) · **691** (3 holders `user`/`admin`/`integration`, slugs
  `p0`…`pN` — la cifra que se publicaba a secas) · **576** (1 holder, `docs:readN`) · **447**
  (3 holders, slugs REALISTAS `recursoN:accion`) · **272** (3 holders, slugs de 40). O sea: con
  nombres de permiso normales el techo está en **~450**, un 35 % por debajo del número publicado; y
  los mismos tres holders con nombres cortos (`bot`) dan 721, así que «tres holder types» tampoco
  basta para fijar la cifra. El mecanismo por BYTES sí es exacto (`factsModelBytes` = los bytes del
  servidor, delta 0) y salta antes de escribir: la cifra derivada no concede nada, induce a error.
  Relación ≤ 50,
  objeto ≤ 256, `batchCheck` ≤ 50 (lo trocea el SDK).
- **Ningún PEP publicado por el paquete acepta `role`.** Toda decisión de acceso pasa por
  `authorize`, que es lo único que el deny gobierna. `hasRole` es consulta de membresía.
- **La abstracción no filtra.** Ningún error del SDK de OpenFGA escapa de
  `src/drivers/openfga_driver.ts` (salvo `provisionOpenFgaStore` y el importer, que
  son herramientas explícitamente FGA).
- **`@openfga/sdk` es peer opcional.** Todo lo que lo toca vive detrás del subpath
  `@jantstack/adonis-authz/openfga` (`src/openfga.ts`). `index.ts`, el manager, `database_driver`,
  `catalog`, `define_config`, providers y services NO importan ni el SDK ni el driver: lo vigila la
  regla 3 de `check_purity.mjs` y un test que carga `index.ts` con el SDK bloqueado. El stub
  importa el driver del subpath dentro de la factory; los comandos `openfga:*` también.
- **Un cambio de driver es migración de hechos, no reescritura.** Si un plan obliga a
  cambiar call-sites al cambiar de driver, está mal.

## Mapa del código

**Estructura de `src/` (Fase 6b)**: el núcleo transversal vive en la raíz de `src/` (`types.ts`,
`manager.ts`, `identity.ts`, `errors.ts`, `clock.ts`, `expiry.ts`, `define_config.ts`, `freeze.ts`,
`reconcile.ts`, resolutores/outbox de scopes, `relations_config_store.ts`) y el resto se agrupa por
dominio: `src/shared/` (utilidades SQL compartidas: `backend_guard.ts`, `sql_expiry.ts`), `src/catalog/`
(`catalog.ts`, `catalog_cache.ts`), `src/relations/` (ReBAC, Fase 4), `src/http/` (los middleware) y
`src/drivers/` (los drivers concretos, incluido openfga). La regla 2 de `check_purity.mjs` vigila que
ningún fichero de `src/catalog|relations|http/` importe `src/manager.ts` ni `src/drivers/*` (componen
sobre el puerto, los errores y `src/shared/`).

| Ruta | Qué es |
|---|---|
| `src/types.ts` | El contrato (`AuthorizationDriver` —con `purgeRole` desde 3B; `grant`/`revoke`/`listSubjects` por `RoleQuery` y `rolesInChain` ⇒ `CatalogRoleRef` desde 3D · M1—, `RoleQuery` (`string \| {slug,scopeType} \| {uuid}`)/`NormalizedRoleQuery`, `CatalogRoleRef`, `SubjectRef`, `ScopeRef`, catálogo: `CatalogSpec`/`CatalogPermissionSpec` (`assignableAt`)/`CatalogRoleSpec`, `CatalogRole` (`owner`, `rank`), `ScopedRoleSpec`/`ScopedRoleChanges`, `AuthzCatalogWriteEvent`, y de 3b-2a `CatalogProjection`/`CatalogProjectionSnapshot`/`CatalogProjectionReport` —el puerto de la proyección derivada, que el sync recibe INYECTADA—). Empieza aquí. |
| `src/manager.ts` | Fachada; resuelve driver del config, dispara `onWrite`. `forRequest({ maxAgeMs = 30_000, now? })` ⇒ `AuthorizationView` (mismo API; lecturas con ancestros memoizados, escrituras en fresco — 2A; tras `maxAgeMs` —reloj monótono, 2E · H3— TODAS las lecturas, `expandExcludedSubtrees` incluida, son 500 `E_AUTHZ_VIEW_EXPIRED` — 2D/2E). Primitivas 2B como composición: `isWithin`/`within` en las SEIS escrituras (`ScopedWriteOptions`; `requireWithin: true \| 'non-root'`; en `moved`/`attached` contra destino Y origen, `#assertWithinOrigin` — 2E · H1), `actor`/`requireActor` (`WriteOptions`), `authorizeMany` (delega —validando el `boolean[]`— o compone), `listDenies`, `effectivePermissions` (`rolesInChain` + `listDenies` una vez), `authorizedScopes` (`none|some|all{excludedSubtrees: ExcludedSubtree[]}`, `descendantsOf` del config, pertenencia por `resolveChain`, cotas que cortan antes de pasear y por llamada solo bajan), `expandExcludedSubtrees`. `driver()` = salida documentada de las barreras. Aviso de seguridad opt-in una vez por config. **API de delegación (3B · B3; `options: ScopedWriteOptions` desde 3D · M3)**: `defineScopedRole(actor, ownerScope, spec, options?)`, `updateScopedRole(actor, uuid, changes, options?)`, `deleteScopedRole(actor, uuid, options?)` — `within` contra el owner + policy antes de escribir (`#assertComposable`/`#assertDelegable`/`#assertRank`/`#assertAboveRole`/`#assertNoRoleCollision` —3F · S3: colisión por AUTORIDAD, el homónimo de un descendiente se ensombrece y se reporta— + `#shadowedBelow`/`#assertAboveShadowed` —3G · W3: ensombrecer exige rango, en define Y en update—), `#rolesAlong`/`#deniedAlong` (compartidos con `effectivePermissions`), `#descendantsOrDegrade` (3F · S2: el subárbol que no se puede enumerar degrada, no tumba; 3G · X1: lo que cuesta esa degradación, escrito), `pruneOrphanRoles` (3b-0 · Z2: los roles locales cuyo owner ya no resuelve; `--dry-run` por defecto, `--force` para purgar; de PLATAFORMA, sin actor ni rango; 3b-0b: `stillGranting`/`assignments` por huérfano, cota de purga masiva ⇒ 500 `E_AUTHZ_MASS_PURGE_REFUSED` salvo `allowMassPurge`, re-resolución del owner antes de cada purga ⇒ `skipped`, y `purged: CatalogRoleRef[]`), owner en fresco, `#writeCatalog` (= `withAuthzCatalogWrite` + invalidación), `#notifyCatalog` (`hooks.onCatalogWrite`). **3b-3a / 3b-7**: `freeze(reason?, { leaseMs?, kind? }) ⇒ Promise<FreezeToken>`/`unfreeze(token)`/`frozen` (¿SOSTIENE este manager un freeze? — el estado real es la fila)/`freezeStatus()`/`withFrozenWrites(reason, fn)` —la barrera (`#assertNotFrozen`, ASYNC: lee la fila `id=2` sin memo) va en `#writeOptions` (las 7 escrituras) y en `#requireActor` (la delegación), más `relayScopeChanges` y `pruneOrphanRoles({force})` (ahí DESPUÉS del check de `purgeRole`: «no sé purgar» se dice sin consultar nada); el freeze es DURABLE (fila `id=2` de `authz_catalog_version`, token de dueño, lease renovado `unref()`, 423 si hay uno vivo ajeno; ver la regla de higiene de reconcile) y alcanza a la flota entera, vistas de `forRequest()` incluidas— y `reconcile({ to, dryRun?, prune?, allowMassDelete?, batchSize? })` (resuelve el destino por `config.drivers[to]`, exige `scopes.enumerateEdges`, congela con `#durableFreezeContext` —**salvo con `dryRun`**, 3b-6; una ventana de OPERADOR viva es contexto propio, la propia ya sostenida corre dentro, la de otra pasada es 423—, delega en `driver.reconcile`, añade la ventana del relay al reporte y publica `report.frozen` con `lapsed`). |
| `src/freeze.ts` | **El freeze DURABLE** (3b-7): primitivas SQL puras sobre la fila `id=2` de `authz_catalog_version` — `readFreezeRow` (fila ausente ⇒ 503 «migración 2.0 no aplicada», jamás «no congelado»), `freezeIsLive`, `acquireFreeze` (condicional y atómico: dos acquire acaban en exactamente uno; un lease VENCIDO no bloquea la toma), `renewFreeze` (condicional por fence+holder y «aún no venció»: 0 filas ⇒ lapsed y no se «recupera»), `releaseFreeze` (condicional; devuelve `lapsed`), `freezeKindOf`, `FreezeToken`/`FreezeKind`, `DEFAULT_FREEZE_LEASE_MS` = 15 000. La policy (anidado, contexto del operador, 423) vive en el manager. **L-1**: `FreezeSqlOptions.client` DESAPARECE (la fila se lee SIEMPRE por `db`, jamás por la trx del llamante), las cuatro consultas van por `freezeSql` = `withDeadline(guardSql(...))` (deadline total), y **`assertNotFrozenRow(operation, { driver, nowMs, timeoutMs })`** es la barrera compartida que llaman el manager de roles y el `RelationsManager` (las cuatro escrituras de relaciones, antes de F-05). |
| `src/drivers/database_driver.ts` | Driver SQL propio sobre `authz_*`. Identidad del rol por uuid (3A · A2: `hasRole` por `(scope, role_uuid)` del memo, `listRoles`/`rolesInChain` por `role_uuid` → memo, `listSubjects` resuelve el rol antes de consultar). **Owner por nivel** (3B · B2): `authorize` une `authz_roles` y filtra `owner_scope_key = 'global' OR IN (claves de la cadena desde ese nivel)` en SQL (`whereVisibleAssignmentIn`); `grant` = `resolveRoleQuery` + `assertRoleAssignableAt` (compartidos con openfga, como `visibleRoleFor`/`rolesToRevoke`/`hasRoleTargets`/`declaredRoleAt` —3D · M1/N5—); `revoke` por slug quita todos los homónimos del scope exacto y por `{uuid}` solo ese. `purgeRole(uuid)` (B4): asignaciones + vínculos + fila en `withAuthzCatalogWrite`. `resolveChain` (cadena canónica; `chain[0]` = identidad de los hechos; `canonicalScope` para revoke/removeDeny/purge), `now?` y `withClock(now)` (2.5 · J1); `whereActive` = `expires_at > now()`; `created_at` con `systemClock()` (K5: sello, no decisión); `expires_at` vía `ExpiryCodec` (K2); `grant` reintenta como inserción si el UPDATE toca 0 filas (K4). **`reconcile(source, options)`** (3b-3b): la VUELTA de la migración — hechos y solo hechos, leídos del origen por `source.facts` (`enumerateFacts`, páginas con cursor) y comparados contra `authz_*` con la clave del UNIQUE (sin `expires_at`: cambiar la caducidad es un UPDATE, no una fila nueva); el árbol y el catálogo NO se migran y sus fases van a CERO; `folded-scope` cuenta los hechos que colapsan en una fila y se queda con la caducidad que más dura; deletes primero, `maxTuples` como cota declarada. `fromDbScopeUuid` se EXPORTA desde 3b-3b (el centinela de la raíz también lo lee `--to=openfga`, y no hacerlo era un 422 a mitad de migración). **L-3 · `{ transaction }`**: opción `transactionalWrites` (default `true`; pool 1 declara `false`) construye `capabilities.transactionalWrites`; `writer(operation, options)` = `assertCallerTransaction` contra `db.primaryConnectionName` ⇒ `{ client: trx, external: true }` o `{ client: db }` — lo usan el «¿ya existe?», el INSERT/UPDATE de `grant`, y los DELETE/INSERT de `revoke`/`deny`/`removeDeny`; NO lo usan `knownScope`/`resolveChain`, `catalog.view()`, `findPermission`, `canonicalTargets` (autoridad, por `db`); `poisoned(operation, error)`: dentro de una trx externa un fallo no se relee — UNIQUE ⇒ 409, deadline ⇒ 503 TIMEOUT, otro ⇒ 503 —, nunca una segunda sentencia sobre una trx que puede estar abortada. Verificado en SQLite, PostgreSQL 18 y MySQL 8.4. |
| `src/drivers/database_relations_driver.ts` · `src/drivers/openfga_relations_driver.ts` · `src/relations/` | Los dos drivers de relaciones y su fachada (Fase 4; ver el bloque de `relations/` en el README). Lo que cambió en `2.4.0-alpha.2`: **R-15** `expires_at`/`with not_expired`, `withClock` (instancia nueva, no vista), renovar = delete+insert; **L-0** `assertRelationDeclared` (F-05) como PRIMERA línea de `relate`/`unrelate` en los DOS drivers (misma clase/`code`/mensaje que el manager; `reconcileRelations` cuenta `skipped.undeclared`); **L-1** la barrera del freeze en el `RelationsManager` (`#assertNotFrozen`, las cuatro escrituras) y `runRelationsReconcile` bajo ventana durable; **L-2** puerta 1 (`#assertTransactional`, nombra `driverName`) y puerta 2 en el constructor; **L-4** `#writer`/`#poisoned` en `database` (con trx externa `relate` NO abre la interna: el trigger de partición dispara en la trx del llamante; deadlock ⇒ 409 `isDeadlock`); **L-4b** `HOLDER_RELATION = ''`, `#whereSubjectRelation` tolera NULL en LECTURA y borrado; **L-5** `#rejectTransaction` como PRIMERA línea de las cuatro escrituras de `openfga` (antes de F-05 y del `Read`). **`2.4.0-alpha.3`** (paridad del EVENTO con roles, réplica de `#write`/`#notify`/`#logHookFailure`/`#transactional`/`#writeOptions`): `RelationWriteEvent` espeja `AuthzWriteEvent` (un tipo, opcionales `transactional?: true`/`indeterminate?: true`, `operation` con `purgeObject`/`purgeSubject`; ya no extiende `RelationRef`), `#write` (invariante 13) y `#notify` (el hook se ESPERA y si lanza se registra y no tumba) en las CUATRO escrituras, `#assertWrite` (un thenable ⇒ 500 `AuthorizationConfigError.asyncAssertWrite`, fail-closed), `#assertActor(options, op)` valida con `assertSubject` ANTES de exigir (también en las purgas — **breaking** para quien ya tenía `requireActor: true`), las purgas notifican UN evento por llamada sin conteo y NO pasan por `assertWrite` (`RelationPurgeOptions` = `transaction` + `actor`); el provider cablea `relations.assertWrite`/`onRelationWrite` y `relations.requireActor ?? config.requireActor` (un solo home, en `relations.*`); runner: `state.events` + R-17 (20 → 21) + el par `transactionalWrites` juzga el evento. Docs con dientes: `tests/relations_events_docs.spec.ts` + B5 en `trx_docs.spec.ts`. **Cierre de alpha.3** (auditor NO APTA, decisiones 2026-09-02 (2c); informe `alpha3-cierre-informe.md`): **F-05 en las SIETE operaciones** —`assertRelationDeclared(config, object, relation?)`, `relation` opcional = solo el TIPO— como primera línea de `purgeObject` (tipo), `purgeSubject` (el userset del sujeto, vía `#assertSubject`/`#subjectColumns`/`#subjectUser`), `check`/`listSubjects` (el par) y `listObjects` (tipo) en el manager Y en los dos drivers (hasta el cierre, por `purgeObject({type:'role_binding', id:R}, S)` el puerto de relaciones BORRABA el binding real del store compartido —`authorize` de `true` a `false`, evento limpio— y `listSubjects('assignee', role_binding)` enumeraba sus asignados; reproducido y fijado contra el `:8101` por manager y por driver, en dobles, en `database` y en el runner publicado: caso nuevo del núcleo, 21 → 22); **`assertWrite` no devuelve veredictos**: todo retorno ≠ `undefined` (promesa, función-thenable, `false`, `true`, `null`, objeto) es 500 `AuthorizationConfigError.assertWriteReturned` antes del driver; **purga parcial ⇒ `indeterminate: true`** (`markPartialWrite`/`isPartialWrite` en `errors.ts`, `#partialIfDeleted` en `openfga`, `#write` del manager notifica para timeout O parcial; invariante 13); `purgeSubject` valida su sujeto en el manager (`isRelUserset` tolera `null`), el evento es una COPIA (`#copyEvent`, el `actor` sin poda), `actor: null` ⇒ 422 anunciado BREAKING, y la anulación silenciosa de `relations.requireActor: false` escrita en el README. Sin deadline en el hook (decisión: paridad con roles), la frase está publicada con caso de letra (F7–F12 en `relations_events_docs.spec.ts`). **Cierre-2** (re-ataque del auditor `alpha3-auditor-cierre.md`, decisiones 2026-09-02 (2d); informe `alpha3-cierre2-informe.md`): la `relation?` OPCIONAL del cierre —`if (relation === undefined) return` compartido— apagó F-05 en `relate`/`unrelate` sin relación (dobles escribían, `openfga` 503 del servidor, `database` lo salvaba su gramática) y `listSubjects(undefined)` devolvía la UNIÓN; son **DOS funciones, no un opcional**: `assertRelationDeclared(config, object, relation)` ESTRICTA (relación ausente/vacía/no-string ⇒ 422 `E_AUTHZ_RELATION_UNKNOWN`, cero llamadas) para `relate`/`unrelate`/`check`/`listSubjects`/`listObjects`/`membersOf` y el userset del sujeto, y `assertObjectTypeDeclared(config, object)` para `purgeObject`; **`membersOf` es la OCTAVA operación** y lleva F-05 (par) ANTES de la capacidad en el manager y en `database`; `markPartialWrite` tolera un error congelado (devuelve el original sin marca, jamás un `TypeError` que sustituya al 503); el driver `openfga` de relaciones importa el `isTimeoutLike` de `backend_guard.ts` (el de roles: sin substring del mensaje); «las lecturas lanzan 422 con tipo/relación no declarados en vez de responder» anunciado BREAKING. Mutante: aceptar `undefined` en la estricta ⇒ el caso «relate sin relación» rojo. |
| `src/shared/sql_expiry.ts` | **Codec de `expires_at` por dialecto** (2.5-B · K2): MySQL escribe/compara cadena UTC `YYYY-MM-DD HH:mm:ss.SSS` y lee con `DATE_FORMAT` (sin depender de `timezone`/`TZ`); PG/SQLite identidad. Lo usan el driver, el importador de openfga y el trait. `dialectOf(connection)`. |
| `src/openfga.ts` | Entrada del subpath `@jantstack/adonis-authz/openfga`: lo ÚNICO que exporta el driver openfga y sus herramientas (peer opcional `@openfga/sdk`). |
| `src/drivers/openfga_driver.ts` | Driver Zanzibar; modelo FGA generado desde `holderTypes`. **`catalogProjection()`** (3b-2a · A5): la proyección derivada que `syncAuthzCatalog` usa —`assertPublishable` antes de escribir, `projectCatalog` después del commit: diff contra un `Read` por prefijo `role:` y deletes+writes en el MISMO `client.write` por lote de 100 (`writeTuples()`+`deleteTuples()` queda prohibido, cruce 8); nunca se lee para responder qué permisos tiene un rol (A6, espía + guardia de fuente). **Ids de binding por uuid del catálogo** (3A · A1): `role_binding:<scopeKey>|<roleUuid>` (el `deny_binding:<scopeKey>|<permissionUuid>` se fue con el modo `resolver` en 3b-2k · K2: el deny es hoy la relación `scope:<key>#denied_<P>`); `parseBindingId` parsea desde la derecha (UUID canónico) — **decisión estructural sin oráculo hoy** (3D · N6): con la gramática actual un `scopeKey` tiene siempre 1 o 2 partes, así que «desde la derecha» y «contando partes» coinciden para TODO id admisible y el mutante es equivalente; solo será observable cuando el `scopeKey` crezca de partes (3b, modo `facts`) — no lo «simplifiques» a conteo creyendo que la suite lo cubre; sin escape de slug (ningún `~`); 2.2 no lee ids 1.x (deriva de `authz:reconcile`, sin comando de migración). Lecturas de membresía filtradas por catálogo por uuid (`roleByUuid`) y por owner por nivel (3B · B2: `declaredRole(catalog, binding, chainKeys)` + `isRoleVisibleWith`; el `checksFor` que expandía la cadena murió con el modo `resolver`, 3b-2k · K2); `purgeRole` ⇒ 500 `E_AUTHZ_UNSUPPORTED` hasta 3b (B4); `Read` paginado y acotado. **El driver ES el modo `facts`** (3b-2b; 3b-2k · K2 borró el modo `resolver` y con él la opción `hierarchy`, `openFgaAuthorizationModel`, el tipo `deny_binding`, `checksFor`, `legacyDenies` y el importador): `onScopeAttached/Moved/Detached` mantienen UNA arista `#parent` por nodo con la identidad CANÓNICA; `assertEdge` repite las TRES validaciones anti-ciclo del manager por defensa en profundidad (`manager.driver()` se salta todas las barreras); `moved` = 1 `Read` del padre actual + la cadena del padre NUEVO en el STORE (3b-8 · A5: el anti-ciclos del consumidor no ve un store desincronizado por una outbox en desorden; el ciclo real se rechaza 422 ANTES del `Write`) + 1 `client.write({deletes,writes})` (cruce 8), su atajo idempotente TAMBIÉN corre `sweepLocalRoleBindings` (3b-8 · A3: el reintento del relay tras morir entre arista y barrido), y >1 padre ⇒ 500 `E_AUTHZ_SCOPE_TREE_DRIFT` (se denuncia, no se «arregla»; `detached`, que se lleva el nodo entero, sí las borra todas); `detached` borra la arista DESPUÉS de que `purgeScope` demuestre cero (S6), y la purga borra también las aristas `scope#binding` de roles que el catálogo YA NO declara en ese nivel (3b-8 · C2: sin eso, un rol borrado entre el commit y el barrido dejaba `E_AUTHZ_PURGE_INCOMPLETE` para siempre). **`reconcile(source, options)`** (3b-3a): el método opcional del puerto que reconstruye el store desde `authz_*` + `source.enumerateEdges` —`readSourceTree` (paginado con cursor, anti-ciclos incremental con `walkUpTo`, y un ciclo deja sin arista a TODOS sus nodos, no solo al que la cerró), `readSourceFacts` (`eachRow` con cursor sobre la PK y `sqlExpiryCodec` para leer `expires_at` sin depender de la zona del cliente; los DOS barridos dentro de `withSourceSnapshot` —3b-6: una sola transacción de lectura repetible, el cliente llega a `eachRow` por parámetro y no hay default a `db`), `readEveryTuple` (`client.read({})` = volcado ENTERO: filtrar por objeto es un 400 del servidor y además no vería lo que sobra), `familyOfTuple` (qué se rehace solo y qué pide `--prune`), `modelPermissions` (un permiso del catálogo que el modelo publicado no declara se CUENTA, no revienta el `Write` a media migración) y `applyReconcileWrites` (deletes primero: si muere a medias queda de MENOS)—. La foto del catálogo la da `readCatalogProjectionSnapshot` (`src/catalog/catalog.ts`), la MISMA que usa el sync: si fueran dos, reconcile «arreglaría» en cada pasada lo que el sync deja bien. **`enumerateFacts(page)`** (3b-3b): la otra mitad —ser el ORIGEN—; `Read` paginado (no `ListObjects`: no tiene `continuation_token`), `assignee` → `(holder, rol, scope, caducidad)`, `denied_<P>` → deny y **el deny del modo `resolver` de 2.2 (`deny_binding:<scopeKey>|<permissionUuid>#denied`) TAMBIÉN se emite como deny** (3b-8 · A2: `reconcile` es el sustituto documentado del importador y tirarlo en silencio perdía los denies explícitos con el verificador en verde; el uuid del permiso lo traduce el catálogo, y lo que no traduce va contado), **sin filtrar la caducada** (tiene que llegar para contarse), la estructura de (c2) y la proyección no se emiten (son derivadas) y lo que no se entiende va en `skipped` de la página. |
| `src/drivers/openfga_facts.ts` | **Modo `facts` (3b-2a/2b)**: el modelo (c2), la proyección del catálogo y el ÁRBOL como hechos, SIN `@openfga/sdk` (pieza pura, juzgable sin servidor). `openFgaFactsModel(holderTypes, permissions)` — cuatro familias por permiso (`<P>`, `can_<P>`, `denied_<P>`, `permits_<P>`), `role#permits_<P>@<holder>:*`, `scope#parent/binding/ancestor/rooted`, `can_<P> = (<P> but not denied_<P>) and rooted` —el modelo es **(c2r)** desde 3b-2i: `rooted` (union de `[<holders>:*]` con la TTU por `parent`) es la ALCANZABILIDAD de la raíz materializada por el modelo, con `factsRootTuples(holderTypes)` = el *marcador de raíz* `scope:app#rooted@<holder>:*` que escribe `projectCatalog`—; `factsRelationMap` (S4: `Map` nombre→origen ⇒ 422, jamás un modelo ambiguo), cotas `FGA_MAX_RELATION_NAME` 50 / `FGA_MAX_OBJECT_ID` 256 (A4), `factsModelBytes` (**el tamaño PROTOBUF, que es lo que mide el servidor**: la razón proto/JSON va de 0,33 a 0,57 con la longitud del slug, así que el JSON no vale de techo; contrastado byte a byte con el `:8101` en cuatro formas de catálogo) y `assertFactsModelPublishable` (techo 262.144 ⇒ 500 `E_AUTHZ_MODEL_TOO_LARGE`, aviso al 80 % por el logger del driver), `factsCatalogTuples`. **3b-2b**: `factsScopeObject`/`factsParentTuple`/`FACTS_SCOPE_TYPE`/`FACTS_PARENT_RELATION` — la arista `scope:<hijo>#parent@scope:<padre>`, UNA por nodo, con la `scopeKey` del paquete. Aquí vive `assertHolderTypes` (la usan los dos generadores; el driver la re-exporta). |
| `src/define_config.ts` | `defineConfig`/`AuthorizationConfig`: `default`, `drivers`, `holderTypes`, `scopes.resolveChain` (la costura del árbol hacia arriba) + `scopes.descendantsOf?`/`maxScopes`/`maxDescendants` (2.1, hacia abajo, solo `authorizedScopes`/`expandExcludedSubtrees`), `requireWithin` (`boolean \| 'non-root'`)/`requireActor`/`warnOnOptInSecurity` (2.1), `clock` (2.5 · J1: reloj de pared que el manager aplica al driver con `withClock`; 500 `E_AUTHZ_CONFIG` si el driver no lo trae), `catalogs`, `delegablePermissions` (3B: lista blanca de la delegación, default `[]`), `hooks.onWrite`/`hooks.onCatalogWrite` (3B). **2.4.0-alpha.2**: `freezeTimeoutMs` (L-1: deadline TOTAL de la barrera del freeze, espera del pool incluida, default 5000; el provider lo pasa también al `RelationsManager`), `requireTransactionalWrites` (L-2: puerta 2, raíz) y `relations.requireTransactionalWrites` (anula el raíz para relaciones; si falta, se hereda como `requireActor`). |
| `src/identity.ts` | `assertIdentity`/`assertScope`/`assertValidSlug`/`assertExpiresAt`/`assertNoSlugCollisions`/`normalizeRoleQuery`/`assertCatalogUuid` (uuid de rol del spec: UUID canónico en minúsculas, 3A), `scopeKey`/`scopeFromKey`/`chainKeysFrom` (3B/3D · N5: `app` \| `<tipo>\|<uuid>`, la clave de los ids de binding FGA Y del owner de un rol; `global` reservada; UNA sola codificación), `isValidScopeType`: gramática de holders, scopes (tipos Y uuids en minúsculas `[a-z0-9._-]` —K1—; holder_type 50, scope_type 20, uuid 36), slugs (minúsculas, **42** = `MAX_SLUG_LENGTH`) y `expiresAt` (422). La aplica el manager y, por defensa en profundidad, cada driver. |
| `src/expiry.ts` | Los tres estados de `expiresAt` (`resolveGrantExpiry`, `sameInstant`, `toExpiryDate`, `expiryChanged`); `now` inyectable (default `systemClock()`). |
| `src/clock.ts` | **El reloj** (2.5 · J1): `Clock`, `systemClock` = el ÚNICO `new Date()`/`Date.now()` de `src/` fuera de `src/testing/` (grep en `tests/clock.spec.ts`). Ambos drivers aceptan `now?` e implementan `withClock(now)` (vista por prototipo); el manager aplica `config.clock` al resolver el driver (500 `E_AUTHZ_CONFIG` sin `withClock`) y las vistas de `forRequest()` lo comparten. Caducidad ESTRICTA: lo que vence ahora no cuenta (`expires_at > now`; `current_time < valid_until`). |
| `src/shared/backend_guard.ts` | Clasificación de fallos compartida: `guardSql` (503 + deadline; también lo usa el catálogo), `withDeadline`, `isSqlDriverError` (K12), `resolveChain`/`assertKnownScope` (árbol: `null` ⇒ desconocido; lanza, cadena vacía, elemento inválido o elemento 0 ≠ scope pedido ⇒ 503; devuelve la cadena CANÓNICA), `canonicalScope` (revoke/removeDeny/purge: la fila si el árbol la conoce, el scope tal cual si no o sin resolutor), `rootOnlyResolver` (sin resolutor solo existe `app`); **L-3/L-4**: `isUniqueViolation` (PG `23505`, MySQL `1062`, SQLite `SQLITE_CONSTRAINT*`) e `isDeadlock` (PG `40P01`/`40001`, MySQL `1213`), mirando la cadena de `cause` — lo que convierte el choque dentro de la trx del llamante en 409 y no en 503. |
| `src/shared/transaction_guard.ts` | **`assertCallerTransaction(operation, transaction, { connection })`** (L-1 · 🟠 9, exportado desde `index.ts` en L-2): devuelve el `trx` tipado (`CallerTransaction`) o `undefined`; 500 `E_AUTHZ_CONFIG` nombrando la operación y las DOS conexiones si (1) no tiene `.from()`/`.table()`, (2) es el `db` de Lucid entero, (3) no es una transacción ABIERTA (`isTransaction !== true`: un `QueryClient` confirma cada sentencia sola) o (4) su `connectionName` no es la de quien escribe. UNA función, tres llamadores: `sqlScopeOutbox.enqueue`, `DatabaseAuthorizationDriver.writer()` (L-3) y `DatabaseRelationsDriver.#writer()` (L-4). «Los dos o ninguno» solo es verdad en la misma conexión. |
| `src/catalog/catalog.ts` | `syncAuthzCatalog` (**devuelve `CatalogSyncReport`** desde 3E: `shadowedByGlobal` + `assignableAtViolations`, reportar y seguir; `syncCatalogs` ⇒ `{ count, ...reporte }` y el comando lo avisa; prune de vínculos por defecto; colisiones también contra la BD; 503 con la BD caída; escribe vía `withAuthzCatalogWrite` —la versión sube como última sentencia de su transacción— e invalida el memo del proceso al terminar; **solo roles globales** —3B · B6: upsert por `(slug, scope_type, owner = 'global')`, colisión con un local ⇒ 422, rank/vínculos de locales intactos—; `assignable_at` de permisos —B5: el config manda, `assertAssignableAt` dentro del spec y contra la BD—), `diffAuthzCatalog` (+ `assignableAtMismatches`, `shadowedByGlobal`/`shadowedByAncestor` —3F · S3: ensombrecidos por AUTORIDAD, se listan (`formatShadowedRoles`) y NO son deriva; 3b-1 · T-3b: UNA entrada por rol ensombrecido, nombrando al ensombrecedor MÁS AUTORIZADO (el ancestro más alto), y `runCatalogDiff` acumula las de TODOS los catálogos con deduplicación (la fuente por spec de `shadowedByGlobal` hacía invisible la del catálogo #2)—, `ambiguousRoles` —solo lo que la autoridad no ordena: deriva con exit ≠ 0—, `scopedRoles` informativo; `storedAssignableAt` normaliza igual que el sync —N5—)/`runCatalogDiff` (`failOnShadows`, 3G · X3)/`syncCatalogs` (catálogos disjuntos o 422 `E_AUTHZ_CATALOG_CONFLICT`), `encodeAssignableAt`, `formatScopedRoles`; **`projection?: CatalogProjection` INYECTADA** (3b-2a · A5: este módulo es la ruta solo-database y no puede importar openfga —regla 3—; valida que el catálogo resultante sea publicable ANTES de escribir y espeja los vínculos rol→permiso DESPUÉS del commit, con el informe en `report.projection`). |
| `src/catalog/catalog_cache.ts` | **Memo del catálogo** (2A; versión compartida 2D · F1): `CatalogView` con `role()` ⇒ el rol GLOBAL `CatalogRole` `{ uuid, slug, scopeType, owner, rank }`, `roleVisible(slug, scopeType, chainKeys)` (3B: el global o el local con owner en la cadena; **más de uno ⇒ 422 `E_AUTHZ_AMBIGUOUS_ROLE`**, 3D · M1), `rolesNamed`, `roleByUuid`, `rolesFor(scopeType, ownerKeys)`, `rolesGranting` (refs con `owner`), `rolePermissionsOf(uuid)`, `permission()` ⇒ `{ uuid, assignableAt }`, `topGlobalRank`, `GLOBAL_OWNER_KEY`, `isRoleVisibleWith`, `parseAssignableAt` (corrupto ⇒ 500); `CatalogCache` (carga perezosa de `authz_*`, 3 consultas con deadline; nunca hechos ni decisiones), revalidación contra `authz_catalog_version` por `view()` (`revalidate: 'always' \| { everyMs }`, ventana con reloj monótono e inyectable `now` solo en tests; recarga si la fila va por delante; sin fila legible ⇒ 503 «migración 2.0 no aplicada»), `readAuthzCatalogVersion()`, `readLocalRoles()` (3b-0 · Z2: TODOS los roles locales LEÍDOS DE LA BASE, con sus permisos y su nº de asignaciones VIGENTES —3b-0b · AA1—, para `prune-orphans`; orden estable por uuid —3F · U5: el orden de `role_purged` se reproduce igual en los tres motores—; cota `DEFAULT_MAX_LOCAL_ROLES` = 10 000 ⇒ 500, nunca lista parcial —3b-0b · AB2), `withAuthzCatalogWrite(fn)` (LA forma de escribir `authz_*` a mano: **cerrojo sobre la fila de versión al principio** —3D · M2, PG/MySQL— + transacción + bump al final, dentro; el canal entre procesos y el serializador del catálogo) y `bumpAuthzCatalogVersion(trx)` (exige el trx; 500 sin él), `assertCatalogOptions` (`catalog` + `catalogRevalidate` ⇒ 500), `invalidateAuthzCatalog()` (contador del proceso), `invalidate()` de instancia por generación (una carga en vuelo no la pierde). Ambos drivers lo usan (`catalog` o `catalogRevalidate`) tomando UNA foto por operación; `purgeScope` lee SQL en fresco. Caso negativo fijado: escribir `authz_*` sin subir la versión no se ve. |
| `src/memoize_ancestors.ts` | `memoizeAncestors(resolver)`: memo de una instancia sobre `ScopeChainResolver` (sin reloj; `null` memoizado; un throw no). SOLO camino de lectura (auditor C3/E3). El puerto tiene `withChainResolver?` opcional para que el manager lo aplique. |
| `src/hierarchical_resolver.ts` | `hierarchicalScopeResolver({ nodeOf, maxDepth = 64 })` (2.1, B4; K1): resolutor de la cadena desde la FILA (`nodeOf` ⇒ `{ self canónico, parent }`; `undefined` = desconocido ⇒ `null`; `parent` `null`/`app` = raíz); clave de visitados con separador `\u001f`; `self`/padre mal formado o `self` que no es el scope pedido ⇒ 503 `E_AUTHZ_RESOLVER_FAILED`; ciclo ⇒ 422 `E_AUTHZ_SCOPE_CYCLE`; `maxDepth` ancestros (app incluida) ⇒ 500 `E_AUTHZ_SCOPE_TOO_DEEP` (nunca cadena corta); un throw se propaga. |
| `src/sql_descendants.ts` | `sqlDescendantsOf({ table, uuidColumn, parentColumn, typeColumn \| scopeType, maxNodes?, connection?, timeoutMs? })` (2.1, B2): `descendantsOf` opt-in con UNA CTE `WITH RECURSIVE` (PG, SQLite y MySQL 8 —2.5 · J3: cita con backticks, resultado `[rows, fields]` de mysql2, hint `SET_VAR(cte_max_recursion_depth)` porque MySQL corta a 1000 iteraciones con el error 3636—; otro dialecto ⇒ 500 `E_AUTHZ_UNSUPPORTED_DIALECT`); identificadores y `scopeType` validados al construir; `LIMIT maxNodes+1` + profundidad `maxNodes+1` (un ciclo termina y lanza 422 `E_AUTHZ_TOO_MANY_SCOPES` con «posible ciclo»). **`sqlScopeEdges({...})`** (3b-3a): el `scopes.enumerateEdges` de la misma tabla —una página de aristas hijo→padre por llamada, `ORDER BY uuid` con cursor sobre la PK, `parentColumn IS NULL` = `app`, y una fila cuyo padre NO existe **no produce arista** (coherente con `resolveChain`, que ahí devuelve `null`; el cursor es la última FILA leída, no la última arista, o la paginación se pararía en seco)—. |
| `src/scope_outbox.ts` | `sqlScopeOutbox({ table?, connection?, timeoutMs?, now?, maxAttempts? }, db?)` (3b-2d; 3b-2h): la implementación publicada del puerto `ScopeOutbox` sobre Lucid, sobre la tabla de `stubs/scopes_outbox_migration.stub` (`authz_scope_outbox`). `enqueue` escribe por `context.transaction` si llega (es TODO el mecanismo: sin eso no hay mitigación); las filas aplicadas se MARCAN (`applied_at`), no se borran; `markFailed` cuenta el intento y guarda la causa. `pending(limit, after?)` pagina desde un id (una pasada ya puede SALTAR filas) y no ofrece lo aparcado (`attempts >= maxAttempts`, default 5), que sale por `dead(limit)`; `acquire()` es el lease del escritor único —`pg_try_advisory_xact_lock` en PG, `GET_LOCK` en MySQL, cerrojo de proceso en SQLite—. El paquete no impone tabla: cualquier implementación del puerto vale. |
| `src/errors.ts` | Todos con `status` + `code`: `AuthorizationBackendError` (503) y su subclase `…TimeoutError`; `ScopeResolverError` (503); `InvalidIdentityError`, `InvalidSlugError`, `UnknownScopeError`, `NoScopeResolverError`, `UnknownRoleError` (por slug+nivel o por uuid), `UnknownPermissionError`, `CatalogConflictError`, `ScopeCycleError`, `NotWithinError`, `WithinRequiredError`, `WithinRootForbiddenError`, `ActorRequiredError`, `TooManyScopesError`, y de 3B/3D `RoleNotVisibleError`, `AmbiguousRoleError` (`E_AUTHZ_AMBIGUOUS_ROLE`), `RoleImmutableError`, `RoleLevelAboveOwnerError` (`E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER`, 3E), `RoleNotAssignableAtError`, `PermissionNotDelegableError`, `RankExceededError` (422); `WriteConflictError` (409); `AuthorizationConfigError`, `AuthorizationInternalError`, `RoleIsNotAccessError`, `PurgeIncompleteError`, `UnsupportedOperationError` (`E_AUTHZ_UNSUPPORTED`), `MassPurgeRefusedError` (`E_AUTHZ_MASS_PURGE_REFUSED`, 3b-0b), `TooManyLocalRolesError` (`E_AUTHZ_TOO_MANY_LOCAL_ROLES`, 3b-0b), `ModelTooLargeError` (`E_AUTHZ_MODEL_TOO_LARGE`, 3b-2a), `ScopeTreeDriftError` (`E_AUTHZ_SCOPE_TREE_DRIFT`, 3b-2b), `NoDescendantsResolverError`, `UnsupportedDialectError`, `ScopeTooDeepError`, `ViewExpiredError` (500). **La LETRA de `{ transaction }`** (L-2/L-5, fijada byte a byte por `tests/trx_docs.spec.ts`): `UnsupportedOperationError.transactional(op, driver, port)` (puerta 1: driver, operación, «una tupla no entra en una transacción SQL», las dos salidas, «falle al ARRANCAR», «Sin { transaction } la misma llamada entra»), `.transactionalDriver(...)` (la misma + «Rechazado por el DRIVER», «manager.driver() no es una salida», `scopes.outbox` para el árbol, «para hechos y relaciones no hay outbox») y `.transactionalCatalog(op)` (la delegación: `withAuthzCatalogWrite`, invariante 14). Tabla en el README. |
| `src/http/*` | Middleware Adonis (Fase 6b: `src/middleware/` → `src/http/`). `app_access_middleware.ts` = `appAccess({ permission })` a nivel `app` (solo `permission`: `{ role }` ⇒ 500 con receta); `resource_access_middleware.ts` = `resourceAccess` (Fase 5). Subpaths públicos `./app_access_middleware` y `./resource_access_middleware` (mismos nombres; la ruta interna de `exports` apunta ahora a `./build/src/http/`). |
| `src/testing/contract.ts` | **El juez**: `runAuthorizationDriverContract` (`level: 'core' \| '2.0' \| '2.1' \| '2.2'`, `capabilities` —`purgeRole` es par de capacidad solo en `'2.2'` (3B · B4: `true` juzga la purga total, `false` el 500 sin tocar nada); los casos `'2.2'` de roles locales usan `localRole`/`linkByHand` (escrituras a mano en `authz_*` con la versión subida) y, bajo `listDenies: true`, `defineScopedRole` por `managerOver({ delegablePermissions })`; `listDenies` es par de capacidad solo en `'2.1'`+ (2E · I5): `true` juzga lo que resta denies y F1, `false` juzga que lo digan con 500 `E_AUTHZ_UNSUPPORTED`; `injectableClock` es par en TODOS los niveles (2.5 · J1): `true` ⇒ tres estados con reloj (core) + caducidad exacta T−1/T/T+1, milisegundos, 2040 (escribiendo con el reloj en 2040, K5) y `config.clock` (2.1), `false` ⇒ tres estados en tiempo real (1,5 s)—, árbol del harness (`makeTree?`: `memoryScopeTree` por defecto; `sqlScopeTree` en el harness de los motores), `makeTwin?` = otra instancia sobre el mismo backend con otro memo del catálogo; default `twinOf`). Los casos `'2.1'` construyen un `AuthorizationManager` sobre el driver del harness (`managerOver`); el espía Proxy usa `receiver` para ver la vista de `withChainResolver`. Casos de motor (2.5 · J3/K1: ids no UUID y MAYÚSCULAS ⇒ 422; alias del uuid jamás evade un deny) y de concurrencia (2.5 · J4: dos grants, purga vs grant —afirma sobre el `GrantOutcome`, K4—, sync vs authorize). Instantes relativos a hoy donde se observa el driver sin reloj (K7). Se publica en `./testing` para drivers de terceros. `scope_tree.ts`: `ContractScopeTree` (`chainOf` = cadena canónica; `descendantsOf?`), `memoryScopeTree`/`resolveChainFrom`/`descendantsFrom`. **L-2/L-3**: el par `transactionalWrites` (la capacidad `transactions` del harness se RENOMBRÓ) en TODOS los niveles, con las DOS caras obligatorias —`BOTH_FACES_REQUIRED` + `uncoveredCapabilities` (pura)—: `whenFalse` = 500 con cero llamadas + puerta 2; `whenTrue` = rollback ⇒ `authorize` sin cambio Y censo cero (hook `harness.transactions: ContractTransactions` = `begin()` + `census(subject)`, default `lucidContractTransactions()` exportado), commit ⇒ aplicado, tres transacciones ajenas ⇒ 500 sin una sentencia. Lo mismo en `relations_contract.ts` (`RelationsContractTransactions`, `lucidRelationsContractTransactions`, `purge*` revierten JUNTOS). |
| `src/models/*` | Modelos Lucid `authz_assignment/deny/permission/role/role_permission`. |
| `src/traits/*` | `has_uuid`, `authz_scopes` (`withAuthzScopes` como mixin o `withAuthzScopes({ clock })` —K6—; PK casteada a texto en PG —K3—; codec de caducidad —K2—). |
| `src/reconcile.ts` | Piezas COMPARTIDAS de `authz:reconcile` (3b-3b): `reconcileBatchSize`, **`reconcileMaxTuples`** (la cota declarada de B5), `RECONCILE_MAX_DETAILS` y la suma de fases. Vive fuera de los drivers porque `database` no puede importar de `openfga` (arrastraría el SDK) y porque duplicar la normalización es la forma más barata de que las dos direcciones cuenten distinto. Módulo puro. |
| `src/testing/migration_contract.ts` | **El contrato de MIGRACIÓN** (3b-3b · B3), publicado en `/testing`. `runMigrationContract(harness)` registra las tres combinaciones; `runMigrationDirection(harness, direction)` es el MOTOR y devuelve el veredicto —separado a propósito para que el paquete pueda demostrar que el contrato **sabe fallar**—. Siembra fija (`makeMigrationSeed`, `plantMigrationTree`, `plantMigrationFacts` desde las tablas `migrationGrants`/`migrationDenies`) y `migrationQuestions` (448, con su descomposición fija). Las dos caras de `expectedLosses` (declarada⇒contada y contada⇒declarada) cruzan `report.skipped`, o sea lo AUTO-DECLARADO; lo silencioso lo cierran el **censo** (`migrationFacts`/`censusMigrationFacts`: los 20 hechos sembrados buscados uno a uno en el destino con `listRoles`/`listDenies` ⇒ `silentLosses`/`censusLimits`) y el **cruce de caducidades** (`grant` con `expiresAt` omitido ⇒ `previousExpiresAt`), los dos también contra el destino INTERMEDIO de `a→b→a`. |
| `commands/` | `authz:catalog:sync` (`--keep-links`; avisa de `shadowedByGlobal`/`assignableAtViolations`, 3E), `authz:catalog:diff` (exit 1 si hay deriva; `--fail-on-shadows` cuenta además los ensombrecidos, 3G · X3), `authz:catalog:prune-orphans` (3b-0 · Z2: lista los roles locales huérfanos —aparte y con aviso los que TODAVÍA conceden, 3b-0b · AA1—; borra con `--force`, y `--allow-mass-purge` para la cota de purga masiva), `authz:scopes:relay` (3b-2d: drena `scopes.outbox` contra el driver; `--dry-run`, `--limit`, `--batch-size`; exit 1 si algo falló o hay entradas APARCADAS —3b-2h—, y dice lo aplazado y lo aparcado uno a uno), `openfga:provision` (3b-2k · K2: publica el modelo **`facts`**, con los permisos de los `catalogs` del config; sin ellos sale ≠ 0). **`authz:freeze` / `authz:unfreeze`** (3b-7 · F6: la ventana del CUTOVER — `--reason` obligatorio, `--lease-ms` opt-in de caducidad; `unfreezePlan(status, fence)` es la función PURA que decide qué se levanta: el de operador sí, el de una pasada viva no salvo `--fence=N`, y un fence viejo no levanta nada). **`authz:reconcile`** (3b-3a + 3b-3b: `--to=<clave de drivers>`, `--from=<clave>`, `--dry-run`, `--prune`, `--allow-mass-delete`, `--batch-size`, `--max-tuples`; `reconcileLines(report)` es la función PURA que decide qué se imprime y si la pasada es limpia —mismo patrón que `orphanLines`—: en `--dry-run` cualquier cosa que haría es deriva (exit 1), y siempre lo son los ciclos, lo aparcado, los dos padres y lo que quede en `skipped` — y desde 3b-7 un `frozen.lapsed` (el lease del freeze se perdió a mitad: la pasada no se certifica); la ventana del relay AVISA pero no tumba). `openfga:import` **se borró** con el modo `resolver`. Los `openfga:*` importan de `src/openfga.ts`; `authz_reconcile.ts` NO (habla con el manager, así que la regla 3 de pureza se cumple sola). |
| `providers/`, `services/main.ts`, `configure.ts`, `stubs/` | Wiring Adonis: provider, singleton, `node ace configure`, plantillas publicadas (`config/authorization` cablea `scopes.resolveChain` —cadena canónica— y la misma función a ambos drivers; `config/app_acl`; migración con las cinco tablas `authz_*` + `authz_catalog_version` sembrada). Decisiones de motor en la migración (2.5 · J3, observadas en PG/MySQL): `holder_uuid`/`scope_uuid` `varchar(64)` (PG `uuid` rechazaba ids válidos), `collate 'utf8mb4_bin'` en identidad (también `authz_roles.scope_type`, ⚪4) y slugs (MySQL `*_ci` fundía `abc`/`ABC`), `expires_at` `DATETIME(3)` (MySQL `TIMESTAMP(0)` redondea al segundo y muere en 2038). **L-4b**: `authz_relations.subject_relation` es `NOT NULL DEFAULT ''` (`''` = holder; con NULL el UNIQUE `authz_rel_tuple_uq` solo defendía usersets porque NULL ≠ NULL en los tres motores, y dos `relate` concurrentes del mismo holder confirmaban DOS filas), el driver escribe `''` y tolera NULL en LECTURA, y el trigger de partición juzga «userset» por `<> ''` (con `IS NOT NULL` dispararía en cada holder); la receta alpha.2→L-4b (trigger PRIMERO, de-duplicado, backfill, ALTER; SQLite sin ALTER COLUMN) se EJECUTA en `upgrade_recipe.spec` en los tres motores. El espejo es `tests/helpers/schema.ts`; `migration_stub.spec` EJECUTA el stub en una base de trabajo y compara tipo/longitud/precisión/collation con el espejo (K11). La receta 1.x→2.x del README se ejecuta en `upgrade_recipe.spec` (K14). |
| `scripts/` | `check_purity.mjs` (reglas 1, 2 y 3 —la ruta database no importa openfga—, con stripper de comentarios), `openfga_prune_stores.mjs` (borra stores huérfanos, solo con `--force` y prefijo), `bench_authorize.mjs` (latencia de `authorize` contra `:8101`; `node --import @poppinss/ts-exec`; K8: `database` sqlite p50 0,35/0,24 ms, `openfga` p50 2,48/0,06 ms). |
| `tests/` | `helpers/app.ts` (**harness multi-motor**, 2.5 · J2: `TEST_DB=sqlite\|sqlite-file\|pg\|mysql`; PG/MySQL crean `authz_test_<8 hex>` desde una conexión administrativa y la borran en `teardown()` —también el proceso hijo de `load_without_sdk`, vigilado por `harness_cleanup.spec` (K13)—; `sqlite-file` = fichero en `mkdtemp` con pool 2..5 y WAL (`pool_concurrency.spec`, K16); MySQL con `timezone: 'Z'`; `bootApp({ reuse })` para hijos sobre la misma base y `openScratchDatabase()` para otra base vacía del motor), `helpers/sql_scope_tree.ts` (árbol del juez en `demo_scopes`, K1), `helpers/schema.ts` (espejo —con las acciones de FK alineadas al stub desde 3D · M6— + `describeAuthzSchema` + `describeAuthzForeignKeys` + `runMigrationSource`), `helpers/expiry_child.ts`/`upgrade_child.ts` (procesos hijos de K2/K14), `fixtures/migration-1.1.0.stub`, `clock` (grep: solo `src/clock.ts` lee la hora), `freeze.spec.ts` (3b-7: el freeze durable entre dos MANAGERS del mismo backend, el token, el lease con reloj inyectado, `unfreezePlan` y la LETRA del README), `freeze_multiprocess.spec.ts` + `helpers/freeze_child.ts` (3b-7: el freeze entre PROCESOS —gateado a pg/mysql/sqlite-file, en `:memory:` un hijo no puede abrir la base y el mutante `modulo` queda VERDE—, patrón de `expiry_timezone`), `contract.spec.ts` (database siempre —y «database (sin listDenies)», la cara `listDenies: false` del juez—; en PG/MySQL además «database (árbol SQL)»; **UN solo harness openfga** —`openfga`, o `openfga (árbol SQL)` en PG/MySQL— si `OPENFGA_TEST_URL`, que desde 3b-2k · K2 **es** el del modo `facts` (`AUTHZ_CONTRACT_FACTS` desapareció con el modo `resolver`); `injectableClock: true` en todos), `contract_harness` (conteo de casos del juez, desde L-2 **41 core / 54 en 2.0 / 72 en 2.1 / 83 en 2.2** con `listDenies: true`, `purgeRole: false` e `injectableClock: false` (87 con el reloj; 78 sin `listDenies`; **con `purgeRole: true`, cinco más: 88** — el par `transactionalWrites` es UN caso por cara y suma uno en cada nivel; desde 3E · P4 la API de DELEGACIÓN entera cuelga de esa capacidad, no solo la purga, y desde 3b-0 · Z3 queda UN caso de COMPOSICIÓN de los cuatro de 3G · W4: los otros tres eran del `detached` que purgaba roles y se fueron con esa superficie): tocarlo al añadir casos. Par nuevo en 3E · R2: `serializedCatalogWrites` (PG/MySQL `true` ⇒ la carrera de dos `define` exige exactamente un ganador y 422 para el perdedor; SQLite `false` ⇒ la forma laxa). **Aviso 3D · N6 / 3E · R6**: la regla de owner en `authorize` Y la regla de ambigüedad de `RoleQuery` cuelgan cada una de UN solo caso por harness (los demás casos `'2.2'` van por rutas de lectura que filtran en otro punto), así que un refactor del SQL/checks —o un driver de terceros con su propio `roleVisible`— puede pasar la suite entera con la regla rota), `expiry_timezone` (K2/K17: hijos en UTC/Tokio/Caracas sobre la misma base, PG/MySQL), `authz_scopes_trait` (K3/K6), `upgrade_recipe` (K14, PG/MySQL), `manager` (incluye el grupo «lote 2B»: actor, aviso opt-in, composición de `authorizeMany`/`effectivePermissions`/`authorizedScopes` con drivers falsos; los de 2D: F5, F8, F9 —con reloj inyectado y `Date.now` hacia atrás, 2E · H3/I2—, F10, espía que sobrevive a `withChainResolver`; H1 en `manager.scopes`; «catálogo» con B5/B6 —`assignableAt`, sync solo globales, diff—; y «roles locales a un scope (3B · B3)»: la policy completa de la delegación, C2, C3, colisiones, globales inmutables, hook, driver sin `purgeRole`), `middleware`, `database_driver`, `openfga_driver` (unitarios sin servidor; desde 3b-2k · K2 sin los dos grupos del `batchCheck` de la cadena, que juzgaban el modo `resolver`), `openfga_facts` (modo `facts`: A1–A6 de 3b-2a y el árbol de 3b-2b; el store en memoria de `projectingDriver`/`treeDriver` juzga qué lee y qué escribe sin servidor y con `OPENFGA_TEST_URL` además el modelo real, la calibración del techo y **el ciclo que FGA acepta**), `spies` (coste por operación **del driver `database`**: catálogo una vez + 1 revalidación por pregunta, `forRequest`, `authorizeMany`, `effectivePermissions` ≤ 2 lecturas; la entrada `openfga` se fue en 3b-2k · K2 —mide `authorize` pasando por el árbol, que en `facts` no pasa— y su evidencia vive en `openfga_facts` y en los pares `singleCheckAuthorize`/`roleInheritanceNative`/`hierarchyFacts` del juez), `catalog_cache` (contrato del memo y de la versión compartida: `withAuthzCatalogWrite`, bump sin trx ⇒ 500, fila ausente ⇒ 503, reloj monótono, `catalog`+`catalogRevalidate` ⇒ 500), `memoize_ancestors`, `hierarchical_resolver` (B4, F6), `sql_descendants` (B2, G1, sobre `demo_scopes` de `helpers/schema.ts`; ciclo con cota > 1000 —MySQL—), `purity` (reglas 1–3 + carga de `index.ts` con el SDK bloqueado, `helpers/load_without_sdk.ts`), `prune_stores`, `configure` (los stubs compilan, con el subpath mapeado), `migration_stub` (seis tablas + semilla + decisiones J3/⚪4 en el texto del stub; K11: el stub ejecutado en una base de trabajo = el espejo, columna a columna **y acción de FK a acción de FK** —3D · M6—; 3B · B1: `owner_scope_key`/`assignable_at`, el `DEFAULT 'global'` del motor y el unique de tres columnas observados), `scope_tree` (3b-1 · M14: el contrato `null` de `descendantsFrom`), `harness_cleanup` (+ 3b-1: un proceso que sale con `process.exit()` SIN `teardown()` —el patrón de los scripts de reproducción, y la causa MEDIDA de la fuga de bases en PG— tampoco deja residuo: `bootApp` registra un guard SÍNCRONO en `process.on('exit')` que destruye lo provisionado con `helpers/drop_database.mjs` y AVISA por stderr; hijo `helpers/exit_without_teardown.ts`; **el nombre de base se DERIVA de la URL** —`provisionedNamePattern(engine)`, 3b-4 · C5: clavar el literal `authz_test_` rompía la suite con un `TEST_PG_URL` legítimo—; y desde 3b-4 · C5 la MISMA red para los **stores de OpenFGA** —`helpers/openfga_stores.ts` + `helpers/delete_stores.mjs`, armada por `bin/test.ts` cuando hay `OPENFGA_TEST_URL`: foto al arrancar y borrado de lo que NO estaba y se creó después; el goteo venía de las corridas INTERRUMPIDAS, no del uso normal; hijo `helpers/exit_with_store.ts`—), `pool_concurrency`. **2.4.0-alpha.2**: `helpers/fga_spy.ts` (`spyFgaClient(driver)`, L-5: Proxy sobre el cliente FGA REAL que cuenta cada método; «cero llamadas» = ni `Write` ni `Read` ni `Check`), `database_transaction.spec.ts` (L-3: los casos de motor de `{ transaction }` en roles —composición con tabla del consumidor, otra conexión real, UNIQUE y deadline por motor— gateados a pool ≥ 2, más la cara de `:memory:`), el grupo L-4 de `relations_database.spec.ts` (trigger en la trx, caducidad × trx, deadlock, holder), los grupos L-5 (`@l5`: roles en `contract.spec`, relaciones en `relations_openfga.spec`, paridad en `relations_bridge.spec`, grep en `openfga_driver.spec`) y **L-6** (`@l6` en `contract.spec`: la receta por dirección MEDIDA; `trx_docs.spec.ts`: grep «atomic» del README, la LETRA del 500, las frases de L-6). `freeze.spec.ts` lleva desde L-1 los casos 🟠 8 (cliente mentiroso, snapshot REPEATABLE READ, pool 1) y J1, flipados en L-3 para el driver capaz. |

## Comandos

```bash
npm test               # Japa; SQLite en memoria (pool 1/1), sin app anfitriona
npm run test:sqlite-file   # SQLite en fichero (mkdtemp) con pool 2..5: concurrencia real (también en CI, job test)
npm run test:pg        # PostgreSQL: TEST_PG_URL (default postgres://postgres:postgres@127.0.0.1:5432/authz_test)
npm run test:mysql     # MySQL 8:   TEST_MYSQL_URL (default mysql://root:root@127.0.0.1:3306/authz_test)
npm run typecheck      # tsc sobre tsconfig.test.json
npm run build          # purity + typecheck + tsc + copia de stubs
OPENFGA_TEST_URL=http://localhost:8101 npm test   # además corre el contrato contra OpenFGA (combinable con TEST_DB)
```

En esta máquina los motores son los contenedores `postgres18` (127.0.0.1:5432, usuario `postgres`; la contraseña
está en `docker inspect postgres18` → `POSTGRES_PASSWORD`, pásala en `TEST_PG_URL`) y `mysql84` (127.0.0.1:3306,
`root`/`root`, el default). La base de la URL es solo el nombre base: cada ejecución crea `authz_test_<8 hex>` y la
borra al terminar; nunca se toca una base existente.

Hay un OpenFGA local en `:8101` (ver `~/proyectos/Personal/api-loco-base`). Para reproducir el tope de
`ListObjects`/`ListUsers` de CI (la prueba de que las enumeraciones no dependen de él):
`docker run -d --name openfga-tiny -p 8103:8080 -e OPENFGA_LIST_OBJECTS_MAX_RESULTS=3 -e OPENFGA_LIST_USERS_MAX_RESULTS=3 -e OPENFGA_DATASTORE_ENGINE=memory openfga/openfga:v1.19.0 run`
y `OPENFGA_TEST_URL=http://localhost:8103 npm test`; al terminar, `docker rm -f openfga-tiny`.

## Estado del roadmap 2.0 (decidido 2026-08-28)

Contexto completo (fuera de git) en `.claude/contexto/`: exigencias del consumidor, cuatro
paneles, decisiones del dueño, y **`roadmap-2.0.md` (fases, contenido y versión de cada una)**.
Resumen operativo:

- **2.0.0 es breaking** (hoy no hay consumidores): sin flags de compatibilidad.
- Driver `openfga` pasa a modo `facts` único (árbol + catálogo proyectado en FGA, `authorize`
  = un `Check`). Modelo: variante (c2) — `role#permits_P@user:*`, `role_binding:<scopeKey>|<roleUuid>`,
  `scope#parent`, `can_P = P but not denied_P`.
- Fases: **0** ✅ (juez con `level`/`capabilities`, `ContractScopeTree`, CI con 2.º OpenFGA) →
  **1** ✅ L0 seguridad (16 defectos, tres lotes A/B/C + lote D de cierre con las correcciones del
  tester, el auditor y el code-review; informes en `.claude/contexto/fase-1-lote-*-informe.md`;
  pendiente el commit del dueño) →
  **2** primitivas (**2A** ✅ optimización: memo del catálogo, 1 batchCheck —4,33 → 2,03 ms p50—,
  `forRequest()`; informe `fase-2-lote-a-informe.md`; **2B** ✅ primitivas B1–B7 —`within`/`isWithin`,
  `descendantsOf`+`sqlDescendantsOf`, `authorizedScopes`, `hierarchicalScopeResolver`, `listDenies`+
  `effectivePermissions`, `authorizeMany`, `actor`— y nivel `'2.1'` del juez; informe
  `fase-2-lote-b-informe.md`; **2D** ✅ correcciones de cierre F1–F10/G1–G6 —versión compartida del catálogo,
  `within` en las seis escrituras, `authorizedScopes` coherente con `authorize`, `forRequest({ maxAgeMs })`—,
  informe `fase-2-lote-d-informe.md`; **2E** ✅ cierre final H1–H4/I1–I7 —`within` contra origen y destino en
  `moved`/`attached`, `withAuthzCatalogWrite` + `bumpAuthzCatalogVersion(trx)` obligatorio, reloj monótono, fila de
  versión ausente ⇒ 503, par de capacidad `listDenies`—, informe `fase-2-lote-e-informe.md`; pendiente el commit
  del dueño) →
  **2.5** ✅ infraestructura de test (J1 reloj inyectable + par `injectableClock`; J2 harness `TEST_DB` con PG 18 /
  MySQL 8.4 / SQLite fichero; J3 defectos de motor —`DATETIME(3)`, `utf8mb4_bin`, `varchar(64)`, CTE en MySQL con
  hint de profundidad—; J4 concurrencia; J5 job `engines` en CI; informe `fase-2.5-informe.md`) → **2.5-B** ✅
  correcciones de cierre K1–K17 —cadena canónica del resolutor (**breaking**: `resolveChain`/`ScopeChainResolver`,
  `nodeOf`, uuids en minúsculas; juez con árbol SQL en PG/MySQL), `expires_at` como UTC explícito en MySQL con
  procesos hijos en TZ distinta, trait/PG, re-grant sobre fila borrada, sellos con reloj del sistema, un `current_time`
  por operación, guard stub↔espejo por `information_schema`, `withAuthzCatalogWrite` clasifica errores SQL, receta
  1.x→2.x ejecutada, cota `MAX_SCOPE_BOUND`—; informe `fase-2.5-lote-b-informe.md`; pendiente el commit del dueño) →
  **3** `catalog/` roles por scope (**3A** ✅ identidad por uuid: binding id FGA `role_binding:<scopeKey>|<roleUuid>` parseado desde la derecha, sin `~`, 2.2 no lee ids 1.x —sin comando de migración—; `database` por uuid; `CatalogView.roleByUuid`/`rolesFor`; informe `fase-3-lote-a-informe.md`; **3B** ✅ roles locales: `owner_scope_key` + `assignable_at` (B1), visibilidad por owner por nivel en ambos drivers (B2), `defineScopedRole/updateScopedRole/deleteScopedRole` con policy y `onCatalogWrite` (B3), `purgeRole` en el puerto + par de capacidad (B4), `assignableAt` como composición —en el PERMISO, desviación documentada— (B5), sync solo globales (B6), memo con owner y canal de versión (B7); juez `'2.2'`; invariante 18; informe `fase-3-lote-b-informe.md`; **3C** cierre: **3D** ✅ correcciones del auditor NO APTA + tester —M1 identidad del rol por uuid en el puerto y ambigüedad ⇒ 422 `E_AUTHZ_AMBIGUOUS_ROLE`; M2 unicidad serializada (cerrojo de la fila de versión) + re-chequeo en transacción + `ambiguousRoles` en el diff; M3 `within` en las nueve escrituras; M4 `scopes.detached` purga los roles de ese owner; M5 parche del tester; M6 FKs stub↔espejo y K11 con `delete_rule`; N1–N7—; informe `fase-3-lote-d-informe.md`; **3E** ✅ cierre final —P1 nivel del rol ≤ owner (`E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER`) y el sync deja de abortar por un local (los globales ganan, `shadowedByGlobal`); P2 `scopes.detached` canónico, leyendo la base y bajando por `descendantsOf`; P3 policy de rank en `detached`; P4 `defineScopedRole` exige `purgeRole` ANTES de escribir (openfga ya no lo trae) y el caso `whenFalse` del juez deja de fijar el callejón; P5 diff tolerante con la fila corrupta; P6 revalidación de `assignableAt` con reporte; Q1–Q8; y del tester R1–R7 —parche del owner por `{uuid}`, par `serializedCatalogWrites`, `effectivePermissions` sin `rolesInChain`, evento con el rol resuelto, carrera sync×define, notas de fragilidad, conteo de vínculos en `purgeRole`—; informe `fase-3-lote-e-informe.md`; **3F** ✅ cierre del cierre —S1 `scopes.detached` de un scope ya borrado purga igual saltándose el rango y lo dice (`ScopeDetachOutcome`, `reason`); S2 el subárbol que no se puede enumerar DEGRADA (`truncated`, regla de nivel mínima) en vez de tumbar la operación; S3 colisión por AUTORIDAD (global > local de un ancestro > local de un descendiente), `shadowedByAncestor`, y el diff deja de contar como deriva lo ensombrecido; S4 la frase del ensombrecimiento corregida y fijada con un caso; T1–T5; y del tester 3E U1–U5 —parche Q1/Q2/P3, corrección honesta de R7 (el `CASCADE` es el garante), rama no juzgable determinista, las dos mitades de Q7 y orden estable de `readRolesOwnedBy`—; informe `fase-3-lote-f-informe.md`; **3G** ✅ cierre de la Fase 3 —W1 el rango de `scopes.detached` se mide por rol en la cadena del owner de cada uno (🟠 auditor P1: `detached` de un ancestro desconocido destruía roles de descendientes vivos); W2 `truncated: true` y `reason` cuando el scope no resuelve y nada se enumera por debajo, con el contrato de `descendantsOf` escrito en el puerto; W3 ensombrecer exige rango; W4 cuatro casos de COMPOSICIÓN en el juez (la causa de las tres regresiones seguidas); X1–X6 —degradación documentada, policy de rango con `below = []`, `--fail-on-shadows` + `classifyHomonyms` sin punto ciego, `CLAUDE.md` coherente, el 422 de rango sin fuga de catálogo ajeno, CHANGELOG/README—; y del tester 3F Y1–Y3 —la carrera ancestro↔descendiente tiene dos finales legales (aserción flaky en el artefacto publicado), el caso de S1 con dos roles y un actor sin rango, el mensaje de `AMBIGUOUS_ROLE`—; informe `fase-3-lote-g-informe.md`; pendiente el commit del dueño) → **3b** (**3b-0** ✅ simplificar antes de añadir, y BORRA: Z1 `scopes.detached` vuelve a purgar SOLO hechos —fuera la policy de rango, la enumeración de descendientes para roles, la degradación, `truncated`/`reason` y `ScopeDetachOutcome`—, Z2 `authz:catalog:prune-orphans`/`pruneOrphanRoles` barre los roles dormidos desde la plataforma, Z3 los tres casos de composición W4 que eran de `detached` se borran con la superficie que juzgaban, D7 docblock duplicado; informe `fase-3b-lote-0-informe.md`; **3b-0b** ✅ correcciones del auditor 3b-0 —AA1 «dormido» = no visible desde ningún scope vivo cuya cadena no pase por el owner (la frase publicada era FALSA y medible: con un descendiente vivo el rol concede, es membresía y se asigna) corregida en README/`CLAUDE.md`/docblocks + `stillGranting`/`assignments` por huérfano; AA2 cota de purga masiva (`E_AUTHZ_MASS_PURGE_REFUSED`/`allowMassPurge`) contra el `resolveChain` ciego; AA3 re-resolución del owner justo antes de cada `purgeRole` (`skipped`/`owner-came-back`); AA4 los hechos del descendiente sobreviven al `detached` y despiertan con el scope, escrito en CHANGELOG/README y fijado con un caso; AB1–AB4; informe `fase-3b-lote-0b-informe.md`; **3b-2a** ✅ el generador del modelo (c2) y la proyección del catálogo —A1–A6, `openfga_facts.ts`, `catalogProjection()`, techo PROTOBUF calibrado contra el `:8101`; informe `fase-3b-lote-2a-informe.md`—; **3b-2b** ✅ el ÁRBOL como hechos —`hierarchy: 'facts'`, la arista `scope#parent` con identidad canónica, anti-ciclos en el PAQUETE con el fail-open del servidor reproducido contra el `:8101`, `moved` = 1 `Read` + 1 `Write` y >1 padre ⇒ 500 `E_AUTHZ_SCOPE_TREE_DRIFT`, orden de `detached` fijado (S6); informe `fase-3b-lote-2b-informe.md`—) → 3b-2c `authorize` de un solo `Check` → 3b-2d outbox → 3b-2e capacidades y borrado del `resolver` → 3b-2f/2g/2h correcciones del auditor R2 → **3b-2i** ✅ el modelo **(c2r)**, cierre del 🔴 1 —`can_<P> = (<P> but not denied_<P>) and rooted` y el marcador de raíz `scope:app#rooted@<holder>:*` (cero tuplas por scope); `authorize` sigue siendo UN solo `Check` y la profundidad sigue en 22, medidos; el techo baja a 691 permisos; el lag del relay cambia de signo a fail-CLOSED para `attached` (**breaking**, decisión del dueño del 2026-08-31 (2)); diseño en `fase-3b-diseno-r1.md`, informe `fase-3b-lote-2i-informe.md`— → `reconcile` (con dos deberes escritos: reportar el marcador de raíz ausente y listar los scopes NO alcanzables desde `app`) → **3b-7** ✅ el freeze DURABLE (B + E-analista, decisión del dueño del 2026-08-31 (3b)): fila `id=2` + token + lease + fence, comandos del cutover `authz:freeze`/`authz:unfreeze`, README reescrito (fuera «the one thing the report promises cannot happen» y «window of seconds»), caso multiproceso que mata al mutante `modulo`; informe `fase-3b-lote-7-informe.md` → **4** `relations/` ✅ (`2.4.0-alpha.1`, publicado 2026-09-01) → **5** `http/` ✅ → **6/6b** consolidación ✅ → **`2.4.0-alpha.2`** ✅ (2026-09-01/02, decisión del dueño «SÍ, ARRANCA CON ESO» tras la verificación 7/9 de COGNITIV): **R-15** caducidad en la tupla de relación (`r15-informe.md`) y el **panel `{trx}`** (`panel-trx-{analista,auditor,juez}.md`, veredicto (C)) en lotes: **L-0** F-05 con dientes en los DOS drivers de relaciones y en `reconcileRelations` (`skipped.undeclared`); **L-1** la barrera del freeze la lee el MOTOR (fuera el cast de `#writeOptions` y `FreezeSqlOptions.client`; `freezeTimeoutMs` como deadline TOTAL —60 s de knex medidos—), `assertCallerTransaction`, relaciones bajo la barrera y `authz:relations:reconcile` bajo ventana durable; **L-2** capacidad `transactionalWrites` + dos puertas en los dos puertos, `transaction` declarado en los tipos, runners con las dos caras obligatorias; **L-3** `{ transaction }` real en `database` roles (`writer`/`poisoned`, 409 que envenena, `transactional: true` en `onWrite`); **L-4** ídem relaciones (trigger en la trx, caducidad × trx, deadlock ⇒ 409); **L-4b** `subject_relation NOT NULL DEFAULT ''` con receta ejecutada; **L-5** `openfga` rechaza con dientes en los dos puertos contra el `:8101` (driver que re-valida, arranque, paridad que fija la asimetría, grep); **L-6** docs con dientes (README consolidado en «Writing inside your transaction» + receta por dirección medida, CHANGELOG con cabecera consolidada, roadmap reescrito, `trx_docs.spec.ts`). Informes `l0..l5-informe.md`, `l4b-informe.md`, `l6-informe.md`. **Publicada el 2026-09-02** (`v2.4.0-alpha.2`). Cifras al cierre: **1074 / 1095 / 1190 / 1190** (sqlite / sqlite-file / pg / mysql).
- Garantía por fase: test rojo→verde por pieza, suite verde en SQLite + OpenFGA, revisión de
  `tester-contrato` y `auditor-seguridad` sobre el diff.

## Cómo se decide un cambio en este paquete

1. Toda feature nueva se expresa primero como **caso del contrato** (¿qué debe
   observar el juez en ambos drivers?). Si no se puede expresar así, se discute
   antes de codificar.
2. Antes de implementar, se evalúa el plan con los agentes `analista-tecnico`
   (arquitectura), `auditor-seguridad` (romperlo), `tester-contrato`
   (verificabilidad) y `juez` (síntesis). Se implementa la opción que gana.
3. Todo cambio de semántica va al `CHANGELOG.md` con el *porqué*, en el estilo del
   1.1.0 (problema → decisión → qué NO se hace y por qué).
4. Un cambio que rompa el contrato para drivers de terceros es **major**.
