# @jantstack/adonis-authz — guía para agentes

Motor de autorización driver-based para AdonisJS 7 + Lucid. Paquete npm publicado (v1.1.0;
en el árbol, `2.0.0-alpha.1`), ESM, Node ≥ 20.6. Autor: José Antonio (jantstack). Idioma de trabajo: **español**
(código y comentarios ya están en español; el README y CHANGELOG en inglés).

## Invariantes del contrato (innegociables)

Todo driver debe cumplirlos; los verifica `src/testing/contract.ts` (la misma suite
corre contra `database` y `openfga`). Cualquier plan que rompa uno de estos sin
discusión explícita es un plan rechazado.

1. **Scopes jerárquicos, herencia SOLO hacia abajo.** Un grant en un scope vale en él
   y en todos sus descendientes; nunca en hermanos ni ancestros. El motor solo
   conoce la raíz `app` (`APP_SCOPE`, uuid null); el árbol lo inyecta el consumidor
   vía `resolveChain`.
2. **Deny explícito gana.** Un deny en cualquier punto de la cadena bloquea aunque un
   rol conceda. Quitar el deny restaura.
3. **Expiración observable sin scheduler.** `expiresAt` pasado ⇒ no concede. En SQL
   para `database`, con *condition* FGA para `openfga`.
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
   Re-revoke / re-deny / re-removeDeny son no-ops seguros.
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
10. **`expiresAt` en tres estados.** Omitido preserva una caducidad vigente (expirada ⇒ revive sin
    caducidad), `null` la quita, `Date` la fija; `grant` devuelve `GrantOutcome` y un cambio se
    audita como `extended` con `previousExpiresAt`.
11. **Purga con demostración de cero.** `scopes.detached` ⇒ `purgeScope` borra los hechos del
    scope exacto cuyo rol/permiso está en el catálogo y demuestra que ESE conjunto quedó a cero
    o lanza 500 `E_AUTHZ_PURGE_INCOMPLETE`; nada resucita; la raíz no se purga (422). Los hechos
    de roles retirados no conceden ni son membresía (las lecturas filtran por catálogo) y los
    recoge `authz:reconcile` (3b).
12. **El catálogo manda y se poda.** `syncAuthzCatalog` poda por defecto los vínculos que el spec
    ya no lista (roles del spec); un rol `(slug, scopeType)` y un permiso pertenecen a exactamente
    un catálogo (422 `E_AUTHZ_CATALOG_CONFLICT`); la membresía (`hasRole`/`list*`) es lo que dice
    el catálogo en ambos drivers.
13. **Una escritura que vence el deadline es indeterminada.** El manager notifica `onWrite` con
    `indeterminate: true` antes de propagar el 503 `E_AUTHZ_BACKEND_TIMEOUT`; el driver openfga no
    deja al SDK reintentar por su cuenta (`maxRetry: 0`).
14. **El catálogo que decide es el de la BD (versión compartida).** `authz_catalog_version` sube como ÚLTIMA
    sentencia de la transacción que escribe `authz_*` — la de `syncAuthzCatalog` y la de cualquier escritura a
    mano, ambas por `withAuthzCatalogWrite(async (trx) => …)`; `bumpAuthzCatalogVersion(trx)` exige ese trx (500
    `E_AUTHZ_CONFIG` sin él: un bump que se confirma antes que su escritura envenena el memo de los demás procesos
    para siempre). El memo la contrasta antes de servir (default `'always'`, un SELECT por PK por pregunta;
    `{ everyMs }` es una ventana acotada opt-in medida con reloj MONÓTONO) y **nunca sirve una decisión con una
    versión distinta de la de la base**. Un sync en otro proceso se ve en la siguiente pregunta de todos. Sin
    fila de versión legible (tabla, fila o número ausentes) ⇒ 503 «migración 2.0 no aplicada», nunca versión 0
    ni el memo viejo.
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
    guiones (tipo `uuid` de PG) lo cierra la cadena canónica. El juez lo observa con `memoryScopeTree` Y con el
    árbol SQL del harness (`sqlScopeTree`, PG/MySQL), que es donde estaba el bypass.
18. **Un rol local solo existe dentro de su owner** (3B). `authz_roles.owner_scope_key` es `global` (catálogo
    del config, `syncAuthzCatalog`) o `scopeKey(owner)` (`<tipo>|<uuid>`; `defineScopedRole`; la raíz nunca es
    owner y `global` no lo produce ningún scope). Regla única en ambos drivers: **una asignación en el scope S del
    rol R cuenta si y solo si R es global o su owner está en chain(S)** (S inclusive), decidida con el árbol de HOY
    (mover la unit fuera del owner retira lo concedido sin escribir; volverla lo restaura). Fuera del owner el rol
    no concede, no es membresía (`hasRole`/`list*`/`rolesInChain`/`effectivePermissions`/`authorizedScopes`) ni se
    asigna (422 `E_AUTHZ_ROLE_NOT_VISIBLE`). El slug no identifica un rol (dos tenants definen `lead@unit`); el uuid
    sí. `defineScopedRole/updateScopedRole/deleteScopedRole` son policy de ESCRITURA (actor obligatorio,
    `delegablePermissions` ∩ efectivos del actor en el owner sin deny —C2—, `0 < rank < min(actor, techo global)`,
    colisión hacia ARRIBA (global o ancestro-o-igual) ⇒ 422 y hacia ABAJO ensombrecimiento por AUTORIDAD **con
    rango** (3F · S3 + 3G · W3), globales inmutables, owner resuelto en FRESCO —C3—) y
    `assignableAt` de un permiso es control de COMPOSICIÓN (sync, define/update, `grant`); `authorize` no mira
    owner-policy, `rank` ni `assignableAt`: lo asignado concede lo que su rol vincula (invariantes 1, 2 y 8).
    `purgeRole(uuid)` en el puerto: todo o nada (`database`); `openfga` lo dice con 500 hasta 3b (`purgeRole: false`).
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
    reporta los homónimos visibles (`ambiguousRoles`; desde 3F · S3 solo son deriva —exit ≠ 0— los que la autoridad no ordena). **Un rol cuyo owner sale del árbol no
    sobrevive** (3D · M4; 3E · P2): `scopes.detached` purga ANTES de los hechos los roles cuyo owner es ese scope —con
    la identidad CANÓNICA (`chain[0]`, como los hechos: un alias del uuid ya no los deja vivos), leídos de la BASE y no
    del memo (una ventana `{ everyMs }` no ve lo que otro proceso acaba de confirmar) y, **con `scopes.descendantsOf`
    declarado, los de todo el SUBÁRBOL**— y ese `(slug, nivel)` vuelve a estar libre; un driver sin `purgeRole` lo dice
    con 500 sin tocar nada. **Sin `descendantsOf` la promesa se acota al scope EXACTO** (un `detached(padre)` deja
    huérfanos los roles de los hijos: se notifica nodo a nodo o se declara `descendantsOf`).
    **El rango de `scopes.detached` se mide POR ROL, en la cadena del OWNER de cada uno** (3G · W1, auditor P1):
    igual que `deleteScopedRole`, y la comprobación solo se salta para los roles cuyo PROPIO owner tampoco resuelve.
    Medirla en la cadena del scope NOTIFICADO y aplicarla a roles de otros owners era fail-open: con `descendantsOf`
    declarado y la fila del padre ya borrada, `detached(padre)` destruía roles locales de descendientes VIVOS de
    cualquier rango (tercera regresión seguida por COMPOSICIÓN de dos piezas correctas; por eso el juez tiene ahora
    cuatro casos `since('2.2')` de composición —3G · W4—). **El puerto no le exige nada a `descendantsOf` sobre un
    scope que `resolveChain` ya no conoce** (3G · W2): puede devolver los hijos o `null`, así que si el scope no
    resuelve y por debajo no llega nada la purga NO se puede declarar completa ⇒ `truncated: true` y `reason`
    aunque `purgedRoles` sea 0. **Ensombrecer exige RANGO, no solo posición** (3G · W3, auditor P3′): `define`/
    `update` que ensombrecen al homónimo de un descendiente piden `rank(actor) > rank(ensombrecido)` (422
    `E_AUTHZ_RANK_EXCEEDED` que NO nombra el rank ni el owner del de abajo); si no, un rank 3 de una organization
    inutilizaba por slug un rol rank 40 de una unit, en toda su cadena y sin que la víctima pudiera repararlo.
    **La degradación de `descendantsOf` relaja la regla de nivel a la MÍNIMA y el propio actor puede provocarla**
    creando hijos (o una réplica caída): está aceptado y acotado —la regla mínima no concede nada, es la que corre
    con el stub publicado— y la mina residual la repara autoridad+rango (3G · X1). `authz:catalog:diff
    --fail-on-shadows` es el gate opt-in para quien sí quiera enterarse por CI (3G · X3).
    **Un scope que el árbol YA NO conoce se purga igual** (3F · S1): `detached` limpia DESPUÉS de borrar la fila,
    así que sin cadena donde medir el rango la purga procede saltándose esa comprobación y lo DICE (`reason:
    'owner-detached-unknown'` en el evento y en el `ScopeDetachOutcome` que ahora devuelve —`{ purgedRoles,
    truncated, reason? }`, ya no `void`—); con el scope en el árbol, el rango se exige igual que en P3.
    **Declarar `descendantsOf` nunca deja peor que no declararlo** (3F · S2): si el subárbol no se puede enumerar
    (más de `maxDescendants`, o un `descendantsOf` que falla) se DEGRADA —la purga se acota al scope exacto con
    `truncated: true` y la regla de nivel cae a la mínima— en vez de tumbar la operación con un 503 que no
    purgaba ni los hechos.
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
  Hoy (2.0) existe `openfga:import --reconcile [--prune]`, unidireccional database → openfga,
  que ya converge: cuenta `extra` (tuplas que SQL no tiene) y con `--prune` las borra (`deleted`).
- **El árbol de scopes es un hecho del contrato.** El consumidor notifica sus cambios con
  `authorization.scopes.attached/moved/detached` en TODOS los drivers (en `database` es casi
  no-op salvo `purgeScope`). `resolveChain` sigue existiendo para validar escrituras y
  para reconcile. Anti-ciclos y validación de existencia son del paquete, nunca del backend.
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

| Ruta | Qué es |
|---|---|
| `src/types.ts` | El contrato (`AuthorizationDriver` —con `purgeRole` desde 3B; `grant`/`revoke`/`listSubjects` por `RoleQuery` y `rolesInChain` ⇒ `CatalogRoleRef` desde 3D · M1—, `RoleQuery` (`string \| {slug,scopeType} \| {uuid}`)/`NormalizedRoleQuery`, `CatalogRoleRef`, `SubjectRef`, `ScopeRef`, catálogo: `CatalogSpec`/`CatalogPermissionSpec` (`assignableAt`)/`CatalogRoleSpec`, `CatalogRole` (`owner`, `rank`), `ScopedRoleSpec`/`ScopedRoleChanges`, `AuthzCatalogWriteEvent`). Empieza aquí. |
| `src/manager.ts` | Fachada; resuelve driver del config, dispara `onWrite`. `forRequest({ maxAgeMs = 30_000, now? })` ⇒ `AuthorizationView` (mismo API; lecturas con ancestros memoizados, escrituras en fresco — 2A; tras `maxAgeMs` —reloj monótono, 2E · H3— TODAS las lecturas, `expandExcludedSubtrees` incluida, son 500 `E_AUTHZ_VIEW_EXPIRED` — 2D/2E). Primitivas 2B como composición: `isWithin`/`within` en las SEIS escrituras (`ScopedWriteOptions`; `requireWithin: true \| 'non-root'`; en `moved`/`attached` contra destino Y origen, `#assertWithinOrigin` — 2E · H1), `actor`/`requireActor` (`WriteOptions`), `authorizeMany` (delega —validando el `boolean[]`— o compone), `listDenies`, `effectivePermissions` (`rolesInChain` + `listDenies` una vez), `authorizedScopes` (`none|some|all{excludedSubtrees: ExcludedSubtree[]}`, `descendantsOf` del config, pertenencia por `resolveChain`, cotas que cortan antes de pasear y por llamada solo bajan), `expandExcludedSubtrees`. `driver()` = salida documentada de las barreras. Aviso de seguridad opt-in una vez por config. **API de delegación (3B · B3; `options: ScopedWriteOptions` desde 3D · M3)**: `defineScopedRole(actor, ownerScope, spec, options?)`, `updateScopedRole(actor, uuid, changes, options?)`, `deleteScopedRole(actor, uuid, options?)` — `within` contra el owner + policy antes de escribir (`#assertComposable`/`#assertDelegable`/`#assertRank`/`#assertAboveRole`/`#assertNoRoleCollision` —3F · S3: colisión por AUTORIDAD, el homónimo de un descendiente se ensombrece y se reporta— + `#shadowedBelow`/`#assertAboveShadowed` —3G · W3: ensombrecer exige rango, en define Y en update—), `#rolesAlong`/`#deniedAlong` (compartidos con `effectivePermissions`), `#descendantsOrDegrade` (3F · S2: el subárbol que no se puede enumerar degrada, no tumba; 3G · X1: lo que cuesta esa degradación, escrito), `#assertAboveOwnedRoles` (3G · W1: el rango de `scopes.detached`, POR ROL y en la cadena del owner de cada uno), owner en fresco, `#writeCatalog` (= `withAuthzCatalogWrite` + invalidación), `#notifyCatalog` (`hooks.onCatalogWrite`). |
| `src/drivers/database_driver.ts` | Driver SQL propio sobre `authz_*`. Identidad del rol por uuid (3A · A2: `hasRole` por `(scope, role_uuid)` del memo, `listRoles`/`rolesInChain` por `role_uuid` → memo, `listSubjects` resuelve el rol antes de consultar). **Owner por nivel** (3B · B2): `authorize` une `authz_roles` y filtra `owner_scope_key = 'global' OR IN (claves de la cadena desde ese nivel)` en SQL (`whereVisibleAssignmentIn`); `grant` = `resolveRoleQuery` + `assertRoleAssignableAt` (compartidos con openfga, como `visibleRoleFor`/`rolesToRevoke`/`hasRoleTargets`/`declaredRoleAt` —3D · M1/N5—); `revoke` por slug quita todos los homónimos del scope exacto y por `{uuid}` solo ese. `purgeRole(uuid)` (B4): asignaciones + vínculos + fila en `withAuthzCatalogWrite`. `resolveChain` (cadena canónica; `chain[0]` = identidad de los hechos; `canonicalScope` para revoke/removeDeny/purge), `now?` y `withClock(now)` (2.5 · J1); `whereActive` = `expires_at > now()`; `created_at` con `systemClock()` (K5: sello, no decisión); `expires_at` vía `ExpiryCodec` (K2); `grant` reintenta como inserción si el UPDATE toca 0 filas (K4). Verificado en SQLite, PostgreSQL 18 y MySQL 8.4. |
| `src/drivers/sql_expiry.ts` | **Codec de `expires_at` por dialecto** (2.5-B · K2): MySQL escribe/compara cadena UTC `YYYY-MM-DD HH:mm:ss.SSS` y lee con `DATE_FORMAT` (sin depender de `timezone`/`TZ`); PG/SQLite identidad. Lo usan el driver, el importador de openfga y el trait. `dialectOf(connection)`. |
| `src/openfga.ts` | Entrada del subpath `@jantstack/adonis-authz/openfga`: lo ÚNICO que exporta el driver openfga y sus herramientas (peer opcional `@openfga/sdk`). |
| `src/drivers/openfga_driver.ts` | Driver Zanzibar; modelo FGA generado desde `holderTypes`. **Ids de binding por uuid del catálogo** (3A · A1): `role_binding:<scopeKey>|<roleUuid>`, `deny_binding:<scopeKey>|<permissionUuid>`; `parseBindingId` parsea desde la derecha (UUID canónico) — **decisión estructural sin oráculo hoy** (3D · N6): con la gramática actual un `scopeKey` tiene siempre 1 o 2 partes, así que «desde la derecha» y «contando partes» coinciden para TODO id admisible y el mutante es equivalente; solo será observable cuando el `scopeKey` crezca de partes (3b, modo `facts`) — no lo «simplifiques» a conteo creyendo que la suite lo cubre; sin escape de slug (ningún `~`); 2.2 no lee ids 1.x (`extra` en reconcile, sin comando de migración). Lecturas de membresía filtradas por catálogo por uuid (`roleByUuid`) y por owner por nivel (3B · B2: `declaredRole(catalog, binding, chainKeys)`, `checksFor` filtra `rolesGranting` con `isRoleVisibleWith` ⇒ mismo nº de checks); `purgeRole` ⇒ 500 `E_AUTHZ_UNSUPPORTED` hasta 3b (B4); `Read` paginado y acotado; importador con `reconcile`/`prune`. |
| `src/define_config.ts` | `defineConfig`/`AuthorizationConfig`: `default`, `drivers`, `holderTypes`, `scopes.resolveChain` (la costura del árbol hacia arriba) + `scopes.descendantsOf?`/`maxScopes`/`maxDescendants` (2.1, hacia abajo, solo `authorizedScopes`/`expandExcludedSubtrees`), `requireWithin` (`boolean \| 'non-root'`)/`requireActor`/`warnOnOptInSecurity` (2.1), `clock` (2.5 · J1: reloj de pared que el manager aplica al driver con `withClock`; 500 `E_AUTHZ_CONFIG` si el driver no lo trae), `catalogs`, `delegablePermissions` (3B: lista blanca de la delegación, default `[]`), `hooks.onWrite`/`hooks.onCatalogWrite` (3B). |
| `src/identity.ts` | `assertIdentity`/`assertScope`/`assertValidSlug`/`assertExpiresAt`/`assertNoSlugCollisions`/`normalizeRoleQuery`/`assertCatalogUuid` (uuid de rol del spec: UUID canónico en minúsculas, 3A), `scopeKey`/`scopeFromKey`/`chainKeysFrom` (3B/3D · N5: `app` \| `<tipo>\|<uuid>`, la clave de los ids de binding FGA Y del owner de un rol; `global` reservada; UNA sola codificación), `isValidScopeType`: gramática de holders, scopes (tipos Y uuids en minúsculas `[a-z0-9._-]` —K1—; holder_type 50, scope_type 20, uuid 36), slugs (minúsculas, **42** = `MAX_SLUG_LENGTH`) y `expiresAt` (422). La aplica el manager y, por defensa en profundidad, cada driver. |
| `src/expiry.ts` | Los tres estados de `expiresAt` (`resolveGrantExpiry`, `sameInstant`, `toExpiryDate`, `expiryChanged`); `now` inyectable (default `systemClock()`). |
| `src/clock.ts` | **El reloj** (2.5 · J1): `Clock`, `systemClock` = el ÚNICO `new Date()`/`Date.now()` de `src/` fuera de `src/testing/` (grep en `tests/clock.spec.ts`). Ambos drivers aceptan `now?` e implementan `withClock(now)` (vista por prototipo); el manager aplica `config.clock` al resolver el driver (500 `E_AUTHZ_CONFIG` sin `withClock`) y las vistas de `forRequest()` lo comparten. Caducidad ESTRICTA: lo que vence ahora no cuenta (`expires_at > now`; `current_time < valid_until`). |
| `src/drivers/backend_guard.ts` | Clasificación de fallos compartida: `guardSql` (503 + deadline; también lo usa el catálogo), `withDeadline`, `isSqlDriverError` (K12), `resolveChain`/`assertKnownScope` (árbol: `null` ⇒ desconocido; lanza, cadena vacía, elemento inválido o elemento 0 ≠ scope pedido ⇒ 503; devuelve la cadena CANÓNICA), `canonicalScope` (revoke/removeDeny/purge: la fila si el árbol la conoce, el scope tal cual si no o sin resolutor), `rootOnlyResolver` (sin resolutor solo existe `app`). |
| `src/catalog.ts` | `syncAuthzCatalog` (**devuelve `CatalogSyncReport`** desde 3E: `shadowedByGlobal` + `assignableAtViolations`, reportar y seguir; `syncCatalogs` ⇒ `{ count, ...reporte }` y el comando lo avisa; prune de vínculos por defecto; colisiones también contra la BD; 503 con la BD caída; escribe vía `withAuthzCatalogWrite` —la versión sube como última sentencia de su transacción— e invalida el memo del proceso al terminar; **solo roles globales** —3B · B6: upsert por `(slug, scope_type, owner = 'global')`, colisión con un local ⇒ 422, rank/vínculos de locales intactos—; `assignable_at` de permisos —B5: el config manda, `assertAssignableAt` dentro del spec y contra la BD—), `diffAuthzCatalog` (+ `assignableAtMismatches`, `shadowedByGlobal`/`shadowedByAncestor` —3F · S3: ensombrecidos por AUTORIDAD, se listan (`formatShadowedRoles`) y NO son deriva—, `ambiguousRoles` —solo lo que la autoridad no ordena: deriva con exit ≠ 0—, `scopedRoles` informativo; `storedAssignableAt` normaliza igual que el sync —N5—)/`runCatalogDiff` (`failOnShadows`, 3G · X3)/`syncCatalogs` (catálogos disjuntos o 422 `E_AUTHZ_CATALOG_CONFLICT`), `encodeAssignableAt`, `formatScopedRoles`. |
| `src/catalog_cache.ts` | **Memo del catálogo** (2A; versión compartida 2D · F1): `CatalogView` con `role()` ⇒ el rol GLOBAL `CatalogRole` `{ uuid, slug, scopeType, owner, rank }`, `roleVisible(slug, scopeType, chainKeys)` (3B: el global o el local con owner en la cadena; **más de uno ⇒ 422 `E_AUTHZ_AMBIGUOUS_ROLE`**, 3D · M1), `rolesOwnedBy(ownerKey)` (3D · M4), `rolesNamed`, `roleByUuid`, `rolesFor(scopeType, ownerKeys)`, `rolesGranting` (refs con `owner`), `rolePermissionsOf(uuid)`, `permission()` ⇒ `{ uuid, assignableAt }`, `topGlobalRank`, `GLOBAL_OWNER_KEY`, `isRoleVisibleWith`, `parseAssignableAt` (corrupto ⇒ 500); `CatalogCache` (carga perezosa de `authz_*`, 3 consultas con deadline; nunca hechos ni decisiones), revalidación contra `authz_catalog_version` por `view()` (`revalidate: 'always' \| { everyMs }`, ventana con reloj monótono e inyectable `now` solo en tests; recarga si la fila va por delante; sin fila legible ⇒ 503 «migración 2.0 no aplicada»), `readAuthzCatalogVersion()`, `readRolesOwnedBy(ownerKeys)` (3E · P2: los roles locales de esos owners LEÍDOS DE LA BASE, con sus permisos, para `scopes.detached`; orden estable por uuid —3F · U5: el orden de `role_purged` se reproduce igual en los tres motores), `withAuthzCatalogWrite(fn)` (LA forma de escribir `authz_*` a mano: **cerrojo sobre la fila de versión al principio** —3D · M2, PG/MySQL— + transacción + bump al final, dentro; el canal entre procesos y el serializador del catálogo) y `bumpAuthzCatalogVersion(trx)` (exige el trx; 500 sin él), `assertCatalogOptions` (`catalog` + `catalogRevalidate` ⇒ 500), `invalidateAuthzCatalog()` (contador del proceso), `invalidate()` de instancia por generación (una carga en vuelo no la pierde). Ambos drivers lo usan (`catalog` o `catalogRevalidate`) tomando UNA foto por operación; `purgeScope` lee SQL en fresco. Caso negativo fijado: escribir `authz_*` sin subir la versión no se ve. |
| `src/memoize_ancestors.ts` | `memoizeAncestors(resolver)`: memo de una instancia sobre `ScopeChainResolver` (sin reloj; `null` memoizado; un throw no). SOLO camino de lectura (auditor C3/E3). El puerto tiene `withChainResolver?` opcional para que el manager lo aplique. |
| `src/hierarchical_resolver.ts` | `hierarchicalScopeResolver({ nodeOf, maxDepth = 64 })` (2.1, B4; K1): resolutor de la cadena desde la FILA (`nodeOf` ⇒ `{ self canónico, parent }`; `undefined` = desconocido ⇒ `null`; `parent` `null`/`app` = raíz); clave de visitados con separador `\u001f`; `self`/padre mal formado o `self` que no es el scope pedido ⇒ 503 `E_AUTHZ_RESOLVER_FAILED`; ciclo ⇒ 422 `E_AUTHZ_SCOPE_CYCLE`; `maxDepth` ancestros (app incluida) ⇒ 500 `E_AUTHZ_SCOPE_TOO_DEEP` (nunca cadena corta); un throw se propaga. |
| `src/sql_descendants.ts` | `sqlDescendantsOf({ table, uuidColumn, parentColumn, typeColumn \| scopeType, maxNodes?, connection?, timeoutMs? })` (2.1, B2): `descendantsOf` opt-in con UNA CTE `WITH RECURSIVE` (PG, SQLite y MySQL 8 —2.5 · J3: cita con backticks, resultado `[rows, fields]` de mysql2, hint `SET_VAR(cte_max_recursion_depth)` porque MySQL corta a 1000 iteraciones con el error 3636—; otro dialecto ⇒ 500 `E_AUTHZ_UNSUPPORTED_DIALECT`); identificadores y `scopeType` validados al construir; `LIMIT maxNodes+1` + profundidad `maxNodes+1` (un ciclo termina y lanza 422 `E_AUTHZ_TOO_MANY_SCOPES` con «posible ciclo»). |
| `src/errors.ts` | Todos con `status` + `code`: `AuthorizationBackendError` (503) y su subclase `…TimeoutError`; `ScopeResolverError` (503); `InvalidIdentityError`, `InvalidSlugError`, `UnknownScopeError`, `NoScopeResolverError`, `UnknownRoleError` (por slug+nivel o por uuid), `UnknownPermissionError`, `CatalogConflictError`, `ScopeCycleError`, `NotWithinError`, `WithinRequiredError`, `WithinRootForbiddenError`, `ActorRequiredError`, `TooManyScopesError`, y de 3B/3D `RoleNotVisibleError`, `AmbiguousRoleError` (`E_AUTHZ_AMBIGUOUS_ROLE`), `RoleImmutableError`, `RoleLevelAboveOwnerError` (`E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER`, 3E), `RoleNotAssignableAtError`, `PermissionNotDelegableError`, `RankExceededError` (422); `StoreNotEmptyError` (409); `AuthorizationConfigError`, `AuthorizationInternalError`, `RoleIsNotAccessError`, `PurgeIncompleteError`, `UnsupportedOperationError` (`E_AUTHZ_UNSUPPORTED`), `NoDescendantsResolverError`, `UnsupportedDialectError`, `ScopeTooDeepError`, `ViewExpiredError` (500). Tabla en el README. |
| `src/middleware/app_access_middleware.ts` | `appAccess({ permission })` a nivel `app`. Solo `permission`: `{ role }` ⇒ 500 con receta. |
| `src/testing/contract.ts` | **El juez**: `runAuthorizationDriverContract` (`level: 'core' \| '2.0' \| '2.1' \| '2.2'`, `capabilities` —`purgeRole` es par de capacidad solo en `'2.2'` (3B · B4: `true` juzga la purga total, `false` el 500 sin tocar nada); los casos `'2.2'` de roles locales usan `localRole`/`linkByHand` (escrituras a mano en `authz_*` con la versión subida) y, bajo `listDenies: true`, `defineScopedRole` por `managerOver({ delegablePermissions })`; `listDenies` es par de capacidad solo en `'2.1'`+ (2E · I5): `true` juzga lo que resta denies y F1, `false` juzga que lo digan con 500 `E_AUTHZ_UNSUPPORTED`; `injectableClock` es par en TODOS los niveles (2.5 · J1): `true` ⇒ tres estados con reloj (core) + caducidad exacta T−1/T/T+1, milisegundos, 2040 (escribiendo con el reloj en 2040, K5) y `config.clock` (2.1), `false` ⇒ tres estados en tiempo real (1,5 s)—, árbol del harness (`makeTree?`: `memoryScopeTree` por defecto; `sqlScopeTree` en el harness de los motores), `makeTwin?` = otra instancia sobre el mismo backend con otro memo del catálogo; default `twinOf`). Los casos `'2.1'` construyen un `AuthorizationManager` sobre el driver del harness (`managerOver`); el espía Proxy usa `receiver` para ver la vista de `withChainResolver`. Casos de motor (2.5 · J3/K1: ids no UUID y MAYÚSCULAS ⇒ 422; alias del uuid jamás evade un deny) y de concurrencia (2.5 · J4: dos grants, purga vs grant —afirma sobre el `GrantOutcome`, K4—, sync vs authorize). Instantes relativos a hoy donde se observa el driver sin reloj (K7). Se publica en `./testing` para drivers de terceros. `scope_tree.ts`: `ContractScopeTree` (`chainOf` = cadena canónica; `descendantsOf?`), `memoryScopeTree`/`resolveChainFrom`/`descendantsFrom`. |
| `src/models/*` | Modelos Lucid `authz_assignment/deny/permission/role/role_permission`. |
| `src/traits/*` | `has_uuid`, `authz_scopes` (`withAuthzScopes` como mixin o `withAuthzScopes({ clock })` —K6—; PK casteada a texto en PG —K3—; codec de caducidad —K2—). |
| `commands/` | `authz:catalog:sync` (`--keep-links`; avisa de `shadowedByGlobal`/`assignableAtViolations`, 3E), `authz:catalog:diff` (exit 1 si hay deriva; `--fail-on-shadows` cuenta además los ensombrecidos, 3G · X3), `openfga:provision`, `openfga:import` (`--dry-run`, `--reconcile`, `--prune`). Los `openfga:*` importan de `src/openfga.ts`. |
| `providers/`, `services/main.ts`, `configure.ts`, `stubs/` | Wiring Adonis: provider, singleton, `node ace configure`, plantillas publicadas (`config/authorization` cablea `scopes.resolveChain` —cadena canónica— y la misma función a ambos drivers; `config/app_acl`; migración con las cinco tablas `authz_*` + `authz_catalog_version` sembrada). Decisiones de motor en la migración (2.5 · J3, observadas en PG/MySQL): `holder_uuid`/`scope_uuid` `varchar(64)` (PG `uuid` rechazaba ids válidos), `collate 'utf8mb4_bin'` en identidad (también `authz_roles.scope_type`, ⚪4) y slugs (MySQL `*_ci` fundía `abc`/`ABC`), `expires_at` `DATETIME(3)` (MySQL `TIMESTAMP(0)` redondea al segundo y muere en 2038). El espejo es `tests/helpers/schema.ts`; `migration_stub.spec` EJECUTA el stub en una base de trabajo y compara tipo/longitud/precisión/collation con el espejo (K11). La receta 1.x→2.x del README se ejecuta en `upgrade_recipe.spec` (K14). |
| `scripts/` | `check_purity.mjs` (reglas 1, 2 y 3 —la ruta database no importa openfga—, con stripper de comentarios), `openfga_prune_stores.mjs` (borra stores huérfanos, solo con `--force` y prefijo), `bench_authorize.mjs` (latencia de `authorize` contra `:8101`; `node --import @poppinss/ts-exec`; K8: `database` sqlite p50 0,35/0,24 ms, `openfga` p50 2,48/0,06 ms). |
| `tests/` | `helpers/app.ts` (**harness multi-motor**, 2.5 · J2: `TEST_DB=sqlite\|sqlite-file\|pg\|mysql`; PG/MySQL crean `authz_test_<8 hex>` desde una conexión administrativa y la borran en `teardown()` —también el proceso hijo de `load_without_sdk`, vigilado por `harness_cleanup.spec` (K13)—; `sqlite-file` = fichero en `mkdtemp` con pool 2..5 y WAL (`pool_concurrency.spec`, K16); MySQL con `timezone: 'Z'`; `bootApp({ reuse })` para hijos sobre la misma base y `openScratchDatabase()` para otra base vacía del motor), `helpers/sql_scope_tree.ts` (árbol del juez en `demo_scopes`, K1), `helpers/schema.ts` (espejo —con las acciones de FK alineadas al stub desde 3D · M6— + `describeAuthzSchema` + `describeAuthzForeignKeys` + `runMigrationSource`), `helpers/expiry_child.ts`/`upgrade_child.ts` (procesos hijos de K2/K14), `fixtures/migration-1.1.0.stub`, `clock` (grep: solo `src/clock.ts` lee la hora), `contract.spec.ts` (database siempre —y «database (sin listDenies)», la cara `listDenies: false` del juez—; en PG/MySQL además «database (árbol SQL)»; openfga —y «openfga (árbol SQL)»— si `OPENFGA_TEST_URL`; `injectableClock: true` en todos), `contract_harness` (conteo de casos del juez, hoy 36 core / 49 en 2.0 / 66 en 2.1 / **75 en 2.2** con `listDenies: true`, `purgeRole: false` e `injectableClock: false` (79 con el reloj; 70 sin `listDenies`; **con `purgeRole: true`, ocho más: 83** — desde 3E · P4 la API de DELEGACIÓN entera cuelga de esa capacidad, no solo la purga, y desde 3G · W4 los cuatro casos de COMPOSICIÓN): tocarlo al añadir casos. Par nuevo en 3E · R2: `serializedCatalogWrites` (PG/MySQL `true` ⇒ la carrera de dos `define` exige exactamente un ganador y 422 para el perdedor; SQLite `false` ⇒ la forma laxa). **Aviso 3D · N6 / 3E · R6**: la regla de owner en `authorize` Y la regla de ambigüedad de `RoleQuery` cuelgan cada una de UN solo caso por harness (los demás casos `'2.2'` van por rutas de lectura que filtran en otro punto), así que un refactor del SQL/checks —o un driver de terceros con su propio `roleVisible`— puede pasar la suite entera con la regla rota), `expiry_timezone` (K2/K17: hijos en UTC/Tokio/Caracas sobre la misma base, PG/MySQL), `authz_scopes_trait` (K3/K6), `upgrade_recipe` (K14, PG/MySQL), `manager` (incluye el grupo «lote 2B»: actor, aviso opt-in, composición de `authorizeMany`/`effectivePermissions`/`authorizedScopes` con drivers falsos; los de 2D: F5, F8, F9 —con reloj inyectado y `Date.now` hacia atrás, 2E · H3/I2—, F10, espía que sobrevive a `withChainResolver`; H1 en `manager.scopes`; «catálogo» con B5/B6 —`assignableAt`, sync solo globales, diff—; y «roles locales a un scope (3B · B3)»: la policy completa de la delegación, C2, C3, colisiones, globales inmutables, hook, driver sin `purgeRole`), `middleware`, `database_driver`, `openfga_driver` (unitarios sin servidor; `authorizeMany` en un batchCheck con dedupe), `spies` (coste por operación: catálogo una vez + 1 revalidación por pregunta, 1 batchCheck, `forRequest`, `authorizeMany`, `effectivePermissions` ≤ 2 lecturas), `catalog_cache` (contrato del memo y de la versión compartida: `withAuthzCatalogWrite`, bump sin trx ⇒ 500, fila ausente ⇒ 503, reloj monótono, `catalog`+`catalogRevalidate` ⇒ 500), `memoize_ancestors`, `hierarchical_resolver` (B4, F6), `sql_descendants` (B2, G1, sobre `demo_scopes` de `helpers/schema.ts`; ciclo con cota > 1000 —MySQL—), `purity` (reglas 1–3 + carga de `index.ts` con el SDK bloqueado, `helpers/load_without_sdk.ts`), `prune_stores`, `configure` (los stubs compilan, con el subpath mapeado), `migration_stub` (seis tablas + semilla + decisiones J3/⚪4 en el texto del stub; K11: el stub ejecutado en una base de trabajo = el espejo, columna a columna **y acción de FK a acción de FK** —3D · M6—; 3B · B1: `owner_scope_key`/`assignable_at`, el `DEFAULT 'global'` del motor y el unique de tres columnas observados), `scope_tree`, `harness_cleanup`, `pool_concurrency`. |

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
  **3** `catalog/` roles por scope (**3A** ✅ identidad por uuid: binding id FGA `role_binding:<scopeKey>|<roleUuid>` parseado desde la derecha, sin `~`, 2.2 no lee ids 1.x —sin comando de migración—; `database` por uuid; `CatalogView.roleByUuid`/`rolesFor`; informe `fase-3-lote-a-informe.md`; **3B** ✅ roles locales: `owner_scope_key` + `assignable_at` (B1), visibilidad por owner por nivel en ambos drivers (B2), `defineScopedRole/updateScopedRole/deleteScopedRole` con policy y `onCatalogWrite` (B3), `purgeRole` en el puerto + par de capacidad (B4), `assignableAt` como composición —en el PERMISO, desviación documentada— (B5), sync solo globales (B6), memo con owner y canal de versión (B7); juez `'2.2'`; invariante 18; informe `fase-3-lote-b-informe.md`; **3C** cierre: **3D** ✅ correcciones del auditor NO APTA + tester —M1 identidad del rol por uuid en el puerto y ambigüedad ⇒ 422 `E_AUTHZ_AMBIGUOUS_ROLE`; M2 unicidad serializada (cerrojo de la fila de versión) + re-chequeo en transacción + `ambiguousRoles` en el diff; M3 `within` en las nueve escrituras; M4 `scopes.detached` purga los roles de ese owner; M5 parche del tester; M6 FKs stub↔espejo y K11 con `delete_rule`; N1–N7—; informe `fase-3-lote-d-informe.md`; **3E** ✅ cierre final —P1 nivel del rol ≤ owner (`E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER`) y el sync deja de abortar por un local (los globales ganan, `shadowedByGlobal`); P2 `scopes.detached` canónico, leyendo la base y bajando por `descendantsOf`; P3 policy de rank en `detached`; P4 `defineScopedRole` exige `purgeRole` ANTES de escribir (openfga ya no lo trae) y el caso `whenFalse` del juez deja de fijar el callejón; P5 diff tolerante con la fila corrupta; P6 revalidación de `assignableAt` con reporte; Q1–Q8; y del tester R1–R7 —parche del owner por `{uuid}`, par `serializedCatalogWrites`, `effectivePermissions` sin `rolesInChain`, evento con el rol resuelto, carrera sync×define, notas de fragilidad, conteo de vínculos en `purgeRole`—; informe `fase-3-lote-e-informe.md`; **3F** ✅ cierre del cierre —S1 `scopes.detached` de un scope ya borrado purga igual saltándose el rango y lo dice (`ScopeDetachOutcome`, `reason`); S2 el subárbol que no se puede enumerar DEGRADA (`truncated`, regla de nivel mínima) en vez de tumbar la operación; S3 colisión por AUTORIDAD (global > local de un ancestro > local de un descendiente), `shadowedByAncestor`, y el diff deja de contar como deriva lo ensombrecido; S4 la frase del ensombrecimiento corregida y fijada con un caso; T1–T5; y del tester 3E U1–U5 —parche Q1/Q2/P3, corrección honesta de R7 (el `CASCADE` es el garante), rama no juzgable determinista, las dos mitades de Q7 y orden estable de `readRolesOwnedBy`—; informe `fase-3-lote-f-informe.md`; **3G** ✅ cierre de la Fase 3 —W1 el rango de `scopes.detached` se mide por rol en la cadena del owner de cada uno (🟠 auditor P1: `detached` de un ancestro desconocido destruía roles de descendientes vivos); W2 `truncated: true` y `reason` cuando el scope no resuelve y nada se enumera por debajo, con el contrato de `descendantsOf` escrito en el puerto; W3 ensombrecer exige rango; W4 cuatro casos de COMPOSICIÓN en el juez (la causa de las tres regresiones seguidas); X1–X6 —degradación documentada, policy de rango con `below = []`, `--fail-on-shadows` + `classifyHomonyms` sin punto ciego, `CLAUDE.md` coherente, el 422 de rango sin fuga de catálogo ajeno, CHANGELOG/README—; y del tester 3F Y1–Y3 —la carrera ancestro↔descendiente tiene dos finales legales (aserción flaky en el artefacto publicado), el caso de S1 con dos roles y un actor sin rango, el mensaje de `AMBIGUOUS_ROLE`—; informe `fase-3-lote-g-informe.md`; pendiente el commit del dueño) → **3b** `facts` + `reconcile` → **4** `relations/` → **5** consolidación.
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
