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
   vía `resolveAncestors`.
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
9. **Scope desconocido = no existe.** `resolveAncestors` ⇒ `null` deniega (`authorize`/`hasRole`),
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
  no-op salvo `purgeScope`). `resolveAncestors` sigue existiendo para validar escrituras y
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
| `src/types.ts` | El contrato (`AuthorizationDriver`, `SubjectRef`, `ScopeRef`, catálogo). Empieza aquí. |
| `src/manager.ts` | Fachada; resuelve driver del config, dispara `onWrite`. `forRequest()` ⇒ `AuthorizationView` (mismo API; lecturas con ancestros memoizados, escrituras en fresco — 2A). Primitivas 2B como composición: `isWithin`/`within`/`requireWithin`, `actor`/`requireActor` (`WriteOptions`), `authorizeMany` (delega o compone), `listDenies`, `effectivePermissions`, `authorizedScopes` (`none|some|all{excludedSubtrees}`, `descendantsOf` del config, cotas que lanzan). Aviso de seguridad opt-in una vez por config. |
| `src/drivers/database_driver.ts` | Driver SQL propio sobre `authz_*`. |
| `src/openfga.ts` | Entrada del subpath `@jantstack/adonis-authz/openfga`: lo ÚNICO que exporta el driver openfga y sus herramientas (peer opcional `@openfga/sdk`). |
| `src/drivers/openfga_driver.ts` | Driver Zanzibar; modelo FGA generado desde `holderTypes`. Lecturas de membresía filtradas por catálogo; `Read` paginado y acotado; importador con `reconcile`/`prune`. |
| `src/define_config.ts` | `defineConfig`/`AuthorizationConfig`: `default`, `drivers`, `holderTypes`, `scopes.resolveAncestors` (la costura del árbol hacia arriba) + `scopes.descendantsOf?`/`maxScopes`/`maxDescendants` (2.1, hacia abajo, solo `authorizedScopes`), `requireWithin`/`requireActor`/`warnOnOptInSecurity` (2.1), `catalogs`, `hooks.onWrite`. |
| `src/identity.ts` | `assertIdentity`/`assertScope`/`assertValidSlug`/`assertExpiresAt`/`assertNoSlugCollisions`/`normalizeRoleQuery`: gramática de holders, scopes (tipos en minúsculas; holder_type 50, scope_type 20, uuid 36), slugs (minúsculas, **42** = `MAX_SLUG_LENGTH`) y `expiresAt` (422). La aplica el manager y, por defensa en profundidad, cada driver. |
| `src/expiry.ts` | Los tres estados de `expiresAt` (`resolveGrantExpiry`, `sameInstant`, `toExpiryDate`, `expiryChanged`). |
| `src/drivers/backend_guard.ts` | Clasificación de fallos compartida: `guardSql` (503 + deadline; también lo usa el catálogo), `withDeadline`, `resolveChain`/`assertKnownScope` (árbol: `null` ⇒ desconocido; lanza o responde un ancestro inválido ⇒ 503), `rootOnlyResolver` (sin resolutor solo existe `app`). |
| `src/catalog.ts` | `syncAuthzCatalog` (prune de vínculos por defecto; colisiones también contra la BD; 503 con la BD caída; invalida el memo al terminar), `diffAuthzCatalog`/`runCatalogDiff`/`syncCatalogs` (catálogos disjuntos o 422 `E_AUTHZ_CATALOG_CONFLICT`). |
| `src/catalog_cache.ts` | **Memo del catálogo** (2A): `CatalogCache` (carga perezosa de `authz_*`, 3 consultas con deadline; nunca hechos ni decisiones), `invalidateAuthzCatalog()` (contador de versión del proceso; lo sube el sync), `ttlMs` opcional (multi-proceso). Ambos drivers lo usan (`catalog`/`catalogTtlMs`); `purgeScope` lee SQL en fresco. Caso negativo fijado: escribir `authz_*` por fuera no se ve hasta invalidar. |
| `src/memoize_ancestors.ts` | `memoizeAncestors(resolver)`: memo de una instancia sobre `ScopeAncestorsResolver` (sin reloj; `null` memoizado; un throw no). SOLO camino de lectura (auditor C3/E3). El puerto tiene `withAncestorsResolver?` opcional para que el manager lo aplique. |
| `src/hierarchical_resolver.ts` | `hierarchicalScopeResolver({ parentOf, maxDepth = 64 })` (2.1, B4): resolutor de ancestros desde un padre (`undefined` = desconocido ⇒ `null`; `null`/`app` = raíz); ciclo ⇒ 422 `E_AUTHZ_SCOPE_CYCLE`; profundidad ⇒ 500 `E_AUTHZ_SCOPE_TOO_DEEP` (nunca cadena corta); un throw se propaga. |
| `src/sql_descendants.ts` | `sqlDescendantsOf({ table, uuidColumn, parentColumn, typeColumn \| scopeType, maxNodes?, connection?, timeoutMs? })` (2.1, B2): `descendantsOf` opt-in con UNA CTE `WITH RECURSIVE` (PG y SQLite; otro dialecto ⇒ 500 `E_AUTHZ_UNSUPPORTED_DIALECT`); identificadores validados; `LIMIT maxNodes+1` + profundidad `maxNodes+1` (un ciclo termina y lanza); uuid repetido ⇒ 422 ciclo. |
| `src/errors.ts` | Todos con `status` + `code`: `AuthorizationBackendError` (503) y su subclase `…TimeoutError`; `ScopeResolverError` (503); `InvalidIdentityError`, `InvalidSlugError`, `UnknownScopeError`, `NoScopeResolverError`, `UnknownRoleError`, `UnknownPermissionError`, `CatalogConflictError`, `ScopeCycleError`, `NotWithinError`, `WithinRequiredError`, `ActorRequiredError`, `TooManyScopesError` (422); `StoreNotEmptyError` (409); `AuthorizationConfigError`, `AuthorizationInternalError`, `RoleIsNotAccessError`, `PurgeIncompleteError`, `UnsupportedOperationError` (`E_AUTHZ_UNSUPPORTED`), `NoDescendantsResolverError`, `UnsupportedDialectError`, `ScopeTooDeepError` (500). Tabla en el README. |
| `src/middleware/app_access_middleware.ts` | `appAccess({ permission })` a nivel `app`. Solo `permission`: `{ role }` ⇒ 500 con receta. |
| `src/testing/contract.ts` | **El juez**: `runAuthorizationDriverContract` (`level: 'core' \| '2.0' \| '2.1'`, `capabilities`, árbol del harness). Los casos `'2.1'` construyen un `AuthorizationManager` sobre el driver del harness (`managerOver`). Se publica en `./testing` para drivers de terceros. `scope_tree.ts`: `memoryScopeTree`/`resolveAncestorsFrom`/`descendantsFrom` (desde `edges()`). |
| `src/models/*` | Modelos Lucid `authz_assignment/deny/permission/role/role_permission`. |
| `src/traits/*` | `has_uuid`, `authz_scopes`. |
| `commands/` | `authz:catalog:sync` (`--keep-links`), `authz:catalog:diff` (exit 1 si hay deriva), `openfga:provision`, `openfga:import` (`--dry-run`, `--reconcile`, `--prune`). Los `openfga:*` importan de `src/openfga.ts`. |
| `providers/`, `services/main.ts`, `configure.ts`, `stubs/` | Wiring Adonis: provider, singleton, `node ace configure`, plantillas publicadas (`config/authorization` cablea `scopes.resolveAncestors` y la misma función a ambos drivers; `config/app_acl`; migración). |
| `scripts/` | `check_purity.mjs` (reglas 1, 2 y 3 —la ruta database no importa openfga—, con stripper de comentarios), `openfga_prune_stores.mjs` (borra stores huérfanos, solo con `--force` y prefijo), `bench_authorize.mjs` (latencia de `authorize` contra `:8101`; `node --import @poppinss/ts-exec`). |
| `tests/` | `contract.spec.ts` (database siempre; openfga si `OPENFGA_TEST_URL`), `contract_harness` (conteo de casos del juez, hoy 36 core / 49 en 2.0 / 57 en 2.1: tocarlo al añadir casos), `manager` (incluye el grupo «lote 2B»: actor, aviso opt-in, composición de `authorizeMany`/`effectivePermissions`/`authorizedScopes` con drivers falsos), `middleware`, `database_driver`, `openfga_driver` (unitarios sin servidor; `authorizeMany` en un batchCheck), `spies` (coste por operación: catálogo una vez, 1 batchCheck, `forRequest`, `authorizeMany`), `catalog_cache` (contrato del memo), `memoize_ancestors`, `hierarchical_resolver` (B4), `sql_descendants` (B2, sobre `demo_scopes` de `helpers/schema.ts`), `purity` (reglas 1–3 + carga de `index.ts` con el SDK bloqueado, `helpers/load_without_sdk.ts`), `prune_stores`, `configure` (los stubs compilan, con el subpath mapeado), `migration_stub`, `scope_tree`. |

## Comandos

```bash
npm test               # Japa; SQLite en memoria (pool 1/1), sin app anfitriona
npm run typecheck      # tsc sobre tsconfig.test.json
npm run build          # purity + typecheck + tsc + copia de stubs
OPENFGA_TEST_URL=http://localhost:8101 npm test   # además corre el contrato contra OpenFGA
```

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
  `fase-2-lote-b-informe.md`; pendiente **2C** cierre/README) →
  **3** `catalog/` roles por scope → **3b** `facts` + `reconcile` → **4** `relations/` → **5** consolidación.
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
