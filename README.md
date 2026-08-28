# @jantstack/adonis-authz

Driver-based **authorization engine for AdonisJS 7 + Lucid**: hierarchical scopes with downward-only inheritance, explicit denies that always win, expiring assignments and polymorphic holders — behind a single contract, so the backend is a config choice, not an architectural commitment.

Ships two drivers that pass **the same executable contract suite**, case for case:

- **`database`** (default) — self-contained, engine-agnostic SQL over its own `authz_*` tables. Zero extra infrastructure.
- **`openfga`** — facts live in an [OpenFGA](https://openfga.dev) server (Zanzibar model); the catalog and your scope hierarchy stay local, so switching drivers is a facts migration, not a rewrite.

```ts
import authorization from '@jantstack/adonis-authz/services/main'
import { APP_SCOPE } from '@jantstack/adonis-authz'

await authorization.grant({ type: 'users', uuid }, 'support', APP_SCOPE, {
  expiresAt: new Date(Date.now() + 30 * 86_400_000),
})

await authorization.authorize({ type: 'users', uuid }, 'audit:read', APP_SCOPE) // → boolean
```

> **2.0.0 is a breaking release.** No compatibility flags: what changed, and why, is in the [CHANGELOG](./CHANGELOG.md), ordered by risk.

## Install

```bash
npm i @jantstack/adonis-authz
node ace configure @jantstack/adonis-authz
node ace migration:run
node ace authz:catalog:sync
```

`configure` registers the provider, the commands and the `appAccess` middleware, defines the env variables, and **publishes into your project** what belongs to you: the migration for the `authz_*` tables and two config files (`config/authorization.ts` for drivers and the scope tree, `config/app_acl.ts` for your role catalog). The suite compiles both published configs against the package on every run, so they cannot drift from it.

For the OpenFGA driver, also install its SDK (optional peer): `npm i @openfga/sdk`. Everything that touches the SDK lives behind the **`@jantstack/adonis-authz/openfga` subpath** (`OpenFgaAuthorizationDriver`, `provisionOpenFgaStore`, `importAuthzFactsToOpenFga`, `openFgaAuthorizationModel`, `assertHolderTypes`); the main entry never imports it, so a database-only install boots without the SDK (the suite loads `index.ts` in a child process with `@openfga/sdk` blocked to prove it: *"index.ts (la entrada principal) carga con el SDK bloqueado"*). The published config imports the driver from that subpath *inside* the factory.

## Semantics (what every driver guarantees)

These are the eight invariants of the contract. Every one of them is a case in the suite that both drivers run (`src/testing/contract.ts`); the case titles are quoted so you can find them.

1. **Hierarchical scopes, inheritance only downward.** A grant on a scope authorizes on that scope and all its descendants — never on siblings or ancestors. The engine only reserves the root (`app`); every other level is yours, declared by the `resolveAncestors` resolver you inject, and the suite proves it on a real three-level tree (*"herencia de dos niveles"*, *"grant en una org vale en sus units, no en app ni en la org hermana"*, *"mover una unit fuera de la org… le quita el permiso, sin otra escritura"*).
2. **Explicit deny wins.** A deny anywhere in the scope chain blocks the permission even if a role grants it; removing the deny restores it; the order of writes does not matter (*"deny explícito gana sobre el rol"*, *"deny antes del grant también bloquea"*). A deny governs `authorize` only — **it does not affect `hasRole`**, which is a membership fact, not an access decision (*"un deny NO afecta a hasRole"*). That is why no middleware in this package accepts a role.
3. **Expiry is observable, without a scheduler.** An assignment past its `expiresAt` grants nothing — enforced in SQL by `database`, by an FGA *condition* in `openfga`, and filtered client-side in enumerations (*"asignación expirada no concede; expiración futura sí"*).
4. **Polymorphic holders.** `{ type: morphName, uuid }`. Two holders with the same uuid and a different type never cross (*"holder polimórfico"*). The `openfga` driver refuses a `holderTypes` map that would merge two morph names into one FGA type (*"holderTypes tiene que ser inyectivo"*).
5. **Deny by default, and three distinguishable outcomes.** No permission, unknown permission, no live assignment, unknown scope → `false`, never a throw. A malformed question (unknown role or permission in `grant`/`deny`/`revoke`/`removeDeny`, invalid identity, bad slug, a `RoleQuery` object where a slug is expected, an `expiresAt` that is not a valid `Date`/`null`, unknown scope on a write) → **422** with an `E_AUTHZ_*` code. A dependency that does not answer — the facts backend, the SQL catalog **in both drivers**, or your own resolver (throwing *or* answering a malformed ancestor) — → **503**, never a silent `false`; in `openfga` a per-check `error` inside a 200 `batchCheck` is a 503 too, in the deny phase and in the role phase (*"un resolutor de ancestros que lanza ⇒ 503"*, *"authorize con el catálogo inaccesible lanza AuthorizationBackendError"*, *"authorize: error en un check de rol ⇒ 503"*).
6. **Idempotent writes.** Re-grant does not duplicate; `expiresAt` has three states (below); re-revoke / re-deny / re-removeDeny are safe no-ops, and a repeated deny needs one `removeDeny` (*"grant duplicado es idempotente"*, *"deny repetido no se duplica"*).
7. **`list*` return direct facts, complete, from the catalog's point of view.** `listSubjects`, `listRoles`, `listRoleScopes`, `listScopes` return *direct*, live assignments of the exact scope — never inherited descendants (that set would be open-ended; ask `authorize` about a concrete scope) — and they return **all of them**: 1,200 direct assignments come back whole in both drivers, and a `listScopes` subtracts a deny even when the holder carries 150 denies of other permissions (more than one `Read` page, more than an OpenFGA server's `ListObjects` cap) (*"listas exhaustivas: 1.200 asignaciones directas"*, *"listScopes resta el deny aunque el sujeto tenga más denies de OTROS permisos que el tope del backend"*). CI runs the judge against a second OpenFGA whose cap is 3. Membership is what the **catalog** says it is: a role removed from `authz_roles` is no longer a membership in either driver, even if `openfga` still holds its tuple (*"rol borrado del catálogo: la tupla sigue en el store pero authorize deniega"*), and a scope the tree no longer knows lists nothing (*"listRoles y listRoleScopes tampoco responden por un scope que el árbol no conoce"*).
8. **`rank` is metadata.** The engine stores it and never evaluates it (*"rank es metadata"*). "Nobody grants a role at or above their own rank" is your assignment policy.

## Your domain stays yours

Nothing about your model is hardcoded. Five seams, all in `config/authorization.ts`:

```ts
export default defineConfig({
  default: env.get('AUTHZ_DRIVER', 'database'),

  // 1. Your guards → FGA types (only the openfga driver uses this; must be injective)
  holderTypes: { users: 'user', admins: 'admin', integrations: 'integration' },

  // 2. Your scope tree — THE seam. Same function for the manager and every driver.
  scopes: { resolveAncestors: resolveScopeAncestors },

  drivers: {
    database: () => new DatabaseAuthorizationDriver({ resolveAncestors: resolveScopeAncestors }),
    openfga: () => new OpenFgaAuthorizationDriver({ apiUrl, storeId, holderTypes, resolveAncestors: resolveScopeAncestors }),
  },

  // 3. Your catalogs (one per module), for authz:catalog:sync / diff
  catalogs: [async () => appAclCatalog()],

  // 4. Your side-effects on every write (audit, events, notifications)
  hooks: { onWrite: (event) => audit(event) },
})
```

### The scope tree

`resolveAncestors(scope)` returns the ancestors of a scope from nearest to root, or **`null` when the scope does not exist**. `null` is a first-class answer: reads deny (`authorize`/`hasRole` → `false`), writes refuse (`grant`/`deny` → 422 `E_AUTHZ_UNKNOWN_SCOPE`), `revoke`/`removeDeny` stay no-ops, and `listScopes` omits it (*"scope que el árbol no conoce"*, *"un scope retirado del árbol deja de responder"*). Never answer `[APP_SCOPE]` for what you do not know: it would make any invented scope a descendant of the root.

There is no default resolver. A driver built without one only knows `app`; asking about any other scope type is 422 `E_AUTHZ_NO_SCOPE_RESOLVER` on the first call (*"sin resolutor de ancestros, cualquier scope que no sea app es 422"*).

The tree is a **contract fact**: when it changes, tell the engine — in every driver:

```ts
await authorization.scopes.attached(unit, org)      // new node under a parent
await authorization.scopes.moved(unit, otherOrg)    // re-parented
await authorization.scopes.detached(unit)           // BEFORE you delete the row
```

The package validates before touching the driver — `child` cannot be `app` (422), the parent must exist (422 `E_AUTHZ_UNKNOWN_SCOPE`), and `child` cannot be an ancestor of the new parent (422 **`E_AUTHZ_SCOPE_CYCLE`**); on failure the driver is not called at all (*"un ciclo es 422 E_AUTHZ_SCOPE_CYCLE en el paquete, sin llamar al driver"*). `detached` runs **`purgeScope`** — every assignment and deny of that exact scope **whose role or permission is in the catalog** is deleted and the driver proves that set is zero or throws 500 `E_AUTHZ_PURGE_INCOMPLETE` — then notifies `onWrite` with `action: 'scope_purged'`. Nothing resurrects when the same uuid is attached again, and siblings keep their facts (*"detach purga los hechos del scope: nada resucita"*, *"detach es quirúrgico"*). Facts of roles you already removed from the catalog are outside that promise: they grant nothing and are not memberships (the reads filter by the catalog), and `authz:reconcile` (3b) collects them. `purgeScope` covers the exact scope only; until `descendantsOf` exists (2.1) you purge each node of the subtree you delete. `scopes.*` require `config.scopes.resolveAncestors` (500 `E_AUTHZ_CONFIG` otherwise).

Your resolver's *answer* is validated too: an ancestor that is not a well-formed `ScopeRef` (or a non-array) is a 503 `E_AUTHZ_RESOLVER_FAILED` — the question was fine, the dependency was not (*"un ancestro inválido devuelto por el resolutor es 503 E_AUTHZ_RESOLVER_FAILED, no un 422"*).

`ScopeType` is an open `string`, so define your own union for type safety. The engine never queries your tables.

### Identity is validated, once and everywhere

`SubjectRef.type`/`uuid`, `ScopeRef.type`/`uuid`, role and permission slugs and `expiresAt` are checked by the manager on every call and again by each driver (the contract suite and third-party drivers bypass the manager). Letters, digits, `.`, `_`, `-`; **types are lowercase** (a `*_ci` MySQL collation would merge `Users` and `users` into one row while FGA keeps them apart); permissions may carry one `:` (`resource:action`); slugs are lowercase and at most **42** characters; `parent`, `binding`, `ancestor`, `role`, `assignee`, `denied` and the prefixes `can_`, `denied_`, `permits_` are reserved; `{ type: 'app', uuid: X }` and the root sentinel uuid outside `app` are rejected — even when your tree knows that sentinel (*"uuid centinela en un scope que el árbol SÍ conoce ⇒ 422"*); `grant`, `revoke` and `listSubjects` take a slug, and a `{ slug, scopeType }` object there is 422 (*"un RoleQuery objeto donde el contrato pide un slug ⇒ 422"*); `expiresAt` is `undefined`, `null` or a valid `Date` (*"expiresAt que no es Date válida, null ni omitido ⇒ 422"*). Violations are **422** (`E_AUTHZ_INVALID_IDENTITY`, `E_AUTHZ_INVALID_SLUG`) before any catalog, tree or backend call — zero queries, spied (*"identidad inválida ⇒ 422"*, *"slug mal formado o reservado ⇒ 422"*, *"una identidad inválida se rechaza con 0 llamadas al backend"*). `assertIdentity`, `assertValidSlug` and `assertExpiresAt` are exported so you can validate at your own edge with the same rule.

## Writes

```ts
const outcome = await authorization.grant(subject, 'editor', scope, { expiresAt })
// outcome: { existed: boolean, previousExpiresAt?: Date | null, expiresAt: Date | null }
```

`expiresAt` has **three states**:

| `expiresAt` | Meaning |
|---|---|
| omitted | do not touch a *live* expiry (an already-expired assignment revives without expiry) |
| `null` | remove the expiry |
| `Date` | set it |

A seeder or an onboarding that calls `grant` "to make sure they have the role" no longer turns a temporary access into a permanent one (*"expiresAt en tres estados"*, verified with a real expiry that elapses inside the case). When a re-grant changes the expiry of an existing assignment, `onWrite` receives `action: 'extended'` with `previousExpiresAt`; a no-change re-grant stays `granted` (*"cambiar la caducidad de una asignación existente notifica 'extended' con la anterior"*).

`onWrite` actions: `granted`, `extended`, `revoked`, `denied`, `deny_removed`, `scope_purged` (no `subject`). It runs *after* the write succeeded, so a hook that throws is logged and swallowed: propagating it would report a failure for an operation that did happen (*"un hook que lanza NO tumba la escritura"*).

One exception, on purpose: when a write **times out** (503 `E_AUTHZ_BACKEND_TIMEOUT`) the outcome is *unknown* — the request may still land on the backend after you received the error. Before propagating, the manager notifies the same event with **`indeterminate: true`**, so your audit records "may have happened" instead of nothing (*"una escritura que vence el deadline notifica onWrite con indeterminate: true ANTES de propagar el 503"*). A 503 that is not a timeout (connection refused) means the write did not happen and emits nothing. The `openfga` driver also stops the SDK from retrying on its own (`retryParams.maxRetry: 0` by default): a background retry after your 503 is exactly the phantom write this is about; enabling retries is opting into it. If you retry a timed-out write yourself, remember it is idempotent.

`grant` always returns a `GrantOutcome`; a third-party driver that still returns `void` is normalized to `{ existed: false, expiresAt: options?.expiresAt ?? null }` (*"un driver de terceros cuyo grant no devuelve GrantOutcome sigue notificando granted"*). `revoke`/`removeDeny` require the role/permission to exist in the catalog for that level (422, like `grant`/`deny`); the safe no-op is for a *missing assignment* of a valid role (*"revoke/removeDeny con rol o permiso fuera del catálogo ⇒ 422"*, *"revoke/removeDeny inexistentes son no-ops seguros"*).

## Queries

```ts
await authorization.authorize(subject, 'docs:write', scope)          // the decision
await authorization.hasRole(subject, 'owner', scope)                 // membership, inherits downward
await authorization.hasRole(subject, { slug: 'owner', scopeType: 'organization' }, scope)
await authorization.listRoles(subject, scope)                        // direct roles in that exact scope
await authorization.listRoleScopes(subject, 'organization')          // scopes of that type with a direct role
await authorization.listScopes(subject, 'docs:write')                // direct scopes granting it, minus denied
await authorization.listSubjects('editor', scope)                    // live holders in that exact scope
```

`hasRole` with a string matches, at every level of the chain, only the role *of that level*: an app `owner` inherits downward, an organization `owner` never matches at `app`. The object form `{ slug, scopeType }` restricts the question to chain levels of that type (*"hasRole con el mismo slug en dos niveles"*).

## Enforcing in routes

```ts
router
  .get('/admin/audit-log', [AuditLogsController, 'index'])
  .use(middleware.appAccess({ permission: 'audit:read' }))
```

The middleware resolves the authenticated holder from its morph name and asks `authorize` at the **`app` scope**. It accepts **`{ permission }` only**: `appAccess({ role })` was removed in 2.0 — a gate over membership could not be denied — and passing `role` is a 500 `E_AUTHZ_ROLE_IS_NOT_ACCESS` with the recipe (create a permission, link it to the role, gate on the permission), thrown before authentication is checked (*"appAccess({ role }) es 500 E_AUTHZ_ROLE_IS_NOT_ACCESS con la receta"*). Per-organization or per-unit enforcement is your controller's or your own middleware's job: only your domain knows which scope a route belongs to. The holder must expose `uuid`; a numeric-PK model is rejected with an explicit error.

## The catalog

Roles and permissions are config-driven:

```ts
// config/app_acl.ts
permissions: [{ slug: 'audit:read' }, { slug: 'admin:manage' }],
roles: [{ slug: 'superadmin', scopeType: 'app', rank: 100, permissions: '*' }],
```

```bash
node ace authz:catalog:sync            # sync every catalog in config.catalogs, in order
node ace authz:catalog:sync --keep-links   # 1.x additive mode
node ace authz:catalog:diff            # exit 1 on drift — run it in CI
```

`syncAuthzCatalog(spec, { prune: 'links' | 'none', timeoutMs })` is idempotent and transactional. The default **prunes**: for every role *of the spec*, role→permission links the spec no longer lists are deleted in the same transaction, so removing a permission from a role in config removes it from every environment on the next sync (*"quitar un permiso de un rol y re-sincronizar el catálogo lo retira: sin privilegios zombi"*, a contract case in both drivers). Roles and permissions are never deleted (they carry assignments), and roles outside the spec are untouched, so two catalogs — platform and tenant — coexist (*"dos catálogos coexisten"*). **A role `(slug, scopeType)` and a permission belong to exactly one catalog**: `authz:catalog:sync` and `authz:catalog:diff` resolve every catalog first and refuse, before writing anything, if two of them declare the same one (422 `E_AUTHZ_CATALOG_CONFLICT`) — otherwise the second sync would prune the first catalog's links in silence (*"un rol o un permiso declarado en dos catálogos es 422 E_AUTHZ_CATALOG_CONFLICT, sin escribir"*). A role granting a permission that exists in no catalog is 422 `E_AUTHZ_UNKNOWN_PERMISSION`; a permission from an earlier catalog in `config.catalogs` is fine, so order matters. The whole catalog is validated before anything is written: slug grammar, `scopeType` as a scope identity, and collisions after encoding (`docs:write` vs `docs_write`) — within the spec **and against the permissions already in the database** (*"la colisión tras codificar se comprueba también contra los permisos ya en la base"*). A database that does not answer during sync or diff is a 503 `E_AUTHZ_BACKEND_UNAVAILABLE`, not a raw driver error (*"el catálogo con la base caída es 503"*).

`authz:catalog:diff` lists missing permissions/roles/links, surplus links and rank mismatches (`diffAuthzCatalog` / `runCatalogDiff` are exported for your own checks).

## Errors

Every error the package raises carries `status` and `code`. A standard AdonisJS exception handler answers on its own; catch only when an endpoint needs a specific response.

| Code | Status | When |
|---|---|---|
| `E_AUTHZ_INVALID_IDENTITY` | 422 | malformed holder/scope, `{app, uuid}`, root sentinel outside `app` |
| `E_AUTHZ_INVALID_SLUG` | 422 | role/permission slug: grammar, length, reserved name or prefix, collision |
| `E_AUTHZ_UNKNOWN_ROLE` / `E_AUTHZ_UNKNOWN_PERMISSION` | 422 | not in the catalog (for that scope type), in `grant`/`deny`/`revoke`/`removeDeny` |
| `E_AUTHZ_CATALOG_CONFLICT` | 422 | two catalogs in `config.catalogs` declare the same role `(slug, scopeType)` or permission |
| `E_AUTHZ_UNKNOWN_SCOPE` | 422 | write on a scope the resolver does not know; unknown parent in `scopes.*` |
| `E_AUTHZ_NO_SCOPE_RESOLVER` | 422 | driver without `resolveAncestors` asked about a non-`app` scope |
| `E_AUTHZ_SCOPE_CYCLE` | 422 | `scopes.attached/moved` would close a cycle |
| `E_AUTHZ_BACKEND_UNAVAILABLE` | 503 | facts backend or SQL catalog did not answer (both drivers, catalog sync/diff included); a per-check `error` in an OpenFGA `batchCheck` |
| `E_AUTHZ_BACKEND_TIMEOUT` | 503 | `timeoutMs` elapsed (subclass of the above) |
| `E_AUTHZ_RESOLVER_FAILED` | 503 | your `resolveAncestors` threw, or answered a malformed ancestor |
| `E_AUTHZ_STORE_NOT_EMPTY` | 409 | `openfga:import` on a store with tuples, without `--reconcile` |
| `E_AUTHZ_CONFIG` | 500 | contradictory config (`holderTypes` not injective or a holder type not declared in it, `scopes.*` without resolver, `appAccess` without `permission`, `openfga:import --prune` without `--reconcile`) |
| `E_AUTHZ_ROLE_IS_NOT_ACCESS` | 500 | `appAccess({ role })` |
| `E_AUTHZ_INTERNAL` | 500 | package invariant violated (empty scope set on a write, misaligned batch, a `Read` continuation token that never advances or more than 10,000 pages) |
| `E_AUTHZ_PURGE_INCOMPLETE` | 500 | `purgeScope` could not prove zero |

## Driver options

Both drivers take `resolveAncestors` and **`timeoutMs`** (default 5000): every SQL query the driver builds is given a knex timeout — the `DELETE`s inside `purgeScope`'s transaction included; only knex's own `BEGIN`/`COMMIT` carry none — every FGA call has a total deadline, and an elapsed deadline is 503 `E_AUTHZ_BACKEND_TIMEOUT`. A server that accepts the connection and never answers is released in under a second (*"authorize contra un servidor mudo ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT en menos de 1 s"*). SQLite's synchronous driver cannot actually time out; what the suite pins there is that every query carries the deadline (*"toda consulta sale con el timeout configurado"*). A deadline releases the caller, it does not abort the request in flight: see `indeterminate` above.

Both also take **`catalogTtlMs`** and **`catalog`** (a `CatalogCache` to share between drivers of the same process) — the catalog memo described under [Performance](#performance).

`openfga` additionally takes `holderTypes` (required, injective; a holder whose morph name is not in it is 500 `E_AUTHZ_CONFIG`), `modelId`, a `logger` (default `console`), **`retryParams`** (default `{ maxRetry: 0 }`, see `indeterminate` above) and **`consistency`**: `'higher_consistency'` (default) or `'minimize_latency'`. The default protects the "removing the deny restores" promise against a server started with `--check-query-cache-enabled`, where a fresh revoke or deny would keep granting for up to the cache TTL; `minimize_latency` is the explicit opt-out (*"todo check lleva context.current_time; toda llamada HIGHER_CONSISTENCY"*). `driver.diagnostics.unparseableBindings` counts store tuples the engine cannot interpret — binding ids it does not understand and malformed tuples alike; each one is logged, never skipped in silence.

## Performance

Two optimisations landed in 2.1, both measured and both **without changing a single answer** (the contract suite is the proof: same cases, both drivers, before and after). Reproduce the numbers with `OPENFGA_TEST_URL=http://localhost:8101 node --import @poppinss/ts-exec scripts/bench_authorize.mjs` (chain of 3 scopes through your resolver, 5 roles per level, 20 permissions, N=200 after 30 warm-up calls, HTTP round-trip included; OpenFGA v1.19.0 on the same machine):

| `authorize` (`openfga`) | before 2.1 | 2.1 | backend calls per question |
|---|---|---|---|
| granted by a root role (worst case: the whole chain) | p50 **4.33 ms** · p95 7.33 ms | p50 **2.03 ms** · p95 3.83 ms | 2 SQL + 2 `batchCheck` → **0 SQL + 1 `batchCheck`** |
| granted by nobody | p50 2.36 ms · p95 3.48 ms | p50 0.01 ms | 2 SQL + 1 `batchCheck` → **0 SQL + 0** |

(`database` on in-memory SQLite: 0.37 → 0.27 ms p50, one catalog query less per question.)

**The catalog is memoised; facts and decisions never are.** Each driver loads `authz_permissions`, `authz_roles` and `authz_role_permissions` once, lazily, into an in-process `CatalogCache` (three queries, all with the driver's deadline; a load that fails is a 503 and caches nothing). Every question still reads its facts — assignments, denies, tuples — from the backend: a `grant`, `deny` or `revoke` is visible in the very next call (*"el memo nunca cachea hechos ni decisiones"*). What the memo answers is "which uuid is `docs:read`", "which roles of which level grant it", "which roles exist at this level". Its invalidation contract:

- **`syncAuthzCatalog` / `node ace authz:catalog:sync` invalidate it** in the process that ran the sync, on success and on failure alike (*"syncAuthzCatalog invalida el memo"*).
- **Writing `authz_*` by hand does not.** A seeder, a data migration or a script that inserts into those tables must call **`invalidateAuthzCatalog()`** (exported from the package; invalidates every memo of the process) or `driver.catalog.invalidate()` (that driver only). Until then the previous answer stands — pinned as a negative case (*"un cambio en authz_* por fuera del sync NO se ve hasta invalidateAuthzCatalog()"*).
- **Multiple processes:** the version counter lives in memory, so a sync in one worker does not reach the others. Either restart the workers after `authz:catalog:sync` (the usual deploy) or set **`catalogTtlMs`** on the driver (default: no TTL) and accept a window of that length with the previous catalog (*"con catalogTtlMs el memo caduca solo"*).
- Two drivers in one process can share one memo: `new DatabaseAuthorizationDriver({ catalog })` and `new OpenFgaAuthorizationDriver({ catalog })` with the same `new CatalogCache({ ttlMs, timeoutMs })`.

**One `batchCheck` per `authorize` in `openfga`.** The denies of the chain and the roles that grant the permission travel in the same request (the SDK splits at 50 checks and parallelises); the rule is unchanged and evaluated in this order: any per-check `error` ⇒ 503, any deny `allowed` ⇒ `false`, any role `allowed` ⇒ `true`. When no role of the catalog grants the permission anywhere in the chain, the answer is `false` without a request — the denies cannot change it.

**A per-request view memoises the scope tree, on reads only.** `authorization.forRequest()` returns an `AuthorizationView`: same API as the manager, sharing its driver and hooks, whose reads (`authorize`, `hasRole`, `list*`) resolve ancestors through `memoizeAncestors(config.scopes.resolveAncestors)` — one call to your resolver per scope for the life of the view — while its writes (`grant`, `revoke`, `deny`, `removeDeny`, `scopes.*`) resolve fresh: a stale read expires by itself, a grant on a chain that moved is written forever. The memo holds ancestors, never decisions: a deny written between two `authorize` of the same view changes the second answer (*"forRequest(): las lecturas de una vista resuelven cada scope una vez; las escrituras, en fresco"*). No `AsyncLocalStorage`: the view is an explicit object with the lifetime you give it. The pattern in AdonisJS is a middleware:

```ts
// app/middleware/authz_middleware.ts
import authorization from '@jantstack/adonis-authz/services/main'

export default class AuthzMiddleware {
  async handle(ctx: HttpContext, next: NextFn) {
    ctx.authz = authorization.forRequest()   // declare `authz` on HttpContext in your types
    return next()
  }
}

// a controller or a policy
if (!(await ctx.authz.authorize(user, 'docs:write', unit))) return ctx.response.forbidden()
```

`memoizeAncestors(resolver)` is exported for the cases where you hold a driver directly; keep it on the read path. Without `scopes.resolveAncestors` in the config, or with a third-party driver that does not implement the optional `withAncestorsResolver`, the view reads through the driver as-is — correct, just not memoised.

## Custom drivers, judged by the same suite

Implement `AuthorizationDriver`, register its factory, and prove it:

```ts
import { runAuthorizationDriverContract, resolveAncestorsFrom } from '@jantstack/adonis-authz/testing'

runAuthorizationDriverContract({
  name: 'my-driver',
  level: '2.0',                         // omit for the 1.x cases only
  capabilities: {                       // what the driver declares; each one has its own cases
    hierarchyFacts: false,
    transactions: false,
    truncationSignal: false,
    singleCheckAuthorize: false,
    injectableClock: false,
    exhaustiveLists: true,              // false ⇒ also pass `limits: { listMaxResults }`
  },
  // The suite builds the scope tree case by case; hand it to your driver.
  makeDriver: (tree) => new MyDriver({ resolveAncestors: resolveAncestorsFrom(tree) }),
  seedCatalog: (catalog) => syncAuthzCatalog(catalog),
  cleanup: () => wipeEverything(),
})
```

Declaring a capability `true` that the suite has no case for makes registration throw — a promise without a judge does not pass. The port also has optional methods a driver may implement to do better than the manager's composition — `onScopeAttached/Moved/Detached` (tree as facts) and, since 2.1, `withAncestorsResolver(resolver)` (a view of the driver bound to another resolver, what `forRequest()` uses to memoise reads); a driver without them keeps passing the same suite. `exhaustiveLists: false` asks for the backend's cap and proves only the exact boundary.

What passing means: **for everything the suite covers, both drivers answer the same** — including the malformed-input edges that used to diverge (`{app, uuid}`, a uuid with `#`), which are contract cases now. What is *not* identical between drivers is operational and listed below: latency, failure modes, the two-call expiry refresh in OpenFGA. Switching drivers is a facts migration (`openfga:import`), not a change at the call-sites the manager exposes.

The package runs that suite on itself: `npm test` judges the `database` driver over in-memory SQLite — no host application — and `OPENFGA_TEST_URL=… npm test` adds the `openfga` driver to the same verdict. CI runs it against two OpenFGA servers, one of them with `ListObjects`/`ListUsers` capped at 3.

## OpenFGA tooling

```bash
node ace openfga:provision                    # creates a store + writes the model from your holderTypes
node ace openfga:import --dry-run             # counts what would be copied from the authz_* tables
node ace openfga:import                       # empty store only
node ace openfga:import --reconcile           # non-empty store: compare tuple by tuple, rewrite what differs, count what SQL no longer has
node ace openfga:import --reconcile --prune   # ...and delete it: the run that converges
```

The import **copies**, it doesn't move: your `authz_*` tables stay intact, so rolling back is setting `AUTHZ_DRIVER=database` again. Already-expired assignments are skipped and counted. A store that already has tuples is refused (409 `E_AUTHZ_STORE_NOT_EMPTY`) unless `--reconcile`, which reads each fact, then reads the **whole store** (paginated `Read({})`) and reports `{ written, updated, unchanged, extra, deleted, skippedExpired }` — `extra` being the `role_binding`/`deny_binding` tuples SQL does not have (a grant revoked in SQL, a holder that never existed): they **keep granting until you pass `--prune`**, which deletes them and reports them as `deleted`; a report with `extra: 0` after `--prune` means the store equals SQL (*"reconcile converge: las tuplas que SQL no tiene se cuentan como extra y --prune las borra"*). Never `onDuplicateWrites: Ignore`, which left old expiries in place while reporting success (*"reconcile: la tupla permanente pasa a llevar la caducidad de SQL"*). `--prune` without `--reconcile` is 500 `E_AUTHZ_CONFIG`. This is the 2.0 tool; the bidirectional `authz:reconcile` (drivers as peers, catalog projection included) is phase 3b.

### Operational notes for this driver

Choosing it adds a **second runtime dependency to every authorization check**: the catalog is read from your database (once per process, then from the memo — see [Performance](#performance)) and the facts from FGA. If FGA is unreachable, the engine throws `AuthorizationBackendError` (503) — it does not quietly return `false`. Denying silently during an outage strips every user of their permissions with nothing to indicate why. Note that the `database` driver is **not** exempt from the 503 outcome: its catalog and facts live in SQL, and a database that does not answer is classified the same way (*"la base local caída es un 503, no un error crudo"*). What `database` avoids is the *second* dependency.

Three more properties worth knowing before putting it in front of production traffic — none of them can grant access that wasn't granted, all fail towards *denied*:

- **Enumerations read tuples, not computed relations.** `listSubjects`, `listRoles`, `listRoleScopes` and `listScopes` use the paginated `Read` API (100 tuples per page, until the continuation token is empty; a token that repeats or more than 10,000 pages is 500 `E_AUTHZ_INTERNAL`, never a hang) and filter expiry client-side. That is what makes them complete regardless of the server's `ListObjects`/`ListUsers` caps. The price: `Read` returns *written* tuples only. With the model this package generates (`assignee` and `denied` are direct relations) that is exactly the same set; if you extend the model with relations derived over `role_binding`, this driver's enumerations will not see them. Membership reads also consult the catalog (`authz_roles` for that level) — from the in-process memo, so no query in steady state — and `listRoleScopes` asks your resolver once per scope it returns, like `listScopes` (a `forRequest()` view memoises those calls).
- **Changing an expiry is not atomic.** FGA rejects deleting and writing the same tuple key in one transaction, so *replacing* an expiry is a delete followed by a write. Between the two, `authorize()` answers `false`, and a crash in that window loses the assignment; re-running the grant restores it. The driver reads the current tuple first, so this only happens when the expiry actually changes — a first grant is a plain write, an identical re-grant touches nothing (*"quitar la expiración es explícito (expiresAt: null); omitirla no la toca ni escribe nada"*). A grant *without* `expiresAt` whose read fails is a 503 whose message carries the recipe: preserving a live expiry requires knowing it; pass `{ expiresAt: null }` if you mean "permanent". A first write that collides with a concurrent one (FGA's "tuple already exists") re-reads and re-grants on top of it; any other write failure is propagated classified, with the SDK error as `cause` — never treated as a race (*"un write que falla con 400 no es una carrera"*).
- **Expiry follows the app server's clock.** The `not_expired` condition is evaluated against a `current_time` your process sends with each check, and enumerations filter with the same clock. Keep NTP running.
- **There is no distributed transaction with your database.** A `grant` validates the role against the local catalog and then writes the tuple. Remove that role from the catalog afterwards and the tuple is orphaned — `authorize()` finds no permission→role mapping and denies, `hasRole`/`list*` filter by the catalog and do not report it, so it fails closed in every read — but `purgeScope` cannot reach bindings of roles that are no longer in the catalog (it reads by exact object, built from the catalog; `Read` cannot enumerate by id prefix without a `user`). Reconciling those is the job of `authz:reconcile` (3b). `openfga:import` is likewise not atomic; it is idempotent, so a run that dies half-way is fixed by running it again with `--reconcile --prune`.

## Compatibility

| | |
|---|---|
| Node | ≥ 20.6 |
| AdonisJS | ^7 (peer) · Lucid ^22 (peer) |
| OpenFGA SDK | ^0.9 (optional peer, only for that driver); server verified against `v1.19.0` |
| Databases | **Verified: SQLite** (the suite runs on it). PostgreSQL and MySQL: the SQL is dialect-agnostic knex, but the suite does not run on them yet — that arrives in 2.1 (multi-engine harness). Until then, treat them as untested. |
| Module format | ESM only |

## Scope and maintenance

Extracted from the [adonis7-base](https://github.com/JantStack/adonis7-base) chassis, where it runs in production-shaped projects. Maintained according to that chassis's needs.

## License

MIT
