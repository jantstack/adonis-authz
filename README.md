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

1. **Hierarchical scopes, inheritance only downward.** A grant on a scope authorizes on that scope and all its descendants — never on siblings or ancestors. The engine only reserves the root (`app`); every other level is yours, declared by the `resolveChain` resolver you inject — which answers the **canonical chain** `[the scope as stored in your table, ...ancestors]`, so the identity of a scope is what your tree says, never the spelling the caller used (*"un alias del uuid del scope … jamás evade un deny"*) — and the suite proves it on a real three-level tree, in memory and on a real SQL table on PostgreSQL and MySQL (*"herencia de dos niveles"*, *"grant en una org vale en sus units, no en app ni en la org hermana"*, *"mover una unit fuera de la org… le quita el permiso, sin otra escritura"*).
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
  scopes: { resolveChain: resolveScopeAncestors },

  drivers: {
    database: () => new DatabaseAuthorizationDriver({ resolveChain: resolveScopeAncestors }),
    openfga: () => new OpenFgaAuthorizationDriver({ apiUrl, storeId, holderTypes, resolveChain: resolveScopeAncestors }),
  },

  // 3. Your catalogs (one per module), for authz:catalog:sync / diff
  catalogs: [async () => appAclCatalog()],

  // 4. Your side-effects on every write (audit, events, notifications)
  hooks: { onWrite: (event) => audit(event) },
})
```

### The scope tree

`resolveChain(scope)` returns the **canonical chain** of a scope — `[the scope itself as it is stored in your table, ...its ancestors from nearest to root, APP_SCOPE]` — or **`null` when the scope does not exist**. Element 0 is *the row you read*, not the argument you received: it is the identity the engine uses for every fact of that scope (assignments, denies, bindings, `purgeScope`). This matters because your tree can canonicalise ids where `authz_*` does not: PostgreSQL's `uuid` type finds the row for `BBBB…` and for the 32-hex form without hyphens, MySQL's default `*_ci` collation merges case — but `authz_*` compares byte-wise. Before 2.1 the chain was built with the caller's spelling, the ancestor's grant applied and the deny (written canonical) did not match: **a deny bypassed by an alias of the uuid**, on both engines and both drivers. Now the chain carries the canonical scope, the engine writes and reads under it, and the suite runs the judge over a real `demo_scopes` table on PostgreSQL and MySQL to prove it (*"un alias del uuid del scope (mayúsculas, guiones quitados) jamás evade un deny"*). Your answer is validated: element 0 must be the asked scope (same type; same uuid up to case and hyphens), everything must be a well-formed `ScopeRef`, an empty array is not a chain — otherwise 503 `E_AUTHZ_RESOLVER_FAILED`. Upper-case uuids are rejected at the gate (see [Identity](#identity-is-validated-once-and-everywhere)), so the only alias your tree can still merge is the hyphen-less one, and the canonical chain closes it.

`null` is a first-class answer: reads deny (`authorize`/`hasRole` → `false`), writes refuse (`grant`/`deny` → 422 `E_AUTHZ_UNKNOWN_SCOPE`), `revoke`/`removeDeny`/`purgeScope` act on the scope as given (a fact of a scope you deleted without telling the engine stays reachable), and `listScopes`, `listRoles`, `listRoleScopes`, `listDenies` and `listSubjects` omit it (*"scope que el árbol no conoce"*, *"un scope retirado del árbol deja de responder"*). Never answer `[scope, APP_SCOPE]` for what you do not know: it would make any invented scope a descendant of the root.

There is no default resolver. A driver built without one only knows `app`; asking about any other scope type is 422 `E_AUTHZ_NO_SCOPE_RESOLVER` on the first call (*"sin resolutor de ancestros, cualquier scope que no sea app es 422"*).

The tree is a **contract fact**: when it changes, tell the engine — in every driver:

```ts
await authorization.scopes.attached(unit, org)      // new node under a parent
await authorization.scopes.moved(unit, otherOrg)    // BEFORE you re-parent the row (containment reads the current chain)
await authorization.scopes.detached(unit)           // BEFORE you delete the row
```

The package validates before touching the driver — `child` cannot be `app` (422), the parent must exist (422 `E_AUTHZ_UNKNOWN_SCOPE`), and `child` cannot be an ancestor of the new parent (422 **`E_AUTHZ_SCOPE_CYCLE`**); on failure the driver is not called at all (*"un ciclo es 422 E_AUTHZ_SCOPE_CYCLE en el paquete, sin llamar al driver"*). `detached` runs **`purgeScope`** — every assignment and deny of that exact scope **whose role or permission is in the catalog** is deleted and the driver proves that set is zero or throws 500 `E_AUTHZ_PURGE_INCOMPLETE` — then notifies `onWrite` with `action: 'scope_purged'`. Nothing resurrects when the same uuid is attached again, and siblings keep their facts (*"detach purga los hechos del scope: nada resucita"*, *"detach es quirúrgico"*). Facts of roles you already removed from the catalog are outside that promise: they grant nothing and are not memberships (the reads filter by the catalog), and `authz:reconcile` (3b) collects them. `purgeScope` covers the exact scope only; until `descendantsOf` exists (2.1) you purge each node of the subtree you delete. `scopes.*` require `config.scopes.resolveChain` (500 `E_AUTHZ_CONFIG` otherwise).

Your resolver's *answer* is validated too: an element that is not a well-formed `ScopeRef`, a non-array, an empty chain or an element 0 that is not the asked scope is a 503 `E_AUTHZ_RESOLVER_FAILED` — the question was fine, the dependency was not (*"un ancestro inválido devuelto por el resolutor es 503 E_AUTHZ_RESOLVER_FAILED, no un 422"*). `scopes.attached/moved` also canonicalise the child through your tree before the cycle check, so an alias cannot slip under it.

`ScopeType` is an open `string`, so define your own union for type safety. The engine never queries your tables.

### Identity is validated, once and everywhere

`SubjectRef.type`/`uuid`, `ScopeRef.type`/`uuid`, role and permission slugs and `expiresAt` are checked by the manager on every call and again by each driver (the contract suite and third-party drivers bypass the manager). Lowercase letters, digits, `.`, `_`, `-` — **types and uuids alike**: types since 2.0 (a `*_ci` MySQL collation would merge `Users` and `users` into one row while FGA keeps them apart), uuids since 2.1 (the tree of a consumer merges `BBBB…` with `bbbb…` on PostgreSQL's `uuid` type and on MySQL's default collation, and the alias evaded a deny — *"la identidad es una cadena validada por la gramática … un uuid con MAYÚSCULAS … es 422"*; lower-case your ids at your edge: a UUID is the same id in any case); permissions may carry one `:` (`resource:action`); slugs are lowercase and at most **42** characters; `parent`, `binding`, `ancestor`, `role`, `assignee`, `denied` and the prefixes `can_`, `denied_`, `permits_` are reserved; `{ type: 'app', uuid: X }` and the root sentinel uuid outside `app` are rejected — even when your tree knows that sentinel (*"uuid centinela en un scope que el árbol SÍ conoce ⇒ 422"*); `grant`, `revoke` and `listSubjects` take a slug, and a `{ slug, scopeType }` object there is 422 (*"un RoleQuery objeto donde el contrato pide un slug ⇒ 422"*); `expiresAt` is `undefined`, `null` or a valid `Date` (*"expiresAt que no es Date válida, null ni omitido ⇒ 422"*). Violations are **422** (`E_AUTHZ_INVALID_IDENTITY`, `E_AUTHZ_INVALID_SLUG`) before any catalog, tree or backend call — zero queries, spied (*"identidad inválida ⇒ 422"*, *"slug mal formado o reservado ⇒ 422"*, *"una identidad inválida se rechaza con 0 llamadas al backend"*). `assertIdentity`, `assertValidSlug` and `assertExpiresAt` are exported so you can validate at your own edge with the same rule.

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
await authorization.listDenies(subject, scope)                       // direct denies in that exact scope (2.1)
```

`hasRole` with a string matches, at every level of the chain, only the role *of that level*: an app `owner` inherits downward, an organization `owner` never matches at `app`. The object form `{ slug, scopeType }` restricts the question to chain levels of that type (*"hasRole con el mismo slug en dos niveles"*).


## Primitives (2.1)

Everything below is composition in the manager over the driver port; a driver keeps its 2.0 shape. The port only gained two *optional* methods, `listDenies?` and `authorizeMany?` — a driver without them still passes `level: '2.0'`, and a primitive that needs one it lacks says so (500 `E_AUTHZ_UNSUPPORTED`, never a simulated `[]`).

**Containment.** **All six writes** — `grant`, `revoke`, `deny`, `removeDeny`, `scopes.attached/moved/detached` — accept `within`: the scope being written must be inside it (`within ∈ chain(scope)`, inclusive; `APP_SCOPE` contains everything), checked against your tree *fresh* — the per-request memo is never used to decide a write. What is checked: the target scope for `grant`/`revoke`/`deny`/`removeDeny`; **both origin and destination** for `scopes.moved` — the new parent *and* the child's current chain — and the same for `scopes.attached` when the child already exists in the tree (attaching an existing node *is* a move; a new node only checks the parent); the child itself for `scopes.detached`. Outside ⇒ 422 `E_AUTHZ_NOT_WITHIN`, nothing written, nothing purged, the driver not called. It is what stops "the admin of organization A grants in a unit of B by passing its uuid" — and, just as much, "removes B's deny" (removing a deny *is* granting), "revokes B's role", "purges B's unit" or **"moves B's unit under A"** (annexing a subtree inherits everything in it: worse than purging it) (*"within en las otras cuatro escrituras"*, *"within contrasta también el ORIGEN de scopes.moved/attached"*). Because the origin is read from your tree, notify `scopes.moved` **before** you re-parent the row, exactly as `scopes.detached` goes before the delete.

```ts
await authorization.grant(user, 'unit-editor', unit, { within: currentOrg })
await authorization.removeDeny(user, 'docs:read', unit, { within: currentOrg })
await authorization.scopes.attached(newUnit, parentUnit, { within: currentOrg })   // the parent must be inside
await authorization.scopes.moved(unit, otherUnit, { within: currentOrg })          // origin AND destination inside
await authorization.isWithin(unit, currentOrg)   // the same question on its own
```

> **`within` must come from the session, never from the request body.** `within = scope` (or the scope's own parent) satisfies the rule *by definition* — the chain always contains the scope itself — so a `within` taken from the same input as the scope is no containment at all; `'non-root'` closes the `app` wildcard, not that one. Take it from the authenticated tenant (`currentOrg` above: the organization the session belongs to), and let the request only name *what* inside it to write.

`requireWithin: true` in the config makes any of the six writes without `within` a 422 `E_AUTHZ_WITHIN_REQUIRED`. `requireWithin: 'non-root'` additionally rejects `within: APP_SCOPE` with 422 `E_AUTHZ_WITHIN_ROOT_FORBIDDEN`: the root contains everything, so as a containment it says nothing — it was the wildcard a tenant call-site could pass to satisfy the rule without naming its tenant. Platform code that really writes at the root uses `manager.driver()` (below) or a config without the flag. **The default is `false` — containment is opt-in in 2.1** and the manager warns once per config at construction (`warnOnOptInSecurity: false` silences it once you have decided). Same for `requireActor`.

**Actor.** Every write (`grant`, `revoke`, `deny`, `removeDeny`, `scopes.*`) takes `{ actor }` — a `SubjectRef`, validated like any identity — which `onWrite` receives as `event.actor`. `requireActor: true` ⇒ a write without it is 422 `E_AUTHZ_ACTOR_REQUIRED` before the driver and before the hook. No `AsyncLocalStorage`: the actor is an explicit argument. The engine never evaluates it (who may grant what is your policy).

**`manager.driver()` is the documented way out of all of that.** It returns the active driver as-is: writes through it skip `actor`/`requireActor`, `within`/`requireWithin` **and `onWrite`**; reads skip the per-request memo. It exists for platform code (seeders, commands, writing at the root under `'non-root'`) and for tests — a tenant call-site should never call it, and a code review can grep for it. Nothing else is offered through it on purpose.

**Decisions in bulk.** `authorizeMany(subject, permission, scopes)` → `boolean[]` by position, identical to N `authorize` (duplicates, unknown scopes, denies); empty ⇒ `[]` without touching anything; a position that cannot be answered rejects the whole call. `openfga` answers with one `batchCheck` for all chains (a repeated scope shares one slot); `database` composes N `authorize` over a memoised view (one tree call per distinct scope). A third-party driver's `authorizeMany` is validated: a result that is not a `boolean[]` with exactly one position per scope is 500 `E_AUTHZ_INTERNAL` naming the driver (*"authorizeMany valida la respuesta de un driver de terceros"*).

**Effective permissions.** `effectivePermissions(subject, scope)` → the union of what the holder's live roles grant along the whole chain, minus what is denied at any level. Exactly `{ p | authorize(subject, p, scope) }` without asking per permission — and in **two reads** of the facts backend, not two per level: the optional port method `rolesInChain(subject, chain)` (both drivers implement it; a driver without it is composed from N `listRoles`) plus one `listDenies(subject)` (*"effectivePermissions con cadena de 3 lee roles y denies UNA vez"*).

**Enumerating scopes.** `authorizedScopes(subject, permission, scopeType)` is the **one** API that enumerates inherited scopes (the explicit exception to "`list*` are direct"):

```ts
const result = await authorization.authorizedScopes(user, 'docs:read', 'organization')
// { kind: 'none' }
// { kind: 'some', scopes: ScopeRef[] }                     // exact set, ≤ maxScopes
// { kind: 'all', excludedSubtrees: ExcludedSubtree[] }     // granted at the root — MINUS these subtrees
//   ExcludedSubtree = { scope: ScopeRef; includesDescendants: true }
```

`all` is never silent about denies: `excludedSubtrees` lists every scope with a live deny of the permission — **each one meaning its whole subtree**, which is why the element is a nominal `ExcludedSubtree` and not a `ScopeRef`: a `WHERE uuid NOT IN (…denied uuids…)` would still list the units of a denied organization. Either subtract the subtree in your own query (recursive CTE, materialised path) or expand it first:

```ts
if (result.kind === 'all') {
  const excluded = await authorization.expandExcludedSubtrees(result.excludedSubtrees) // each scope + all its descendants, via descendantsOf
  orgs = orgs.whereNotIn('uuid', excluded.filter((s) => s.type === 'organization').map((s) => s.uuid))
}
```

`expandExcludedSubtrees` is bounded like `authorizedScopes`, expires with its `forRequest()` view like every other read, and throws if `descendantsOf` cannot enumerate a subtree (subtracting it half-way would be fail-open). `some` = direct granting scopes ∪ their descendants via your `descendantsOf`, filtered by type — and **every candidate is checked against `resolveChain`**: its chain must run through the granting scope and must contain no denied scope (the exact rule of `authorize`). So the answer is `{ s | authorize(subject, permission, s) }` scope by scope whenever `descendantsOf` and `resolveChain` describe the same tree; if they disagree — a descendant that the ancestors resolver hangs elsewhere, or does not know — the call is 503 `E_AUTHZ_RESOLVER_FAILED`, never a list with a foreign tenant in it (*"authorizedScopes ≡ { s | authorize(s) } scope a scope"*). More than `maxScopes` ⇒ 422 `E_AUTHZ_TOO_MANY_SCOPES`, never a partial list, and the walk stops as soon as the count of the requested type exceeds it — direct scopes are counted before any subtree is fetched. `{ maxScopes }` per call can only **lower** `scopes.maxScopes` (default 1000), never raise it. It needs `scopes.descendantsOf` in the config; without it, 500 `E_AUTHZ_NO_DESCENDANTS_RESOLVER` — even for a holder with nothing (a `none` without a tree would be a lie).

**What it costs.** `authorizedScopes` is **O(descendants of the granting scopes × `resolveChain`)**, not O(answer): every candidate returned by `descendantsOf` — *of any type* — is checked against `resolveChain` once (memoised per call), so an organisation with 300 teams and one unit pays 300 resolver calls to list that one unit, and `maxScopes` (a bound on the *answer*, by type) does not cut that walk. The bound on the *work* is **`scopes.maxDescendants`** (default 10 000, the `maxNodes` handed to `descendantsOf`; more ⇒ 422) per granting scope — set it to what a request may afford, and keep `resolveChain` cheap (`hierarchicalScopeResolver` over an in-memory or cached `parentOf`, or a single SQL per scope). A subtree-shaped `descendantsOf` filtered by type would cut the walk; that change is deferred, the cost is documented instead.

### Scopes: ancestors and descendants

```ts
import { hierarchicalScopeResolver, sqlDescendantsOf } from '@jantstack/adonis-authz'

scopes: {
  // From your table: nodeOf reads the ROW — { self: the canonical scope, parent: ScopeRef | null (top level) } — or undefined = unknown scope.
  resolveChain: hierarchicalScopeResolver({ nodeOf: (scope) => nodes.nodeOf(scope), maxDepth: 64 }),
  // One recursive CTE over your table (PostgreSQL, MySQL 8 and SQLite; any other dialect ⇒ E_AUTHZ_UNSUPPORTED_DIALECT).
  descendantsOf: sqlDescendantsOf({ table: 'org_nodes', uuidColumn: 'uuid', parentColumn: 'parent_uuid', typeColumn: 'kind' }),
  maxScopes: 1000,        // answer bound of authorizedScopes
  maxDescendants: 10000,  // maxNodes handed to descendantsOf
}
```

`hierarchicalScopeResolver` walks `nodeOf` — the row of a scope: its **canonical** `self` (what makes the chain canonical: the row found for an alias carries the real id) and its `parent` — with a visited set (a cycle is 422 `E_AUTHZ_SCOPE_CYCLE`) and a depth bound (`maxDepth` ancestors, `app` included) that **throws** rather than truncating (500 `E_AUTHZ_SCOPE_TOO_DEEP`: a chain without its root would lose the root's denies). A `self` or `parent` that is not a well-formed scope (`{ type: 'app', uuid }`, an upper-case type…), or a `self` that is not the row of the scope asked, is 503 `E_AUTHZ_RESOLVER_FAILED`, never normalised. It costs one `nodeOf` per level — wrap it with `memoizeAncestors` or read through `forRequest()`. `descendantsOf(scope, { maxNodes })` returns the whole subtree (any type, any depth) or `null` for an unknown scope; more than `maxNodes` ⇒ throw. `sqlDescendantsOf` validates identifiers and `scopeType` (nothing else is interpolated), gives every query the deadline, reads at most `maxNodes + 1` rows and bounds the recursion so that a cycle in your table terminates and is reported as 422 `E_AUTHZ_TOO_MANY_SCOPES` ("posible ciclo"). `descendantsOf` is **never** called from `authorize`, `hasRole`, `list*`, `authorizeMany`, `effectivePermissions` or a write — an architecture spy in the contract pins zero calls.

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
| `E_AUTHZ_NO_SCOPE_RESOLVER` | 422 | driver without `resolveChain` asked about a non-`app` scope |
| `E_AUTHZ_SCOPE_CYCLE` | 422 | `scopes.attached/moved` would close a cycle; `hierarchicalScopeResolver` met a cycle |
| `E_AUTHZ_NOT_WITHIN` | 422 | any of the six writes with `within` not in the chain of the scope it writes to (the new parent **and** the child's current chain for `scopes.moved`, and for `scopes.attached` of an existing child) (2.1) |
| `E_AUTHZ_WITHIN_REQUIRED` | 422 | `requireWithin` set and a write without `within` (2.1) |
| `E_AUTHZ_WITHIN_ROOT_FORBIDDEN` | 422 | `requireWithin: 'non-root'` and `within: APP_SCOPE` (2.1) |
| `E_AUTHZ_ACTOR_REQUIRED` | 422 | `requireActor: true` and a write without `actor` (2.1) |
| `E_AUTHZ_TOO_MANY_SCOPES` | 422 | `authorizedScopes`/`expandExcludedSubtrees` over `maxScopes`, or `descendantsOf` over `maxNodes` (`sqlDescendantsOf`: also a possible cycle) — never a partial list (2.1) |
| `E_AUTHZ_BACKEND_UNAVAILABLE` | 503 | facts backend or SQL catalog did not answer (both drivers, catalog sync/diff and the `authz_catalog_version` check included); the version row is missing or unreadable ("migración 2.0 no aplicada": fail-closed, never version 0); a per-check `error` in an OpenFGA `batchCheck` |
| `E_AUTHZ_BACKEND_TIMEOUT` | 503 | `timeoutMs` elapsed (subclass of the above) |
| `E_AUTHZ_RESOLVER_FAILED` | 503 | your `resolveChain`, `parentOf` or `descendantsOf` threw or answered a malformed scope; `descendantsOf` and `resolveChain` disagree in `authorizedScopes`; a subtree to exclude cannot be enumerated |
| `E_AUTHZ_STORE_NOT_EMPTY` | 409 | `openfga:import` on a store with tuples, without `--reconcile` |
| `E_AUTHZ_CONFIG` | 500 | contradictory config (`holderTypes` not injective or a holder type not declared in it, `scopes.*` without resolver, `appAccess` without `permission`, `openfga:import --prune` without `--reconcile`, `catalog` together with `catalogRevalidate`, an invalid `maxAgeMs`); `bumpAuthzCatalogVersion` called without the writing transaction's client |
| `E_AUTHZ_ROLE_IS_NOT_ACCESS` | 500 | `appAccess({ role })` |
| `E_AUTHZ_INTERNAL` | 500 | package invariant violated (empty scope set on a write, misaligned batch, a third-party `authorizeMany` answering the wrong shape, a `Read` continuation token that never advances or more than 10,000 pages) |
| `E_AUTHZ_PURGE_INCOMPLETE` | 500 | `purgeScope` could not prove zero |
| `E_AUTHZ_UNSUPPORTED` | 500 | a 2.1 primitive needs an optional port method (`listDenies`) the active driver lacks |
| `E_AUTHZ_NO_DESCENDANTS_RESOLVER` | 500 | `authorizedScopes`/`expandExcludedSubtrees` without `scopes.descendantsOf` |
| `E_AUTHZ_VIEW_EXPIRED` | 500 | a `forRequest()` view used to read (`expandExcludedSubtrees` included) after its `maxAgeMs` (default 30 s, monotonic clock) |
| `E_AUTHZ_UNSUPPORTED_DIALECT` | 500 | `sqlDescendantsOf` on a dialect other than PostgreSQL / MySQL 8 / SQLite |
| `E_AUTHZ_SCOPE_TOO_DEEP` | 500 | `hierarchicalScopeResolver` over `maxDepth` (no truncated chain) |

## Driver options

Both drivers take `resolveChain` and **`timeoutMs`** (default 5000): every SQL query the driver builds is given a knex timeout — the `DELETE`s inside `purgeScope`'s transaction included; only knex's own `BEGIN`/`COMMIT` carry none — every FGA call has a total deadline, and an elapsed deadline is 503 `E_AUTHZ_BACKEND_TIMEOUT`. A server that accepts the connection and never answers is released in under a second (*"authorize contra un servidor mudo ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT en menos de 1 s"*). SQLite's synchronous driver cannot actually time out; what the suite pins there is that every query carries the deadline (*"toda consulta sale con el timeout configurado"*). A deadline releases the caller, it does not abort the request in flight: see `indeterminate` above.

Both also take **`catalogRevalidate`** (`'always'`, the default, or `{ everyMs }`) *or* **`catalog`** (a `CatalogCache` to share between drivers of the same process; its own `revalidate` is the policy) — the catalog memo described under [Performance](#performance). Passing both is 500 `E_AUTHZ_CONFIG` at construction: the driver's `catalogRevalidate` would be silently ignored otherwise.

Both take **`now`** (default `() => new Date()`): the wall clock every time-based *decision* uses — `expires_at > now()` in SQL, the `current_time` of every FGA check (one instant per operation: every check of a `batchCheck` carries the same `current_time`, and the two reads of `listScopes` filter with the same `now`), the client-side expiry filter of the enumerations and the three states of a re-grant. The audit stamps (`created_at`) are **not** decisions and use the system clock: with MySQL's `TIMESTAMP` an injected clock in 2040 made every write fail (*"… se escribe estando el reloj en 2040"*). Every driver of the package also implements `withClock(now)` on the port (a view bound to another clock, like `withChainResolver`), and the manager applies **`clock`** from the config to the driver it resolves — all `forRequest()` views share it; a config `clock` over a driver without `withClock` is 500 `E_AUTHZ_CONFIG`, never a clock silently ignored. It exists so that expiry is observable *without sleeping* (the contract fixes the exact instant: one millisecond before `expiresAt` grants, at `expiresAt` it does not — *"caducidad exacta con el reloj inyectado"*) and so that your own tests can freeze time; in production leave it alone and keep NTP running. It is not the monotonic clock of `forRequest({ maxAgeMs })`, which measures a window and must not move with NTP. Nothing else in `src/` reads the wall clock (a grep test pins it) — except the model trait `withAuthzScopes` (`whereRoles`/`wherePermissions`), which cannot see the manager: it decides "live" with the system clock unless you compose it with the same clock, `compose(BaseModel, withAuthzScopes({ clock }))` (*"withAuthzScopes({ clock }) decide la vigencia con ESE reloj"*). Its primary-key comparison is dialect-aware (on PostgreSQL a `uuid` primary key is cast to text against the `varchar` subquery: *"… con la clave primaria uuid nativa del modelo"*).

`openfga` additionally takes `holderTypes` (required, injective; a holder whose morph name is not in it is 500 `E_AUTHZ_CONFIG`), `modelId`, a `logger` (default `console`), **`retryParams`** (default `{ maxRetry: 0 }`, see `indeterminate` above) and **`consistency`**: `'higher_consistency'` (default) or `'minimize_latency'`. The default protects the "removing the deny restores" promise against a server started with `--check-query-cache-enabled`, where a fresh revoke or deny would keep granting for up to the cache TTL; `minimize_latency` is the explicit opt-out (*"todo check lleva context.current_time; toda llamada HIGHER_CONSISTENCY"*). `driver.diagnostics.unparseableBindings` counts store tuples the engine cannot interpret — binding ids it does not understand and malformed tuples alike; each one is logged, never skipped in silence.

## Performance

Two optimisations landed in 2.1, both measured and both **without changing a single answer** (the contract suite is the proof: same cases, both drivers, before and after). Reproduce the numbers with `OPENFGA_TEST_URL=http://localhost:8101 node --import @poppinss/ts-exec scripts/bench_authorize.mjs` (chain of 3 scopes through your resolver, 5 roles per level, 20 permissions, N=200 after 30 warm-up calls, HTTP round-trip included; OpenFGA v1.19.0 on the same machine):

| `authorize` (`openfga`) | before 2.1 | 2.1 (lot A) | 2.1 (lot D, shared catalog version) | backend calls per question |
|---|---|---|---|---|
| granted by a root role (worst case: the whole chain) | p50 **4.33 ms** · p95 7.33 ms | p50 **2.03 ms** · p95 3.83 ms | p50 **2.35 ms · p95 3.70 ms** | 2 SQL + 2 `batchCheck` → **1 SQL (version check) + 1 `batchCheck`** |
| granted by nobody | p50 2.36 ms · p95 3.48 ms | p50 0.01 ms | p50 **0.05 ms** | 2 SQL + 1 `batchCheck` → **1 SQL + 0** |

(`database` on in-memory SQLite: 0.37 → 0.27 → 0.38 ms p50 for the granted case — the version check is one primary-key `SELECT` per question.)

**The catalog is memoised; facts and decisions never are — and the memo never decides with a catalog the database has already replaced.** Each driver loads `authz_permissions`, `authz_roles` and `authz_role_permissions` once, lazily, into an in-process `CatalogCache` (three queries, all with the driver's deadline; a load that fails is a 503 and caches nothing). Every question still reads its facts — assignments, denies, tuples — from the backend: a `grant`, `deny` or `revoke` is visible in the very next call (*"el memo nunca cachea hechos ni decisiones"*). What the memo answers is "which uuid is `docs:read`", "which roles of which level grant it", "which roles exist at this level" — and since those answers **do** feed decisions (`rolesGranting` in `openfga`, `effectivePermissions` in both drivers), the memo is only ever served after checking it is current:

- **A shared version in the database.** The migration ships `authz_catalog_version` (one row, `id = 1`). `syncAuthzCatalog` / `node ace authz:catalog:sync` increment it **as the last statement of the sync's transaction** — a sync that does not commit does not bump it. Before serving, each `CatalogCache` compares the version it loaded with that row (one primary-key `SELECT`, with the deadline, classified 503 like any other query; concurrent checks share one read) and reloads when the database is ahead. So a sync run by one worker, one container or a deploy job is seen by **every process on its next question** — no pub/sub, no restart, no TTL (*"el catálogo que decide es el de la base: un sync en otro proceso…"*, a contract case in both drivers, with two managers and two memos over the same database). If the version row cannot be read — the table is missing, **the row is missing or not a number** (a database without the 2.0 migration) — the question is 503 `E_AUTHZ_BACKEND_UNAVAILABLE` saying so: never version `0`, never an answer from a memo that might be stale (*"sin la fila de authz_catalog_version… 503"*).
- **`catalogRevalidate: 'always'`** (default) checks on every question. **`{ everyMs }`** checks at most once per window: it saves that `SELECT` at the price of a **bounded window in which another process's revocation is not yet seen** (a fail-open window you accept explicitly; a sync in the *same* process is still seen immediately). `{ everyMs: 30_000 }` is a reasonable trade for a read-heavy deployment whose catalog changes at deploy time. The window — like a view's `maxAgeMs` — is measured with a **monotonic clock** (`performance.now()`), so a wall clock stepped backwards by NTP or a snapshot restore neither stretches it nor revives an expired view (*"la ventana de { everyMs } se mide con reloj MONÓTONO"*).
- **Writing `authz_*` by hand** (a seeder, a data migration, a script) goes through **`withAuthzCatalogWrite(async (trx) => { … })`** — exported: it opens the transaction, runs your write with *that* client and bumps the version **as the last statement, inside**, so either both land or neither. Order matters and is enforced: `bumpAuthzCatalogVersion(trx)` requires the writing transaction's client (500 `E_AUTHZ_CONFIG` without it, or with the global `db`). A bump that commits *before* its write would make every other process reload the **old** rows tagged with the **new** version — and never revalidate again, a permanent fail-open (reproduced with two real processes; closed in 2.1). Until the write commits, the previous catalog stands, pinned as a negative case (*"un cambio en authz_* SIN subir la versión NO se ve"*). `withAuthzCatalogWrite` is the cross-process channel only: this process sees it on its next question under `'always'` and at the end of the window under `{ everyMs }` — call `invalidateAuthzCatalog()` after it if you use `everyMs` and need it at once (what `syncAuthzCatalog` does); `driver.catalog.invalidate()` reaches only that driver's memo (an invalidation that lands while a load is in flight is not lost).
- Two drivers in one process can share one memo: `new DatabaseAuthorizationDriver({ catalog })` and `new OpenFgaAuthorizationDriver({ catalog })` with the same `new CatalogCache({ revalidate, timeoutMs })` — and without `catalogRevalidate` on the drivers (500 `E_AUTHZ_CONFIG`: the shared memo's `revalidate` is the policy).

**One `batchCheck` per `authorize` in `openfga`.** The denies of the chain and the roles that grant the permission travel in the same request (the SDK splits at 50 checks and parallelises); the rule is unchanged and evaluated in this order: any per-check `error` ⇒ 503, any deny `allowed` ⇒ `false`, any role `allowed` ⇒ `true`. When no role of the catalog grants the permission anywhere in the chain, the answer is `false` without a request — the denies cannot change it. Each operation takes one snapshot of the catalog, so one version check per question.

**A per-request view memoises the scope tree, on reads only — and expires.** `authorization.forRequest({ maxAgeMs })` returns an `AuthorizationView`: same API as the manager, sharing its driver and hooks, whose reads (`authorize`, `hasRole`, `list*`, `authorizeMany`, `effectivePermissions`, `authorizedScopes`, `expandExcludedSubtrees`) resolve ancestors through `memoizeAncestors(config.scopes.resolveChain)` — one call to your resolver per scope for the life of the view — while its writes (`grant`, `revoke`, `deny`, `removeDeny`, `scopes.*`) and `isWithin` resolve fresh: a stale read expires by itself, a grant on a chain that moved is written forever. The memo holds ancestors, never decisions: a deny written between two `authorize` of the same view changes the second answer (*"forRequest(): las lecturas de una vista resuelven cada scope una vez; las escrituras, en fresco"*). Because a view kept beyond its request would serve the old chain forever (after a `scopes.moved`, a cross-tenant answer), **a view stops reading after `maxAgeMs` (default 30 000 ms, monotonic clock)**: any later read is 500 `E_AUTHZ_VIEW_EXPIRED`, loud on purpose. `forRequest({ maxAgeMs: 0 })` is the explicit "no limit". No `AsyncLocalStorage`: the view is an explicit object with the lifetime you give it. The pattern in AdonisJS is a middleware:

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

`memoizeAncestors(resolver)` is exported for the cases where you hold a driver directly; keep it on the read path. Without `scopes.resolveChain` in the config, or with a third-party driver that does not implement the optional `withChainResolver`, the view reads through the driver as-is — correct, just not memoised.

## Custom drivers, judged by the same suite

Implement `AuthorizationDriver`, register its factory, and prove it:

```ts
import { runAuthorizationDriverContract, resolveChainFrom } from '@jantstack/adonis-authz/testing'

runAuthorizationDriverContract({
  name: 'my-driver',
  level: '2.1',                         // '2.0' = up to Phase 1; omit for the 1.x cases only
  capabilities: {                       // what the driver declares; each one has its own cases
    hierarchyFacts: false,
    transactions: false,
    truncationSignal: false,
    singleCheckAuthorize: false,
    injectableClock: false,
    exhaustiveLists: true,              // false ⇒ also pass `limits: { listMaxResults }`
    listDenies: true,                   // the port's optional listDenies; judged at '2.1' only (declare false below it)
  },
  // The suite builds the scope tree case by case; hand it to your driver.
  makeDriver: (tree) => new MyDriver({ resolveChain: resolveChainFrom(tree) }),   // tree.chainOf(scope) = the canonical chain
  // Optional: another instance over the SAME facts backend with its own catalog memo (what a second
  // process would be). Default: a prototype view of the driver with a fresh `CatalogCache` when it exposes `catalog`.
  makeTwin: (driver, tree) => new MyDriver({ resolveChain: resolveChainFrom(tree), sameBackendAs: driver }),
  seedCatalog: (catalog) => syncAuthzCatalog(catalog),
  cleanup: () => wipeEverything(),
})
```

Declaring a capability `true` that the suite has no case for makes registration throw — a promise without a judge does not pass. The port also has optional methods a driver may implement to do better than the manager's composition — `onScopeAttached/Moved/Detached` (tree as facts) and, since 2.1, `withChainResolver(resolver)` (a view of the driver bound to another resolver, what `forRequest()` uses to memoise reads), `listDenies(subject, scope?)` (direct denies; what `effectivePermissions` and `authorizedScopes` subtract), `authorizeMany(subject, permission, scopes)` (one round-trip for N decisions; its `boolean[]` is validated) and `rolesInChain(subject, chain)` (the holder's direct roles along a resolved chain in one read; what `effectivePermissions` uses); a driver without them keeps passing the same suite at `'2.0'`. At `'2.1'`, **`listDenies` is a capability pair**: `listDenies: true` judges `listDenies`, `effectivePermissions`, `authorizedScopes` and the shared catalog version through them; `listDenies: false` judges instead that those primitives *say so* — 500 `E_AUTHZ_UNSUPPORTED` naming the method, never a simulated `[]` (the package runs that face itself, over a `database` view without the method: *"sin listDenies en el puerto: … 500 E_AUTHZ_UNSUPPORTED"*). Declaring `listDenies: true` below `'2.1'` throws: nothing observes it there. `exhaustiveLists: false` asks for the backend's cap and proves only the exact boundary.

What passing means: **for everything the suite covers, both drivers answer the same** — including the malformed-input edges that used to diverge (`{app, uuid}`, a uuid with `#`), which are contract cases now. What is *not* identical between drivers is operational and listed below: latency, failure modes, the two-call expiry refresh in OpenFGA. Switching drivers is a facts migration (`openfga:import`), not a change at the call-sites the manager exposes.

The package runs that suite on itself: `npm test` judges the `database` driver over in-memory SQLite — no host application — and `OPENFGA_TEST_URL=… npm test` adds the `openfga` driver to the same verdict. `npm run test:pg` and `npm run test:mysql` run the **same** suite over PostgreSQL 18 and MySQL 8.4 (`TEST_PG_URL` / `TEST_MYSQL_URL`; each run creates a database with a random suffix and drops it), `npm run test:sqlite-file` over a SQLite file with a pool of 2–5 connections (real connection-level concurrency: a case pins `pool.max ≥ 2` and a read that answers while another connection holds an open transaction — *"una lectura responde mientras OTRA conexión mantiene una transacción abierta"*; the two-concurrent-grants case itself is a JavaScript check-then-insert race and dies with a single connection too). On PostgreSQL and MySQL the judge additionally runs with the scope tree in a real SQL table (`hierarchicalScopeResolver` + `sqlDescendantsOf` over `demo_scopes`), which is where the uuid-alias bypass lived. CI runs all of it: SQLite in memory and as a file, PostgreSQL and MySQL, each with and without OpenFGA, plus a second OpenFGA server with `ListObjects`/`ListUsers` capped at 3; a case also checks that the child process the suite spawns leaves no database behind. Two capability pairs are exercised on both drivers: `listDenies` and **`injectableClock`** (`true` ⇒ the judge fixes the instant through `withClock(now)` and observes exact expiry, renewal and "expires right now" without waiting; `false` ⇒ it can only observe the three states of `expiresAt` in real time, with a 1.5 s wait).

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

### Operational notes for the SQL engines

The published migration (`stubs/migration.stub`) carries three decisions that were **observed** by running the suite on PostgreSQL and MySQL, not guessed — each one was a red test first. The suite also **executes** the migration on a scratch database of each engine and compares what the engine reports for every column (type, length, precision, nullability, collation) with the schema the tests run on (*"el esquema que CONSTRUYE el stub y el espejo del harness son el mismo"*).

- **Identity columns are `varchar(64)`, not `uuid`.** `holder_uuid` and `scope_uuid` hold whatever your grammar-valid id is (`[a-z0-9._-]`, ≤ 36 chars): `user-42`, a ULID, a UUID. PostgreSQL's `uuid` type rejected anything else with `invalid input syntax for type uuid` (a 503 on `grant`). The suite pins that non-UUID ids work in every engine (*"la identidad es una cadena validada por la gramática, no un UUID del motor"*).
- **Identity columns and slugs are compared byte-wise.** They carry `collate 'utf8mb4_bin'` in the migration (`holder_type`, `holder_uuid`, `scope_type`, `scope_uuid` in assignments and denies; `slug` and `scope_type` in the catalog tables); knex only compiles it for MySQL, where the default collation (`utf8mb4_0900_ai_ci`) merged `abc` and `ABC` into one row — a grant to one authorised the other and the unique index treated them as duplicates. PostgreSQL and SQLite already compare `=` byte-wise. If you copy the migration into an existing MySQL schema, alter those columns' collation too. Your own **scope tree table** is outside this promise — that is why the chain resolver returns the canonical row and why upper-case uuids are rejected (see [The scope tree](#the-scope-tree)).
- **`expires_at` is `DATETIME(3)`.** knex's `timestamp` is `TIMESTAMP(0)` on MySQL: it *rounds* to the second (an expiry 600 ms away was stored 1 s away and kept granting past its instant) and cannot hold dates after 2038-01-19. Expiry is millisecond-exact in every engine and `2040-01-01` is a valid expiry (*"la caducidad guarda milisegundos y fechas más allá de 2038"*). PostgreSQL stores it as `timestamptz(3)`.

Also on MySQL: `sqlDescendantsOf` quotes identifiers with backticks and sends `/*+ SET_VAR(cte_max_recursion_depth = …) */` with each walk — MySQL aborts a recursive CTE after 1000 iterations (`cte_max_recursion_depth`, error 3636), which turned a cycle under a bound above 1000 (the manager's default is 10 000) into a 503 instead of the contract's 422 "posible ciclo". The bound is the same one the query already imposes with `depth < maxNodes + 1`; nothing from your input reaches the hint, and `maxScopes`/`maxDescendants` are capped at 10 000 000 (`MAX_SCOPE_BOUND`; above it the hint leaves MySQL's range and the 422 degrades to a 503 — 500 `E_AUTHZ_CONFIG` instead).

**Expiry is an instant, and the package stores it as UTC itself.** On MySQL `expires_at` is `DATETIME(3)`, which has no time zone, and `mysql2` serialises and parses `Date` values with the **process's** `TZ` (`timezone: 'local'`, its default): a process in UTC wrote `12:00:00` for `12:00Z` and a process in Caracas read it as `16:00Z` — the assignment expired four hours late for it (and nine hours early for one in Tokyo). The `database` driver does not depend on your connection options: on MySQL it writes `expires_at` as an explicit UTC string (`YYYY-MM-DD HH:mm:ss.SSS`), compares with `now` formatted the same way and reads it back through `DATE_FORMAT` (a string, parsed as UTC), so `timezone`, `dateStrings` and `TZ` do not enter the decision; `openfga:import` reads it the same way; the model trait compares the same way. PostgreSQL stores `timestamptz(3)` (an absolute instant) and SQLite a number. The suite spawns real child processes in `UTC`, `Asia/Tokyo` and `America/Caracas` over the same database, with the default connection options, writing and reading in both directions (*"expires_at es un instante: procesos con TZ distinta sobre la misma base ven la misma caducidad"*). Keep the process on NTP; do not set MySQL's `timezone` option for the package's sake — it is not needed, and it must not be relied on.

**`withAuthzCatalogWrite` and a swallowed SQL error.** Do not `try/catch` a SQL failure inside the `fn(trx)` you pass and carry on: on PostgreSQL the transaction is aborted (`25P02`) and every following statement fails — the package classifies that as 503 `E_AUTHZ_BACKEND_UNAVAILABLE` with the `pg` error as `cause` (never the raw error with your SQL in it); on MySQL and SQLite the engine does **not** abort the transaction and what follows **is committed**. The divergence is the engines', pinned by the suite on the three (*"un error SQL tragado dentro de fn envenena la transacción en PostgreSQL ⇒ 503 …; en MySQL y SQLite la transacción sigue y se confirma"*).

Upgrading a 1.x installation (which used `uuid` columns, `timestamp` for `expires_at`, the default collation and had no `authz_catalog_version`): run the statements below for your engine in a migration of your own. They are **executed by the suite** (`tests/upgrade_recipe.spec.ts`): the 1.1.0 migration is created on a scratch database, these exact statements are applied, the resulting schema is compared column by column with the published migration, and the 2.x engine is exercised on top (non-UUID ids, millisecond expiry, dates past 2038, byte-wise identity, the catalog version). Existing UUID values are valid strings; nothing needs rewriting.

```sql
-- PostgreSQL: upgrading a 1.x schema to 2.x
ALTER TABLE authz_assignments
  ALTER COLUMN holder_uuid TYPE varchar(64),
  ALTER COLUMN scope_uuid TYPE varchar(64),
  ALTER COLUMN expires_at TYPE timestamptz(3);
ALTER TABLE authz_denies
  ALTER COLUMN holder_uuid TYPE varchar(64),
  ALTER COLUMN scope_uuid TYPE varchar(64);
CREATE TABLE authz_catalog_version (
  id integer NOT NULL PRIMARY KEY,
  version bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL
);
INSERT INTO authz_catalog_version (id, version, updated_at) VALUES (1, 0, now());
```

```sql
-- MySQL: upgrading a 1.x schema to 2.x
ALTER TABLE authz_roles
  MODIFY slug varchar(100) COLLATE utf8mb4_bin NOT NULL,
  MODIFY scope_type varchar(20) COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE authz_permissions
  MODIFY slug varchar(100) COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE authz_assignments
  MODIFY holder_type varchar(50) COLLATE utf8mb4_bin NOT NULL,
  MODIFY holder_uuid varchar(64) COLLATE utf8mb4_bin NOT NULL,
  MODIFY scope_type varchar(20) COLLATE utf8mb4_bin NOT NULL,
  MODIFY scope_uuid varchar(64) COLLATE utf8mb4_bin NOT NULL,
  MODIFY expires_at datetime(3) NULL;
ALTER TABLE authz_denies
  MODIFY holder_type varchar(50) COLLATE utf8mb4_bin NOT NULL,
  MODIFY holder_uuid varchar(64) COLLATE utf8mb4_bin NOT NULL,
  MODIFY scope_type varchar(20) COLLATE utf8mb4_bin NOT NULL,
  MODIFY scope_uuid varchar(64) COLLATE utf8mb4_bin NOT NULL;
CREATE TABLE authz_catalog_version (
  id int NOT NULL PRIMARY KEY,
  version bigint NOT NULL DEFAULT 0,
  updated_at timestamp NOT NULL
);
INSERT INTO authz_catalog_version (id, version, updated_at) VALUES (1, 0, CURRENT_TIMESTAMP);
```

## Compatibility

| | |
|---|---|
| Node | ≥ 20.6 |
| AdonisJS | ^7 (peer) · Lucid ^22 (peer) |
| OpenFGA SDK | ^0.9 (optional peer, only for that driver); server verified against `v1.19.0` |
| Databases | The full contract suite (`database` driver, and `openfga` with the catalog in SQL) runs on every engine in CI: **SQLite** (in memory, and as a file with a pool of 2–5), **PostgreSQL 18** and **MySQL 8.4**. See [Operational notes for the SQL engines](#operational-notes-for-the-sql-engines) for the three schema decisions those runs forced. |
| Module format | ESM only |

## Scope and maintenance

Extracted from the [adonis7-base](https://github.com/JantStack/adonis7-base) chassis, where it runs in production-shaped projects. Maintained according to that chassis's needs.

## License

MIT
