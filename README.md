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

> **2.x is a single breaking release over 1.x.** No compatibility flags — there were no external consumers to keep. What changed, and why, is in the [CHANGELOG](./CHANGELOG.md) (start with the summary at the top, ordered by risk); upgrading a 1.x install is [its own section](#upgrading-from-1x-to-2x).

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

The package validates before touching the driver — `child` cannot be `app` (422), the parent must exist (422 `E_AUTHZ_UNKNOWN_SCOPE`), and `child` cannot be an ancestor of the new parent (422 **`E_AUTHZ_SCOPE_CYCLE`**); on failure the driver is not called at all (*"un ciclo es 422 E_AUTHZ_SCOPE_CYCLE en el paquete, sin llamar al driver"*). `detached` runs **`purgeScope`** — every assignment and deny of that exact scope **whose role or permission is in the catalog** is deleted and the driver proves that set is zero or throws 500 `E_AUTHZ_PURGE_INCOMPLETE` — then notifies `onWrite` with `action: 'scope_purged'`. Nothing resurrects when the same uuid is attached again, and siblings keep their facts (*"detach purga los hechos del scope: nada resucita"*, *"detach es quirúrgico"*). Facts of roles you already removed from the catalog are outside that promise: they grant nothing and are not memberships (the reads filter by the catalog), and `authz:reconcile --to=openfga --prune` collects them. `purgeScope` covers the exact scope only, and **only the facts** — it never writes the catalog, so the local roles owned by that scope survive **dormant** (see [Scoped roles](#scoped-roles-22)); you purge each node of the subtree you delete. `scopes.*` require `config.scopes.resolveChain` (500 `E_AUTHZ_CONFIG` otherwise).

Your resolver's *answer* is validated too: an element that is not a well-formed `ScopeRef`, a non-array, an empty chain or an element 0 that is not the asked scope is a 503 `E_AUTHZ_RESOLVER_FAILED` — the question was fine, the dependency was not (*"un ancestro inválido devuelto por el resolutor es 503 E_AUTHZ_RESOLVER_FAILED, no un 422"*). `scopes.attached/moved` also canonicalise the child through your tree before the cycle check, so an alias cannot slip under it.

`ScopeType` is an open `string`, so define your own union for type safety. The engine never queries your tables.

#### The tree outbox, and the relay lag you are accepting

Those three notifications write to the backend **inside your transaction, and they do not roll back with it**. If a later statement of that transaction fails — a constraint, a validation, a pool timeout; no crash needed — your database keeps the old tree and the backend keeps the new one. With the `openfga` driver the backend *is* the PDP, so what is left is a **persistent escalation your own database cannot show you**: every holder with a role in the new parent authorises over a scope that, in SQL, still belongs to the old tenant. This is not misuse; correct use leaks. The suite demonstrates it against a real server — the rollback happens and the escalation stays.

The mitigation is the **outbox port**. Declare `scopes.outbox` and `authorization.scopes.attached/moved/detached` stop writing to the backend: they **enqueue** the change inside your transaction, so the tree change and its propagation commit — or vanish — together. `node ace authz:scopes:relay` applies them afterwards.

```ts
import { sqlScopeOutbox } from '@jantstack/adonis-authz'

const outbox = sqlScopeOutbox()                      // or your own implementation of ScopeOutbox

export default defineConfig({
  scopes: { resolveChain, outbox },
  drivers: {
    openfga: () => new OpenFgaAuthorizationDriver({ /* … */ outbox }),
  },
})

await db.transaction(async (trx) => {
  await authorization.scopes.moved(unit, otherOrg, { within, actor, transaction: trx })
  await unit.useTransaction(trx).merge({ organizationId: otherOrg.uuid }).save()
})
```

```bash
node ace authz:scopes:relay              # drain the queue and apply the edges
node ace authz:scopes:relay --dry-run    # list what is still unpropagated
```

The package **does not impose a table**: the contract is the `ScopeOutbox` port (`enqueue`, `pending`, `markApplied`, `markFailed`, plus two optional ones: `dead` for parked entries and `acquire` for the single-writer lease). `sqlScopeOutbox` is the published implementation over Lucid and `stubs/scopes_outbox_migration.stub` is its migration — **copy it into your migrations yourself**; `node ace configure` does not publish it, because the outbox is opt-in. The only thing an implementation must do is write `enqueue` inside the transaction it is handed.

The relay is resumable and never silent: the report says *which* changes were applied, not a count. A change that cannot be applied **defers what depends on it and lets the rest through**: the failure poisons the scopes that change names, every later change naming one of them is reported as `deferred` and not attempted (transitively), and everything else is applied. That is what keeps the tree order — `attached(P, org)` before `attached(C, P)`, a `moved` before the `detached` of the same node — without letting one tenant freeze the queue for all of them. Until 2.0 the pass stopped at the first failure, and a single change that can never be applied (its parent scope was deleted before the pass) then blocked every later change of every tenant, indefinitely. `sqlScopeOutbox` also **parks** an entry after `maxAttempts` failures (default 5): it stops being retried, it is reported in `dead` on every pass, and the command exits non-zero while any exists — a parked entry is a permanent divergence of the backend's tree, not a resolved incident. The command exits non-zero on any failure too, so a supervisor notices. Applying a queued `detached` runs `purgeScope` and only then removes the edge, and it emits the `scope_purged` audit event at that point, carrying the actor that ordered it.

**The relay is a single writer.** `pending()` reserves nothing, so two passes at once (a Kubernetes `CronJob` with the default `concurrencyPolicy: Allow`, two replicas, a pass that lasts longer than its interval) work on the same batch: the straggler re-applies an old `attached` after the other applied the new `moved`, and the store is left with the **old parent and a single edge, so nothing denounces it** — the old tenant keeps access to a subtree that is no longer theirs (measured). `sqlScopeOutbox.acquire()` takes a lease for the pass — a server-side lock on PostgreSQL and MySQL, a process-wide one on SQLite — and a second simultaneous pass does nothing and says so (`busy`). If you implement the port yourself and skip `acquire`, run the relay one pass at a time.

**What the outbox does not fix, in plain words.** Between your commit and the relay pass there is a lag of **seconds during which FGA decides with the old tree**. What that costs you depends on the change, and the two directions have **opposite signs** (2.0, the `rooted` relation of the `facts` model — see [What a scope that is not attached grants](#what-a-scope-that-is-not-attached-grants)):

- after a `moved` or a `detached` it is a **temporary fail-open**: the **old tenant keeps access** to the moved subtree, and the scope you deleted is only purged when the relay runs;
- after an `attached` it is a **temporary fail-CLOSED**: **a newly created scope grants nothing at all until the relay runs.** Its chain does not reach the root in the store yet, so `can_<P>` is false there for everyone — including the tenant admin you just created it for — and `database` would answer `true`. **The recipe: drain the queue in the same request, right after your commit** (`await authorization.relayScopeChanges()`) on the interactive "create a tenant" path; that shrinks the window to one relay cycle for whatever failed, and nothing else. **Without an outbox the window is zero**: `authorization.scopes.*` calls the driver inline, in your transaction — which is the trade the outbox exists to make.

This is a **breaking change of observable behaviour in 2.0**: until then a not-yet-relayed `attached` *granted*, and **did not inherit the denies above it** — the fail-open the audit found, closing which is exactly what `rooted` buys. Denying for seconds is availability; granting for seconds is the defect this package spent two releases hunting.

There is no two-phase commit between your database and the store, and no outbox can fix this, because FGA does not know it is out of date. This is the structural price of keeping the tree in two places, it is an accepted 🟠 risk of this driver, and a shorter relay cycle shortens that window **only for the changes the queue can actually apply**. A change that fails is not bounded by your cycle: it is retried pass after pass, and once it is parked it is never applied at all. While it is unapplied that node's tree is frozen in the store — a new scope never inherits its denies and a deleted one is never purged — so the window there is as long as it takes you to look. The relay tells you, on every pass and in the exit code (`failures`, `deferred`, `dead`); nothing else will. If that window is not acceptable to you, use the `database` driver, where the tree is never a second copy. (Until 2.2 the `openfga` driver had a second mode, `hierarchy: 'resolver'`, that resolved the chain from your database on every question; **2.3 removes it** — see the changelog.)

Because a port nobody declares mitigates nothing, the `openfga` driver **refuses to be constructed** without `outbox` and without an explicit `acceptScopeDriftRisk: true` — 500 `E_AUTHZ_SCOPE_DRIFT_UNGUARDED`, at construction, not on the first tenant write. `acceptScopeDriftRisk: true` is the signature for a deployment that only moves the tree from the platform, in a process that shares a transaction with nothing; it must be the literal boolean.

#### What a scope that is not attached grants

**Nothing.** The model asks, on every question, whether the scope's chain reaches the root: `can_<P>` = *what your roles grant, minus what a deny takes away, **and only if this scope reaches `app`***. A scope whose chain is broken — the store never got its `attached`, or an ancestor was detached and the subtree was left hanging — grants nothing, whatever bindings it carries. This is the same answer `database` gives for a scope your `resolveChain` does not place under the root (invariant 9), and it is a **breaking change in 2.0**: before, such a scope kept granting *and stopped inheriting the denies above it*, so detaching an intermediate node worked as a bulk `removeDeny` over its whole subtree while every `within` barrier held (the deny was still written — the path by which it was inherited was what broke).

Two consequences you have to plan for:

- **Notify `attached` for every node.** A consumer that materialises paths and only notifies some of its nodes used to get *more* than it asked for; now it gets less. Diagnose it with `authz:reconcile --dry-run`, which lists the scopes that are not reachable from `app`.
- **Publishing the model is not enough: the store needs its root marker.** The reachability of the root is anchored by one tuple per holder type (`scope:app#rooted@<holder>:*`) — **zero per scope**, so the outbox and the relay carry nothing new. `syncAuthzCatalog` writes it (idempotently, and that is also how a holder type added to your config gets one), and `authz:reconcile` reports it as drift if it is missing. **Without it the whole store denies** — fail-closed and loud on the first question, but total; it is the same class of accident as "the model was never published".

### Identity is validated, once and everywhere

`SubjectRef.type`/`uuid`, `ScopeRef.type`/`uuid`, role and permission slugs and `expiresAt` are checked by the manager on every call and again by each driver (the contract suite and third-party drivers bypass the manager). Lowercase letters, digits, `.`, `_`, `-` — **types and uuids alike**: types since 2.0 (a `*_ci` MySQL collation would merge `Users` and `users` into one row while FGA keeps them apart), uuids since 2.1 (the tree of a consumer merges `BBBB…` with `bbbb…` on PostgreSQL's `uuid` type and on MySQL's default collation, and the alias evaded a deny — *"la identidad es una cadena validada por la gramática … un uuid con MAYÚSCULAS … es 422"*; lower-case your ids at your edge: a UUID is the same id in any case); permissions may carry one `:` (`resource:action`); slugs are lowercase and at most **42** characters; `parent`, `binding`, `ancestor`, `rooted`, `role`, `assignee`, `denied` and the prefixes `can_`, `denied_`, `permits_` are reserved; `{ type: 'app', uuid: X }` and the root sentinel uuid outside `app` are rejected — even when your tree knows that sentinel (*"uuid centinela en un scope que el árbol SÍ conoce ⇒ 422"*); `grant`, `revoke` and `listSubjects` take a slug, and a `{ slug, scopeType }` object there is 422 (*"un RoleQuery objeto donde el contrato pide un slug ⇒ 422"*); `expiresAt` is `undefined`, `null` or a valid `Date` (*"expiresAt que no es Date válida, null ni omitido ⇒ 422"*). Violations are **422** (`E_AUTHZ_INVALID_IDENTITY`, `E_AUTHZ_INVALID_SLUG`) before any catalog, tree or backend call — zero queries, spied (*"identidad inválida ⇒ 422"*, *"slug mal formado o reservado ⇒ 422"*, *"una identidad inválida se rechaza con 0 llamadas al backend"*). `assertIdentity`, `assertValidSlug` and `assertExpiresAt` are exported so you can validate at your own edge with the same rule.

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

`onWrite` actions: `granted`, `extended`, `revoked`, `denied`, `deny_removed`, `scope_purged` (no `subject`). Since 2.2 the role-bearing events carry **`roles: CatalogRoleRef[]`** — the *resolved* role(s) (`uuid`, `slug`, `scopeType`, `owner`), not the `RoleQuery` that was asked: a sink that filtered by slug keeps working and now also has the uuid, which is what identifies a role since 2.2. It is a list because a `revoke` by slug removes the facts of every homonym visible in that scope; a `grant` resolves exactly one. It is absent when the role could not be resolved (a scope the tree does not know, a role outside the catalog) — the driver decides the outcome, the event never guesses. It runs *after* the write succeeded, so a hook that throws is logged and swallowed: propagating it would report a failure for an operation that did happen (*"un hook que lanza NO tumba la escritura"*). **It is not free**: resolving those roles costs a **fresh** `resolveChain` (not the `forRequest()` memo) plus a catalog view *per write* — a tree query per `grant`/`revoke` that did not exist before 2.2. Declare `hooks.onWrite` when you want the audit trail, not by default.


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

**Containment.** **All nine writes** — `grant`, `revoke`, `deny`, `removeDeny`, `scopes.attached/moved/detached` and, since 2.2, `defineScopedRole`/`updateScopedRole`/`deleteScopedRole` — accept `within`: the scope being written must be inside it (`within ∈ chain(scope)`, inclusive; `APP_SCOPE` contains everything), checked against your tree *fresh* — the per-request memo is never used to decide a write. What is checked: the target scope for `grant`/`revoke`/`deny`/`removeDeny`; **both origin and destination** for `scopes.moved` — the new parent *and* the child's current chain — and the same for `scopes.attached` when the child already exists in the tree (attaching an existing node *is* a move; a new node only checks the parent); the child itself for `scopes.detached`; the role's **owner** for `defineScopedRole`/`updateScopedRole`/`deleteScopedRole`. Outside ⇒ 422 `E_AUTHZ_NOT_WITHIN`, nothing written, nothing purged, the driver not called. It is what stops "the admin of organization A grants in a unit of B by passing its uuid" — and, just as much, "removes B's deny" (removing a deny *is* granting), "revokes B's role", "purges B's unit" or **"moves B's unit under A"** (annexing a subtree inherits everything in it: worse than purging it) (*"within en las otras cuatro escrituras"*, *"within contrasta también el ORIGEN de scopes.moved/attached"*). Because the origin is read from your tree, notify `scopes.moved` **before** you re-parent the row, exactly as `scopes.detached` goes before the delete.

```ts
await authorization.grant(user, 'unit-editor', unit, { within: currentOrg })
await authorization.removeDeny(user, 'docs:read', unit, { within: currentOrg })
await authorization.scopes.attached(newUnit, parentUnit, { within: currentOrg })   // the parent must be inside
await authorization.scopes.moved(unit, otherUnit, { within: currentOrg })          // origin AND destination inside
await authorization.isWithin(unit, currentOrg)   // the same question on its own
```

> **`within` must come from the session, never from the request body.** `within = scope` (or the scope's own parent) satisfies the rule *by definition* — the chain always contains the scope itself — so a `within` taken from the same input as the scope is no containment at all; `'non-root'` closes the `app` wildcard, not that one. Take it from the authenticated tenant (`currentOrg` above: the organization the session belongs to), and let the request only name *what* inside it to write.

`requireWithin: true` in the config makes any of the nine writes without `within` a 422 `E_AUTHZ_WITHIN_REQUIRED`. `requireWithin: 'non-root'` additionally rejects `within: APP_SCOPE` with 422 `E_AUTHZ_WITHIN_ROOT_FORBIDDEN`: the root contains everything, so as a containment it says nothing — it was the wildcard a tenant call-site could pass to satisfy the rule without naming its tenant. Platform code that really writes at the root uses `manager.driver()` (below) or a config without the flag. **The default is `false` — containment is opt-in in 2.1** and the manager warns once per config at construction (`warnOnOptInSecurity: false` silences it once you have decided). Same for `requireActor`.

**Actor.** Every write (`grant`, `revoke`, `deny`, `removeDeny`, `scopes.*`) takes `{ actor }` — a `SubjectRef`, validated like any identity — which `onWrite` receives as `event.actor`. `requireActor: true` ⇒ a write without it is 422 `E_AUTHZ_ACTOR_REQUIRED` before the driver and before the hook. No `AsyncLocalStorage`: the actor is an explicit argument. For these six writes the engine never evaluates it (who may grant what is your policy) — **but the delegation API of 2.2 does**: there the `actor` is the whole policy, so it must come from the session and never from the request body. See [Scoped roles](#scoped-roles-22).

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

### Per-resource enforcement: `resourceAccess` (2.5)

`appAccess` gates a route at the `app` scope. To gate one **resource** — *this document, in that
organization* — the `resourceAccess` middleware composes the same `authorize`: your code says how to
load the resource and which `{ scope }` it lives in, and the middleware asks the engine about that
scope. It is not a new model or a driver, it is the HTTP edge of a resource's scope.

```ts
router
  .get('/orgs/:orgId/documents/:id', [DocumentsController, 'show'])
  .use(middleware.resourceAccess({
    resource: 'document',            // ctx.document = the loaded resource, for the controller
    param: 'id',                     // ctx.params.id
    containerParam: 'orgId',         // optional: the tenant/parent in a nested route
    permission: 'documents:write',   // mutating methods
    readPermission: 'documents:read',// safe methods (GET/HEAD); omitted ⇒ reads still need `permission`
    load: (ctx, id) => Document.query().where('id', id).first(),   // → { scope } | null
    gate: (ctx) => ctx.auth.user!.isMemberOf(ctx.params.orgId),    // optional pre-ability
  }))
```

**The order of the responses is the security property** — a 403 where a 404 belongs leaks which
resources exist (enumeration):

1. **401** if there is no authenticated holder;
2. **403** if your optional `gate(ctx)` (a prior ability, e.g. "is admin of this tenant") denies;
3. **404** if the declared `containerParam` is absent from the route;
4. **404** if `load` returns `null` — **the same body** as the container 404, so "does not exist" and
   "not yours" are indistinguishable;
5. `authorize` **once** over the scope `load` returned (with `readPermission` on safe methods): a
   `false` here is **also a 404 with the same body**, never a 403 — that you cannot see it does not
   reveal that it exists.

The non-negotiables mirror `appAccess`: `AuthorizationBackendError` (503) is **never disguised** as a
404/403 (if `gate`/`load`/`authorize` throw, the error rises as-is — "denied" and "could not check"
stay distinct, so these calls are deliberately not wrapped in try/catch); **`role` is forbidden**
(`resourceAccess({ role })` is a 500 `E_AUTHZ_ROLE_IS_NOT_ACCESS` with the recipe, because membership
is not access and the deny does not govern it); and there is **no second `authorize`**. A throw from
`load` is "could not check" (503), never a 404. The middleware imports no consumer alias — `load`/
`gate` arrive injected in the route options.

> **Known limit — a timing channel.** The status and body of "does not exist" and "exists but is not
> yours" are identical, but the **time** is not: a non-existent id answers 404 without a round-trip to
> `authorize`, a foreign one answers the same 404 *after* that call. This is inherent to
> `load → authorize` (you cannot authorize the scope of something you have not loaded), not a defect;
> whoever needs to close the channel equalises the time in their own layer (a constant delay), not in
> the middleware.

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
node ace authz:catalog:diff --fail-on-shadows   # …and on roles shadowed by a more authoritative one
node ace authz:catalog:prune-orphans   # list local roles whose owner scope is gone (--force to purge)
node ace authz:scopes:relay            # drain the scope-tree outbox (see The scope tree)
node ace authz:reconcile --to=openfga --dry-run   # verify a driver against authz_* and your tree (exit 1 on drift)
```

`syncAuthzCatalog(spec, { prune: 'links' | 'none', timeoutMs })` is idempotent and transactional. The default **prunes**: for every role *of the spec*, role→permission links the spec no longer lists are deleted in the same transaction, so removing a permission from a role in config removes it from every environment on the next sync (*"quitar un permiso de un rol y re-sincronizar el catálogo lo retira: sin privilegios zombi"*, a contract case in both drivers). Roles and permissions are never deleted (they carry assignments), and roles outside the spec are untouched, so two catalogs — platform and tenant — coexist (*"dos catálogos coexisten"*). **A role `(slug, scopeType)` and a permission belong to exactly one catalog**: `authz:catalog:sync` and `authz:catalog:diff` resolve every catalog first and refuse, before writing anything, if two of them declare the same one (422 `E_AUTHZ_CATALOG_CONFLICT`) — otherwise the second sync would prune the first catalog's links in silence (*"un rol o un permiso declarado en dos catálogos es 422 E_AUTHZ_CATALOG_CONFLICT, sin escribir"*). A role granting a permission that exists in no catalog is 422 `E_AUTHZ_UNKNOWN_PERMISSION`; a permission from an earlier catalog in `config.catalogs` is fine, so order matters. The whole catalog is validated before anything is written: slug grammar, `scopeType` as a scope identity, and collisions after encoding (`docs:write` vs `docs_write`) — within the spec **and against the permissions already in the database** (*"la colisión tras codificar se comprueba también contra los permisos ya en la base"*). A database that does not answer during sync or diff is a 503 `E_AUTHZ_BACKEND_UNAVAILABLE`, not a raw driver error (*"el catálogo con la base caída es 503"*).

**Global roles win, and nothing is silent (2.2).** A spec only ever declares **global** roles (`owner_scope_key = 'global'`), and a local role with the same `(slug, scopeType)` no longer stops the deploy: until 2.2 the sync answered 422 and **rolled the whole catalog back**, so a tenant admin with rank 2 could stop the platform's deploy for ever by squatting a name. The sync now writes the global — it wins — and **reports** every local role it shadows (`shadowedByGlobal: CatalogRoleRef[]`, printed as a warning by `authz:catalog:sync`); from then on, **inside that chain the name is unusable by slug for everyone — the platform included**: `grant`, `hasRole` and `listSubjects` by slug answer 422 `E_AUTHZ_AMBIGUOUS_ROLE` there, so onboarding your *own* global role in that tenant needs `{ uuid }` (measured: 5 of 5 shadowed slugs, audit N4). Outside that subtree the slug keeps working, and nothing escalates — a fact points at a role's uuid, so the local role's holder never inherits the global's permissions. The form that always works is `{ uuid }`; the way back is purging one of the two. `listRoles` returns **slugs**, so a shadowed pair is indistinguishable there (`['soporte']` for both holders, with different effective permissions): branch on permissions, or read the identity with `rolesInChain`/`{ uuid }`, never on a role name. `defineScopedRole` still refuses collisions **upwards** (global, or a local of an ancestor); a local of a *descendant* is shadowed instead — see [Scoped roles](#scoped-roles-22). Narrowing a permission's `assignableAt` is reported the same way: the sync revalidates **every** role that already carries it — local ones and globals from another catalog — and lists the links the new restriction no longer admits (`assignableAtViolations`) instead of leaving them in place in silence; it does not delete them (what is assigned keeps granting, invariant 1), so you decide. `assignableAtViolations` is drift for `authz:catalog:diff` (exit ≠ 0); the shadows are **not** — they are listed and the command exits 0, because a tenant who squats a name must not be able to keep the platform's CI gate red (audit N1). If you would rather know from CI (the shadows mean the by-slug routes of that subtree are dead for you too), `authz:catalog:diff --fail-on-shadows` counts them as drift for that run (audit P5).

`authz:catalog:diff` lists missing permissions/roles/links, surplus links, rank and `assignableAt` mismatches, the two reports above, and **homonym roles** — two roles with the same `(slug, level)` visible from one chain, which make every by-slug question there a 422 (the global+local pair is always detected, the local+local pair needs your `scopes.resolveChain`, which the command passes). Those are classified by authority: `shadowedByGlobal` and `shadowedByAncestor` are *listed* and exit 0 (`--fail-on-shadows` makes them drift too), and only what authority cannot order (`ambiguousRoles`) is drift — (`diffAuthzCatalog` / `runCatalogDiff` are exported for your own checks). The shadows of **every** catalog are printed, deduplicated (2.3: only those of the first were), and `shadowedByAncestor` carries **one entry per shadowed role**, naming the most authoritative shadower — with nested owners `a > b > c` you get two lines and not three. It also lists the roles that scopes defined for themselves as *"propios de un scope"* — informative, never surplus. The sync never touches a local role's links or rank (*"el sync solo toca roles GLOBALES"*), and a corrupt `assignable_at` row is reported as a difference — the diff exists to *report* it, so it no longer dies with a 500 in the very deploy that would repair it. A permission may carry `assignableAt` — the levels whose roles can carry it — see [Scoped roles](#scoped-roles-22).

## Scoped roles (2.2)

A role has an **owner**: `global` — declared in config and synced with `syncAuthzCatalog` — or the scope that defined it with `defineScopedRole(actor, ownerScope, spec)`. One rule, in both drivers: *an assignment in scope S of role R counts if and only if R is global or R's owner is in chain(S)* (S inclusive). Outside its owner a local role does not exist: it grants nothing, is no membership (`hasRole`, `listRoles`, `listSubjects`, `listRoleScopes`, `listScopes`, `effectivePermissions`, `authorizedScopes` all apply the rule) and cannot be granted (422 `E_AUTHZ_ROLE_NOT_VISIBLE`, nothing written). Moving a unit out of the owner's subtree **retires** what the local role granted there, and moving it back restores it — the tree of *today* decides. **How that retirement happens depends on the driver (2.3, breaking):** in `database` it costs no write at all (the rule is evaluated on every question). In `openfga` the model has no `owner`, so a `role_binding` would keep granting while its scope is reachable — a fail-open — and the package therefore **writes**: `scopes.moved` sweeps the `scope#binding` edges of the local roles whose owner is no longer in the chain, across the **whole moved subtree**, and rewrites them when the owner is in the chain again. Global roles are never touched, and neither is a local role whose owner is still an ancestor. That write follows the same path as any other tree change: with `scopes.outbox` it is applied by `authz:scopes:relay`, so it inherits the [temporary fail-open of the relay lag](#the-tree-outbox-and-the-relay-lag-you-are-accepting), and `authz:reconcile --to=<the driver you are serving from>` reconciles it if the relay was lost — that pass reads the facts from the store itself, recomputes the same rule with the tree and the catalog of *today*, deletes the `scope#binding` edges the rule forbids and writes the ones it requires, and counts them in `drift.roleVisibility` (see [whoever owns the facts](#migrating-and-verifying-authzreconcile-23); before 2.3's last cut it rebuilt from `authz_*`, which in a `facts` deployment hold no facts at all, so the sweep never ran and the report said `0`) (*"un rol local de la organization A concede en A y sus units, no en B ni en app"*). **The same is true of a role's level** (2.3): the (c2) model does not carry `scope_type` either, so changing the level of a role — an assignment stays where it is, but the role is no longer declared for that kind of scope — is retired in `database` by evaluating the rule again, and in `facts` by the same sweep, run from `projectCatalogRole` (the package calls it after `defineScopedRole`/`updateScopedRole`; a process that writes `authz_*` by hand owes it the same call it already owed for the permission mirror). **What this makes the `scope#binding` edge mean, plainly: "the role is visible here", not "this assignment exists".** The assignment itself is the `assignee` tuple, which no sweep ever touches — which is why `hasRole`, `listRoles` and `listSubjects` still enumerate assignments and filter them through the catalog, and answer exactly as they did before. Two tenants may each define `lead@unit` with different permissions: the slug no longer identifies a role, the uuid does, and nothing crosses tenants (*"dos tenants definen el mismo slug"*). A deny anywhere in the chain still wins over a local role (invariant 2).

**A local role never lives *above* its owner.** A role whose `scopeType` is the level of one of the owner's **ancestors** (`app` included, which is in every chain) is visible nowhere: it grants nothing, is nobody's membership and cannot be granted — all it does is occupy that `(slug, level)` for the owner of the tree and for the global catalog, which is squatting with the shape of a spec (like `permissions: []`). It is 422 `E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER`, in `defineScopedRole` and in `updateScopedRole` — a row that already has an impossible level is not perpetuated either; purge it. The rule is decided with the owner's chain, which is already resolved, so it costs nothing and needs no extra configuration: the owner's own level is fine and **any other level is assumed to be below** — delegating downwards (`lead@unit` owned by an organization) keeps working with the published config stub. If you do declare `scopes.descendantsOf`, the check is **tightened**: the level must actually appear below the owner in today's tree — and if that subtree cannot be enumerated (more nodes than `maxDescendants`, or a `descendantsOf` that fails) the check **degrades to the minimal rule** instead of failing: *declaring `descendantsOf` must never leave you worse off than not declaring it* (audit N3, where a tenant with more units than the bound could no longer delegate downwards at all). **Be explicit about what that degradation costs** (audit P4): the strong check is a control the watched subject can switch off — creating scopes is a normal product feature, so an actor who creates more than `maxDescendants` children of their own scope gets the minimal rule back — and it also switches itself off when the resolver is down. That is deliberate and bounded: the minimal rule is the one every consumer runs with the published stub, it never grants anything, and the residual damage is squatting a `(slug, level)` that stays repairable by **authority plus rank** — an ancestor defines its own role and shadows it (below) **only if its rank is above the squatter's**. Ranks are your metadata (invariant 8) and nothing forces them to decrease with depth, so with a non‑monotonic layout — a rank‑60 role in a unit under a rank‑50 organization admin who owns that tree — the owner of the tree gets 422 `E_AUTHZ_RANK_EXCEEDED` from **both** doors (defining its own homonym and `deleteScopedRole`), and `scopes.detached` is not a third door either (since 2.3 it purges facts and never the catalog). The recourse is then the **platform**: whoever carries the highest‑rank global role outranks every local role by construction (`0 < rank < min(actor, highest global rank)`), and `manager.driver().purgeRole(uuid)` always works (audit D1). If that trade is not acceptable for you, keep `maxDescendants` above the size of your biggest subtree.

**The slug is a name, the uuid is the identity.** Since a role can be local, `RoleQuery` — what `grant`, `revoke`, `hasRole` and `listSubjects` take — has three forms: a slug, `{ slug, scopeType }` and, since 2.2, **`{ uuid }`**. If two roles with the same `(slug, level)` are visible from the same chain — a `scopes.moved` that joins two subtrees, or a local one living next to a global one — the two name-based forms fail **closed** with 422 `E_AUTHZ_AMBIGUOUS_ROLE`, naming every uuid and owner; `{ uuid }` is the only form that answers (the role must be visible in that scope, else 422 `E_AUTHZ_ROLE_NOT_VISIBLE`). Choosing one — "the closest owner wins" — is what let the admin of A hand out B's role by the same slug, so ambiguity is an error, not a resolution rule. `authorize` never addresses by slug and keeps answering; `listRoles` is a membership API and keeps returning slugs (which may therefore have homonyms — the unambiguous form is `{ uuid }`, and `rolesInChain` in the port returns `uuid`, `slug`, `scopeType` and `owner`). `revoke` by slug does not choose either: it removes the facts of **every** homonym in that exact scope (removing never grants). `authz:catalog:diff` lists such pairs, classified by **authority** (global > local of an ancestor > local of a descendant): the ones authority orders are `shadowedByGlobal`/`shadowedByAncestor` — listed, exit 0, because a tenant must not be able to keep your CI gate red; pass **`--fail-on-shadows`** if you *do* want your pipeline to stop on them (they mean the slug routes of a whole subtree are dead, yours included) — and only a pair nothing orders (two owners each claiming to be the other's ancestor: a `resolveChain` with a cycle or that contradicts itself) stays `ambiguousRoles`, which is drift (exit ≠ 0). **The way out is purging, not renaming**: `updateScopedRole` changes `name`, `description`, `rank` and `permissions` and never the slug, so a tenant caught in an ambiguity keeps operating with `{ uuid }` and someone with enough rank purges one of the two (`deleteScopedRole`, or the platform with `manager.driver().purgeRole(uuid)`). If a `scopes.moved` dropped a high-rank homonym into a tenant with a lower rank, only the platform can undo it.

**The uniqueness is enforced, not hoped for.** Every write to `authz_*` goes through `withAuthzCatalogWrite`, which locks the `authz_catalog_version` row first (PostgreSQL/MySQL; SQLite already serialises writes) and bumps it last, so catalog writers run one at a time; `defineScopedRole` re-checks the collision **inside** that transaction against the database, not against the memo. Two concurrent `defineScopedRole` of the same `(slug, level)` **for the same owner** end with exactly one role and a 422 `E_AUTHZ_CATALOG_CONFLICT` for the loser (a contract case in PostgreSQL and MySQL, where the row lock serialises catalog writers — capability `serializedCatalogWrites`; SQLite serialises by locking the whole database, so the loser's transaction may instead die with a 503, and the judge only requires that it never writes). If the two owners are in an **ancestor→descendant** relation the race has *two* legal endings and which one you get depends on who commits first (milliseconds decide it): if the ancestor's commits first the descendant's is 422; if the descendant's commits first the ancestor's no longer collides — it is written and **shadows** it (authority, 2.2), so you end with two roles and that slug ambiguous inside the descendant's subtree. Both endings are loud; neither writes twice for one owner. **The 422 is what you get when the loser reaches the lock; if it *waits* on the lock past the deadline it gets 503 `E_AUTHZ_BACKEND_TIMEOUT` (`catalog.lock`) without writing** — fail-closed and retryable, but it is a 503, not a 422 (audit N6). Keep the critical section short: it holds while a `syncAuthzCatalog` runs, so a big deploy makes that 503 likelier for concurrent `defineScopedRole` (2.2 batches the shadow lookup into one query for exactly this reason; the `assignableAt` revalidation is already a single one). A `defineScopedRole` racing a `syncAuthzCatalog` has **two** legal endings, both loud: if the sync commits first the define hits the global and is 422; if the define commits first the sync writes the global anyway and reports the local role it shadowed (`shadowedByGlobal`). What can never happen is a local role that nobody mentions.

**When a scope disappears, its roles fall asleep — and the platform sweeps them.** `scopes.detached(child)` purges **facts and only facts** (invariant 11): assignments and denies of that exact scope, under the canonical `chain[0]` like everything else (invariant 17), and it never writes the catalog. The local roles owned by that scope stay in `authz_roles` **dormant**, and *dormant* means exactly this: **the role is not visible from any live scope whose chain does not pass through its owner**. It does **not** mean the role stops granting. The single visibility rule (invariant 18) asks the owner to be in the chain of the scope you are asking about, and **a live descendant whose materialised path still goes through the owner satisfies it** — there the role grants, is a membership on all six read paths and *can be granted*, by slug and by uuid (measured, audit of 2.3). That is the normal shape of a two-step delete, or of any consumer with materialised paths: the owner's row is gone, its children are not. So: a dormant role grants nothing **in a scope whose chain no longer reaches the owner**, and a dormant role with no live assignments grants nothing at all — but "dormant" is not a synonym for "inert". What it does in every case is occupy its `(slug, level)` wherever it is still seen, and `deleteScopedRole` cannot reach it — it resolves the owner fresh and answers 422 `E_AUTHZ_UNKNOWN_SCOPE`. That is what the sweeper is for:

```bash
node ace authz:catalog:prune-orphans           # dry run: lists the local roles whose owner no longer resolves
node ace authz:catalog:prune-orphans --force   # purges them (purgeRole each: assignments + links + row), notifies role_purged
node ace authz:catalog:prune-orphans --force --allow-mass-purge   # ... even if that is *every* owner (read the next paragraph first)
```

It is a **platform** operation — a maintenance command with access to the catalog, like `authz:catalog:sync` — so it takes no actor and measures no rank, exactly like the `purgeRole` of last resort. `manager.pruneOrphanRoles({ force })` is, next to `manager.driver()`, **platform API**: it deliberately bypasses `requireActor` and `requireWithin`, so it belongs in a command or a maintenance job, never behind an HTTP controller. `--dry-run` is the default: nothing is written until a human has read the list. Because a dormant role may still be granting, every orphan is reported with `assignments` (live facts) and `stillGranting`, and the command lists those **apart, with a warning** — purging them revokes permissions that work today. The flag is conservative: it counts live facts and does not check whether each fact's scope still resolves, so `false` means "grants nothing, for sure" and `true` means "look before you force". **Those facts are counted by the driver** (`countRoleAssignments`, 2.3), because facts belong to the driver: counting rows of `authz_assignments` from the sweep meant that with `openfga` — where facts live in the store — `stillGranting` was *always* `false`, which is the one answer that must never be wrong here. A driver that does not implement it leaves both fields **`undefined`, never `false`**, and the command lists those orphans apart too, with their own warning: "I don't know" is not "it does not grant" when the next step is a delete. The roles are read **from the database**, not from the catalog memo (with `catalogRevalidate: { everyMs }` a role another process has just committed is not in your snapshot), in a stable order by uuid, so the list and the `role_purged` events reproduce identically on PostgreSQL, MySQL and SQLite, and no more than `maxLocalRoles` (10 000) of them (500 `E_AUTHZ_TOO_MANY_LOCAL_ROLES`, never a partial list). A second pass is a no-op. A driver without `purgeRole` says 500 `E_AUTHZ_UNSUPPORTED` before reading anything.

**Two safeties, because the dangerous input is your own resolver.** The realistic accident is not someone calling the method by hand: it is a `scopes.resolveChain` **filtered by the request's tenant** — a normal multi-tenant pattern — or running with no context at all (a command, a lagging replica). It answers `null` for everything, so *every* local role looks orphaned and one `--force` pass deletes the local catalog of every tenant (measured: 2 of 2 live roles). So (a) if **all** distinct owners come out orphaned, or the orphans are more than **50 %** of the local roles, `force` is 500 `E_AUTHZ_MASS_PURGE_REFUSED` **before deleting anything**, naming the ratio; a real large prune passes `allowMassPurge: true` (`--allow-mass-purge`), which is a human decision, not a default (the dry run does not throw — it is the diagnostic you need to be able to read — it reports `massPurge: true`). And (b) each owner is re-resolved **fresh immediately before its own `purgeRole`**: the window between reading and deleting is the whole pass, not an instant, so a concurrent `scopes.attached` or restore would otherwise delete a role whose owner is back. A role whose owner came back is skipped and reported (`skipped: [{ role, reason: 'owner-came-back' }]`). The set is not atomic — it does not need to be — so the report says **which** roles were purged (`purged: CatalogRoleRef[]`), not how many: if one `purgeRole` fails halfway, the previous ones are already gone, and with the above that can be a partial revocation of live permissions.

**Facts of live descendants survive `detached`, and wake up with the scope.** `scopes.detached` purges the facts of the **exact** scope; an assignment held in a *descendant* whose path went through it is not touched (invariant 11 — you purge each node of the branch you delete). While the branch is gone those facts grant nothing, because the descendant does not resolve either; but if the scope is **restored with the same uuid** (an undelete, a restore from the bin, re-creating the unit) the facts grant again, with no write of any kind. Between 2.2's first cut and 2.3 the role took its assignments with it, so this is a change of behaviour, and it is deliberate: the tree of *today* decides (invariant 18). If you want those facts gone, delete them by notifying `detached` for every node of the branch, or run `authz:reconcile --to=<driver> --prune` (2.3), which reports — and, with `--prune`, deletes — the facts whose scope no longer resolves.

**Why it is not `scopes.detached`'s job (2.3).** Between 2.2's first cut and its close, `detached` also purged the roles owned by the scope and — with `descendantsOf` — those of the whole subtree. That put a *catalog* write at the end of an operation a **tenant** triggers, about a scope that no longer resolves, so it needed a rank policy with no chain to measure it on, a subtree enumeration and a degradation for when that enumeration fails. Five batches touched it and **three of the four regressions of that phase were born there**, every time by composing pieces that were correct on their own — the last one destroying local roles of **live** descendants that both other doors refused with 422 (audit P1). None of those pieces exists any more: `detached` is O(1) again, and the cleanup happens where nobody is racing anybody.

```ts
// config/authorization.ts — the platform declares what may be delegated at all:
delegablePermissions: ['docs:read', 'docs:write', 'billing:read'],

// An organization admin (the actor) defines a role that exists only inside orgA and its descendants:
const lead = await authorization.defineScopedRole(admin, orgA, {
  slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'],
})                                                                   // { uuid, slug, scopeType, owner: 'organization|<uuid>', rank }
await authorization.grant(bob, 'lead', unitA1, { within: orgA })     // unitA1 is under orgA
await authorization.grant(bob, 'lead', unitB1, { within: orgB })     // 422 E_AUTHZ_ROLE_NOT_VISIBLE
await authorization.updateScopedRole(admin, lead.uuid, { permissions: ['docs:read'], rank: 25 }, { within: orgA })
await authorization.deleteScopedRole(admin, lead.uuid, { within: orgA })  // purges every assignment, then the role
await authorization.grant(bob, { uuid: lead.uuid }, unitA1, { within: orgA })  // the unambiguous form
```

**Policy — write-time, mandatory, checked before anything is written.** The `actor` is required (422 `E_AUTHZ_ACTOR_REQUIRED`, whatever `requireActor` says: without it there is no policy to evaluate). **It must come from the session, never from the request body** — the same rule as `within`, and here it matters more: the package only validates the actor's *grammar*, and everything the delegation policy allows is measured against that identity. An endpoint that forwards `req.body.actor` lets anybody delegate anybody's permissions. The owner is a real scope that is not the root (the root's roles are global: config + sync) and the role's level is not `app`. Every permission must be in `config.delegablePermissions` (a whitelist; `[]` by default, so nobody delegates anything until the platform says what — platform permissions should not be in it), exist in the catalog, be composable at that level (`assignableAt`, below) and be **effective for the actor in the owner** — granted by a role of theirs along the owner's chain and not denied there; a deny is not laundered by composing a role for a puppet (security panel C2) — else 422 `E_AUTHZ_PERMISSION_NOT_DELEGABLE`. `0 < rank < min(actor's rank, highest global rank)`, else 422 `E_AUTHZ_RANK_EXCEEDED` — the actor's rank is the highest `rank` among their visible roles along the owner's chain, so an actor whose roles have rank 0 delegates nothing. No **more authoritative** role `(slug, scopeType)` may be visible where the new one would be — global, or local to an ancestor (or the owner itself) — else 422 `E_AUTHZ_CATALOG_CONFLICT`; sibling organizations may share a slug. A homonym local to a **descendant** is *not* a conflict since 2.2: **a more authoritative definition wins and shadows the less authoritative one** (global > local of an ancestor > local of a descendant), so the owner of the tree can always define their role even if somebody below took the name first, and the squat only shadows itself. **Shadowing also takes rank**: the actor's rank must be *above* the rank of every role they would shadow, else 422 `E_AUTHZ_RANK_EXCEEDED` and nothing is written — and `updateScopedRole` on a role that already shadows one asks the same. Shadowing is as destructive as deleting (inside the shadowed role's subtree that slug becomes 422 for everyone, and the victim cannot undo it: their rank is measured on the chain of the *shadowing* role's owner, where they are nobody), so it follows the one rule the rest of the API follows — *you only act on a role you outrank* — instead of position alone: without it a rank-3 actor in an organization made a rank-40 unit role unusable by slug for good (audit P3′). The 422 does not name the shadowed role's rank or owner: an ancestor does not get to enumerate what is below it (same rule as `E_AUTHZ_AMBIGUOUS_ROLE`). **Read that rule as what it is: a check performed when the catalog is written, not an invariant of the system** (audit D3). Whether one role shadows another is a function of *today's tree*, and the tree moves without asking the catalog: `scopes.moved` can drop a subtree under an organization that already holds a homonym and a shadow appears with **no rank judged anywhere** — the owner of the moved subtree may then be unable to repair it, because their rank is measured on the chain of the shadowing role's owner, where they are nobody (only the platform can undo that one). The same happens in a narrower window at write time: if `scopes.resolveChain` does not answer for the victim's owner at that instant, the shadow cannot be proved and the write goes through (audit D2) — deliberately, because refusing would turn a **dormant** role into a lock on its `(slug, level)`, which is precisely the mine 2.3 removed. Both are loud (`authz:catalog:diff` lists them as `shadowedByAncestor`, `--fail-on-shadows` makes them drift) and neither grants anything: `authorize` never addresses by slug. And note the honest limit of the check itself — it only protects roles that **already exist**: the same actor gets the same denial by simply **going first**, which has always been free. The shadowed roles come back in the `role_defined` event (`shadowedByAncestor`) and `authz:catalog:diff` lists them without counting them as drift. Inside the descendant's chain that slug is then 422 `E_AUTHZ_AMBIGUOUS_ROLE` for everyone and `{ uuid }` is the form that answers — the same deal as with a global, and nothing grants more (a fact points at a uuid). Before 2.2 this was 422 and it was the last shape of the slug mine: a rank-5 actor could take a name from the tree owner for good and keep `authz:catalog:diff` — the CI gate of the deploy — red until someone purged role by role (audit N1). `permissions: []` is 422 `E_AUTHZ_INVALID_IDENTITY`: a role that grants nothing only occupies its owner's `(slug, level)`. `updateScopedRole` takes `name`, `description`, `rank` and `permissions` — **never** slug, level or owner, and passing one of those is 422 `E_AUTHZ_INVALID_IDENTITY` rather than a silent no-op; a no-op change writes and notifies nothing — and it and `deleteScopedRole` additionally require the actor's rank to be **above** the role's, and a global role is 422 `E_AUTHZ_ROLE_IMMUTABLE` (change the config and sync). All three take `ScopedWriteOptions` (`within`, `actor`) like the other six writes: `requireWithin` covers them and the scope checked is the role's owner. `rank` remains metadata for `authorize` (invariant 8): all of this is composition and delegation policy, never evaluation.

The three resolve the owner's chain **fresh** — never through a `forRequest()` memo: a unit that moved to another tenant during the request cannot receive a role delegated by the old tenant's admin (C3), and the owner is written with the tree's canonical identity — write through `withAuthzCatalogWrite` (the shared catalog version bumps as the last statement of the same transaction, so every other process sees the new role on its next question; the contract observes it with a second catalog memo) and notify `hooks.onCatalogWrite` (`role_defined` / `role_updated` / `role_purged`, always with `actor`, the role, its owner and its permissions; a hook that throws is logged, the write stands). `deleteScopedRole` goes through the port's `purgeRole(roleUuid)`: every assignment of the role in every scope, its links and the row, atomically, so re-creating the slug revives nothing (`database`). `purgeRole` is **optional** in the port: a driver that cannot purge roles simply does not implement it (the `openfga` driver until 3b — it cannot enumerate a role's bindings by role without reading the whole store — capability `purgeRole: false`). Then `defineScopedRole` is **500 `E_AUTHZ_UNSUPPORTED` before writing anything**: a local role that nothing could ever delete would leave `deleteScopedRole` and `authz:catalog:prune-orphans` dead for ever. State that cannot be undone is not created. If such rows exist anyway, the way out is deleting them yourself — the catalog is always SQL and it is yours. Two ways to get there: rows written by hand or by a migration, and **switching the deployment's driver to one without `purgeRole`** (the catalog is shared SQL, so roles created under `database` are still there under `openfga`). That second one freezes the *catalog* of every scope with a local role — `deleteScopedRole` is 500 and you cannot define another role there — but not the facts: `scopes.detached` never needed `purgeRole` since 2.3 and purges the scope normally. The recipe, verified (audit N7):

```ts
// One-off, from a command: purge with a driver that can, then carry on with the new one.
const sql = new DatabaseAuthorizationDriver({ resolveChain })   // whatever your config/authorization.ts passes it
for (const uuid of roleUuids) await sql.purgeRole(uuid)         // assignments + links + row, atomically
await authorization.scopes.detached(scope)                      // the facts, with any driver
```

Plan the driver switch like a fact migration (`authz:reconcile`), and treat "this deployment has local roles" as a reason not to move to a driver without `purgeRole`. Without `listDenies` in the port, `defineScopedRole` and a permission change in `updateScopedRole` are 500 `E_AUTHZ_UNSUPPORTED` too: the policy subtracts the actor's denies and will not assume there are none.

**`assignableAt` — composition, never evaluation.** A permission may declare the levels whose roles can carry it: `{ slug: 'org:settings', assignableAt: ['app', 'organization'] }`. `syncAuthzCatalog`, `defineScopedRole`/`updateScopedRole` and — for links written by hand — `grant` reject a role of another level carrying it (422 `E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT`, nothing written). `authorize` **never** looks at it: an assignment that exists keeps granting what its role links (invariant 1), pinned by a contract case in both drivers (*"assignableAt es control de COMPOSICIÓN, jamás de evaluación"*). It covers "a unit role must not carry `org:settings`" without a permission that stops inheriting downwards. The config wins over the stored value; `authz:catalog:diff` reports the drift.

**A note for driver authors (fragility, like the one about the owner rule in `authorize`).** Two of the sharpest rules here hang on a *single* contract case per harness: the owner check inside `authorize`, and the ambiguity rule of `RoleQuery` (a driver with its own `roleVisible` can pass 82 of 83 cases with the escalation inside). If you refactor either path, do not trust a green suite alone — read the case, and add one of your own.

Storage: `authz_roles.owner_scope_key varchar(80) NOT NULL DEFAULT 'global'` with `unique(slug, scope_type, owner_scope_key)` and an index by owner — the key is `<type>|<uuid>`, the same `scopeKey` as the OpenFGA binding ids (exported, with `scopeFromKey`); `'global'` is reserved and no scope produces it (the root gives `app`, everything else carries `|`); any other value — `app` included, which would be visible in *every* chain: a global in disguise the sync does not govern — is a corrupt row, 500 `E_AUTHZ_INTERNAL` — and `authz_permissions.assignable_at` (a JSON list, `NULL` = any level; it must fit in `varchar(500)`, checked at write time with 422, so a truncated value can never turn every `view()` into a 500; a corrupt value is 500 `E_AUTHZ_INTERNAL`, never "any level"). A 1.x row is global after the [upgrade recipe](#operational-notes-for-the-sql-engines) and the next sync recognises it as the same role.

## Relations (ReBAC) (2.4)

Alongside role-based `authorize`, the package ships a **separate** relationship engine for
object-level sharing — the Drive case: *this document is shared with that user as `viewer`, with
that team as `editor`*. It is a distinct port (`RelationsDriver`), a distinct façade
(`RelationsManager`) and a distinct config (`defineRelationsConfig`); roles and relations never
answer each other's questions.

```ts
const relations = defineRelationsConfig({
  holderTypes: ['user', 'admin'],
  objectTypes: [
    { type: 'document', relations: [
      { name: 'owner' },
      { name: 'editor', includes: ['owner'] },   // includes, no `from` in v1
      { name: 'viewer', includes: ['editor'] },  // editor ⊆ viewer
    ] },
  ],
  database: { membersOf: true },   // membersOf is database-only (see below)
})

await rel.relate(user, 'viewer', { type: 'document', id }, tenant)                 // share with a user
await rel.relate({ object: team, relation: 'member' }, 'editor', doc, tenant)      // share with a TEAM (userset)
await rel.relate(guest, 'viewer', doc, tenant, { expiresAt: new Date(Date.now() + 7 * 86_400_000) }) // time-boxed share
await rel.check(user, 'viewer', doc, tenant)   // one Check; editor⊆viewer resolves server-side
```

**Relation expiry (2.4.0-alpha.2, R-15).** A relation tuple may carry an `expiresAt`, with the
**same three states as `grant`** (invariant 10): omitted preserves a live expiry (an expired one
revives without expiry — it is a new share), `null` removes it, a `Date` sets it. Expiry is
**strict** — a share that expires *now* no longer grants — and is honoured by `check`,
`listObjects`, `listSubjects` and `membersOf` in both drivers, including a membership that expires
(`relate(u, 'member', group, tenant, { expiresAt })` stops granting through the userset at that
instant). Enforced in SQL by `database` (`expires_at > now`, the same `DATETIME(3)` column and codec
as assignments) and by the `not_expired` condition on every relation subject in the fused model for
`openfga` (`current_time` travels in every `Check`/`ListObjects`). The `RelationsManager` takes the
same `clock` as the roles manager (the provider passes `config.clock`), and both drivers implement
`withClock`. In `database`, **renewing an expiry is delete+insert, never an `UPDATE`** — the table
stays insert/delete-only, and the case that observes it is in the suite (the row changes its uuid).
A bad `expiresAt` (not a valid `Date`/`null`/omitted) is 422 `E_AUTHZ_INVALID_IDENTITY` before the
driver. `enumerateRelations` does **not** filter expired tuples: they reach `authz:relations:reconcile`
with their `expiresAt` and are counted in `skipped.expired`, never silently dropped.

`group` is a **built-in** object type (the userset carrier: `group#member`, nesting allowed), so
teams work without declaring anything. Every operation takes a **`partition: ScopeRef`** — the
tenant — and it is **mandatory**: a relation in tenant A never resolves in tenant B (`APP_SCOPE` is
the mono-tenant value). The partition lives in the object id (`document:<partitionKey>|<uuid>`), not
in the model.

**The model is shared with the catalog, and so is its byte budget.** In the `openfga` driver,
relations fuse into the same `facts` model and the same store, so a single `Check` still answers
each question. The price is one budget: the 262,144-byte model holds **both** your permissions and
your object types. Measured (3 holder types, realistic permission names): the ceiling is **~450–470
permissions**, and since relation expiry (2.4.0-alpha.2) a three-relation object type costs about
**1.0 of a permission** (≈ 579 B vs ≈ 557 B; before the `not_expired` condition on relation subjects
it was ≈ 0.5) and `group` ≈ 0.34 (191 B; was 86 B). The condition adds `(holders + 1) × (type name +
"not_expired")` bytes per declared relation — ≈ 103 B per relation with three holders. So a catalog
of 447 realistic permissions has room for **24** three-relation object types (was 52), and one object
type costs the permission ceiling a single permission (472 → 471); a small catalog has room to
spare. The gate
watches the **fused** model — `defineRelationsConfig` that would push it over is 500
`E_AUTHZ_MODEL_TOO_LARGE` before anything is published (80 % warns), the same protection
`syncAuthzCatalog` already gives the permissions. A consumer that needs *many* object types **and**
is pinned to the permission ceiling is the documented case for a separate store; everyone else
shares.

**The boundary is enforced, not hoped for (the 🔴 the audit found, closed by construction).** In the
shared store a naive relations write could compose the id of a real `role_binding` and escalate to
`roles.authorize`. Two rules close it structurally: `defineRelationsConfig` **refuses** to declare a
reserved `facts` type or relation (`scope`/`role`/`role_binding`/`group`/`can_<P>`/`assignee`… → 422
`E_AUTHZ_RELATION_CONFIG`), and `relate`/`unrelate` **refuse** an object type or relation not
declared (422 `E_AUTHZ_RELATION_TYPE_UNKNOWN` / `E_AUTHZ_RELATION_UNKNOWN`) **before touching the
driver** — so the id of a `role_binding` is never composed by the relations driver, the collision
does not exist rather than being watched. This is F-05, and it is a **chokepoint**: every write path
funnels through it, and the published contract plants the exploit so a third-party relations driver
that does not enforce it **does not pass**. Because it lives in the manager, calling
`manager.driver()` (the platform escape hatch) skips it — as with every other barrier.

**`membersOf` is `database`-only.** `membersOf(group, 'member', partition)` returns the **transitive**
membership (through nested groups). Only the `database` driver has it (a recursive CTE); in `openfga`
it is 500 `E_AUTHZ_UNSUPPORTED` naming it — the transitive form is `ListUsers`, which truncates
without a reliable signal, and we never return a silent partial. `listSubjects` (direct facts,
invariant 7) works in both. `listObjects` in `openfga` signals `truncated: true` when the server's
`ListObjects` cap cuts the page, never a mute partial list.

**The config is persisted, and republishing never mutilates the model.** `saveRelationsConfig(spec)`
stores the relations config in `authz_relations_config` under the shared version gate (invariant 14).
Because the catalog and the relations config share one model lifecycle, both `syncAuthzCatalog` and a
config save republish the fused model — and they race for the `modelId`. `republishFusedModel` reads
**both** persisted halves (catalog permissions + relation types) every time, so the published model
is never "the model of one, the tuples of another"; the `modelId` is pinned with a bounded CAS, and
contention that will not yield is 409 `E_AUTHZ_WRITE_CONFLICT`, never a half model.

**Migrating tuples between drivers** is `node ace authz:relations:reconcile --to=<key>` — the relations
analog of `authz:reconcile`, idempotent, bidirectional and never silent (it reports written / deleted
/ unchanged / extra). `--to`/`--from` are keys of `relations.drivers` in `config/authorization.ts`;
`--dry-run` is the read-only verifier and also flags **model drift** (an object type in the source the
destination does not declare); `--prune` deletes what the source no longer backs. It migrates **facts
only** — there is no tree or catalog in `relations/` — and works **per partition** (`--partition-type`
/`--partition-uuid`; default `app`).

**Still not in 2.4.** `includes` with `from` (cross-object inheritance like `viewer from parent`),
which would add a TTU between object types and force re-measuring depth; and `{trx}` on
`relate`/`unrelate` (parity with `roles/`). Relation expiry (R-15) **landed in 2.4.0-alpha.2** (see
above); an installation that migrated 2.4.0-alpha.1 adds the column with the recipe in
[Upgrading](#upgrading-from-240-alpha1-authz_relationsexpires_at).

## Errors

Every error the package raises carries `status` and `code`. A standard AdonisJS exception handler answers on its own; catch only when an endpoint needs a specific response.

| Code | Status | When |
|---|---|---|
| `E_AUTHZ_INVALID_IDENTITY` | 422 | malformed holder/scope, `{app, uuid}`, root sentinel outside `app` |
| `E_AUTHZ_INVALID_SLUG` | 422 | role/permission slug: grammar, length, reserved name or prefix, collision |
| `E_AUTHZ_UNKNOWN_ROLE` / `E_AUTHZ_UNKNOWN_PERMISSION` | 422 | not in the catalog (for that scope type), in `grant`/`deny`/`revoke`/`removeDeny`; by uuid in `purgeRole`/`updateScopedRole`/`deleteScopedRole` (2.2) |
| `E_AUTHZ_CATALOG_CONFLICT` | 422 | two catalogs in `config.catalogs` declare the same role `(slug, scopeType)` or permission; a local role whose `(slug, scopeType)` is already visible from its owner through a **more authoritative** definition (a global, or a local of an ancestor), or that appeared while it was being validated (2.2). **Not** a homonym local to a *descendant* (the new one shadows it, `shadowedByAncestor`), and **not** a global role of the spec colliding with a local one: the sync writes the global and reports it as `shadowedByGlobal` |
| `E_AUTHZ_ROLE_NOT_VISIBLE` | 422 | `grant` of a local role outside its owner's subtree; a `{ uuid }` `RoleQuery` whose role is declared for another level or whose owner is not in the scope's chain (2.2) |
| `E_AUTHZ_AMBIGUOUS_ROLE` | 422 | `grant`/`revoke`/`hasRole`/`listSubjects` **by slug** where more than one role with that `(slug, level)` is visible in the chain — ask by `{ uuid }` (2.2) |
| `E_AUTHZ_ROLE_IMMUTABLE` | 422 | `updateScopedRole`/`deleteScopedRole` on a global role (2.2) |
| `E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER` | 422 | `defineScopedRole`/`updateScopedRole` with a `scopeType` that is the level of an *ancestor* of the owner (or, with `scopes.descendantsOf` declared, a level that does not appear below it) (2.2) |
| `E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT` | 422 | a role of level L carrying — or granted while carrying — a permission whose `assignableAt` excludes L: sync, `defineScopedRole`/`updateScopedRole`, `grant` (2.2) |
| `E_AUTHZ_PERMISSION_NOT_DELEGABLE` | 422 | `defineScopedRole`/`updateScopedRole`: a permission not in `delegablePermissions`, or not effective for the actor in the owner (not granted, or denied) (2.2) |
| `E_AUTHZ_RANK_EXCEEDED` | 422 | a local role's rank outside `0 < rank < min(actor's rank, highest global rank)`, or touching (or shadowing) a role of rank ≥ the actor's — `defineScopedRole`, `updateScopedRole`, `deleteScopedRole` |
| `E_AUTHZ_UNKNOWN_SCOPE` | 422 | write on a scope the resolver does not know; unknown parent in `scopes.*` |
| `E_AUTHZ_NO_SCOPE_RESOLVER` | 422 | driver without `resolveChain` asked about a non-`app` scope |
| `E_AUTHZ_SCOPE_CYCLE` | 422 | `scopes.attached/moved` would close a cycle; `hierarchicalScopeResolver` met a cycle |
| `E_AUTHZ_NOT_WITHIN` | 422 | any of the nine writes with `within` not in the chain of the scope it writes to (the new parent **and** the child's current chain for `scopes.moved`, and for `scopes.attached` of an existing child; the role's owner for the delegation API since 2.2) (2.1) |
| `E_AUTHZ_WITHIN_REQUIRED` | 422 | `requireWithin` set and a write without `within` (2.1) |
| `E_AUTHZ_WITHIN_ROOT_FORBIDDEN` | 422 | `requireWithin: 'non-root'` and `within: APP_SCOPE` (2.1) |
| `E_AUTHZ_ACTOR_REQUIRED` | 422 | `requireActor: true` and a write without `actor` (2.1) |
| `E_AUTHZ_TOO_MANY_SCOPES` | 422 | `authorizedScopes`/`expandExcludedSubtrees` over `maxScopes`, or `descendantsOf` over `maxNodes` (`sqlDescendantsOf`: also a possible cycle) — never a partial list (2.1) |
| `E_AUTHZ_BACKEND_UNAVAILABLE` | 503 | facts backend or SQL catalog did not answer (both drivers, catalog sync/diff and the `authz_catalog_version` check included); the version row is missing or unreadable ("migración 2.0 no aplicada": fail-closed, never version 0); a per-check `error` in an OpenFGA `batchCheck` |
| `E_AUTHZ_BACKEND_TIMEOUT` | 503 | `timeoutMs` elapsed (subclass of the above) |
| `E_AUTHZ_FROZEN` | 503 | the engine's writes are frozen by a platform operation (`authz:reconcile`, or the cutover window of `authz:freeze`) — **durably, fleet-wide** (row `id = 2` of `authz_catalog_version`, 2.3): reads keep working and the error is **retryable** (`error.retryable === true`) — reissue the write when the window ends (the message says how it lifts) |
| `E_AUTHZ_FREEZE_HELD` | 423 | `freeze()` (or a second `authz:reconcile`) found a live freeze owned by someone else: two windows never interleave, and only the owner's token — or `authz:unfreeze` — lifts one. The message names the holder, the reason and the fence |
| `E_AUTHZ_RESOLVER_FAILED` | 503 | your `resolveChain`, `parentOf` or `descendantsOf` threw or answered a malformed scope; `descendantsOf` and `resolveChain` disagree in `authorizedScopes`; a subtree to exclude cannot be enumerated |
| `E_AUTHZ_WRITE_CONFLICT` | 409 | an `openfga` write kept clashing with another transaction over the same tuples (FGA answers `Aborted`/409, or 400 "cannot write a tuple which already exists"): the driver re-reads and re-applies, and only gives up after three rounds. The backend answered, so this is never a 503 — retry the write |
| `E_AUTHZ_CONFIG` | 500 | contradictory config (`holderTypes` not injective or a holder type not declared in it, `scopes.*` without resolver, `appAccess` without `permission`, `catalog` together with `catalogRevalidate`, an invalid `maxAgeMs`); `bumpAuthzCatalogVersion` called without the writing transaction's client |
| `E_AUTHZ_ROLE_IS_NOT_ACCESS` | 500 | `appAccess({ role })` |
| `E_AUTHZ_INTERNAL` | 500 | package invariant violated (empty scope set on a write, misaligned batch, a third-party `authorizeMany` answering the wrong shape, a `Read` continuation token that never advances or more than 10,000 pages, a corrupt `assignable_at`/`owner_scope_key` row) |
| `E_AUTHZ_PURGE_INCOMPLETE` | 500 | `purgeScope` could not prove zero |
| `E_AUTHZ_RECONCILE_TOO_LARGE` | 500 | the destination's dump does not fit the declared `--max-tuples` cap (default 1 000 000) and reconciling needs the whole snapshot to know what is left over. Nothing was written; raise the cap if your process can take it |
| `E_AUTHZ_MASS_RECONCILE_REFUSED` | 500 | `authz:reconcile --prune` would delete facts from the destination while the source has not contributed a single **usable** one — empty, or every fact it returned was skipped (expired, on scopes your tree no longer resolves): the signature of a wrong connection, of the wrong source, or of a blind resolver. Nothing was deleted; pass `--allow-mass-delete` if you really mean to empty it (`--dry-run` flags it instead of throwing). A source that is merely **stale** but still usable is covered by reading the facts from whoever owns them |
| `E_AUTHZ_MASS_PURGE_REFUSED` | 500 | `pruneOrphanRoles({ force: true })` would purge every distinct owner (or more than half the local roles): the signature of a blind `resolveChain`. Nothing was deleted; pass `allowMassPurge: true` (`--allow-mass-purge`) if the prune is real |
| `E_AUTHZ_TOO_MANY_LOCAL_ROLES` | 500 | more local roles than `maxLocalRoles` (10 000) in a `prune-orphans` pass; never a partial list |
| `E_AUTHZ_UNSUPPORTED` | 500 | a primitive needs an optional port method the active driver lacks: `listDenies` (2.1; also behind `defineScopedRole`), `purgeRole` (2.2 — behind `deleteScopedRole`, `authz:catalog:prune-orphans` and, before writing anything, `defineScopedRole`; the `openfga` driver until 2.3); `reconcile` (2.3 — `authz:reconcile --to=<driver>`); `enumerateFacts` (2.3 — being the *source* of `authz:reconcile`; the `database` driver does not implement it: its facts are `authz_*`. Also raised when `--to` is the **active** driver and declares `hierarchyFacts`: its facts are its own, so the pass has to be able to read them instead of rebuilding it from `authz_*`) |
| `E_AUTHZ_MODEL_TOO_LARGE` | 500 | the catalog does not fit in an OpenFGA authorization model (262,144 **bytes** — around **450 permissions with realistic slugs**; see [the model ceiling](#the-model-ceiling-is-bytes-not-permissions)): checked in `syncAuthzCatalog` **before** writing, with a warning past 80 % |
| `E_AUTHZ_RELATION_CONFIG` | 422 | a `relations/` object type or relation cannot be **fused** into the shared `facts` model: it duplicates a reserved `facts` type (`scope`/`role`/`role_binding`/`deny_binding`/`group`) or relation family (`can_<P>`/`denied_<P>`/`permits_<P>`/`parent`/`rooted`/`assignee`…), or a relation name collides with a catalog permission (F-04). The generator raises it — not OpenFGA's opaque 400 — because in the shared store the id-spaces overlap |
| `E_AUTHZ_SCOPE_DRIFT_UNGUARDED` | 500 | the `openfga` driver was constructed without `scopes.outbox` and without `acceptScopeDriftRisk: true`. Thrown at construction: a rollback of your transaction would otherwise leave the store's tree ahead of yours, and that escalation is invisible from your database |
| `E_AUTHZ_SCOPE_TREE_DRIFT` | 500 | the materialized tree has more than one `parent` edge for the same scope: someone else writes to the store. A write never "fixes" it by guessing; `authz:reconcile` rebuilds the tree from yours and reports the scope |
| `E_AUTHZ_NO_DESCENDANTS_RESOLVER` | 500 | `authorizedScopes`/`expandExcludedSubtrees` without `scopes.descendantsOf` |
| `E_AUTHZ_VIEW_EXPIRED` | 500 | a `forRequest()` view used to read (`expandExcludedSubtrees` included) after its `maxAgeMs` (default 30 s, monotonic clock) |
| `E_AUTHZ_UNSUPPORTED_DIALECT` | 500 | `sqlDescendantsOf` / `sqlScopeEdges` on a dialect other than PostgreSQL / MySQL 8 / SQLite |
| `E_AUTHZ_SCOPE_TOO_DEEP` | 500 | `hierarchicalScopeResolver` over `maxDepth` (no truncated chain) |

## Driver options

Both drivers take `resolveChain` and **`timeoutMs`** (default 5000): every SQL query the driver builds is given a knex timeout — the `DELETE`s inside `purgeScope`'s transaction included; only knex's own `BEGIN`/`COMMIT` carry none — every FGA call has a total deadline, and an elapsed deadline is 503 `E_AUTHZ_BACKEND_TIMEOUT`. A server that accepts the connection and never answers is released in under a second (*"authorize contra un servidor mudo ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT en menos de 1 s"*). SQLite's synchronous driver cannot actually time out; what the suite pins there is that every query carries the deadline (*"toda consulta sale con el timeout configurado"*). A deadline releases the caller, it does not abort the request in flight: see `indeterminate` above.

Both also take **`catalogRevalidate`** (`'always'`, the default, or `{ everyMs }`) *or* **`catalog`** (a `CatalogCache` to share between drivers of the same process; its own `revalidate` is the policy) — the catalog memo described under [Performance](#performance). Passing both is 500 `E_AUTHZ_CONFIG` at construction: the driver's `catalogRevalidate` would be silently ignored otherwise.

Both take **`now`** (default `() => new Date()`): the wall clock every time-based *decision* uses — `expires_at > now()` in SQL, the `current_time` of every FGA check (one instant per operation: every check of a `batchCheck` carries the same `current_time`, and the two reads of `listScopes` filter with the same `now`), the client-side expiry filter of the enumerations and the three states of a re-grant. The audit stamps (`created_at`) are **not** decisions and use the system clock: with MySQL's `TIMESTAMP` an injected clock in 2040 made every write fail (*"… se escribe estando el reloj en 2040"*). Every driver of the package also implements `withClock(now)` on the port (a view bound to another clock, like `withChainResolver`), and the manager applies **`clock`** from the config to the driver it resolves — all `forRequest()` views share it; a config `clock` over a driver without `withClock` is 500 `E_AUTHZ_CONFIG`, never a clock silently ignored. It exists so that expiry is observable *without sleeping* (the contract fixes the exact instant: one millisecond before `expiresAt` grants, at `expiresAt` it does not — *"caducidad exacta con el reloj inyectado"*) and so that your own tests can freeze time; in production leave it alone and keep NTP running. It is not the monotonic clock of `forRequest({ maxAgeMs })`, which measures a window and must not move with NTP. Nothing else in `src/` reads the wall clock (a grep test pins it) — except the model trait `withAuthzScopes` (`whereRoles`/`wherePermissions`), which cannot see the manager: it decides "live" with the system clock unless you compose it with the same clock, `compose(BaseModel, withAuthzScopes({ clock }))` (*"withAuthzScopes({ clock }) decide la vigencia con ESE reloj"*). Its primary-key comparison is dialect-aware (on PostgreSQL a `uuid` primary key is cast to text against the `varchar` subquery: *"… con la clave primaria uuid nativa del modelo"*).

`openfga` additionally takes `holderTypes` (required, injective; a holder whose morph name is not in it is 500 `E_AUTHZ_CONFIG`), `modelId`, a `logger` (default `console`), **`retryParams`** (default `{ maxRetry: 0 }`, see `indeterminate` above) and **`consistency`**: `'higher_consistency'` (default) or `'minimize_latency'`. The default protects the "removing the deny restores" promise against a server started with `--check-query-cache-enabled`, where a fresh revoke or deny would keep granting for up to the cache TTL; `minimize_latency` is the explicit opt-out (*"todo check lleva context.current_time; toda llamada HIGHER_CONSISTENCY"*). `driver.diagnostics.unparseableBindings` counts store tuples the engine cannot interpret — binding ids it does not understand and malformed tuples alike; each one is logged, never skipped in silence.

**The `openfga` driver *is* the `facts` mode, and there is no other (2.3, breaking).** The scope tree is materialised in the store as one `scope:<child>#parent@scope:<parent>` edge per node, which is what the model needs to inherit downwards without asking your database. `authorization.scopes.attached/moved/detached` maintain those edges: `moved` is one `Read` plus one atomic `Write` carrying the delete of the old parent and the write of the new one, and `detached` removes the edge **after** `purgeScope` has proved the facts of that scope are gone. Finding more than one parent for a scope is 500 `E_AUTHZ_SCOPE_TREE_DRIFT`: the package writes one edge per node, so two means something else writes to your store, and it is reported rather than silently "fixed".

Until 2.2 there was a second mode, `hierarchy: 'resolver'`, in which the tree stayed in your database and the package expanded the chain into a `batchCheck` of N×M on every question. **The option is gone**; passing it is a TypeScript error and is ignored at runtime. What that mode did is described in the changelog, together with what it cost to keep.

It also takes **`outbox`** and **`acceptScopeDriftRisk`**, and one of the two is mandatory: without either, construction throws 500 `E_AUTHZ_SCOPE_DRIFT_UNGUARDED`. Pass the same `scopes.outbox` instance you put in the config (the driver never uses it — the manager is what enqueues; here it is the evidence for the gate). **Declaring it on the driver alone is not enough, and since 2.3 it is refused**: the manager reads `config.scopes.outbox`, so an outbox that only the driver knows about leaves the mitigation switched off. The manager therefore applies the same gate when it resolves a driver that declares `capabilities.hierarchyFacts` — the outbox (or `scopes.acceptScopeDriftRisk: true`) has to be in **the config**, which is where the enqueueing happens. Read [The tree outbox](#the-tree-outbox-and-the-relay-lag-you-are-accepting) before choosing: the reason for the gate is that a rollback of your transaction otherwise leaves an escalation nothing in your database can show you, and the reason `acceptScopeDriftRisk` exists is that a deployment that only moves the tree from the platform can knowingly accept it.

**What the driver actually promises, and what it does not (2.3).** The exact claim, and nothing more:

> In `facts` mode, `authorize` is a **single `Check`** against OpenFGA: it does not consult your tree (`resolveChain`) and it consults the local catalog only through an in-memory memo, invalidated by `syncAuthzCatalog`. `hasRole`, `listRoles`, `listRoleScopes`, `listSubjects` and `listScopes` **do** use `resolveChain`. `grant` and `deny` use it too, to validate that the scope exists.

So **"no SQL in the hot path" is not a claim this package makes**, and you should not repeat it: what is true is *no SQL per request in `authorize`*. Membership and enumeration still go through your tree — in the (c2) model there is no alternative, and it is measured, not assumed. What you do get is that `authorize` survives your application database being down, and that its latency is constant in tree depth and in number of roles.

Every driver **declares** this through `driver.capabilities`, and each declared value has a case in the contract suite — never a skip:

| Capability | `database` | `openfga` | What the judge fixes |
|---|---|---|---|
| `hierarchyFacts` | `false` | **`true`** | the tree is the backend's; the manager then requires the outbox (or your signature) |
| `singleCheckAuthorize` | `false` | **`true`** | `authorize` makes one backend call and zero `resolveChain` |
| `roleInheritanceNative` | `false` | `false` | the five membership reads **do** consult your tree (a spy counts the calls) |
| `listObjectsInherited` | `false` | `false` | a grant on the ancestor never appears in the descendant's `list*`, even though `authorize` says `true` there (invariant 7; `ListObjects` is never used — it truncates at the server's cap with no signal) |
| `purgeRole` | `true` | **`true`** | with (c2) a binding points at its role, so a role's bindings *can* be enumerated |
| `countRoleAssignments` | `true` | **`true`** | how many live facts a role has — what makes `stillGranting` true instead of a guess (2.3; same enumeration `purgeRole` needs) |
| `canonicalScopeReads` | `true` | **`false`** | whether a read canonicalises the caller's scope spelling against your tree before looking for facts (see below) |
| `enumerateFacts` | `false` | **`true`** | the driver can be the **source** of a migration: `enumerateFacts` hands its live facts back page by page, unfiltered and with their expiry (2.3). `database` declares `false` on purpose — its facts *are* `authz_assignments`/`authz_denies`, this package's published schema, so the destination reads them straight from there |

**Two answers `facts` does not share with `database`, declared — not scheduled fixes (2.3).** `authorize` decides with the tree that lives in the store; it never calls your `resolveChain`. That is the property you are buying: a PDP that answers when your database does not. It has two consequences, and each one is a **capability pair with a negative case** in the published contract suite — the package does not skip them, it judges both faces.

> **(a) A resolver that is down no longer makes `authorize` throw — and it can no longer make it stop, either.** This is the property, and it is one-sided. While your tree is unavailable `authorize` and `authorizeMany` keep answering, and what they answer is `true` for everything that was granted; meanwhile `revoke`, `deny`, `removeDeny`, `purgeScope`, `hasRole` and every `list*` are 503 `E_AUTHZ_RESOLVER_FAILED`, because they all canonicalise against your tree. The mode is **grant-only until your database comes back**: it grants and there is no way to revoke. Plan your incident response around that — in `database`, everything stops together. Closing it would mean putting `resolveChain` back on `authorize`'s hot path, which is the whole point of this mode (*"con el resolutor del consumidor caído el modo es \*grant-only\*"*, *"authorizeMany con un scope cuyo árbol lanza: RESPONDE con el árbol del store"*).

> **(b) A uuid alias does not find its facts on the read path.** `authorize` composes `scope:<type>|<uuid>` from the caller's spelling without canonicalising it, so the same id written differently — without dashes, which PostgreSQL's `uuid` column and MySQL's `*_ci` collation fold into the same row — answers `false` where `database` answers `true`. It is fail-**closed**: it never evades a deny and never grants what was not granted, but it is not the same answer. **Pass scope uuids exactly as your table stores them.** The write path is *not* affected: `grant`, `revoke`, `removeDeny`, `purgeScope` and `scopes.detached` canonicalise in both modes, including after the row is gone (that half was fail-*open* until 2.3 and is fixed, not declared), and the judge pins it on both faces of the pair so this is not read as "spelling does not matter in `facts`" (*"un alias del uuid que el árbol funde con la fila canónica NO encuentra sus hechos … pero las ESCRITURAS sí canonizan"*).

**The anti-cycle checks are the package's, in both modes, and they are not optional.** Measured against OpenFGA v1.19: the server *accepts* an edge that closes a cycle, does not hang, answers in 2–7 ms, and from then on inheritance runs both ways — a grant on a descendant grants on its ancestor, and with the root inside the cycle it grants everywhere. Nothing is logged and there is no error to catch. That is why `child ≠ app`, "the parent exists" and `child ∉ ancestors(parent)` are checked before anything is written (422, no edge), and why you should not expect the backend to be a second line of defence.

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
  level: '2.2',                         // '2.1' = up to Phase 2, '2.0' = up to Phase 1; omit for the 1.x cases only
  capabilities: {                       // what the driver declares; each one has its own cases
    hierarchyFacts: false,
    transactions: false,
    truncationSignal: false,
    singleCheckAuthorize: false,
    injectableClock: false,
    exhaustiveLists: true,              // false ⇒ also pass `limits: { listMaxResults }`
    listDenies: true,                   // the port's optional listDenies; judged at '2.1' and above (declare false below it)
    purgeRole: true,                    // purgeRole really purges (2.2); false ⇒ it must say so with 500 E_AUTHZ_UNSUPPORTED
    countRoleAssignments: true,         // the port's optional countRoleAssignments (2.3); false ⇒ pruneOrphanRoles reports `undefined`, never `false`
    canonicalScopeReads: true,          // reads canonicalise the caller's scope spelling against your tree (2.3); false ⇒ an alias finds no facts (fail-closed)
    enumerateFacts: false,              // the port's optional enumerateFacts (2.3): can this driver be the SOURCE of authz:reconcile?
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

Since 2.2 the port has **`purgeRole(roleUuid)`** (optional): revoke every assignment of the role in every scope, delete its links and the role row, atomically, bumping the shared catalog version (`withAuthzCatalogWrite`); a malformed uuid is 422 `E_AUTHZ_INVALID_IDENTITY`, an unknown one 422 `E_AUTHZ_UNKNOWN_ROLE`. **The atomicity of the link deletion is guaranteed by the SCHEMA, not by the driver code**: `authz_role_permissions.role_uuid` is `ON DELETE CASCADE` and `authz_assignments.role_uuid` is `ON DELETE RESTRICT` in the published migration (and in the test mirror, compared action by action by the stub-vs-mirror guard). The judge counts the links after the purge, but on this schema a driver that "forgot" to delete them would pass anyway — the engine deletes them: measured, and it is an equivalent mutant in SQLite, PostgreSQL and MySQL (tester 3E · R7). **If you run your own schema without those actions, or with foreign keys disabled, deleting the links is your driver's job and no test of this package will catch you.** It does not distinguish global from local (that barrier is the manager's). A driver that cannot purge declares **`purgeRole: false`** and must throw 500 `E_AUTHZ_UNSUPPORTED` without touching anything — the pair at `'2.2'` judges either the purge (*"purgeRole(uuid) revoca todas las asignaciones del rol en TODOS los scopes"*) or the refusal (*"sin purgeRole de verdad: el driver lo dice con 500"*); `true` below `'2.2'` throws. The `'2.2'` cases also judge local roles on the driver itself — visibility by owner in every read and write (*"un rol local de la organization A concede en A y sus units"*, *"dos tenants definen el mismo slug"*, the reserved `global` key, deny × local role, `assignableAt` not evaluated) — using roles written straight into `authz_*` as another process would, and, under `listDenies: true`, the delegation API through a manager over your driver (*"defineScopedRole: el rol que el administrador de A delega concede en A y sus descendientes"*); under `listDenies: false`, that `defineScopedRole` says so with 500. A driver reads a role's owner from the catalog memo (`CatalogView.roleVisible(slug, scopeType, chainKeys)` — which **throws** 422 `E_AUTHZ_AMBIGUOUS_ROLE` when more than one role is visible: never resolve the ambiguity yourself —, `rolesNamed`, `roleByUuid(...).owner`, `isRoleVisibleWith`, and the shared `declaredRoleAt(catalog, uuid, scopeType, chainKeys)`) and applies the rule per level of the chain: an assignment in scope S counts only if the role is global or its owner is in chain(S).

Since 2.3 the port also has **`countRoleAssignments(roleUuids)`** (optional, and **breaking if you wrote a 2.2 driver**): how many live facts each role has, across every scope, answered **by position** like `authorizeMany`. A live fact is an assignment that has not expired, judged with the driver's own clock; a role with none — or one the backend does not know — is `0`; a malformed uuid is 422 `E_AUTHZ_INVALID_IDENTITY`. It is what `pruneOrphanRoles` (`authz:catalog:prune-orphans`) asks before saying whether an orphan role is still granting, and it is a question for the *driver* because the facts are the driver's: until 2.3 the sweep counted rows of `authz_assignments` — the `database` driver's table — so with `openfga` it always answered "this role grants nothing", right before a destructive delete. It is deliberately conservative: it counts facts, it does not re-resolve each fact's scope. A driver that does not implement it declares **`countRoleAssignments: false`** and the sweep reports `assignments` and `stillGranting` as **`undefined`** — never `false` — and the command lists those roles apart; the pair at `'2.2'` judges either the counting (*"countRoleAssignments(uuids) cuenta los hechos VIGENTES"*) or that "I don't know" never degrades to "it does not grant" (*"sin countRoleAssignments: el puerto NO lo trae"*).

Since 2.3 there is also **`enumerateFacts({ limit, after })`** (optional): being the *source* of `authz:reconcile`. It hands the driver's live facts back page by page — at most `limit` per page, in a total and stable order, with an opaque cursor that must advance (repeating it is a 500, never a loop) — and it **filters nothing**: an already-expired assignment arrives with its `expiresAt` so the destination can count it in `skipped` with its reason, and what the source cannot express as a port fact (leftovers of an older version, a holder type your config does not declare) comes back in the page's own `skipped`, never dropped in silence. The pair at `'2.2'` judges either the enumeration (*"enumerateFacts: los hechos del driver salen paginados, con su caducidad SIN filtrar"*) or, with **`enumerateFacts: false`**, that `authz:reconcile` **says so** — 500 `E_AUTHZ_UNSUPPORTED` naming the method — instead of reading zero facts and then emptying the destination with `--prune`. The `database` driver declares `false` on purpose: its facts are `authz_assignments` / `authz_denies`, the published schema, and the destination reads them straight from there.

### The migration contract: `runMigrationContract` (2.3)

Passing the driver contract means two drivers answer the same. It does **not** mean that moving your data from one to the other keeps the answers — and the panel that designed this phase was explicit that migration *"is possible with declared losses and a window"*, not lossless. `runMigrationContract` is the executable form of that sentence, published next to the rest of the suite because a third-party driver has to be able to run it:

```ts
import { runMigrationContract } from '@jantstack/adonis-authz/testing'

runMigrationContract({
  name: 'mine ⇄ theirs',
  a: 'mine',
  b: 'theirs',
  seedCatalog: (catalog) => syncAuthzCatalog(catalog),
  setup: async (tree) => ({ reconcile: (o) => manager.reconcile(o), drivers: { mine, theirs } }),
  cleanup: () => wipeEverything(),
  expectedLosses: [
    { reason: 'expired', why: 'an assignment whose expiry has passed grants nothing, so it is not migrated' },
  ],
})
```

It seeds a **fixed fixture** (7 nodes, 6 holders, 4 roles, 14 grants, 5 expiries, 6 denies, written through the driver's own API), asks **448 identical questions** on the source, migrates, and asks the same 448 on the destination — 168 `authorize`, 168 `hasRole`, 42 `listRoles`, 24 `listScopes`, 28 `listSubjects` and 18 `listRoleScopes`. It runs **three combinations**: there, back, and there-and-back-again with `--prune`. And it cuts both ways on the losses:

- **an answer that changes and that no declared loss explains fails the contract** — this is the whole point;
- **every reason the pass counts in `report.skipped` that you did not declare fails it too**;
- and a loss you declared that **never happens** fails as well: a loss that does not occur is a false line in your README.

Those last two cross what the driver *declares about itself*, so they close the **careless** omissions, not the silent ones: a driver that drops a fact without counting it never populates `skipped`. Two more checks close that, and they do not ask the driver anything:

- **the census (2.3.1).** The contract looks for the **20 seeded facts one by one in the destination** — 14 assignments through `listRoles` and 6 denies through `listDenies`, the port's direct read path (invariant 7) — and a fact that is missing with no declared **and counted** reason fails, whether or not any of the 448 answers moved. It was measured that without it a deny relocated to another scope of the same chain passed all three combinations green: `authorize` cannot tell it apart, and no other question asks about denies. `listDenies` is optional in the port: a driver that does not implement it leaves its denies observed by `authorize` alone, and the verdict says so in `censusLimits` instead of keeping quiet about it;
- **the expiry cross (2.3.1).** None of the 448 returns an `expiresAt` and the contract advances no clock, so losing the expiry of a *live* grant — turning a temporary permission into a permanent one, which is fail-**open** — used to be invisible. It is crossed through the only path in the port that hands an expiry back: `grant` with `expiresAt` **omitted** returns `previousExpiresAt` (invariant 10). It runs on the destination and, in the `a→b→a` combination, on the intermediate one too.

For the package's own pair (`database` ⇄ `openfga` in `facts` mode, against a real server, with the tree in SQL) the declared list is **one entry**: `expired`. The other three losses the design panel had listed were measured and are not losses of the migration: sub-second precision in MySQL is closed by the published schema (`expires_at` is `DATETIME(3)` and the codec writes and reads milliseconds), facts on phantom scopes are `unknown-scope` and have their own case in both directions, and the `*_ci` collation is a **read-path** divergence (the `canonicalScopeReads` pair), not something migrating loses — with one exception that *is* counted: two facts of the source that fold into a single destination row are reported as `folded-scope`, and the row keeps the expiry that lasts longest.

Two things worth knowing before you refactor a driver, because the suite cannot tell you: the owner rule in `authorize` hangs on **one case per harness** (the other `'2.2'` cases go through read paths that filter elsewhere), and "binding ids are parsed from the right" is currently a mutant-equivalent decision (see the OpenFGA notes). Both stop being free the day a `scopeKey` grows more parts.

What passing means: **for everything the suite covers, both drivers answer the same** — including the malformed-input edges that used to diverge (`{app, uuid}`, a uuid with `#`), which are contract cases now. What is *not* identical between drivers is operational and listed below: latency, failure modes, the two-call expiry refresh in OpenFGA. Switching drivers is a facts migration (`authz:reconcile`), not a change at the call-sites the manager exposes.

The package runs that suite on itself: `npm test` judges the `database` driver over in-memory SQLite — no host application — and `OPENFGA_TEST_URL=… npm test` adds the `openfga` driver to the same verdict. `npm run test:pg` and `npm run test:mysql` run the **same** suite over PostgreSQL 18 and MySQL 8.4 (`TEST_PG_URL` / `TEST_MYSQL_URL`; each run creates a database with a random suffix and drops it), `npm run test:sqlite-file` over a SQLite file with a pool of 2–5 connections (real connection-level concurrency: a case pins `pool.max ≥ 2` and a read that answers while another connection holds an open transaction — *"una lectura responde mientras OTRA conexión mantiene una transacción abierta"*; the two-concurrent-grants case itself is a JavaScript check-then-insert race and dies with a single connection too). On PostgreSQL and MySQL the judge additionally runs with the scope tree in a real SQL table (`hierarchicalScopeResolver` + `sqlDescendantsOf` over `demo_scopes`), which is where the uuid-alias bypass lived. CI runs all of it: SQLite in memory and as a file, PostgreSQL and MySQL, each with and without OpenFGA, plus a second OpenFGA server with `ListObjects`/`ListUsers` capped at 3; a case also checks that the child process the suite spawns leaves no database behind. Two capability pairs are exercised on both drivers: `listDenies` and **`injectableClock`** (`true` ⇒ the judge fixes the instant through `withClock(now)` and observes exact expiry, renewal and "expires right now" without waiting; `false` ⇒ it can only observe the three states of `expiresAt` in real time, with a 1.5 s wait).

## OpenFGA tooling

```bash
node ace openfga:provision                    # creates a store + writes the model for your holderTypes AND your permissions
node ace openfga:provision --store-id 01H…    # writes a new model version into an existing store
node ace authz:catalog:sync                   # …and projects the catalog into it (role→permission tuples + the root marker)
```

**`openfga:provision` writes the `facts` model, and that model carries your permissions** (four relations each: `<P>`, `can_<P>`, `denied_<P>`, `permits_<P>`), so the command resolves the `catalogs` you declared in `config/authorization.ts` — they are plain functions, no database needed. Without them there is nothing to publish and the command exits non-zero rather than leaving a store that denies everything. Adding or removing a permission changes the model: write a new version with `--store-id` and re-run `authz:catalog:sync`, which rewrites the derived projection (and re-places the root marker) through the driver.

**`openfga:import` is gone (2.3, breaking).** It copied `authz_*` into the tuple shapes of the old `resolver` mode (`role_binding#assignee`, `deny_binding#denied`) — shapes the current model does not even declare, so a store filled by it would be rejected by the server and grant nothing. Its replacement is **`authz:reconcile`**, below. `E_AUTHZ_STORE_NOT_EMPTY` went with the command.

### Migrating and verifying: `authz:reconcile` (2.3)

```bash
node ace authz:reconcile --to=openfga --dry-run   # the VERIFIER: reads everything, writes nothing, exit 1 on drift
node ace authz:reconcile --to=openfga --from=database          # migrate: rebuild the store from authz_* and your tree
node ace authz:reconcile --to=openfga --from=database --prune  # …and delete the facts that source no longer backs
node ace authz:reconcile --to=openfga             # already serving from it? then it is the MAINTENANCE pass (see below)
node ace authz:reconcile --to=database            # the way back: rebuild authz_* from the store's facts
node ace authz:reconcile --to=database --prune    # …and delete the rows the store no longer backs
```

This is the **only** migration and verification primitive of the package, and the reason phase 3b exists: *every driver is complete on its own (facts + tree + catalog projection), and moving between them is one idempotent command*. `--to` names a key of `drivers` in `config/authorization.ts`, **not** the active driver: migrating is filling the destination while the engine keeps serving from the other one.

**The way back (`--to=database`, 2.3) migrates the facts and only the facts.** The **tree is not migrated** in that direction — the `database` driver reads it from *your* tables on every question, and they are its source of truth, so copying it somewhere would be inventing a second copy and a drift that does not exist today. The **catalog is not migrated** either: it is local property always, it already lives in `authz_*`, and no driver is ever its source. That is why the `root marker`, `catalog projection` and `tree` phases report **zero** in that direction: there is nothing derived to rebuild, and the zero says so. The tree is still *used* — to decide which facts are migratable (`unknown-scope`) and under which canonical identity each row is written (invariant 17).

**Where the facts come from: the `enumerateFacts` port.** A driver that can be the **source** of a migration implements `enumerateFacts({ limit, after })` and hands its live facts back page by page, **unfiltered** (an already-expired assignment must arrive, with its expiry, so the destination can count it in `skipped` — filtering it at the source would make it vanish with no trace) and with an opaque cursor that must advance. The `openfga` driver implements it — its facts are tuples in the store and only it knows how to turn them back into `(holder, role, scope)`. The `database` driver **declares `enumerateFacts: false` on purpose**: its facts *are* `authz_assignments` / `authz_denies`, this package's published schema, and the destination reads them straight from there. Both faces have cases in the published contract suite.

**Which driver is the source is decided out loud, never guessed.** With exactly two registered drivers the source is the one that is not `--to`. With more than one candidate the command stops (500 `E_AUTHZ_CONFIG`) and asks for `--from=<driver>` — where the facts come from decides what ends up written. With no candidate at all it stops with 500 `E_AUTHZ_UNSUPPORTED` naming `enumerateFacts`, rather than reading zero facts and then emptying the destination with `--prune`.

**Whoever owns the facts is where they are read from (2.3, and it is the whole safety of this command).** `--to=openfga` used to read `authz_assignments` / `authz_denies` *always*. In a deployment that has already cut over to `facts` those tables are **not** the source of truth of the facts — the store is, and nothing keeps them in sync after the cutover — so a pass that rebuilt from them re-wrote grants you had revoked (no flag needed) and, with `--prune`, deleted the denies that only lived in the store. So the pass now asks first, and **says the answer in its first line** (`report.factsFrom`):

- **`--to` is the *active* driver and its facts live in its own backend** (`capabilities.hierarchyFacts`, which is what `openfga` declares): then its facts are its own and it is read from *itself*. This is the **maintenance pass**: it rebuilds everything **derived** — root marker, catalog projection, tree — and applies the visibility sweep of invariant 18 with the tree and the catalog of *today*, and it **writes and deletes no fact at all**. It is also what makes `--dry-run` usable as the CI verifier of a `facts` deployment: a correct store now comes out **clean** instead of reporting every live fact as `extra-fact`. (A driver in that position that cannot enumerate its own facts is 500 `E_AUTHZ_UNSUPPORTED` naming `enumerateFacts` — reading `authz_*` for it would be the bug.)
- **`--from=<driver>` is given**: you decide. If that driver's facts are `authz_*` (the package's `database`), `--to=openfga` is the **one-way migration** it always was, and it will happily overwrite the destination's facts with what those tables hold. That is what you want while migrating — and it is a loaded gun pointed at a store that is already live, which is why it now takes an explicit `--from` to fire it.
- **Otherwise** (the destination is not the active driver): the migration of always, facts read from `authz_*`.

**It needs `scopes.enumerateEdges`** in your config: the whole tree, paginated with a cursor. `sqlScopeEdges({ table, uuidColumn, parentColumn, typeColumn })` implements it over a table with a parent column, exactly like `sqlDescendantsOf`. Without it the command refuses (500 `E_AUTHZ_CONFIG`) instead of assuming a flat tree — a flat tree would be an invented hierarchy, and an invented hierarchy grants.

What one pass does, in order: the **root marker** (`scope:app#rooted`, without which the whole store denies), the **catalog projection** (`role:<uuid>#permits_<P>`, read with the very same function `syncAuthzCatalog` uses), the **tree** from `enumerateEdges`, and the **facts** from `authz_assignments` / `authz_denies` — each assignment as its `assignee` tuple plus the two (c2) edges, each deny as `scope:<key>#denied_<P>`. It is **idempotent** (a second pass writes zero — the word the requirement used, and it has its case), **resumable** (the source is read in batches of 100 with a cursor over the primary key; repeating a pass converges) and **never silent**: the report carries `{ written, updated, unchanged, extra, deleted, skipped{reason} }` per phase, plus each row that did not migrate with its reason (`unknown-scope`, `unknown-role`, `unknown-permission`, `unknown-holder-type`, `expired`, `role-not-visible`, `cycle`, …).

**The source is read in one consistent snapshot — in the direction where the source is `authz_*` (2.3).** The two sweeps (`authz_assignments`, then `authz_denies`) used to run on the global connection, one after the other, so the gap between them — the time it takes to walk the first table in batches of 100 — let *composite* business operations slip through. An offboarding is `revoke` + `removeDeny`: landing in that gap, the pass kept one half of each and wrote **the role without its deny** into the destination, granting a permission that **neither the previous nor the following state granted**, while the report said `written=13 extra=0 skipped={} clean=true`. That is not a lost permission, it is a fabricated one — an escalation, with nothing in the report to distrust. Both sweeps now run inside **one repeatable-read transaction**, so the worst outcome of the window is *the consistent state of `t0`* — recoverable drift that the next pass repairs — instead of a state that never existed. What each engine guarantees is not the same and is stated rather than assumed: PostgreSQL takes the snapshot with `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ`; MySQL/InnoDB is sent `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ` explicitly (it is InnoDB's default, but a server setting is not a promise of this package) and fixes the consistent read on the first query; SQLite takes no isolation level at all (knex warns and ignores it) because a read transaction is already a snapshot there, so the package does not send it one.

**What that does NOT cover, said out loud.** It covers the direction whose source is `authz_*` (`--to=openfga`). When the source of truth of the facts is the **store** (`enumerateFacts`: `--to=database`, and the maintenance pass), the `Read` pages are **not** a consistent snapshot either, and there is no repeatable read to ask for: the same half-a-transaction composition is possible there. That direction is *not* closed in this version. The instrumentation that could name it — `readChanges({ startTime })` as a window witness, reporting the tuples that moved during the pass — is **not implemented**; the honest statement today is that the direction whose source is a store has an open window, and a second pass after the cutover is the only thing that closes it.

**What it deletes on its own, and what needs `--prune`.** The root marker, the catalog projection and the tree are mirrors of local data nobody else writes, so whatever is left over goes — that is what repairs a scope that ended up with **two parents** in the store (the drift `scopes.moved` refuses to guess about) and what removes edges your tree no longer backs. **Facts are only deleted with `--prune`**: the facts of a scope that no longer resolves (the ones that would grant again if the scope came back with the same uuid) and anything an older version of the store left behind. One deliberate exception: a `scope#binding` edge that your source backs but whose visibility rule says *no* (invariant 18) is deleted **without** `--prune` and counted in `drift.roleVisibility` — leaving it is fail-open, and it is exactly the write `scopes.moved` / `projectCatalogRole` lose when the relay does not get there.

**`--dry-run` is the verifier, and it is read-only by contract**: same walk, same numbers, zero writes, exit 1 if there is anything to do. Run it in CI or in a cron. **`expired` does not fail the pass** (2.3): it is the migration's one *declared* loss — an expired assignment grants nothing in either driver, nothing sweeps expired rows out of the source (observable expiration without a scheduler, on purpose), and no write to the destination can "fix" it — so counting it as drift made the green verifier unreachable with real data: the first expiry pinned exit 1 forever. It is still reported (`N sin migrar por 'expired'`); it just is not drift. Expired facts *left over in the destination* are still drift (`extra-fact`), and their sweep exists: `--prune`. **There is no `--fix` and there will not be one** — a repair flag on a verifier is a grant mechanism. **And it does not freeze** (2.3): a pass that writes nothing has nothing to protect, so freezing there would buy zero and cost a write-outage mechanism fired by a cron job — which is precisely what "run it in a cron" invites. The pass that *does* write still freezes.

**Cycles are reported, not just edge differences.** OpenFGA accepts a `parent` cycle and evaluates it, which makes inheritance bidirectional (a grant in a descendant would grant in its ancestor), so **no edge of a cycle is written**: those nodes stop reaching the root and therefore deny, and the cycle is named in the report. The **relay window** is reported too (how many tree changes are queued and unrelayed — the window in which the backend decides with the old tree) and so are the **parked** entries, which are not a window but permanent divergence.

**While the pass that WRITES runs, writes are frozen — durably, fleet-wide (2.3)** (never under `--dry-run`, see above). The freeze lives in **row `id = 2` of `authz_catalog_version`** — the same cross-process signal every write already depends on — so it reaches **every process that shares the `authz_*` tables**, not just the process that froze: every engine write (`grant`/`revoke`/`deny`/`removeDeny`, the three `scopes.*`, the delegation API, `pruneOrphanRoles --force` and the relay) answers 503 `E_AUTHZ_FROZEN` (**retryable**) and **reads keep working** — `authorize` is never frozen, not for a millisecond. Until 2.3 `freeze()` was a per-process boolean and this paragraph promised otherwise; that promise was false in every deployment with more than one worker, and it is gone. What the mechanism can honestly promise is this: **another process gets a retryable 503 while the window is live** — never "no write enters the window" (a write that had already passed its barrier when the freeze landed still lands; there is no atomicity between a SQL row and an external store, so that phrasing would not even be falsifiable). The cost is measured: one extra primary-key `SELECT` per **write** (+0.14 ms p50 on PostgreSQL, +0.11 on MySQL), zero per `authorize`. And the window is *minutes*, not seconds, at the declared cap (0.136 ms per fact ⇒ ≈ 136 s at `--max-tuples` 1,000,000).

The freeze has an **owner and a lease**. `manager.freeze(reason?, { leaseMs?, kind? })` takes the row (a live freeze held by someone else is 423 `E_AUTHZ_FREEZE_HELD`, never two owners) and returns a **token** (`{ fence, holder }`); `unfreeze(token)` only lifts the freeze whose token matches, so a nested or stale window can never lift somebody else's barrier — a `reconcile` running *inside* a frozen window runs inside it and leaves it standing. The lease (default 15 s) is renewed conditionally every `leaseMs / 3` while the freezing process lives; if that process dies (`SIGKILL`, OOM, pod eviction) **the fleet resumes writing on its own within `leaseMs`** — nobody cleans a row by hand. And the guarantee is **demonstrated, not assumed**: the writing pass reports `frozen: { durable, lapsed, leaseMs, fence }`, and `lapsed: true` — the lease was lost mid-pass (an event-loop stall longer than the lease, the database down, someone lifting the window) — means the pass is **not certified** and the command exits non-zero.

**What the freeze does NOT freeze, by name**: `syncAuthzCatalog` (a free function that never sees the manager — a sync during the window changes what the catalog grants), `manager.driver()` (the documented way out of *all* the manager's barriers), and your own scope-tree tables (your SQL never passes through this package). While the window is open the relay cannot drain either, so the queued-tree window *grows* with the freeze — the report counts it. Two more honest boundaries: the guarantee holds only between processes that **share the `authz_*` tables** (that is invariant 14's deployment shape; a process pointed at another database sees nothing), and it is a guarantee of **this package's manager** — a third-party driver inherits the wording but the published contract suite never checks it (`MigrationContractHarness` has no manager, no second writer and no second process).

### The cutover window: `authz:freeze` / `authz:unfreeze` (2.3)

The dangerous interval is not the pass: it is **[end of the last pass → the last worker reloads `config.default`]** — minutes or hours, decided by a human, during which every write still goes to the driver that is about to stop being the source of truth. Freezing only the pass would close the small window and leave the big one open. So the window belongs to the **operator**:

```bash
node ace authz:freeze --reason="cutover to openfga"   # open the window: fleet-wide 503 on writes
node ace authz:reconcile --to=openfga --from=database # the pass RECOGNISES the operator window
# … switch config.default, redeploy, verify …
node ace authz:unfreeze                                # close the window
```

`authz:reconcile` treats a live **operator** freeze as its own context: it runs inside it, does not take a second freeze, does not renew it and does not lift it when the pass ends — and its report's `frozen.fence` names the window it ran in (with `lapsed: true` if the window did not survive the whole pass). A live freeze of *another* pass is 423 instead: two migrations never interleave. **The operator window does not expire by default** — a cutover has no known duration in advance (window length and outage tolerance are independent magnitudes, the same argument that killed a fixed TTL), and a window that expires mid-cutover silently hands back exactly the fail-open this mechanism exists to close. The declared price: forget `authz:unfreeze` and the fleet cannot write until someone runs it — a *loud* incident (every 503 names the reason and the command that lifts it), not an invisible loss. `--lease-ms` is the opposite opt-in: the window lifts itself after that many milliseconds with nobody renewing it (the command has exited), and *its* declared price is that a cutover slower than the lease resumes the writers silently, mid-cutover. `authz:unfreeze` lifts an operator window; it refuses to lift a live pass's freeze unless you pass `--fence=<n>` (the explicit human decision for a process that died without a lease — and a stale fence lifts nothing).

**`--prune` refuses to run blind.** If it would delete facts while the source has not contributed a single **usable** one, it stops with 500 `E_AUTHZ_MASS_RECONCILE_REFUSED` before writing anything: that is the signature of a wrong connection, of the wrong source, or of a resolver that no longer resolves any of the source's scopes. Until 2.3 the guard looked at the *raw* count — incremented before each skip — so a source whose facts were **all discarded** (every one expired, or on scopes your tree no longer knows) disarmed it and `--prune` emptied the destination with a green report; now a fact only counts if it actually backs something the pass would keep, and the error says how many were read and discarded. `--allow-mass-delete` is the human decision; `--dry-run` never throws, it flags it. A source that is merely **stale** but still partially usable is not this guard's job: what protects you there is the rule above (the facts are read from whoever owns them).

**The declared cap on the dump (2.3).** Reconciling means comparing against the **whole** state of the destination — without that snapshot there is no way to know what is left over, and "what is left over" is half the job. The *source* is read in batches with a cursor; the destination snapshot is not, and it is held in memory. That is declared rather than hidden: above `--max-tuples` (default 1 000 000) the pass refuses with 500 `E_AUTHZ_RECONCILE_TOO_LARGE` **before writing anything**, naming the cap. There is no partitioned migration in this version, and "resumable" means *idempotent and repeatable* — a pass that was interrupted is resumed by running it again; the second one converges and what was already written comes back as `unchanged` — not "a cursor persisted between runs".

**Migration is not lossless, and the losses are declared.** Run `runMigrationContract` (below) against your own pair: it seeds a fixed fixture, asks **448 identical questions** on both ends and fails if a single answer changes without a declared loss, if the pass counted a skip you did not declare, or if a seeded fact is simply **missing from the destination** with nothing declaring it — that last one is the census, and it does not depend on any of the 448 moving.

**The way out of a store written by the previous version.** After 2.3 "a store written by the previous version is not read by this one": the old importer wrote assignments without the two (c2) edges and denies as `deny_binding` objects, a type the current model does not declare. `authz:reconcile --to=openfga --from=database --prune` rebuilds the store from `authz_*` — the source of truth *of that migration*, named out loud because the store you are rebuilding may already be the live one (see [whoever owns the facts](#migrating-and-verifying-authzreconcile-23)) — and clears the leftovers — a tuple whose type the model no longer declares can still be read and deleted (measured against the server). That store grants again after one pass.

### Operational notes for this driver

Choosing it adds a **second runtime dependency to every authorization check**: the catalog is read from your database (once per process, then from the memo — see [Performance](#performance)) and the facts from FGA. If FGA is unreachable, the engine throws `AuthorizationBackendError` (503) — it does not quietly return `false`. Denying silently during an outage strips every user of their permissions with nothing to indicate why. Note that the `database` driver is **not** exempt from the 503 outcome: its catalog and facts live in SQL, and a database that does not answer is classified the same way (*"la base local caída es un 503, no un error crudo"*). What `database` avoids is the *second* dependency.

Three more properties worth knowing before putting it in front of production traffic — none of them can grant access that wasn't granted, all fail towards *denied*:

- **Binding ids carry the catalog uuid, never the slug (2.2).** A role assignment is `role_binding:<scopeKey>|<roleUuid>#assignee` with `<scopeKey>` = `app` or `<type>|<uuid>` (a deny is not an object of its own: it is the relation `scope:<scopeKey>#denied_<P>`); ids are parsed **from the right** (last component = the uuid, everything before it = the scope key) and contain no `~` escape. With today's grammar a `scopeKey` always has one or two parts, so parsing from the right and counting parts agree on every id the grammar admits: the rule is a *structural* decision with no test that can tell the two apart, and it only gets one when a `scopeKey` grows more parts (3b, `facts` mode). Do not "simplify" it to counting on the strength of a green suite. A store written by 1.x/2.0–2.1 (slug in the id) is **not read** by 2.2: those tuples grant nothing, are no membership, are counted in `diagnostics.unparseableBindings`, and `authz:reconcile --to=openfga` reports them as leftovers (`--prune` clears them). There is no *import* command (*"un store con ids 1.x (slug en el id) no es leído por 2.2"*).
- **Enumerations read tuples, not computed relations.** `listSubjects`, `listRoles`, `listRoleScopes` and `listScopes` use the paginated `Read` API (100 tuples per page, until the continuation token is empty; a token that repeats or more than 10,000 pages is 500 `E_AUTHZ_INTERNAL`, never a hang) and filter expiry client-side. That is what makes them complete regardless of the server's `ListObjects`/`ListUsers` caps. The price: `Read` returns *written* tuples only. With the model this package generates (`assignee` and `denied_<P>` are direct relations) that is exactly the same set; if you extend the model with relations derived over `role_binding`, this driver's enumerations will not see them. Membership reads also consult the catalog (`authz_roles` for that level) — from the in-process memo, so no query in steady state — and `listRoleScopes` asks your resolver once per scope it returns, like `listScopes` (a `forRequest()` view memoises those calls).
- **Changing an expiry is not atomic.** FGA rejects deleting and writing the same tuple key in one transaction, so *replacing* an expiry is a delete followed by a write. Between the two, `authorize()` answers `false`, and a crash in that window loses the assignment; re-running the grant restores it. The driver reads the current tuple first, so this only happens when the expiry actually changes — a first grant is a plain write, an identical re-grant touches nothing (*"quitar la expiración es explícito (expiresAt: null); omitirla no la toca ni escribe nada"*). A grant *without* `expiresAt` whose read fails is a 503 whose message carries the recipe: preserving a live expiry requires knowing it; pass `{ expiresAt: null }` if you mean "permanent". A first write that collides with a concurrent one (FGA's "tuple already exists") re-reads and re-grants on top of it; any other write failure is propagated classified, with the SDK error as `cause` — never treated as a race (*"un write que falla con 400 no es una carrera"*).
- **Expiry follows the app server's clock.** The `not_expired` condition is evaluated against a `current_time` your process sends with each check, and enumerations filter with the same clock. Keep NTP running.
- **There is no distributed transaction with your database, and the catalog that *decides* is the projection in the store.** A `grant` validates the role against the local catalog and then writes the tuple. Delete that role from `authz_*` **by hand** afterwards and the two drivers stop agreeing, which is worth knowing before you write a migration script: membership (`hasRole`, `listRoles`, `listRoleScopes`, `listSubjects`) filters through the local catalog in both drivers and fails closed from the first instant, but `authorize` is decided by the store, where the permission→role mapping is the projection (`role:<uuid>#permits_<P>`) that your delete did not touch — **so it keeps granting**. Whoever writes `authz_*` by hand owes it a `driver.projectCatalogRole(uuid)`, exactly as it already owes a catalog-version bump; `syncAuthzCatalog` and the delegation API do it for you (*"en `facts` el catálogo que decide es la proyección del store, no la fila que acabas de borrar"*). `purgeScope`, meanwhile, cannot reach bindings of roles that are no longer in the catalog (it reads by exact object, built from the catalog; `Read` cannot enumerate by id prefix without a `user`). Reconciling both is the job of `authz:reconcile --to=openfga`.

#### The model ceiling is bytes, not permissions

The `facts` model publishes **four relations per permission**, so a big catalog can outgrow OpenFGA's authorization-model limit (262,144 bytes by default, `OPENFGA_MAX_AUTHORIZATION_MODEL_SIZE_IN_BYTES`). `syncAuthzCatalog` checks it **before writing anything** — 500 `E_AUTHZ_MODEL_TOO_LARGE`, with a warning past 80 % — and the check is exact: the package measures the **protobuf** size, which is what the server measures, and it matches the number the server reports byte for byte (four catalog shapes, verified against a real server).

What is *not* a property of the model is **how many permissions those bytes are**. It depends on three things: how many holder types you declare, **how long their names are in the model**, and how long your permission slugs are. Measured, and pinned by a case:

| catalog | permissions that fit |
|---|---|
| 1 holder type, slugs `p0`…`pN` | **800** |
| 3 holder types (`user`/`admin`/`integration`), slugs `p0`…`pN` | **691** |
| 1 holder type, slugs `docs:readN` | **576** |
| 3 holder types, slugs `recursoN:accion` (**realistic**) | **447** |
| 3 holder types, slugs of 40 characters | **272** |

Versions up to 2.3 published "**≈691 permissions**" without saying that it was measured on a catalog whose permissions are named `p0`, `p1`, `p2`… With permission names anybody would actually write, the ceiling is around **450** — 35 % lower. And the same three holder types with shorter names (`bot` instead of `integration`) give 721, so "three holder types" does not pin the figure either. Nothing here can grant access: the byte gate is exact and fires before writing. Take the table as the shape of the curve and let the 80 % warning tell you where *your* catalog is.

#### The scope-chain depth ceiling (facts)

The `facts` model answers `authorize` in a single `Check` that walks the scope chain to the root
(`can_<P>` unions two tuple-to-userset rewrites and subtracts the deny), and OpenFGA bounds how deep
a `Check` resolves (`--resolve-node-limit`, 25 by default). Measured against OpenFGA v1.19 with 500
resolutions per side, the `facts` model resolves reliably to **22 `parent` hops** and no further: at
23 the same question answers *almost* always and fails between 4 % and 26 % of the time (the node
budget is consumed non-deterministically resolving the union), at 24 it always fails. So the driver
declares **22** — `FACTS_MAX_RESOLVE_DEPTH`, the depth that resolves *every* time, not the first that
fails. Past the ceiling the server returns 400 ("resolution required too many rewrite rules") and the
package propagates it as **503, never a `false`** (invariant 5): fail-closed, but a chain that deep is
legal for the `database` driver, which has no such ceiling — the same tree is fine in one driver and a
503 in the other, and it is a DoS within reach of whoever can nest sub-scopes. Raise
`OPENFGA_RESOLVE_NODE_LIMIT` on the server if your tree is deeper.

### Operational notes for the SQL engines

The published migration (`stubs/migration.stub`) carries three decisions that were **observed** by running the suite on PostgreSQL and MySQL, not guessed — each one was a red test first — plus, since 2.2, `authz_roles.owner_scope_key` (`varchar(80)`, byte-wise like the other identity columns, `DEFAULT 'global'`, in the role unique index) and `authz_permissions.assignable_at` (see [Scoped roles](#scoped-roles-22)). The suite also **executes** the migration on a scratch database of each engine and compares what the engine reports for every column (type, length, precision, nullability, collation) with the schema the tests run on (*"el esquema que CONSTRUYE el stub y el espejo del harness son el mismo"*).

- **Identity columns are `varchar(64)`, not `uuid`.** `holder_uuid` and `scope_uuid` hold whatever your grammar-valid id is (`[a-z0-9._-]`, ≤ 36 chars): `user-42`, a ULID, a UUID. PostgreSQL's `uuid` type rejected anything else with `invalid input syntax for type uuid` (a 503 on `grant`). The suite pins that non-UUID ids work in every engine (*"la identidad es una cadena validada por la gramática, no un UUID del motor"*).
- **Identity columns and slugs are compared byte-wise.** They carry `collate 'utf8mb4_bin'` in the migration (`holder_type`, `holder_uuid`, `scope_type`, `scope_uuid` in assignments and denies; `slug` and `scope_type` in the catalog tables); knex only compiles it for MySQL, where the default collation (`utf8mb4_0900_ai_ci`) merged `abc` and `ABC` into one row — a grant to one authorised the other and the unique index treated them as duplicates. PostgreSQL and SQLite already compare `=` byte-wise. If you copy the migration into an existing MySQL schema, alter those columns' collation too. Your own **scope tree table** is outside this promise — that is why the chain resolver returns the canonical row and why upper-case uuids are rejected (see [The scope tree](#the-scope-tree)).
- **`expires_at` is `DATETIME(3)`.** knex's `timestamp` is `TIMESTAMP(0)` on MySQL: it *rounds* to the second (an expiry 600 ms away was stored 1 s away and kept granting past its instant) and cannot hold dates after 2038-01-19. Expiry is millisecond-exact in every engine and `2040-01-01` is a valid expiry (*"la caducidad guarda milisegundos y fechas más allá de 2038"*). PostgreSQL stores it as `timestamptz(3)`.

Also on MySQL: `sqlDescendantsOf` quotes identifiers with backticks and sends `/*+ SET_VAR(cte_max_recursion_depth = …) */` with each walk — MySQL aborts a recursive CTE after 1000 iterations (`cte_max_recursion_depth`, error 3636), which turned a cycle under a bound above 1000 (the manager's default is 10 000) into a 503 instead of the contract's 422 "posible ciclo". The bound is the same one the query already imposes with `depth < maxNodes + 1`; nothing from your input reaches the hint, and `maxScopes`/`maxDescendants` are capped at 10 000 000 (`MAX_SCOPE_BOUND`; above it the hint leaves MySQL's range and the 422 degrades to a 503 — 500 `E_AUTHZ_CONFIG` instead).

**Expiry is an instant, and the package stores it as UTC itself.** On MySQL `expires_at` is `DATETIME(3)`, which has no time zone, and `mysql2` serialises and parses `Date` values with the **process's** `TZ` (`timezone: 'local'`, its default): a process in UTC wrote `12:00:00` for `12:00Z` and a process in Caracas read it as `16:00Z` — the assignment expired four hours late for it (and nine hours early for one in Tokyo). The `database` driver does not depend on your connection options: on MySQL it writes `expires_at` as an explicit UTC string (`YYYY-MM-DD HH:mm:ss.SSS`), compares with `now` formatted the same way and reads it back through `DATE_FORMAT` (a string, parsed as UTC), so `timezone`, `dateStrings` and `TZ` do not enter the decision; the model trait compares the same way. PostgreSQL stores `timestamptz(3)` (an absolute instant) and SQLite a number. The suite spawns real child processes in `UTC`, `Asia/Tokyo` and `America/Caracas` over the same database, with the default connection options, writing and reading in both directions (*"expires_at es un instante: procesos con TZ distinta sobre la misma base ven la misma caducidad"*). Keep the process on NTP; do not set MySQL's `timezone` option for the package's sake — it is not needed, and it must not be relied on.

**`withAuthzCatalogWrite` and a swallowed SQL error.** Do not `try/catch` a SQL failure inside the `fn(trx)` you pass and carry on: on PostgreSQL the transaction is aborted (`25P02`) and every following statement fails — the package classifies that as 503 `E_AUTHZ_BACKEND_UNAVAILABLE` with the `pg` error as `cause` (never the raw error with your SQL in it); on MySQL and SQLite the engine does **not** abort the transaction and what follows **is committed**. The divergence is the engines', pinned by the suite on the three (*"un error SQL tragado dentro de fn envenena la transacción en PostgreSQL ⇒ 503 …; en MySQL y SQLite la transacción sigue y se confirma"*).

## Upgrading from 1.x to 2.x

2.x is a breaking release with **no compatibility flags** (the [CHANGELOG summary](./CHANGELOG.md)
groups every breaking change by risk); this section is the whole upgrade path.

**The schema jump.** 1.x had `authz_permissions`, `authz_roles`, `authz_role_permissions`,
`authz_assignments` and `authz_denies`, with `uuid` identity columns, `timestamp` for `expires_at`,
the default collation, a `(slug, scope_type)` unique on roles, and no version row. 2.x adds and
changes:

- **`authz_catalog_version`** — the cross-process catalog version (row `id = 1`) and the durable,
  fleet-wide freeze (row `id = 2`). Without a readable version row every write is 503 "migration 2.0
  not applied" (invariant 14), so both rows are seeded at version 0.
- **`authz_roles.owner_scope_key`** (`varchar(80)`, `DEFAULT 'global'`) plus the new
  `(slug, scope_type, owner_scope_key)` unique — roles are global or local to an owner scope (2.2). A
  1.x role stays **global** and the next `authz:catalog:sync` recognises it as the same role (same
  uuid), without duplicating it.
- **`authz_permissions.assignable_at`** (`varchar(500)`, nullable) — the levels a permission may be
  composed at (2.2).
- **`authz_relations` and `authz_relations_config`** — the ReBAC tables of 2.4. A fresh install gets
  them from the published forward migration (`node ace configure` publishes all eight tables); the
  ALTER recipe below does **not** create them, because they are new tables, not a transformation of
  1.x ones. `authz_relations.expires_at` (`DATETIME(3)`, nullable) arrived in **2.4.0-alpha.2**: see
  [the alpha.1 → alpha.2 recipe](#upgrading-from-240-alpha1-authz_relationsexpires_at).
- Identity columns become **`varchar(64)` `collate utf8mb4_bin`** (not `uuid`), so a non-UUID id
  (`user-42`, a ULID) is valid and case is compared byte-wise; `expires_at` becomes **`DATETIME(3)`**
  (millisecond-exact, valid past 2038). Each was a red test first — see [Operational notes for the SQL
  engines](#operational-notes-for-the-sql-engines).
- **The scope-tree outbox** (`authz_scope_outbox`) is **opt-in** and not part of this recipe: `node
  ace configure` offers to publish its migration, or copy `stubs/scopes_outbox_migration.stub`
  yourself (see [the tree outbox](#the-tree-outbox-and-the-relay-lag-you-are-accepting)).

**There is no id-migration command, and 2.x does not read a 1.x OpenFGA store.** A store written by
1.x/2.0–2.1 carried the role **slug** in the binding id, under the old `resolver`-mode tuple shapes;
2.2+ carries the role **uuid** and the `facts` model does not even declare those shapes, so those
tuples grant nothing and are no membership. The way across is **`authz:reconcile --to=openfga
--from=database --prune`**, which rebuilds the store from `authz_*` and your tree and clears the
leftovers in one pass — there is no `openfga:import` (removed in 2.3). See [Migrating and
verifying](#migrating-and-verifying-authzreconcile-23).

**The SQL recipe.** Upgrading a 1.x installation (which used `uuid` columns, `timestamp` for `expires_at`, the default collation, had no `authz_catalog_version`, and — before 2.2 — no `owner_scope_key` on roles nor `assignable_at` on permissions): run the statements below for your engine in a migration of your own. They are **executed by the suite** (`tests/upgrade_recipe.spec.ts`): the 1.1.0 migration is created on a scratch database with a role already in it, these exact statements are applied, the resulting schema is compared column by column with the published migration, and the 2.x engine is exercised on top (non-UUID ids, millisecond expiry, dates past 2038, byte-wise identity, the catalog version, and the pre-existing role left **global** and recognised by the next sync as the same role). Existing UUID values are valid strings; nothing needs rewriting.

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
  updated_at timestamptz NOT NULL,
  freeze_reason varchar(255),
  freeze_holder varchar(120),
  freeze_until_ms bigint,
  freeze_fence bigint NOT NULL DEFAULT 0
);
INSERT INTO authz_catalog_version (id, version, updated_at) VALUES (1, 0, now());
INSERT INTO authz_catalog_version (id, version, updated_at) VALUES (2, 0, now());
ALTER TABLE authz_roles ADD COLUMN owner_scope_key varchar(80) NOT NULL DEFAULT 'global';
ALTER TABLE authz_roles DROP CONSTRAINT authz_roles_slug_scope_uq;
ALTER TABLE authz_roles ADD CONSTRAINT authz_roles_slug_scope_owner_uq UNIQUE (slug, scope_type, owner_scope_key);
CREATE INDEX authz_roles_owner_idx ON authz_roles (owner_scope_key);
ALTER TABLE authz_permissions ADD COLUMN assignable_at varchar(500);
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
  updated_at timestamp NOT NULL,
  freeze_reason varchar(255) NULL,
  freeze_holder varchar(120) NULL,
  freeze_until_ms bigint NULL,
  freeze_fence bigint NOT NULL DEFAULT 0
);
INSERT INTO authz_catalog_version (id, version, updated_at) VALUES (1, 0, CURRENT_TIMESTAMP);
INSERT INTO authz_catalog_version (id, version, updated_at) VALUES (2, 0, CURRENT_TIMESTAMP);
ALTER TABLE authz_roles
  ADD COLUMN owner_scope_key varchar(80) COLLATE utf8mb4_bin NOT NULL DEFAULT 'global',
  DROP INDEX authz_roles_slug_scope_uq,
  ADD UNIQUE INDEX authz_roles_slug_scope_owner_uq (slug, scope_type, owner_scope_key),
  ADD INDEX authz_roles_owner_idx (owner_scope_key);
ALTER TABLE authz_permissions ADD COLUMN assignable_at varchar(500) NULL;
```

### Upgrading from 2.4.0-alpha.1: `authz_relations.expires_at`

Relation expiry (R-15) adds **one nullable column** to `authz_relations`; nothing else changes and
existing rows keep granting (NULL = no expiry). It is the same type decision as
`authz_assignments.expires_at` (millisecond precision, valid past 2038 — 2.5 · J3). A Lucid
migration does it engine-agnostically:

```ts
this.schema.alterTable('authz_relations', (table) => {
  table.datetime('expires_at', { precision: 3 }).nullable()
})
```

Or by hand:

```sql
-- PostgreSQL
ALTER TABLE authz_relations ADD COLUMN expires_at timestamptz(3) NULL;
-- MySQL
ALTER TABLE authz_relations ADD COLUMN expires_at datetime(3) NULL;
-- SQLite
ALTER TABLE authz_relations ADD COLUMN expires_at datetime NULL;
```

The `openfga` driver needs **no store migration**: the fused model gains `with not_expired` on every
relation subject, so republish it (`node ace openfga:provision --store-id <id>` with your
`relations.config` loaded, or any `saveRelationsConfig`/catalog sync that republishes the fused model)
— existing tuples have no condition and keep granting without expiry.

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
