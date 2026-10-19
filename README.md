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

> **Upgrading to 2.4.0-alpha.7 on MySQL from 2.4.0-alpha.4 or earlier — stop the relay, do not roll.** alpha.5 and alpha.6 took both the old (64-char-truncated) and the new (stable, hashed) `GET_LOCK` names of the outbox lease so a mixed rolling deploy kept a single writer; alpha.7 takes only the new one (`SCOPE_OUTBOX_TAKES_LEGACY_LOCK = false`). A leftover alpha.4 relay holding the old name is **not seen** by alpha.7 — pinned by a case, on purpose — so upgrade with a full stop of every relay (cron and inline) and a restart. From alpha.5 or later, or on PostgreSQL/SQLite, nothing to do.

> **Upgrading to 2.4.0-alpha.4 — how the commands are registered.** `@jantstack/adonis-authz/commands` is now a real ace loader (it exports `getMetaData()`/`getCommand()`, built with `ListLoader` over the nine command classes, next to the named class exports). Until alpha.4 it only re-exported the classes, so the line `configure` writes — `commands: [() => import('@jantstack/adonis-authz/commands')]` — made **the whole `node ace` crash** at boot (`TypeError: loaderInstance.getMetaData is not a function`). If you registered the commands by wrapping the barrel in a `ListLoader(Object.values(m))` (the only way it worked before alpha.4), remove the wrapper and register the module directly: `() => import('@jantstack/adonis-authz/commands')`, which is what `node ace configure` writes. The wrapper now fails with `TypeError: command.serialize is not a function`, because the module also exports the loader functions: `Object.values(m)` includes them and `ListLoader.getMetaData()` calls `serialize()` on each value. The module has no `default` export on purpose — ace calls `getMetaData()` on the module namespace and never unwraps `default` (same shape as `@adonisjs/core/commands`).

For the OpenFGA driver, also install its SDK (optional peer): `npm i @openfga/sdk`. Everything that touches the SDK lives behind the **`@jantstack/adonis-authz/openfga` subpath** (`OpenFgaAuthorizationDriver`, `OpenFgaRelationsDriver`, `provisionOpenFgaStore`, `openFgaFactsModel`, `assertHolderTypes`); the main entry never imports it, so a database-only install boots without the SDK (the suite loads `index.ts` in a child process with `@openfga/sdk` blocked to prove it: *"index.ts (la entrada principal) carga con el SDK bloqueado"*). The published config imports the driver from that subpath *inside* the factory.

## Semantics (what every driver guarantees)

These are the eight invariants of the contract. Every one of them is a case in the suite that both drivers run (`src/testing/contract.ts`); the case titles are quoted so you can find them.

1. **Hierarchical scopes, inheritance only downward.** A grant on a scope authorizes on that scope and all its descendants — never on siblings or ancestors. The engine only reserves the root (`app`); every other level is yours, declared by the `resolveChain` resolver you inject — which answers the **canonical chain** `[the scope as stored in your table, ...ancestors]`, so the identity of a scope is what your tree says, never the spelling the caller used (*"un alias del uuid del scope … jamás evade un deny"*) — and the suite proves it on a real three-level tree, in memory and on a real SQL table on PostgreSQL and MySQL (*"herencia de dos niveles"*, *"grant en una org vale en sus units, no en app ni en la org hermana"*, *"mover una unit fuera de la org… le quita el permiso, sin otra escritura"*).
2. **Explicit deny wins.** A deny anywhere in the scope chain blocks the permission even if a role grants it; removing the deny restores it; the order of writes does not matter (*"deny explícito gana sobre el rol"*, *"deny antes del grant también bloquea"*). A deny governs `authorize` only — **it does not affect `hasRole`**, which is a membership fact, not an access decision (*"un deny NO afecta a hasRole"*). That is why no middleware in this package accepts a role.
3. **Expiry is observable, without a scheduler.** An assignment past its `expiresAt` grants nothing — enforced in SQL by `database`, by an FGA *condition* in `openfga`, and filtered client-side in enumerations (*"asignación expirada no concede; expiración futura sí"*).
4. **Polymorphic holders.** `{ type: morphName, uuid }`. Two holders with the same uuid and a different type never cross (*"holder polimórfico"*). The `openfga` driver refuses a `holderTypes` map that would merge two morph names into one FGA type (*"holderTypes tiene que ser inyectivo"*).
5. **Deny by default, and three distinguishable outcomes.** No permission, unknown permission, no live assignment, unknown scope → `false`, never a throw. A malformed question (unknown role or permission in `grant`/`deny`/`revoke`/`removeDeny`, invalid identity, bad slug, a `RoleQuery` object where a slug is expected, an `expiresAt` that is not a valid `Date`/`null`, unknown scope on a write) → **422** with an `E_AUTHZ_*` code. A dependency that does not answer — the facts backend, the SQL catalog **in both drivers**, or your own resolver (throwing *or* answering a malformed ancestor) — → **503**, never a silent `false`; in `openfga` a per-check `error` inside a 200 `batchCheck` is classified exactly like the same failure thrown by a single `Check`, in the deny phase and in the role phase (*"un resolutor de ancestros que lanza ⇒ 503"*, *"authorize con el catálogo inaccesible lanza AuthorizationBackendError"*, *"authorize: error en un check de rol ⇒ 503"*). **Since 2.5.0-alpha.4 (R3) `openfga` tells the dependency that does not answer from the one that answers "no"**: a deployment the config does not match — store or model that does not exist, credentials (401/403), a type, relation or context the pinned model rejects — is **500 `E_AUTHZ_CONFIG` "not transient"** (retrying fails the same way until the deployment is fixed; the tree relay still treats it as transient, so it never parks an entry), an unknown 4xx is 500 with the server's error as `cause`, and a graph deeper than the engine resolves is **503 `E_AUTHZ_RESOLUTION_LIMIT`** (see [Limits](#limits)) — see [How OpenFGA failures are classified](#how-openfga-failures-are-classified-250-alpha4).
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

**How deep can the tree go?** In `database`, as deep as your resolver walks. With the `openfga` driver the `facts` model resolves a chain reliably up to **22 `parent` hops** (`FACTS_MAX_RESOLVE_DEPTH`) and answers 503 `E_AUTHZ_RESOLUTION_LIMIT` — never `false` — past it, so design the tree with that number in front of you and, if you want the engine to refuse the 23rd level before it is written, declare `scopes.maxDepth` (422 `E_AUTHZ_SCOPE_DEPTH_LIMIT`, partial: it does not see the height of a moved subtree). Every bound the package enforces is in one table: [Limits](#limits).

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
node ace authz:scopes:relay --only=12,13 # apply only these entries (the receipt of scopes.*), 2.4.0-alpha.5
node ace authz:scopes:requeue --id=12    # return a parked entry to the queue (refuses to revert later applied changes), 2.4.0-alpha.5
node ace authz:scopes:relay --max-age=300000   # exit ≠ 0 if the oldest pending entry is older than 5 min (the age is always printed), 2.4.0-alpha.8
```

The package **does not impose a table**: the contract is the `ScopeOutbox` port (`enqueue`, `pending`, `markApplied`, `markFailed`, plus five optional ones: `dead` for parked entries, `acquire` for the single-writer lease and, since 2.4.0-alpha.5, `earlierPending` — the dependency probe of `only` —, `requeue` and `laterApplied` — the pair behind `authz:scopes:requeue`; in the same release `enqueue` may return `{ id }`, `pending` takes an optional `{ ids }` filter and `markFailed` an optional `{ transient }`, all three covariant: an implementation written against alpha.4 still compiles and works). Since 2.4.0-alpha.5 the port has a published judge, [`runScopeOutboxContract`](#the-outbox-contract-runscopeoutboxcontract-240-alpha5). `sqlScopeOutbox` is the published implementation over Lucid and `stubs/scopes_outbox_migration.stub` is its migration — **copy it into your migrations yourself**; `node ace configure` does not publish it, because the outbox is opt-in. Two things an implementation must do: write `enqueue` inside the transaction it is handed, and **`pending()` must return the whole unapplied queue, oldest first** — it must not hide an entry the relay did not filter through `{ ids }`, by tenant, by scope or by anything else: the order guarantee of the relay (a `moved` before the `attached` that depends on it) rests on the manager seeing the whole queue, and no guard of the manager can tell when a port hides rows on its own (that is exactly how the cross-tenant escalation measured in the audit is reproduced with a "filtering" outbox). It is a duty of the port and the contract judges it (O-08).

**Two rules about that transaction (2.4.0-alpha.2, lot L-1).** First, **`{ transaction }` carries the write, never the authority**: the freeze barrier that precedes every write (row `id = 2` of `authz_catalog_version`, see [the freeze](#migrating-and-verifying-authzreconcile-23)) is read through the engine's own connection, **never through your transaction** — a transaction opened *before* a freeze does not see it in its snapshot (InnoDB's REPEATABLE READ, PostgreSQL under that level, SQLite in WAL), and a barrier decided by the caller's snapshot is not a barrier (the suite reproduces the bypass on all three engines and pins the 503). The price is declared: **`{ transaction }` requires a connection pool of at least 2**. With a pool of 1 (SQLite `:memory:`) the barrier cannot get a connection while you hold the only one, and the notification is **503 `E_AUTHZ_BACKEND_TIMEOUT` at `freezeTimeoutMs`** (config, default 5000 ms) — fail-closed, never a hang, never a bypass. Second, `sqlScopeOutbox` **checks whose transaction it is**: it must be an *open* Lucid transaction (`isTransaction === true`) of the **outbox's own connection** (`connection`, or the primary one). A transaction of another connection, a `QueryClient` (`db.connection()`) or the whole `db` service are **500 `E_AUTHZ_CONFIG`** naming both connections, before any statement — until L-1 a transaction of another connection silently enqueued in *its* database (where no relay reads and `dead()` never shows it), and `db` passed the duck-check and wrote outside any transaction, in silence. The same check (`assertCallerTransaction`) is the rule for every `{ transaction }` of the package. The whole story — what `{ transaction }` means on each call, what the engines do, the `resolveChain` limit and what `openfga` offers instead — is in [Writing inside your transaction](#writing-inside-your-transaction-240-alpha2).

The relay is resumable and never silent: the report says *which* changes were applied, not a count. A change that cannot be applied **defers what depends on it and lets the rest through**: the failure poisons the scopes that change names, every later change naming one of them is reported as `deferred` and not attempted (transitively), and everything else is applied. That is what keeps the tree order — `attached(P, org)` before `attached(C, P)`, a `moved` before the `detached` of the same node — without letting one tenant freeze the queue for all of them. Until 2.0 the pass stopped at the first failure, and a single change that can never be applied (its parent scope was deleted before the pass) then blocked every later change of every tenant, indefinitely. `sqlScopeOutbox` also **parks** an entry after `maxAttempts` failures (default 5): it stops being retried, it is reported in `dead` on every pass, and the command exits non-zero while any exists — a parked entry is a permanent divergence of the backend's tree, not a resolved incident. The command exits non-zero on any failure too, so a supervisor notices. Applying a queued `detached` runs `purgeScope` and only then removes the edge, and it emits the `scope_purged` audit event at that point, carrying the actor that ordered it.

**"Was mine applied?" — the receipt and `only` (2.4.0-alpha.5).** `scopes.attached/moved/detached` return a receipt, **`{ queued: [id] }`** — the outbox ids of what they just enqueued (plural on purpose: a `detached` whose row is already gone enqueues one entry per spelling of the uuid). Empty means there is nothing to relay: without an outbox the change was applied inline; with a third-party `ScopeOutbox` whose `enqueue` still returns `void` there is no id, and then there is no `only` either. Hand the receipt to the relay on the interactive path, right after your commit: **`await authorization.relayScopeChanges({ only: queued })`**. That is the fix for the cost a consumer measured: with 500 entries of another tenant ahead in the queue, the inline pass cost **4,507 ms and 2,004 OpenFGA calls** to land one change; with `only` it costs **19 ms and 4 calls**, because the filter lives in the port (`pending(limit, after, { ids })` — the primary key) and the pass never reads the other 500 rows (the suite spies on `pending` to pin that; a port implementation that ignores the filter is 500 `E_AUTHZ_CONFIG` before anything is applied, never a silent drain of the backlog inside your request). **The order by scope key is not relaxed — deferred, never out of order.** Before applying each requested entry the relay probes the *whole* queue (`earlierPending`: one existence query against the `(applied_at, id)` index, 0.69 ms measured; a port without it is paged through `pending()`): if an earlier unapplied entry names one of the same scopes and was not requested, yours is reported `deferred` with `depends-on:<id>` and not applied. Why, measured: with `#1 moved(unit → orgB)` pending and `only: [#2 attached(child, unit)]`, a filter without the probe wrote `child → unit` while the store still said `unit → orgA`, and the editor of the *old* organization authorised over the child (`authorize(A@orgA, docs:read, child) = true`, report all green). One level is enough — the last link of any chain of pending dependencies shares a scope with yours by definition of the key contamination — so the probe costs one query, not the queue. The report is **per entry**: `entries` names every entry the pass looked at, `applied` / `deferred` (reason `depends-on:<id>` or `parked:<id>`) / `failed` / `dead`, with or without `only`; and `missing` names the ids of `only` that are not in the queue at all — neither pending nor parked: already applied by an earlier pass, or unknown; the relay cannot tell — never an empty report in green. **`notEvaluated` names the ids of `only` that are still pending and the pass never looked at** because it reached `limit` first (2.4.0-alpha.10): until then `{ only: [a, b], limit: 1 }` put the pending `b` in `missing` — "already applied, or unknown" — and the applying pass exited 0. Telling them apart costs one read of the queue filtered by those ids, only when some requested id was not seen. `authz:scopes:relay --only … --limit …` names each of them ("is PENDING and this pass did NOT evaluate it", saying whether it was `--dry-run` or the applying pass and which `--limit`) and exits ≠ 0, in both. `only: []` is 500 `E_AUTHZ_CONFIG`: an empty `filter` on your side, or a receipt from an outbox without ids, cannot end up draining the whole queue under the lease of an HTTP request. **`remaining` and `dead` are always global**, with or without `only`: a filtered report that kept quiet about a queue that does not converge would be a green report over a broken tree. Three things this is **not**. `only` takes the ids from the receipt your own process just got, **never from the request body** — an endpoint that accepts `only` from a client is policy in an API that has no policy (the relay skips `requireActor`/`requireWithin` on purpose). **There is no filter by tenant or organization**: a `detached` whose row is already gone belongs to no organization (excluding it always is a permanent fail-open — its facts are never purged; including it always is "anyone relays anyone's `detached`"), and a `moved` would be attributed to its *destination*, which is the bias that keeps accesses. And `only` does not pull its dependencies along — that is transitive and ends up being the whole queue; if what you want is "the queue landed up to here", run the relay without `only`. **Do not return the relay report over HTTP**: it enumerates the tree activity of every tenant (ids, scope uuids, actors, the backend's error text); read it, log it, act on `entries`, and hand the client your own answer. Finally, **the inline pass returns a report, it does not throw**: a `deferred` or a `failures` does not abort your request unless you look at it — if `entries` says your change is `deferred`, it has not landed, and that is the fail-closed window described below.

**A 503 does not consume an attempt (2.4.0-alpha.5).** `maxAttempts` exists to converge on the *irreparable* — the parent of an enqueued `attached` was deleted and will not come back — and until alpha.4 a backend outage spent the same budget: measured, with the store down, **five requests of another tenant** running the inline relay parked an entry that was not theirs (one attempt per request: the entry at the head of the queue pays for everyone's pass), and from then on its dependants were applied without it. Now the manager tells the two apart by the nature of the error: an `AuthorizationBackendError` — the store did not answer, the deadline expired, any 503 — is reported in `failures` with `transient: true` and passed to `markFailed(id, error, { transient: true })`, and `sqlScopeOutbox` writes `last_error` **without** counting the attempt; a 422, a 500, `E_AUTHZ_SCOPE_TREE_DRIFT`, a missing parent or a bare error from a third-party driver count as before. A port implementation that ignores the third parameter counts everything — exactly the alpha.4 behaviour, degrading towards safe. For the inline recipe, with the numbers: an outage of the store lasting `N` requests leaves `N−1` entries deferred behind the failing head on request `N`, and none of them parked.

**A parked entry blocks, by scope key, what grants or re-parents (`attached`, `moved`) and lets through what retires (`detached`) (2.4.0-alpha.5).** Until alpha.4 a parked entry left `pending()` and stopped contaminating, so what depended on it was applied *without* it — for an `attached` behind a parked `moved` that is the store keeping the **old parent, permanently**, the persistent escalation this outbox exists to prevent (measured; and live in a consumer running the inline relay, with no change of theirs involved). Now the keys of `dead()` seed the blocked set at the start of every pass: an `attached` or `moved` naming one of those scopes is reported `deferred` with `parked:<id>`, on every pass, until someone looks at the parked entry (the command names it; the way out is `authz:reconcile --to=<driver>`, which recomputes with today's tree, or a new notification from your side). A `detached` of that key is applied anyway — a purge never waits (invariant 11: a half-applied tree may leave denies *in excess*, never facts alive on a node nobody purges) — **and that holds transitively** (closing lot of alpha.5, auditor 🟠 1): a `detached` behind an `attached` that is itself deferred *because of* a parked entry is applied too, because the manager tracks the *origin* of every key block; only a block born from a real failure of the pass (an entry that threw) still holds a purge back, as it did since 2.0, so the order between a failed `attached` and the purge of that same node is kept. The parked keys are read **in full on every pass, whatever `--limit` or `batchSize`** (🟠 2: a census bounded by `limit` let the 101st parked entry go unnoticed with `--limit 50` or the inline `{ only, limit: 1 }`, and the `attached` landed under the old parent); more than `PARKED_CENSUS_MAX` (50,000) parked entries is a 500 before anything is applied, never a blind plug. The price is declared: one irreparable parked entry freezes the *grants and moves* of its scope key until a human acts — bounded to the key, not the queue, and loud (`deferred` + `dead` + exit code ≠ 0).

**When the parked set grows.** Nothing in the package shrinks it for you, on purpose: `authz:reconcile` never touches the outbox (the counter does not go down), `authz:scopes:requeue` has no `--all` (re-queueing an irreparable entry parks it again in one pass, and re-queueing a stale one is the reversal the probe refuses), and past `PARKED_CENSUS_MAX` (50,000) every pass is a 500 before applying anything. The remedy is an operator's SQL on **your** table: list `authz_scope_outbox` rows with `attempts >= maxAttempts` and `applied_at IS NULL`, read `last_error`, and either `authz:scopes:requeue --id` the ones whose cause is gone (a parent that exists again) or **delete** the irreparable ones (a parent that will never exist) — then `authz:reconcile --to=<driver>` rebuilds the tree from today's rows. Deleting a parked entry is safe for the tree only because the reconcile recomputes it; do not delete and skip the reconcile.

**The root `app` is not a scope key, and a parked entry only plugs the key of its own child (2.4.0-alpha.8).** Two corrections to the key rule above, both measured in a consumer. *First*, until alpha.7 the keys of an `attached`/`moved` were `[child, parent]` and the parent of every tenant registration is `app`, so every tenant registration shared a key with every other one: one parked `attached(orgA, app)` left every later registration `deferred · parked:` on every pass (five passes with `applied = []`), two concurrent registrations relayed inline left the second one `deferred · depends-on:` **with nothing parked at all** (the root was a global serialiser of sign-ups, and under (c2r) a fail-closed one: the new organisation granted nothing until the cron ran), and `authz:scopes:requeue` refused the parked one with a false conflict as soon as another tenant had registered. The root **never moves, is never purged and is never a child** (`scopes.attached(APP_SCOPE, …)`, `scopes.moved(APP_SCOPE, …)` and `scopes.detached(APP_SCOPE)` are 422), so two changes whose *only* shared scope is `app` commute and there is no order to keep: the manager now leaves the root out of the keys — decided on the reference (`type === 'app'` and a null uuid), never on the string `'app'`, and in the three places that build the list (the pass, the `only` probe, the requeue probe), also for blocks born from a real failure. The child's key still orders everything that matters: a `detached(orgA)` that failed still holds back an `attached(orgA, app)` with the same uuid, and a failed `moved(unit, app)` still holds back a later `moved(unit, orgB)`. The port is untouched: `sqlScopeOutbox.earlierPending`/`laterApplied` still know how to match the root as a parent; the manager just never asks. *Second*, the parked census now seeds only the key of the parked entry's **child**: a parked entry says the position of *its child* in the store is wrong, nothing about its new parent, so a `moved(otherUnit → orgA)` behind a parked `moved(unit → orgA)` is applied (until alpha.7 it was `deferred · parked:` for no reason and the store kept the old parent of everything under `orgA` with no expiry), while `attached(child, unit)` and `moved(unit → orgC)` — which name the parked child — stay `deferred · parked:<id>` and a `detached(unit)` still passes. When comparing two changes the manager still uses both keys; only the seeding of the census changed. Both are a change of observable behaviour: an `attached`/`moved` that used to come out `deferred` under those conditions is now applied, which is the bug.

**Under `only` the purge exemption holds too (2.4.0-alpha.6).** With `relayScopeChanges({ only })` the probe that finds an earlier unapplied entry sharing a scope key with yours now **inherits the origin of the block** of that entry, the same way the full pass tracks it: if the earlier entry is — directly or through its own dependencies — waiting only on a **parked** one (it would be `parked:<id>` or `depends-on:` of one in a full pass), a requested `detached` is **applied and purges**, exactly as in the full pass (invariant 11: a purge never waits for a parked entry). If the earlier entry is an `attached`/`moved` that is genuinely pending (it would be applied by the next full pass) or is held by a **real failure** of the pass, the `detached` stays `deferred` (`depends-on:<id>`), because applying a purge ahead of a pending `moved` of the same scope leaves drift. Until alpha.6 the probe marked every such deferral as a real block, so a deployment that only ever relayed inline never purged behind a parked entry (audit 🟡 of alpha.5, measured). The probe walks back one `earlierPending` query per hop over entries it does not apply, at most `RELAY_ORIGIN_MAX_HOPS` (100) hops; past that it assumes a real block and defers — towards safe, never applying without knowing. Entries you did not request are not touched: they keep their attempts and their place.

**Requeueing a parked entry: `node ace authz:scopes:requeue --id=<id>` (2.4.0-alpha.5).** A parked entry is never retried on its own. When you have fixed the cause — the missing parent is back, the store was reconciled — `authorization.requeueScopeChanges([id])` (platform API, like the relay; the command is its ace face) returns it to `pending()` with its old id, and **`attempts` is set to `maxAttempts − 1`**, neither `0` nor kept (owner's decision): if the cause is still broken the entry is parked again after **one** pass — and it contaminates its scope key only during that pass, so an automated requeue of something irreparable is not a permanent deferral tap for that tenant's new changes —, and if you fixed it, it lands on the first pass. No new column. It is all or nothing: an id that does not exist, is still pending, or was already applied is a 500 naming it and **no row is touched** (an applied entry never comes back: requeueing an applied `detached` would purge again). **The anti-reversion probe lives in the manager and has no exception.** Before touching the queue it asks the port (`laterApplied`) whether an entry *applied after* the parked one shares a scope key with it; if one does, requeueing would re-apply the old change on top of the new — measured: a parked `moved(unit → orgB)` requeued after `moved(unit → orgC)` was applied leaves the store with the **old** parent and a single edge, so nothing denounces it while the old tenant regains access — and the call is **500 `E_AUTHZ_REQUEUE_REFUSED`** naming the later entry and the key, with the right remedy (`authz:reconcile --to=<driver>`, which recomputes with today's tree). **`--force` exists only in the ace command**: it prints the diff — the parked entry and every applied entry it would revert — and then requeues anyway; `requeueScopeChanges(ids, { force: true })` is what the command calls and nothing reachable over HTTP should. The probe is the manager's, not the table's, so a third-party `ScopeOutbox` gets it for free by implementing the two optional methods (`requeue` and `laterApplied`); without them the command says so (500 `E_AUTHZ_UNSUPPORTED`). Two limits of the probe, written: the diff lists at most 100 later entries per parked one and says when it is cut (`truncated`, "… y más"); and **`laterApplied` only sees the outbox** — `authz:reconcile` does not write to it, so a requeue *after* a reconcile can revert what the reconcile just certified and the probe has nothing to compare against: **do not requeue after reconciling**; if you already did, the remedy is to reconcile again.

**Closing the incident in one call: `requeueScopeChanges(ids, { apply: true })` / `node ace authz:scopes:requeue --id=<id> --apply` (2.4.0-alpha.8).** Measured in a consumer (panel relay 2, tester P14): after `requeue` the entry comes back with its *original* id — smaller than everything enqueued since — so the tenant's next inline `relayScopeChanges({ only })` found it *in front* and came out `deferred · depends-on:<id>`; the incident needed a full pass behind the command. With `apply: true` the entry is requeued **and relayed in the same call**, and the relay's report travels in `report.relay`. Four rules, each pinned by a case: **one lease** for the whole call, taken *first* — if another pass holds it the result is `relay.busy === true` with **zero rows requeued** and the command exits ≠ 0 (requeueing and then saying "busy" would leave the entry pending with `attempts = maxAttempts − 1`, to be parked again by the next pass and poison its key once more; `waitForLeaseMs` composes with it); it **passes the freeze barrier** before touching anything (with `apply` the command writes the tree; without `apply`, `requeue` still does not, it only touches the queue); it **does not compose with `force`** (500 `E_AUTHZ_CONFIG` — with both, reverting the tree over what was applied later would be a single call); and the internal `only` is **exactly the requeued ids**: what depended on the parked entry is *not* dragged along (it stays `deferred`/pending, the report says so — `remaining`, and the command prints it), because `only` is *your receipt* and nothing else. The anti-reversion probe still runs before anything is requeued (a refusal is 500 with zero driver calls, and the lease is released). If the cause is still broken, the same call parks the entry again (`attempts` goes from `maxAttempts − 1` to `maxAttempts`, `relay.failed` says why); a 503 from the store leaves it pending with `attempts = maxAttempts − 1`, as always. `--apply` is explicit, never the default: without it the command behaves exactly as before. Platform API, like the relay: never reachable over HTTP.

**The relay is a single writer.** `pending()` reserves nothing, so two passes at once (a Kubernetes `CronJob` with the default `concurrencyPolicy: Allow`, two replicas, a pass that lasts longer than its interval) work on the same batch: the straggler re-applies an old `attached` after the other applied the new `moved`, and the store is left with the **old parent and a single edge, so nothing denounces it** — the old tenant keeps access to a subtree that is no longer theirs (measured). `sqlScopeOutbox.acquire()` takes a lease for the pass — a server-side lock on PostgreSQL and MySQL, a process-wide one on SQLite — and a second simultaneous pass does nothing and says so (`busy`). Since 2.4.0-alpha.5 that is **observed between real processes** (`tests/scope_outbox_multiprocess.spec.ts`: a second process relays the same queue while the first holds the lease ⇒ `busy`, zero writes, on PostgreSQL and MySQL), and the SQLite limitation is pinned the same way — the second process *does* apply over the first: **SQLite is not the engine for two replicas of the relay**. If you implement the port yourself and skip `acquire`, run the relay one pass at a time.

**Waiting for the lease instead of giving up: `relayScopeChanges({ waitForLeaseMs })` / `--wait-lease-ms` (2.4.0-alpha.8).** By default (`waitForLeaseMs: 0`) a pass that finds the lease taken reports `busy` at once — one `acquire()` attempt, the behaviour above, unchanged. With a positive value the pass retries `acquire()` every `RELAY_LEASE_POLL_MS` (25 ms; measured 0.29 ms per busy poll in PostgreSQL, and a failed poll holds no connection between attempts) until the lease is free or the budget is spent, and then reports `busy` — bounded, never a hang. It is opt-in and it **needs a pool of at least 2** connections, like `{ transaction }`: with a pool of 1 the waiting pass may be holding the very connection the pass that has the lease needs. Do not size it to a full backlog: a pass over 2,000 entries with real backend writes takes tens of seconds; the option exists so that an operator's `authz:scopes:requeue --apply --wait-lease-ms` does not lose systematically against the cron, not to queue relays behind each other.

**How old is the queue? `report.queue` and `--max-age` (2.4.0-alpha.8).** Measured in a consumer (panel relay 2, auditor B2): with the store down, ten relay passes in a row reported `attempts = 0` on every entry (a 503 does not consume an attempt, since alpha.5), `dead = 0` and **no notion of time anywhere** — the cron was red because of `failures`, but nobody could tell since when, and nothing distinguished a queue that has been stuck for an hour from one that was enqueued a second ago. Every relay report now carries **`queue: { oldestPendingAt, pendingAgeMs }`**: the `createdAt` of the **oldest pending entry of the whole queue** — the `pending(1)` the pass already ran at the end for `remaining`, so it costs no extra query — and its age, `max(0, now − createdAt)`, measured with the manager's injectable clock (`config.clock`; no `Date.now()` in the package sources, the suite greps for it). It is **always global, also under `only`**, like `remaining` and `dead`: it names nobody, it only says "there is backlog". Both fields are `null` when nothing is *pending* (an empty queue, or only parked entries — those have their own alarm, `deadCount`, below) and when the port does not provide `createdAt`: a third-party `ScopeOutbox` whose entries carry no `createdAt` reads as `null`, **never as `0` or "now"** (the same rule as `stillGranting`: "I do not know" does not degrade to a number). `sqlScopeOutbox` returns it from the `created_at` column it already had (`createdAt?: Date` is an optional field of `PendingScopeTreeChange`; the outbox contract has a `createdAt` capability pair). Read the number for what it is: **the age is the clock of whoever enqueued** — another replica with a skewed clock stamps its own `created_at`, so the age is clamped at zero and never negative, and it is not a decision the package takes (audit stamps are not decisions). The command prints it on every pass; **`--max-age=<ms>`** makes the pass exit ≠ 0 when the age is above the threshold — **only with a threshold**: without it the age is reported and never fails the run, because a cron that goes red for ever over a queue that simply has backlog is a cron nobody reads. Parking by age (`parkAfterMs`) is *not* offered, on purpose — see the changelog: it reintroduces, with another clock, the mass parking alpha.5 removed, and it was measured to make every pass a 500 once the census fills.

**Enqueueing outside your transaction: `sqlScopeOutbox({ requireTransaction: true })` (2.4.0-alpha.8).** The mitigation above is *entirely* the `{ transaction: trx }` you hand to `scopes.attached/moved/detached`. Without it the call still enqueues — the row commits on its own, outside your unit of work — and if your transaction rolls back afterwards **the change stays in the queue and the relay applies it to the store**: your database says one parent, the PDP another, and nothing on your side can show it (the S5 leak, on the *correct-use* path; measured by the tester of panel relay 2, P13). With `requireTransaction: true` that call is **500 `E_AUTHZ_CONFIG` before the `INSERT`**, naming exactly that leak, through the manager and through the outbox alone; with an open transaction of the outbox's connection it enqueues as always. **The default is **`true` since 2.5.0** (lot B · B6, owner's decision; it was `false` in 2.4 because the published outbox contract enqueued without a transaction and a `true` default would have turned every third-party outbox red). `requireTransaction: false` is the explicit opt-out — the signature of code that enqueues outside any unit of work on purpose (a seeder, a harness) —, and the published contract now carries the capability pair **`requiresTransaction`** (optional, `false` when absent): with `true` the judge enqueues inside a transaction of your connection in every case, direct and through `scopes.*`, and pins the refusal (500 naming `requireTransaction`, zero rows, by the outbox alone and by the manager); with `false` it pins that enqueueing without one enters. Mind the pool: `{ transaction }` **through the manager** needs a pool of at least 2 (the freeze barrier reads through another connection; with a single one the notification is 503 `E_AUTHZ_BACKEND_TIMEOUT` at `freezeTimeoutMs`), so a deployment with **pool max 1 — knex's default for every SQLite connection, file or `:memory:`** — cannot use the default through `scopes.*`: declare `requireTransaction: false` there and say so (the 500 names the pool and that way out; following its first advice alone on a pool of 1 leads to the 503). A transaction that is **already committed or rolled back** is a different 500, below.

**What the report says about the parked set — `deadCount`, `deadDetail`, and the `origin` of a deferral (2.4.0-alpha.8).** Three small corrections to the report, each measured in a consumer. **`deadCount`** is always present and always global: `dead[]` is capped at `batchSize` (100), so `dead.length` *lies* once more than that is parked; the alarm "the queue does not converge" now rests on the count, which comes from the census the pass already reads for the key plug (no extra query). **Under `only`, `dead[]` carries `id`, `change` and `attempts` and — by default — no `error`**: the inline recipe runs inside a tenant's request, and the error text is what the backend said about *another* tenant's tree; pass `deadDetail: 'full'` to get it back (without `only` nothing changes, and the entries you *asked for* keep their `reason` in `entries`, they are yours). Read this as the safe-fields rule for a report you might be tempted to surface: `deadCount` and the ids say "there is a parked backlog" and nothing else; `change` still names scopes of other tenants (the actor never travels in `dead[]`), so the rule above stands — do not return the report over HTTP. And every `deferred` entry now carries **`origin`**: `'parked'` (held, directly or transitively, by a parked entry — the only origin that lets a `detached` through, invariant 11), `'failed'` (held by a real failure of this pass), or `'pending'` (under `only`: held by an earlier entry that is genuinely pending and was not requested — it will land on the next full pass). Until alpha.8 `depends-on:<id>` did not distinguish the last two and the origin lived only in the Spanish prose of `deferred[].error`; it is derived from the block itself, never parsed back from the text of `reason`.

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

### Writing inside your transaction (2.4.0-alpha.2)

`{ transaction: trx }` — an open Lucid transaction of yours — means **three different things** depending on the call, and the difference is the whole story of this section:

| Call | What `{ transaction }` does | `database` | `openfga` |
|---|---|---|---|
| `grant` / `revoke` / `deny` / `removeDeny` | **writes the fact inside your transaction** — commit and the fact is there with your rows, roll back and neither is | yes (`transactionalWrites: true`, lot L-3) | **500 `E_AUTHZ_UNSUPPORTED`**, nothing called (lot L-5) — see [the recipe by direction](#openfga-the-recipe-by-direction) |
| `relate` / `unrelate` / `purgeObject` / `purgeSubject` | **writes the tuple inside your transaction** | yes (lot L-4) | the same 500 |
| `scopes.attached` / `moved` / `detached` | **enqueues** the tree change in the outbox, inside your transaction (`scopes.outbox`, see [the tree outbox](#the-tree-outbox-and-the-relay-lag-you-are-accepting)). Enqueueing ≠ writing: this never passes the capability gate | both | both |
| `defineScopedRole` / `updateScopedRole` / `deleteScopedRole` | **refused**, 500 `E_AUTHZ_UNSUPPORTED`: the catalog is written through `withAuthzCatalogWrite`, the cross-process serializer (invariant 14), which your transaction would defeat | — | — |

The capability behind the first two rows is **`transactionalWrites`** (same name on both ports), and it means **exactly** *both or neither with your transaction* — never *"not lost"*; there is no intermediate value. `database` declares `true`; `openfga` declares `false` and cannot declare anything else: a tuple lives in another service and there is no two-phase commit between it and your database. `requireTransactionalWrites: true` in the config (root, or `relations.requireTransactionalWrites`) turns a wrong deployment into one that **does not start** — 500 `E_AUTHZ_CONFIG` when the driver is resolved, reads included — instead of a 500 on a rarely travelled route. It is the first capability of this package that is **not portable between drivers**: the same call is 200 on `database` and 500 on `openfga`, and the suite pins that asymmetry on purpose (each driver declares what it can do; you read the capability and adjust).

#### The rule: the write goes through your transaction, the authority never does

**A transaction that is already committed or rolled back is refused before any statement (2.4.0-alpha.8).** Lucid keeps `isTransaction === true` on a finished transaction, so until alpha.7 `assertCallerTransaction` let it through and the statement blew up inside knex as **503 `E_AUTHZ_BACKEND_UNAVAILABLE`** ("the backend did not answer") — which is false: it is the caller's wiring (a `trx` reused after `await trx.commit()`). It is now the fourth check of the shared guard (`isCompleted === true` ⇒ **500 `E_AUTHZ_CONFIG`** naming the operation, "confirmada o revertida", zero statements), in the three places that take `{ transaction }`: `sqlScopeOutbox.enqueue`, the `database` roles driver and the `database` relations driver — pinned in the four engines.

**Through your transaction: the write, and only the write** — the `INSERT`/`UPDATE`/`DELETE`, plus the "does it already exist?" read that belongs to it (a `grant` and its re-grant, a `relate` and its renewal, inside the same transaction see each other). **Through the engine's own connection, always: the authority** — the freeze barrier (row `id = 2` of `authz_catalog_version`), the catalog memo, `resolveChain`, F-05 and `assertWrite`. They are decided **before the first statement on your transaction** (the suite spies on the transaction and counts zero), and a transaction opened *before* a freeze does not get to decide it is not frozen (its snapshot would say so under InnoDB's REPEATABLE READ, PostgreSQL at that level and SQLite in WAL — the suite reproduces the bypass on the three engines and pins the 503). Until 2.4.0-alpha.2 the barrier *was* read through the caller's transaction "so a pool of 1 would not deadlock"; that traded authority for availability and it is gone.

Hence the deployment rule, said out loud: **`{ transaction }` requires a pool of at least 2.** With a pool of 1 (SQLite `:memory:`, the suite's default mode) the authority cannot get a connection while you hold the only one, and the write is **503 `E_AUTHZ_BACKEND_TIMEOUT` at `freezeTimeoutMs`** (config, default 5000 ms — the barrier's own total deadline, pool wait included; knex's own `acquireConnectionTimeout` would have made it 60 s) with **zero statements on your transaction**: fail-closed, never a hang, never a bypass. A pool-of-1 deployment declares it — `new DatabaseAuthorizationDriver({ transactionalWrites: false })`, `new DatabaseRelationsDriver(config, { transactionalWrites: false })` — and gets gate 1's immediate 500 instead; the driver declares what its deployment can do, the package does not guess the pool. This also applies to `scopes.*` with `{ transaction }` (the outbox): a single-connection deployment that used it has to raise the pool (breaking of deployment, lot L-1). While the engine is **frozen**, `{ transaction }` is the retryable 503 `E_AUTHZ_FROZEN` before the first statement on your transaction.

The transaction must be **yours and the driver's**: an open Lucid transaction (`isTransaction === true`) of the driver's connection (the primary one for facts; `connection` or the primary one for relations and the outbox). Another connection, a `QueryClient` (`db.connection()`) or the whole `db` service are 500 `E_AUTHZ_CONFIG` naming both connections, before any statement (`assertCallerTransaction`, exported: the same check for every `{ transaction }` of the package — until lot L-1 a foreign transaction silently enqueued in *its* database and `db` passed the duck-check and wrote outside any transaction). "Both or neither" is only true on the same connection.

What the published suite pins, **by census and not by the answer**: after a rollback `authz_assignments`/`authz_denies` hold zero rows for that holder and `authz_relations` zero new tuples in that partition, for the four writes of each port, on SQLite (file), PostgreSQL and MySQL; `purgeObject`/`purgeSubject` delete and revert *together*; while the transaction is open the authority (reading through the engine's connection) does not see the write; on commit census and answer change together (`runAuthorizationDriverContract` / `runRelationsDriverContract`, the `true` face of the pair). `onWrite`/`onRelationWrite` fire when the driver returns, with **`transactional: true`** on the event: at that instant the row exists only inside your transaction and it is a fact if and only if you commit — the package never sees that; a sink that wants the last word hangs itself on `trx.after('commit')`.

#### What the engines do when the write lives as long as your transaction (measured)

Outside a transaction the driver absorbs a clash: it re-reads and keeps the winner's row (2.5-B · K4). Inside yours it must not — PostgreSQL has already aborted your transaction, and under REPEATABLE READ the re-read would not see the winner (a mutant that re-reads fails differently on each engine) — so **a clash poisons your transaction**: the driver never issues a second statement on a transaction that may be aborted, the choice between roll back and retry is yours, and `onWrite` publishes nothing for the loser (a clash is not a deadline). Measured on the three engines, facts and tuples alike:

| Situation | PostgreSQL | MySQL | SQLite (file, WAL) |
|---|---|---|---|
| **Two open transactions write the same fact/tuple** (unique index) | the second `INSERT` waits until the first ends; on its commit, `23505` ⇒ **409 `E_AUTHZ_WRITE_CONFLICT`** ("roll back and retry"); your transaction is **aborted** (`25P02` on every later statement until you roll back) | waits (shared lock on the duplicate); `1062` ⇒ **409 `E_AUTHZ_WRITE_CONFLICT`**; your transaction **lives on**, only the statement was undone | does not wait: a reader cannot become the writer while another holds the reserved lock ⇒ `SQLITE_BUSY` at once, *before* the first commits ⇒ 503 `E_AUTHZ_BACKEND_UNAVAILABLE`; alive |
| **The driver's `timeoutMs` elapses while your statement waits** | knex cancels the query (`pg_cancel_backend`) ⇒ 503 `E_AUTHZ_BACKEND_TIMEOUT`; **aborted** | knex kills it (`KILL QUERY`) ⇒ 503 `E_AUTHZ_BACKEND_TIMEOUT`; lives on | the synchronous driver cannot elapse a deadline: `SQLITE_BUSY` above |
| **Two transactions write two tuples in crossed order** (A→B / B→A) | detected after `deadlock_timeout` (1 s by default); the victim gets **409 `E_AUTHZ_WRITE_CONFLICT`** (`40P01`) and stays **aborted** until its rollback; the winner waits for that rollback | InnoDB detects it at once; the victim gets **409** (`1213`) and InnoDB **rolls back its whole transaction** — its earlier rows are gone too; the winner may resolve first | cannot deadlock: the second writer is `SQLITE_BUSY` (503) at its first write |
| **A cross-partition userset row your own code inserts on that transaction** (the partition trigger fires inside it, lot L-4) | refused by the trigger; your transaction is **aborted** and the next `relate` of the package on it is a classified 503 (`25P02`), never the raw error | refused; lives on | refused; lives on |
| **A transaction that read before another writer committed** (a freeze put and lifted after your first `SELECT`, say) | — | — | cannot write afterwards: `SQLITE_BUSY` snapshot ⇒ 503, the engine's rule |

Two more things that follow from "as long as your transaction": for the 503 of an elapsed deadline `onWrite` publishes **`indeterminate: true` *and* `transactional: true`** — your rollback does determine the outcome, but the rollback is yours and the package never sees it (invariant 13 stands); and **renewing a relation expiry (delete+insert, R-15) rolls back to the previous expiry** — the census after the rollback holds the old row with its old `expires_at` and its old uuid.

#### The decision is not in your transaction: `resolveChain`

The *row* is inside your transaction; the *decision* that authorises writing it is not. `resolveChain` is your function and it reads your tree through your `db` — the engine's connection, not your transaction — so **the tree is judged against the state before your transaction** (`within` too): creating a scope and granting on it inside the same transaction is 422 `E_AUTHZ_UNKNOWN_SCOPE`, fail-closed, and that is the correct answer, pinned. It is the one limit of this port, and it is not fixed by handing the driver your transaction (that would put the authority back inside the caller's snapshot). Two recipes:

- **To grant on a scope you create in the same transaction**, use a `ScopeChainResolver` that closes over your transaction — `scopes.resolveChain` is a plain callback of yours and nothing stops it from reading your tree through `trx` (no case of this package exercises that form: it is your code). You are then telling the authority to trust your uncommitted tree — your call, said out loud. Otherwise commit the scope first and grant after.
- **If you move the tree *and* write facts in the same transaction, notify `authorization.scopes.*` first**, then write the facts. The notification validates the move against the tree as it stands (anti-cycles, existence), and with the outbox it **enqueues** in your transaction, so the tree change and your rows commit or vanish together; the facts you write after it are still judged against the pre-transaction tree, which is the fail-closed side.

#### `openfga`: the recipe by direction

`openfga` cannot put a tuple in your transaction and says so — 500 `E_AUTHZ_UNSUPPORTED` on every write that carries `{ transaction }`, through the manager **and through the driver itself** (`manager.driver()` re-validates: the message names the driver and the operation, nothing was called; the way out is the `database` driver or `requireTransactionalWrites`, and the driver's own letter adds that entering through `manager.driver()` is not a way out — for the **tree** the way out that exists is `scopes.outbox`; **for facts and relations there is no outbox**, on purpose: an outbox of facts was measured as fail-open during its lag and discarded by the panel, the numbers are in the changelog). What you *can* do with `openfga` is order your writes by **direction**, so that whichever of the two fails, the failure lands on the closed side:

| Direction | With `openfga` | If your transaction rolls back |
|---|---|---|
| **Permissive** — `grant`, `relate`, `removeDeny` | write **after the commit** (`trx.after('commit', …)`, or after `db.transaction()` returns) | nothing was granted ⇒ **fail-closed** |
| **Restrictive** — `revoke`, `deny`, `unrelate` | write **before, or inside, in line** (no `{ transaction }`) | something was revoked that your SQL still grants ⇒ **fail-closed**, and repairable (grant again) |

**This is not "both or neither"**: it is a write *order* that makes the failure fall on the closed side, and its limits are measured against a real server:

- **Its limit: it does not compose.** A `grant` and a `revoke` of the *same* fact in the same transaction are applied in inverted order — the revoke in line, on a fact that does not exist yet (a safe no-op), the grant after the commit — and **end up granting**. If your unit of work both grants and revokes the same fact, the recipe is not for it.
- **The package does not automate it.** `grant` with `{ transaction }` on `openfga` is the 500 above: the driver does not hook `trx.after('commit')` to write later, does not write in line "pretending", and nothing lands when you commit (pinned: zero hooks registered on the transaction, zero client calls, `onWrite` empty). The order is yours to write.
- **Lucid swallows what an `after('commit')` handler throws** (`TransactionClient.commit()` runs the hooks and catches). A `grant` that fails there — 503, 422 — fails in silence: still fail-closed, but unreported. Await the write after `db.transaction()` returns, or catch inside the handler and report it yourself.
- **"Inside" needs a pool of at least 2 even with `openfga`.** The write goes to the store, but the freeze barrier before it is read through the engine's SQL connection: a `revoke` in line *inside* your open transaction on a pool of 1 is the 503 of the barrier at `freezeTimeoutMs`, not a revoke. On a pool of 1 the restrictive write goes **before** you open the transaction.

#### Third-party drivers, and what the suite can and cannot prove

"Both or neither" is **a guarantee of this package's `database` driver**, measured on its own schema on three engines. For a driver of yours declaring `transactionalWrites: true`, the runner requires the census (the `transactions` hook: how to open a transaction of *your* connection and how to count *your* rows) and judges rollback ⇒ zero, commit ⇒ applied, the uncommitted write invisible to the authority and three foreign transactions ⇒ 500 with zero statements — but it **cannot prove that a third-party driver's write really lives and dies with the transaction it is handed**: the census it counts is the one your hook reports, and a driver that opens its own transaction underneath passes the answer checks. Two more honest boundaries: the `true` face only runs where a second connection exists (`sqlite-file`, PostgreSQL, MySQL — the engine jobs of CI are not optional for this capability), so a driver judged only on `:memory:` never sees those cases; and the 409/503 classification of the table above is the `database` driver's — a third-party driver that returns the raw engine error is not caught by the suite. The same honesty for relations: the `listObjectsTruncation` pair of `runRelationsDriverContract` judges the **cap** only (`limits.listMaxResults`); **the runner does not judge the deadline** signal of a third-party `listObjects` (there is no way to observe it without sleeping), so a driver that does not implement it passes — the deadline cause is a property of this package's `openfga` driver, pinned by its own cases and by the surface guard. And the B3 case (a userset other than `group#member` as subject) observes your backend **through the port** — `listSubjects` and, under `enumerateRelations: true`, the whole partition — so a driver that stores the inert row and then throws the 422 goes red only through a port it declares: the minimal harness (`usersetSubjects: false`, `enumerateRelations: false`) has no port through which the runner can see that row, and such a driver passes (measured with that mutant on the double). **`denyPhase` (2.5.0-alpha.3) is judged by the driver
runner**: with `relationDenies: true`, `runRelationsDriverContract` asks your driver, built on the contract's deny config,
for the phase of each type (`document` 'write', `workspace` 'read', `note` none) and checks that it is the truth about
`deny()` ('write' ⇒ the deny lands and `check` is false; 'read' and none ⇒ 422 `E_AUTHZ_RELATION_NOT_DENYABLE`, nothing
written) plus F-05 (undeclared type, undeclared or missing relation ⇒ 422); with `relationDenies: false`, a `denyPhase` you
still expose must claim no phase (`null`). It is the gate `authz:relations:reconcile` uses before writing a deny into your
driver; what the runner cannot see is a driver whose `deny()` and `check` agree with each other and both ignore the opt-in.

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


One exception, on purpose: when a write **times out** (503 `E_AUTHZ_BACKEND_TIMEOUT`) the outcome is *unknown* — the request may still land on the backend after you received the error. Before propagating, the manager notifies the same event with **`indeterminate: true`**, so your audit records "may have happened" instead of nothing (*"una escritura que vence el deadline notifica onWrite con indeterminate: true ANTES de propagar el 503"*). A 503 that is not a timeout means the write did not happen and emits nothing — **with one family carved out on `openfga` (2.5.0-alpha.4, R3 closure)**: on a **write**, the server's own deadline (`deadline_exceeded`) and a **504** from a gateway or proxy in front of it are timeouts too (503 `E_AUTHZ_BACKEND_TIMEOUT`, `indeterminate: true`): the `Write` may have committed upstream after the response was cut. Every other 5xx on a write (500, 502, 503, 501) keeps "did not happen": the server answered that it failed. On a read, a 504 stays 503 `E_AUTHZ_BACKEND_UNAVAILABLE` (there is nothing to audit). On `openfga` a refused connection is not one of those since 2.5.0-alpha.4: the SDK hands it over as the same bare `FgaError` as a client timeout, without a code, and the package does not read messages — so it is classified as the conservative one, a timeout (`indeterminate: true`): "may have happened" said once too often, never once too few. The `openfga` driver also stops the SDK from retrying on its own (`retryParams.maxRetry: 0` by default): a background retry after your 503 is exactly the phantom write this is about; enabling retries is opting into it. If you retry a timed-out write yourself, remember it is idempotent.

**Inside your transaction (2.4.0-alpha.2, lot L-3) the event also carries `transactional: true`**, and a deadline that elapses there is *still* `indeterminate: true`. The `{trx}` panel's auditor objected that inside a transaction "the rollback determines it" — it does, but the rollback is *yours* and the package never sees it: when the 503 reaches you the statement may or may not have landed inside your transaction (SQLite cannot cancel; MySQL kills the statement and your transaction lives on; PostgreSQL leaves your transaction aborted), and whether you commit is yours. `transactional: true` is on **every** event of a write inscribed in your transaction (`granted`/`extended`/`revoked`/`denied`/`deny_removed`): at that instant the row exists only inside your transaction and is a fact if and only if you commit. A sink that wants the last word hooks `trx.after('commit', …)`. Enqueueing through `scopes.*` is not writing and does not carry it.

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

**`manager.driver()` is the documented way out of all of that.** It returns the active driver as-is: writes through it skip `actor`/`requireActor`, `within`/`requireWithin` **and `onWrite`**; reads skip the per-request memo. It exists for platform code (seeders, commands, writing at the root under `'non-root'`) and for tests — a tenant call-site should never call it, and a code review can grep for it. Nothing else is offered through it on purpose. **Grep for `relationsDriverFactory` and `relationsDriverKeys` too** (2.4.0-alpha.10): `manager.relationsDriverFactory(key)` returns the factory registered under `relations.drivers[key]` and `manager.relationsDriverKeys()` lists the keys — platform API next to `driver()`, used by `runRelationsReconcile` to resolve source and destination from the manager's own config. With the factory, any code holding the manager (a `forRequest()` view included) can build a relations driver that is **not** the active one and write to it with no `assertWrite`, no `requireActor`, no freeze and no `onRelationWrite`. It adds no real capability — `app.config` already hands out the factories — but it is one more thing to look for in a review. And `runRelationsReconcile(authorization, …)` takes the manager **structurally** (`Pick<AuthorizationManager, 'withFrozenWrites' | 'relationsDriverKey' | 'relationsDriverFactory'>`): an object that fakes `relationsDriverKey` or `relationsDriverFactory` decides which driver is active and which factories are compared, so pass it the service manager, never a hand-built or wrapped one.

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
  maxDepth: 22,           // optional (2.4.0-alpha.5): refuse attached/moved past this many parent hops from app — see Limits
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

### Per-resource enforcement: `resourceAccess` (2.4.0-alpha.1)

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
with their `expiresAt` and are counted in `skipped.expired`, never silently dropped. And a *live*
tuple whose object type or relation the **destination** does not declare is **not written** and is
counted in `skipped.undeclared` (L-0): with the destination config at hand the pass discards it
before the driver (so `--dry-run` and the real pass report the same numbers, and the type also shows
in `modelDrift`); without it, the destination driver's own F-05 422 funnels it and it is counted the
same. Unlike `expired`, that one is a live relation that did not arrive, so the command exits ≠ 0:
declare the type in the destination, republish its model, and run the pass again.

`group` is a **built-in** object type (the userset carrier: `group#member`, nesting allowed), so
teams work without declaring anything. Every operation takes a **`partition: ScopeRef`** — the
tenant — and it is **mandatory**: a relation in tenant A never resolves in tenant B (`APP_SCOPE` is
the mono-tenant value). The partition lives in the object id (`document:<partitionKey>|<uuid>`), not
in the model.

**Spelling is identity (2.5.0, D4).** Relations have no resolver chain to canonicalise against (roles do,
invariant 17), so the partition key is a string compared byte for byte — and until 2.5.0 the same tenant
uuid written **without dashes** (32 hex, what PostgreSQL's `uuid` type or a `*_ci` collation fold into the
dashed row elsewhere) was *another* partition that the canonical purge never saw. Since 2.5.0 **a partition
uuid that is 32 hex once the dashes are removed and is not exactly `8-4-4-4-12` is 422 `E_AUTHZ_INVALID_IDENTITY`
in every operation that takes a partition** — the manager, both drivers, the in-memory double,
`authz:relations:reconcile --partition-uuid` — with zero backend calls, the message naming the canonical form.
The rule is "every spelling an engine folds", not only "no dashes": PostgreSQL also reads `8-4-4-16`, four groups
of eight or the canonical form minus one dash as the same `uuid` (`'a0eebc99-9c0b4ef8-bb6d6bb9-bd380a11'::uuid`
is the canonical row), and each of those was a partition of its own that an offboarding by the canonical spelling
left alive (the lot A audit, A2; pinned by a truth table of forms and, on PostgreSQL, by measuring the cast). A
partition id that is *not* a uuid at all — 32 characters that are not all hex, 31 or 33 hex, `md5`-style ids with
an underscore — is a legal id and is untouched. Rows written with a non-canonical spelling before 2.5.0 are
**detected, listed and deleted** by [the upgrade recipe](#upgrading-to-250-non-canonical-partition-spellings)
(fail-closed by default; re-keying them is the explicit `--rekey` step). **Object and
subject ids are compared byte for byte; use one spelling.** They are *not* rejected: a 32-hex object id may
be a legitimate non-uuid id, so `{ type: 'document', id: '0192…aa' }` and `{ id: '0192…-…-aa' }` are two
documents in both directions (pinned by a case), exactly as a holder `uuid` is for roles.

**Deciding in bulk: `checkMany` (2.5.0).** `checkMany(subject, relation, objects, partition)` → `boolean[]`
by position, with the **same semantics as N `check`** (includes, usersets, strict expiry) for the ancestor
chain or the list you already hold: `database` answers in **one query** (one `now` for the whole batch),
`openfga` in **one `batchCheck`** (one `current_time` in every item, results aligned by `correlationId`,
never by position), and a driver that does not implement it is composed by the manager as N `check`s
(correct, N round trips, each with its own instant). Batches are **1..50** objects (`RELATIONS_CHECK_MANY_MAX`,
the server's `batchCheck` cap): 51 and `[]` are 422 `E_AUTHZ_CHECK_MANY_BATCH` with zero calls; duplicates
are allowed and answered by position (`[a, a, b]` ⇒ `[x, x, y]`); object types may be mixed as long as the
relation is declared for each (F-05 runs **per item**, so a `role_binding` in position 21 of 21 is 422 with
nothing asked); a per-item `error` inside a 200 `batchCheck` is a **503 for the whole batch**, never a
`false`. **`checkMany` returns one boolean per object: `false` does not distinguish "denied here" from
"nothing here", so it cannot implement deny-wins along a chain of objects that you walk yourself** — that is
`decideMany` (2.5.0, lot D). A third-party driver's answer is validated: anything but a `boolean[]` with one
position per object is 500 `E_AUTHZ_INTERNAL` naming the driver.

**Deny on relations (2.5.0).** A relation can be **denied** to a subject on an object: `deny(subject, relation,
object, partition)` writes the tuple `object#denied_<relation>@subject` (in `authz_relations` on `database`, in the store
on `openfga`) and **every read honours it** — `check`, `checkMany`, `decideMany`, `listObjects`. It is opt-in **per
type and in two phases** (`deny: 'read' | 'write'` on the object type in `defineRelationsConfig`; there is no `deny:
true` — that would be the single switch with no safe rollout order):

- `deny: 'read'` (phase 1): the published model declares `denied_<rel>` (`<rel> … but not denied_<rel>`) and all reads
  honour it; `deny()` on that type is still 422 `E_AUTHZ_RELATION_NOT_DENYABLE`.
- `deny: 'write'` (phase 2): writes are accepted too.

The rollout is two deployments: (1) the whole fleet on ≥ 2.5.0-alpha.3 with the type in `'read'`, the model
republished (`openfga:provision`) and **every pod pinned to the new `modelId`**; (2) verify; (3) a second deployment
moves the type to `'write'`. Both `openfga` drivers **require a pinned `modelId`, always** (2.5.0-alpha.4, with or
without deny: 500 `E_AUTHZ_CONFIG` at construction otherwise) and check, once per process, that the pinned model **is
the one your config generates** — [the model gate](#the-pinned-model-is-the-one-your-config-generates-250-alpha4) —:
in particular that it declares `denied_<rel>` for every relation of those types **and that `<rel>` subtracts it**
(`<rel> … but not denied_<rel>`, with the closure of the path cut); a pinned model without it is 500 `E_AUTHZ_CONFIG`
on first use, never a grant over a denied object. **`decideMany` on `openfga` requires a pinned `modelId` always**, like
every operation since 2.5.0-alpha.4, and asks the `denied_*` of exactly the types the gate saw in the deny form. A relation of a deniable type measures **at most 43 characters**
(`DENIABLE_RELATION_NAME_MAX`: `denied_<rel>` has to fit FGA's 50); a type without `deny` keeps the 50.

**The semantics is a path cut** (decision D5, the 64-state table T1 in the suite): a deny on `Y` cuts every grant of
`T` with `Y ∈ up*(T)` (everything that includes `T`), with all that derives from it. With `owner ⊆ editor ⊆ viewer`:

| allows | deny | `viewer` / `editor` / `owner` | case |
|---|---|---|---|
| owner | viewer | F / F / F | *"D-06 · un deny en viewer bloquea al owner"* |
| owner | editor | F / F / F | *"D-07 · un deny en editor anula el grant de owner ENTERO"* |
| owner + viewer | editor | T / F / F | *"D-08 · …salvo un viewer directo"* |
| viewer | editor | T / F / F | *"D-11 · un deny en una relación MÁS FUERTE no toca un grant más débil"* |

A deny reaches the subject **directly or through `group#member`** (nested groups too), and a group membership that
expires stops carrying it (a deny itself does not expire). Rules that go with it, each with its case: **no expiry**
(`expiresAt` on `deny`/`removeDeny` is 422 `E_AUTHZ_DENY_EXPIRY_UNSUPPORTED` — measured on OpenFGA 1.19: a live
deny's condition cannot be changed without a window in which it stops blocking); no `*` subject and no deny on
`group` (422 `E_AUTHZ_RELATION_NOT_DENYABLE`); a userset subject must be `group#member`; `deny`/`removeDeny` go
through the same gates as `relate` (`{ transaction }`, the freeze, F-05, `actor`, `assertWrite` with `operation:
'deny' | 'removeDeny'`, invariant 13) and notify `onRelationWrite`; `removeDeny` and `listDenies` accept **any declared
type** (retiring the opt-in must be reversible); `listSubjects` **does not** subtract (it lists facts) and
`listDenies(relation, object, partition)` lists the direct denies; `listObjects` **does** subtract (on `openfga` the
server does, so a page cut at the server's cap is a subset — never a denied object), and so does `membersOf` on
`database` (one `check` per candidate, only when the object has a deny row — at most `RELATIONS_MEMBERS_DENY_CHECK_MAX`
candidates, 1,000, past it 500 `E_AUTHZ_MEMBERS_DENY_LIMIT` and never a partial list, under one total deadline, 503);
the purges delete denies too. **On `openfga` a purge that fits in one `Write` is one `Write`**
(`RELATIONS_PURGE_WRITE_MAX`, 100 tuples — the server's `--max-tuples-per-write` default, measured: 101 is a 400 and
nothing applies), which FGA applies atomically; a larger one deletes the allows first, then **the subject's group
memberships in a `Write` of their own** (a membership carries denies too), then the denies — so **a purge cut halfway
grants nothing that neither the state before nor the state after granted**
(*"purgeSubject cortada, deny por grupo (holder)"*, *"purgeSubject cortada, deny anidado (userset g#member)"*, and the
symmetric row — the membership carries the allow, the deny is direct —
*"purgeSubject cortada, allow por grupo × deny DIRECTO (holder)"*; the same table runs without a server in the surface
guard, with the five order mutants in `npm run check:guard-mutants`).
**Declared row:** with more than 100 group memberships of the subject, a membership that carries a deny can fall in an earlier `Write` than one that carries an
allow, and a purge cut between the two grants until it is repeated (it stays marked `indeterminate: true`; the purge is
not refused before deleting — a purge does not wait) (*"FILA DECLARADA · purgeSubject con más de 100 membresías de grupo"*).
**The order of the purge is the same function as the reconcile's** (`relationTransitionOrder`,
`src/relations/tuple_order.ts`; closure 2 of D2): allows, then memberships (by the precedence graph), then denies; one
ordering point for every multi-request write or delete of relations.
**Renewing a membership that carries a deny is refused on `openfga`** (closure 2 of sublot D2, owner's decision): `relate`
on an EXISTING `group:*#member` tuple with another expiry is, on `openfga`, two `Write`s (delete, write: FGA does not
replace the same key in one `Write`), and between them the membership is not there — if that group, or a group that
contains it, is the subject of a live deny of the partition, the subject would be granted (for good, if the second
`Write` failed). So that renewal is **409 `E_AUTHZ_RENEWAL_UNSAFE` with zero writes** (always zero: closure 4) and an
honest recipe in the message (closure 5 of D2): on `openfga` **there is no window-free way** to change that expiry (see
*The limit* below); the recommended pattern is memberships WITHOUT expiry in groups that carry a deny, ended with
`unrelate`; if the expiry must change, `unrelate` + `relate` **accepting the window**, said as such. (Until closure 5 the
message also offered "retire the deny first, renew, write it again" as if it were the safe way out: it opens the same
window.) Cost: only on a membership renewal, one `Read` per deny type and one for the parents, per group up the nesting.
Every other renewal stays two `Write`s, and if the second fails the error is marked as a **partial write**
(`isPartialWrite`; `onRelationWrite` gets `indeterminate: true`) — until closure 2 it was a 503 that said nothing was
written while the tuple was gone. **Declared window** (closure 3 of D2): the carrier check reads, then the two `Write`s
follow; a `deny` on that group (or one containing it) written CONCURRENTLY, between the check and the delete, does not
reach the subject during the two `Write`s — and for good if the second one fails, because the membership is gone. The
driver re-checks after the two `Write`s (and after a failed second one) and the window stops being silent: if the renewal
went through, it throws **409 `E_AUTHZ_RENEWAL_RACED`** (`RenewalRacedError`; its own code since closure 4 of D2 —
until then it shared `E_AUTHZ_RENEWAL_UNSAFE`, and automating that code's recipe, `unrelate` + `relate`, here would
reopen the window with the deny already inside the group) marked partial with `renewalApplied: true` and `carriedDeny`
naming the deny (the final state is right: there is nothing to rewrite; review that subject's decisions in the window);
if the second `Write` failed, the 503
keeps its class and code, is marked partial and carries `carriedDeny` and the recipe (write the membership again: it is
gone, so `relate` is ONE `Write`). It does not close the window: FGA has no primitive to serialise a `deny` against a
renewal. A membership that is ALREADY EXPIRED carries nothing (it connects nothing), so rewriting it is not refused,
and neither is a membership whose only path to a deny is an expired nesting edge. `database` renews in one transaction
and does not refuse.
The same rule holds for the role facts' twin: `grant` with another expiry on `openfga` is `deleteTuples` +
`writeTuples`; if the second fails the `assignee` is already gone (fail-closed: the grant is lost), and since closure 3
of D2 the 503 is marked partial and `onWrite` gets `indeterminate: true` (until then: "not written", no event); so is
`purgeScope` of roles on `openfga` (several `Write`s: structure, facts, denies, batches of 100) cut after its first one
(closure 4 of D2; `indeterminate: true`, as its relations twin). The capability is
**`atomicRenewal`** (optional, normalised to `false`; `database` `true`, `openfga` `false`): a driver without it must
refuse that renewal the same way — the runner judges both faces — and `authz:relations:reconcile` does not ask it to renew
a carrying membership: the plan lists it as the destination residue `renewal-unsafe` (same numbers in `--dry-run` and the
real pass, a line starting with `sin renovar (renewal-unsafe) destino:` with the recipe, exit ≠ 0). **Not renewing is not
neutral over time**: the destination would keep the OLD expiry, and from it (an extension) the membership no longer
carries its deny, or until it (a shortening) it still grants what the source stopped granting. **So the PARTITION is
refused** (closure 5 of D2, owner's decision: option A): a partition with at least one `renewal-unsafe` or
`deny-conditional` (below) gets **zero writes and zero deletes** — with `--prune` too, expired leftovers included —, its
destination stays **exactly as it was**, with its previous drift in view, and **every other partition migrates**. The plan
decides it, so `--dry-run` and the real pass give the same numbers; `report.partitionsRefused` lists each one with its
causes, its recipe and what is pending (`write`/`update`/`delete`), its row in `report.partitions` has `status:
'refused'`, and the command prints one line starting with `partición NEGADA <partition>:` that names the partition and
the causes and says that its destination stays as it was (exit ≠ 0 while it exists). Refusing does not make the
destination more restrictive than the source: it leaves it as it was — what it already granted, it still grants, and
the line shows what is pending. **And "as it was" is not static** (closure 6 of D2): a refused partition IS "not
renewing", so the drift over time stays — from the old expiry of an extended carrying membership the destination no
longer carries its deny and **grants what that deny cuts** (if another path grants it) while the source still denies.
The line says when and what (`a partir de <date> el destino concederá a <subject> lo que cortan <denies>`; in the report,
`partitionsRefused[].evolves`). Ways out for a refused partition, none free: `unrelate` the membership in the SOURCE and
repeat; or `unrelate` + `relate` it in the DESTINATION with the source's expiry (or none), accepting the window; or wait
for the destination's old expiry — then the tuple is absent for the plan, the rewrite is a plain write and the partition
migrates on its own, with the interval above in between. Making the membership expiry-less in the SOURCE does NOT unlock
it (the destination's still expires: that is still an expiry change). (Closure 4 withheld, tuple by tuple, what the lost deny would let grant, with a
pass-wide refusal `carrier-conflict`; measured, that left grants the destination already gave in place without saying so,
and one tenant could block every other partition with `--prune`. Both are gone.)
**The limit: changing the expiry of a deny-carrying membership on `openfga`.** FGA cannot replace the same key in one
`Write` (no upsert: [openfga/openfga#2151](https://github.com/openfga/openfga/issues/2151)), so a renewal is two `Write`s,
and between them the subject does not get the group's deny. Therefore, on `openfga`: `relate` with another expiry on a
membership whose group (or a group containing it) carries a live deny is **409 `E_AUTHZ_RENEWAL_UNSAFE`, zero writes**;
the reconcile refuses that partition when its plan counts that deny (a deny EXPIRED at the pass's `now` carries nothing,
for the plan and for the driver alike — closure 6 of D2; until then the driver counted it and the real pass aborted with
a 409 the dry run had not announced). A deny the plan does NOT see can still reach the driver's 409 and abort the pass
instead (not measured; e.g. a leftover deny on a relation the destination no longer declares).
**There is no window-free way to do it.** The recommended pattern, for the future: memberships
**without expiry** in groups that carry a deny, ended with `unrelate`. If an expiry must change: `unrelate` + `relate`,
**accepting the window** — while it lasts the subject does not get the group's deny and is granted whatever another path
gives it and that deny cuts. **Declared window (TOCTOU of N1):** a NEW deny on a group written while ANOTHER membership of
that group is being renewed (its two `Write`s) does not reach that subject in between — the driver re-checks after the
renewal and says so (`E_AUTHZ_RENEWAL_RACED`), but it cannot close it. `database` renews in one transaction and has
none of this. **When OpenFGA offers an upsert, the renewal will be one `Write` and `atomicRenewal` will become `true`**
on `openfga`, without touching the model. **A destination tuple
that is expired at the pass's `now` is ABSENT for the plan** (closure 3 of D2): rewriting it is a plain write (never a
renewal, never `renewal-unsafe`), it is not part of the order's context (no carrier, no edge of the self-cut, no
"renewal" in phase 4), and with `--prune` the expired leftovers are deleted first and outside the order (they connect
nothing). Until closure 3 an expired carrying membership was taken as live: the pass refused to "renew" it while it
wrote the new allow, and the destination granted to a subject the source denied, pass after pass.
**`database` honours a `denied_*` row always**, also on a type without the opt-in (a deny row is a fact): retiring
`deny` from a type with live denies does not switch them off — remove them with `removeDeny`. Both drivers declare the
capability `relationDenies` (optional, normalised to `false`); a driver without it answers the four deny operations
with 500 `E_AUTHZ_UNSUPPORTED` and zero calls.

**`decideMany` is the chain primitive.** `decideMany(subject, relation, objects, partition)` →
`('allow' | 'deny' | 'none')[]` by position, with the same guarantees as `checkMany` (1..50 objects, `[]` and 51 are 422
`E_AUTHZ_CHECK_MANY_BATCH`, F-05 per item, one `now` per batch, a per-item error is a 503 for the whole batch — never
`none`). `allow` if `check` grants on that object; otherwise `deny` if the subject has a live deny (direct or through a
group) on any relation of `up*(down*(R))` on it; otherwise `none`. *`decideMany` is the chain primitive: walk from the
leaf up and stop at the first non-`none`. `deny` means "do not inherit past this object"; it is broader than `check` on
purpose (fail-closed). A deny given to `org#member` does not reach a guest who is not a member: to make a folder grant
only what it holds directly, break inheritance in your evaluator (`inherits = false`).* It answers **by the partition of
the object**: a guest holder with an allow in organisation A and a deny on the same object id in organisation B gets
`allow` in A and `deny` in B (and `check`/`checkMany` agree). Do not use `checkMany` for a chain: with the deny on the
middle object and the allow on its parent, `checkMany` says `[false, false, true]` and `decideMany` says `[none, deny,
allow]`.

**Writes that remove access can GIVE access back — declared rows, each with its case.** With a deny on `g#member`:
`unrelate(u, member, g)` gives `u` back the allow it holds directly (S8), `purgeObject(group:g)` does the same (S9), and
`purgeSubject(g#member)` deletes the group's denies (S10) (*"S8–S10 · FILAS DECLARADAS"*). A policy that treats "leave a
group" or "purge" as safe has to know it. And an `openfga` pod still pinned to a model **without** `denied_*` grants
over a denied object (S11, *"S11 · FILA DECLARADA"*): that is why the rollout above pins every pod before phase 2.

**A pure, stable key for a tuple (2.5.0).** `relationTupleKey({ partition, object, relation, subject, kind? })`
(root export) is deterministic and injective over exactly those five components — the expiry is not part of it
(renewing a share keeps its key, even though `database` rewrites the row with a new uuid) and neither is any
backend id. It is what `authz:relations:reconcile` matches source and destination with, and what you can index
your own metadata by, without the package storing it. `kind` is `'allow'` by default and travels in the key from
day one (`allow|unit|<uuid>|document:<id>#viewer@user:<uuid>`), so the key of an allow you already hold **does not
change** when denies (`kind: 'deny'`) arrive in 2.5.0.

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
that does not enforce it **does not pass**. **It lives in the manager AND in both drivers** (L-0,
2.4.0-alpha.2): `relate`/`unrelate` of `database` and `openfga` apply the very same function
(`assertRelationDeclared` — same class, same `code`, same message) **before touching the backend**
(zero `Write`, zero `INSERT`; the suite spies on the client and on the connection). Until L-0 the
port's docblock claimed the drivers re-validated and it was false in both: `manager.driver()` (the
platform escape hatch) and `authz:relations:reconcile` — which writes through the destination
*driver* — went straight past F-05, and in the shared store `driver.relate(evil, 'assignee',
{ type: 'role_binding', id: <roleUuid> }, S)` turned `roles.authorize(evil)` from `false` to `true`
(measured against a real server; the bridge spec keeps that case, and removing the driver guard puts
it back in red). `manager.driver()` still skips the manager's *other* barriers (`actor`,
`assertWrite`, `onRelationWrite`), as documented — F-05 is no longer one of them. **The userset subject is part of
that grammar (2.5.0 · B3)**: the only userset the fused model admits as a subject is `group#member`, so
`{ object: document, relation: viewer }` as subject is 422 `E_AUTHZ_RELATION_USERSET_UNSUPPORTED` on every operation
that takes a subject, through the same single function in the manager, both drivers and the published double — until
2.5.0 `database` stored that row inert and `openfga` surfaced the server's 400 as a 503.

**And since `2.4.0-alpha.3` F-05 covers **all thirteen operations of the port** — the eight of alpha.3 plus
`checkMany` (per item) since 2.5.0 and `deny`, `removeDeny`, `listDenies` and `decideMany` (per item) since
2.5.0-alpha.3 —, not only the two writes that compose a tuple.** The alpha.3 audit found the chokepoint one call-site short (pre-existing in alpha.2, in
code alpha.3 had just rewritten): `purgeObject`/`purgeSubject`/`check`/`listObjects`/`listSubjects`/`membersOf`
never called `assertRelationDeclared`, so in the shared store `purgeObject({ type: 'role_binding', id: R }, S)`
composed — byte for byte — the id of a real binding and **deleted the real binding** with proof of zero
(`authorize` went from `true` to `false`, zero tuples left, and a clean `purgeObject` audit event), and
`listSubjects('assignee', role_binding)` enumerated the holders assigned to a role in a scope through the
relations port, with no catalog, no `within`, no `requireActor` and no role visibility. Now the same
check runs first on the eight, in the manager **and** in both drivers (`manager.driver()` is not an
exit, same pattern as L-0 and L-5) — and it is **two functions, not an optional**: `assertRelationDeclared`
is **strict** (object type *and* relation, and the relation is mandatory) for `relate`/`unrelate`/`check`/
`listObjects`/`listSubjects`/`membersOf` and for the userset of any subject, while `assertObjectTypeDeclared`
(type only) serves `purgeObject`, which names no relation (`purgeSubject` validates the userset of its
subject). The first closing lot had made `relation` optional on one shared function, and the auditor's second
pass showed what that opened: `relate(u, undefined, doc, p)` — `request.input('relation')` missing — went past
F-05 (it wrote on the doubles, came back as a 503 from the OpenFGA server, and was saved only by the
`database` driver's own grammar), and `listSubjects(undefined, doc, p)` returned the **union** of every
relation's holders. So a missing `relation` (`undefined`) is 422 `E_AUTHZ_RELATION_UNKNOWN` on the six that
name one, on both drivers, with zero calls — 422 `E_AUTHZ_RELATION_TYPE_UNKNOWN` / `E_AUTHZ_RELATION_UNKNOWN`,
**zero client calls, zero events**, everywhere. The exploit is pinned against the shared store on the real
server (*"por el MANAGER: purgeObject(role_binding:R) ⇒ 422 … authorize(U, read, S) SIGUE true"*, *"por el
DRIVER en directo"*, *"cierre-2 · relate/unrelate/check/listSubjects/listObjects con relation: undefined"*),
and the published runner plants it on the six for any third-party driver (*"F-05 ·
purgeObject/purgeSubject(userset)/check/listObjects/listSubjects/membersOf"*). `membersOf` runs F-05 **before**
its capability check, so a `role_binding` there is 422 even where `membersOf` itself would be 500.

**`membersOf` is `database`-only.** `membersOf(group, 'member', partition)` returns the **transitive**
membership (through nested groups). Only the `database` driver has it (a recursive CTE); in `openfga`
it is 500 `E_AUTHZ_UNSUPPORTED` naming it — the transitive form is `ListUsers`, which truncates
without a reliable signal, and we never return a silent partial. `listSubjects` (direct facts,
invariant 7) works in both. `listObjects` in `openfga` signals `truncated: true` when the server's
`ListObjects` cap cuts the page **and** when the call took **90 % or more of the server's `ListObjects`
deadline** (`listObjectsDeadlineMs`, default 3,000 ms, OpenFGA's default `--listObjects-deadline`; set it to
your server's **effective** cut, below) — past its deadline the server answers 200 with whatever it had resolved and **no signal**
(measured, 2.5.0 · B4; until then the README promised no mute partial list at all, and that was only true of the
cap). Both causes are one signal, through one envelope (`#listObjectsPage`, measured with a monotonic clock);
the signal is conservative on purpose: a slow-but-complete call may be flagged, a cut one never passes as
complete — the price is in [Limits](#limits). `listObjectsDeadlineMs` is the server's **effective** cut, whichever is
lower of the three — `--listObjects-deadline` (when it is not 0), `--request-timeout` (3 s by default) and, over HTTP,
the gateway's `--http-upstream-timeout` (5 s by default) — declare that lowest one: a server running with
`--listObjects-deadline=0` has **no** "no deadline" — its `--request-timeout` still cuts `ListObjects` with a mute 200
(measured on OpenFGA v1.19.0 by the audit of 2.5.0-alpha.2: `--request-timeout=30ms` answered `200` with 0 of 40,000
objects; `list_objects.go` only sets its own timeout when the deadline is not 0 and inherits the request-timeout
context otherwise) — so declare that value instead. `Infinity` is refused (500 `E_AUTHZ_CONFIG`): it would make the
driver pass that mute list as complete. Both at 0 is not supported (what the HTTP gateway's `--http-upstream-timeout`
does then is not measured for `ListObjects`; the package promises no "no deadline" it has not measured). And the
driver's own `timeoutMs` (5 s by default) cannot be lower than `listObjectsDeadlineMs`: the signal has to be able to
fire before the client cuts, so a deadline above the client timeout is 500 `E_AUTHZ_CONFIG` at construction
(`Number.MAX_SAFE_INTEGER` was "no deadline" under another name, 2.5.0-alpha.2 · closure 3). A 200 **without
`objects`** is 503, not an empty list. The `Read`-based enumerations — `listSubjects`, `enumerateRelations(Many)`,
the purges — are **exhaustive or 503**: they page until the continuation token is empty and throw on a response
without `tuples`, a repeating token or more than 10,000 pages (`E_AUTHZ_BACKEND_UNAVAILABLE`), never a short page.
The roles driver's `Read`s (`readAllTuples`, the reconcile dump, `enumerateFacts`) hold the same rule since
`2.5.0-alpha.2`.

**The config can be persisted, and nothing republishes the model behind your back.** `saveRelationsConfig(spec)`
stores the relations config in `authz_relations_config` under the shared version gate (invariant 14), so a
process without `defineRelationsConfig` in memory can read the declared types (`readRelationsConfig()`,
`null` when nothing was ever saved). **The fused model is published by one thing only: `node ace
openfga:provision`**, from the *static* config (`relations.config` and the `catalogs`) — the command boots
without a database and cannot read the table —, and re-publishing it is a manual operator step (single writer:
the `modelId` goes to every pod by hand, see [the cutover window](#the-cutover-window)). Neither
`syncAuthzCatalog` nor a config save republishes anything. The persisted copy has one reader today:
`authz:relations:reconcile`, which uses it as the **destination's** config to flag model drift — and since
2.5.0 a *failed* read of that table stops the command before any write (an unreadable config is not "no
config"; `null` is).

**Migrating tuples between drivers** is `node ace authz:relations:reconcile --to=<key>` — the relations
analog of `authz:reconcile`, idempotent, bidirectional and never silent (it reports written / deleted
/ unchanged / extra). `--to`/`--from` are keys of `relations.drivers` in `config/authorization.ts`;
`--dry-run` is the read-only verifier and also flags **model drift** (an object type in the source the
destination does not declare); `--prune` deletes what the source no longer backs — except a destination row the API
does not admit (`details`: `invalid-identity`, `userset-unsupported`, `undeclared` — a relation or type the
destination no longer declares —, `invalid-condition` — a tuple whose condition the package does not write or cannot
read, 2.5.0-alpha.4: present and untouchable in the destination, never rewritten from the source, and never migrated
from the source as "permanent"), which no flag touches: listed, exit ≠ 0 in every mode, deleted by hand or, for
`undeclared`, declared again ([Upgrading, 6](#upgrading-to-250)); a 422 of the relations family from the destination's
`unrelate` is classified the same way and never aborts the pass. **Denies migrate as denies (2.5.0-alpha.3):**
`enumerateRelations` marks every tuple with `kind` (`denied_viewer` is enumerated as `viewer` + `kind: 'deny'`), the key
carries it, and the pass applies the WHOLE transition of each partition —writes, renewals and, with `--prune`, deletes—
as **one sequence**, in the order of ONE function shared with the `openfga` purges (`relationTransitionOrder`,
`src/relations/tuple_order.ts`), in five phases: (1) new denies (`deny`); (2) with `--prune`, leftover allows on
non-`group` objects; (3) the group memberships (`group:*#member`) that come in and go out, in the order of a
**precedence graph** (computed in the union of both states: between two memberships of a common subject, one that brings
a deny on X goes before one that brings an allow on X; one that leaves carrying an allow on X before one that leaves
carrying a deny on X; one that leaves before one that comes in on the same nested path when the composed path would
carry an allow; one that comes in carrying a deny before one that leaves carrying a deny that protects an allow of the
subject; since closure 4 of D2 a membership RENEWAL is in that graph too, as the entry —or, if it shortens, the exit— it
becomes at the shorter of its two expiries); (4) new allows and the renewals of allows that extend (one that shortens
goes with the deletes of phase 2); (5) with `--prune`, the leftover denies **last** (`removeDeny`, never
`unrelate`). Never the source's enumeration order (`database` enumerates by creation: a document shared on Monday, its
user put in a denied group on Tuesday). Until closure 2 of sublot D2 every write went before every delete, and a former
member composed with a new allow (U ∈ g leaves, `g#member viewer X` arrives: cut after the first write, U was granted X).
**What that guarantees, exactly — demonstrated by brute force, not by hand-made tables**: **if the precedence graph has
no cycle, no state of a pass cut after any write grants something neither the initial nor the final state granted, and
no subject denied in both is granted in any.** The **residue is the cycle** — two memberships changed in the same pass
whose order constraints contradict each other; the typical shape: the same subject joins (or leaves) two groups at once,
and each brings a deny that cuts an allow the other brings — and there, in general, **no order of the diff is safe**;
the pass applies them in a fixed order and reports them (`report.orderResidue`, a warning line starting with
`orden SIN garantía`: the final state is right, so it is not drift; if the window matters, apply them in two passes). The
demonstration (`tests/relations_order_exhaustive.spec.ts`, oracle = the package's own path cut, both with `--prune` and
without): **exhaustive** over 1 user, 2 groups with one nesting level, 2 objects and one relation with deny (10 possible
tuples, every (initial, final) pair: 2,097,152 pairs, ~23 s) — 0 pairs grant without a declared residue; 4,176 pairs have
a cycle, 816 of them grant in some prefix and 352 of those admit no safe order of the diff at all — plus a seeded sample
of 30,000 pairs per mode of the universe with 2 users and direct/group allows and denies (21 tuples) and of one with three
groups and two nesting levels (20 tuples): 0 without residue. **Group membership counts as a grant** (closure 5 of D2):
the oracle also judges `(user, group:G)` — being a member is itself a grant (`check(member)`, `membersOf`) —, so a pass
cut between `+U ∈ h` and `−h ⊂ g` must not make U a member of g, which neither state did; the order gives that pair a
precedence (the price, declared: more pairs with a cycle in the two-level universe, 4,188 of 60,000 sampled, all of them
reported as order residue). **Validity and the time HORIZON are part of the universe**
(closures 3 and 4 of D2): every destination tuple is live (expiring at `now + 1 h`), expired or absent, and the source
has it absent or live with the same, a LATER or an EARLIER expiry (8 states per tuple); the plan is derived by the same
rules as the pass (`liveInDestination`: expired = absent; `deny-conditional` in the plan; a partition with a
`renewal-unsafe` or a `deny-conditional` is refused — zero writes, so its state is the initial one at every instant: the
ONLY exclusion), renewals are steps (one write on an `atomicRenewal` destination; two `Write`s with the gap checked as a
prefix on `openfga`), and **every prefix and the final state are judged at
`now` and at every later expiry** (`+30 min`, `+1 h`), each tuple with ITS expiry (the destination's if the pass did not
touch it, the source's if it wrote or renewed it, none for a deny it wrote). Property: at no instant of the horizon does a
prefix grant outside initial ∪ source, or to a subject denied in both, without a declared order residue; and the final
state never grants what the source denies at that instant — no exception (closure 4 counted a `preexisting` grant as
declared; it is gone with the withholding). **Exhaustive** over the reduced
universe (8 tuples: 33,554,432 combinations per destination kind, `AUTHZ_ORDER_VIGENCIA_EXHAUSTIVE=1`) and seeded
samples of the four universes in the default suite — 0 grant without a declared residue. Without the destination's config (`toConfig`) the order does
not assume any allow is cut by a deny (more precedences, more residue, never less guarantee). Surface-guard properties
`relations.order.exhaustive` (the brute force over a reduced universe, 131,072 pairs, plus a declared sample of 50,000
combinations per mode with validity and horizon, on every mutant of the order),
`relations.reconcile.order` and `openfga.purge.order`, the last two judged with the source enumerated in both orders. **The destination driver decides, before the first write, whether it can take each deny**
(`capabilities.relationDenies` and its own `denyPhase(type, relation)`: the opt-in of ITS config, and on `openfga` its
pinned model, D-31 — never the persisted spec): a source deny that the destination cannot write (`no-capability`,
`no-deny-phase`, `phase` — the type is not in `deny: 'write'` there —, `undeclared`, `model`, `unmarked` — a source driver
that does not mark `kind`, on either side —, `invalid`) makes the pass refuse with 500 `E_AUTHZ_DENY_MIGRATION_REFUSED` and **zero
writes** in every partition — never `skipped`: writing the allows without the deny would grant what the source denies.
`--dry-run` does not throw: one line per refusal starting with `deny NO migrable`, and exit ≠ 0. **Each refusal carries
the recipe of ITS reason** (`DenyRefusal.recipe`): `phase` — the type in `deny: 'write'` in the destination's config
(provision → pin → deploy); `undeclared` — a relation RETIRED with live denies: re-declare the relation temporarily in the
config of the process that writes the source (the relation is enough; `removeDeny` needs no opt-in), `removeDeny` those
denies, retire it again and repeat (`removeDeny` on an undeclared pair is 422, F-05; executed in the suite); `model` —
publish and pin the destination's model; `unmarked` — update the driver that does not mark `kind`; `invalid` — delete
the row by hand (the API would reject `removeDeny` too); `no-capability`/`no-deny-phase` — a destination that can write
denies. (A partition refused by the plan, above, writes nothing, so its denies do not ask for a phase.) A deny already present in a destination WITHOUT the opt-in is refused too (`phase`) although `database` would
honour the row (D8): `denyPhase = null` means «no opt-in» and the pass does not certify what the destination does not
declare. **A destination deny with an expiry** (only writable from outside the package, D3) —live with another expiry, or
ALREADY EXPIRED— that the source has is rewritten permanent on `database`; on a destination without `atomicRenewal`
(`openfga`: it cannot replace the same key in a `Write`, M5, and its `deny` there is 500 `E_AUTHZ_CONFIG` with the recipe
`removeDeny` + `deny`, a declared window between the two) **the plan decides it** (closure 4 of D2; same numbers in
`--dry-run` and the real pass): the destination residue `deny-conditional` (exit ≠ 0), not rewritten, and **its partition
is refused** (closure 5, above) — an expired one denies nothing, and until closure 4 the pass still wrote the allow it cut
(the destination granted, and `--dry-run` reported a different count). A driver that declares
`atomicRenewal` and still answers that 500 contradicts its capability: the error propagates. The report carries
`denies: { written, updated, deleted, unchanged, extra }` (a subset of the totals, printed as its own `denies:` line),
`denyRefused` (dry-run) and `partitions` (one row per partition with its status); a pass that blows up halfway throws
with `error.report` (`partial: true`: the partitions `done`, the one that `failed` with what it wrote, the `pending`
ones) and the command prints it, one `pasada PARCIAL:` line per partition; one that fails before writing anything has
`partial: false` and prints `pasada FALLIDA sin escribir nada:`. **The totals `written`/`unchanged`/`extra` include the
denies** (2.5.0-alpha.3, a change of meaning): subtract `denies` to count allows only. **Never towards the
ACTIVE relations driver** (2.4.0-alpha.10): once `relations.default ?? config.default` is `--to`, any
other source — with `--from` or picked by elimination — is 500 `E_AUTHZ_STALE_SOURCE_REFUSED` (it
would resurrect shares revoked since the cutover and, with `--prune`, delete the new ones); `--dry-run`
flags it, and `--allow-stale-source` is the human decision. It migrates **facts
only** — there is no tree or catalog in `relations/` — and works **per partition** (`--partition-type`
/`--partition-uuid`; default `app`). **From code, the one public way is `runRelationsReconcile`** —
`import { runRelationsReconcile } from '@jantstack/adonis-authz/relations/reconcile'` (its own subpath since 2.5.0; until
`2.5.0-alpha.1` it was `…/commands/authz_relations_reconcile`, which no longer exports it) and
`runRelationsReconcile(authorization, { toKey, fromKey, partitions: [...] })` migrates several partitions in one
pass (see the sweep below), with the same guard and the same durable window as the command. Source and
destination are **keys of `relations.drivers`, resolved from the manager's own config**, and the guard compares
the *resolved* driver, not the label: two keys that point at the same factory are the same driver (an alias of the
active one is refused too; source = destination is 500 `E_AUTHZ_CONFIG`), and the active driver is always the
manager's — there is no `activeKey` to contradict it. **Declared limit: identity is the factory reference, not the
backend.** Two *different* factories that build the same store — `openfga: () => new OpenFgaRelationsDriver(…)` and an
alias `fga: () => new OpenFgaRelationsDriver(…)` with the same `OPENFGA_STORE_ID`, which is how an alias is naturally
written in a config — are **not** detected: `--to=fga --from=database` passes the guard and resurrects what was revoked.
Nothing is built before the guard, so there is no backend to compare. Register an alias with the *same* reference
(`const fga = () => …` and `{ openfga: fga, alias: fga }`) or do not register it; a backend identity declared by the
driver is on the 2.5 list. Until the closing lot of 2.4.0-alpha.10 the primitive
`reconcileRelations` was exported from the package root and this paragraph recommended it for K partitions: it
never saw the active driver nor took the window, so a loop written after the cutover resurrected revoked shares
with the fleet still writing. It is no longer public. **The guard reads the config of the process that runs it**:
`relations.default ?? config.default` *there* — a job or pod started with another environment (say, without
`AUTHZ_DRIVER`) believes another driver is active and the guard is off. Run it with the fleet's config; a durable
seal of the active driver is on the 2.5 list. **The pass that writes runs under the durable freeze** (2.4.0-alpha.2,
lot L-1), exactly like `authz:reconcile`: every write of the package — roles *and* relations — answers a
retryable 503 `E_AUTHZ_FROZEN` fleet-wide while it runs; a live **operator** window (`authz:freeze`) is its
own context (it runs inside, does not renew or lift it); a live freeze of another pass is 423; and the
report carries `frozen: { durable, lapsed, leaseMs, fence }` — **`lapsed: true` means the lease was lost
mid-pass and the pass is not certified** (exit ≠ 0). `--dry-run` does not freeze: the verifier is
read-only and is meant for a cron.

#### The source sweep, measured

In `openfga`, `enumerateRelations(partition)` — the *source* of the migration — is a `Read({})` of the
**whole store**, paginated by 100 (the server's cap) and filtered in memory by the whole partition key.
There is no cheaper `Read`: by type without `user` is a 400, and by **prefix** of the object id
(`document:unit|<uuid>|`) answers **200 with zero tuples** — silently, which in the source of a migration
means "this partition is empty" and in a purge "proved zero" without deleting anything. Never optimise it
that way; the suite spies the filter of every `read` and it is always `{}`. What *is* cheaper is doing the
sweep **once for K partitions**: `enumerateRelationsMany(partitions)` (optional port method, implemented by
`openfga`; `RelationsManager` exposes it and falls back to K calls for a driver without it) and
`runRelationsReconcile(authorization, { toKey, fromKey, partitions })`, which enumerates source and destination once, decides the K diffs
first (the mass-delete guard R-17 is evaluated for every partition **before** writing anything) and then
applies them; the report is the sum. Same output per partition, byte for byte, as K separate calls; `app`
does not pull `appliance|…`, `org|U` does not pull `organization|U`, and each spelling of a uuid is its own
partition. Measured against OpenFGA 1.19.0 (2.4.0-alpha.6):

| Store | Partitions asked | `enumerateRelations` × K (before) | `enumerateRelationsMany` (after) |
|---|---|---|---|
| 5,000 tuples (3 × 1,000 + 2,000 foreign) | 3 | 150 `Read`, 502–558 ms | **50 `Read`, 170–209 ms** |
| 15,000 tuples (panel measurement) | 3 | 453 `Read`, ≈ 1.4 s | **151 `Read`, ≈ 0.46 s** |
| 15,000 tuples | 50 | ≈ 23 s | ≈ 0.5 s (extrapolated from the same sweep) |

The cost is O(tuples in the store) **per sweep**, whatever the size of the partitions asked, and the sweep is
exhaustive or loud: a page with zero tuples *and* a continuation token is not the end; a token that
repeats, more than 10,000 pages, or a response without `tuples` is 503 `E_AUTHZ_BACKEND_UNAVAILABLE`,
never a shorter enumeration. Run it from a job or a cron, **never from a tenant request**.

**Writing relations inside your transaction (2.4.0-alpha.2, lot L-4).** `relate`/`unrelate`/`purgeObject`/
`purgeSubject` with **`{ transaction: trx }`** on the `database` relations driver write the tuple **inside
your open Lucid transaction** of the driver's connection — the same rule, the same guard, the same pool ≥ 2
requirement, the same census in the published suite and the same per-engine behaviour as facts, all in one
place: [Writing inside your transaction](#writing-inside-your-transaction-240-alpha2). What is specific to
tuples is there too: with a transaction present `relate` no longer opens its own, so the partition trigger
fires inside yours; renewing an expiry rolls back to the previous one; two crossed writes deadlock into a
409. A pool-of-1 deployment declares `new DatabaseRelationsDriver(config, { transactionalWrites: false })`;
on `openfga` it is the 500 and [the recipe by direction](#openfga-the-recipe-by-direction). **And the unique
index guards holder tuples too (lot L-4b).** Until L-4b `subject_relation` was `NULL` for a holder and every engine treats two
`NULL`s as distinct in a unique index, so `authz_rel_tuple_uq` only guarded **userset** tuples: two concurrent
`relate`s of the *same holder tuple* in two open transactions both went in and committed **two identical
rows** (no over-grant, but `listSubjects`/`enumerateRelations` listed the subject twice and the reconcile
census counted it twice). Since L-4b the column is **`NOT NULL DEFAULT ''`** (`''` = holder; the only option
with parity on the three engines — MySQL has no partial index, `NULLS NOT DISTINCT` is PostgreSQL 15+) and the
driver writes `''`, so the same holder tuple in two transactions ends in **exactly one row**: the loser gets
the same **409 `E_AUTHZ_WRITE_CONFLICT`** as a userset (PostgreSQL/MySQL) or `SQLITE_BUSY` (SQLite file), pinned
on the three engines, with the mutant (column back to nullable ⇒ two rows) red. An installation that migrated
before L-4b runs [the recipe](#upgrading-from-240-alpha2-before-l-4b-authz_relationssubject_relation): the
driver tolerates old `NULL` rows on read meanwhile.

### The relation write event (2.4.0-alpha.3)

`onRelationWrite` gives **the same guarantees as `onWrite`** — every one of them was missing or half-true on the relations port until `2.4.0-alpha.3`, and COGNITIV found the first two in real consumption. The event (`RelationWriteEvent`) mirrors the shape of `AuthzWriteEvent`: one type, optional fields, no discriminated union.

| `operation` | What the event carries | What it does not |
|---|---|---|
| `relate` | `subject`, `relation`, `object`, `partition`, `expiresAt` if you passed it, `actor` if you passed it | — |
| `unrelate` | `subject`, `relation`, `object`, `partition`, `actor` | — |
| `purgeObject` | `object`, `partition`, `actor` | no `subject`, no `relation` |
| `purgeSubject` | `subject`, `partition`, `actor` | no `object`, no `relation` |
| `deny` (2.5.0) | `subject`, `relation` (the public name, never `denied_<rel>`), `object`, `partition`, `actor` | no `expiresAt` (a deny does not expire) |
| `removeDeny` (2.5.0) | `subject`, `relation`, `object`, `partition`, `actor` | no `expiresAt` |

**`operation` widened in 2.5.0 with `deny` and `removeDeny`** — on the event and on the `RelationRef` that `assertWrite`
receives. TypeScript does not warn about a widened union inside an `if`/`else`: **a handler that treats everything that is
not `unrelate` as an addition grants too much** (it would index a deny as a share). Switch on the operation.

A purge notifies **one event per call** — even when the driver sweeps both spellings of the partition uuid underneath, and even when it deletes many tuples — and it **does not count**: the port returns `void` (a count would break the port for third-party drivers, and inside `{ transaction }` it would be a number your rollback contradicts). If you need the "how many", call `enumerateRelations` (or `listSubjects`) before purging — inside your transaction, through your transaction. And a purge that deletes nothing notifies all the same: the auditable fact is *someone asked to delete the keys of X*, whether or not there were any. `scopes.detached` on the roles port emits one `scope_purged` per spelling because there the **manager** canonicalises; the relations manager does not, so the divergence is on purpose and pinned (*"E6 · UN evento por llamada aunque el driver barra DOS ortografías"*). A purge does not go through `assertWrite` — `RelationRef.operation` is `'relate' | 'unrelate' | 'deny' | 'removeDeny'` (the four writes on ONE tuple), the published type of the R-13 hook — and that is pinned too (*"E9 · negativo declarado"*). But F-05 runs first on the purges too (2.4.0-alpha.3, closing the audit's critical finding): `purgeObject` validates the object type and `purgeSubject` the userset of its subject **before** the actor, the scope and the driver, so a purge of a `role_binding` is 422 with zero driver calls and zero events — see [F-05 on the seven operations](#relations-rebac-24) above. `purgeSubject` also validates its subject like `relate` does (a malformed holder or `{}` is 422 `E_AUTHZ_INVALID_IDENTITY` and never reaches the event).

**The four guarantees, on the four writes** (`relate`, `unrelate`, `purgeObject`, `purgeSubject`):

- **`transactional: true`** when the write went through your `{ transaction }` (lot L-4): at that instant the tuple exists only inside your transaction and is a fact if and only if you commit — the package never sees that; a sink that wants the last word hangs itself on `trx.after('commit')`, and the suite runs exactly that recipe: rollback ⇒ the deferred sink holds zero firm records and the census holds zero tuples, commit ⇒ one and one (*"B2 · rollback ⇒ ni tupla NI evento contabilizado como definitivo"*, *"E4 · purgeObject/purgeSubject dentro de una trx"*). Absent — not `false` — without a transaction, and `{ transaction: undefined }`/`null` count as none. The published runner judges it as the other face of the `transactionalWrites` capability: with `true`, the eight events of the four writes inside a transaction carry it; with `false`, a refused write emits nothing.
- **`indeterminate: true`** — invariant 13, now on this port too: a relation write that elapses its deadline notifies `onRelationWrite` with `indeterminate: true` before propagating the 503 `E_AUTHZ_BACKEND_TIMEOUT`, with the rest of the event intact (*"C1 · relate/unrelate que vencen el deadline notifican indeterminate: true"*, *"E5 · purgeObject/purgeSubject que vencen el deadline"*). Both drivers have a deadline to elapse: `database` through `guardSql` (`timeoutMs`), `openfga` through the SDK's `baseOptions.timeout` with `retryParams.maxRetry: 0` — measured against a socket that accepts and never answers, without a server (*"C4 · openfga (relations) contra un servidor MUDO"*). Inside your transaction the event carries `indeterminate: true` *and* `transactional: true` (PostgreSQL leaves your transaction aborted, MySQL kills the statement and leaves it alive, SQLite cannot elapse a deadline: `SQLITE_BUSY` is a 503 that is not a timeout and emits nothing — *"C3 · deadline vencido DENTRO de la trx externa"*); on `openfga` the event never carries `transactional` (gate 1 makes `{ transaction }` impossible there). A 422 (F-05, R-16, a bad `expiresAt`), an `assertWrite` that throws and the freeze emit **nothing** and call nothing: that write did not happen (*"C2"*). A 503 that is not a timeout emits nothing **when it arrives before the first statement or `Write`** — and that is the only case on `relate`/`unrelate` (one statement, one `Write`); on `database` a purge is one `DELETE`, so it holds there too; on `openfga` only when nothing had been deleted yet, because a purge on `openfga` is **not one request**: it is one `Read` + `deleteTuples` + `Read` (the proof of zero) per spelling of the partition uuid and, for `purgeSubject`, per declared type. When such a purge fails **after** it has already deleted part of its tuples — a connection error, or the 500 `E_AUTHZ_PURGE_INCOMPLETE` of the proof of zero — the driver marks the error (`markPartialWrite`, exported from the package: a property, the class and the `code` are unchanged) and the manager notifies `indeterminate: true` as well, before propagating, exactly like a deadline: *may have happened* is the honest word there (*"purgeObject: la demostración de cero falla tras el deleteTuples ⇒ … indeterminate: true"*, and its control: a failure on the first `Read` emits nothing). A third-party driver whose purge is multi-request has the same duty.
- **A hook that throws — sync or async — is logged and swallowed**: the write is already applied when the hook runs, so propagating would report a failure for an operation that did happen and invite a retry of something done. Until alpha.3 the hook was called with neither `await` nor `try/catch`: a failing audit sink turned an applied `relate` into an error for the caller, and an `async` hook that rejected vanished as an unhandled rejection. Now the returned promise is awaited, the failure is logged naming the operation (`logger.error`, or `console.error` outside an app), and the caller gets its result (*"D1 · un onRelationWrite SÍNCRONO que lanza no propaga"*, *"D2 · un onRelationWrite ASYNC que rechaza tampoco propaga"*). The flip side of that guarantee: the sink is **awaited**, so it is on the critical path of the write — its latency is the write's latency — and, with `{ transaction }`, inside your transaction: a sink that never resolves keeps it open (and, since `{ transaction }` requires a pool ≥ 2, a few of those exhaust the engine's connections and the freeze barrier starts answering 503 to everybody). There is no deadline on the hook, on purpose — parity with `hooks.onWrite`, and a deadline would be a design decision of its own — so defer anything slow to `trx.after('commit')` or to a queue, and never do I/O without a timeout in there.
- **`actor` is validated like any identity, then required**: a malformed `actor` is 422 `E_AUTHZ_INVALID_IDENTITY` before the driver, on the four writes, and never travels to the event (until alpha.3 only its *presence* was checked, so `{ uuid: 'A#B' }` poisoned the trail and `actor: {}` satisfied `requireActor`); `requireActor: true` + `actor: {}` is the identity 422, not "actor required" (*"D4"*). **Breaking**: `requireActor` now reaches `purgeObject`/`purgeSubject` — a mass deletion of keys is the write that most needs an actor — so a deployment with `requireActor: true` that purged without one gets 422 `E_AUTHZ_ACTOR_REQUIRED` (*"E3"*); the purges take `RelationPurgeOptions` (`transaction` + `actor`).

**`assertWrite`.** `assertWrite` is **synchronous, pure and has no `actor`** on purpose (R-13): it receives the full tuple reference (`subject`, `relation`, `object`, `partition`, `operation`, `expiresAt`) and throws to refuse; it runs after F-05 and before the driver, so a refusal is zero driver calls and zero events. Because a function returning `Promise<void>` is assignable to `void`, `assertWrite: async (ref) => { throw … }` compiles — and until alpha.3 the promise was discarded and the write went in: a policy gate that refused nothing, in silence. Since alpha.3 **returning a promise is 500 `E_AUTHZ_CONFIG`** before touching the driver — the message names `assertWrite`, "synchronous", and the recipe — whether the promise would have rejected or resolved (*"D3 · un assertWrite ASYNC no es un assertWrite"*). And more generally `assertWrite` **does not return verdicts**: it throws or it does not. `assertWrite: (ref) => allowed.has(ref.object.type)` compiles under `--strict` just the same, and until the alpha.3 closing lot returning `false` did not refuse anything — the write went in — so now returning **any value at all** — `false`, `true`, a thenable *function*, `null`, an object — is 500 `E_AUTHZ_CONFIG` before the driver, with zero calls and zero events (*"assertWrite que DEVUELVE algo (false, true, thenable-función, null) es 500"*). The policy that needs the actor, your database or an `await` belongs in your service, before calling `relate`/`unrelate`.

**Wiring.** The three live in `relations` of `defineConfig` — `relations.assertWrite`, `relations.onRelationWrite`, `relations.requireActor` — and not in `hooks`: one home for the port, no precedence rule (the published stub declares them there, and a case compiles it). Until alpha.3 the provider passed neither hook to the service manager (`authz.relations`), so through the service there was no policy gate and no audit trail at all; `requireActor` *was* wired (inherited from the root). `relations.requireActor` overrides the root per port, `relations.requireActor ?? requireActor`, exactly like `relations.requireTransactionalWrites`: unset inherits, `true` requires it here even if the root does not, `false` waives it here even if the root requires it (*"A3 · relations.requireActor anula el raíz por PUERTO, en los tres sentidos"*). Read the third direction as what it is: `relations.requireActor: false` under a root `requireActor: true` **overrides the root for relations, silently** — `warnOnOptInSecurity` does not cover it — so a template that carries the key waives the actor on the four relation writes without a warning; write it only on purpose. `manager.driver()` still skips all three, as documented above.

**Still not in 2.4.** `includes` with `from` (cross-object inheritance like `viewer from parent`),
which would add a TTU between object types and force re-measuring depth. Relation expiry (R-15)
**landed in 2.4.0-alpha.2** (see above); an installation that migrated 2.4.0-alpha.1 adds the column with
the recipe in [Upgrading](#upgrading-from-240-alpha1-authz_relationsexpires_at). `{ transaction }` on
`relate`/`unrelate`/`purge*` **landed with lot L-4** (above); on `openfga` it is the honest 500 and
[the recipe by direction](#openfga-the-recipe-by-direction).

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
| `E_AUTHZ_ACTOR_REQUIRED` | 422 | `requireActor: true` and a write without `actor` (2.1); on the relations port (`relations.requireActor ?? requireActor`) the four writes, `purgeObject`/`purgeSubject` included since 2.4.0-alpha.3 |
| `E_AUTHZ_SCOPE_DEPTH_LIMIT` | 422 | `scopes.attached`/`scopes.moved` with `scopes.maxDepth` declared: the child would end up more than `maxDepth` `parent` hops from `app` (the parent's chain + 1). Refused **before** writing or enqueueing; the gate is opt-in and partial — see [Limits](#limits) (2.4.0-alpha.5). Since 2.4.0-alpha.8 the `message` is written for the tenant that made the request — the depth reached, `scopes.maxDepth`, "nothing written or enqueued" — and names no backend: *why* the ceiling exists (`FACTS_MAX_RESOLVE_DEPTH`, `OPENFGA_RESOLVE_NODE_LIMIT`) travels in `error.details` for the operator's log |
| `E_AUTHZ_TOO_MANY_SCOPES` | 422 | `authorizedScopes`/`expandExcludedSubtrees` over `maxScopes`, or `descendantsOf` over `maxNodes` (`sqlDescendantsOf`: also a possible cycle) — never a partial list (2.1) |
| `E_AUTHZ_BACKEND_UNAVAILABLE` | 503 | facts backend or SQL catalog did not answer (both drivers, catalog sync/diff and the `authz_catalog_version` check included); the version row is missing or unreadable ("migración 2.0 no aplicada": fail-closed, never version 0); on `openfga` (since 2.5.0-alpha.4, R3) only the **transient** class: 5xx (501 included), 408, 429, `deadline_exceeded`, a per-check `internal_error` in a `batchCheck` — a 4xx is no longer a 503, see [How OpenFGA failures are classified](#how-openfga-failures-are-classified-250-alpha4) |
| `E_AUTHZ_BACKEND_TIMEOUT` | 503 | `timeoutMs` elapsed (subclass of the above); on `openfga` also the SDK error that carries no response at all (a client timeout and a refused connection — but also a DNS failure, a TLS error or a reset connection — arrive as the same bare `FgaError`, and are not told apart without reading the message: the conservative class, `indeterminate`, 2.5.0-alpha.4), and a **write** answered 504 or `deadline_exceeded` (the deadline of the server or of a gateway in front of it: the write may have landed) |
| `E_AUTHZ_RESOLUTION_LIMIT` | 503 | `openfga` (2.5.0-alpha.4, R3): the server answered `authorization_model_resolution_too_complex` — a scope chain or a group nesting deeper than it resolves —, from a single `Check` or as the per-check error of a `batchCheck`. Subclass of `E_AUTHZ_BACKEND_UNAVAILABLE` (a 503, transient for the relay) because at the edge it is probabilistic and a retry may succeed; past the bound it always fails. Never `false`. The bounds are in [Limits](#limits) |
| `E_AUTHZ_FROZEN` | 503 | the engine's writes are frozen by a platform operation (`authz:reconcile`, or the cutover window of `authz:freeze`) — **durably, fleet-wide** (row `id = 2` of `authz_catalog_version`, 2.3): reads keep working and the error is **retryable** (`error.retryable === true`) — reissue the write when the window ends (the message says how it lifts) |
| `E_AUTHZ_FREEZE_HELD` | 423 | `freeze()` (or a second `authz:reconcile`) found a live freeze owned by someone else: two windows never interleave, and only the owner's token — or `authz:unfreeze` — lifts one. The message names the holder, the reason and the fence |
| `E_AUTHZ_RESOLVER_FAILED` | 503 | your `resolveChain`, `parentOf` or `descendantsOf` threw or answered a malformed scope; `descendantsOf` and `resolveChain` disagree in `authorizedScopes`; a subtree to exclude cannot be enumerated |
| `E_AUTHZ_WRITE_CONFLICT` | 409 | an `openfga` write kept clashing with another transaction over the same tuples (FGA answers `Aborted`/409, or 400 "cannot write a tuple which already exists"): the driver re-reads and re-applies, and only gives up after three rounds. The backend answered, so this is never a 503 — retry the write. Since 2.5.0-alpha.4 (R3) also any such race (409, or 400 `write_failed_due_to_invalid_input`) that escapes a write which does not re-read (until then a 503). Also (2.4.0-alpha.2, lot L-3) a `database` `grant`/`deny` **inside your transaction** (`{ transaction }`) that hits the UNIQUE because another transaction committed the same fact while yours was open: outside a transaction the driver re-reads and keeps the winner's row; inside yours it cannot (PostgreSQL has already aborted your transaction — every later statement is `25P02` until you roll back — and under REPEATABLE READ the re-read would not see the winner), so it **poisons your transaction**: roll back and retry. Measured on all three engines, see [writing inside your transaction](#writing-inside-your-transaction-240-alpha2). The same for a `database` `relate`/`unrelate`/`purge*` inside your transaction (lot L-4) — on a UNIQUE clash of a tuple (userset, and since lot L-4b holder too: `subject_relation` is `''`, never `NULL`), and on a **deadlock** (two transactions writing two tuples in crossed order: PostgreSQL `40P01`, MySQL `1213`; the engine's victim gets this 409, never a hang nor the raw error) |
| `E_AUTHZ_CONFIG` | 500 | on `openfga` (2.5.0-alpha.4, R3), a failure of the **deployment**: the store or the pinned model does not exist (`authorization_model_not_found`, `latest_authorization_model_not_found`, a 404 `store_id_not_found`), the credentials are refused (401/403), the server rejects a type, relation or context the pinned model does not admit (`validation_error`, also per check in a `batchCheck`), its `--max-tuples-per-write` is below the driver's batches (`exceeded_entity_limit`), or the client refuses a malformed id before calling; and a **4xx the package does not know** (the server's error in `cause`). "Not transient": the same call fails the same way until the deployment is fixed — but the tree relay does **not** consume an attempt on it (a parked `moved` would keep the old parent in the store) and `authz:scopes:relay` prints it on its own line, `fallo de DESPLIEGUE #…`. Also: `relayScopeChanges({ only: [] })`, a `ScopeOutbox` that ignores `pending(limit, after, { ids })` and returns an entry that was not asked for, `requeueScopeChanges` with an id that is not parked (or an empty list), or a `scopes.maxDepth` that is not an integer ≥ 1 (2.4.0-alpha.5); contradictory config (`holderTypes` not injective or a holder type not declared in it, `scopes.*` without resolver, `appAccess` without `permission`, `catalog` together with `catalogRevalidate`, an invalid `maxAgeMs`); `bumpAuthzCatalogVersion` called without the writing transaction's client; a `{ transaction }` handed to `sqlScopeOutbox` that is not an open Lucid transaction of the outbox's own connection (another connection, a `QueryClient`, or the whole `db` — the message names both connections), **or one that is already committed or rolled back** (`isCompleted`, 2.4.0-alpha.8 — the same check in the roles and relations drivers; it used to surface as a 503); `sqlScopeOutbox()` enqueueing without `{ transaction }` (`requireTransaction`, 2.4.0-alpha.8; `true` by default since 2.5.0 · B6, `false` is the explicit opt-out); `relayScopeChanges({ deadDetail })` with a value other than `'full'`; `requireTransactionalWrites: true` (root, or `relations.requireTransactionalWrites`) with an active driver that does not declare `transactionalWrites: true` — raised **when the driver is resolved**, so reads fail too and the deployment does not start (2.4); a `relations.assertWrite` that returns a promise — or any value at all: `false`, `true`, a thenable function (it must be synchronous and it does not return verdicts: it throws or it does not; the write is refused before the driver, 2.4.0-alpha.3); an `openfga` relations purge against a server whose `--max-tuples-per-write` is below `RELATIONS_PURGE_WRITE_MAX` (100) — the server's 400 `exceeded_entity_limit`, marked as a partial write if an earlier `Write` already deleted (2.5.0) |
| `E_AUTHZ_ROLE_IS_NOT_ACCESS` | 500 | `appAccess({ role })` |
| `E_AUTHZ_INTERNAL` | 500 | package invariant violated (empty scope set on a write, misaligned batch, a third-party `authorizeMany` answering the wrong shape, a `Read` continuation token that never advances or more than 10,000 pages, a corrupt `assignable_at`/`owner_scope_key` row) |
| `E_AUTHZ_PURGE_INCOMPLETE` | 500 | `purgeScope` could not prove zero; on the relations port, `purgeObject`/`purgeSubject` of `openfga` could not prove zero after deleting — the error carries the `markPartialWrite` mark and the event was emitted with `indeterminate: true` (2.4.0-alpha.3) |
| `E_AUTHZ_RECONCILE_TOO_LARGE` | 500 | the destination's dump does not fit the declared `--max-tuples` cap (default 1 000 000) and reconciling needs the whole snapshot to know what is left over. Nothing was written; raise the cap if your process can take it |
| `E_AUTHZ_STALE_SOURCE_REFUSED` | 500 | `authz:reconcile --to=<config.default>` (or `authz:relations:reconcile --to=<relations.default ?? default>`) with any resolved source other than the destination itself — `--from`, picked by elimination, or `authz_*` (2.4.0-alpha.10): the stale direction — the source stopped seeing the active driver's facts at the cutover, so the pass would resurrect every revocation made since. Nothing was read, frozen or written; for roles the maintenance pass is `--to=<active>` without `--from`, and `--allow-stale-source` is the human decision (`--dry-run` flags `report.staleSource` instead of throwing) |
| `E_AUTHZ_OPERATOR_WINDOW_EXPIRED` | 503 | `freeze()` — and with it `authz:reconcile`, `authz:relations:reconcile`, `withFrozenWrites`, `authz:freeze` — found the OPERATOR window expired (2.4.0-alpha.10): taking a freeze over it would erase the trace that writers resumed mid-cutover. Acknowledge it with `authz:unfreeze`, reopen with `authz:freeze` |
| `E_AUTHZ_MASS_RECONCILE_REFUSED` | 500 | `authz:reconcile --prune` would delete facts from the destination while the source has not contributed a single **usable** one — empty, or every fact it returned was skipped (expired, on scopes your tree no longer resolves): the signature of a wrong connection, of the wrong source, or of a blind resolver. Nothing was deleted; pass `--allow-mass-delete` if you really mean to empty it (`--dry-run` flags it instead of throwing). A source that is merely **stale** but still usable is covered by reading the facts from whoever owns them |
| `E_AUTHZ_RENEWAL_UNSAFE` | 409 | `relate` on `openfga` (closure 2 of sublot D2) renewing — another expiry on an existing tuple — a `group:*#member` membership whose group, or a group containing it, is the subject of a live deny of the partition: the renewal is two `Write`s there and between them the subject would be granted. **Always zero writes**; the message carries the honest recipe (closure 5 of D2): there is no window-free way on `openfga` (openfga/openfga#2151); memberships without expiry in groups with a deny, or `unrelate` + `relate` accepting the window. A driver declaring `atomicRenewal: false` must answer it the same way. An already EXPIRED membership is not refused (closure 3 of D2). **Since 2.5.0-alpha.4 (L11) also** `relate` (relations) and `grant` (roles) on `openfga` when the key already exists with a condition the package does not write or cannot read (`foreign`/`unparseable`, see «The pinned model is the one your config generates»): zero writes, the message says "condición que este paquete no escribe"; its recipe is to inspect that tuple and delete it by hand, NOT `unrelate` + `relate` with a window |
| `E_AUTHZ_RENEWAL_RACED` | 409 | `RenewalRacedError` (closure 4 of D2; until then the same `E_AUTHZ_RENEWAL_UNSAFE`): an allowed two-`Write` renewal on `openfga` WENT THROUGH, and the re-check after it finds a deny that arrived concurrently and did not reach the subject between the two `Write`s. Marked partial (`indeterminate: true`), `renewalApplied: true`, `carriedDeny`. The final state is right: do NOT apply the `E_AUTHZ_RENEWAL_UNSAFE` recipe (it would reopen the window with the deny inside); review the subject's decisions in the window |
| `E_AUTHZ_DENY_MIGRATION_REFUSED` | 500 | `authz:relations:reconcile` / `runRelationsReconcile` (2.5.0-alpha.3): the source carries a live deny the **destination driver** cannot take — no `relationDenies`, no `denyPhase`, the type not in `deny: 'write'` in ITS config, the pair undeclared there, its pinned model without `denied_*`, or a source that does not mark `kind`. Decided in the plan phase: **zero writes** in every partition, never `skipped` (the allows alone would grant what the source denies). `error.refusals` lists them; `--dry-run` flags `report.denyRefused` instead of throwing (`deny NO migrable (<reason>)`, exit ≠ 0) |
| `E_AUTHZ_MASS_PURGE_REFUSED` | 500 | `pruneOrphanRoles({ force: true })` would purge every distinct owner (or more than half the local roles): the signature of a blind `resolveChain`. Nothing was deleted; pass `allowMassPurge: true` (`--allow-mass-purge`) if the prune is real |
| `E_AUTHZ_MEMBERS_DENY_LIMIT` | 500 | `membersOf` on `database` over an object with a live deny and more than `RELATIONS_MEMBERS_DENY_CHECK_MAX` (1,000) candidates; never a partial list. 500 and not 422: it is not an invalid question from the caller but a bound of the deployment (precedent `E_AUTHZ_TOO_MANY_LOCAL_ROLES`) (2.5.0) |
| `E_AUTHZ_TOO_MANY_LOCAL_ROLES` | 500 | more local roles than `maxLocalRoles` (10 000) in a `prune-orphans` pass; never a partial list |
| `E_AUTHZ_UNSUPPORTED` | 500 | a primitive needs an optional port method the active driver lacks: `listDenies` (2.1; also behind `defineScopedRole`), `purgeRole` (2.2 — behind `deleteScopedRole`, `authz:catalog:prune-orphans` and, before writing anything, `defineScopedRole`; the `openfga` driver until 2.3); `reconcile` (2.3 — `authz:reconcile --to=<driver>`); `enumerateFacts` (2.3 — being the *source* of `authz:reconcile`; the `database` driver does not implement it: its facts are `authz_*`. Also raised when `--to` is the **active** driver and declares `hierarchyFacts`: its facts are its own, so the pass has to be able to read them instead of rebuilding it from `authz_*`). Also `{ transaction }` on `grant`/`revoke`/`deny`/`removeDeny` or `relate`/`unrelate`/`purge*` when the active driver declares `transactionalWrites: false` (2.4 — the message names the driver and the operation, nothing was called; the way out is the `database` driver or `requireTransactionalWrites`; the `openfga` drivers raise it themselves too, so `manager.driver()` is not a way out — see [the recipe by direction](#openfga-the-recipe-by-direction)), and `{ transaction }` on the delegation API (`defineScopedRole`/`updateScopedRole`/`deleteScopedRole`: the catalog is written through `withAuthzCatalogWrite`, the cross-process serializer, which a caller's transaction would defeat) |
| `E_AUTHZ_MODEL_TOO_LARGE` | 500 | the catalog does not fit in an OpenFGA authorization model (262,144 **bytes** — around **450 permissions with realistic slugs**; see [the model ceiling](#the-model-ceiling-is-bytes-not-permissions)): checked in `syncAuthzCatalog` **before** writing, with a warning past 80 % |
| `E_AUTHZ_RELATION_CONFIG` | 422 | a `relations/` object type or relation cannot be **fused** into the shared `facts` model: it duplicates a reserved `facts` type (`scope`/`role`/`role_binding`/`deny_binding`/`group`) or relation family (`can_<P>`/`denied_<P>`/`permits_<P>`/`parent`/`rooted`/`assignee`…), or a relation name collides with a catalog permission (F-04). The generator raises it — not OpenFGA's opaque 400 — because in the shared store the id-spaces overlap |
| `E_AUTHZ_SCOPE_DRIFT_UNGUARDED` | 500 | the `openfga` driver was constructed without `scopes.outbox` and without `acceptScopeDriftRisk: true`. Thrown at construction: a rollback of your transaction would otherwise leave the store's tree ahead of yours, and that escalation is invisible from your database |
| `E_AUTHZ_REQUEUE_REFUSED` | 500 | `requeueScopeChanges` / `authz:scopes:requeue`: an entry applied *after* the parked one shares a scope key with it, so requeueing would re-apply the old change on top of the new (the store reverted, with a single edge). Nothing was requeued; the error carries `conflicts` (the diff); `authz:reconcile --to=<driver>` is the remedy and `--force` (ace command only) the override (2.4.0-alpha.5) |
| `E_AUTHZ_SCOPE_TREE_DRIFT` | 500 | the materialized tree has more than one `parent` edge for the same scope: someone else writes to the store. A write never "fixes" it by guessing; `authz:reconcile` rebuilds the tree from yours and reports the scope |
| `E_AUTHZ_NO_DESCENDANTS_RESOLVER` | 500 | `authorizedScopes`/`expandExcludedSubtrees` without `scopes.descendantsOf` |
| `E_AUTHZ_VIEW_EXPIRED` | 500 | a `forRequest()` view used to read (`expandExcludedSubtrees` included) after its `maxAgeMs` (default 30 s, monotonic clock) |
| `E_AUTHZ_UNSUPPORTED_DIALECT` | 500 | `sqlDescendantsOf` / `sqlScopeEdges` on a dialect other than PostgreSQL / MySQL 8 / SQLite |
| `E_AUTHZ_SCOPE_TOO_DEEP` | 500 | `hierarchicalScopeResolver` over `maxDepth` (no truncated chain) |

## Driver options

Both drivers take `resolveChain` and **`timeoutMs`** (default 5000): every SQL query the driver builds is given a knex timeout — the `DELETE`s inside `purgeScope`'s transaction included; only knex's own `BEGIN`/`COMMIT` carry none — every FGA call has a total deadline, and an elapsed deadline is 503 `E_AUTHZ_BACKEND_TIMEOUT`. A server that accepts the connection and never answers is released in under a second (*"authorize contra un servidor mudo ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT en menos de 1 s"*). SQLite's synchronous driver cannot actually time out; what the suite pins there is that every query carries the deadline (*"toda consulta sale con el timeout configurado"*). A deadline releases the caller, it does not abort the request in flight: see `indeterminate` above.

Both also take **`catalogRevalidate`** (`'always'`, the default, or `{ everyMs }`) *or* **`catalog`** (a `CatalogCache` to share between drivers of the same process; its own `revalidate` is the policy) — the catalog memo described under [Performance](#performance). Passing both is 500 `E_AUTHZ_CONFIG` at construction: the driver's `catalogRevalidate` would be silently ignored otherwise.

Both take **`now`** (default `() => new Date()`): the wall clock every time-based *decision* uses — `expires_at > now()` in SQL, the `current_time` of every FGA check (one instant per operation: every check of a `batchCheck` carries the same `current_time`, and the two reads of `listScopes` filter with the same `now`), the client-side expiry filter of the enumerations and the three states of a re-grant. The audit stamps (`created_at`) are **not** decisions and use the system clock: with MySQL's `TIMESTAMP` an injected clock in 2040 made every write fail (*"… se escribe estando el reloj en 2040"*). Every driver of the package also implements `withClock(now)` on the port (a view bound to another clock, like `withChainResolver`), and the manager applies **`clock`** from the config to the driver it resolves — all `forRequest()` views share it; a config `clock` over a driver without `withClock` is 500 `E_AUTHZ_CONFIG`, never a clock silently ignored. It exists so that expiry is observable *without sleeping* (the contract fixes the exact instant: one millisecond before `expiresAt` grants, at `expiresAt` it does not — *"caducidad exacta con el reloj inyectado"*) and so that your own tests can freeze time; in production leave it alone and keep NTP running. It is not the monotonic clock of `forRequest({ maxAgeMs })`, which measures a window and must not move with NTP. Nothing else in `src/` reads the wall clock (a grep test pins it) — except the model trait `withAuthzScopes` (`whereRoles`/`wherePermissions`), which cannot see the manager: it decides "live" with the system clock unless you compose it with the same clock, `compose(BaseModel, withAuthzScopes({ clock }))` (*"withAuthzScopes({ clock }) decide la vigencia con ESE reloj"*). Its primary-key comparison is dialect-aware (on PostgreSQL a `uuid` primary key is cast to text against the `varchar` subquery: *"… con la clave primaria uuid nativa del modelo"*).

### Testing expiry from your app (2.5.0)

Expiry, renewal and "it expires right now" are decided by that one injectable clock, so your own tests can fix
the instant instead of sleeping. `createTestClock(start?)` (from **`@jantstack/adonis-authz/testing/clock`** — a
light module with no test-framework or Lucid import, so it is safe in a config file that production loads; `/testing`
re-exports it but pulls `@japa/runner` and `@adonisjs/lucid/services/db`, which an `--omit=dev` deploy does not have) returns a
**stable function over a mutable instant** — the same reference lives in your config for the whole test
process; `set(at)`, `advance(ms)`, `now()` and `at(offsetMs)` move or read it — and it mutates nothing global
(`systemClock`, the audit stamps and whatever does not receive the clock stay on wall time):

```ts
// config/authorization.ts
import { createTestClock } from '@jantstack/adonis-authz/testing/clock' // never from '/testing' here: that module imports Japa and Lucid
export const testClock = createTestClock('2030-01-01T00:00:00.000Z')
export default defineConfig({ …, clock: app.inTest ? testClock : undefined })

// tests/sharing.spec.ts
await relations.relate(user, 'viewer', doc, tenant, { expiresAt: testClock.at(+3_600_000) })
assert.isTrue(await relations.check(user, 'viewer', doc, tenant))
testClock.advance(3_600_000)                                      // the share expires right now (strict)
assert.isFalse(await relations.check(user, 'viewer', doc, tenant))
```

The provider hands `config.clock` to **both** managers (roles and relations), and each applies it to its driver
with `withClock`, so one clock decides every expiry in the process — the suite pins that wiring with a case that
turns red if the relations manager stopped receiving it (P5-1). **Two things to know.** First, **the same clock
decides the freeze barrier and the reconcile lease**: a frozen window with a lease is "expired" for a process
whose clock has moved past `untilMs` (advance it 16 s and a pass sees its 15 s lease lapsed; freeze it and an
operator window with a lease never expires for that process). That is also what it means in production: **the
lease is judged by the clock of the process that reads the freeze row**, against an `untilMs` written with the
clock of the one that froze — a writer whose wall clock runs ahead by more than the lease writes inside the window
of a running pass (pre-existing, not introduced by the injectable clock; windows without a lease are not affected).
Keep NTP on every process that writes. Second, a `relate` that reads a *ticking* clock
(one advancing per read) is fine, but it is your test's clock: production leaves `clock` alone and keeps NTP
running.

`openfga` additionally takes `holderTypes` (required, injective; a holder whose morph name is not in it is 500 `E_AUTHZ_CONFIG`), **`modelId` (required since 2.5.0-alpha.4, in both `openfga` drivers: `openfga:provision` prints it as `OPENFGA_MODEL_ID`; see [the model gate](#the-pinned-model-is-the-one-your-config-generates-250-alpha4))**, a `logger` (default `console`), **`retryParams`** (default `{ maxRetry: 0 }`, see `indeterminate` above) and **`consistency`**: `'higher_consistency'` (default) or `'minimize_latency'`. The default protects the "removing the deny restores" promise against a server started with `--check-query-cache-enabled`, where a fresh revoke or deny would keep granting for up to the cache TTL; `minimize_latency` is the explicit opt-out (*"todo check lleva context.current_time; toda llamada HIGHER_CONSISTENCY"*). `driver.diagnostics.unparseableBindings` counts store tuples the engine cannot interpret — binding ids it does not understand and malformed tuples alike; each one is logged, never skipped in silence.

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
| `transactionalWrites` | **`true`** (default; declare `transactionalWrites: false` in the driver options on a pool of 1) | **`false`** | `grant`/`revoke`/`deny`/`removeDeny` with **`{ transaction }`** write the fact **inside the caller's transaction** — *both or neither*, never *"not lost"* (2.4, the `{trx}` panel). `database` does it since 2.4.0-alpha.2 (lot L-3): the write goes through your open Lucid transaction of the driver's connection (`assertCallerTransaction`: another connection, a `QueryClient` or the whole `db` are 500 `E_AUTHZ_CONFIG` before any statement), the authority never does, and the published suite pins **rollback ⇒ zero rows by census** for the four writes — see [writing inside your transaction](#writing-inside-your-transaction-240-alpha2). `openfga` cannot be anything but `false`: a tuple does not enter a SQL transaction and there is no 2PC; what it offers instead is [the recipe by direction](#openfga-the-recipe-by-direction). With `false`, `{ transaction }` is **500 `E_AUTHZ_UNSUPPORTED`** naming driver and operation, with **zero driver calls** (the manager's gate *and* the driver's own) — never ignored, never a warning; `requireTransactionalWrites: true` in the config makes it **500 `E_AUTHZ_CONFIG` when the driver is resolved** (the deployment does not start). Same name and same two gates on `RelationsDriverCapabilities` (`relate`/`unrelate`/`purgeObject`/`purgeSubject`; `relations.requireTransactionalWrites`, inherited from the root) — and since lot L-4 the `database` **relations** driver declares **`true`** too (`new DatabaseRelationsDriver(config, { transactionalWrites: false })` on a pool of 1; see [writing relations inside your transaction](#relations-rebac-24)). The only pair whose **two** faces are mandatory in the suite. Not to be confused with `scopes.*`'s `{ transaction }`, which **enqueues** in the outbox — enqueueing ≠ writing |

**Two answers `facts` does not share with `database`, declared — not scheduled fixes (2.3).** `authorize` decides with the tree that lives in the store; it never calls your `resolveChain`. That is the property you are buying: a PDP that answers when your database does not. It has two consequences, and each one is a **capability pair with a negative case** in the published contract suite — the package does not skip them, it judges both faces.

> **(a) A resolver that is down no longer makes `authorize` throw — and it can no longer make it stop, either.** This is the property, and it is one-sided. While your tree is unavailable `authorize` and `authorizeMany` keep answering, and what they answer is `true` for everything that was granted; meanwhile `revoke`, `deny`, `removeDeny`, `purgeScope`, `hasRole` and every `list*` are 503 `E_AUTHZ_RESOLVER_FAILED`, because they all canonicalise against your tree. The mode is **grant-only until your database comes back**: it grants and there is no way to revoke. Plan your incident response around that — in `database`, everything stops together. Closing it would mean putting `resolveChain` back on `authorize`'s hot path, which is the whole point of this mode (*"con el resolutor del consumidor caído el modo es \*grant-only\*"*, *"authorizeMany con un scope cuyo árbol lanza: RESPONDE con el árbol del store"*).

> **(b) A uuid alias does not find its facts on the read path.** `authorize` composes `scope:<type>|<uuid>` from the caller's spelling without canonicalising it, so the same id written differently — without dashes, which PostgreSQL's `uuid` column and MySQL's `*_ci` collation fold into the same row — answers `false` where `database` answers `true`. It is fail-**closed**: it never evades a deny and never grants what was not granted, but it is not the same answer. **Pass scope uuids exactly as your table stores them.** The write path is *not* affected: `grant`, `revoke`, `removeDeny`, `purgeScope` and `scopes.detached` canonicalise in both modes, including after the row is gone (that half was fail-*open* until 2.3 and is fixed, not declared), and the judge pins it on both faces of the pair so this is not read as "spelling does not matter in `facts`" (*"un alias del uuid que el árbol funde con la fila canónica NO encuentra sus hechos … pero las ESCRITURAS sí canonizan"*).

**The anti-cycle checks are the package's, in both modes, and they are not optional.** Measured against OpenFGA v1.19: the server *accepts* an edge that closes a cycle, does not hang, answers in 2–7 ms, and from then on inheritance runs both ways — a grant on a descendant grants on its ancestor, and with the root inside the cycle it grants everywhere. Nothing is logged and there is no error to catch. That is why `child ≠ app`, "the parent exists" and `child ∉ ancestors(parent)` are checked before anything is written (422, no edge), and why you should not expect the backend to be a second line of defence.

### Reading capabilities at runtime (2.4.0-alpha.4)

The table above is what each driver **declares**; your service code can read it from the manager instead of guessing from the driver name — and instead of calling `driver()`:

```ts
// The same service code serves both drivers, without a single driver() in it.
if ((await authorization.capabilities()).transactionalWrites) {
  await authorization.grant(user, 'editor', unit, { transaction: trx })   // both or neither, with YOUR transaction
} else {
  await authorization.grant(user, 'editor', unit)                          // openfga: the recipe by direction
}
if (relations.capabilities().transactionalWrites) { /* relate(…, { transaction: trx }) */ }
```

`authorization.capabilities()` is `async` — it resolves the active driver through `driver()`, so it pays the driver factory once (cached from then on) and **inherits its two gates**: with `requireTransactionalWrites: true` and a driver that does not comply it is the same 500 `E_AUTHZ_CONFIG` the deployment already fails with, and a `facts` driver without `scopes.outbox` or the signature is the same 500 `E_AUTHZ_SCOPE_DRIFT_UNGUARDED`. That is deliberate: capabilities belong to the *instance* (`database` decides `transactionalWrites` from its options), and a reading that resolved the driver by any other path would leave `driver()` serving an instance that never passed the gates. Call it once at boot (a `booted`/`ready` hook), not per request. `relations.capabilities()` is synchronous: the relations driver is built eagerly and its gate already ran. Both return a **read-only, frozen, normalised copy** typed as `AuthorizationDriverCapabilities` / `RelationsDriverCapabilities` (both exported): every known key is present, only `true` is `true` — the same reading the write gates apply — so a third-party driver with partial or no `capabilities` reads as `false`, **never `undefined`**; mutating the copy throws in strict mode and changes nothing. The read does not soften anything: `{ transaction }` to a driver that declares `false` is still 500 `E_AUTHZ_UNSUPPORTED` whether or not you asked first, and **`driver()` is still platform API** — tenant code should not call it, and a code review can keep grepping for it.

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
    transactionalWrites: false,           // can the driver write grant/revoke/deny/removeDeny INSIDE the caller's transaction (2.4)? false ⇒ { transaction } is 500 E_AUTHZ_UNSUPPORTED, with zero driver calls; true ⇒ the suite opens a transaction and pins rollback ⇒ ZERO rows by census (the `transactions` hook below; default Lucid's db.transaction() + authz_assignments/authz_denies)
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
  // Only with `transactionalWrites: true` (2.4): how the suite opens a transaction of YOUR driver's connection
  // and counts a holder's facts in YOUR backend (the census). Omit it for Lucid's `db.transaction()` + `authz_*`.
  transactions: { begin: async () => openMyTransaction(), census: async (subject) => countMyFacts(subject) },
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

### The outbox contract: `runScopeOutboxContract` (2.4.0-alpha.5)

The `ScopeOutbox` port has duties nobody judged until alpha.5 — the receipt, oldest first, `after` as a continuation, an idempotent `markApplied`, a `markFailed` that counts and keeps the row, the actor that travels — and since alpha.5 every optional method is a **capability pair**: a `true` face that judges the duty and a `false` face that judges that the manager *says so* (or that the implementation degrades towards safe), never a skip. A third-party outbox proves itself the same way the package's does:

```ts
import { runScopeOutboxContract } from '@jantstack/adonis-authz/testing'

runScopeOutboxContract({
  name: 'my-outbox',
  capabilities: {
    transactionalEnqueue: true,   // enqueue writes through context.transaction: rollback ⇒ nothing pending (needs `transactions`)
    filter: true,                 // pending(limit, after, { ids }) filters in the port; false ⇒ `only` is 500 E_AUTHZ_CONFIG
    transient: true,              // markFailed(..., { transient: true }) does not count; false ⇒ it counts anyway
    dead: true,                   // dead() exists: parked after limits.maxAttempts; false ⇒ nothing is ever parked
    acquire: true,                // acquire() is a held, exclusive lease; false ⇒ the relay never says busy
    earlierPending: true,         // the dependency probe of `only`; false ⇒ the manager pages pending(), same verdict
    requeue: true,                // requeue + laterApplied (needs dead); false ⇒ requeueScopeChanges is 500 E_AUTHZ_UNSUPPORTED
    createdAt: true,              // entries carry createdAt (the enqueue stamp): the relay reports the queue age; false ⇒ queue is { null, null } (2.4.0-alpha.8)
  },
  limits: { maxAttempts: 3 },                                  // with dead: true — what your outbox parks at (≥ 3)
  makeOutbox: () => myOutbox({ maxAttempts: 3 }),              // fresh, over an empty queue
  cleanup: () => emptyMyQueue(),
  transactions: { begin: async () => openMyTransaction() },    // with transactionalEnqueue: true
})
```

Seventeen cases per harness (2.4.0-alpha.8): nine core duties — including O-07b, the root `app` is not a scope key — and one face per each of the eight capabilities. Declaring `dead: true` without `limits.maxAttempts`, `requeue: true` without `dead: true`, or `transactionalEnqueue: true` without `transactions` throws at registration — a promise without a judge does not pass. The package runs it on `sqlScopeOutbox` over the four engines and on an in-memory double (`makeScopeOutbox`, exported too) with all capabilities and with none, so both faces of every pair run on every `npm test`.

## OpenFGA tooling

```bash
node ace openfga:provision                    # creates a store + writes the model for your holderTypes AND your permissions
node ace openfga:provision --store-id 01H…    # writes a new model version into an existing store
node ace authz:catalog:sync                   # …and projects the catalog into it (role→permission tuples + the root marker)
```

**`openfga:provision` writes the `facts` model, and that model carries your permissions** (four relations each: `<P>`, `can_<P>`, `denied_<P>`, `permits_<P>`), so the command resolves the `catalogs` you declared in `config/authorization.ts` — they are plain functions, no database needed. Without them there is nothing to publish and the command exits non-zero rather than leaving a store that denies everything. Adding or removing a permission changes the model: write a new version with `--store-id` and re-run `authz:catalog:sync`, which rewrites the derived projection (and re-places the root marker) through the driver.

**`openfga:provision` re-reads what it published (2.5.0-alpha.4).** Right after `writeAuthorizationModel` it reads
the model back by its id and compares it, whole, with the one the config generates (the same comparison the drivers
run at start-up). Equal ⇒ it prints `OPENFGA_MODEL_ID=…`. Different, or the read fails ⇒ exit 1 with the stable
prefix `provision RELECTURA FALLIDA:` — the model **is already published** in the store, and the line
`OPENFGA_MODEL_ID=` is **not** printed: do not pin it (a server that serialises the model differently, e.g. another
OpenFGA version — CI runs v1.19.0 — would make every driver answer 500 at its first use). Both clients of the command
and `provisionOpenFgaStore` run with `retryParams: { maxRetry: 0 }`: since SDK 0.9.6 a client without them retries
429/5xx three times, and a retried `createStore` can leave an orphan store.

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

- **`--to` is the *active* driver and its facts live in its own backend** (`capabilities.hierarchyFacts`, which is what `openfga` declares): then its facts are its own and it is read from *itself*. This is the **maintenance pass**: it rebuilds everything **derived** — root marker, catalog projection, tree — and applies the visibility sweep of invariant 18 with the tree and the catalog of *today*, and **it writes no fact; with `--prune` it deletes the facts of scopes that no longer resolve**, the expired ones and those of roles or permissions the catalog or the model no longer has (and the leftovers) — without `--prune` it deletes no assignment or deny (only the role-visibility edges invariant 18 forbids) and reports them as `extra-fact`. (Until 2.4.0-alpha.9 this line, and the command's first line, claimed the pass deleted nothing while `--prune` deleted them — measured by a consumer.) It is also what makes `--dry-run` usable as the CI verifier of a `facts` deployment: a correct store now comes out **clean** instead of reporting every live fact as `extra-fact`. (A driver in that position that cannot enumerate its own facts is 500 `E_AUTHZ_UNSUPPORTED` naming `enumerateFacts` — reading `authz_*` for it would be the bug.)
- **`--from=<driver>` is given**: you decide. If that driver's facts are `authz_*` (the package's `database`), `--to=openfga` is the **one-way migration** it always was, and it will happily overwrite the destination's facts with what those tables hold. That is what you want while migrating — and it is a loaded gun pointed at a store that is already live, which is why it now takes an explicit `--from` to fire it. **Except towards the active driver (2.4.0-alpha.10, breaking):** if `--to` is `config.default`, the only legitimate source is `--to` itself (the maintenance pass above); any other **resolved** source — named with `--from`, picked by elimination without `--from` (with `database` active, `--to=database` alone picks `openfga`), or the `authz_*` tables — makes the manager refuse with 500 `E_AUTHZ_STALE_SOURCE_REFUSED` before resolving the source, reading or freezing anything. That is the **stale direction**: once the engine serves from `--to`, its facts are written there and the source stopped seeing them, so the pass would re-write what was revoked since the cutover (with or without `--prune`; and the mass-deletion guard does not fire, because the source is stale, not empty). The guard looks at `--to` and at the source it resolves, never at the flag — and at the *resolved* driver, not the key: the same factory registered under two keys is the same driver, so an alias of `config.default` is refused too (**declared limit**: identity is the factory *reference*, so two different factories that build the same backend are not detected and such an alias passes; register an alias with the same reference, and a backend identity declared by the driver is on the 2.5 list) — so the four rows are: maintenance pass — runs; initial cutover (`--to=<new>` while the engine still serves from the old one) — runs; going back **before** switching `default` — runs; re-running either of the two **after** switching `default` — refused. `authz:relations:reconcile` applies the same rule with the active relations driver (below). `--allow-stale-source` (`allowStaleSource: true`) is the human decision; `--dry-run` never throws, it flags `report.staleSource = { to, from, allowed }`, prints a warning and exits non-zero. **The guard is only as reliable as the `config.default` of the process that runs the command**: it has no durable record of what the fleet serves from, so a migration job or pod started with a different environment (`default: env.get('AUTHZ_DRIVER', 'database')` without that variable) believes another driver is active and the guard is silently off. Run it with the fleet's config; a durable seal of the active driver is on the 2.5 list.
- **Otherwise** (the destination is not the active driver): the migration of always, facts read from `authz_*`.

**It needs `scopes.enumerateEdges`** in your config: the whole tree, paginated with a cursor. `sqlScopeEdges({ table, uuidColumn, parentColumn, typeColumn })` implements it over a table with a parent column, exactly like `sqlDescendantsOf`. Without it the command refuses (500 `E_AUTHZ_CONFIG`) instead of assuming a flat tree — a flat tree would be an invented hierarchy, and an invented hierarchy grants.

**`sqlScopeEdges` covers ONE table, and concatenating several does not cover a tree that lives in more than one (2.4.0-alpha.4).** The helper does a `LEFT JOIN` of the table *against itself* on `parentColumn = uuidColumn`, and a row whose declared parent has no match in *that* table is **skipped in silence** — that is the documented "a parent that does not exist is not emitted", and it has no way to tell "orphan" from "the parent lives in another table". So if your tree is spread over several tables (say `organizations` → `organization_units` → `ia_spaces`), the obvious composition — one `sqlScopeEdges` per table, drained one after the other — **does not emit the edges between tables**: every `ia_space → organization_unit` and `organization_unit → organization` edge is dropped without a word, and the parent's *type* would come out wrong anyway (it is the child table's fixed `scopeType`). With `authz:reconcile --to=openfga` that is not "some edges are missing": the destination sees them as surplus and deletes them, and by invariant 9 (`can_<P>` requires `rooted`) **the whole subtree denies**. Fail-closed, noisy, nobody escalates — and a day lost. Write your own `enumerateEdges` instead: one query that concatenates the tables (`UNION ALL` of `(child_uuid, child_type, parent_uuid, parent_type)` across the tables, `parent IS NULL` meaning `app`), ordered by a total and stable key (the child uuid works) with the cursor over that key, and emitting an edge only when the parent exists in *any* of the tables; then compare with `authz:reconcile --to=<driver> --dry-run` before the first real pass. Alternatively chain the tables in a fixed order and encode *which table* inside the opaque cursor — the contract only asks for a total, stable order across calls. *Recipe not verified by the suite* (it has no multi-table fixture); a composition helper (`composeScopeEdges`, or `parentTable` on `sqlScopeEdges`) is deferred to 2.6.

What one pass does, in order: the **root marker** (`scope:app#rooted`, without which the whole store denies), the **catalog projection** (`role:<uuid>#permits_<P>`, read with the very same function `syncAuthzCatalog` uses), the **tree** from `enumerateEdges`, and the **facts** from `authz_assignments` / `authz_denies` — each assignment as its `assignee` tuple plus the two (c2) edges, each deny as `scope:<key>#denied_<P>`. It is **idempotent** (a second pass writes zero — the word the requirement used, and it has its case), **resumable** (the source is read in batches of 100 with a cursor over the primary key; repeating a pass converges) and **never silent**: the report carries `{ written, updated, unchanged, extra, deleted, skipped{reason} }` per phase, plus each row that did not migrate with its reason (`unknown-scope`, `unknown-role`, `unknown-permission`, `unknown-holder-type`, `expired`, `role-not-visible`, `cycle`, …).

**The source is read in one consistent snapshot — in the direction where the source is `authz_*` (2.3).** The two sweeps (`authz_assignments`, then `authz_denies`) used to run on the global connection, one after the other, so the gap between them — the time it takes to walk the first table in batches of 100 — let *composite* business operations slip through. An offboarding is `revoke` + `removeDeny`: landing in that gap, the pass kept one half of each and wrote **the role without its deny** into the destination, granting a permission that **neither the previous nor the following state granted**, while the report said `written=13 extra=0 skipped={} clean=true`. That is not a lost permission, it is a fabricated one — an escalation, with nothing in the report to distrust. Both sweeps now run inside **one repeatable-read transaction**, so the worst outcome of the window is *the consistent state of `t0`* — recoverable drift that the next pass repairs — instead of a state that never existed. What each engine guarantees is not the same and is stated rather than assumed: PostgreSQL takes the snapshot with `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ`; MySQL/InnoDB is sent `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ` explicitly (it is InnoDB's default, but a server setting is not a promise of this package) and fixes the consistent read on the first query; SQLite takes no isolation level at all (knex warns and ignores it) because a read transaction is already a snapshot there, so the package does not send it one.

**What that does NOT cover, said out loud.** It covers the direction whose source is `authz_*` (`--to=openfga`). When the source of truth of the facts is the **store** (`enumerateFacts`: `--to=database`, and the maintenance pass), the `Read` pages are **not** a consistent snapshot either, and there is no repeatable read to ask for: the same half-a-transaction composition is possible there. That direction is *not* closed in this version. The instrumentation that could name it — `readChanges({ startTime })` as a window witness, reporting the tuples that moved during the pass — is **not implemented**; the honest statement today is that the direction whose source is a store has an open window, and a second pass after the cutover is the only thing that closes it.

**What it deletes on its own, and what needs `--prune`.** The root marker, the catalog projection and the tree are mirrors of local data nobody else writes, so whatever is left over goes — that is what repairs a scope that ended up with **two parents** in the store (the drift `scopes.moved` refuses to guess about) and what removes edges your tree no longer backs. **Facts are only deleted with `--prune`**: the facts of a scope that no longer resolves (the ones that would grant again if the scope came back with the same uuid) and anything an older version of the store left behind. One deliberate exception: a `scope#binding` edge that your source backs but whose visibility rule says *no* (invariant 18) is deleted **without** `--prune` and counted in `drift.roleVisibility` — leaving it is fail-open, and it is exactly the write `scopes.moved` / `projectCatalogRole` lose when the relay does not get there.

**The store is SHARED, and this pass only governs its own four object types (2.4.0-alpha.9).** With `openfga`, the facts of this engine and the tuples of [`relations/`](#relations-rebac-24) live in the **same store**, and this pass has to read it whole (that is the only way to see what is left over). Until 2.4.0-alpha.8 everything it did not recognise was classified as a leftover *fact*, so **`--prune` deleted every relation tuple in the store** — 60 out of 60 measured by a consumer, the built-in `group` type included — and the destructive pass reported `clean = true` with exit 0, because it had just deleted the very thing that made it dirty. What this pass governs is now an explicit, frozen list of **object types**: `scope`, `role`, `role_binding` and the obsolete `deny_binding` (the deny of the ≤ 2.2 `resolver` mode, which `enumerateFacts` still reads and emits — so the promise that *one pass cleans a store written by the previous version* is kept whole). **Anything else is foreign**: it is not deleted, not even with `--prune`, it is not drift, and it does not enter `skipped` (which is why `clean` can be `true` again on a shared store). The classification **reads nothing at runtime** — not your relations config, not the published model, not a table: the process that runs a cutover is exactly the one that may not have that config, and a failed read must never turn somebody else's data into something deletable.

The report carries them in a field of their own, `foreign: { tuples, types, relations?, unknown? }` (`phases` does not grow: it is a published type), and the command prints them with their type: `ajenas: 60 tupla(s) de tipos que esta pasada NO gobierna [document (40), group (10), space (10)]`, plus `--prune ha respetado 60 tupla(s) ajenas` on the destructive pass. When `relations.config` is wired, `foreign` is split into `relations` (your declared types, plus `group`) and `unknown` (nobody claims them) — **for the report only**. The way back has no symmetric defect and never had one: the relations reconcile has always enumerated by an allowlist of types and cannot see, let alone delete, a fact (measured). Two limits worth writing down: foreign tuples still count against `--max-tuples` (the snapshot is of the *store*, not of this pass), and **the tuples of a relation type you no longer declare are swept by nobody** — take `document` out of `objectTypes` and its tuples stay in the store (`enumerateRelations` filters by the allowlist, `unrelate`/`purgeObject` are 422 by F-05, and this pass now respects them), so they **grant again if you ever re-declare that type**. The way out today is to declare the type again and run `authz:relations:reconcile --prune` **for that partition** — and two caveats before you do (audit of alpha.9): the pass refuses with `E_AUTHZ_MASS_RECONCILE_REFUSED` when the source (`database`) holds none of those tuples, and the flag that lifts that refusal (`--allow-mass-delete`) will happily empty the **live** relations of the partition you point it at, so check `--partition-type`/`--partition-uuid` twice; and the command reconciles **one partition per pass**, so a multi-tenant cleanup is a loop you write. A `--prune-undeclared` is on the 2.5 list. There is deliberately **no `--prune-foreign`**: a mass deletion of another subsystem's data, triggerable from CI, is not a flag.

**`--dry-run` is the verifier, and it is read-only by contract**: same walk, same numbers, zero writes, exit 1 if there is anything to do. Run it in CI or in a cron. **`expired` does not fail the pass** (2.3): it is the migration's one *declared* loss — an expired assignment grants nothing in either driver, nothing sweeps expired rows out of the source (observable expiration without a scheduler, on purpose), and no write to the destination can "fix" it — so counting it as drift made the green verifier unreachable with real data: the first expiry pinned exit 1 forever. It is still reported (`N sin migrar por 'expired'`); it just is not drift. Expired facts *left over in the destination* are still drift (`extra-fact`), and their sweep exists: `--prune`. **There is no `--fix` and there will not be one** — a repair flag on a verifier is a grant mechanism. **And it does not freeze** (2.3): a pass that writes nothing has nothing to protect, so freezing there would buy zero and cost a write-outage mechanism fired by a cron job — which is precisely what "run it in a cron" invites. The pass that *does* write still freezes.

**Cycles are reported, not just edge differences.** OpenFGA accepts a `parent` cycle and evaluates it, which makes inheritance bidirectional (a grant in a descendant would grant in its ancestor), so **no edge of a cycle is written**: those nodes stop reaching the root and therefore deny, and the cycle is named in the report. The **relay window** is reported too (how many tree changes are queued and unrelayed — the window in which the backend decides with the old tree) and so are the **parked** entries, which are not a window but permanent divergence.

**While the pass that WRITES runs, writes are frozen — durably, fleet-wide (2.3)** (never under `--dry-run`, see above). The freeze lives in **row `id = 2` of `authz_catalog_version`** — the same cross-process signal every write already depends on — so it reaches **every process that shares the `authz_*` tables**, not just the process that froze: every engine write (`grant`/`revoke`/`deny`/`removeDeny`, the three `scopes.*`, the delegation API, `pruneOrphanRoles --force` and the relay) answers 503 `E_AUTHZ_FROZEN` (**retryable**) and **reads keep working** — `authorize` is never frozen, not for a millisecond. Until 2.3 `freeze()` was a per-process boolean and this paragraph promised otherwise; that promise was false in every deployment with more than one worker, and it is gone. What the mechanism can honestly promise is this: **another process gets a retryable 503 while the window is live** — never "no write enters the window" (a write that had already passed its barrier when the freeze landed still lands; there is no atomicity between a SQL row and an external store, so that phrasing would not even be falsifiable). The cost is measured: one extra primary-key `SELECT` per **write** (+0.14 ms p50 on PostgreSQL, +0.11 on MySQL), zero per `authorize`. And the window is *minutes*, not seconds, at the declared cap (0.136 ms per fact ⇒ ≈ 136 s at `--max-tuples` 1,000,000).

The freeze has an **owner and a lease**. `manager.freeze(reason?, { leaseMs?, kind? })` takes the row (a live freeze held by someone else is 423 `E_AUTHZ_FREEZE_HELD`, never two owners) and returns a **token** (`{ fence, holder }`); `unfreeze(token)` only lifts the freeze whose token matches, so a nested or stale window can never lift somebody else's barrier — a `reconcile` running *inside* a frozen window runs inside it and leaves it standing. The lease (default 15 s) is renewed conditionally every `leaseMs / 3` while the freezing process lives; if that process dies (`SIGKILL`, OOM, pod eviction) **the fleet resumes writing on its own within `leaseMs`** — nobody cleans a row by hand. And the guarantee is **demonstrated, not assumed**: the writing pass reports `frozen: { durable, lapsed, leaseMs, fence }`, and `lapsed: true` — the lease was lost mid-pass (an event-loop stall longer than the lease, the database down, someone lifting the window) — means the pass is **not certified** and the command exits non-zero.

**What the freeze does NOT freeze, by name**: `syncAuthzCatalog` (a free function that never sees the manager — a sync during the window changes what the catalog grants), `manager.driver()` (the documented way out of *all* the manager's barriers), and your own scope-tree tables (your SQL never passes through this package). While the window is open the relay cannot drain either, so the queued-tree window *grows* with the freeze — the report counts it.

**What it DOES freeze since 2.4.0-alpha.2 (lot L-1): the relations engine too.** `RelationsManager.relate`/`unrelate`/`purgeObject`/`purgeSubject` pass **the same barrier** (the same row, the same function, the same retryable 503 `E_AUTHZ_FROZEN`) before validating anything; `check`/`listObjects`/`listSubjects`/`membersOf` keep answering. Until L-1 nothing in `relations/` looked at the freeze: during a cutover role writes got 503 and relation writes went in. And **the barrier is read through the engine's own connection, never through a caller's `transaction`** — that reading, introduced in 2.3 "so a pool of 1 would not deadlock", let the caller's snapshot decide whether the engine was frozen; it is gone, and `{ transaction }` now requires a pool of at least 2 (see [the tree outbox](#the-tree-outbox-and-the-relay-lag-you-are-accepting)). Two more honest boundaries: the guarantee holds only between processes that **share the `authz_*` tables** (that is invariant 14's deployment shape; a process pointed at another database sees nothing), and it is a guarantee of **this package's manager** — a third-party driver inherits the wording but the published contract suite never checks it (`MigrationContractHarness` has no manager, no second writer and no second process).

**And `{ transaction }` neither shortens nor skips the window (2.4.0-alpha.2, lot L-6).** The authority is read through the engine's own connection, so **a snapshot taken before the freeze does not skip it** — a transaction of yours opened before the freeze gets the same retryable 503 as everyone else (pinned on the three engines, with the barrier's own deadline on a pool of 1). What changes is the *other* arm of the sentence above: a write that had passed its barrier before the freeze landed still lands, and with `{ transaction }` it lands **when your transaction commits** — the window between barrier and commit is now **as long as your transaction**, minutes if you keep it open, at your discretion. The freeze still promises "another process gets a retryable 503", never "no write enters the window", and what it does NOT freeze does not change: `syncAuthzCatalog`, `manager.driver()` and your own scope-tree tables.

### The cutover window: `authz:freeze` / `authz:unfreeze` (2.3)

The dangerous interval is not the pass: it is **[end of the last pass → the last worker reloads `config.default`]** — minutes or hours, decided by a human, during which every write still goes to the driver that is about to stop being the source of truth. Freezing only the pass would close the small window and leave the big one open. So the window belongs to the **operator**:

```bash
node ace authz:freeze --reason="cutover to openfga"   # open the window: fleet-wide 503 on writes
node ace authz:reconcile --to=openfga --from=database # the pass RECOGNISES the operator window
# if you use relations/: one pass PER PARTITION, inside the same window
node ace authz:relations:reconcile --to=openfga --from=database [--partition-type=<t> --partition-uuid=<id>]
# VERIFY HERE, before switching config.default: openfga is not active yet, so this is a plain verifier
node ace authz:reconcile --to=openfga --from=database --dry-run
node ace authz:relations:reconcile --to=openfga --from=database --dry-run [--partition-type=<t> --partition-uuid=<id>]
# … only when both come out clean: switch config.default (and relations.default, if you set it), redeploy …
node ace authz:reconcile --to=openfga --dry-run        # after the switch: the MAINTENANCE verifier, no --from
node ace authz:unfreeze                                # close the window
```

**Retiring the old store: deleting it is not enough (measured on OpenFGA v1.19.0, memory engine).** A store removed
with `DELETE /stores/{id}` (204) **keeps serving** in that process: `ReadAuthorizationModel` of its pinned model, `Read`,
`Check` — and it **accepts `Write`**. The pinned-model gate (L11) sees it alive, so a process still configured with the
old `OPENFGA_STORE_ID` keeps deciding and writing against it without any error. After the switch, remove the old store
id from **every** process's configuration (and restart them) before you delete it; do not take the `204` (nor
`scripts/openfga_prune_stores.mjs`) as proof that nothing can use it any more. With a persistent datastore
(PostgreSQL/MySQL) this has not been measured.

**Verify before the switch, never with `--from` after it (2.4.0-alpha.10).** Once `config.default` is `openfga`,
`--to=openfga --from=database` is the stale direction by definition — even inside the same live operator window,
where nobody has written since the migration — so its `--dry-run` comes out as drift (exit 1) and the real pass is
500 `E_AUTHZ_STALE_SOURCE_REFUSED`. There is deliberately **no exception for a live window**: a check that is only
green in one narrow moment teaches operators to reach for `--allow-stale-source`, which is the one flag that must stay
rare. So the runbook verifies while the destination is not active yet, and after the switch the roles verifier is the
maintenance pass (`--to=openfga --dry-run`, no `--from`: it reads the store itself). Relations have no maintenance
pass: their verification is the pre-switch `--dry-run`.

**Relations move with `config.default` (2.4.0-alpha.10).** The relations service resolves its driver as **`relations.default ?? config.default`**: if you did not set `relations.default`, switching `config.default` switches `relations/` too — and a store with zero relation tuples denies every `check` (fail-closed, total), while `authz:reconcile --to=openfga --dry-run` comes out clean (it does not govern relation tuples). So the relations pass belongs to the cutover window, **one partition per pass** (`authz:relations:reconcile` is per partition; a multi-tenant migration is a loop you write), before the switch. If you set `relations.default`, it is that key — not `config.default` — that decides which relations driver serves, and the stale-direction guard of `authz:relations:reconcile` uses the same resolution: once `relations.default ?? config.default` is the destination, no other source is accepted (500 `E_AUTHZ_STALE_SOURCE_REFUSED`, with or without `--from`, unless `--allow-stale-source`; `--dry-run` flags it). There is no maintenance pass for relations: after the cutover the active relations driver *is* the source of truth.

`authz:reconcile` treats a live **operator** freeze as its own context: it runs inside it, does not take a second freeze, does not renew it and does not lift it when the pass ends — and its report's `frozen.fence` names the window it ran in (with `lapsed: true` if the window did not survive the whole pass). A live freeze of *another* pass is 423 instead: two migrations never interleave. **The operator window does not expire by default** — a cutover has no known duration in advance (window length and outage tolerance are independent magnitudes, the same argument that killed a fixed TTL), and a window that expires mid-cutover silently hands back exactly the fail-open this mechanism exists to close. The declared price: forget `authz:unfreeze` and the fleet cannot write until someone runs it — a *loud* incident (every 503 names the reason and the command that lifts it), not an invisible loss. `--lease-ms` is the opposite opt-in: the window lifts itself after that many milliseconds with nobody renewing it (the command has exited), and *its* declared price is that a cutover slower than the lease resumes the writers silently, mid-cutover. `authz:unfreeze` lifts an operator window; it refuses to lift a live pass's freeze unless you pass `--fence=<n>` (the explicit human decision for a process that died without a lease — and a stale fence lifts nothing).

**An expired operator window is evidence, not free space (2.4.0-alpha.10).** A `reconcile` (roles or relations) — or any `freeze()` — that finds the operator window **expired** no longer takes a freeze of its own over it: until 2.4.0-alpha.9 it certified itself with its own 15 s window and, on release, cleared the row, erasing the only trace that writers had resumed mid-cutover. It is now 503 `E_AUTHZ_OPERATOR_WINDOW_EXPIRED` naming when the window expired; acknowledge it with `authz:unfreeze` and reopen it with `authz:freeze`. (An expired freeze of a *pass* is still taken over — that is the lease after a `SIGKILL`.) And both reconcile commands now always say **which window** the pass ran in: inside the operator window (fence N), or a window of its own because no operator window was live — until alpha.9 those two outputs were identical.

**`authz:unfreeze` on a window that already EXPIRED is an error, not a no-op (2.4.0-alpha.10).** A window opened with `--lease-ms` that expired before `authz:unfreeze` used to look exactly like "there was no window" and the command said success — the last step of the cutover hid that the writers had resumed halfway, i.e. writes the new engine may not have seen. The row tells them apart (lifting clears the reason; an expired window keeps it, with its expiry in the past), so `authz:unfreeze` now prints an error naming when the window expired (ISO) and for how long the fleet has been writing, **exits non-zero**, and clears the row — a second `authz:unfreeze` is a plain success, and "there never was a window / already lifted" is still success. `manager.lastFreezeStatus()` is the reader that also returns the expired row (`expired: true`); `freezeStatus()` still returns only a live freeze. Don't call the cutover done: repeat the migration inside a window without expiry. And a pass that runs inside an operator window with an expiry now says so: `report.frozen.untilMs` is the window's expiry and `frozen.leaseMs` what it had left when the pass adopted it (`null` only for a window that does not expire).

**`--prune` refuses to run blind.** If it would delete facts while the source has not contributed a single **usable** one, it stops with 500 `E_AUTHZ_MASS_RECONCILE_REFUSED` before writing anything: that is the signature of a wrong connection, of the wrong source, or of a resolver that no longer resolves any of the source's scopes. Until 2.3 the guard looked at the *raw* count — incremented before each skip — so a source whose facts were **all discarded** (every one expired, or on scopes your tree no longer knows) disarmed it and `--prune` emptied the destination with a green report; now a fact only counts if it actually backs something the pass would keep, and the error says how many were read and discarded. `--allow-mass-delete` is the human decision; `--dry-run` never throws, it flags it. A source that is merely **stale** but still partially usable is not this guard's job: what protects you there is the rule above (the facts are read from whoever owns them) and, when `--from` points at a stale source towards the active driver, `E_AUTHZ_STALE_SOURCE_REFUSED`.

**The declared cap on the dump (2.3).** Reconciling means comparing against the **whole** state of the destination — without that snapshot there is no way to know what is left over, and "what is left over" is half the job. The *source* is read in batches with a cursor; the destination snapshot is not, and it is held in memory. That is declared rather than hidden: above `--max-tuples` (default 1 000 000) the pass refuses with 500 `E_AUTHZ_RECONCILE_TOO_LARGE` **before writing anything**, naming the cap. There is no partitioned migration in this version, and "resumable" means *idempotent and repeatable* — a pass that was interrupted is resumed by running it again; the second one converges and what was already written comes back as `unchanged` — not "a cursor persisted between runs".

**Migration is not lossless, and the losses are declared.** Run `runMigrationContract` (below) against your own pair: it seeds a fixed fixture, asks **448 identical questions** on both ends and fails if a single answer changes without a declared loss, if the pass counted a skip you did not declare, or if a seeded fact is simply **missing from the destination** with nothing declaring it — that last one is the census, and it does not depend on any of the 448 moving.

**The way out of a store written by the previous version.** After 2.3 "a store written by the previous version is not read by this one": the old importer wrote assignments without the two (c2) edges and denies as `deny_binding` objects, a type the current model does not declare. `authz:reconcile --to=openfga --from=database --prune` rebuilds the store from `authz_*` — the source of truth *of that migration*, named out loud — and clears the leftovers — a tuple whose type the model no longer declares can still be read and deleted (measured against the server). That store grants again after one pass. **Run it while `database` is still `config.default`** (2.4.0-alpha.10): if `openfga` is already the active driver, that command is the stale direction and the manager refuses it with 500 `E_AUTHZ_STALE_SOURCE_REFUSED` before reading or freezing anything — `authz_*` stopped seeing the store's writes at the cutover, so rebuilding from them would resurrect every revocation since (and `--prune` would delete what was granted since). If the store is already live *and* you know for a fact that nothing has been written to it since — a store written by the previous version that nobody served from — `--allow-stale-source` is the explicit human decision; run the same command with `--dry-run` first, which flags `report.staleSource` instead of throwing.

### Operational notes for this driver

Choosing it adds a **second runtime dependency to every authorization check**: the catalog is read from your database (once per process, then from the memo — see [Performance](#performance)) and the facts from FGA. If FGA is unreachable, the engine throws `AuthorizationBackendError` (503) — it does not quietly return `false`. Denying silently during an outage strips every user of their permissions with nothing to indicate why. Note that the `database` driver is **not** exempt from the 503 outcome: its catalog and facts live in SQL, and a database that does not answer is classified the same way (*"la base local caída es un 503, no un error crudo"*). What `database` avoids is the *second* dependency.

Three more properties worth knowing before putting it in front of production traffic — none of them can grant access that wasn't granted, all fail towards *denied*:

- **Binding ids carry the catalog uuid, never the slug (2.2).** A role assignment is `role_binding:<scopeKey>|<roleUuid>#assignee` with `<scopeKey>` = `app` or `<type>|<uuid>` (a deny is not an object of its own: it is the relation `scope:<scopeKey>#denied_<P>`); ids are parsed **from the right** (last component = the uuid, everything before it = the scope key) and contain no `~` escape. With today's grammar a `scopeKey` always has one or two parts, so parsing from the right and counting parts agree on every id the grammar admits: the rule is a *structural* decision with no test that can tell the two apart, and it only gets one when a `scopeKey` grows more parts (3b, `facts` mode). Do not "simplify" it to counting on the strength of a green suite. A store written by 1.x/2.0–2.1 (slug in the id) is **not read** by 2.2: those tuples grant nothing, are no membership, are counted in `diagnostics.unparseableBindings`, and `authz:reconcile --to=openfga` reports them as leftovers (`--prune` clears them). There is no *import* command (*"un store con ids 1.x (slug en el id) no es leído por 2.2"*).
- **Enumerations read tuples, not computed relations.** `listSubjects`, `listRoles`, `listRoleScopes` and `listScopes` use the paginated `Read` API (100 tuples per page, until the continuation token is empty; a token that repeats or more than 10,000 pages is 500 `E_AUTHZ_INTERNAL`, never a hang) and filter expiry client-side. That is what makes them complete regardless of the server's `ListObjects`/`ListUsers` caps. The price: `Read` returns *written* tuples only. With the model this package generates (`assignee` and `denied_<P>` are direct relations) that is exactly the same set; if you extend the model with relations derived over `role_binding`, this driver's enumerations will not see them. Membership reads also consult the catalog (`authz_roles` for that level) — from the in-process memo, so no query in steady state — and `listRoleScopes` asks your resolver once per scope it returns, like `listScopes` (a `forRequest()` view memoises those calls).
- **Changing an expiry is not atomic.** FGA rejects deleting and writing the same tuple key in one transaction, so *replacing* an expiry is a delete followed by a write. Between the two, `authorize()` answers `false`, and a crash in that window loses the assignment; re-running the grant restores it. The driver reads the current tuple first, so this only happens when the expiry actually changes — a first grant is a plain write, an identical re-grant touches nothing (*"quitar la expiración es explícito (expiresAt: null); omitirla no la toca ni escribe nada"*). A grant *without* `expiresAt` whose read fails is a 503 whose message carries the recipe: preserving a live expiry requires knowing it; pass `{ expiresAt: null }` if you mean "permanent". A first write that collides with a concurrent one (FGA's "tuple already exists") re-reads and re-grants on top of it; any other write failure is propagated classified, with the SDK error as `cause` — never treated as a race (*"un write que falla con 400 no es una carrera"*).
- **Expiry follows the app server's clock.** The `not_expired` condition is evaluated against a `current_time` your process sends with each check, and enumerations filter with the same clock. Keep NTP running.
- **There is no distributed transaction with your database, and the catalog that *decides* is the projection in the store.** A `grant` validates the role against the local catalog and then writes the tuple. Delete that role from `authz_*` **by hand** afterwards and the two drivers stop agreeing, which is worth knowing before you write a migration script: membership (`hasRole`, `listRoles`, `listRoleScopes`, `listSubjects`) filters through the local catalog in both drivers and fails closed from the first instant, but `authorize` is decided by the store, where the permission→role mapping is the projection (`role:<uuid>#permits_<P>`) that your delete did not touch — **so it keeps granting**. Whoever writes `authz_*` by hand owes it a `driver.projectCatalogRole(uuid)`, exactly as it already owes a catalog-version bump; `syncAuthzCatalog` and the delegation API do it for you (*"en `facts` el catálogo que decide es la proyección del store, no la fila que acabas de borrar"*). `purgeScope`, meanwhile, cannot reach bindings of roles that are no longer in the catalog (it reads by exact object, built from the catalog; `Read` cannot enumerate by id prefix without a `user`). Reconciling both is the job of `authz:reconcile --to=openfga`.

#### The pinned model is the one your config generates (2.5.0-alpha.4)

Both `openfga` drivers decide with a model **the server** holds, so the package checks it before trusting it. Once per
process (one `ReadAuthorizationModel` of the pinned `modelId`, shared with every `withClock`/`withChainResolver`/
`forRequest()` view), each driver compares the model it serves with the one its config generates, **per type**, in
**rules, type restrictions (with their condition) and conditions**:

- **What is compared.** The roles driver: your holder types, `role`, `role_binding`, `scope` and the `conditions`
  map, modulo the catalog (the permissions are the ones the served model declares: `role#permits_*`). The relations
  driver: your holder types, `group` and the object types of its config — **per operation**: the types the operation
  touches, plus `group` (a different `group#member` changes who is a member, so what every type grants) and the
  `conditions` (they decide whether any tuple is alive), plus your holder types always (the subject of every operation).
  It is **per type**: a drift in `note` does not block a `check` on `document`. An operation on `group` (a membership)
  compares **every** type of the config — its renewal reads the `denied_*` of the types with deny —, which is wider than
  "the operation's types + `group`": a drift in any type blocks the memberships too (fail-closed, on purpose). A
  relation **more** than the config declares is drift too. A type without `deny` may be served in the deny form only as
  a **whole type** (the form a config with `deny` generates, D8); a mixed type is drift.
- **Different ⇒ 500 `E_AUTHZ_CONFIG`** naming the differences by path (`document#denied_viewer (restricciones de
  tipo)`, `conditions.inverted (condición de más)`, `scope#can_docs_read (regla)`…) with **zero** calls that evaluate or
  write. Recipe: republish from the current config (`openfga:provision --store-id`) and pin the new `modelId` on the
  whole fleet before deploying. The comparison is memoised once it was *made* (with or without differences); a failure
  to **read** the model, whatever its class, is not memoised — the next operation reads again. Since R3 is not in yet, a
  `modelId` that does not exist in the store is a 503 for now.
- **For the scope relay that 500 is a deployment failure, not the entry's**: `authz:scopes:relay` records it
  (`last_error`, `transient: true`) **without consuming an attempt and without parking** the `moved`/`detached` — parking
  them on a half-done deployment kept the old parent (and the old tenant's access) until a manual `requeue`. The next
  pass after the fleet runs the right model applies them.
- **No operation is exempt.** Reads, purges and writes pass the whole gate (the order a purge deletes in was proven on
  the config's semantics). `enumerateRelations(Many)` and `enumerateFacts` — the *source* of a migration, which has to
  be able to rescue a drifted store — pass only the `conditions` part.
- **Declared limit.** A type of the store that is neither yours nor the package's (another application's type in a
  shared store) is not compared: no rule the package generates references it (a case proves it structurally).

**A tuple's expiry comes from one function, and "unreadable" is never "permanent".** `fgaTupleExpiry` (in `src/expiry.ts`)
reads `not_expired` only when its context is **exactly** `{ valid_until }` with a timestamp of the grammar the server
accepts (fraction of any length truncated to nanoseconds, `.` or `,`, offsets up to `±24:mm`; measured on v1.19.0) and
rounds **up** to the next millisecond — the server compares in nanoseconds and the package sends `current_time` in
milliseconds, so this is the exact same answer (a `valid_until` of `…30.999999999Z` is alive at `.999`; `new Date()`
used to truncate it and call it expired). Anything else is `foreign` (another condition, or a `not_expired` whose tuple
freezes its own `current_time`) or `unparseable` (no `valid_until`: the server answers 400 when it evaluates it), and
each reader decides, always failing closed:

| Who reads it | `foreign` / `unparseable` |
|---|---|
| `relate` (relations) / `grant` (roles) on that key (also when the key appears in a race) | 409 `E_AUTHZ_RENEWAL_UNSAFE`, nothing written, recipe: inspect it and delete it by hand |
| the renewal check of a group membership that carries a deny | the deny (or the nesting edge) counts as **alive**: more 409s, never fewer |
| the denies that decide `listScopes` (roles) | counted **alive**: fewer scopes listed, never more |
| counts: `countRoleAssignments` (roles; `stillGranting` of `authz:catalog:prune-orphans`) | **counted**: "I don't know" never degrades to "does not grant" |
| `listSubjects` / `listDenies` (relations), `listSubjects` / `listRoles` / `listDenies` / … (roles) | not listed; warned and counted (`diagnostics.unparseableTuples` / `unparseableBindings`) |
| `enumerateRelations` / `enumerateFacts` (source of a migration) | `enumerateRelations`: emitted marked (`RelationTuple.invalidCondition`, with `expiresAt` = the epoch). **Check the mark before the date**: a reader that ignores it reads the tuple **expired**, which fails closed for an allow but **open** for a deny (or a `group` membership carrying one) — no `expiresAt` value is safe for both. `enumerateFacts`: an assignment is skipped with `invalid-condition` (never migrated); a **deny** is emitted marked (`ReconcileFact.invalidCondition`): `--to=database` migrates it as a deny (fails closed) and declares it (`invalid-condition`, drift) |
| the source of `authz:relations:reconcile` | not migrated (`skipped.invalid`, drift); a **deny** like that refuses the pass (500 `E_AUTHZ_DENY_MIGRATION_REFUSED`); a **`group` membership** like that in a partition with **any** deny refuses that partition (`partitionsRefused`, `invalid-condition`: zero writes in it — the server may be evaluating it alive and carrying the deny) |
| the destination of `authz:relations:reconcile` / `authz:reconcile` | present and untouchable: `extra`/`skipped` with `invalid-condition`, never deleted (not even with `--prune`), its key never rewritten from the source; drift (exit ≠ 0). A source deny whose key it blocks refuses the pass (500 `E_AUTHZ_DENY_MIGRATION_REFUSED`, both commands; `--dry-run` lists it) — except the roles **maintenance pass** (`--to=<active driver>`, source = the store itself): there the deny is reported (drift), neither written nor deleted, and the pass still rebuilds the root marker, the tree and the `roleVisibility` sweep; a `group` membership like that in a partition with any deny refuses the partition (relations) |
| purges | deleted like any other tuple |

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

### How OpenFGA failures are classified (2.5.0-alpha.4)

Until 2.5.0-alpha.4 every failure of the OpenFGA server that was not a timeout came out as 503 "the backend did not answer" — also a 401, a store that does not exist or a relation the pinned model does not declare, which answer the same way on every retry. Since R3 **one function** classifies them (`classifyFgaFailure`, owner's decisions 2026-10-17 (3) and (4)), called from the three places an OpenFGA error can come from in the two drivers (the client wrapper of each driver and the per-check error of a `batchCheck`), and it decides **by the HTTP status and the server's error code — an allowlist — or by the key of a per-check error (`input_error` / `internal_error`), never by the message** (measured: 41 shapes of SDK 0.9.6 against OpenFGA v1.19, pinned as fixtures in the suite):

| Class | What the server said | You get | The tree relay |
|---|---|---|---|
| transient | no answer, 5xx (501 included), 408, 429, `deadline_exceeded`, per-check `internal_error` | 503 `E_AUTHZ_BACKEND_UNAVAILABLE` (or `E_AUTHZ_BACKEND_TIMEOUT`, including the bare SDK error a client timeout and a refused connection share — and, **on a write**, a 504 or `deadline_exceeded`: indeterminate, see [Writes](#writes)) | does not consume an attempt |
| graph too deep | `authorization_model_resolution_too_complex` (single `Check` or per check) | 503 `E_AUTHZ_RESOLUTION_LIMIT` — at the edge a retry may succeed; past it, never | does not consume an attempt |
| deployment or data the pinned model rejects | 401/403/404; 400 `validation_error`, `authorization_model_not_found`, `latest_authorization_model_not_found`, `exceeded_entity_limit` (also per check) | 500 `E_AUTHZ_CONFIG`, "not transient", the server's error in `cause` | does **not** consume an attempt (it is the deployment, not the entry: parking a `moved` would leave the old parent in the store) |
| race with another writer | 409; 400 `write_failed_due_to_invalid_input` | handled by the driver (re-read and re-apply); if it escapes, 409 `E_AUTHZ_WRITE_CONFLICT` | does **not** consume an attempt either (owner's decision (3), "race ⇒ as before": until R3 an escaped race was a 503; contention — a concurrent `grant` writing the same `scope#binding` edge the `moved` sweep rewrites — must never park a `moved`); `authz:scopes:relay` prints it as `CARRERA en #…` |
| unknown 4xx | any other 4xx (a 422 included), or a 400 code outside the allowlist | 500 `E_AUTHZ_CONFIG` with `cause` | does not consume an attempt |

Three things the classes cannot see, said out loud. A relation missing from the pinned model, a tuple without its `valid_until` and a request without `current_time` are the same `validation_error`, and a store that does not exist answers the same `authorization_model_not_found` as a model that does not exist when the model id is pinned: each pair lands in the same class, so the message of the `500` names them all. Telling "already exists" from "does not exist" inside a race needs the message; the two functions that read it (`isDuplicateWrite`, `isTreeWriteRace`) are the only exemption, signed by the owner, and they sit on top of the race class. And the SQL twin (`guardSql`: a missing table or column is still a 503) is out of this release. A failure to **read the pinned model** is never memoised, whatever its class: a rotated token recovers on the next call without restarting the process.

**What "does not consume an attempt" costs you in monitoring.** A deployment failure, an unknown 4xx or a race that never clears is transient **forever**: the entry never parks, so `dead()` stays empty and `deadCount` stays 0 while a `moved` is not applied (the old parent still grants in the store). An alert that watches only `dead()` does not see it. Watch the relay's **exit code** (≠ 0 on every pass with a failure, with a line per branch: `fallo de DESPLIEGUE #…`, `CARRERA en #…`, `límite de RESOLUCIÓN en #…`, `falló #…`) and the **age of the queue** (`authz:scopes:relay --max-age=<ms>` exits ≠ 0 past it; `report.queue.pendingAgeMs`). And an entry whose failure repeats keeps contaminating its scope key on every pass, so a later `detached` of that key waits behind it too (invariant 11 is about parked entries, not failed ones) — fix the cause and the next pass applies both, in order.

### Limits

Every bound the package enforces or measured, in one place, each with the constant or option that carries it — the suite imports those constants and asserts that **these numbers are the ones in the code** (a constant that changes without this table turns red). What lies past each bound is written next to it, because "past the limit" is never a silent `false` here.

| Limit | Constant / option | Value | Where | Past it |
|---|---|---|---|---|
| Scope-chain depth the `facts` model resolves reliably (`parent` hops from a scope to `app`) | `FACTS_MAX_RESOLVE_DEPTH` | 22 | `openfga` only, `database` has no ceiling | `authorize` is 503 `E_AUTHZ_RESOLUTION_LIMIT` (2.5.0-alpha.4; until then the generic `E_AUTHZ_BACKEND_UNAVAILABLE`), never `false`, for the whole subtree below (measured: 23 fails between 4 % and 26 % of the time, 24 always). Raise `OPENFGA_RESOLVE_NODE_LIMIT` on the server if your tree is deeper — and declare `scopes.maxDepth`, below |
| Depth gate on writes (opt-in, 2.4.0-alpha.5) | `scopes.maxDepth` | none by default; set it to 22 for `facts` | the manager, `scopes.attached`/`scopes.moved`, every driver | 422 `E_AUTHZ_SCOPE_DEPTH_LIMIT` **before** writing or enqueueing; see below |
| Authorization-model size | `FACTS_MODEL_MAX_BYTES` | 262,144 | `openfga`, `syncAuthzCatalog` | 500 `E_AUTHZ_MODEL_TOO_LARGE` before writing, warning past 80 % (`FACTS_MODEL_WARN_RATIO`); how many permissions those bytes are is [not a property of the model](#the-model-ceiling-is-bytes-not-permissions) |
| Checks per `batchCheck` | `FGA_MAX_BATCH_CHECK` | 50 | `openfga`, `authorizeMany` | the driver splits into batches of 50 (the SDK's cap), nothing to do |
| `ListObjects` effective cut of the server (relations `listObjects`) | `listObjectsDeadlineMs` (`DEFAULT_LIST_OBJECTS_DEADLINE_MS`) | 3,000 ms | the `openfga` relations driver (2.5.0 · B4) | a call that takes ≥ `LIST_OBJECTS_DEADLINE_RATIO` (0.9) × this value returns `truncated: true` — the server cuts at its deadline with a 200 and no signal; set it to the **lowest** of your server's `--listObjects-deadline` (when not 0), `--request-timeout` (3 s by default) and, over HTTP, `--http-upstream-timeout` (5 s by default) — declare that lowest one: with `--listObjects-deadline=0` the request timeout still cuts with a mute 200 (measured on OpenFGA v1.19.0), there is no "no deadline", `Infinity` is 500, both at 0 is not supported (the gateway's cut is not measured for `ListObjects`), and the driver's `timeoutMs` (5 s by default) cannot be lower than `listObjectsDeadlineMs` (500 at construction: the signal has to fire before the client cuts; `Number.MAX_SAFE_INTEGER` is caught by that). **The price of the conservative signal**: with the default, every `ListObjects` that takes 2,700 ms or more comes back `truncated` even when complete; a consumer that treats `truncated` as a 503 pays that p99 as user-facing 503s — raise the server's deadline (and this value) or handle `truncated` as a partial list, not as an outage |
| Objects per `checkMany` / `decideMany` | `RELATIONS_CHECK_MANY_MAX` | 50 | the `RelationsManager` and both relations drivers (2.5.0) | 422 `E_AUTHZ_CHECK_MANY_BATCH` with zero backend calls — split the list yourself; `[]` is 422 too. One batch is one `batchCheck` in `openfga` and one query in `database` |
| `membersOf` candidates judged one by one when the object has a deny (`database`) | `RELATIONS_MEMBERS_DENY_CHECK_MAX` | 1,000 | the `database` relations driver (2.5.0) | 500 `E_AUTHZ_MEMBERS_DENY_LIMIT` before the first `check`, never a partial list; the whole loop also runs under one total deadline (`timeoutMs`), 503 `E_AUTHZ_BACKEND_TIMEOUT` past it. Without a deny row on the object there is no extra query and no bound |
| Tuples a relations purge deletes in one atomic `Write` | `RELATIONS_PURGE_WRITE_MAX` | 100 | the `openfga` relations driver (2.5.0) | the server's `--max-tuples-per-write` default (101 is a 400, measured on v1.19.0). Up to it a purge is one `Write`; past it, allows → the subject's group memberships in their own `Write` → denies. With more than 100 memberships a cut purge can grant until repeated (declared row, [Relations](#relations-rebac-24), «Deny on relations»). **Requires `--max-tuples-per-write` ≥ 100 on the server**: below it, the `Write` that passes the server's cap — not necessarily the first — is 500 `E_AUTHZ_CONFIG` naming the requirement (never a 503 that looks transient: repeated, the purge would fail the same way forever), marked as a partial write (`indeterminate: true`) if an earlier `Write` already deleted |
| `openfga:provision --store-id` sweep for live denies of a dropped relation | — (no cap: streamed page by page) | — | `openfga:provision --store-id` (2.5.0-alpha.3), only when some model of the store declared a `denied_*` the new one does not | it reads the WHOLE store, page by page, keeping only a count and three examples (memory does not grow with the store, time does: O(store) per run); a server that does not advance (a repeated continuation token) or a page without `tuples` is exit 1 (`provision NEGADO:`) without writing the model — "zero live denies" is never assumed from a sweep that did not finish. Until closure 2 of sublot D2 the sweep stopped at 1,000,000 tuples, and since the store's model history keeps a retired opt-in forever, a bigger store could never be provisioned again |
| Models of the store `openfga:provision --store-id` reads to judge the store's state (every published model is one) | `PROVISION_MODEL_HISTORY_MAX` | 10,000 | `openfga:provision --store-id` (2.5.0-alpha.3) | exit 1 (`provision NEGADO:`) without writing the model — never judged on a truncated history |
| Relation name in a type with `deny` | `DENIABLE_RELATION_NAME_MAX` | 43 | `defineRelationsConfig` and the `openfga` model generator (2.5.0) | 422 `E_AUTHZ_RELATION_CONFIG` at definition: `denied_<rel>` has to fit FGA's 50. A type without `deny` keeps 50 |
| `Read` page size (enumerations, `enumerateFacts`, `enumerateRelations`) | — | 100 | `openfga` | the server's hard cap: `pageSize: 1000` is a 400; the driver pages until the continuation token is empty — a page with zero tuples **and** a token is not the end; a token that repeats, more than 10,000 pages, or a response without `tuples` is 503 `E_AUTHZ_BACKEND_UNAVAILABLE`, never a shorter enumeration |
| `enumerateRelations(partition)` / `enumerateRelationsMany(partitions)` cost | — | O(tuples in the store) **per sweep** — one sweep per `enumerateRelations` call, **one sweep for K partitions** with `enumerateRelationsMany` / `runRelationsReconcile(…, { partitions })` (2.4.0-alpha.6) | `openfga`, the *source* of `authz:relations:reconcile` | there is no prefix `Read` in OpenFGA (a prefix object answers 200 with **zero** tuples, measured: never "optimise" it that way — the suite spies the filter of every `read`, it is always `{}`); measured 15,000 tuples ⇒ 151 pages ≈ 0.5 s per sweep whatever the partition size; 3 partitions in a 5,000-tuple store: **150 reads / 502–558 ms** as three sweeps → **50 reads / 170–209 ms** as one ([the table](#the-source-sweep-measured)). Run it from a job or a cron, **never from a tenant request** |
| Hops the `only` probe walks back to inherit a block's origin | `RELAY_ORIGIN_MAX_HOPS` | 100 | the manager, `relayScopeChanges({ only })` | the origin is taken as a real block and the entry stays `deferred` (the purge waits for a full pass); one `earlierPending` query per hop |
| Interval between `acquire()` retries under `waitForLeaseMs` | `RELAY_LEASE_POLL_MS` | 25 ms | the manager, `relayScopeChanges({ waitForLeaseMs })` and `requeueScopeChanges({ apply, waitForLeaseMs })` | the budget is spent in polls of this size; past it the pass reports `busy` (default `waitForLeaseMs` is 0: one attempt) |
| Scopes a `pending()` pass reads per round trip | `DEFAULT_RELAY_BATCH` | 100 | `authz:scopes:relay` (`--batch-size`) | the pass keeps paging |
| Changes one relay pass applies | `DEFAULT_RELAY_LIMIT` | 10,000 | `authz:scopes:relay` (`--limit`) | the rest stays pending (`remaining: true`); run again |
| Failed attempts before an outbox entry is parked | `maxAttempts` | 5 | `sqlScopeOutbox` | the entry leaves `pending()`, shows in `dead()` on every pass and the command exits ≠ 0; a 503 of the backend does not count; `authz:scopes:requeue --id` brings it back |
| Longest wait for the relay lease (`waitForLeaseMs`) | `RELAY_WAIT_LEASE_MAX_MS` | 60,000 | `relayScopeChanges` / `requeueScopeChanges({ apply })` | 500 `E_AUTHZ_CONFIG` above it — a wait without a cap hangs the tenant's request; shorten the pass (`only`, `limit`) instead. The wait is counted in polls of `RELAY_LEASE_POLL_MS`, so it ends even under a frozen injected clock |
| Parked outbox entries the relay can census per pass | `PARKED_CENSUS_MAX` | 50,000 | the manager, every relay pass (read in full, whatever `--limit`) | 500 `E_AUTHZ_CONFIG` before anything is applied — the relay of **every** tenant stops, loudly, never a blind plug. Measured cost of the census under the lease: 1,000 parked ⇒ 16 ms, 10,000 ⇒ 69 ms, 49,000 ⇒ 199 ms per pass. The way out is below (*When the parked set grows*) |
| Answer size of `authorizedScopes` / `expandExcludedSubtrees` | `maxScopes` | 1,000 | the manager | 422 `E_AUTHZ_TOO_MANY_SCOPES`, never a partial list (per call it can only be lowered) |
| Nodes one `descendantsOf` call may return | `maxDescendants` | 10,000 | the manager (`maxNodes` handed to your resolver) | 422 `E_AUTHZ_TOO_MANY_SCOPES`; both bounds are capped at `MAX_SCOPE_BOUND` (10,000,000) |
| Local roles a `prune-orphans` pass may read | `maxLocalRoles` | 10,000 | `pruneOrphanRoles` | 500 `E_AUTHZ_TOO_MANY_LOCAL_ROLES`, never a partial list |
| Ancestors `hierarchicalScopeResolver` walks | `maxDepth` (resolver option) | 64 in the README example | your `resolveChain` | 500 `E_AUTHZ_SCOPE_TOO_DEEP`, never a truncated chain |

**`scopes.maxDepth` — the depth gate (2.4.0-alpha.5).** Declare it in `config.scopes` and `scopes.attached`/`scopes.moved` refuse, with **422 `E_AUTHZ_SCOPE_DEPTH_LIMIT`**, any child that would end up more than `maxDepth` `parent` hops from `app` — the parent's chain plus one — **before writing or enqueueing** (zero driver calls, zero outbox rows) and at zero extra I/O: the parent's chain is already resolved for the cycle check. Without the option there is no gate: a tree of any depth stays legal, and the `database` driver pays nothing. It lives in the config and not in `capabilities()` because a capability is a boolean by doctrine (`capabilities()` normalises with `=== true`); and it is the same knob `authz:reconcile` uses to report chains above the ceiling as drift (`drift.tooDeep`, exit ≠ 0 — a scope legal in `database` and a 503 in `openfga` belongs in CI, not in the first tenant that reaches it; without the option the verifier uses `FACTS_MAX_RESOLVE_DEPTH`). Set it to `22` for the `facts` model: then every question stays within the measured ceiling whichever ancestor carries the binding. **How to size it: `maxDepth` counts `parent` hops from the child to `app`, so a tree of N levels below `app` needs `scopes.maxDepth = N`** — not N + 1: the parent's chain includes `app`, but a child at exactly `maxDepth` hops *enters* (`chain.length > maxDepth` is the refusal). Pinned by an executable case (`scope_depth.spec.ts`): a tree of exactly three levels (organization → unit → sub-unit), `maxDepth: 2` refuses the third level with 422, `maxDepth: 3` lets it in. The 422's `message` is for the tenant (depth, `scopes.maxDepth`, nothing written or enqueued); the reason the ceiling exists goes to `error.details` (2.4.0-alpha.8). **The gate is **partial**, and sold as such**: it looks at the *destination* of the child, not at the height of the subtree a `moved` drags along — a subtree of height *h* moved under a parent at depth *d* leaves its leaves at *d + h + 1*, and the gate does not see them; measuring that would need `descendantsOf` on the write path, which is forbidden. The reconcile report is what catches those afterwards. Why a gate at all: past the ceiling the model answers 503 for the whole subtree (a DoS within reach of whoever can nest sub-scopes), and the cost of each relayed `attached` grows with the depth of its neighbour (measured ×5.8 from depth 1 to 34) on the queue every tenant shares.

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

### Upgrading to 2.5.0: non-canonical partition spellings

There is **no `2.4.0` stable**: the 2.4 line ends at `2.4.0-alpha.10` and the next stable is **2.5.0** (the
plan 2.5: this lot is `2.5.0-alpha.1`; the tenancy work — deny, `decideMany`, `listObjectsForSubject` — follows
in the same line). Three things change for an installation on `2.4.0-alpha.x`:

1. **A relation partition whose uuid is 32 hex without its dashes and is not exactly `8-4-4-4-12` is 422** (D4,
   above): the dashless spelling *and* every other placement of the dashes that PostgreSQL folds into the same
   `uuid`. Those spellings were accepted until now, so any tuple written that way is unreachable from the API
   after the upgrade — not granting, not purgeable, not enumerable. **It is also a grant the canonical purge never
   saw**: a share written through the id of the URL (no dashes) survived `purgeSubject(user, <canonical tenant>)`
   on 2.4, and an `unrelate` or a shorter `expiresAt` written by the canonical spelling never reached it. That is
   why the recipe has **three branches and the default one writes nothing**: the default is the detector, the
   list and two counts (rows *with* a canonical twin / rows *without* one) — read-only, run it as many times as
   you like. The two branches that write are explicit: **`--delete`** (fail-closed: the rows go away — a grant
   the canonical purge never saw does not survive the upgrade) and **`--rekey`** (the rows are re-keyed to the
   canonical spelling; a non-canonical row whose canonical twin exists is dropped and the twin is left exactly
   as it is — an expiry is **never extended**, `NULL` does not win — the rest are re-keyed with their own expiry).
   **Which branch is yours depends on which population you are** — the detector lists the same rows for both,
   so look at your ids, not at the count:
   - *Population A — your tenant ids are uuids, written somewhere without their dashes (the id of a URL, a
     `uuid` column read as hex, …).* The detector lists **some** of your partitions. These rows are aliases of
     the canonical partition, invisible to its purge: **`--delete`** is your branch. `--rekey` cannot tell
     "written dashless and never revoked" from "revoked by the canonical spelling and surviving through the
     alias", so it is a decision taken after reading the list, not a default (the audit's scenario — purge by
     the canonical spelling, then the recipe — is pinned as "still revoked" after `--delete` and "granted again,
     as reviewed" after `--rekey`).
   - *Population B — your tenant ids were never uuids: 32 hex characters by construction
     (`randomBytes(16).toString('hex')`, md5, …), with or without dashes at non-uuid positions.* The detector lists
     **every one of your partitions** (that is the signature) and nothing is an alias of anything: **`--rekey`** is
     your branch — it keeps every relation and moves it under the `8-4-4-4-12` spelling of the same 32 hex
     (pinned: a population-B store keeps all its tuples and answers `check` by the dashed id) — and from 2.5.0 on
     you pass that spelling to the API (`dashedUuid(hex)` is exported). **Running `--delete` on this population
     empties `authz_relations`**, which is why neither branch runs without its explicit statements.
   All three branches are executed verbatim by the suite on PostgreSQL, MySQL and SQLite (`upgrade_recipe.spec`),
   twice (idempotent), the default one pinned as zero writes. The detector uses the same rule as `assertPartition`:
   what the API rejects, the detector lists (pinned). One statement per line, run each line whole. A partition id
   that is not a uuid once the dashes are removed (31 or 33 hex, 32 characters that are not all hex) is untouched:
   it is a legal id.
2. **F-05 is demanded of the driver called directly** (D13): `runRelationsDriverContract` now calls the harness
   driver without the manager and expects the same 422s — on `membersOf` too when the driver declares
   `membersOfNative`, and `checkMany` called directly must refuse 51 objects and `[]`. A third-party harness
   that seeded undeclared types straight through its driver breaks on purpose; the in-memory double already
   behaved this way since lot 0. **Since `2.5.0-alpha.2` the same is demanded for B3** (closure 1 of lot B): a
   userset subject that is not `group#member` must be 422 `E_AUTHZ_RELATION_USERSET_UNSUPPORTED` through the
   manager *and* through the driver called directly, on `relate`/`unrelate`/`check`/`checkMany`/`listObjects`/
   `purgeSubject` — through the manager with zero driver calls, spied — (29 core cases per harness). A third-party
   driver that stored such a row inert, or answered 503, passed the contract until then.
3. **`checkMany` and `relationTupleKey` are additive** (`relationTupleKey` demands `kind`: there is no default);
   `contractRelationsConfig()` declares a second object type (`workspace`, same relations as `document`) so the
   mixed-types case is observable — a harness that asserted on the published model of that config sees one type
   more. `createTestClock` lives at **`@jantstack/adonis-authz/testing/clock`** (no Japa or Lucid import):
   import it from there in a config file production loads.

**Lot B (`2.5.0-alpha.2`) — the breaking changes decided for before the first 2.x stable**, each with how to adapt:

4. **A cycle in `includes` is 422 at `defineRelationsConfig`** (B1): `editor ⊇ viewer ⊇ editor` (direct, two or more
   relations) used to be accepted — `database` served it, `openfga:provision` could not publish it. The message names
   the cycle (`document#editor → document#viewer → document#editor`). *Adapt*: remove the edge that closes it; a diamond
   (`viewer ⊇ editor ⊇ owner` and `viewer ⊇ owner`) is fine.
5. **An unknown key anywhere in the relations spec is 422 `E_AUTHZ_RELATION_CONFIG_UNKNOWN_KEY`** (B2), naming the path
   (`objectTypes[1].deny`, `objectTypes[0].relations[1].denny`, `database.foo`) and the allowed keys of that level — until
   now every unknown key was dropped in silence. **The roles `defineConfig` rejects unknown keys too** (500
   `E_AUTHZ_CONFIG`, root and the `openfga`/`scopes`/`relations`/`hooks` blocks — and since `2.5.0-alpha.2` the roles
   check also runs in the `AuthorizationManager` constructor and in the relations service, so a config exported without
   `defineConfig` is judged too; a block that is not an object, `scopes: true`, is 500 as well). *Adapt*: fix the typo or
   remove the key; if you were parking a key for a future version, it does not belong in the spec yet. **The persisted
   copy is revalidated too**: `saveRelationsConfig` before 2.5.0 stored the spec *as given*, unknown keys included, so a
   row written then that carries one (or an `includes` cycle, B1) makes `readRelationsConfig()` 422 and
   `authz:relations:reconcile` stops with its own line — *"la config persistida en authz_relations_config NO valida en
   2.5: <motivo>"* — distinct from the unreadable-table line (point 8). *Adapt*: re-save it once from a process with
   the corrected static config, `saveRelationsConfig(<corrected spec>)` (the spec, not the frozen config: passing the
   output of `defineRelationsConfig` is 422 with that hint), and run the pass again.
6. **A userset subject that is not `group#member` is 422 `E_AUTHZ_RELATION_USERSET_UNSUPPORTED`** (B3) on `relate`/
   `unrelate`/`check`/`checkMany`/`listObjects`/`purgeSubject`, in both drivers and the manager, before any backend
   call. Until now `database` stored such a row inert and `openfga` answered a misclassified 503. *Adapt*: relate the
   holder or the group, never the relation of another object. **Rows written before 2.5.0 with such a subject are a
   residue the package lists but never deletes**: `listSubjects` still returns them (output is not validated),
   `purgeSubject(userset)` no longer reaches them (422), and `purgeObject(<the tuple's own object>)` removes them only
   together with every legitimate share of that object (`purgeObject` on the userset's object does not touch them).
   `authz:relations:reconcile` classifies them **in the plan, before any driver call**, on both sides and with or
   without the persisted config: one enumerated from the *source* counts in `skipped.usersetUnsupported` and is listed
   in `details` (`side: 'origen'`, `reason: 'userset-unsupported'`); one found in the *destination* counts in `extra`
   and is listed (`side: 'destino'`, `pruned: false` under `--prune`) — **`--prune` never deletes it** (no platform
   `DELETE` on a row the API does not admit), the pass writes and prunes everything else, `--dry-run` and the real pass
   give the same numbers (declared limit: if the persisted config and the destination driver's config differ —
   `saveRelationsConfig` is manual — the dry-run classifies with the persisted one and the real pass with the driver's,
   so the numbers can differ until you re-save the config), and the pass exits ≠ 0 with the residue, its side and the recipe on the line until you run
   it. The **form** of the userset is judged before the pair's F-05, with or without the persisted config: a residue
   whose userset names a type or a relation the destination does not declare is still this residue (with the recipe),
   never `skipped.undeclared` with the false remedy "declare it in the destination". **One rule for every destination
   row the API does not admit**: a tuple whose identity is outside the grammar (`reason: 'invalid-identity'` — an
   `object_uuid` written by hand in upper case, say) and — since closure 3 of this release — a row whose **relation or
   object type the destination no longer declares** (`reason: 'undeclared'`: a relation retired from the config while
   its rows were still there; `enumerateRelations` filters by type, not by relation, and `unrelate` refuses the row by
   F-05) have exactly the same semantics — `extra`, listed with `pruned: false` under `--prune`, never asked of the
   driver when the persisted config is at hand (both package drivers would refuse it in `unrelate`: R-16 for the
   grammar, F-05 for `undeclared`), exit ≠ 0 with or without `--prune`, the remedy on the line ("delete it by hand
   (SQL/SDK)"; for `undeclared`, "or declare the relation again in the destination and re-save its persisted config"),
   and never "repeat with `--prune`" (that advice is printed only for what `--prune` really deletes, and only when
   `--prune` was not passed; the report carries `prune`). Without the persisted config (`reconcileRelations` called
   with no `toConfig`) the plan cannot anticipate F-05 — `--dry-run` counts that row in `deleted`, the declared limit
   of L-0 for `written` — and the real pass **catches only the 422s of the relations family** from `unrelate`
   (`E_AUTHZ_RELATION_TYPE_UNKNOWN`, `E_AUTHZ_RELATION_UNKNOWN`, `E_AUTHZ_RELATION_USERSET_UNSUPPORTED`,
   `E_AUTHZ_INVALID_IDENTITY`), classifies each by code, goes on with the other rows and lists it the same way; any
   other error still propagates (that is the driver contradicting the plan for a reason the report cannot count).
   Until `2.5.0-alpha.2` such a tuple was asked of the driver, a destination residue under `--prune` aborted the pass
   mid-way (after writing), a source residue was counted as `skipped.undeclared` with a false remedy, and — until
   closure 3 — a retired relation's row made `--prune` throw `E_AUTHZ_RELATION_UNKNOWN` mid-pass, after writing, on
   every run (🟠 N9 of the final audit: `--prune` was unusable for that partition). The recipe — one detector and one `DELETE`, the same
   statements on PostgreSQL, MySQL and SQLite, executed verbatim by the suite on the three (`upgrade_recipe.spec`) and
   printed on the reconcile line:

```sql
-- B3 · userset residue (PostgreSQL, MySQL and SQLite: the same two statements)
-- 1 · detector: every row whose subject is a userset other than group#member (zero rows = nothing to do)
SELECT uuid, partition_key, object_type, object_uuid, relation, subject_type, subject_uuid, subject_relation FROM authz_relations WHERE subject_relation <> '' AND NOT (subject_type = 'group' AND subject_relation = 'member');
-- 2 · delete them (holders have subject_relation = ''; a pre-L-4b NULL holder is excluded too: NULL <> '' is not true)
DELETE FROM authz_relations WHERE subject_relation <> '' AND NOT (subject_type = 'group' AND subject_relation = 'member');
```

   (on `openfga` such tuples never existed: the server refused them).
7. **`listObjects` of `openfga` signals `truncated: true` on the server's deadline too** (B4): a call that takes ≥ 90 % of
   `listObjectsDeadlineMs` (default 3,000 ms, OpenFGA's default `--listObjects-deadline`). *Adapt*: set `listObjectsDeadlineMs`
   to your server's **effective** cut in `OpenFgaRelationsDriver`; code that already handled `truncated` needs nothing else; code
   that assumed the list complete on a slow server was wrong before and is told now. The value is the server's
   **effective** cut — whichever is lower of the three: `--listObjects-deadline` (when it is not 0), `--request-timeout`
   (3 s by default) and, over HTTP, the gateway's `--http-upstream-timeout` (5 s by default); declare that lowest one. A server that runs with **`--listObjects-deadline=0`** does **not** run without a deadline:
   its `--request-timeout` still cuts `ListObjects` with a mute 200 (measured on OpenFGA v1.19.0 by the audit of this
   release, 40,000 tuples: `--request-timeout=30ms` ⇒ `200`, 0 objects of 40,000, three runs; control with 30 s ⇒
   40,000 of 40,000; in the source, `list_objects.go` sets its own timeout only when the deadline is not 0 and the
   request-timeout interceptor returns the partial result without a signal) — declare *that* value. The earlier advice
   of this release (`Infinity` on the driver for a deadline of 0) is withdrawn: it was measured against a
   whole list that returned in 5 ms, which cannot tell "no deadline" from "deadline = request timeout", and it made
   the driver pass the mute partial list as complete — strictly worse than the default; `Infinity` is now 500
   `E_AUTHZ_CONFIG` ("the server always cuts at one of the two; declare the lower one"), like `NaN`, `0` and
   negatives (`0` on the driver would mean "everything truncated"). Both at 0 is not supported: the HTTP gateway's
   `--http-upstream-timeout` (5 s) is not measured for `ListObjects`, and the package promises no "no deadline" it
   has not measured. And the driver's `timeoutMs` (5 s by default) cannot be lower than `listObjectsDeadlineMs`
   (closure 3, ⚪ N10): a deadline the client cuts before the 0.9 threshold is a signal that can never fire — and if
   the server cuts earlier, a mute list passes as complete — so `listObjectsDeadlineMs > timeoutMs` is 500
   `E_AUTHZ_CONFIG` at construction ("the signal has to be able to fire before the client cuts"), which also closes
   `Number.MAX_SAFE_INTEGER`, "no deadline" under another name. *Adapt*: a driver built with a `timeoutMs` below
   3,000 ms must now declare a `listObjectsDeadlineMs` at or below it. And since `2.5.0-alpha.2` a `ListObjects` that answers 200 **without `objects`** is
   503 `E_AUTHZ_BACKEND_UNAVAILABLE`, like a `Read` without `tuples` — the same for the three `Read`s of the roles
   driver (`readAllTuples`, the reconcile dump, `enumerateFacts`), where such a response used to read as an empty
   enumeration and `purgeScope` "proved" zero on it.
8. **`authz:relations:reconcile` stops (exit 1) when `authz_relations_config` cannot be read** (B5) — before building,
   freezing or writing anything; "no config persisted" (`null`) still runs and says so. A persisted config that **does
   not validate in 2.5** (a pre-2.5 row with a key 2.4 dropped in silence, an `includes` cycle, corrupt JSON) is a
   fourth branch with its own line, *"NO valida en 2.5: <motivo> … saveRelationsConfig(<spec corregida>)"* — never
   sold as "the read failed" nor as "no config" (point 5). *Adapt*: nothing, unless a cron relied on the silent
   continuation: give the command a readable database; for the fourth branch, re-save the corrected spec once.
9. **`sqlScopeOutbox()` requires `{ transaction }` by default** (B6): `scopes.attached/moved/detached` (and
   `outbox.enqueue`) without the open transaction of the outbox's connection are **500 `E_AUTHZ_CONFIG` before the
   `INSERT`**. *Adapt*: pass `{ transaction: trx }` from `db.transaction()` as the recipe above shows; if you really
   enqueue outside any unit of work (a seeder, a platform job), say so: `sqlScopeOutbox({ requireTransaction: false })`.
   `{ transaction }` through the manager needs a pool ≥ 2 (the freeze barrier reads through another connection; with
   one connection it is 503 `E_AUTHZ_BACKEND_TIMEOUT` at `freezeTimeoutMs`), so with **pool max 1 — knex's default for
   every SQLite connection, file or `:memory:`** — keep the opt-out; the 500 says so too. A third-party outbox
   judged by `runScopeOutboxContract` declares the new optional capability `requiresTransaction` (absent = `false`) and,
   with `true`, hands the judge `transactions.begin()`.
10. **`runRelationsReconcile` is imported from `@jantstack/adonis-authz/relations/reconcile`** (B7); the command module
    `./commands/authz_relations_reconcile` no longer exports it (nor `RunRelationsReconcileOptions`). *Adapt*: change the
    import path; the signature is the same.
11. **The roles reconcile verifier reads the pinned model** (B8): with `modelId` set on `OpenFgaAuthorizationDriver`, the
    pass checks the catalog against *that* model, not the latest one in the store. *Adapt*: nothing; a pass that used to
    report `permission-not-in-model` for a permission only present in a newer model now projects it under the pinned one
    — and one that used to die with a 503 mid-pass (permission in the latest model but not in the pinned one) now counts
    it. The runbook rule stands: publish and roll out the model **before** the window, never inside it.

**Default (read-only): detect, list, count.** Nothing is written. Statement 3 says, per branch, what `--rekey`
would do: a row *with* a canonical twin is dropped by it, a row *without* one is re-keyed.

```sql
-- D4 · PostgreSQL
-- 1 · detector: non-canonical partitions and how many tuples each one holds (zero rows = nothing to do)
SELECT partition_key, COUNT(*) AS tuples FROM authz_relations WHERE replace(split_part(partition_key, '|', 2), '-', '') ~ '^[0-9a-f]{32}$' AND split_part(partition_key, '|', 2) !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' GROUP BY partition_key;
-- 2 · the list: every tuple that is about to be deleted — review it (an offboarded user in it is the reason this is the default)
SELECT uuid, partition_key, object_type, object_uuid, relation, subject_type, subject_uuid, subject_relation, subject_partition, expires_at FROM authz_relations WHERE replace(split_part(partition_key, '|', 2), '-', '') ~ '^[0-9a-f]{32}$' AND split_part(partition_key, '|', 2) !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' ORDER BY partition_key, object_type, object_uuid;
-- 3 · the counts: rows WITH a canonical twin (--rekey drops them) and rows WITHOUT one (--rekey re-keys them); --delete removes both
SELECT CASE WHEN EXISTS (SELECT 1 FROM authz_relations c WHERE c.partition_key = split_part(d.partition_key, '|', 1) || '|' || substr(replace(split_part(d.partition_key, '|', 2), '-', ''), 1, 8) || '-' || substr(replace(split_part(d.partition_key, '|', 2), '-', ''), 9, 4) || '-' || substr(replace(split_part(d.partition_key, '|', 2), '-', ''), 13, 4) || '-' || substr(replace(split_part(d.partition_key, '|', 2), '-', ''), 17, 4) || '-' || substr(replace(split_part(d.partition_key, '|', 2), '-', ''), 21, 12) AND c.object_type = d.object_type AND c.object_uuid = d.object_uuid AND c.relation = d.relation AND c.subject_type = d.subject_type AND c.subject_uuid = d.subject_uuid AND c.subject_relation = d.subject_relation) THEN 'with-canonical-twin' ELSE 'without-twin' END AS twin, COUNT(*) AS tuples FROM authz_relations d WHERE replace(split_part(d.partition_key, '|', 2), '-', '') ~ '^[0-9a-f]{32}$' AND split_part(d.partition_key, '|', 2) !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' GROUP BY 1;
```

```sql
-- D4 · MySQL
-- 1 · detector: non-canonical partitions and how many tuples each one holds (zero rows = nothing to do)
SELECT partition_key, COUNT(*) AS tuples FROM authz_relations WHERE partition_key LIKE '%|%' AND REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', '') REGEXP '^[0-9a-f]{32}$' AND SUBSTRING_INDEX(partition_key, '|', -1) NOT REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' GROUP BY partition_key;
-- 2 · the list: every tuple that is about to be deleted — review it (an offboarded user in it is the reason this is the default)
SELECT uuid, partition_key, object_type, object_uuid, relation, subject_type, subject_uuid, subject_relation, subject_partition, expires_at FROM authz_relations WHERE partition_key LIKE '%|%' AND REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', '') REGEXP '^[0-9a-f]{32}$' AND SUBSTRING_INDEX(partition_key, '|', -1) NOT REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' ORDER BY partition_key, object_type, object_uuid;
-- 3 · the counts: rows WITH a canonical twin (--rekey drops them) and rows WITHOUT one (--rekey re-keys them); --delete removes both
SELECT CASE WHEN EXISTS (SELECT 1 FROM authz_relations c WHERE c.partition_key = CONCAT(SUBSTRING_INDEX(d.partition_key, '|', 1), '|', SUBSTRING(REPLACE(SUBSTRING_INDEX(d.partition_key, '|', -1), '-', ''), 1, 8), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(d.partition_key, '|', -1), '-', ''), 9, 4), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(d.partition_key, '|', -1), '-', ''), 13, 4), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(d.partition_key, '|', -1), '-', ''), 17, 4), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(d.partition_key, '|', -1), '-', ''), 21, 12)) AND c.object_type = d.object_type AND c.object_uuid = d.object_uuid AND c.relation = d.relation AND c.subject_type = d.subject_type AND c.subject_uuid = d.subject_uuid AND c.subject_relation = d.subject_relation) THEN 'with-canonical-twin' ELSE 'without-twin' END AS twin, COUNT(*) AS tuples FROM authz_relations d WHERE d.partition_key LIKE '%|%' AND REPLACE(SUBSTRING_INDEX(d.partition_key, '|', -1), '-', '') REGEXP '^[0-9a-f]{32}$' AND SUBSTRING_INDEX(d.partition_key, '|', -1) NOT REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' GROUP BY 1;
```

```sql
-- D4 · SQLite
-- 1 · detector: non-canonical partitions and how many tuples each one holds (zero rows = nothing to do)
SELECT partition_key, COUNT(*) AS tuples FROM authz_relations WHERE instr(partition_key, '|') > 0 AND replace(substr(partition_key, instr(partition_key, '|') + 1), '-', '') GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' AND substr(partition_key, instr(partition_key, '|') + 1) NOT GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' GROUP BY partition_key;
-- 2 · the list: every tuple that is about to be deleted — review it (an offboarded user in it is the reason this is the default)
SELECT uuid, partition_key, object_type, object_uuid, relation, subject_type, subject_uuid, subject_relation, subject_partition, expires_at FROM authz_relations WHERE instr(partition_key, '|') > 0 AND replace(substr(partition_key, instr(partition_key, '|') + 1), '-', '') GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' AND substr(partition_key, instr(partition_key, '|') + 1) NOT GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' ORDER BY partition_key, object_type, object_uuid;
-- 3 · the counts: rows WITH a canonical twin (--rekey drops them) and rows WITHOUT one (--rekey re-keys them); --delete removes both
SELECT CASE WHEN EXISTS (SELECT 1 FROM authz_relations c WHERE c.partition_key = substr(d.partition_key, 1, instr(d.partition_key, '|')) || substr(replace(substr(d.partition_key, instr(d.partition_key, '|') + 1), '-', ''), 1, 8) || '-' || substr(replace(substr(d.partition_key, instr(d.partition_key, '|') + 1), '-', ''), 9, 4) || '-' || substr(replace(substr(d.partition_key, instr(d.partition_key, '|') + 1), '-', ''), 13, 4) || '-' || substr(replace(substr(d.partition_key, instr(d.partition_key, '|') + 1), '-', ''), 17, 4) || '-' || substr(replace(substr(d.partition_key, instr(d.partition_key, '|') + 1), '-', ''), 21, 12) AND c.object_type = d.object_type AND c.object_uuid = d.object_uuid AND c.relation = d.relation AND c.subject_type = d.subject_type AND c.subject_uuid = d.subject_uuid AND c.subject_relation = d.subject_relation) THEN 'with-canonical-twin' ELSE 'without-twin' END AS twin, COUNT(*) AS tuples FROM authz_relations d WHERE instr(d.partition_key, '|') > 0 AND replace(substr(d.partition_key, instr(d.partition_key, '|') + 1), '-', '') GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' AND substr(d.partition_key, instr(d.partition_key, '|') + 1) NOT GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' GROUP BY 1;
```

**`--delete` (population A, after reviewing the list): fail-closed, one statement per engine, run *instead of*
`--rekey`.**

```sql
-- D4 · PostgreSQL · --delete
-- 1 · fail-closed: delete every non-canonical row (grants invisible to the canonical purge do not survive the upgrade)
DELETE FROM authz_relations WHERE replace(split_part(partition_key, '|', 2), '-', '') ~ '^[0-9a-f]{32}$' AND split_part(partition_key, '|', 2) !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
```

```sql
-- D4 · MySQL · --delete
-- 1 · fail-closed: delete every non-canonical row (grants invisible to the canonical purge do not survive the upgrade)
DELETE FROM authz_relations WHERE partition_key LIKE '%|%' AND REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', '') REGEXP '^[0-9a-f]{32}$' AND SUBSTRING_INDEX(partition_key, '|', -1) NOT REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
```

```sql
-- D4 · SQLite · --delete
-- 1 · fail-closed: delete every non-canonical row (grants invisible to the canonical purge do not survive the upgrade)
DELETE FROM authz_relations WHERE instr(partition_key, '|') > 0 AND replace(substr(partition_key, instr(partition_key, '|') + 1), '-', '') GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' AND substr(partition_key, instr(partition_key, '|') + 1) NOT GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]';
```

**`--rekey` (population B, or population A as a reviewed decision): run these two statements *instead of*
`--delete`.** Two non-canonical spellings of the *same*
tenant without a canonical twin collide on the unique index of `authz_relations` and the `UPDATE` fails loudly
(atomically: nothing is re-keyed, for any tenant, until the statement succeeds). Delete one of the two by hand
first — **keep the row with the nearest expiry (a `NULL` expiry is the farthest) and delete the other one**, so the
re-keyed tuple never outlives what either row already granted.

```sql
-- D4 · PostgreSQL · --rekey
-- 1 · a non-canonical row whose canonical twin exists goes away; the twin is NOT touched (its expiry is never extended)
DELETE FROM authz_relations d WHERE replace(split_part(d.partition_key, '|', 2), '-', '') ~ '^[0-9a-f]{32}$' AND split_part(d.partition_key, '|', 2) !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND EXISTS (SELECT 1 FROM authz_relations c WHERE c.partition_key = split_part(d.partition_key, '|', 1) || '|' || substr(replace(split_part(d.partition_key, '|', 2), '-', ''), 1, 8) || '-' || substr(replace(split_part(d.partition_key, '|', 2), '-', ''), 9, 4) || '-' || substr(replace(split_part(d.partition_key, '|', 2), '-', ''), 13, 4) || '-' || substr(replace(split_part(d.partition_key, '|', 2), '-', ''), 17, 4) || '-' || substr(replace(split_part(d.partition_key, '|', 2), '-', ''), 21, 12) AND c.object_type = d.object_type AND c.object_uuid = d.object_uuid AND c.relation = d.relation AND c.subject_type = d.subject_type AND c.subject_uuid = d.subject_uuid AND c.subject_relation = d.subject_relation);
-- 2 · the rest are re-keyed to the canonical spelling (and the subject_partition of their usersets with them)
UPDATE authz_relations SET subject_partition = CASE WHEN subject_partition = partition_key THEN split_part(partition_key, '|', 1) || '|' || substr(replace(split_part(partition_key, '|', 2), '-', ''), 1, 8) || '-' || substr(replace(split_part(partition_key, '|', 2), '-', ''), 9, 4) || '-' || substr(replace(split_part(partition_key, '|', 2), '-', ''), 13, 4) || '-' || substr(replace(split_part(partition_key, '|', 2), '-', ''), 17, 4) || '-' || substr(replace(split_part(partition_key, '|', 2), '-', ''), 21, 12) ELSE subject_partition END, partition_key = split_part(partition_key, '|', 1) || '|' || substr(replace(split_part(partition_key, '|', 2), '-', ''), 1, 8) || '-' || substr(replace(split_part(partition_key, '|', 2), '-', ''), 9, 4) || '-' || substr(replace(split_part(partition_key, '|', 2), '-', ''), 13, 4) || '-' || substr(replace(split_part(partition_key, '|', 2), '-', ''), 17, 4) || '-' || substr(replace(split_part(partition_key, '|', 2), '-', ''), 21, 12) WHERE replace(split_part(partition_key, '|', 2), '-', '') ~ '^[0-9a-f]{32}$' AND split_part(partition_key, '|', 2) !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
```

```sql
-- D4 · MySQL · --rekey
-- 1 · a non-canonical row whose canonical twin exists goes away; the twin is NOT touched (its expiry is never extended)
DELETE d FROM authz_relations d JOIN authz_relations c ON c.partition_key = CONCAT(SUBSTRING_INDEX(d.partition_key, '|', 1), '|', SUBSTRING(REPLACE(SUBSTRING_INDEX(d.partition_key, '|', -1), '-', ''), 1, 8), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(d.partition_key, '|', -1), '-', ''), 9, 4), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(d.partition_key, '|', -1), '-', ''), 13, 4), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(d.partition_key, '|', -1), '-', ''), 17, 4), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(d.partition_key, '|', -1), '-', ''), 21, 12)) AND c.object_type = d.object_type AND c.object_uuid = d.object_uuid AND c.relation = d.relation AND c.subject_type = d.subject_type AND c.subject_uuid = d.subject_uuid AND c.subject_relation = d.subject_relation WHERE d.partition_key LIKE '%|%' AND REPLACE(SUBSTRING_INDEX(d.partition_key, '|', -1), '-', '') REGEXP '^[0-9a-f]{32}$' AND SUBSTRING_INDEX(d.partition_key, '|', -1) NOT REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
-- 2 · the rest are re-keyed to the canonical spelling (and the subject_partition of their usersets with them)
UPDATE authz_relations SET subject_partition = CASE WHEN subject_partition = partition_key THEN CONCAT(SUBSTRING_INDEX(partition_key, '|', 1), '|', SUBSTRING(REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', ''), 1, 8), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', ''), 9, 4), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', ''), 13, 4), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', ''), 17, 4), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', ''), 21, 12)) ELSE subject_partition END, partition_key = CONCAT(SUBSTRING_INDEX(partition_key, '|', 1), '|', SUBSTRING(REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', ''), 1, 8), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', ''), 9, 4), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', ''), 13, 4), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', ''), 17, 4), '-', SUBSTRING(REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', ''), 21, 12)) WHERE partition_key LIKE '%|%' AND REPLACE(SUBSTRING_INDEX(partition_key, '|', -1), '-', '') REGEXP '^[0-9a-f]{32}$' AND SUBSTRING_INDEX(partition_key, '|', -1) NOT REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
```

```sql
-- D4 · SQLite · --rekey
-- 1 · a non-canonical row whose canonical twin exists goes away; the twin is NOT touched (its expiry is never extended)
DELETE FROM authz_relations WHERE instr(authz_relations.partition_key, '|') > 0 AND replace(substr(authz_relations.partition_key, instr(authz_relations.partition_key, '|') + 1), '-', '') GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' AND substr(authz_relations.partition_key, instr(authz_relations.partition_key, '|') + 1) NOT GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' AND EXISTS (SELECT 1 FROM authz_relations c WHERE c.partition_key = substr(authz_relations.partition_key, 1, instr(authz_relations.partition_key, '|')) || substr(replace(substr(authz_relations.partition_key, instr(authz_relations.partition_key, '|') + 1), '-', ''), 1, 8) || '-' || substr(replace(substr(authz_relations.partition_key, instr(authz_relations.partition_key, '|') + 1), '-', ''), 9, 4) || '-' || substr(replace(substr(authz_relations.partition_key, instr(authz_relations.partition_key, '|') + 1), '-', ''), 13, 4) || '-' || substr(replace(substr(authz_relations.partition_key, instr(authz_relations.partition_key, '|') + 1), '-', ''), 17, 4) || '-' || substr(replace(substr(authz_relations.partition_key, instr(authz_relations.partition_key, '|') + 1), '-', ''), 21, 12) AND c.object_type = authz_relations.object_type AND c.object_uuid = authz_relations.object_uuid AND c.relation = authz_relations.relation AND c.subject_type = authz_relations.subject_type AND c.subject_uuid = authz_relations.subject_uuid AND c.subject_relation = authz_relations.subject_relation);
-- 2 · the rest are re-keyed to the canonical spelling (and the subject_partition of their usersets with them)
UPDATE authz_relations SET subject_partition = CASE WHEN subject_partition = partition_key THEN substr(partition_key, 1, instr(partition_key, '|')) || substr(replace(substr(partition_key, instr(partition_key, '|') + 1), '-', ''), 1, 8) || '-' || substr(replace(substr(partition_key, instr(partition_key, '|') + 1), '-', ''), 9, 4) || '-' || substr(replace(substr(partition_key, instr(partition_key, '|') + 1), '-', ''), 13, 4) || '-' || substr(replace(substr(partition_key, instr(partition_key, '|') + 1), '-', ''), 17, 4) || '-' || substr(replace(substr(partition_key, instr(partition_key, '|') + 1), '-', ''), 21, 12) ELSE subject_partition END, partition_key = substr(partition_key, 1, instr(partition_key, '|')) || substr(replace(substr(partition_key, instr(partition_key, '|') + 1), '-', ''), 1, 8) || '-' || substr(replace(substr(partition_key, instr(partition_key, '|') + 1), '-', ''), 9, 4) || '-' || substr(replace(substr(partition_key, instr(partition_key, '|') + 1), '-', ''), 13, 4) || '-' || substr(replace(substr(partition_key, instr(partition_key, '|') + 1), '-', ''), 17, 4) || '-' || substr(replace(substr(partition_key, instr(partition_key, '|') + 1), '-', ''), 21, 12) WHERE instr(partition_key, '|') > 0 AND replace(substr(partition_key, instr(partition_key, '|') + 1), '-', '') GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]' AND substr(partition_key, instr(partition_key, '|') + 1) NOT GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]';
```

**On `openfga` the store is the tuples themselves**, and the package cannot address a non-canonical partition
any more (the driver refuses to compose its id), so there is no `--partition-uuid` to reconcile *from* it. The
non-canonical tuples left in the store grant nothing from the API on 2.5.0. The same three branches, with the SDK:
the default is to **list** them (`client.read({})` and keep the objects whose partition segment is 32 hex but not
`8-4-4-4-12`); `--delete` is `client.write({ deletes })` of that list; the `--rekey` equivalent is fail-closed
while there are no denies (write the canonical tuple first, then delete the old one): if `database` holds the same
facts, run the SQL `--rekey` there and **`authz:relations:reconcile --to=openfga --from=database
--partition-type=<type> --partition-uuid=<canonical>`** writes the canonical tuples, then delete the old ones with
the SDK — which is what the suite executes against a real server (`relations_openfga.spec`, "D4 recipe"). If the
store is the only copy, read the old tuples with the SDK, write them under the canonical object id and delete the
old ones in that order. **Roles have nothing to migrate but do have the same rule**: with the consumer's row alive
the resolver chain canonicalises the scope (invariant 17); where there is no chain — `scopes.detached` after the
row is gone, `revoke`/`removeDeny` on a scope the tree no longer knows — the purge covers the caller's spelling
*and* the canonical one it can be an alias of, under `pgFusedSpellings`: **exactly the spellings PostgreSQL's
`uuid` folds** (hyphens only after groups of four hex digits — dashless, `8-4-4-16`, `8-8-8-8`, `12-4-4-12`…;
measured against PostgreSQL 18), which is deliberately *narrower* than the partition rule `isNonCanonicalUuid`
(`-<32hex>`, `<32hex>-`, `a0e-…`, `--` are legal ids PostgreSQL rejects: a 422 too many is harmless, a purge too
many is not). And a spelling the resolver still knows as a **live** scope is never purged by that fan-out: with
text scope ids a tenant could otherwise create and delete `<32 hex of another tenant's unit>` and have
`detached`/`removeDeny` reach the live unit (cierre-3 of lot A). If the resolver fails while checking, the write is
a 503 — never "purge just in case".

### Upgrading from 2.4.0-alpha.1: `authz_relations.expires_at`

An installation that migrated 2.4.0-alpha.1 runs **both** recipes below, **in this order** — `expires_at` first (additive, R-15), then `subject_relation` (lot L-4b) — in the **same deploy** as the package upgrade: until the second one is applied, every holder `relate` is refused by the old partition trigger (measured, below). Both are executed verbatim by the suite on the three engines.

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

### Upgrading from 2.4.0-alpha.2 (before L-4b): `authz_relations.subject_relation`

Lot L-4b makes `subject_relation` **`NOT NULL DEFAULT ''`** (`''` = holder, a value = userset) so the unique
index `authz_rel_tuple_uq` guards holder tuples too — with `NULL` it only guarded usersets, because every
engine treats two `NULL`s as distinct, and two concurrent `relate`s of the same holder committed two identical
rows (see [writing relations inside your transaction](#relations-rebac-24)). The `database` driver now writes
`''` and **tolerates an old `NULL` row on read** (it is a holder: `check`/`list*`/`membersOf` count it, `relate`
of the same holder finds it and is a no-op, `unrelate`/`purgeSubject` delete it). **But the recipe belongs to the
same deploy as the package upgrade, not "later"**: until step 4 the *old* partition trigger (`IS NOT NULL`)
fires on every holder the new driver inserts (`''` with `subject_partition` NULL), so **every holder `relate`
is refused** — 503 `E_AUTHZ_BACKEND_UNAVAILABLE` carrying the trigger's message, fail-closed, the driver's
internal transaction undone (measured on the three engines). Reads and deletes keep working; the census counts
the old duplicates until you run it. The recipe is **idempotent** (the suite runs it twice). Four steps, **in
this order**: **re-create the partition trigger first** — its "is a userset" test becomes
`subject_relation <> ''`; the old `IS NOT NULL` fires on `''`, so with it in place *the backfill itself is
refused* by the `BEFORE UPDATE` trigger (measured on the three engines) —, then **de-duplicate** the holder
rows the old index let through (keeps the oldest `uuid` per tuple; without it the backfill hits the unique
index), then **backfill** `NULL` → `''`, then **alter** the column. One statement per line; the trigger bodies
carry `;` inside, so run each line **whole** (never through a runner that splits on `;`). The suite executes
each block verbatim on its engine (`upgrade_recipe.spec`).

```sql
-- L-4b · PostgreSQL
CREATE OR REPLACE FUNCTION authz_relations_partition_guard() RETURNS trigger LANGUAGE plpgsql AS $authz$ BEGIN IF NEW.subject_relation <> '' AND NEW.subject_partition IS DISTINCT FROM NEW.partition_key THEN RAISE EXCEPTION 'authz_relations: un userset no puede pertenecer a otra partición que su tupla (subject_partition=%, partition_key=%)', NEW.subject_partition, NEW.partition_key; END IF; RETURN NEW; END; $authz$;
DELETE FROM authz_relations WHERE subject_relation IS NULL AND CAST(uuid AS CHAR(36)) NOT IN (SELECT keep FROM (SELECT MIN(CAST(uuid AS CHAR(36))) AS keep FROM authz_relations WHERE subject_relation IS NULL GROUP BY partition_key, object_type, object_uuid, relation, subject_type, subject_uuid) AS k);
UPDATE authz_relations SET subject_relation = '' WHERE subject_relation IS NULL;
ALTER TABLE authz_relations ALTER COLUMN subject_relation SET DEFAULT '', ALTER COLUMN subject_relation SET NOT NULL;
```

```sql
-- L-4b · MySQL
DROP TRIGGER IF EXISTS authz_relations_partition_bi;
DROP TRIGGER IF EXISTS authz_relations_partition_bu;
CREATE TRIGGER authz_relations_partition_bi BEFORE INSERT ON authz_relations FOR EACH ROW BEGIN IF NEW.subject_relation <> '' AND NOT (NEW.subject_partition <=> NEW.partition_key) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'authz_relations: un userset no puede pertenecer a otra partición que su tupla'; END IF; END;
CREATE TRIGGER authz_relations_partition_bu BEFORE UPDATE ON authz_relations FOR EACH ROW BEGIN IF NEW.subject_relation <> '' AND NOT (NEW.subject_partition <=> NEW.partition_key) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'authz_relations: un userset no puede pertenecer a otra partición que su tupla'; END IF; END;
DELETE FROM authz_relations WHERE subject_relation IS NULL AND CAST(uuid AS CHAR(36)) NOT IN (SELECT keep FROM (SELECT MIN(CAST(uuid AS CHAR(36))) AS keep FROM authz_relations WHERE subject_relation IS NULL GROUP BY partition_key, object_type, object_uuid, relation, subject_type, subject_uuid) AS k);
UPDATE authz_relations SET subject_relation = '' WHERE subject_relation IS NULL;
ALTER TABLE authz_relations MODIFY subject_relation varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '';
```

```sql
-- L-4b · SQLite
DROP TRIGGER IF EXISTS authz_relations_partition_bi;
DROP TRIGGER IF EXISTS authz_relations_partition_bu;
CREATE TRIGGER authz_relations_partition_bi BEFORE INSERT ON authz_relations FOR EACH ROW WHEN NEW.subject_relation <> '' AND NEW.subject_partition IS NOT NEW.partition_key BEGIN SELECT RAISE(ABORT, 'authz_relations: un userset no puede pertenecer a otra partición que su tupla'); END;
CREATE TRIGGER authz_relations_partition_bu BEFORE UPDATE ON authz_relations FOR EACH ROW WHEN NEW.subject_relation <> '' AND NEW.subject_partition IS NOT NEW.partition_key BEGIN SELECT RAISE(ABORT, 'authz_relations: un userset no puede pertenecer a otra partición que su tupla'); END;
DELETE FROM authz_relations WHERE subject_relation IS NULL AND CAST(uuid AS CHAR(36)) NOT IN (SELECT keep FROM (SELECT MIN(CAST(uuid AS CHAR(36))) AS keep FROM authz_relations WHERE subject_relation IS NULL GROUP BY partition_key, object_type, object_uuid, relation, subject_type, subject_uuid) AS k);
UPDATE authz_relations SET subject_relation = '' WHERE subject_relation IS NULL;
```

**SQLite has no `ALTER COLUMN`**: after the backfill the column stays nullable there (the suite measures that
this is the *only* difference from the published schema). The driver never writes `NULL` and the unique index
already guards `'' = ''`, so the guarantee holds; if you want the constraint itself, recreate the table with the
DDL of the published migration (`stubs/migration.stub`) and copy the rows. The de-duplication keeps the oldest
row per tuple: if the two rows raced with different expiries, the survivor is the first written. The `openfga`
driver needs nothing — a tuple is unique by construction.

### Upgrading to 2.5.0-alpha.3: rolling out the deny on relations, migrating it, and why there is no rollback below 2.5

Nothing changes until a type opts in: with no `deny` in `defineRelationsConfig` the fused model is byte for byte the
one of 2.4.0-alpha.10 and there is no DDL (a deny is a row of `authz_relations` with `relation = 'denied_<rel>'`).

**Turning the deny on is two deployments, in this order: provision → pin `modelId` → deploy.** A pod still pinned to a
model without `denied_*` grants over a denied object (S11, declared row), and a pod running < 2.5.0-alpha.3 on
`database` never looks at the `denied_*` rows — so no deny may be written until the whole fleet serves the new model with
the new code:

1. Put the type in **`deny: 'read'`** and publish the model from that config: `node ace openfga:provision
   --store-id=$OPENFGA_STORE_ID` (it prints a new `OPENFGA_MODEL_ID`).
2. Pin **every** pod to that `modelId` and deploy the fleet on ≥ 2.5.0-alpha.3 with `deny: 'read'`: reads honour
   denies, `deny()` is still 422 `E_AUTHZ_RELATION_NOT_DENYABLE`. A pod with the new config and the old pin is 500 on
   first use (D-31), never a grant.
3. Verify, then a **second** deployment moves the type to **`deny: 'write'`** (same model: the two phases publish the
   same rules). Only now are denies written.

The job `cutover-runbook` runs exactly this (steps 20 and 21, against pg and sqlite-file with a real OpenFGA): phase 1 ⇒
`deny` 422 on both drivers; phase 2 ⇒ the deny lands, `authz:relations:reconcile` carries it to the store (`denies:
escritos 1`), `check` is false on both drivers; and the S11 table — a pod that was not redeployed, pinned to the old
model, grants; the same pod with the new `modelId` does not (the server subtracts); a pod with the new config and the
old pin is 500.

**`openfga:provision --store-id` refuses to mutilate the model.** Publishing from a process whose config lacks the opt-in
(a refactor, another branch of the config, an old binary) would drop `denied_*` and switch every deny of that type off,
silently. Before writing, the command judges the **state of the store**, not just its last model: it reads every model the
store has (`PROVISION_MODEL_HISTORY_MAX`) and, if any of them declared a `<type>#denied_<rel>` of a relation type that the
new one does not, it sweeps the store (all of it, streamed page by page with no tuple cap — closure 2 of sublot D2; it
costs O(store) per run, and a store with a retired opt-in pays it on every `provision --store-id`) — a live deny of those
relations is exit 1
(`provision NEGADO: …`) and nothing is written, also when a model without `denied_*` was published in between (a rollback
rehearsal with an older binary). Dropping one the **latest** model declares also needs `--allow-drop-deny` (the way to
retire an opt-in for real, said out loud); the flag **never switches off a live deny**. Right before
`writeAuthorizationModel` the sweep is repeated (`provision NEGADO: el RECUENTO …` if a deny arrived meanwhile: the fleet
is still writing denies). **The recount narrows the window, it does not close it**: a deny that lands on a page the
recount already read, or between the recount and `writeAuthorizationModel`, is not seen — **step 0 (the whole fleet on
`deny: 'read'` before counting) is what closes it**. A sweep that fails halfway is exit 1 too. (`database` honours `denied_*` rows always, also
without the opt-in: retiring it there does not switch them off either — remove them with `removeDeny`.)

**Rolling back below 2.5 with live denies is not supported (D12 · S17, declared row).** A process < 2.5.0-alpha.3 ignores
every deny: on `database` its `check` never reads `denied_*`; its `defineRelationsConfig` drops the `deny` key in
silence; its `openfga:provision` republishes a model without `but not`; its `authz:relations:reconcile` counts the denies
as undeclared relations and migrates the allows. There is no command that makes that safe. **Before any rollback, stop
the denies, count them and take them to zero — in this order:**

0. **Move the whole fleet to `deny: 'read'`** for every type with the opt-in, and deploy it, **before** counting, sweeping
   or publishing anything: every `deny()` is then 422 `E_AUTHZ_RELATION_NOT_DENYABLE` on every pod and reads still honour
   the denies. Skipping this leaves a window — counting, publishing, redeploying — in which a tenant's `deny()` lands and
   is then switched off in silence, for good.
1. Count the live denies (below).
2. Retire them: `removeDeny` (or the purges) on the active driver and `authz:relations:reconcile … --prune` on the mirror,
   until the count is 0.
3. Publish the model without the opt-in: `node ace openfga:provision --store-id=… --allow-drop-deny` (it sweeps, and
   re-counts right before writing the model — the recount narrows the window, it does not close it: step 0 does).
4. **Count again: it must still be 0.** If it is not, a pod was still in `'write'`: do not pin the new model, go back to 0.
5. Pin, redeploy, roll back.

The count, on `database` (the three engines; executed by the suite):

```sql
-- D12 · live relation denies (rollback below 2.5 requires 0)
SELECT count(*) AS n FROM authz_relations WHERE substr(relation, 1, 7) = 'denied_';
```

On `openfga`, `node ace authz:relations:reconcile --to=<other> --from=openfga --dry-run` per partition prints a
`denies:` line (`escritos + iguales` are the store's live denies). Retire them with `removeDeny` (or the purges) on the
active driver and `authz:relations:reconcile … --prune` on the mirror until the count is 0. Step 21 of the runbook executes
this procedure with its EFFECT: with the denies alive both `provision` attempts exit 1 without touching the store; an
operator who skips step 0 retires the denies to zero and a pod still in `'write'` writes one more — the count is 1 again
and `provision --allow-drop-deny` exits 1 instead of publishing; with the fleet in `'read'` the concurrent `deny` is 422 on
both drivers, the count reaches 0 and stays 0, and only then the model is published.

**A pass of 2.5 never classifies a deny as `undeclared`**: it migrates it as a deny or refuses the whole pass (above).
Never run `authz:relations:reconcile` from a process < 2.5.0-alpha.3 once there are denies in a store: it counts them as
undeclared, and its `--prune` hands them to `unrelate`.

### Upgrading to 2.5.0-alpha.4: pin `OPENFGA_MODEL_ID` everywhere (`openfga` only)

**Breaking for `openfga`**: both drivers refuse to construct without `modelId` (500 `E_AUTHZ_CONFIG` with the recipe),
with or without deny types — until alpha.3 it was required only with a deny type (and by `decideMany`). Unpinned, the
driver would check one model and the server would evaluate each request with the *latest* one of the store.

1. `node ace openfga:provision --store-id=$OPENFGA_STORE_ID` from the config you are deploying: it publishes, **re-reads
   and compares** the model, and only then prints `OPENFGA_MODEL_ID=…` (no such line ⇒ do not pin, see the error).
2. Put that id in the `.env` of **every** process (web, workers, the `ace` commands) and deploy. The published
   `config/authorization.ts` stub already passes `env.get('OPENFGA_MODEL_ID')` to both drivers and now throws a plain
   error at resolution if it is missing.
3. A pod whose config and pinned model differ answers 500 `E_AUTHZ_CONFIG` on first use naming the differences
   ([the model gate](#the-pinned-model-is-the-one-your-config-generates-250-alpha4)) — fix the pair, never the gate.

`database` is not affected.

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
