# Changelog

## [Unreleased] — 2.1.0

Phase 2 of the 2.0 roadmap: engine primitives and measured optimisation,
**additive** over the 2.0 port (a driver that implements only the 2.0 port
keeps passing the same suite). Lot 2A below is optimisation only — no answer
of the contract changes; what changes is the bill per question, pinned by
spies and by `scripts/bench_authorize.mjs`.

### Lot 2.5 — test infrastructure: injectable clock, PostgreSQL/MySQL harness, concurrency (no semantic change)

- **The clock is injectable, and read in exactly one place (J1).**
  **Problem.** `whereActive` (SQL) and `checkContext` (FGA) called
  `new Date()`: the exact instant an assignment stops granting, a renewal,
  "expires right now" — none of it was observable without sleeping (the
  contract waited 1.5 s of real time). **Decision.** `src/clock.ts`
  (`systemClock`) is the only wall-clock read in `src/` (a grep test pins
  it); both drivers take `now?` and implement `withClock(now)` on the port;
  the manager applies `clock` from the config to the driver it resolves and
  every `forRequest()` view shares it (500 `E_AUTHZ_CONFIG` if the driver has
  no `withClock`: a clock ignored in silence would lie). `injectableClock`
  is a capability pair of the suite at every level: `true` judges exact
  expiry (T−1 ms grants, T does not) and renewal without waiting; `false`
  keeps the real-time case. Expiry is strict: what expires *now* no longer
  counts, in SQL (`expires_at > now`) and in FGA (`current_time <
  valid_until`). **Not done.** No clock in `AuthzWriteEvent`, no server-side
  `NOW()`: the process clock decides in both drivers, as documented.

- **The suite runs on PostgreSQL and MySQL (J2/J5).** **Problem.** The
  README promised three engines and the suite verified one. **Decision.**
  `TEST_DB=sqlite|sqlite-file|pg|mysql` in the harness (`npm run test:pg`,
  `test:mysql`, `test:sqlite-file`); PG/MySQL runs create `authz_test_<random>`
  from an admin connection and drop it at teardown — never an existing
  database; the file-backed SQLite mode uses a pool of 2–5 so concurrency is
  connection-level. CI job `engines` (matrix `pg`/`mysql`, official service
  images) runs the suite with and without OpenFGA.

- **Three schema defects the engines revealed (J3), fixed in the published
  migration and the harness mirror.** (a) MySQL `TIMESTAMP(0)` rounded
  `expires_at` to the second and rejected dates past 2038 ⇒ `expires_at` is
  `DATETIME(3)` (`timestamptz(3)` on PG). (b) MySQL's default `*_ci`
  collation merged `abc` and `ABC` into one holder ⇒ identity columns and
  slugs carry `collate 'utf8mb4_bin'` (compiled only by MySQL). (c)
  PostgreSQL's `uuid` type rejected grammar-valid ids like `user-42` ⇒
  `holder_uuid`/`scope_uuid` are `varchar(64)`. Plus one finding not in the
  plan: MySQL aborts a recursive CTE after `cte_max_recursion_depth` (1000)
  iterations, so a cycle under a larger bound was a 503 instead of the 422
  "posible ciclo" ⇒ `sqlDescendantsOf` now supports MySQL 8 (backtick
  quoting) and sends a `SET_VAR` hint with the bound it already imposes.
  Each defect has a contract or unit case that was red on the engine that
  showed it. `whereRaw`/`LIMIT`/`timeout({ cancel: true })` needed nothing.

- **Concurrency is observed (J4).** Three contract cases at `'2.1'`: two
  concurrent grants with different expiries leave one assignment whose
  expiry is one of the two (a mutant without the race fallback turns 503);
  `purgeScope` concurrent with `grant` never leaves a half state (the only
  allowed rejection is `E_AUTHZ_PURGE_INCOMPLETE`, and a fresh purge proves
  zero); `syncAuthzCatalog` concurrent with `authorize` is monotone — once
  a question sees the permission withdrawn, no later one grants it, in this
  memo or in another. `transactions` stays `false`: `{ trx }` is 2.6.

### Lot 2A — measured optimisation (same answers)

- **The catalog is memoised in-process; facts and decisions never are (A1).**
  **Problem.** Every `authorize` read the catalog from SQL to answer a
  question whose answer only changes on sync: `findPermission` in both
  drivers, plus `rolesGranting` in `openfga` — one or two SQL round-trips per
  decision, in every process, forever. **Decision.** `CatalogCache`
  (`src/catalog_cache.ts`): three queries (permissions, roles, links), lazy,
  with the driver's deadline; both drivers read `findPermission`/`findRole`,
  `rolesGranting`, `catalogRoles`/`roleLevels` from it (*"100 authorize
  seguidos leen el catálogo UNA vez (3 consultas)"*). Invalidated by
  `syncAuthzCatalog` (version counter bumped in `finally`: a sync whose
  commit is uncertain also invalidates), by `invalidateAuthzCatalog()`
  (exported; for whoever writes `authz_*` by hand), by
  `driver.catalog.invalidate()` (that memo only) and by the optional
  `catalogTtlMs` (default none; the belt for multi-process deployments, where
  one worker's sync does not reach the others). A load that fails is 503 and
  caches nothing; concurrent loads share one read; a `CatalogCache` can be
  shared between drivers (`catalog` option). **Pinned negative case:** a
  change in `authz_*` outside the sync is **not** seen until invalidation or
  TTL (*"caso negativo: un cambio en authz_* por fuera del sync NO se ve
  hasta invalidateAuthzCatalog()"*). **Not done.** No cross-process
  invalidation (no pub/sub, no polling): restart or TTL, documented.
  `purgeScope` keeps reading the catalog from SQL: a purge must prove zero
  against the catalog as it is, not as it was.

- **One `batchCheck` per `authorize` in `openfga` (A2).** **Problem.** Two
  sequential requests per decision — the chain's denies, then the roles that
  grant — doubled the round-trip for every question. **Decision.** Both sets
  travel in one `batchCheck` (the SDK still splits at 50 and parallelises);
  the rule and its order are unchanged: any per-check `error` ⇒ 503 (D1),
  any deny `allowed` ⇒ `false`, any role `allowed` ⇒ `true`. When no role of
  the catalog grants the permission in the chain the answer is `false`
  without a request (*"si ningún rol del catálogo concede el permiso en la
  cadena ⇒ false sin tocar el backend"*). **Measured** (`scripts/bench_authorize.mjs`,
  chain of 3, 5 roles/level, 20 permissions, N=200, OpenFGA v1.19.0 local):
  granted-by-root p50 **4.33 → 2.03 ms** (p95 7.33 → 3.83), granted-by-nobody
  p50 2.36 → 0.01 ms. **Not done.** No single-`Check` mode: that is `facts`
  (3b) and, at this depth, measured slower.

- **`memoizeAncestors` + `authorization.forRequest()` (A3).** **Problem.** A
  request that asks several questions about the same scope pays the
  consumer's resolver each time, and `listRoleScopes`/`listScopes` pay it once
  per returned scope. **Decision.** `memoizeAncestors(resolver)` (exported):
  a one-instance memo over a `ScopeAncestorsResolver`, no clock, `null`
  memoised, a throw memoises nothing. `AuthorizationManager.forRequest()`
  returns an `AuthorizationView` (same API, shared driver and hooks) whose
  **reads** use the memoised resolver and whose **writes** — `grant`,
  `revoke`, `deny`, `removeDeny`, `scopes.*` — resolve fresh (auditor C3/E3:
  a stale read expires by itself; a grant on a moved chain is written
  forever). The memo is of ancestors, never of decisions: a deny between two
  `authorize` of one view changes the second answer (*"forRequest(): las
  lecturas de una vista resuelven cada scope una vez; las escrituras, en
  fresco"*). Mechanism: the optional port method
  `withAncestorsResolver?(resolver)`, implemented by both package drivers as a
  prototype-chained view of the driver; a third-party driver without it reads
  through the view unmemoised and stays correct. **Not done.** No
  `AsyncLocalStorage`, no middleware in the package: the README shows the
  `ctx.authz = authorization.forRequest()` pattern and the consumer owns it.

- **Test adjustment.** *"rol borrado del catálogo: la tupla sigue en el
  store pero authorize deniega"* deletes catalog rows by hand and now calls
  `invalidateAuthzCatalog()` afterwards — exactly what the memo's contract
  asks of a consumer that writes `authz_*` outside the sync. Its assertions
  are unchanged.

### Lot 2B — containment and enumeration primitives (contract level `'2.1'`)

All of it is composition in the manager over the 2.0 port. The port gains only
two **optional** methods (`listDenies?`, `authorizeMany?`); a third-party driver
that implements the 2.0 port keeps passing `level: '2.0'`, and with `level:
'2.1'` the judge names what it lacks (500 `E_AUTHZ_UNSUPPORTED`) instead of
skipping. The judge gets the level `'2.1'` (36 core / 49 in 2.0 / 57 in 2.1;
`core ⊂ 2.0 ⊂ 2.1`) and its 2.1 cases run through an `AuthorizationManager`
built over the harness driver and the harness tree.

- **`within` + `isWithin` + `requireWithin` (B1).** **Problem.** A call-site
  that grants "in the unit the request named" writes wherever the uuid points:
  the admin of organization A can grant in a unit of B by passing its uuid,
  and nothing in the engine can tell. **Decision.** `grant`/`deny` accept
  `within?: ScopeRef`; the manager checks `within ∈ chain(scope)` (inclusive;
  `APP_SCOPE` contains everything) against the tree **fresh** — never the
  per-request memo (auditor C3/E3) — and rejects with 422 `E_AUTHZ_NOT_WITHIN`
  before touching the driver (*"within: grant/deny dentro de la cadena
  escriben; fuera ⇒ 422 E_AUTHZ_NOT_WITHIN sin escribir"*). `isWithin(inner,
  outer)` is the same question on its own. `config.requireWithin: true` makes
  a `grant`/`deny` without `within` a 422 `E_AUTHZ_WITHIN_REQUIRED`. **Default
  `false`, named as opt-in security** (auditor E2): the manager warns once per
  config at construction (`console.warn`, silenced with
  `warnOnOptInSecurity: false`), and the negative case is pinned — with the
  default, the same grant without `within` still writes (*"requireWithin:
  true ⇒ … con el default (false) siguen escribiendo"*). **Not done.** No
  `requireWithin` per scope type, and `revoke`/`removeDeny` never require it:
  removing in the exact scope escalates nothing.

- **`descendantsOf` as a consumer port + `sqlDescendantsOf` (B2).**
  **Problem.** `authorizedScopes` needs the subtree of a scope and the package
  does not know the consumer's tree; deriving it from `resolveAncestors` would
  be an unbounded N+1. **Decision.** `scopes.descendantsOf?: (scope, { maxNodes })
  => ScopeRef[] | null` in the config (unknown ⇒ `null`; more than `maxNodes`
  ⇒ the consumer throws, or the manager throws 422 `E_AUTHZ_TOO_MANY_SCOPES`
  if it returned more; a throw or a malformed node ⇒ 503
  `E_AUTHZ_RESOLVER_FAILED`, like `resolveAncestors`). **It is never called
  from `authorize`, `hasRole`, `list*`, `authorizeMany`, `effectivePermissions`
  or writes** — an architecture spy pins zero calls; only `authorizedScopes`
  uses it. `sqlDescendantsOf({ table, uuidColumn, parentColumn, typeColumn |
  scopeType, maxNodes?, connection?, timeoutMs? })` is the opt-in helper: one
  `WITH RECURSIVE` CTE, the same SQL for PostgreSQL and SQLite, identifiers
  validated (nothing else is interpolated), every query with the deadline,
  `LIMIT maxNodes + 1` and a depth bound of `maxNodes + 1` so that a cycle in
  the table terminates **and is reported** (a two-node cycle with `depth <
  maxNodes` returned `maxNodes − 1` duplicated rows in silence — found red;
  a repeated uuid is the second barrier, 422 `E_AUTHZ_SCOPE_CYCLE`). MySQL and
  any other dialect ⇒ 500 `E_AUTHZ_UNSUPPORTED_DIALECT` on first call: there is
  no observation until Phase 2.5. Tested over the harness table `demo_scopes`.
  **Not done.** No `descendantsOf` supplied by the package from `parentOf`.

- **`authorizedScopes(subject, permission, scopeType)` (B3)** → `{ kind:
  'none' } | { kind: 'some', scopes } | { kind: 'all', excludedSubtrees }`.
  **Problem.** A listing endpoint ("which organizations can this user see?")
  needs the set without one `authorize` per row; and the naive `all` ("has it
  at the root") ignored denies — the denied organization showed up in the list
  while `authorize` said `false` (auditor E1, judge cross 5). **Decision.**
  `all` **only** with `excludedSubtrees` = every scope with a live deny of the
  permission (from `listDenies`), never `all` on its own (*"all SOLO con
  excludedSubtrees … deny en app ⇒ none"*). `some` = direct granting scopes
  (`listScopes`, already minus the ones blocked by a deny in their chain) ∪
  their descendants via `descendantsOf`, minus the denied scopes and their
  subtrees, filtered by type; pinned scope-by-scope against `authorize`
  (*"some = directos del tipo ∪ descendientes … menos subárboles denegados"*).
  More than `maxScopes` (call option, `scopes.maxScopes`, default 1000) ⇒ 422
  `E_AUTHZ_TOO_MANY_SCOPES`, **never partial**; the exact boundary answers. No
  `scopes.descendantsOf` ⇒ 500 `E_AUTHZ_NO_DESCENDANTS_RESOLVER` even for a
  subject with nothing (a `none` without a tree would be a lie). This is the
  **explicit exception to invariant 7**: the `list*` stay direct (pinned in
  the same case). **Not done.** `excludedSubtrees` is not minimised (a deny
  nested in another excluded subtree is listed too); the consumer subtracts
  every listed subtree.

- **`hierarchicalScopeResolver({ parentOf, maxDepth = 64 })` (B4).**
  **Problem.** Most consumers have a `parent_id`, not an ancestors function.
  **Decision.** Builds a `ScopeAncestorsResolver` by walking `parentOf`:
  `undefined` = unknown scope ⇒ `null` (also mid-chain: a child whose parent
  is gone is a broken tree, not a child of `app`); `null` or `app` = root ⇒
  the chain ends in `APP_SCOPE`; a visited set makes a cycle 422
  `E_AUTHZ_SCOPE_CYCLE`; `maxDepth` exceeded ⇒ 500 `E_AUTHZ_SCOPE_TOO_DEEP`
  and **no short chain** (truncating would drop the root and its denies:
  fail-open); a `parentOf` that throws propagates as is and a driver
  classifies it 503 `E_AUTHZ_RESOLVER_FAILED` (*"maxDepth … superado ⇒ lanza;
  exactamente 64 se resuelve entera"*). One `parentOf` call per level: wrap
  it with `memoizeAncestors` / use `forRequest()`.

- **`listDenies?` (optional port method) + `effectivePermissions` (B5).**
  **Problem.** `catalog/` (Phase 3) needs "what can this holder do here" as a
  set, and there was no way to enumerate denies. **Decision.**
  `listDenies(subject, scope?) → DenyRef[]` (`{ permission, scope }`): direct,
  live, exact scope (invariant 7), catalog-filtered, unknown scope ⇒ `[]`;
  without `scope`, all of the holder's direct denies with their scope (scopes
  the tree no longer knows are not listed, D8). Both package drivers implement
  it (`database`: one SQL read + memo; `openfga`: paginated `Read` of
  `deny_binding`, never `ListObjects`). `effectivePermissions(subject, scope)`
  = union of what the live roles of the whole chain grant (`listRoles` per
  level + catalog memo, `CatalogView.rolePermissions`) minus what is denied at
  any level of the chain (`listDenies` per level); pinned per permission
  against `authorize`, order of writes irrelevant, unknown scope ⇒ `[]`. A
  driver without `listDenies` ⇒ 500 `E_AUTHZ_UNSUPPORTED` naming the method
  — never `[]`, which would read as "no denies" (fail-open). **Deviation from
  the plan:** `listDenies` returns `DenyRef[]` instead of `string[]` because
  `authorizedScopes` needs the deny *scopes* of a permission and one optional
  method serves both primitives.

- **`authorizeMany(subject, permission, scopes[])` → `boolean[]` (B6).**
  **Problem.** N decisions in a request cost N round-trips. **Decision.**
  Optional `authorizeMany?` on the port; the manager delegates to it or
  composes `Promise.all` of `authorize` over a per-call memoised view (one
  tree call per distinct scope). `openfga` implements it with **one**
  `batchCheck` for the checks of every chain, attributed per position inside
  the id-correlated batch (L0.14); any per-check `error` ⇒ 503 for the whole
  call (D1). Same answer as N `authorize` (duplicates by position, unknown ⇒
  false); empty ⇒ `[]` with zero backend and tree calls; a position that
  cannot be answered rejects the whole call, never a partial array (*"authorizeMany:
  idéntico a N authorize por posición …"*; spies: openfga 1 `batchCheck` for
  20 positions, `database` 2 queries per position minus the ones a deny cuts
  short).

- **`actor` + `requireActor` (B7).** **Problem.** Audit needs "who ordered
  this" and the package refuses `AsyncLocalStorage`. **Decision.** A common
  `WriteOptions { actor?: SubjectRef }` (`GrantOptions extends ScopedWriteOptions
  extends WriteOptions`; `deny` takes `DenyOptions`; `revoke`, `removeDeny` and
  `scopes.attached/moved/detached` gain a trailing `options?: WriteOptions`).
  `actor` is validated as an identity (422 `E_AUTHZ_INVALID_IDENTITY`) and
  travels in `AuthzWriteEvent.actor` — absent when not given, never invented.
  `config.requireActor: true` ⇒ a write without `actor` is 422
  `E_AUTHZ_ACTOR_REQUIRED` before the driver and before `onWrite` (*"requireActor:
  una escritura sin actor es 422 … sin llamar al driver ni al hook"*). Reads
  never require it. The engine does not evaluate `actor` (who may grant what
  is the consumer's policy, invariant 8). Opt-in, same warning as
  `requireWithin`.

- **Hygiene found on the way.** The role key of the catalog memo and the memo
  key of `memoizeAncestors` used a literal U+001F separator inside template
  strings; both are now the explicit escape `\u001f` (`roleKey()` in
  `catalog_cache.ts`). No behaviour change; a copy of the invisible
  character had silently broken `rolePermissions` during this lot.

### Lot 2E — final closing (auditor and tester findings on 2D)

- **`within` checks the origin of a move, not only its destination (H1, auditor 1).** **Problem.**
  `scopes.moved(child, newParent, { within })` and `scopes.attached` only checked `within` against the chain of
  the *new parent*: the admin of organisation A could annex `unit:B1` by calling `scopes.moved(unitB1, orgA,
  { within: orgA })` with the `within` of her own session — reproduced: `authorize(mallory, 'docs:read', unitB1)`
  went from `false` to `true` after the move (annexing a subtree inherits everything in it; worse than purging
  it, and in 3b the package itself will write the `parent` edge). **Decision.** `moved` requires `within ∈
  chain(newParent)` **and** `within ∈ chain(child)` — the child's *current* chain, resolved fresh (a child the
  tree does not know is 422 `E_AUTHZ_UNKNOWN_SCOPE`: no origin to check); `attached` checks the parent and, when
  the child already exists (attaching an existing node is a move), its chain too. Both before the driver is
  called. Documented consequence: notify `scopes.moved` **before** re-parenting the row, as `detached` goes
  before the delete. Contract case *"within contrasta también el ORIGEN de scopes.moved/attached"* (61 cases at
  `'2.1'`) + a `manager.spec` case with a fake driver (zero calls). Invariant 15 rewritten ("contra origen y
  destino"). **Not done.** Without `within` the origin is not read (no extra tree call for a lax config).

- **`bumpAuthzCatalogVersion(trx)` requires the writing transaction; `withAuthzCatalogWrite` (H2, auditor 2).**
  **Problem.** `bumpAuthzCatalogVersion({ client? })` defaulted to the global `db`: called from inside a
  consumer's transaction without `client: trx`, the `UPDATE` of the version committed *before* the consumer's
  `DELETE`. A process that asked in between reloaded the **old** rows tagged with the **new** version and, the
  versions now matching, **never revalidated again** — a permanent fail-open in every process but the one that
  restarts (reproduced with two real `node` processes over a shared SQLite + OpenFGA: `true, true, true` after
  the link was removed). **Decision.** (a) `bumpAuthzCatalogVersion(trx, { driver?, timeoutMs? })`: the first
  argument must be a transaction client (`isTransaction === true`, Lucid's and knex's); anything else — nothing,
  the global `db`, a plain object — is 500 `E_AUTHZ_CONFIG` with the recipe. (b) **`withAuthzCatalogWrite(async
  (trx) => …, { driver?, timeoutMs?, connection? })`**, exported: opens the transaction, runs the consumer's
  write with that client, bumps the version **as the last statement, inside**, returns `fn`'s result; a throw
  from `fn` rolls everything back and surfaces as-is (the version does not move); a failure to open or commit is
  503. (c) `syncAuthzCatalog` writes through the same helper (plus its in-process invalidation). (d) README,
  jsdoc and the migration stub say: write `authz_*` only via `withAuthzCatalogWrite`; the bump is always the last
  statement of the transaction. The helper is the cross-process channel only (no in-memory invalidation, on
  purpose: the two-memo tests keep proving the row, not the counter). Tests: bump without trx ⇒ 500 and the
  version unchanged; the helper's `UPDATE` lands after the consumer's write and before `COMMIT` (spied);
  rollback on a consumer error; the two-memo case of the judge and of `catalog_cache.spec` now write through the
  helper and stay green; two real processes with the corrected writer: `false, false, false`.

- **Monotonic clock for `{ everyMs }` and `maxAgeMs` (H3, auditor 3).** **Problem.** Both were measured with
  `Date.now()`: a wall clock stepped back (NTP, snapshot restore) kept the `everyMs` window open past two full
  windows and let an expired `forRequest()` view read again. **Decision.** `performance.now()` in
  `CatalogCache` (`#checkedAt`) and in the view (`#readsUntil`); `CatalogCacheOptions.now` and
  `ForRequestOptions.now` are test-only clock sources (the boundary tests — 29 999 ms reads, 30 000 does not;
  39 ms no revalidation, 40 yes — use them instead of patching `Date.now`). Tests: `Date.now` moved back one
  hour ⇒ the window still closes and the view still expires. `CatalogView.loadedAt` stays wall-clock
  (informational).

- **Version row missing ⇒ 503, never version `0` (I1, auditor 7).** `readAuthzCatalogVersion` used to turn "no
  row" into `0`; invariant 14 said 503. Now a missing row or a non-numeric `version` is 503
  `E_AUTHZ_BACKEND_UNAVAILABLE` whose message says "migración 2.0 no aplicada" — hot memo, cold load and the
  function itself (test deletes the row and restores it).

- **`expandExcludedSubtrees` expires with its view (I2, auditor 10).** It was the one read of a `forRequest()`
  view that ignored `maxAgeMs`; every read now goes through the same `#assertReadable()`.

- **`catalog` + `catalogRevalidate` is 500 `E_AUTHZ_CONFIG` at construction, both drivers (I3, auditor 11).**
  The driver's policy was silently ignored in favour of the shared memo's; now the contradiction is refused
  (`assertCatalogOptions` in `catalog_cache.ts`).

- **`within` comes from the session (I4, auditor 6).** README §Containment: `within = scope` (or the scope's
  parent) satisfies the rule by definition, so a `within` taken from the request body is no containment;
  `'non-root'` closes the `app` wildcard, not that one. Same note in `ScopedWriteOptions` and `requireWithin`.

- **`listDenies` is a capability pair of the judge (I5, tester).** `DriverCapabilities.listDenies: boolean`,
  judged at `'2.1'` only: `true` registers the seven cases that subtract denies (`listDenies`,
  `effectivePermissions`, the three `authorizedScopes` cases, its bounds case and the shared-version case F1,
  which observes the catalog through `effectivePermissions`); `false` registers instead *"sin listDenies en el
  puerto: listDenies, effectivePermissions y authorizedScopes son 500 E_AUTHZ_UNSUPPORTED nombrándolo"* — and
  asserts the driver really lacks the method. `true` below `'2.1'` throws like any capability without a case.
  The package runs the `false` face for real: a third harness, `database (sin listDenies)`, over a prototype view
  of the driver without the method (55 cases). The mutant "`#optional` returns `async () => []`" dies in the
  judge and in `manager.spec`. All package harnesses pass `warnOnOptInSecurity: false` (one `manager.spec`
  config was missing it and printed the opt-in warning in the middle of the suite).

- **`authorizedScopes` cost documented (I6, auditor 4).** README §Enumerating scopes: O(descendants ×
  `resolveAncestors`), not O(answer); `maxScopes` bounds the answer by type and does not cut the walk;
  `maxDescendants` is the bound on the work. Algorithm unchanged in this phase.

- **Tests from the tester's 2D patch (H4).** *"una identidad inválida se rechaza con 0 llamadas al backend"*
  counts **all** queries (catalog and version included), and F10 rejects malformed descendants from
  `descendantsOf` in `expandExcludedSubtrees` (503). Contract cases: 36 core / 49 at `'2.0'` / **61** at `'2.1'`
  (55 with `listDenies: false`).

### Lot 2D — closing corrections (auditor, tester and code-review findings on 2A/2B)

- **The catalog that decides is the one in the database: a shared version row (F1, auditor 1 and 4 — the blocker).**
  **Problem.** The catalog memo of lot 2A fed *decisions* (`rolesGranting`/`catalogRoles` in `openfga`,
  `effectivePermissions` in both drivers) and its invalidation counter lived in memory: a
  `node ace authz:catalog:sync` in another worker never reached it, so a permission removed from a role kept
  granting indefinitely in `openfga` (reproduced: `openfga=true`, `database=false` after the link was
  deleted) — a fail-open revocation, and the two drivers diverged. **Decision.** The migration ships
  `authz_catalog_version` (`id = 1`, `version`, `updated_at`, seeded). `syncAuthzCatalog` bumps it **inside
  its transaction** (`bumpAuthzCatalogVersion({ client: trx })`; a sync that fails does not bump).
  `CatalogCache.view()` compares its snapshot's version with that row before serving — one primary-key
  `SELECT` under `guardSql` with the deadline; concurrent checks share one read; a version the database
  has moved past reloads (reusing the version just read) — under `catalogRevalidate: 'always'` (default) or
  `{ everyMs }` (opt-in: a *bounded* window in which another process's revocation is not yet seen;
  documented as such). A version row that cannot be read is 503, never the old memo. Both drivers take one
  snapshot per operation (`authorize`/`authorizeMany`/`listScopes` in `openfga` used to call `view()`
  twice) — one revalidation per question, pinned by spies. Exported: `bumpAuthzCatalogVersion()` (what a
  by-hand writer of `authz_*` must call; it is exactly what a foreign sync leaves behind),
  `readAuthzCatalogVersion()`, `CatalogRevalidate`, `CATALOG_VERSION_TABLE`; `CatalogView.version`.
  **Removed:** `ttlMs`/`catalogTtlMs` — the TTL "belt for multi-process" no longer has a purpose; `{ everyMs }`
  is the one knob. Contract case in both drivers with **two managers over two memos** on the same database
  and no in-memory signal between them (*"el catálogo que decide es el de la base: un sync en otro proceso…"*):
  the other memo answers `false` on its next `authorize`/`authorizeMany`/`effectivePermissions`; a real sync
  restores it. The harness gained the optional `makeTwin(driver, tree)` (default: a prototype view with a
  fresh `CatalogCache` when the driver exposes `catalog`). Measured: see README §Performance (≈ +0.1 ms
  p50 for the `SELECT`). New invariant 14 in `CLAUDE.md`. **Not done.** No pub/sub and no polling thread:
  the check rides on the question that needs it.

- **`within` covers the six writes; `requireWithin: 'non-root'` (F2, auditor 2 and 9, CR1).** **Problem.**
  Only `grant`/`deny` checked `within`; `revoke`, `removeDeny` and `scopes.*` accepted it (JS) and ignored
  it, and `requireWithin: true` did not require it there — so "the admin of A" could remove a deny of B
  (which *is* granting), revoke in B or purge B's unit. And `within: APP_SCOPE` satisfied `requireWithin`
  without naming any tenant. **Decision.** `ScopedWriteOptions` on all six; `revoke`/`removeDeny` check the
  scope, `scopes.attached`/`moved` the (new) parent — with the chain `#assertEdge` already resolves, no
  extra tree call —, `scopes.detached` the child (which must therefore still be in the tree: purge before
  deleting the row). `requireWithin: true` requires it everywhere; `'non-root'` also rejects `within:
  APP_SCOPE` with 422 `E_AUTHZ_WITHIN_ROOT_FORBIDDEN` (`WithinRootForbiddenError`). Contract cases:
  *"within en las otras cuatro escrituras"* and the rewritten `requireWithin` case — it used to assert
  "`revoke`/`removeDeny` do not require it"; that assertion was inverted, not relaxed. `manager.driver()`
  is documented as the explicit exit from `actor`/`within`/`onWrite` (G4, auditor 8; jsdoc + README).

- **`authorizedScopes` is coherent with `authorize`, or throws (F3, auditor 3).** **Problem.**
  `descendantsOf(deny) === null` was read as `[]`, so a denied subtree was listed as granted; and foreign
  descendants returned by a broken `descendantsOf` were listed (cross-tenant). **Decision.** Every candidate
  descendant is checked against `resolveAncestors` (memoised per request): its chain must run through the
  granting scope — otherwise the two resolvers describe different trees and the call is 503
  `E_AUTHZ_RESOLVER_FAILED` — and the **deny is applied through that chain**, the exact rule of `authorize`.
  `descendantsOf` is no longer called for denies at all, so the `null`-for-deny case cannot leak. `null` for
  a *granting* scope stays conservative (`[]`). Contract case *"authorizedScopes ≡ { s | authorize(s) }
  scope a scope"* (intermediate deny, three levels, a grant inside the denied subtree, a blind, a crossed
  and a ghost `descendantsOf`, ≤ one tree call per candidate).

- **Bounds cut before walking; per-call `maxScopes` only lowers (F8, CR8, auditor 6 and 11).** Direct
  scopes of the requested type are counted before any subtree is fetched; inside the walk the count of the
  requested type is checked after each candidate; `options.maxScopes` is `min(call, config)`. The bound
  counts scopes *of the requested type* rather than all candidates — the literal formula gave false 422s
  (five granting organisations with no units when asking for units) and broke the contract's "the bound is
  on the answer" case. Spied: 5 orgs > 4 ⇒ zero `descendantsOf` calls.

- **`ExcludedSubtree` + `expandExcludedSubtrees` (F10, auditor 7).** `all.excludedSubtrees` is
  `{ scope, includesDescendants: true }[]` — a nominal type so a `NOT IN (uuids)` cannot be written by
  accident. `authorization.expandExcludedSubtrees(excluded, { maxScopes? })` (also exported as a function)
  returns each scope with its whole subtree via `descendantsOf`; a subtree it cannot enumerate is 503
  (subtracting half of it would be fail-open); bounded ⇒ 422. README shows the correct `NOT IN`.

- **A `forRequest()` view expires (F9, auditor 5).** A view kept in a module served the old chain forever
  after a `scopes.moved` (reproduced: manager `false`, view `true`). `forRequest({ maxAgeMs })`, default
  30 000; reads after it — everything that goes through the view's reader, `authorizeMany`/
  `effectivePermissions`/`authorizedScopes` included — are 500 `E_AUTHZ_VIEW_EXPIRED` (`ViewExpiredError`);
  writes and `isWithin` still work (they resolve fresh); `maxAgeMs: 0` is the explicit "no limit"; an
  invalid value is 500 `E_AUTHZ_CONFIG`. `DEFAULT_VIEW_MAX_AGE_MS`, `ForRequestOptions` exported.

- **Smaller closes.** *F4 (CR2):* `CatalogCache.invalidate()` is an instance generation captured before the
  load reads — an invalidation landing during a load is not lost (test with a load in flight, for the
  instance and the global signal). *F5 (CR3):* `authorizeMany` validates a third-party driver's answer —
  not an array, wrong length or a non-boolean ⇒ 500 `E_AUTHZ_INTERNAL` naming the driver. *F6 (CR4,
  auditor 10):* `hierarchicalScopeResolver` keys visited nodes with an explicit `\u001f` separator (`org`+`a-1`
  and `o`+`rga-1` were a false 422 cycle) and validates the parent `parentOf` returns (`{ app, uuid }` was
  silently taken as the root) ⇒ 503 `E_AUTHZ_RESOLVER_FAILED`. *F7 (CR5):* the contract's Proxy spy calls
  `value.apply(receiver, args)` so the `Object.create(this)` view of `withAncestorsResolver` inherits from
  the Proxy; the "zero calls" assertion is no longer vacuous (the mutant "ask position 0 before validating"
  now dies) and the case also asserts the spy sees a valid call. *G1 (CR6, auditor 11):* `sqlDescendantsOf`
  drops the unreachable repeated-uuid barrier (with depth `maxNodes + 1` a cycle never fits in `maxNodes`
  rows), reports a cycle as 422 `E_AUTHZ_TOO_MANY_SCOPES` mentioning "posible ciclo", and validates
  `scopeType` with the identity grammar (never `app`) at construction. *G2 (CR9):* `openfga.authorizeMany`
  gives a repeated scope one slot (14 → 10 checks in the spied case; same answer per position). *G3
  (CR10):* `spies.spec` asserts `calls === 100 * factsPerAuthorize` directly and counts the version
  revalidations apart. *G5 (CR7):* `effectivePermissions` reads roles and denies **once per subject**: new
  optional port method `rolesInChain(subject, chain)` (both drivers: one `whereScopeIn(chain)` query /
  one `Read` of the bindings grouped by scope key; composed from N `listRoles` when absent) plus one
  `listDenies(subject)` — spied ≤ 2 facts reads in both drivers. Contract cases: 36 core / 49 at `'2.0'`
  / **60** at `'2.1'`.

## [Unreleased] — 2.0.0

**Breaking release, no compatibility flags** (there are no consumers yet).
Sixteen defects reproduced by the panels of 2026-08-28 (security, tester,
architecture, judge) closed in three lots, plus the verification round's
corrections (lot D), each with a case that was red before and green after,
in both drivers. This section is **ordered by
risk**: first what could grant access that was never granted (fail-open),
then what could fail the wrong way (a raw error, a hang, a silent `false`),
then what changes the answer to a well-formed question, then the judge and
the tooling. Every entry: problem → decision → what is **not** done.

### Closing corrections — phase 1, lot D (tester, auditor and code-review findings)

Sixteen blocking findings (D1–D16) and five mandatory ones (E1–E5) from the
verification round, each with a case red before and green after. Package
version becomes `2.0.0-alpha.1`.

- **A per-check `error` inside a 200 `batchCheck` is a 503 (D1).**
  **Problem.** OpenFGA can answer 200 with `error: { input_error… }` on one
  check; the role phase of `authorize` and `hasRole` collapsed it into
  `false` — a partial backend failure disguised as "no permission"
  (invariant 5). **Decision.** Any `error` in a batch result ⇒
  `AuthorizationBackendError` (503) with the server error as `cause`, in the
  deny phase and in the role phase alike (*"un error por check en batchCheck
  es 503, nunca false"*). **Not done.** No per-check retry: the caller retries
  the question.

- **Phantom writes after a timeout are visible (D2).** **Problem.** With the
  package deadline the caller got a 503 while the SDK kept retrying in the
  background (`maxRetry: 3`) and the tuple landed *after* the error, with no
  `onWrite` event — a live privilege with no audit trail (auditor H1).
  **Decision.** (a) the `openfga` client no longer retries on its own
  (`retryParams.maxRetry: 0` by default, configurable through
  `OpenFgaDriverOptions.retryParams`); (b) when a write throws
  `AuthorizationBackendTimeoutError`, the manager notifies `onWrite` with the
  same event plus **`indeterminate: true`** *before* propagating, so the audit
  records "may have happened" (*"una escritura que vence el deadline notifica
  onWrite con indeterminate: true"*). A non-timeout 503 emits nothing: that
  write did not happen. **Not done.** Aborting the in-flight request: the SDK
  (0.9.6) has no per-call `AbortSignal`.

- **A role or permission belongs to exactly one catalog (D3).** **Problem.**
  Two catalogs declaring the same `support@app` pruned each other's links
  (the prune is per role) and the last one in order won silently; a slug
  collision after encoding (`docs:write` / `docs_write`) split across two
  catalogs was accepted (auditor H5). **Decision.** `syncCatalogs` and
  `runCatalogDiff` resolve every catalog first and refuse, before any write,
  if a role `(slug, scopeType)` or a permission appears twice: 422
  **`E_AUTHZ_CATALOG_CONFLICT`**. `syncAuthzCatalog`/`diffAuthzCatalog`
  check encoding collisions against the permissions already in the database
  too, inside the transaction. **Not done.** No merge of two catalogs'
  permissions for one role: split the role or move it.

- **`purgeScope` in `database` has a deadline (D4).** Each `DELETE` inside the
  transaction goes through `guardSql` (auditor H13); the L0.13 case walks
  `purgeScope` too. knex's own `BEGIN`/`COMMIT` carry no timeout — they are not
  queries the driver builds — and the case says so.

- **Membership is what the catalog says, in both drivers (D5).** **Problem.**
  `openfga` answered `hasRole`/`listRoles`/`listRoleScopes`/`listSubjects`
  from tuples: a role removed from `authz_roles` stayed a membership there and
  not in `database`; and `purgeScope` promised "zero" over a set it could not
  enumerate (auditor H2, CR5). **Decision.** The four reads filter by the
  catalog (slug declared for that level) — an orphan tuple is not a
  membership, `hasRole` is `false` and it is not listed, though the tuple
  stays in the store until `authz:reconcile` (*"un binding de un rol que no
  está en el catálogo no es membresía"*, and with a server: *"rol borrado del
  catálogo: la tupla sigue en el store pero authorize deniega"*). The
  `purgeScope` promise (port, README) is now honest: it purges and proves
  zero over the facts **whose role/permission is in the catalog**. **Not
  done.** Enumerating orphan bindings by id prefix: `Read` cannot do it
  without a `user`; the full enumeration arrives with the `facts` model (3b).

- **A race in `grant` is only a race on a duplicate write (D6).** **Problem.**
  The collision branch did `catch {}`: a 400 validation error or a 5xx was
  treated as "someone wrote first", retried blindly, and the cause was lost;
  with `expiresAt` omitted and a failed re-read, a permanent tuple could be
  written (L0.4 in a narrow window, tester H5). **Decision.** Only FGA's
  duplicate-write rejection counts as a race — measured against v1.19: HTTP
  400 with `apiErrorCode: 'write_failed_due_to_invalid_input'` and "cannot
  write a tuple which already exists" (a 409 is accepted too); anything else
  propagates classified with the SDK error as `cause`. Duplicate + empty
  re-read + no `expiresAt` ⇒ 503 whose message carries the recipe
  `{ expiresAt: null }`, and nothing is written (*"la carrera de grant solo es
  carrera con un duplicado"*).

- **`expiresAt` is validated (D7).** A string, a number or an `Invalid Date`
  is 422 `E_AUTHZ_INVALID_IDENTITY` in the manager and both drivers
  (`assertExpiresAt`, exported); before, one driver threw a raw TypeError and
  the other persisted garbage (*"expiresAt que no es Date válida, null ni
  omitido ⇒ 422"*, core contract case).

- **`listRoles`/`listRoleScopes` apply "unknown scope ⇒ nothing" (D8).** Like
  `authorize`/`hasRole` since L0.3. `listRoleScopes` asks the resolver once
  per scope it returns (documented cost; the per-request memo is phase 2)
  (*"listRoles y listRoleScopes tampoco responden por un scope que el árbol no
  conoce"*).

- **The OpenFGA driver moves to the `@jantstack/adonis-authz/openfga` subpath
  (D9, breaking).** **Problem.** `index.ts` re-exported the driver
  statically, so a database-only consumer could not boot without
  `@openfga/sdk` — the "optional peer" was not optional. **Decision.** New
  `exports["./openfga"]` with `OpenFgaAuthorizationDriver`,
  `provisionOpenFgaStore`, `importAuthzFactsToOpenFga`,
  `openFgaAuthorizationModel`, `assertHolderTypes` and the types; `index.ts`
  no longer imports the driver (`HolderTypeMap` lives in `types.ts`); the
  published config imports the driver from the subpath *inside* the factory;
  the `openfga:*` commands import it from there; `check_purity` rule 3 fails
  the build if anything outside `src/openfga.ts`, the driver and
  `commands/openfga_*` imports the SDK or the driver; and a test loads
  `index.ts` in a child process with `@openfga/sdk` blocked by a resolve hook
  (with the control face: the subpath must fail). **Migration.**
  `import { OpenFgaAuthorizationDriver } from '@jantstack/adonis-authz'` →
  `from '@jantstack/adonis-authz/openfga'`.

- **`revoke`/`removeDeny` with an unknown role/permission are 422 (D10).**
  Like `grant`/`deny`, in both drivers (`E_AUTHZ_UNKNOWN_ROLE` /
  `E_AUTHZ_UNKNOWN_PERMISSION`); the silent no-op hid the real case (a role's
  `scope_type` changed under an assignment) and diverged between drivers
  (auditor H9). The safe no-op remains for a missing assignment of a valid
  role.

- **A `RoleQuery` object where a slug is expected is 422 (D11).** `grant`,
  `revoke`, `listSubjects` validate with the slug grammar
  (`E_AUTHZ_INVALID_SLUG`); before it was a 503 in one driver and a raw
  TypeError in the other (auditor H4).

- **`Read` pagination is bounded (D12).** A `continuation_token` that repeats,
  or more than 10,000 pages, is 500 `E_AUTHZ_INTERNAL` — before it was an
  infinite loop no deadline could cut (auditor H7). Malformed tuples are
  counted in `diagnostics.unparseableBindings` and logged (auditor H16).

- **The resolver's answer is validated (D13).** A malformed ancestor (or a
  non-array) is 503 `E_AUTHZ_RESOLVER_FAILED` with the reason as `cause`,
  not a 422 of identity on a read (auditor H11).

- **`--reconcile` converges (D14).** **Problem.** Tuples SQL no longer had
  survived and the report of zeros looked like "in sync" (auditor H3).
  **Decision.** With `reconcile` the importer reads the whole store
  (paginated, bounded `Read({})`), counts `role_binding`/`deny_binding`
  tuples with no SQL counterpart as **`extra`**, and with `prune`
  (`--prune`) deletes them (**`deleted`**). Report:
  `{ written, updated, unchanged, extra, deleted, skippedExpired, dryRun }`;
  `prune` without `reconcile` is 500 `E_AUTHZ_CONFIG`. Still an FGA tool
  (raw SDK errors). **Not done.** The bidirectional `authz:reconcile` with
  the catalog projection: 3b.

- **Catalog failures are classified (D15).** `syncAuthzCatalog`/
  `diffAuthzCatalog` go through `guardSql` (503, `timeoutMs` option, default
  5000) instead of leaking a raw SQL error at deploy time; a holder type not
  declared in `holderTypes` is 500 `E_AUTHZ_CONFIG`.

- **L0.7 crosses a `Read` page (D16).** The contract case writes 150 noise
  denies before the relevant one: a driver that does not follow the
  continuation token now fails the judge, not only the unit test.

- **Tests and docs (E1–E5).** The tester's five cases (H2 `hasRole` per level
  on a hand-written row, H3 `purgeScope(APP_SCOPE)` in `database`, H4 a
  third-party driver returning `void`, T1/T2 a removed role denies) are in;
  the manager normalizes a `void` grant to
  `{ existed: false, expiresAt: options?.expiresAt ?? null }` so the signature
  never lies. `IDENTITY_LIMITS.slug` (100, dead) is removed: the limit is
  `MAX_SLUG_LENGTH` (42). The sentinel uuid is 422 even when the tree knows
  it. `CatalogRoleSpec.scopeType` is validated as a scope identity, and
  **holder and scope types must be lowercase** (a `*_ci` MySQL collation
  would merge `Users`/`users` while FGA keeps them apart).

  **Migrating slugs legal in 1.1.0.** 1.1.0 accepted any string; 2.0 rejects
  a role with `:` (`org:admin`), the reserved names (`parent`, `binding`,
  `ancestor`, `role`, `assignee`, `denied`), the families `can_*`,
  `denied_*`, `permits_*`, uppercase, more than 42 characters, and pairs that
  collide after encoding (`docs:write` / `docs_write`). Before upgrading:
  rename in the catalog spec (`org:admin` → `org-admin`, `can_edit` →
  `edit`), run `authz:catalog:sync` **with the old package** so the rows get
  the new slug (roles are upserted by `(slug, scope_type)`: add the new role,
  move assignments with `UPDATE authz_assignments SET role_uuid = <new>
  WHERE role_uuid = <old>`, drop the old row), then upgrade. `openfga` stores
  hold the slug inside the binding id: re-import with `openfga:import
  --reconcile --prune` after the rename.

### Enumeration and docs — phase 1, lot C

- **`openfga` enumerations are complete: paginated `Read`, never
  `ListObjects`/`ListUsers` (L0.7).** `listSubjects`, `listRoles`,
  `listRoleScopes` and the deny set of `listScopes` read tuples with the
  `Read` API — `page_size` 100, `continuation_token` until empty,
  `HIGHER_CONSISTENCY` — and filter expiry client-side by
  `condition.context.valid_until`. The driver contains zero calls to
  `listObjects`/`listUsers` (a source-level test pins it). Contract: a new
  `level: '2.0'` case, *"listScopes resta el deny aunque el sujeto tenga más
  denies de OTROS permisos que el tope del backend"*, and the 1,200-assignment
  case now runs in `openfga` too (`exhaustiveLists: true` in both drivers;
  the package harness no longer passes `limits`). CI keeps the second OpenFGA
  with the cap at 3 as the proof that no enumeration depends on it.

  **Problem.** The only fail-open of L0 reproduced end to end: `listScopes`
  fetched *every* deny of the holder with `ListObjects` (server cap, no
  truncation signal) and filtered by permission in the client, so four
  irrelevant denies pushed the relevant one off the page and a scope where
  `authorize` answers `false` was listed as granted — measured: 10,030 denies,
  1,000 returned, 30 denied organisations reported as granted. `listBindings`
  (1,200 → 1,000) and `listSubjects` (`ListUsers`, same cap) truncated in the
  closed direction, equally silent. **Decision.** `ListObjects` has no
  pagination at all (verified in the SDK and upstream), so the fix is a
  different API: with the model this package generates (`assignee`/`denied`
  are direct relations) `Read` is exactly equivalent and has no cap. **Not
  done.** `Read` does not expand computed relations: a third party that
  extends the model with derived relations over `role_binding` would not see
  them in these enumerations — documented as an operational note. No
  `truncationSignal: true` case exists: nothing in the package truncates, so
  there is nothing to signal; a third-party driver with a capped backend
  declares `exhaustiveLists: false` and proves only the boundary.

- **The README stops promising what the code does not do.** Five statements
  audited as false by the tester panel are corrected: "deny wins" is scoped
  to `authorize` (it never affected `hasRole`, now a contract case);
  polymorphic holders are guaranteed only with an injective `holderTypes`
  (now enforced); "call-sites never change when you swap backends" becomes
  "for everything the suite covers, both drivers answer the same — including
  the malformed-input edges that used to diverge, which are contract cases
  now"; "the `database` driver has no equivalent failure" becomes "a SQL
  outage is a 503 in **both** drivers; `database` avoids the *second*
  dependency"; and "PostgreSQL, MySQL, SQLite" becomes "verified on SQLite;
  PG/MySQL untested until the multi-engine harness (2.1)". The README also
  documents what 2.0 adds — `scopes.*`, `purgeScope`, anti-cycles, the three
  states of `expiresAt`, `GrantOutcome`, `RoleQuery`, `prune`,
  `authz:catalog:diff/sync`, `config.catalogs`, `timeoutMs`, `consistency`,
  `--reconcile`, the error table — and its "Semantics" section is the eight
  invariants of the contract, each with the test that backs it. **Not
  promised:** anything about a single-`Check` mode (phase 3b).

### Fail-open closed — phase 1, lots A and B

- **An unknown scope denies; there is no flat default resolver any more
  (L0.3).** `ScopeAncestorsResolver` now returns `ScopeRef[] | null`: `null`
  means "this scope does not exist". On it, `authorize`/`hasRole` answer
  `false`, `grant`/`deny` are **422 `E_AUTHZ_UNKNOWN_SCOPE`**, `revoke`/
  `removeDeny` stay safe no-ops and `listScopes` omits it. A driver built
  **without** `resolveAncestors` only knows the root: any other scope type is
  **422 `E_AUTHZ_NO_SCOPE_RESOLVER`** on the first call. `resolveAncestorsFrom
  (tree)` (testing) passes `null` through. Unknown role / permission now carry
  codes too: **422 `E_AUTHZ_UNKNOWN_ROLE` / `E_AUTHZ_UNKNOWN_PERMISSION`**.

  **Problem.** Both drivers shipped `anything → [APP_SCOPE]` as default, and
  the type had no vocabulary for "does not exist". Measured: a deny on
  `organization:B` stopped applying inside a unit of B the moment the tree
  failed to find the unit, and a scope *invented* by the caller inherited
  every app-level grant. **Decision.** Deny by default on the unknown; make
  it impossible to write a fact on a scope nobody recognises; drop the
  default so a misconfigured deployment fails loudly instead of leaking.
  **Not done.** No `flatScopeFallback` escape hatch (rejected by the owner:
  it would reopen the defect from config); a consumer resolver that returns
  `[APP_SCOPE]` for what it does not know is still legal — the contract can
  only offer `null`, not enforce its use.

- **`syncAuthzCatalog` prunes stale role→permission links by default, and
  the catalog is diffable from the CLI (L0.9).** `syncAuthzCatalog(spec,
  { prune: 'links' | 'none' })`, default `'links'`: for every role **of the
  spec**, links the spec no longer lists are deleted in the same
  transaction. Roles and permissions are never deleted; roles outside the
  spec are untouched (two catalogs coexist). A role granting a permission
  that exists in no catalog is **422 `E_AUTHZ_UNKNOWN_PERMISSION`** (it used
  to be skipped in silence). New: `AuthorizationConfig.catalogs?:
  Array<() => Promise<CatalogSpec>>`, commands **`authz:catalog:sync`**
  (`--keep-links` for the 1.x additive mode) and **`authz:catalog:diff`**
  (exit 1 listing missing permissions/roles/links, **surplus links** and
  rank mismatches), `diffAuthzCatalog` / `runCatalogDiff` exported, and the
  `configure` stub wires `catalogs`. This is also a `level: '2.0'` contract
  case: re-seeding the catalog without `docs:write` on `editor` makes
  `authorize` answer `false` in both drivers.

  **Problem.** The sync was purely additive: removing `docs:write` from
  `editor` in `config/app_acl.ts` changed nothing in any environment, ever —
  the only visible source of truth lied about effective permissions.
  **Decision.** The spec rules its own roles; a diff that fails CI catches
  drift the sync did not run for. **Not done.** No pruning of roles or
  permissions (they carry assignments; retiring one is an explicit consumer
  decision, `purgeRole` arrives with `catalog/`), no `scope_type` migration
  of an existing role.

- **The scope tree is a contract fact: `manager.scopes.attached / moved /
  detached`, `purgeScope` in the port, anti-cycles in the package.**
  `AuthorizationDriver.purgeScope(scope)` is **required** (deletes every
  assignment and deny of the *exact* scope; must prove zero or throw **500
  `E_AUTHZ_PURGE_INCOMPLETE`**; the root is 422); `onScopeAttached? /
  onScopeMoved? / onScopeDetached?` are optional hooks. The manager needs
  `config.scopes.resolveAncestors` (500 `E_AUTHZ_CONFIG` otherwise) and
  validates **before touching the driver** — spied: zero calls on failure:
  `child.type === 'app'` ⇒ 422, unknown parent ⇒ 422
  `E_AUTHZ_UNKNOWN_SCOPE`, `child ∈ chain(parent)` (or `child === parent`)
  ⇒ **422 `E_AUTHZ_SCOPE_CYCLE`**. `detached` runs `purgeScope` **first**,
  then the hook, then notifies `onWrite` with `action: 'scope_purged'`
  (no `subject`; `AuthzWriteEvent.subject` is now optional). The `openfga`
  driver purges by exact-object paginated `Read` (one `role_binding` per
  catalog role of that scope type, one `deny_binding` per permission),
  deletes in batches of ≤ 100 and re-reads to prove zero. The judge's `tree.detach` now calls `driver.purgeScope`
  before removing the edge, so N7 (nothing resurrects on re-attach) and N8
  (siblings and parent intact) are `level: '2.0'` cases in both drivers.

  **Problem.** Deleting a tenant left its grants and denies alive forever in
  both drivers (polymorphic scope: no FK; FGA: nothing), and with the flat
  resolver a "deleted" scope still had holders. FGA evaluates `parent`
  cycles instead of rejecting them (S2: 7 ms to `true` at the root), and a
  half-finished purge after the edge is gone leaves undeniable grants (S6).
  **Decision.** The package is the only barrier for cycles; facts first,
  edge last; a purge that cannot prove zero fails the consumer's delete.
  **Not done.** `purgeScope` covers the exact scope only until
  `descendantsOf` exists (phase 2) — the consumer purges each node it
  deletes; bindings of a role removed from the catalog are unreachable by
  the openfga purge (no index by object) and become `authz:reconcile`'s job
  in 3b; `moved` in facts mode as one atomic `Write` is 3b as well.

- **`openfga:import` no longer ignores duplicates; `--reconcile` compares
  tuple by tuple (S7).** `importAuthzFactsToOpenFga` throws **409
  `E_AUTHZ_STORE_NOT_EMPTY`** on a store with tuples unless
  `{ reconcile: true }`; with it, each fact is read exactly — absent ⇒
  write, present with a different condition ⇒ delete + write (`updated`),
  identical ⇒ `unchanged`. Report: `{ written, updated, unchanged,
  skippedExpired, dryRun }` (replaces `assignments`/`denies`). Writes go in
  batches of 100 with no `onDuplicateWrites: Ignore`.

  **Problem.** In FGA the condition is not part of the tuple key: importing
  a now-expiring grant over its old permanent tuple kept it permanent and
  reported success; measured, and with the current SDK/server pair it was
  not even ignored but a raw 409 `FgaApiError`. **Decision.** Refuse to
  import blind; reconcile explicitly and count every outcome. **Not done.**
  No deletion of tuples that SQL no longer has (that is `authz:reconcile`,
  phase 3b); the tool still surfaces SDK errors raw, as every explicitly
  OpenFGA tool does.

- **`appAccess({ role })` is gone; `hasRole` takes `{ slug, scopeType }`;
  a deny never affects `hasRole` — now a contract case (L0.6).** The
  middleware type only admits `{ permission }`; passing `role` at runtime
  is **500 `E_AUTHZ_ROLE_IS_NOT_ACCESS`** with the migration recipe (create
  a permission, link it to the role, use `{ permission }`), thrown before
  authentication is even checked. `hasRole(subject, 'owner', scope)` matches,
  at every level of the chain, only the role *of that level* (an app
  `owner` inherits downward; an organization `owner` never matches app);
  `hasRole(subject, { slug: 'owner', scopeType: 'organization' }, scope)`
  restricts to chain levels of that type.

  **Problem.** The package published a policy enforcement point over a
  membership query: a holder with every permission denied still passed
  `appAccess({ role: 'superadmin' })`, and nothing short of revoking the role
  could stop them. **Decision.** Retire, do not deprecate — while it is
  exported it is an undeniable gate; and pin, in the judge, that `hasRole`
  ignores denies so nobody "fixes" it into a second access decision.
  **Not done.** `hasRole` does not consult denies (it is a fact, not a
  decision); the two-`owner` string case already behaved correctly in both
  drivers (grant binds the role to its own level), the object form is the
  new capability.

- **`{ type: 'app', uuid: X }` is a 422 (L0.10) and the root sentinel uuid is
  rejected outside `app` (L0.15).** Both in `assertIdentity` and at the one
  place each driver serialises a scope (`scopeKey`, `toDbScopeUuid`).

  **Problem.** `app` is the root and takes no uuid, but nothing enforced it:
  the `openfga` driver dropped the uuid and wrote the grant on the *global*
  root (tenant → platform escalation, measured `true` in `APP_SCOPE`), the
  `database` driver stored it and answered `false`. The sentinel
  `00000000-…` is how `database` stores the root; as an `organization` uuid it
  would collide with it. **Decision.** Reject, with the same status in both
  drivers, before anything is written. **Not done.** No attempt to "repair"
  the intent (`{app, X}` is not silently mapped to `APP_SCOPE`): a malformed
  scope is a bug at the call-site and should surface there.

- **`assertValidSlug` is public, applied by the drivers on every operation and
  by `syncAuthzCatalog` on the whole catalog (L0.8a, S4, S13, S14, L0.16).**
  Rules: lowercase grammar (roles take no `:`, permissions at most one),
  **at most 42 characters** (50 of an FGA relation name minus `permits_`, the
  longest derived prefix), reserved names (`parent`, `binding`, `ancestor`,
  `role`, `assignee`, `denied`), reserved prefix families (`can_`, `denied_`,
  `permits_`), and, catalog-wide, no two slugs that project to the same
  relation (`docs:write` vs `docs_write`). Violation: **422
  `E_AUTHZ_INVALID_SLUG`**. Binding ids read back from the store that do not
  parse (wrong arity, invalid parts) are **counted and logged**
  (`driver.diagnostics.unparseableBindings`, injectable `logger`), never
  skipped in silence.

  **Problem.** `encodeSlug` (`:` → `~`) is not injective from the caller's
  side: `removeDeny(u, 'docs~read', s)` lifted the deny of `docs:read`. A
  permission named `parent` would invalidate the whole phase-3b model, and
  `can_docs_write` would silently *replace* the derived relation of
  `docs:write` — a deny bypass reproduced end to end. A 53-character slug is
  legal in SQL and unpublishable in FGA, so the divergence surfaced on
  migration day. **Decision.** One grammar, enforced in the core for both
  drivers, so a catalog that works with `database` is guaranteed to work with
  `openfga`. **Not done.** The Lucid models are still exported writable; the
  driver-side check is what makes a slug inserted behind the catalog's back
  harmless (it cannot be addressed), not what prevents the insert.

- **Identity is validated once, in the manager, and again in every driver
  (L0.5).** `SubjectRef.type`/`uuid`, `ScopeRef.type`/`uuid`, `role` and
  `permission` must be non-empty strings of letters, digits, `.`, `_`, `-`
  (permissions may carry one `:`), within the column lengths (`holder_type`
  50, `scope_type` 20, uuid 36). Anything else is **422
  `E_AUTHZ_INVALID_IDENTITY`** before catalog, tree or backend are touched —
  verified with spies: zero SQL queries and zero FGA calls.

  **Problem.** The same input diverged by driver: `uuid: undefined` made the
  `openfga` driver write `user:undefined`, after which *every* holder without
  a uuid inherited that grant; the `database` driver persisted `''`,
  `"x' OR '1'='1"` and `u#assignee` as if they were holders; a 400 from FGA
  was reported as a 503 "backend down". **Decision.** One function
  (`assertIdentity` in `src/identity.ts`, exported) with an allow-list, called
  by the manager and by both drivers — defence in depth, not duplicated logic,
  since the contract suite and third-party drivers bypass the manager. **Not
  done.** No registry of *declared* holder types in the manager: the
  `openfga` driver still rejects an unknown morph name (500) because only it
  knows the model; `database` accepts any well-formed type. Breaking: a
  consumer feeding non-uuid identifiers (spaces, `:`) must map them first.

- **`holderTypes` must be injective (L0.2).** Checked in the
  `OpenFgaAuthorizationDriver` constructor and in `openFgaAuthorizationModel`
  (exported as `assertHolderTypes`): empty maps and malformed FGA type names
  are rejected too. **500 `E_AUTHZ_CONFIG`**.

  **Problem.** `{ users: 'user', integrations: 'user' }` merged two holders
  into one for the store: a grant to `users:U` authorised `integrations:U`,
  `listSubjects` reported the wrong morph and a revoke of one deleted the
  other (invariant 4). The model generator *knew* — it deduplicated with a
  `Set` — and published anyway. **Decision.** Fail at construction, with the
  colliding names in the message. **Not done.** The driver does not read the
  store's model back to compare it with the map it was given; that stays a
  documented obligation.

### Failures classified — phase 1, lot A (never a raw error, a hang or a silent `false`)

- **A failing SQL catalog or a throwing ancestor resolver are 503, in both
  drivers (L0.11, N3).** Every query goes through one guard: a raw knex/SQLite
  error becomes `AuthorizationBackendError` (`E_AUTHZ_BACKEND_UNAVAILABLE`,
  cause kept); a resolver that throws becomes `ScopeResolverError` (503,
  **`E_AUTHZ_RESOLVER_FAILED`**). Semantic errors (unknown role, 422) pass
  through untouched.

  **Problem.** With the catalog unreachable, `authorize` threw a `SqliteError`
  without status or code in *both* drivers — a 500 in the exception handler
  and, for anyone wanting to tell "backend down" apart, an import of Lucid's
  error type. The README claimed the opposite. **Decision.** The three
  dependencies of a question (catalog, tree, facts backend) are classified the
  same way; none of them is ever a `false`. **Not done.** `syncAuthzCatalog`
  is a tool, not a decision path: its SQL errors are still raw.

- **Every backend call has a deadline (L0.13, N6).** `timeoutMs` (default
  5000) on both drivers. `database`: every query is built with
  `.timeout(ms, { cancel: true })` (falling back to no-cancel on dialects that
  cannot cancel, e.g. SQLite). `openfga`: axios `timeout` via the SDK's
  `baseOptions` **and** a total deadline per call, retries included. Expired
  ⇒ **503 `E_AUTHZ_BACKEND_TIMEOUT`** (a subclass of
  `AuthorizationBackendError`, so existing handlers keep working).

  **Problem.** A backend that accepts the connection and never answers held
  the request forever — the panel had to kill the reproduction after two
  minutes. `AuthorizationBackendError` covered *errors*, not *hangs*. The SDK
  has no timeout option of its own (its axios default is 10 s) and retries
  network errors three times with backoff, so a per-attempt timeout alone
  would still make the caller wait for the sum. **Decision.** Deadline means
  deadline: the caller is released at `timeoutMs`; the SDK may still retry in
  the background within its own bounds. A mute server now answers in under a
  second with the right code. **Not done.** No circuit breaker, no
  per-operation deadlines, and SQLite's synchronous driver can never actually
  time out — what the suite pins there is that every query *carries* the
  deadline.

- **`context.current_time` on every check, denies included, and
  `HIGHER_CONSISTENCY` by default (S17, S11).** Every `check`, `batchCheck`
  and `read` sends `consistency: HIGHER_CONSISTENCY` (there are no other
  read paths left: see L0.7 above); `consistency: 'minimize_latency'` in the
  driver options is the explicit opt-out.

  **Problem.** Deny checks went without `context`, which works only while deny
  tuples carry no condition; in the single-check `facts` mode (phase 3b) a
  missing context fails the whole decision (400 → 503). Separately, an OpenFGA started with
  `--check-query-cache-enabled` turns Check into an eventually consistent
  API: a fresh `revoke` or `deny` kept granting for up to 10 s, while the
  contract promises "removing the deny restores". **Decision.** One
  `checkContext()` for every evaluated relation (enumerations evaluate
  nothing: they read tuples and filter expiry with the same clock), and the
  package protects its own promise by asking for higher consistency; the operator's cache flag can
  no longer silently invalidate it. **Not done.** The two-call refresh window
  of `grant` (delete + write) and the SQL↔FGA drift (S5) are of a different
  nature and are not closed by this.

- **`batchCheck` results are correlated by `correlationId`, never by position
  (L0.14, N7).** The driver assigns an id per check and `correlateBatchResults`
  (exported) aligns the response: exactly one result per requested id — a
  duplicate plus a missing one, which passes a cardinality check, is **500
  `E_AUTHZ_INTERNAL`**, as is a result nobody asked for.

  **Problem.** The SDK splits the batch into parallel sub-requests and
  concatenates responses in arrival order. Harmless today because every
  consumer uses `.some()`; with `authorizeMany` (phase 2) a misattributed
  result is a `true` in the wrong scope. **Decision.** Fix it before the API
  that would expose it exists. **Not done.** The driver no longer chunks by
  50 itself; the SDK's `maxBatchSize` does that.

- **`whereScopeIn([])` can no longer mean "no filter" (L0.1).** Exported from
  `database_driver.ts` with an explicit intent: on reads an empty scope set
  returns `null` and the caller answers `false`/`[]` **without running a
  query**; on writes it throws **500 `E_AUTHZ_INTERNAL`**.

  **Problem.** An empty `OR` chain compiles to no `WHERE` at all. The asymmetry
  is what makes it dangerous: the deny query over-blocks (closed), the
  assignment query grants in *any* scope (open). Unreachable in 1.x (the
  chain always contains the scope) but `descendantsOf`/`authorizedScopes`
  (phase 2) make it reachable. **Decision.** Fix it before it is reachable,
  as a typed function whose `null` the call-sites must handle. **Not done.**
  No `whereRaw('1 = 0')` fallback: a query that cannot match is not run.

### Semantics — phase 1, lot B (what a well-formed question answers)

- **`expiresAt` has three states, and re-grant reports what it did (L0.4).**
  `grant(s, r, scope)` with `expiresAt` **omitted** preserves a *live*
  expiry (and revives an already-expired assignment without expiry);
  `expiresAt: null` removes it; a `Date` sets it. `grant` returns a
  `GrantOutcome { existed, previousExpiresAt?, expiresAt }`, and the manager
  emits **`action: 'extended'`** with `previousExpiresAt` when a re-grant
  changes the expiry of an existing assignment (a no-change re-grant stays
  `granted`). In the `openfga` driver a grant *without* `expiresAt` whose
  read fails is a **503**: preserving requires reading.

  **Problem.** Any idempotent "make sure they have the role" (seeders,
  onboarding) called `grant` without options and turned a 60-second
  emergency access into a permanent one, with an indistinguishable
  `granted` audit event. **Decision.** The judge's graft: preserve only what
  is live, so the existing cases ("grant duplicado", "expirada revive") stay
  green and the temporary/permanent confusion disappears; verified with a
  real expiry that elapses inside the case. **Not done.** No attempt to
  preserve through a failed read by "assuming permanent" — that is the
  defect in degraded mode; and `openfga` still pays delete+write (a window
  of `false`) when the expiry really changes, because FGA refuses both on
  one key in a single request.

### The judge — phase 0 (breaking harness signature)

- **`runAuthorizationDriverContract` has a new harness signature.** A harness
  written against 1.x no longer compiles. What changed and why:

  - `capabilities` (required) — what the driver *declares* it can do
    (`hierarchyFacts`, `transactions`, `truncationSignal`,
    `singleCheckAuthorize`, `injectableClock`, `exhaustiveLists`). The rule:
    every capability gets a pair of cases `{ whenTrue, whenFalse }` and there
    is **never a `skip`**. Pairs exist today for `exhaustiveLists` (both
    faces), `truncationSignal: false` and `hierarchyFacts: false`; the
    others arrive with their phase, and until then declaring one `true`
    makes the suite **throw at registration** — a promise without a judge
    does not pass. `exhaustiveLists: false` requires `limits.listMaxResults`
    and proves only the exact boundary; both package drivers declare `true`.
  - `level` (optional, default `'core'`) — `'core'` runs the 1.x cases;
    `'2.0'` adds the tree-dependent cases. Without this, every new case in
    the judge would be a major for third-party drivers. **`core` is not
    untouched**: `listSubjects`/`listScopes` assert set equality instead of
    inclusion (a driver returning too much used to pass), the inheritance
    cases require the tree the harness hands to the driver (an unknown scope
    resolves to `null` — no implicit `app`), and invariants that were never
    tested are core cases now: `rank` is metadata, a repeated `deny` does not
    duplicate, `deny` before `grant` still blocks, identity and slug
    validation, unknown scope, the three states of `expiresAt`, `hasRole`
    by level, deny not affecting `hasRole`. A 1.x driver that honoured the
    documented semantics passes all of them; one that leaned on the flat
    default resolver does not — that was the point. Counts: 32 core cases,
    44 at `'2.0'`.
  - `makeDriver(tree)` receives a `ContractScopeTree` and `makeTree()`
    (optional, default `memoryScopeTree()`, exported from `./testing`) builds
    it. Setup order is `cleanup → seedCatalog → makeTree → makeDriver(tree)`.
    The judge's `tree.detach` calls `driver.purgeScope` before removing the
    edge.

  **Problem.** The judge never mentioned the scope tree. The default ancestor
  resolver was flat (`anything → [app]`), no harness injected another one, so
  invariant 1 — the feature the README sells — was only ever tested with
  chains of length 2. Three cases passed for the wrong reason and five would
  have failed outright against a driver that materialises the tree as facts.
  **Decision.** The tree becomes an abstraction of the *contract*: the suite
  writes `await tree.attach(org, APP_SCOPE)` and the harness decides what is
  behind it (a `Map` walked by `resolveAncestors` today; backend facts in
  phase 3b). Zero conditionals in the cases. Verified: with the `attach`
  calls removed, the core cases "inheritance app → org", "close deny" and
  "`hasRole` inheritance" **fail** in both drivers. **Not done.** The
  `hierarchyFacts: true` face (A1–A6) and `singleCheckAuthorize` are phase
  3b; `transactions` and `injectableClock` are phase 2.5.

- Backend spies for the package suite (`withFailing`, `countCalls`,
  `countQueries`) and tests pinning the current cost: `authorize` on a chain
  of three resolves ancestors **exactly once** in both drivers.

### Tooling and hygiene

- **`check:purity` runs inside `npm test`** (so in the `test` CI job), with a
  second rule ready for opt-in modules: nothing under `src/<module>/` may
  import the manager or a driver. Lot C closes the phase-0 leftovers: the
  import regex catches a template-literal `import(\`#config/${x}\`)`,
  comments (`//`, `/* */`) are stripped with a string/template/regex-aware
  scanner so an alias mentioned in a comment does not fail the build while a
  real import after a URL on the same line still does (fixtures prove both
  directions), and the script's "invoked directly" check is proven through a
  symlink (nvm, `npm link`).
- **`scripts/openfga_prune_stores.mjs` has a test** against an ephemeral HTTP
  server: dry-run lists (paginating) and deletes nothing, `--force` deletes
  only the stores with a given prefix across every page, a prefix shorter
  than 4 characters, a missing `--prefix`, a flag without value and an
  unknown argument all exit 2 without touching the server.
- **The published config stubs are compiled by the suite**
  (`tests/configure.spec.ts`): `authorization.stub` and `app_acl.stub` are
  rendered and type-checked against the package, and the stub is checked to
  wire `resolveAncestors` in its three places (manager `scopes`, `database`
  driver, `openfga` driver) with the same function. The stub documents that
  seam.
- CI runs the judge against **two** OpenFGA servers (`v1.19.0`): defaults,
  and `OPENFGA_LIST_OBJECTS_MAX_RESULTS=3` / `OPENFGA_LIST_USERS_MAX_RESULTS=3`.
  With L0.7 closed the second server is no longer *how* truncation is
  reproduced but the proof that no enumeration depends on the cap.
- The `openfga` test harnesses delete the stores they create (one per test);
  they used to accumulate forever on the local server.

## [1.1.0] — 2026-07-29

### Added

- **`AuthorizationBackendError`** — the engine now owns its own failure type
  for "the backend didn't answer", with `status = 503` and code
  `E_AUTHZ_BACKEND_UNAVAILABLE`, and the original error kept as `cause`.

  Previously a raw `FgaError` from the OpenFGA SDK escaped to the caller. That
  broke the abstraction the package exists for: telling "backend down" apart
  from anything else meant importing `@openfga/sdk` at the call-site, and that
  code would break the day you switched drivers. It also meant a 500 where a
  503 belongs.

  **No `try/catch` is required.** With the status set, a standard exception
  handler answers on its own. Catch it only when a specific endpoint wants a
  specific response.

  The three outcomes stay distinguishable: no permission → `false`; invalid
  question → 422; couldn't ask → 503. Semantic errors are *not* reclassified,
  so an unknown role is still a 422 even while the backend is down.

  Every SDK call in the driver is covered by construction (the client is
  wrapped once, not call-by-call), so a future call site can't be forgotten.
  `provisionOpenFgaStore` and the importer are deliberately excluded: they are
  explicitly OpenFGA tools, so the SDK's own error is the most useful thing
  there and no abstraction leaks.

### Fixed

- **The "`authorize()` never throws" guarantee was overstated.** It holds for
  every *semantic* unknown (unrecognised permission, role without it, no valid
  assignment → `false`), but not for an **unreachable backend**. Found while
  documenting what the `openfga` driver implies; verified by pointing the
  driver at a dead port.

  Throwing is intentional and unchanged — only the error's type and status
  changed. A test pins it so it can't be "fixed" into a silent `false` without
  noticing what that costs.

### Added

- README: choosing the `openfga` driver adds a **second runtime dependency to
  every check** — something the `database` driver has no equivalent of, since
  authorization is available whenever your database is.
- README: there is **no distributed transaction** between your database and
  FGA. A grant validates the role against the local catalog and then writes
  the tuple; deleting that role afterwards orphans the tuple, but
  `authorize()` finds no permission→role mapping and denies, so the
  inconsistency fails closed.

## [1.0.1] — 2026-07-28

### Fixed

- **A failing `onWrite` hook no longer fails the caller.** The hook runs after
  the write has already been applied, so propagating its error reported a
  failure for an operation that did happen — and invited a retry of something
  already done. It is now logged and swallowed, which turns the documented
  contract ("the hook must not throw") into an enforced one.
- **`syncAuthzCatalog` is transactional.** A mid-way failure left the catalog
  half applied — roles without their permissions, i.e. holders with a role
  that grants nothing. Re-running fixed it thanks to idempotency, but until
  then authorization answered with less than the config said.
- **A holder without `uuid` now says so.** The engine identifies holders by
  uuid, not by the model's primary key; a numeric-PK model surfaced as an
  unreadable Knex error several layers down. It already failed closed — now it
  also explains why.

### Added

- The package has **its own test suite and CI**: 37 tests over in-memory
  SQLite with no host application (`npm test`), plus the same contract suite
  against a real OpenFGA server when `OPENFGA_TEST_URL` is set (64 tests
  total). Previously the suite lived in the consumer chassis, so the package
  could not verify itself.
- A test comparing the published migration stub against the schema the suite
  runs on, so the two can't drift apart unnoticed.
- README: the operational properties of the OpenFGA driver (expiry bound to
  the app server's clock) and the two things the `appAccess` middleware
  deliberately does not do.

### Changed

- **The OpenFGA driver reads before re-granting.** FGA can't delete and write
  the same tuple key in one transaction, so refreshing an expiry means two
  calls with a brief window where `authorize()` answers `false`. The driver
  now checks the current tuple first: a first grant is a plain write, an
  identical re-grant is a no-op, and only a real change to the expiry pays the
  window. Re-running a seeder no longer produces one. It costs one extra read
  per grant — writes are rare next to checks — and the semantics are unchanged
  (the contract suite still passes on both drivers).

  The read is strictly a **shortcut, never a precondition for writing**: if it
  fails, or if a concurrent writer wins the race between read and write, the
  grant still goes through. Skipping a write on incomplete information would
  be worse than the window it saves — the `onWrite` hook has already recorded
  the grant, so the audit log would claim something FGA never stored.

## [1.0.0] — 2026-07-28

First release, extracted from the [adonis7-base](https://github.com/JantStack/adonis7-base)
chassis where the engine was developed, hardened and security-audited.

### Added

- `AuthorizationDriver` contract with executable semantics: hierarchical
  scopes (downward-only inheritance), explicit denies that win, observable
  expiry, polymorphic holders, deny-by-default reads and idempotent writes.
- `database` driver — self-contained, engine-agnostic SQL over `authz_*`.
- `openfga` driver — facts in an OpenFGA server, expiry via FGA conditions;
  catalog and hierarchy stay local.
- Executable contract suite published at `@jantstack/adonis-authz/testing`
  so custom drivers are judged by the same cases.
- `configure` hook publishing the migration and both config files, plus
  `appAccess` middleware, provider, and the `openfga:provision` /
  `openfga:import` commands.
- Idempotent catalog sync with role `rank` metadata for consumer-side
  assignment policies.

### Security

- Scope keys are validated in the openfga driver: a type or uuid containing
  the separator could make two distinct scopes collide into one binding id,
  letting a grant in one scope authorize in another. The `database` driver is
  immune by construction (type and uuid live in separate columns).
- Catalog slugs are validated (no `~` or `|`) for the same reason.
- Reads fail closed: an errored deny check counts as denied, and batched
  checks verify completeness before granting.
