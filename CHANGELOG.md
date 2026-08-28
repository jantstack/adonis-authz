# Changelog

## [Unreleased] — 2.0.0

### Breaking

- **`runAuthorizationDriverContract` has a new harness signature.** A harness
  written against 1.x no longer compiles. What changed and why:

  - `capabilities` (required) — what the driver *declares* it can do
    (`hierarchyFacts`, `transactions`, `truncationSignal`,
    `singleCheckAuthorize`, `injectableClock`, `exhaustiveLists`). The rule:
    every capability gets a pair of cases `{ whenTrue, whenFalse }` and there
    is **never a `skip`**. Today the pair exists for `truncationSignal` /
    `exhaustiveLists` (see below); the others arrive with their phase, and
    until then declaring one `true` makes the suite **throw at registration**
    — a promise without a judge does not pass. `exhaustiveLists: false`
    requires `limits.listMaxResults`.
  - `level` (optional, default `'core'`) — `'core'` runs the 1.x cases;
    `'2.0'` adds the tree-dependent cases below. Without this, every new case
    in the judge would be a major for third-party drivers. **`core` is not
    untouched**: `listSubjects`/`listScopes` now assert set equality instead
    of inclusion (a driver returning too much used to pass), the eight
    inheritance cases require the tree the harness hands to the driver (an
    unknown scope resolves to no ancestors — no implicit `app`), and three
    invariants that were never tested are now core cases: `rank` is metadata,
    a repeated `deny` does not duplicate, and `deny` before `grant` still
    blocks. A 1.x driver that honoured the documented semantics passes all of
    them; one that leaned on the flat default resolver does not — that was
    the point.
  - `makeDriver(tree)` now receives a `ContractScopeTree` and `makeTree()`
    (optional, default `memoryScopeTree()`, exported from `./testing`) builds
    it. Setup order is `cleanup → seedCatalog → makeTree → makeDriver(tree)`.

  **Problem.** The judge never mentioned the scope tree. The default ancestor
  resolver is flat (`anything → [app]`), no harness injected another one, so
  invariant 1 — the feature the README sells — was only ever tested with
  chains of length 2. Three cases passed for the wrong reason and five would
  have failed outright against a driver that materialises the tree as facts
  (the 2.0 `openfga` mode). **Decision.** The tree becomes an abstraction of
  the *contract*: the suite writes `await tree.attach(org, APP_SCOPE)` and the
  harness decides what is behind it (a `Map` walked by `resolveAncestors`
  today; backend facts in phase 3b). Zero conditionals in the cases. **What is
  not done.** No driver behaviour changed; the package still does not validate
  cycles or unknown scopes itself (phase 1 / 3b) — the test tree does, and
  throws.

### Added

- Eight contract cases rewritten over the tree (isolation, inheritance, close
  deny, `hasRole` inheritance, `listSubjects`, `listScopes`, `listRoles`,
  `listRoleScopes`), with `resolveAncestorsFrom(tree)` exported for
  harnesses. Verified: with the `attach` calls removed, the core cases
  "inheritance app → org", "close deny" and "`hasRole` inheritance" **fail**
  in both drivers (plus every 2.0 case that reads the tree) — they no longer
  pass by accident.
- Seven `level: '2.0'` cases, all green today on both drivers: two-level
  inheritance (app → org → unit), org grant confined to its subtree, deny
  inheriting downward only, `tree.move` changing the answer with **no other
  write** (both directions, and not touching what is inherited from app), and
  `list*` not enumerating inherited descendants on a real tree.
- Capability pair `truncationSignal: false`: with `exhaustiveLists: true`
  (`database`) 1,200 direct assignments are listed whole; with
  `exhaustiveLists: false` (`openfga`) the suite proves the **exact boundary**
  — `limits.listMaxResults` assignments come back whole (1,000 against a
  default server, 3 against the capped one in CI). One more than the cap
  would be returned truncated in silence: that is defect L0.7 and it is
  deliberately **not** encoded as accepted behaviour; its pair arrives in
  phase 1.
- Backend spies for the package suite (`withFailing`, `countCalls`) and a
  test pinning the current cost: `authorize` on a chain of three resolves
  ancestors **exactly once** in both drivers, and a failing resolver is an
  error, not a silent `false`.
- `check:purity` now runs inside `npm test` (so in the `test` CI job), with a
  second rule ready for opt-in modules: nothing under `src/<module>/` may
  import the manager or a driver. Both rules are exercised against temporary
  fixtures in the suite.
- CI runs the judge against **two** OpenFGA servers (`v1.19.0`): defaults, and
  `OPENFGA_LIST_OBJECTS_MAX_RESULTS=3` / `OPENFGA_LIST_USERS_MAX_RESULTS=3`
  exposed to the harness as `limits.listMaxResults`, so phase 1 can reproduce
  truncation with four tuples instead of a thousand.
- The `openfga` test harnesses delete the stores they create (one per test);
  they used to accumulate forever on the local server. One-shot cleanup
  script for orphans: `scripts/openfga_prune_stores.mjs --prefix contract-
  --prefix regrant- --prefix spies-` lists, and only deletes with `--force`.

### Security — phase 1, lot A (identity, errors, limits)

Nine defects reproduced by the security panels of 2026-08-28, closed one by
one, each with a case that was red before and green after. None of them
changes what a well-formed question answers; all of them change what a
malformed one, a failing dependency or a silent limit does. **Breaking** where
noted: input that used to be accepted (and persisted) is now a 422.

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
  `HIGHER_CONSISTENCY` by default (S17, S11).** All checks, `read`,
  `listObjects` and `listUsers` send `consistency: HIGHER_CONSISTENCY`;
  `consistency: 'minimize_latency'` in the driver options is the explicit
  opt-out.

  **Problem.** Deny checks went without `context`, which works only while deny
  tuples carry no condition; in the single-check `facts` mode (phase 3b) a
  missing context fails the whole decision (400 → 503), and `ListObjects`
  without it returns a server 500. Separately, an OpenFGA started with
  `--check-query-cache-enabled` turns Check into an eventually consistent
  API: a fresh `revoke` or `deny` kept granting for up to 10 s, while the
  contract promises "removing the deny restores". **Decision.** One
  `checkContext()` for every evaluated relation, and the package protects its
  own promise by asking for higher consistency; the operator's cache flag can
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

### Semantics — phase 1, lot B (what a well-formed question answers)

Six changes that alter answers, each reproduced by the panels of
2026-08-28 and closed with a case that was red before and green after, in
both drivers. All **breaking** — 2.0.0 ships no compatibility flags.

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
  deletes in batches of ≤ 100 and re-reads to prove zero — never
  `ListObjects`. The judge's `tree.detach` now calls `driver.purgeScope`
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
