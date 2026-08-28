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
