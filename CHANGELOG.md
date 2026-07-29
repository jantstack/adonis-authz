# Changelog

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
