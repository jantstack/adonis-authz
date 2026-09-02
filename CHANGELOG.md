# Changelog

## [Unreleased] — 2.4.0-alpha.2 · relation expiry (R-15)

**The problem.** COGNITIV verified `2.4.0-alpha.1` against its nine requirements and got 7 ✅; one of
the two ❌ was **expiry on the relation tuple** (their requirement #5), which 2.4 had deferred to 2.6
on an assumption that turned out to be false for the customer. The owner decided to bring it forward.
It is **additive**: nothing published changes shape; a consumer that already migrated adds one
column (recipe below).

**The decision.** The same expiry the package already has for assignments, applied to the relation
tuple, at the same rigor and in both drivers:

- **`relate(subject, relation, object, partition, { expiresAt })`** — the three states of invariant
  10 (omitted preserves a live expiry and revives an expired one without expiry; `null` removes;
  `Date` sets), validated in the `RelationsManager` before the driver (422 `E_AUTHZ_INVALID_IDENTITY`),
  carried in `RelationRef`/`RelationWriteEvent` (`assertWrite` can refuse an open-ended share).
- **Strict expiry, one clock**: `expires_at > now` in SQL, `current_time < valid_until` in FGA; what
  expires *now* no longer counts. `check`, `listObjects`, `listSubjects` and `membersOf` filter it in
  both drivers, and a membership that expires stops granting through its userset at that instant.
  Both drivers implement **`withClock`** (capability `injectableClock`, a pair with two faces in
  `runRelationsDriverContract`: T−1 ms / T / T+1 ms, milliseconds, renewal and revival with an
  injected clock; the three states in real time without one). `RelationsManager` takes `clock`
  (the provider passes `config.clock`, the same clock as roles).
- **`database`**: `authz_relations.expires_at` (`DATETIME(3)` nullable, the 2.5 · J3 decision; read
  and written through `sqlExpiryCodec`, so MySQL is UTC-explicit regardless of the process TZ). The
  table stays **insert/delete-only** (judge's decision (c)): **renewing an expiry is delete+insert,
  never `UPDATE`**, and the suite observes it (the row changes its uuid; the same expiry, or an
  omitted one, leaves the row untouched). The recursive CTEs walk only live facts.
- **`openfga`**: every relation subject in the fused model (the holders and `group#member`) is also
  admitted `with not_expired` — the same condition as `role_binding#assignee`. `relate` reads the
  exact tuple first (one `Read`): absent ⇒ one `Write` (with the condition when it expires); same
  expiry ⇒ no-op; another expiry ⇒ delete + write in two calls (FGA cannot rewrite a tuple's
  condition, and an `Ignore` would keep the old expiry silently). `check`/`ListObjects` carry
  `current_time`; `listSubjects` filters client-side with the driver's clock; `purge*` delete
  everything, expired included.
- **`enumerateRelations` does not filter**: an expired tuple reaches the destination with its
  `expiresAt` and `reconcileRelations` counts it in **`skipped.expired`** (the declared loss of the
  migration, like `expired` in roles — reported, not drift); a live tuple travels with its instant
  (a different expiry in the destination is rewritten and counted in **`updated`**, never an
  `Ignore` that keeps the old one). The published reconcile contract gains one case per direction.
- **Parity**: the bridge spec asks both drivers the same questions with the same injected clock
  (T−1/T/T+1, renewal, expired membership, enumeration) and expects the same answers.

**The fused-model byte ceiling moves, measured.** The condition costs `(holders + 1) × (type name +
"not_expired")` bytes per declared relation — with three holders ≈ 103 B per relation. A
three-relation object type goes from ≈ 270 B to ≈ 579 B (≈ 1.0 of a realistic permission, was ≈ 0.5)
and `group` from 86 B to 191 B (≈ 0.34, was ≈ 0.15). With 447 realistic permissions the room for
three-relation object types drops from **52 to 24**; with one object type the permission ceiling
moves by one (472 → 471). The gate (`assertFactsModelPublishable`) measures the fused model as
before; the self-calibrated cases in the suite do not pin these numbers.

**Schema (additive).** `stubs/migration.stub` and the test mirror declare
`authz_relations.expires_at`. An installation that already ran the 2.4.0-alpha.1 migration adds it:

```ts
this.schema.alterTable('authz_relations', (table) => {
  table.datetime('expires_at', { precision: 3 }).nullable()
})
```

```sql
ALTER TABLE authz_relations ADD COLUMN expires_at timestamptz(3) NULL;   -- PostgreSQL
ALTER TABLE authz_relations ADD COLUMN expires_at datetime(3) NULL;      -- MySQL
ALTER TABLE authz_relations ADD COLUMN expires_at datetime NULL;         -- SQLite
```

The `openfga` store needs no tuple migration: republish the fused model (existing tuples carry no
condition and keep granting without expiry).

**Counts.** `runRelationsDriverContract` registers 19 cases per harness (was 17: the R-15 core case
plus the `injectableClock` face); the relations reconcile contract 11 (was 9). The judge's ~41 for
Phase 4 is now landed in full (`relations_harness.spec.ts`: nothing deferred), plus three cases R-15
added beyond his count (the two clock faces and expiry through reconcile).

**What is NOT done.** No `{trx}` on `relate` (still parity with `roles/`); no race handling between
two concurrent `relate` with different expiries (the last `Write` wins or is ignored as a duplicate
— the same posture as before R-15; roles' 409 re-read is not ported); `includes` with `from` still
deferred.

### Lot L-4b · the unique index of `authz_relations` now guards **holders** too (`subject_relation NOT NULL DEFAULT ''`)

**The problem.** Lot L-4 made a schema defect from lot 4-3 observable: the published unique index
`authz_rel_tuple_uq` includes `subject_relation`, which was **`NULL` for a holder** (only a userset carries one),
and on all three engines two `NULL`s are *distinct* in a unique index — so the index only guarded **userset**
tuples. Two concurrent `relate`s of the *same holder tuple* in two open transactions (each one's "does it exist?"
cannot see the other) both went in and committed **two identical rows**. No over-grant (`check` is the same
`true`, `unrelate`/`purge*` delete both), but `listSubjects`/`enumerateRelations` listed the subject twice and the
relations reconcile census counted it twice — invariant 6's idempotence held in sequence, not under concurrency.

**The decision (owner, 2026-09-02).** `authz_relations.subject_relation` becomes **`varchar(50) NOT NULL DEFAULT ''`**
(`''` = holder; a value = userset), in `stubs/migration.stub` and in the test mirror, and the `database` driver
**writes `''` for a holder, never `NULL`**. It is the only option with parity on the three engines: a partial unique
index (`WHERE subject_relation IS NULL`) does not exist in MySQL, and `UNIQUE NULLS NOT DISTINCT` is PostgreSQL 15+
only. Measured per engine, the default is declared as `''::character varying` (PostgreSQL `information_schema`),
`''` (MySQL `column_default`) and `''` (SQLite `PRAGMA table_info`); a row inserted without the column is a holder
`''`, an explicit `NULL` is refused, and the same holder inserted twice is refused by the index. The concurrent
case that L-4 left pinning the defect now **flips**: two `relate`s of the same holder tuple in two transactions
end in **exactly one row**, the loser gets **409 `E_AUTHZ_WRITE_CONFLICT`** on PostgreSQL/MySQL (the same wait on
the unique index as a userset: PostgreSQL leaves the loser aborted, MySQL undoes the statement) and 503
`SQLITE_BUSY` on SQLite (file), one event, `listSubjects` ×1, `enumerateRelations` ×1. Mutant: the column back to
nullable (or the driver writing `NULL`) ⇒ two rows ⇒ red.

**The partition trigger changes with it.** "Is a userset" is now `subject_relation <> ''`, not `IS NOT NULL` — with
`''` on holders, `IS NOT NULL` would fire on **every** holder (`subject_partition` is `NULL`, never equal to
`partition_key`). `NULL <> ''` is `NULL` (false) on all three engines, so an old `NULL` row nobody backfilled does not
fire either. Same text in `relationPartitionTrigger` (the package) and in the stub's inlined copy; a case pins the
holder with `''` and with the column omitted against the trigger.

**Reads tolerate an old `NULL` row (decision).** The backfill is the consumer's responsibility, so the driver does
not break on a row it did not write: `check`/`listObjects` (`COALESCE(subject_relation, '')`), `membersOf`
(`COALESCE(…) = ''` for holders), `listSubjects`/`enumerateRelations` (`''` *or* `NULL` ⇒ holder), and the WHERE
of `relate` ("does it exist?"), `unrelate` and `purgeSubject` for a holder match `''` **or** `NULL` — because an
`unrelate` that did not see the old row would leave it granting after the retirement (fail-open). The recipe's
executed test measures it: with the alpha.1 shape and a `NULL` holder row, the new driver answers `check` true,
lists the holder once, `relate` of the same holder is a no-op, and `unrelate` deletes the `NULL` row. **Writes do
not wait for the recipe, they are refused by it being missing (measured)**: until the trigger is re-created (step 4)
the old `IS NOT NULL` guard fires on every holder the new driver inserts (`''` with `subject_partition` NULL), so
every holder `relate` — new or a renewal — is 503 `E_AUTHZ_BACKEND_UNAVAILABLE` with the trigger's message, the
driver's internal transaction undone, fail-closed and loud. That is why the recipe belongs to the **same deploy**
as the package upgrade; it is idempotent (the suite runs it twice: same schema, same census, trigger still on).

**Schema recipe** for an installation that already ran the 2.4.0-alpha.1/alpha.2 migration — **executed by the
suite** (`upgrade_recipe.spec`, all three engines: the alpha.1 shape with `NULL` holder rows, including a
duplicated one, then the recipe verbatim from the README, then the engine's description of the column compared
with the mirror and the driver working on top). One statement per line; the trigger bodies carry `;` inside, so run
each line **whole**, never through a runner that splits on `;`. The recipe is in
[Upgrading from 2.4.0-alpha.2 (before L-4b)](./README.md#upgrading-from-240-alpha2-before-l-4b-authz_relationssubject_relation),
and it is four steps **in this order**: **(1) re-create the partition trigger** (PostgreSQL: `CREATE OR REPLACE
FUNCTION` of the guard, the trigger keeps calling it; MySQL and SQLite: drop and create the two triggers) — it goes
FIRST because the old `IS NOT NULL` guard fires on `''`, so with it in place **the backfill itself is refused by
the `BEFORE UPDATE` trigger** (measured on the three engines: the first draft had it last and the `UPDATE` died
with the trigger's message), **(2) de-duplicate** the holder rows the old index let through (keep the oldest `uuid`
per tuple — the backfill would otherwise hit the unique index itself), **(3) backfill** `NULL` → `''`, **(4)
`ALTER`** (`SET DEFAULT '' / SET NOT NULL` on PostgreSQL; `MODIFY … NOT NULL DEFAULT ''` on MySQL; **no
`ALTER COLUMN` in SQLite** — there the column stays nullable, the driver never writes `NULL` and the unique index
already guards `'' = ''`; recreate the table with the stub's DDL if you want the constraint itself). The `openfga`
driver needs nothing: a tuple is unique by construction.

**Counts.** +2 per mode: the two schema cases of the trigger group (explicit `NULL` refused; the same holder twice
refused by the index) run in the four modes, plus the DEFAULT/`column_default` case of `migration_stub.spec` and the
executed recipe of `upgrade_recipe.spec` (now also in SQLite). The concurrent holder case is flipped, not added.

**What is NOT done.** `openfga` is untouched (L-5). No `NULLS NOT DISTINCT`, no partial index, no generated
column. No automatic backfill from the package (a migration of the consumer's data is the consumer's, with the
recipe). The de-duplication keeps the oldest row per tuple: if the two rows raced with different expiries, the
survivor is the first written, not the longest-lived — both are legal outcomes of that race, and the recipe says so.

### Lot L-4 · `{ transaction }` for real in the `database` driver, relations port (the `{trx}` panel's verdict (C), §7 · L-4)

**The problem.** After L-3 the roles port wrote inside the caller's transaction and the relations port still
declared `transactionalWrites: false`: a consumer sharing a document and writing its own row in the same
transaction had the honest 500 and no driver that did it — the same gap L-3 closed for facts, one port over.

**The decision.** `DatabaseRelationsDriver` declares **`transactionalWrites: true`** (new option
`transactionalWrites`, default `true`; a pool-of-1 deployment declares `false`, exactly like the roles driver)
and `relate`/`unrelate`/`purgeObject`/`purgeSubject` write **inside the caller's open Lucid transaction** of the
driver's connection — *both or neither*, judged by census: after a rollback `authz_relations` holds zero new
tuples in the partition, for the four writes, on SQLite (file), PostgreSQL and MySQL; `purgeObject`/`purgeSubject`
delete and revert **together**. The same rule as L-3 — **the write goes through your transaction; the
authority never does** (the freeze barrier, F-05 and `assertWrite` throw before the first statement on your
transaction: a spy counts zero) — and the same guard (`assertCallerTransaction` against the driver's connection:
another connection, a `QueryClient` or the whole `db` are 500 `E_AUTHZ_CONFIG` before any statement). What is
specific to tuples, all pinned per engine:

- **With a transaction present, `relate` no longer opens its own** (the internal one of 4-3 that gave
  trigger+insert atomicity): the check-then-delete-insert runs on yours, so **the partition trigger fires inside
  your transaction**. A cross-partition userset row inserted on that same transaction by your own code is refused
  by the engine there; PostgreSQL then leaves your transaction aborted and the next `relate` of the package on it
  is a classified 503 (`25P02`), MySQL and SQLite leave it alive. The mandatory mutant — reopening the internal
  transaction with an external one present — turns the rollback case red (the row commits on its own).
- **Expiry × transaction (R-15)**: renewing an expiry is still delete+insert, now inside your transaction, and
  a rollback **returns the previous expiry** — the census holds the old row with its old uuid and its old
  `expires_at`, not the new one.
- **Two open transactions writing the same userset tuple**: PostgreSQL and MySQL make the second wait on the
  unique index and hand it **409 `E_AUTHZ_WRITE_CONFLICT`** when the first commits (PostgreSQL aborts it, MySQL
  only undoes the statement); SQLite (file) answers `SQLITE_BUSY` at once (503).
- **Deadlock A→B / B→A (the auditor's 🟡 12, closed)**: two transactions writing two tuples in crossed order. The
  engine picks a victim and the driver classifies it as **409 `E_AUTHZ_WRITE_CONFLICT`** ("roll back and retry";
  `isDeadlock`: PostgreSQL `40P01`/`40001`, MySQL `1213`) — never a hang, never the raw engine error, never a 503
  "did not answer" (it did). PostgreSQL detects it after `deadlock_timeout` (1 s) and leaves the victim aborted
  until the rollback (the winner waits for that rollback); InnoDB detects it at once and **rolls back the victim's
  whole transaction** (its earlier row is gone too), so the winner can resolve before the victim's error reaches
  the event loop — the case accepts both orders. SQLite cannot deadlock: the second writer is `SQLITE_BUSY` at its
  first write. A mutant that does not classify the deadlock fails on both engines with the 503.
- **Pool ≥ 2**, as in L-3: on `:memory:` the driver declaring `true` and a caller holding the only connection
  get 503 `E_AUTHZ_BACKEND_TIMEOUT` from the barrier at `freezeTimeoutMs`, with zero statements on the
  transaction; the default suite judges the `false` face, `sqlite-file`/PG/MySQL the `true` one.
- **The `true` face of the pair in `runRelationsDriverContract`** (declaring `true` no longer throws at
  registration): rollback ⇒ zero tuples by census for the four writes, commit ⇒ applied, the uncommitted write
  invisible to the authority, `purge*` reverting together, and three foreign transactions ⇒ 500 with a spy
  counting zero statements. New harness hook **`transactions?: RelationsContractTransactions`** (`begin()` +
  `census(partition)`), default `lucidRelationsContractTransactions()` (exported from `/testing`). One case per
  face: the literal count (20) does not move. The `openfga` harness keeps `false` explicit.

**A finding of the published schema, measured and NOT fixed here (owner's decision).** The unique index of
`authz_relations` (`authz_rel_tuple_uq`) includes `subject_relation`, which is `NULL` for a holder, and SQLite,
PostgreSQL and MySQL all treat two `NULL`s as distinct in a unique index: **it only guards userset tuples**. Two
concurrent `relate`s of the *same holder tuple* in two open transactions (each one's "does it exist?" read cannot
see the other) both go in, without waiting, and commit **two identical rows** — invariant 6's idempotency holds in
sequence, not under concurrency. It does not over-grant (`check` is the same `true`; `unrelate`/`purge*` delete
both by their `WHERE`), but `listSubjects`/`enumerateRelations` list the subject twice. It predates L-4 (4-3's
internal transaction was too short to make the race practical); L-4 makes it observable and pins it with a case.
Closing it is a schema change with an `ALTER` recipe — `subject_relation NOT NULL DEFAULT ''` (touching every
`IS NULL`/`COALESCE` of the driver), a partial unique index `WHERE subject_relation IS NULL` (PostgreSQL and SQLite;
**MySQL has none**, it would need a generated column), or `UNIQUE NULLS NOT DISTINCT` (PostgreSQL 15+ only).

**What is NOT done.** `openfga` still declares `false` and always will; its active refusal against a live server is
L-5. The README recipe by direction, the freeze sentence and the `resolveChain` limit's recipe are L-6. The holder
unique hole above is declared, not closed — **closed in lot L-4b** (above). No composition case with a consumer
table for relations (L-3's case covers the mechanism; the census does the rest).

### Lot L-3 · `{ transaction }` for real in the `database` driver, roles port (the `{trx}` panel's verdict (C), §1.2)

**The problem.** Since L-2 the capability existed and both drivers declared `false`: `{ transaction }` on a
fact write was an honest 500. A consumer who needs "the fact and my rows commit or roll back together" —
the reason the capability exists — had no driver that did it.

**The decision.** `DatabaseAuthorizationDriver` declares **`transactionalWrites: true`** and
`grant`/`revoke`/`deny`/`removeDeny` write **inside the caller's open Lucid transaction** — *both or
neither*, judged by census: after a rollback `authz_assignments`/`authz_denies` hold zero rows for that
holder, for the four writes, on SQLite (file), PostgreSQL and MySQL. The rule that governs it: **the write
goes through your transaction; the authority never does.** Through your transaction: the
`INSERT`/`UPDATE`/`DELETE` and the "does it exist?" read that belongs to it (a `grant` and its re-grant in
the same transaction see each other). Through the engine's own connection: the freeze barrier, the catalog,
`resolveChain`. Consequences, all pinned:

- **Pool ≥ 2 is a deployment requirement** (the owner's decision, 2026-09-01 (3)). With a pool of 1 the
  barrier cannot get a connection while you hold yours: 503 `E_AUTHZ_BACKEND_TIMEOUT` at `freezeTimeoutMs`
  with **zero statements** on your transaction. A pool-of-1 deployment declares
  `new DatabaseAuthorizationDriver({ transactionalWrites: false })` (new option, default `true`) and gets
  gate 1's immediate 500 instead — the driver declares what its deployment can do; the package does not
  guess the pool. The default suite (`:memory:`) judges that `false` face; the `true` face runs on
  `sqlite-file`/PG/MySQL.
- **Frozen + `{ transaction }` ⇒ 503 `E_AUTHZ_FROZEN` before the first statement on your transaction**
  (the two L-2 cases of `freeze.spec.ts` flipped for the capable driver; the caller's snapshot is still
  never consulted).
- **Whose transaction it is** is checked in the driver with `assertCallerTransaction` against the primary
  connection: another connection (a real second connection in the suite), a `QueryClient` or the whole
  `db` are 500 `E_AUTHZ_CONFIG` before any statement.
- **Two concurrent `grant`s of the same fact in two open transactions, measured per engine.** PostgreSQL
  and MySQL make the second `INSERT` wait on the unique index until the first transaction ends; when it
  commits, the loser gets **409 `E_AUTHZ_WRITE_CONFLICT`** ("poisons your transaction: roll back and
  retry") — outside a transaction the driver re-reads and keeps the winner's row (2.5-B · K4); inside
  yours it must not: PostgreSQL has already **aborted** the transaction (`25P02` until the rollback) and
  under REPEATABLE READ (MySQL's default) the re-read would not see the winner. A mutant that re-reads
  fails differently on each engine (503 by `25P02` on PG; the raw 503 of the insert on MySQL). SQLite (file,
  WAL) does not wait: the second writer gets `SQLITE_BUSY` at once (503) and its transaction lives on.
- **A deadline that elapses inside your transaction.** PostgreSQL cancels the query and leaves your
  transaction aborted; MySQL kills it and your transaction lives on; SQLite cannot elapse one (synchronous)
  and answers `SQLITE_BUSY`. What `onWrite` publishes there (invariant 13 vs the auditor's 🟡 12):
  **`indeterminate: true` stays**, and the event carries **`transactional: true`** — the rollback does
  determine the outcome, but the rollback is the caller's and the package never sees it. `transactional:
  true` is on every event of a write inscribed in the caller's transaction (`AuthzWriteEvent.transactional`,
  additive): at that instant the row exists only inside it. Enqueueing through `scopes.*` does not carry it.
- **The `true` face of the pair in `runAuthorizationDriverContract`** (all levels): rollback ⇒ zero rows by
  census for the four writes, commit ⇒ applied, the uncommitted write invisible to the authority, and three
  foreign transactions ⇒ 500 with a spy counting zero statements. New harness hook
  **`transactions?: ContractTransactions`** (`begin()` + `census(subject)`), default
  `lucidContractTransactions()` (exported from `/testing`: Lucid's `db.transaction()` + `authz_*`), for a
  third-party driver with another connection or other tables. Declaring `true` no longer throws at
  registration; the literal counts do not move (one case per face). The `openfga` harness pins `false`
  explicitly.
- **Exported.** `isUniqueViolation` stays internal (`src/shared/backend_guard.ts`).

**What is NOT done.** `relations/` (`relate`/`unrelate`/`purge*`) still declares `false` — lot L-4.
`openfga` still declares `false` and always will; its active refusal against a live server is L-5. The
README recipe by direction, the freeze sentence and the `resolveChain` limit's recipe are L-6 (the limit
itself is stated). `resolveChain` still does not receive the transaction (§6.2: creating a scope and granting
on it in the same transaction is 422, fail-closed). The delegation API still refuses `{ transaction }`.

### Lot L-2 · the `transactionalWrites` capability and its two gates, on both ports (the `{trx}` panel's verdict (C))

**The problem.** `{ transaction }` on a fact write did not exist in the types and, since L-1, was silently
ignored at runtime: a consumer could pass it to `grant` and believe the fact would roll back with its
rows. The roadmap's answer — *"the manager fails to construct if the driver does not support it"* —
was rejected by both panelists: it makes `openfga` unconstructible in any app that merely registers
it, and the driver is resolved lazily and by name, so at construction time nobody knows whether
`{ transaction }` will ever be passed. And the only honest promise `openfga` can make is *"I cannot,
and I tell you before writing anything"*: a tuple does not enter a SQL transaction — no 2PC.

**The decision.** The capability **`transactionalWrites`**, same name on `AuthorizationDriverCapabilities`
and `RelationsDriverCapabilities` (a third-party driver does not learn two), meaning **exactly** *"both
or neither with YOUR transaction"* — never *"not lost"*; no intermediate value is published. And two
gates instead of "fails to construct":

- **Gate 1, per call, always on.** `{ transaction }` on `grant`/`revoke`/`deny`/`removeDeny` or
  `relate`/`unrelate`/`purgeObject`/`purgeSubject` with a driver that declares `false` (or nothing) is
  **500 `E_AUTHZ_UNSUPPORTED`** naming driver and operation, with **zero driver calls** (a spy proves
  it in both contract runners) and no `onWrite`/`onRelationWrite`. 500 and not 422 by precedent
  (`membersOf`, `purgeRole`): it is not a malformed question, it is a deployment that does not match
  what was asked of it; the message carries the way out.
- **Gate 2, per config, opt-in.** `requireTransactionalWrites: true` (root; `relations.requireTransactionalWrites`
  overrides it for the relations port, otherwise inherited like `requireActor`) with a driver that
  declares `false` is **500 `E_AUTHZ_CONFIG` when the driver is resolved** — reads and `manager.driver()`
  included, the `RelationsManager` at construction: the deployment does not start, in the whole fleet,
  instead of failing on a rarely-travelled route.

**Declared in the types, with the docblock that keeps two promises apart.** `WriteOptions.transaction`
(the four fact writes; the port's `revoke`/`deny`/`removeDeny` now receive `options` like `grant`) and
`RelationTransactionOptions.transaction` (`RelationWriteOptions` extends it; `purgeObject`/`purgeSubject`
take it on the port and on the manager). **Enqueueing ≠ writing**: `scopes.attached/moved/detached`
already carried `transaction` with *another* meaning — *put the ENQUEUE in my transaction* — and that
notification does **not** pass through the capability gate (an `openfga` driver accepts it). The
delegation API (`defineScopedRole`/`updateScopedRole`/`deleteScopedRole`) **refuses** `{ transaction }`
with 500 `E_AUTHZ_UNSUPPORTED`: the catalog is written through `withAuthzCatalogWrite`, which *is* the
cross-process serializer (invariant 14); moving it into the consumer's commit would defeat it.

**The runners judge both faces — and this is the only pair where both are mandatory.** In
`runAuthorizationDriverContract` the harness capability `transactions` (a placeholder since 2.5) is
**renamed `transactionalWrites`** (pre-release; update your harness), it registers its `false` face at
every level (it is manager composition over `driver.capabilities`, so a `core` third-party driver observes
it too), and the closing guard now fails for `transactionalWrites: false` without a `whenFalse` case as
it already did for `true` without `whenTrue` (`uncoveredCapabilities`, judged in pure). In
`runRelationsDriverContract` the pair has its two faces; declaring `true` is rejected at registration
until the next lots bring the case. Literal counts move by one at every level (core 41, 2.0 54, 2.1 72,
2.2 83; relations 20 with 8 capabilities). **Both drivers of the package declare `false` today** — the
real write inside the caller's transaction in `database` is the next lots, and until then declaring
`true` without doing it is exactly what the panel forbids.

**Exported.** `assertCallerTransaction` (with `CallerTransaction`/`CallerTransactionOwner`) from the
package root: the single check a driver with `transactionalWrites: true` runs against *its* connection.

**What is NOT done.** No driver writes inside the caller's transaction yet (`database` roles and
relations are the next lots; `openfga` never will). No README recipe by direction for `openfga`
(permissive writes after commit, restrictive before) — it is documentation of the docs lot. No
`requireTransactionalWrites` on `RelationsManager` built by hand beyond the option itself (the provider
wires it).

### Lot L-1 · whose connection is this, and who decides the barrier (the `{trx}` panel's 🟠 8, 🟠 9 and J1)

**BREAKING (deployment):** `scopes.attached/moved/detached` with `{ transaction }` **require a
connection pool of at least 2**. With a pool of 1 — SQLite `:memory:`, the suite's default mode —
the notification now answers **503 `E_AUTHZ_BACKEND_TIMEOUT`** at `freezeTimeoutMs` (new config,
default 5000 ms) instead of going through. No API changes; a deployment on a single-connection pool
that used the outbox inside its transaction has to raise the pool (the three rollback cases of the
suite that demonstrate the outbox against a real OpenFGA moved to `sqlite-file`/PostgreSQL/MySQL for
that reason, and a dedicated case pins the 503 in `:memory:`).

**The problem (🟠 8).** Since 2.3 the freeze barrier — the `SELECT` on row `id = 2` that precedes
every write — was read **through the caller's `transaction`** when one was passed, "so a pool of 1
would not deadlock". That made the authority a decision of the caller: a client that answers "not
frozen", or, in production, the snapshot of a transaction opened *before* the freeze (InnoDB's
REPEATABLE READ; PostgreSQL under that level; SQLite in WAL), let the write in while every other
process got 503. Measured on all three engines. Worse: `GrantOptions` never declared `transaction`,
but `#writeOptions` read it with a cast, so a `{ actor, transaction }` object (which compiles: TS only
rejects the fresh literal) smuggled the bypass into `grant`/`revoke`/`deny`/`removeDeny` too.

**The decision (the judge's rule).** *The write travels in your transaction; the authority that
decides whether you may write never does.* `readFreezeRow` no longer accepts a client: the barrier is
read through the engine's connection, always, and the cast is gone — `transaction` is only consumed
by the types that declare it (`ScopeTreeWriteOptions`, to **enqueue**, never to decide). The price is
the deployment break above, and it is fail-closed: the freeze reads now carry a **total** deadline
(`withDeadline` over `guardSql`), because knex's `timeout()` only starts once the query has a
connection — with the pool exhausted the wait was governed by `acquireConnectionTimeout`, **60 s
measured**, not the 5 s the barrier declared. The case pins that the 503 arrives at the barrier's
deadline, not the pool's. The mutant — reading the barrier through the caller's client again — turns
the injected-client case red in `:memory:` and the snapshot case red in MySQL.

**The problem (🟠 9).** `sqlScopeOutbox` with a `trx` returned the `trx` as is and **ignored
`connection`**: with the queue on a named connection and the caller's primary-connection transaction,
the row was inserted in the caller's database — loud if the table is missing (503), **silent if it
exists** (a copied migration, a cloned environment), where no relay reads it and `dead()` never
shows it. And the whole `db` service passed the duck-check (`.from`/`.table`) and wrote **outside any
transaction**, in silence: the entire mitigation switched off without a warning.

**The decision.** One reusable check, **`assertCallerTransaction(operation, transaction, { connection })`**
(`src/shared/transaction_guard.ts`): an open Lucid transaction (`isTransaction === true`) of the
writer's own connection (`connectionName`), or 500 `E_AUTHZ_CONFIG` naming the operation and both
connections, before any statement. `db`, a `QueryClient` and a foreign-connection `trx` are all
rejected; a double without `primaryConnectionName` is still required to be a transaction. It is the
rule the judge asked for the `{ transaction }` port of lots L-3/L-4 (`grant`/`relate` in
`database`): "both or neither" is only true on the same connection.

**The problem (J1).** Nothing in `src/relations/` or in `authz:relations:reconcile` looked at the
freeze: during a cutover role writes got 503 and relation writes went in, and a relations reconcile
pass certified a state that could change underneath.

**The decision.** `assertNotFrozenRow` (`src/freeze.ts`) is the barrier, and it is now **the same
function** for both engines: `RelationsManager.relate`/`unrelate`/`purgeObject`/`purgeSubject` call
it first (503 `E_AUTHZ_FROZEN`, retryable, before validating anything; reads untouched; the
provider passes `freezeTimeoutMs`). `authz:relations:reconcile` runs its writing pass under the
durable window through `runRelationsReconcile` (the command; `reconcileRelations` itself cannot see
the roles manager, purity rule 2): `withFrozenWrites` now takes `{ kind, operatorAsContext }` and
hands the pass the window (`fence`, `leaseMs`, `lapsed()`), so the report publishes
`frozen: { durable, lapsed, leaseMs, fence }` and **`lapsed: true` fails the command** (the pass is
not certified) — `--dry-run` does not freeze, an operator window is context, another pass's freeze
is 423. The mutant (no barrier in relations, no window in the command) turns four cases red.

**What is NOT done, and why.** `check`/`listObjects`/`listSubjects`/`membersOf` are not frozen
(reads never are). `manager.driver()` and `relationsManager.driver()` remain the documented way out.
`syncAuthzCatalog` is still not frozen (unchanged from 2.3). The barrier's own deadline is not a
per-call option — it is `freezeTimeoutMs` in the config, one value for both engines. The relation
drivers themselves do not read the freeze (the barrier is the manager's, as in roles). And the
`{ transaction }` port of `grant`/`relate` is still lots L-3/L-4: this lot only closes the holes
that exist today, before that port multiplies their surface.

### Lot L-0 · F-05 gets teeth in BOTH relations drivers (the `{trx}` panel's 🔴 2)

**The problem.** F-05 — *`relate`/`unrelate` only accept an `object.type`/`relation` declared in
`defineRelationsConfig`* — is what closes, by construction, the escalation Phase 4 found: in the
shared `openfga` store, `relate(evil, 'assignee', { type: 'role_binding', id: <roleUuid> }, S)`
composes byte for byte the id of a real role binding. But it lived **only in the `RelationsManager`**.
Neither `openfga_relations_driver.ts` nor `database_relations_driver.ts` checked `hasType`/`isDeclared`
(only the id grammar, R-16), while the port's docblock in `types.ts` **published that the drivers
re-validated it "for defence in depth" — false in both**. Worse, `reconcileRelations` writes with
`to.relate(...)` — through the *driver* — so the Phase 4 premise ("one validation every write path
funnels through") did not hold: a tuple of an undeclared type in the source was reported in
`modelDrift` and **written anyway**. The auditor measured it against the server: one call to the
relations port through the driver and `roles.authorize(evil)` went from `false` to `true`.

**The decision.** One function, three callers. `assertRelationDeclared(config, object, relation)`
(exported from `define_relations_config.ts`, pure) is now what the manager calls first **and** what
both drivers call at the top of `relate` and `unrelate`, before any `Read`/`Write`/`INSERT` — same
class, same `code`, same message, so the manager's cut and the driver's net cannot disagree. The
bridge spec's "red reproduced" case (which *asserted* the escalation through the driver) becomes the
L-0 case: 422 `E_AUTHZ_RELATION_TYPE_UNKNOWN`, zero `Write`/`Read` (spy on the client),
`authorize(evil)` still `false`, alice's binding intact, and `unrelate(alice, 'assignee',
role_binding)` refused too (it would be a revoke through the relations door) — measured against the
`:8101` in the same store. Parity: the same four attempts (two undeclared types, an undeclared
relation of a declared type, an undeclared relation of the built-in `group`) get the same
`status:code` from both drivers, in `relate` and `unrelate`; per-driver specs spy on the injected
connection (`database`: zero `connection()` calls) and on the FGA client (`openfga`: zero
`read`/`write`). **Mutant**: removing the guard from either driver puts the exploit case back in red
with the escalation literal (`expected true to be false` on `authorize(evil)`), and the parity case
red on the other side.

**`reconcileRelations` funnels through the same validation.** With `toConfig`, a live source tuple
whose type or relation the destination does not declare is discarded **before** the driver and
counted in **`skipped.undeclared`** (dry-run and real pass give the same numbers; the type still
shows in `modelDrift`); without `toConfig`, the destination driver's own 422 funnels it
(`relateOrSkip` catches exactly `RelationTypeUnknownError`/`RelationUnknownError`, nothing else) and
it is counted the same, discounted from `written`/`updated`. Such a tuple also no longer *backs* a
matching one in the destination: it is `extra`, and `--prune` sweeps it. `authz:relations:reconcile`
prints it as an **error** and exits ≠ 0 — unlike `expired`, it is a live relation that did not
arrive. The docblock in `types.ts` is now true (kept, made precise); the README stops saying that
`manager.driver()` skips F-05.

**What is NOT done, and why.** The published `runRelationsDriverContract` does not plant the
driver-level case (it plants it through the manager): adding it would make the in-memory double
validate too and change the contract for third-party drivers — a decision for the owner, not for
this lot. `check`/`listObjects`/`listSubjects`/`purge*` do not apply F-05 in the drivers: they are
reads (and a purge of an undeclared object finds nothing to purge) and were outside the acceptance
criteria; a `check(evil, 'can_<P>', { type: 'scope', … })` through `manager.driver()` would read a
roles decision through the relations port but cannot write one. Without `toConfig`, `--dry-run`
cannot anticipate the driver's rejection and reports the tuple as `written`; the command always
passes the persisted config when it can read it.

## [2.4.0-alpha.1] — 2026-09-01 · the 2.x release (summary)

This is the reader's guide to the jump from **1.1.0** to **2.x**, for anyone who did not follow the
release batch by batch. It is an overview: the per-phase notes below (2.4.0 → 2.0.0) keep the
batch-by-batch detail and the *why* of every decision, and nothing here replaces them. **2.x is a
single breaking release over 1.x** — no compatibility flags, because there were no external
consumers to keep. Every claim in the README is backed by a case in the executable contract suite,
which both drivers pass, case for case.

**What the release is, phase by phase.**

- **Security lot + `scopes.*` (2.0).** Closes the fail-open defects reproduced in 1.1.0: the flat
  `[APP_SCOPE]` fallback is gone (an unknown scope denies and refuses writes, never invents a root),
  identity is a validated grammar in the manager *and* every driver, enumerations page the whole
  result (no truncated-deny fail-open), `expiresAt` has three honest states, and the scope tree
  became a contract fact you notify (`scopes.attached/moved/detached`) with anti-cycle and existence
  validation in the package.
- **Engine primitives (2.1).** `within` containment and `requireWithin`, `actor`/`requireActor`,
  `authorizedScopes` (the one enumeration that walks descendants, never `all` with live denies),
  `effectivePermissions`, `authorizeMany`, `listDenies`, and the `descendantsOf` consumer port.
- **Roles by scope — `catalog/` (2.2).** Roles are global or **local to an owner scope**
  (`owner_scope_key`); a local role is visible only where its owner is in the chain. Delegation API
  (`defineScopedRole`/`updateScopedRole`/`deleteScopedRole`) with an actor policy, `assignableAt` as
  a composition control, `purgeRole`, and role identity by **uuid** (ambiguity by slug is an error,
  not a resolution rule).
- **`openfga` = `facts` + `reconcile` (2.3).** One driver, one shape: the `resolver` mode is gone,
  `authorize` is a single `Check` against a model that carries your catalog, and the scope tree
  lives in the store anchored by a root marker. `authz:reconcile` is the **only** migration and
  verification primitive (`openfga:import` was removed), with a durable fleet-wide freeze and a
  cutover window (`authz:freeze`/`authz:unfreeze`).
- **`relations/` — ReBAC (2.4).** Object-level sharing (the Drive case) in a separate port and
  façade, with a **mandatory partition** in every object id, built for both drivers in a shared,
  fused OpenFGA model.
- **`http/` — `resourceAccess` (2.5).** A resource-level middleware that composes `authorize`;
  its response order (401 → 403 gate → 404 container → 404 resource → `authorize`) is the security
  property, and it refuses `role` like `appAccess`.

**BREAKING, grouped (the detail and rationale are in the per-phase notes below).**

- **No flat scope fallback.** An unresolved scope denies reads and rejects writes (422
  `E_AUTHZ_UNKNOWN_SCOPE`); there is no `[APP_SCOPE]` default. Without a resolver only `app` exists.
- **`appAccess({ role })` removed.** A gate over membership could not be denied; passing `role` is a
  500 with the recipe. `resourceAccess` inherits the same rule.
- **Identity is validated everywhere.** Types and uuids are lowercase grammar (`[a-z0-9._-]`);
  upper-case ids, `{ type: 'app', uuid ≠ null }`, the sentinel uuid outside `app`, malformed slugs
  and a bad `expiresAt` are 422 before any backend call.
- **`expiresAt` semantics changed.** Omitting it preserves a live expiry (an expired assignment
  revives without one); a re-grant "to be safe" no longer makes a temporary access permanent.
- **A scope that does not reach the root grants nothing** (`facts`). An `attached` not yet relayed
  is a temporary fail-**closed**, the opposite sign of the old behaviour — the fail-open the audit
  hunted, closed by the model's `rooted` relation.
- **`openfga` driver reshaped.** `hierarchy: 'resolver'` and `openfga:import` are gone; a store
  written by 1.x/2.0–2.1 (slug in the binding id) is **not read** by 2.2+ — its facts grant nothing
  and `authz:reconcile` clears them (`--prune`). Binding ids carry the role **uuid**. The driver
  refuses to construct without an `outbox` (or explicit `acceptScopeDriftRisk: true`).
- **Role identity is the uuid.** Slug ambiguity across owners is 422 `E_AUTHZ_AMBIGUOUS_ROLE`, not
  "nearest owner wins".
- **Schema jump.** New `authz_catalog_version` (shared version + durable freeze row), `owner_scope_key`
  and `assignable_at`, `authz_relations`/`authz_relations_config`, identity columns are
  `varchar(64)` `utf8mb4_bin` (not `uuid`), and `expires_at` is `DATETIME(3)`. See
  [Upgrading from 1.x to 2.x](./README.md#upgrading-from-1x-to-2x) — the recipe is executed by the
  suite.

**Deferred to 2.6 (not in this release, on purpose).**

- **`{ trx }` in `GrantOptions`** and `onWriteInTrx` (the `transactions` capability): a write that
  enlists in the caller's Lucid transaction.
- **`from` in `relations/`** (usersets that walk another relation) — 2.4 ships `includes` and
  one-level usersets only.
- **Relation expiry (R-15).** `authz_relations` is insert/delete-only; time-boxed shares wait.
  *(Landed in 2.4.0-alpha.2 — see the entry above; the table stays insert/delete-only.)*
- Also deferred: the file reorg into per-module folders and per-module migrations (cosmetic,
  high-risk right before the release), read-only Lucid models (documentation).

## [Unreleased] — 2.4.0

Phase 4 of the 2.0 roadmap: **`relations/` — generic ReBAC**, object-level sharing (the Drive
case) alongside role-based `authorize`. A separate port (`RelationsDriver`), façade
(`RelationsManager`) and config (`defineRelationsConfig`), judged by its own contract runner
(`runRelationsDriverContract`, published in `/testing`) — not a level of the roles runner, so the
roles counts (core 40 / 2.0 53 / 2.1 71 / 2.2 82) do not move. Every `Lot 4-*` belongs to this
cycle.

**The problem.** A tenant needs to share individual objects — *this document with that user as
`viewer`, with that team as `editor`* — which roles-and-scopes does not express: roles grant over a
scope subtree, not over one object. ReBAC (relationships between subjects and objects, à la
Zanzibar) does, and OpenFGA already runs underneath the `facts` driver.

**The decision.** Build it for both drivers at equal rigor, in the **shared** OpenFGA store and the
**fused** model (owner's decision, 2026-08-31): `relate`/`unrelate` are writes to the same store,
`check` is a single `Check`, and the `document`/`group` types are disjoint from `scope`/`role`. The
measured cost is one **shared model budget** — the 262,144-byte ceiling holds both permissions
(~450 realistic) and object types (each ≈ 0.46 of a permission; `group` ≈ 0.1) — and the fused-model
gate (`assertFactsModelPublishable`) watches it: a `defineRelationsConfig` that would overflow is 500
`E_AUTHZ_MODEL_TOO_LARGE` before publishing. Partition (tenant) is **mandatory** on every operation
and lives in the object id, isolating tenants by string comparison (and, in `database`, a
per-dialect partition trigger as defense in depth).

**The 🔴, closed by construction.** The security audit reproduced an escalation against the real
server: in the shared store a naive `relate(evil, 'assignee', { type: 'role_binding', id }, S)`
composed the id of a real binding and made `roles.authorize(evil, …)` true. It is closed **by
construction**, not by a check: `defineRelationsConfig` refuses to declare a reserved `facts` type
or relation (⚪4), and the `RelationsManager` refuses `relate`/`unrelate` on an undeclared
type/relation **before touching the driver** (F-05, 422 `E_AUTHZ_RELATION_TYPE_UNKNOWN` /
`E_AUTHZ_RELATION_UNKNOWN`) — so the driver never composes a `role_binding` id and the collision
does not exist. The published contract plants the exploit: a third-party relations driver that does
not enforce F-05 does not pass. F-05 is a chokepoint (every write path funnels through it);
`manager.driver()` skips it, like every barrier.

**What is NOT done, and why.**
- **Relation expiry (R-15) is not in 2.4** (owner's decision). `authz_relations` is
  insert/delete-only, no `expiresAt`; time-boxed shares are **deferred to 2.6** (an additive
  `expires_at` column plus the `BEFORE UPDATE` trigger the driver already carries). With R-15 out,
  the "renew = delete+insert" driver case is moot and the honest landed case count is ~39, not the
  judge's ~41 target (the two-case gap is exactly R-15 and renew).
- **`includes` with `from`** (cross-object inheritance, `viewer from parent`) is deferred to 2.6+:
  it adds a TTU between object types and forces re-measuring depth (today includes + one userset
  level are 2–4 fixed hops, and `can_<P>` depth stays at 22, measured on the fused model).
- **`{trx}` on `relate`/`unrelate`** stays deferred (parity with `roles/`, 2.6+); the `database`
  driver uses a transaction internally for trigger+insert atomicity but does not expose it.
- **`membersOf` is `database`-only** (transitive membership via a recursive CTE); in `openfga` it is
  500 `E_AUTHZ_UNSUPPORTED` — the transitive form is `ListUsers`, which truncates — declared as a
  capability with its negative case, never a skip.

Lots: **4-1** fused model + generator + fused byte gate + ⚪4/F-04 at model level · **4-2** the
`RelationsDriver` port + `defineRelationsConfig` + F-05 + `membersOf` + `runRelationsDriverContract`
· **4-3** the `database` driver (recursive CTE + per-dialect partition trigger, insert/delete-only)
· **4-4** the `openfga` driver (shared store) + the 🔴 proven green + `listObjectsTruncation` ·
**4-5** the boundary with teeth (F-01/F-02) + the `defineRelationsConfig`↔`syncAuthzCatalog` race +
relations `reconcile` + persisted relations config (`authz_relations_config`, under the version
gate) · **4-6** the two design cases (Drive-style sharing + COGNITIV keys) with example consumer
tables, the judge's literal count landed in `relations_harness.spec.ts`, the
`authz:relations:reconcile` platform command, and this entry.

## [Unreleased] — 2.3.0

Phase 3b of the 2.0 roadmap: the `openfga` driver becomes the `facts` mode —
the scope tree lives in OpenFGA and `authorize` is a single `Check` — plus
`authz:reconcile`, the idempotent migration between drivers. Every `Lot 3b-*`
below belongs to this cycle, and the contract suite judges them at
`level: '2.3'`.

Phase 3 (**2.2**, everything from `Lot 3A` down) is included here because
neither has shipped yet: `catalog/` — roles global or local to a scope.
Lot 3A below is the prerequisite: the internal identity of a role is its
**uuid** in both drivers, and the OpenFGA binding ids carry that uuid. No
answer of the contract changes (the judge passes identically); the store
format does. Lot 3B adds the owner, and lot 3D makes that uuid the identity
of a role in the **public port** too.

### Lot 3b-8 · the end-of-phase code review: five fail-opens, three loss/availability defects, two boot defects — each with its red case

The high-level `/code-review` of the whole branch confirmed ten defects. Fail-open first, then
data loss, then boot; every one reproduced red against the real server before the fix.

- **A1 — `authz:catalog:sync` now rewrites the derived projection through the active driver.** The
  README sold that command as the recovery path of a `facts` deployment, but it called
  `syncCatalogs` without the driver's projection: `authz_*` came out right and the store's mirror
  untouched, so a permission removed from the catalog **kept granting** and a new role granted
  nothing. `catalogProjection?()` is now part of the driver port (optional, like
  `projectCatalogRole`), and the command's decision is a pure exported function
  (`catalogSyncOptions`, the `reconcileLines` pattern) with its case against the real server.
- **A2 — migrating a 2.2 store no longer loses its explicit denies.** The `resolver` mode kept
  denies in `deny_binding:<scopeKey>|<permissionUuid>#denied` objects, which (c2r) does not even
  declare; `enumerateFacts` dropped them with the rest of the "structure" — invariant 2 broken
  with the verifier green and nothing in any counter. They are now **emitted as denies** (the
  catalog translates the permission uuid; what it cannot translate is counted, never silent),
  which is what makes `reconcile` the honest substitute of the deleted importer.
- **A3 — a retried `scopes.moved` also sweeps.** The idempotent shortcut of `reparent` (edge
  already the wanted one) skipped `sweepLocalRoleBindings`: a `moved` whose first attempt wrote
  the edge and died before the sweep never ran invariant 18's sweep on retry — tenant A's local
  role kept granting in tenant B's subtree, with the relay green. The shortcut now sweeps too
  (zero requests without local roles, as always).
- **A4 — `revoke`/`removeDeny` on a scope the tree no longer knows cover every spelling the uuid
  can alias** (`canonicalScopeTargets`, shared by both drivers). With the caller's spelling alone
  plus `onMissingDeletes: Ignore`, a dash-less alias made the delete a **silent no-op** and the
  canonical fact granted again if the scope was restored — the same hole 3b-2h closed in
  `scopes.detached`, one call-site over.
- **A5 — the anti-cycle check also walks the STORE's tree.** The consumer-chain check cannot see a
  store desynchronized by an out-of-order outbox (a parked `moved` plus the later inverse move): a
  new edge, legal for the consumer, closed a **real cycle** in the store, which OpenFGA evaluates
  without complaint (bidirectional inheritance, the measured fail-open of cruce 3).
  `reparent` now walks the new parent's store chain before the `Write` and refuses with 422
  `E_AUTHZ_SCOPE_CYCLE`; the cost is O(depth) reads per tree change, off the hot path.
- **B1 — the mass-delete guard counts *usable* facts, not raw rows.** The counter was incremented
  before each skip, so a source whose facts were **all discarded** (expired, unknown scopes — the
  signature of a blind resolver or the wrong store) disarmed `E_AUTHZ_MASS_RECONCILE_REFUSED` and
  `--prune` emptied the destination with a green report. Fixed in **both directions**, and the
  error now says how many facts were read and discarded.
- **B2 — `expired` no longer pins `authz:reconcile` at exit 1 forever.** Both directions count
  already-expired assignments in `skipped['expired']` and nothing sweeps expired rows out of the
  source (observable expiration without a scheduler, on purpose), so the CI verifier this
  changelog promises green was unreachable with real data after the first expiry. `expired` is
  the migration's one **declared** loss: still reported, no longer drift. Expired facts left over
  in the *destination* are still drift (`extra-fact`) and `--prune` is their sweep.
- **B3 — the freeze barrier is re-asserted mid-pass.** `relayScopeChanges` checked the durable
  freeze once on entry and then applied up to 10,000 tree writes without looking again — a freeze
  acquired mid-drain did not stop the rest of the pass, and those writes appear in no counter of
  the certified pass. The documented trade-off covers "a write already past its barrier", not a
  pass of 10,000. The barrier is now re-asserted **per batch** (one `id = 2` read per batch; the
  0.14 ms/write cost was already measured and accepted), and `pruneOrphanRoles --force` re-asserts
  **per purge** with the frozen 503 travelling inside `PruneInterruptedError` so the list of what
  was already purged travels with it.
- **C1 — a freshly scaffolded app in `openfga` mode boots.** The config stub signed
  `acceptScopeDriftRisk` only inside the driver factory, but the drift gate that fires per request
  is the **manager's** and reads `config.scopes.*`: every request was a 500
  `E_AUTHZ_SCOPE_DRIFT_UNGUARDED` until you hand-edited config the stub's comments never
  mentioned. The stub now signs it in `scopes` too, with the same "switch to the outbox" note.
- **C2 — `purgeScope` also purges the `scope#binding` edge of a role the catalog no longer
  declares at that level.** The sweep is not atomic with the catalog: a role whose row was deleted
  (or changed `scope_type`) between the commit and the purge left an edge step 1 cannot see and
  the zero-proof counts — `E_AUTHZ_PURGE_INCOMPLETE` on every retry, `scopes.detached` blocked
  forever, only `reconcile` could unblock it. Deleting that edge never grants; the edge of a
  *catalog* role rewritten by a concurrent grant is still protected and still comes out as
  residue, which is the correct retry signal.
- **E5 (not a package bug) — the depth-22 case no longer confuses the shared server's contention
  with the depth verdict.** Measured with a load probe against the real `:8101`: the server's
  depth verdict is a *named, deterministic* error (`authorization_model_resolution_too_complex` ·
  "resolution depth exceeded") while contention arrives as a different one (`deadline_exceeded`).
  The 500-resolution property now counts **only the server's own verdict** as evidence about the
  bound, retries contention a bounded number of times, and still fails loudly (naming saturation)
  if the server stays saturated — never a skip, and the published 22 is untouched.

### Lot 3b-7 · `freeze()` becomes durable — and the README stops promising what the code did not do

**The problem.** `freeze()` was a per-process boolean. The README sold it as the reason a write
landing during a migration "would not appear in any counter, **which is the one thing the report
promises cannot happen**" — false in every deployment with more than one worker: the other
workers' writes sailed straight through, a `revoke` accepted with a 200 during the pass never
reached the destination, and the report said `clean=true`. A four-agent panel measured it from
every side; the owner's decision (2026-08-31) was **B + E**: rewrite the promise *and* build the
mechanism that makes it true where it can be true — his words: *"la parada no me pesa si garantiza
el trabajo"* (a bounded write outage is acceptable; a silently lost revoke is not).

**The decision.** The freeze now lives in **row `id = 2` of `authz_catalog_version`** — the
cross-process signal every write already reads (invariant 14) — with three properties, each with
its case:

- **Owner token.** `freeze()` is async and returns `{ fence, holder }`; `unfreeze(token)` lifts
  only its own freeze. A live freeze of another owner is **423 `E_AUTHZ_FREEZE_HELD`** (new error,
  exported): two concurrent `reconcile` passes no longer un-freeze each other (the measured A1.3
  defect), and a nested window runs *inside* the outer one instead of lifting it.
- **Renewed lease, not a TTL.** Default 15 s, renewed conditionally every 5 s while the freezing
  process lives; after a `SIGKILL` the fleet resumes writing on its own within the lease (measured
  in two real processes: 2.5 s with a 3 s lease). `leaseMs: null` = no expiry — the operator's
  window.
- **Published fence.** The writing pass reports `frozen: { durable, lapsed, leaseMs, fence }`;
  `lapsed: true` (the lease was lost mid-pass) means the pass is **not certified** and
  `authz:reconcile` exits non-zero. The guarantee is demonstrated, never assumed.

The cost is measured and deliberate: **one primary-key `SELECT` per engine write** (+0.14 ms p50
PostgreSQL, +0.11 MySQL), **zero per `authorize`**. The barrier query is its own and unmemoized —
piggybacking on the catalog memo would have made the freeze "a bounded window of freeze that does
not apply yet" under `catalogRevalidate: { everyMs }`.

**The cutover has commands.** The dangerous interval is not the pass but
[last pass → the last worker reloads `config.default`] — minutes or hours, human-timed.
`node ace authz:freeze --reason=…` opens an **operator** window (fleet-wide 503 on writes, no
expiry by default; `--lease-ms` is the opt-in self-expiring variant, each with its declared
downside) and `node ace authz:unfreeze` closes it; `authz:reconcile` recognises a live operator
window as its own context — runs inside it, neither renews nor lifts it. `authz:unfreeze` refuses
to lift a live pass's freeze unless given `--fence=<n>`.

**Breaking, with the recipe:**

- **Schema.** `authz_catalog_version` gains four columns (`freeze_reason` varchar(255) null,
  `freeze_holder` varchar(120) null, `freeze_until_ms` bigint null, `freeze_fence` bigint not null
  default 0) and a seeded **row `id = 2`**. The published migration stub and the 1.x→2.x recipe in
  the README carry both. A database without the row (or the columns) makes **every engine write
  503** "migración 2.0 no aplicada" — the missing row is never read as "not frozen", exactly like
  the missing version row of invariant 14. Upgrading an existing 2.0-alpha database:
  `ALTER TABLE authz_catalog_version ADD COLUMN freeze_reason …, freeze_holder …, freeze_until_ms …,
  freeze_fence …; INSERT INTO authz_catalog_version (id, version, updated_at) VALUES (2, 0, now());`
  (exact statements per engine in the README recipe).
- **API.** `freeze(reason?, { leaseMs?, kind? })` is now `async` and returns the token;
  `unfreeze(token)` requires it; `frozen` now answers "does *this* manager hold a freeze" (the
  engine-wide question is the new `freezeStatus()`); `withFrozenWrites` keeps its signature but the
  window is durable and nested windows no longer lift the outer one.
- **The README paragraph is rewritten.** Gone: "the one thing the report promises cannot happen"
  and "a maintenance window of seconds" (at the declared cap the pass is ≈ 136 **seconds**, i.e.
  minutes, measured at 0.136 ms/fact). The published promise is "**another process gets a
  retryable 503**", never "no write enters the window" — the latter is not falsifiable with an
  OpenFGA destination (no atomicity between a SQL row and an external store). And the freeze's
  exact scope is enumerated: it does **not** freeze `syncAuthzCatalog`, `manager.driver()`, or
  your own scope-tree tables; it only reaches processes sharing the `authz_*` tables; and it is a
  guarantee of this package's manager that the published contract suite never checks for
  third-party drivers. A letter test pins all of it.

**What is NOT done, on purpose.** The `readChanges({ startTime })` window witness for the
store-sourced direction stays unimplemented (unmeasured retention/granularity — the panel refused
to publish it as a guarantee); the barrier↔write race stays open by nature and is documented
instead of "fixed"; and the multi-process guarantee is only *observable* on engines a second
process can open (`pg`, `mysql`, `sqlite-file`) — on SQLite `:memory:` the `modulo` mutant (freeze
as a module global) leaves `npm test` green, which is why the engine CI jobs are not optional.

### Lot 3b-6 · the migration stops **fabricating** a permission, and `--dry-run` stops freezing

Two defects a four-agent panel found while arguing about `freeze()`, both independent of that
decision (which is still the owner's) and both ruled *previous* to it.

**1. The source was read in two separate sweeps, and the pass composed two halves of two different
operations.** `readSourceFacts` walked `authz_assignments` and *then* `authz_denies`, each page
built on the global connection, with no transaction covering both. The gap between sweeps is not
narrow: it is the time it takes to walk the first table whole, in batches of 100 with a cursor —
seconds or minutes on a real database. A *composite* business operation landing in it is split.
Measured, against a real server and comparing with the `database` driver on the same tree and the
same catalog: a holder with a role **and** an explicit deny of `docs:write` (so today they cannot
write); HR does the full offboarding in the gap (`revoke` + `removeDeny`, two writes of **one**
business operation); the destination ends up with **the role without its deny** and grants
`docs:write` — which **neither the previous nor the following state granted** — while the report
says `written=13 extra=0 skipped={} clean=true`. The migration did not lose a permission: it
**invented** one, and the operator has no reason at all to distrust the green.

Both sweeps now run inside **one repeatable-read transaction**, so the worst outcome of the window
is *the consistent state of `t0`* — recoverable drift the next pass repairs — instead of a state
that never existed. That is a whole risk category removed at the price of one local, cheap read
transaction, with no coordination between processes. **What each engine guarantees is declared, not
assumed** (the kind of difference phase 2.5 exists to surface): PostgreSQL takes the snapshot with
`BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ`; MySQL/InnoDB is sent `SET TRANSACTION
ISOLATION LEVEL REPEATABLE READ` explicitly — it is InnoDB's default, but a server setting is not a
promise of this package — and fixes the consistent read on its first query; SQLite is sent **no**
isolation level (knex warns and ignores it) because a read transaction there is already a snapshot.

**What this does NOT cover, written down instead of implied.** It covers the direction whose source
is `authz_*` (`--to=openfga`). Where the source of truth of the facts is the **store**
(`enumerateFacts`: `--to=database` and the maintenance pass), the `Read` pages are not a consistent
snapshot either and there is no repeatable read to ask for: the same composition is possible there.
That direction is **open** in this version. The instrumentation that could name it —
`readChanges({ startTime })` as a window witness — is **not implemented**, and the README says so
rather than implying one snapshot covers both directions.

**2. `--dry-run` froze the engine's writes.** `manager.reconcile` wrapped the pass in
`withFrozenWrites` unconditionally, without looking at `options.dryRun`. The verifier is published
as read-only by contract and as something to *run in CI or in a cron*, so a read-only job pointed at
production froze that process's writes for the length of a full destination dump. It writes nothing,
so it has nothing to protect: freezing there buys zero. Today the damage is bounded (the freeze is
per-process); the day the freeze becomes durable, the same code turns a cron job into a global write
outage. `--dry-run` no longer freezes; the pass that writes still does, and both halves are one
case.

Neither change touches the design of `freeze()` itself, which is a separate open decision.

### Lot 3b-5 · who owns the facts decides where `authz:reconcile` reads them

The final adversarial audit of the phase blocked the merge with two 🔴, and both were the same
defect seen from two sides: **`authz:reconcile --to=openfga` read the facts from
`authz_assignments` / `authz_denies` without ever asking whether those tables are the source of
truth of the facts *in this deployment*.** After a cutover to `facts` they are not — the store is,
and nothing keeps them in sync from that moment on. Nobody is told to empty them, and the catalog
lives in the same tables, so they stay there frozen. From that single hole came:

- **A grant revoked after the cutover came back, with no flag at all.** The rows still in
  `authz_assignments` entered `wanted`, were not in the store, and were written (`written 1`). And
  `--prune` — which the command itself suggests on `unknown-scope` — deleted a live `denied_<P>`
  that only ever lived in the store: both holders went back to `true`. The
  `E_AUTHZ_MASS_RECONCILE_REFUSED` guard never fired: it asks whether the source is *empty*, not
  whether it is *stale*, and one leftover row disarms it. Worse, `--dry-run` — the verifier the
  README puts in CI — called the correct state "drift" and pushed the operator to "repair" it.
- **The visibility sweep of invariant 18 never ran on that path.** The set of forbidden
  `scope#binding` edges is built while reading the source facts, so with those tables empty it came
  out empty, `wanted.facts` came out empty, every live fact of the store was reported as
  `extra-fact` (the verifier was permanently red in a `facts` deployment) and `drift.roleVisibility`
  read `0`. Meanwhile the **tree** was rebuilt as always, because it is derived. So a `moved` whose
  relay entry was parked got the half that **grants** applied — the node re-hung under the new
  tenant, inheriting its permissions — and not the half that **retires**: a local role of `orgA`
  kept granting inside `orgB`, permanently, while `database` answered `false` on the same tree and
  the same catalog. That made the published sentence of invariant 18 (*"and `authz:reconcile`
  reconciles it if the relay was lost"*) false exactly where it is invoked.

**The fix is the question, not another escape flag.** `ReconcileSource.factsOrigin` (new, set by the
manager, obeyed by the driver) says where the facts of this pass come from:

- **`--to` is the active driver (`config.default`) and declares `hierarchyFacts`** ⇒ its facts are
  its own and are read from **itself**, through the `enumerateFacts` port that lot 3b-3b already
  published. This is the **maintenance pass**: it rebuilds what is derived — root marker, catalog
  projection, tree — and applies the invariant 18 sweep with the tree and the catalog of *today*,
  and it writes and deletes **no fact at all**. A driver in that position that cannot enumerate its
  own facts is 500 `E_AUTHZ_UNSUPPORTED` naming the method, because reading `authz_*` for it is the
  bug itself.
- **`--from=<driver>` is given** ⇒ the operator decides; if that driver's facts are `authz_*` (the
  package's `database`), `--to=openfga` is the one-way migration it always was.
- **Otherwise** ⇒ `authz_*`, as before.

Consequences worth knowing: `--to=openfga --dry-run` against a correct `facts` deployment now comes
out **clean** instead of red, so the CI verifier is usable again and the signals that matter
(`roleVisibility`, `multiParent`, `cycles`) are no longer drowned in permanent noise; the pass says
**where the facts came from** in its first line and in `report.factsFrom` (a migration and a
maintenance pass are not the same operation and must not look the same); and the initial migration
of a deployment whose config already names the destination as `default` must name its source
(`--from=database`), which the maintenance line spells out. The mass-delete guard is unchanged: it
still covers the *empty* source, which is all it ever covered.

Both reproductions of the audit are cases of the suite now, against a real server and comparing with
the `database` driver on the same tree and the same catalog.

### Lot 3b-4 · closing the phase verification: the census, the ceiling figure, the depth

The phase tester planted 28 mutants; 23 died. This lot closes what the survivors exposed.

- **The migration contract can no longer be passed while losing data (C1).** Both faces of
  `expectedLosses` compare `Object.keys(report.skipped)` — that is, the omissions a driver
  **declares about itself**. They close the *careless* losses, not the silent ones: a driver that
  drops a fact without counting it never populates `skipped`, and if that loss does not move any of
  the 448 answers the contract used to pass. Measured, and not in theory: a deny relocated to
  another scope of the same chain keeps every `authorize` answer identical (denies are not asked
  about by any other question), and all three combinations stayed **green**.
  `runMigrationContract` now also runs a **census**: it looks for the **20 seeded facts one by one
  in the destination**, through the port's direct read path — `listRoles` for the 14 assignments,
  `listDenies` for the 6 denies (invariant 7) — and a fact that is missing with no declared **and
  counted** reason fails the contract, whether or not a single answer moved (`silentLosses` in the
  verdict). `listDenies` is optional in the port: a driver that does not bring it leaves its denies
  observed by `authorize` alone, and the verdict says so in `censusLimits` rather than degrading in
  silence. The **expiry cross** — none of the 448 returns an `expiresAt` — now also runs against the
  *intermediate* destination of `a→b→a`, which the outbound leg could otherwise strip unnoticed.
- **The published sentence about that contract was rewritten to match what it does (C2).** It used
  to sell the `skipped` half as the cut against "a driver could drop whatever it liked"; that is the
  census's job, and it is now named as such in `CLAUDE.md`, the README and above.
- **"≈691 permissions" was measured with permissions named `p0`…`p690` (C3).** The byte ceiling
  itself is exact (`factsModelBytes` matches the server byte for byte, checked again against a real
  server), but the *derived* figure is not a property of the model: it depends on **how long your
  permission slugs are** and on **how many holder types** you declare. With three holder types and
  realistic `resource:action` slugs the real ceiling is **447** — 35 % below the published number.
  Every place that quoted 691 now quotes the catalogue it was measured with and carries the table,
  and a case pins the whole table — each figure with the catalog that produces it, and the exact
  edge (N fits, N+1 does not) — so nobody publishes a number again without saying what it was
  measured on.
- **The resolve depth is now pinned from above too (C4).** `FACTS_MAX_RESOLVE_DEPTH = 22` used to be
  held by a pair of cases that fixed the interval [22, 23], not 22: setting it to 23 left the suite
  green three runs out of three. One more case pins it deterministically — 500 resolutions per side
  through `authorizeMany`, not a single roll — because the boundary at 23 is *probabilistic*
  (measured on a real server: 22 resolves 200/200, 23 fails between 4 % and 26 % of the time, 24
  always fails). *The largest depth that resolves reliably* is the property, and it is 22.
- **Two operational fixes (C5).** `tests/harness_cleanup.spec.ts` pinned the literal `authz_test_`
  and broke the suite whenever `TEST_PG_URL` named another base — it derives the name from the URL
  now. And `bin/test.ts` had a net for the SQL database but none for the OpenFGA stores: an
  **interrupted** run leaked them (measured: 60 stores, 7.9 GB of RAM on the dev server). It now
  arms the same synchronous `process.on('exit')` guard, which deletes the stores this run created.

### Lot 3b-3b · `authz:reconcile --to=database` and the **migration contract**

The way back, and — above all — the guarantee. Lot 3b-3a shipped `--to=openfga`; this one ships
the inverse direction and `runMigrationContract`, the piece that turns *"it migrates"* into
*"it migrates without losing anything that is not declared"*.

```bash
node ace authz:reconcile --to=database            # rebuild authz_* from the store's facts
node ace authz:reconcile --to=database --prune    # ... and delete the rows the store no longer backs
node ace authz:reconcile --to=database --from=fga # when more than one registered driver could be the source
```

- **The facts, and only the facts.** The **tree is not migrated** in this direction: the `database`
  driver reads it from the consumer's tables on every question and they are its source of truth, so
  copying it would invent a second copy and a drift that does not exist. The **catalog** is not
  migrated either — it is local property always. The `root`, `catalog` and `tree` phases therefore
  report **zero**, and that zero is an answer, not a hole. The tree is still used, to decide which
  facts are migratable (`unknown-scope`) and under which canonical identity each row is written
  (invariant 17).
- **New optional port method `enumerateFacts({ limit, after })`, with capability
  `enumerateFacts`** — the entry lot 3b-3a deliberately left for this one. It is what it means to
  be the **source** of a migration: at most `limit` facts per page, a total and stable order, an
  opaque cursor that must advance, and **no filtering** — an already-expired assignment arrives
  with its `expiresAt` so the destination can count it in `skipped`, because filtering it at the
  source would make it vanish with no trace. Both faces have cases in the published suite:
  `openfga` implements it (its facts are tuples), `database` declares `false` on purpose (its facts
  *are* the published `authz_*` schema and the destination reads them straight from there).
- **Which driver is the source is decided out loud.** With two registered drivers it is the one
  that is not `--to`; with more than one candidate the pass stops (500 `E_AUTHZ_CONFIG`) and asks
  for `--from`; with none it stops with 500 `E_AUTHZ_UNSUPPORTED` naming `enumerateFacts`, rather
  than reading zero facts and then emptying the destination with `--prune`. Resolution is **lazy**:
  `--to=openfga` never builds a source driver.
- Everything else is the same contract as the outbound direction: **idempotent** (a second pass
  writes zero), `--dry-run` is the verifier and **read-only by contract — there is no `--fix`**,
  **never silent** (`skipped{reason}` + the named rows), facts that are left over are only deleted
  with `--prune`, and `--prune` over a source that returned **no facts at all** refuses with 500
  `E_AUTHZ_MASS_RECONCILE_REFUSED` before touching anything (`--allow-mass-delete` is the human
  decision; `--dry-run` flags it instead of throwing).
- **`runMigrationContract` (published in `/testing`).** Fixed fixture — 7 nodes, 6 holders, 4
  roles, 14 grants, 5 expiries, 6 denies, all written through the driver's own API — then
  **448 identical questions** on both ends (168 `authorize`, 168 `hasRole`, 42 `listRoles`, 24
  `listScopes`, 28 `listSubjects`, 18 `listRoleScopes`), in **three combinations** (there, back,
  and there-and-back with `--prune`). Losses are declared in advance in `expectedLosses` and the
  contract cuts three ways: an answer that changes with no declared loss to explain it fails;
  **every reason counted in `report.skipped` that was not declared fails too**; and a declared loss
  that never happens fails as well. Those last two cross what the driver declares about *itself* —
  see Lot 3b-4 for the census that closes the losses a driver never counts.
- **The declared losses of the package's own pair are one: `expired`.** The other three the design
  panel had listed were measured and are not losses of the migration — sub-second precision in
  MySQL is closed by the published schema (`DATETIME(3)` plus the UTC-string codec: a millisecond
  round-trips exactly, and there is a case in every engine), facts on phantom scopes are
  `unknown-scope` with cases in both directions, and the `*_ci` collation is a **read-path**
  divergence (the `canonicalScopeReads` capability pair), not something migrating loses. The one
  real collation effect that *is* counted: two source facts that fold into a single destination row
  are reported as **`folded-scope`**, and the row keeps the expiry that lasts longest — the source
  granted while either one was alive.
- **Bug found by the contract and fixed here (regression of 3b-3a):** `authz_assignments.scope_uuid`
  is `NOT NULL` and the **root** scope is stored with the sentinel `00000000-…`, so
  `--to=openfga` did `row.scope_uuid ?? null`, which is never null, and `scopeKey` rejected
  `{app, uuid}` with a 422 **in the middle of the pass**. A grant or a deny on `app` could never be
  migrated. `fromDbScopeUuid` is now exported and used on both sides; there is a case for the root
  in both directions.
- **The memory bound of lot 3b-3a is now declared instead of implicit (B5)**: the destination dump
  is held in memory (reconciling needs the whole snapshot to know what is left over), so
  `--max-tuples` (default 1 000 000) caps it and going over is 500 **`E_AUTHZ_RECONCILE_TOO_LARGE`**
  before anything is written, naming the cap. There is still no partitioned migration, and
  "resumable" still means *idempotent and repeatable*, not a cursor persisted between runs — both
  written down rather than discovered in production.

### Lot 3b-3a · `authz:reconcile --to=openfga` — the migration, one direction

The reason the phase exists: *"todo en un driver o todo en otro, y una migración idempotente y
bidireccional entre drivers"*. This lot ships the **DB → FGA** direction and the shared
infrastructure; `--to=database` and the migration contract are the next one (`--to=database` is
already reachable and answers 500 `E_AUTHZ_UNSUPPORTED` naming the port method it needs, never a
half migration in silence).

```bash
node ace authz:reconcile --to=openfga --dry-run   # the VERIFIER: read-only, exit 1 on drift
node ace authz:reconcile --to=openfga             # migrate
node ace authz:reconcile --to=openfga --prune     # ... and delete the facts the source no longer backs
```

- **What it migrates.** The root marker (`scope:app#rooted`, without which the whole store denies),
  the derived catalog projection (`role:<uuid>#permits_<P>`), the **tree** (from the new
  `scopes.enumerateEdges`) and the **facts** of `authz_assignments` / `authz_denies` — including
  the two (c2) edges of every assignment and the `denied_<P>` of every deny.
- **`--to` names a key of `drivers`, not the active driver.** Migrating means filling the
  destination while the engine keeps running on the other one.
- **Idempotent**: a second pass writes zero. **Resumable**: the source is read in batches of 100
  with a cursor over the primary key, and a repeated pass converges. **Never silent**: the report
  carries `{ written, updated, unchanged, extra, deleted, skipped{reason} }` per phase plus the
  rows that did not migrate, one by one, with their reason.
- **`--dry-run` is the verifier and it is read-only by contract** (panel 2, cruce 4 · S18): same
  walk, same numbers, zero writes. **There is no `--fix` and there will not be one** — it would be
  a grant mechanism.
- **What it deletes without asking, and what needs `--prune`.** The root marker, the catalog
  projection and the tree are mirrors of local data nobody else writes: whatever is left over goes.
  That is what repairs a scope with **two parents** in the store (the drift that `scopes.moved`
  refuses to guess about, 3b-2h · 🟠 4) and what removes edges `enumerateEdges` no longer backs
  (cruce 9 · S7). The **facts** are only deleted with `--prune`: the facts of a scope that no
  longer resolves — the "resurrection" of 3b-0b · AA4, which until now nothing cleaned — and
  anything left over by an older version of the store.
- **The exception, on purpose**: a `scope#binding` edge that the source backs but whose visibility
  rule says *no* (invariant 18) is deleted **without `--prune`** and counted in
  `drift.roleVisibility`. Leaving it is fail-**open** — it is exactly the write `scopes.moved` /
  `projectCatalogRole` lose when the relay does not get there.
- **Cycles are reported, not just edge differences** (cruce 3, part ii). A cycle in the consumer's
  tree makes OpenFGA's inheritance bidirectional, so **no edge of a cycle is written**: those nodes
  stop reaching the root and therefore deny (fail-closed), and the cycle is named in the report.
- **The relay window is reported as drift** (owner's decision of 2026-08-30, consequence 4): how
  many tree changes are queued and unrelayed — the window in which the backend decides with the old
  tree — and how many are **parked**, which is not a window but permanent divergence.
- **`manager.freeze()` / `unfreeze()` / `withFrozenWrites()`** (platform API, next to `driver()`):
  during the pass every write of the engine answers 503 `E_AUTHZ_FROZEN` **retryable** and reads
  keep working; a `finally` thaws whatever happens. A `grant` landing between the read of the
  source and the write of the destination would be lost *and* uncounted.
- **`scopes.enumerateEdges` is new in the config** (optional; only `authz:reconcile` uses it): the
  whole tree, paginated with a cursor. `sqlScopeEdges({ table, uuidColumn, parentColumn,
  typeColumn })` implements it over a table with a parent column, like `sqlDescendantsOf`. Without
  it the command refuses (500 `E_AUTHZ_CONFIG`) instead of assuming a flat tree.
- **The way out of a store written by the previous version.** After lot 2k "a store written by the
  previous version is not read by this one". `reconcile --to=openfga` rebuilds it from `authz_*`,
  which is the source of truth: measured against the server, a tuple whose *type* the current model
  no longer declares can still be read and deleted, so `--prune` cleans it and the store grants
  again.
- **Two new errors**: 503 `E_AUTHZ_FROZEN` (retryable) and 500 `E_AUTHZ_MASS_RECONCILE_REFUSED` —
  `--prune` refuses to delete facts while `authz_assignments`/`authz_denies` are **empty** (the
  signature of a wrong connection, or of the other driver being the one that writes the facts);
  `--allow-mass-delete` is the human decision, and `--dry-run` never throws, it flags it. Same
  pattern as `E_AUTHZ_MASS_PURGE_REFUSED` (3b-0b · AA2).
- **No `Ignore` blindfolded** (cruce 9 · S7): the deleted importer wrote with
  `onDuplicateWrites: Ignore`, so a tuple already there with **another expiry** stayed as it was and
  was counted as written — breaking invariants 3 and 6. Here the destination is read whole first,
  an expiry difference is resolved with delete + write, and the counters come from the diff, never
  from the write.

### Lot 3b-2k · K2 — the `resolver` mode is gone: the `openfga` driver **is** `facts` (**breaking**)

Twelfth lot of the `facts` mode, and the one that closes the 3b-2 cycle. Nothing is deprecated and
nothing is flagged: the dead path is **deleted**.

- **`hierarchy` is no longer an option.** It used to default to `'resolver'` — the tree stayed in
  your database and the package expanded the chain into a `batchCheck` of N×M on every question.
  Passing it is now a TypeScript error and is ignored at runtime. `driver.capabilities` is therefore
  constant: `hierarchyFacts` and `singleCheckAuthorize` are `true`, `purgeRole` and
  `countRoleAssignments` are `true`, `canonicalScopeReads` is `false`.
- **The construction gate always applies.** `outbox` or `acceptScopeDriftRisk: true` is now
  mandatory for *every* `openfga` driver (500 `E_AUTHZ_SCOPE_DRIFT_UNGUARDED`), because there is no
  longer a mode whose tree is not a second copy. The published `config/authorization.ts` stub was
  updated accordingly (it signs `acceptScopeDriftRisk: true` and says when to swap it for the
  outbox).
- **What was deleted, and why it was dead**: the chain expansion in `authorize`/`authorizeMany`
  (`checksFor`, the N×M batch, the per-level deny checks), the object type **`deny_binding`** and
  its reader (`legacyDenies`, the `deny_binding` branch of `deniedScopeKeys` and of `purgeScope` —
  which stops being O(permissions) per scope), the `!structure.length` guard in `grant`, the
  removal of `purgeRole`/`countRoleAssignments` in the constructor, and the old model generator
  **`openFgaAuthorizationModel`**.
- **`openfga:provision` publishes the `facts` model.** It used to publish the `resolver` one. The
  (c2r) model declares four relations per permission, so the command resolves the `catalogs` from
  your config (plain functions, no database) and refuses to provision a store with no permissions
  rather than leave one that denies everything. `provisionOpenFgaStore(apiUrl, name, holderTypes,
  permissions)` gains that fourth argument.
- **`openfga:import` is deleted, and so is `E_AUTHZ_STORE_NOT_EMPTY`.** The importer wrote the
  `resolver` tuple shapes into the store; against the (c2r) model those types do not exist, so it
  would have filled a store that grants nothing — keeping it would have been the silent break, not
  removing it. Its declared replacement is `authz:reconcile` (phase 3b, bidirectional, resumable,
  tree and catalog projection included). Until it lands, moving from `database` to `openfga` is:
  provision a store, run `authz:catalog:sync` (projection + root marker), notify your tree with
  `authorization.scopes.attached`, and re-issue the grants.
- **One behaviour changes for a `grant` that collides**: with the `resolver` mode the `assignee` was
  the only tuple of the write, so a duplicate whose re-read saw nothing was inexplicable and came
  out as a 503 with the "preserve" recipe. With (c2)'s structure it *is* explicable — another holder
  already had that role in that scope, the commonest case there is — so the write is retried giving
  the duplicate for granted, and a contention that does not yield is 409 `E_AUTHZ_WRITE_CONFLICT`.
  The 503 with the recipe survives where it still applies: when the **re-read itself fails**.
- **And one answer the two drivers no longer share, now written down**: delete a role from
  `authz_*` **by hand** and `hasRole`/`list*` fail closed in both drivers (they filter through the
  local catalog), but `authorize` in `openfga` keeps granting until the derived projection is
  redone — the store's permission→role map is the projection, not the row you deleted. Whoever
  writes `authz_*` by hand owes a `driver.projectCatalogRole(uuid)`, exactly as it already owed a
  catalog-version bump. The README said the opposite; it now says this.

### Lot 3b-2k · K1 — the two answers `facts` does not share with `database`, declared with a negative case

Eleventh lot of the `facts` mode. It does not change a single decision: it makes the judge tell the
truth about two divergences that were red, and it adds them to the port's declaration so a
third-party driver cannot inherit them by accident. **Nothing is skipped** — both faces of both
pairs run.

- **(b) With your resolver down, `facts` is *grant-only*.** `authorize` and `authorizeMany` keep
  answering with the tree that lives in the store, while `revoke`, `deny`, `removeDeny`,
  `purgeScope`, `hasRole` and every `list*` are 503 `E_AUTHZ_RESOLVER_FAILED`. It grants and, for as
  long as the outage lasts, **nothing can revoke it**. That is the property this mode was bought for
  (a PDP that answers when your database does not); closing it would put `resolveChain` back on
  `authorize`'s hot path. The general `authorizeMany` case no longer claims "a scope that throws
  throws the whole call" for every driver: that claim moved into the `hierarchyFacts` pair, whose
  `false` face keeps it verbatim and whose `true` face demands the **exact** answer the store's tree
  gives. The `true` face also pins the whole consequence, not half of it (auditor R2 · 🟡 5).
- **(c) A uuid alias does not find its facts on the read path.** `authorize` composes the store
  object from the caller's spelling, so an id written without dashes — the same row for a PostgreSQL
  `uuid` column or a MySQL `*_ci` collation — answers `false` where `database` answers `true`. It is
  fail-**closed** (it evades no deny and grants nothing extra) but it is not the same answer: pass
  scope uuids exactly as your table stores them. New capability **`canonicalScopeReads`**, on the
  port and in the suite, judged on both faces; the `false` face also pins that the **write** path
  *does* canonicalise (`grant`/`revoke`/`deny`/`removeDeny`/`purgeScope`), which is the half that was
  fail-*open* and that lot 3b-2h fixed rather than declared.
- **`AuthorizationDriverCapabilities` gains `canonicalScopeReads`** (breaking for a third-party
  driver that declares the object literally): `true` in `database` and in `openfga`'s `resolver`
  mode, `false` in `facts`.
- With `AUTHZ_CONTRACT_FACTS=1` the judge is now **green on SQLite, PostgreSQL and MySQL**.

### Lot 3b-2j — `stillGranting` becomes a question for the driver (**breaking change to the port**)

Tenth lot of the `facts` mode, and the one that closes the finding lot 3b-2i uncovered.

- **The problem, measured.** `pruneOrphanRoles().stillGranting` was computed by counting rows of
  `authz_assignments`. That is the `database` driver's table, so with the `openfga` driver — where
  facts live in the store — it was **always `false`**. The published contract of that field is
  *"false ⇒ this role definitely grants nothing"*, and it is read **right before a destructive
  delete**: the orphan sweep was declaring inert garbage a role that was granting. It has been there
  since 2.3's `stillGranting` (the flag lot 3b-0b added precisely so a prune would not silently
  revoke live permissions); the judge could only see it once lot 3b-2i unblocked the case around it.
- **The fix: a new optional port method.** `AuthorizationDriver.countRoleAssignments(roleUuids)`
  returns, **by position** (like `authorizeMany`), how many **live** facts each role has across every
  scope — expiry judged strictly with the driver's clock. `0` for a role with no facts or one the
  backend does not know, 422 `E_AUTHZ_INVALID_IDENTITY` for a malformed uuid. `database` answers with
  one grouped query; `openfga` answers it **only in `hierarchy: 'facts'`**, where (c2)'s
  `role_binding#role` edge makes a role's bindings enumerable — the same edge `purgeRole` needs. In
  `resolver` mode the constructor removes the method, which is how a driver says "I cannot".
- **Breaking for third-party drivers, and the suite says so.** A driver written for 2.2 does not have
  the method. Then `pruneOrphanRoles` reports `assignments` and `stillGranting` as **`undefined` —
  never `false`**: "I don't know" must not degrade to "it does not grant", which is the bug itself.
  `authz:catalog:prune-orphans` now has **three** buckets instead of two and lists those roles
  **apart, with their own warning**, exactly as it already did with the ones that do grant. The new
  capability `countRoleAssignments` is judged by the published contract suite
  (`@jantstack/adonis-authz/testing`) on both faces, so a third-party driver finds out what is
  expected of it by running the suite it already runs.
- **`readLocalRoles` no longer counts facts** (it was the source of the lie); the shape of
  `pruneOrphanRoles`'s report changes accordingly (`assignments: number | undefined`,
  `stillGranting: boolean | undefined`).

### Lot 3b-2i — `can_<P>` now requires reaching the root: the (c2r) model (auditor R2, finding 🔴 1)

Ninth lot of the `facts` mode, and the one the previous lot deliberately left open. **Breaking, twice.**

- **The problem.** In `hierarchy: 'facts'`, a scope whose chain no longer reached `app` kept granting
  whatever was bound to it **and stopped inheriting the denies above it**. So `scopes.detached` of an
  *intermediate* node worked as a bulk `removeDeny` over its whole subtree — while every `within`
  barrier held, because detaching your own division is a legitimate operation. Measured end to end
  against a real server with `requireWithin: true`: `removeDeny` on the organization above ⇒ 422,
  `grant` there ⇒ 422, `scopes.detached` of the actor's own division ⇒ OK, and afterwards
  `authorize(alice, 'docs:write', unit)` = **`true` in `facts` and `false` in `database`**, with the
  deny still written in the store. `database` never had this: there a chain that does not reach the
  root is an unknown scope (invariant 9).
- **The fix, in one relation.** `type scope` gains
  `define rooted: [<holders>:*] or rooted from parent`, and `can_<P>` becomes
  `(<P> but not denied_<P>) and rooted`. Reachability of the root is now computed **by the model**,
  on every question, so a detached subtree stops granting without anyone enumerating it. Measured,
  against OpenFGA v1.19: `authorize` is still **one single `Check`** (`{check:1, batchCheck:0}`,
  `resolveChain` called 0 times — `singleCheckAuthorize` stays `true`), the chain-depth ceiling does
  **not** move (25/25 at 22 hops, 16/25 at 23, 0/25 at 24 — `FACTS_MAX_RESOLVE_DEPTH` is still 22),
  and the cost is +0.13 ms p50 at three hops, inside the measurement noise.
- **Migration step, not a footnote: an existing store needs its root marker.** `rooted` is anchored
  by **one tuple per holder type in the whole store** — `scope:app#rooted@<holder>:*`, and **zero per
  scope**, so the outbox and the relay carry nothing new. `syncAuthzCatalog` writes it idempotently
  (one `Read`, and a `Write` only of what is missing — that is also how a holder type added to your
  config gets one). **Republishing the model without writing the marker makes the whole store deny**:
  fail-closed and loud on the first question, but total. Run `node ace authz:catalog:sync` after
  republishing; `authz:reconcile` will report it as drift.
- **Breaking (1): a scope you never notified stops granting.** A consumer that materialises paths and
  only notifies `attached` for some of its nodes used to get *more* than it asked for; now it gets
  less, and it looks like "my permissions disappeared". Diagnose it with `authz:reconcile --dry-run`,
  which lists the scopes that are not reachable from `app`.
- **Breaking (2): the relay lag changes sign.** With `scopes.outbox` declared, a newly created scope
  now **grants nothing until the relay runs** (`facts=false` while `database=true`), where before it
  granted and did not inherit the denies above it. The window is fail-**closed**, which is the trade
  the owner took on purpose: denying for seconds is availability, granting for seconds is the defect
  this mode spent two lots hunting. **Drain the queue in the same request, right after your commit**
  (`await authorization.relayScopeChanges()`) on the interactive "create a tenant" path, and
  **without an outbox the window is zero** — `scopes.*` calls the driver inline. Both sides are
  pinned by a case.
- **The model's size ceiling drops by about 4 %** — on the reference catalog (three holder types
  named `user`/`admin`/`integration`, permissions named `p0`…`pN`) from 721 to 691 permissions;
  `rooted` costs 92 fixed bytes + 16 per permission with three holders. **That figure is not a
  property of the model** — see Lot 3b-4 for what it depends on and the table. Verified from both
  sides against the server — it accepts 691
  and rejects 692 — and `factsModelBytes` still reports **exactly** what the server reports
  (delta 0). Depth, relation-name, object-id and `batchCheck` limits are unchanged.
- **`rooted` is a reserved slug** in both drivers, like `parent`, `binding` and `ancestor`: a
  permission called `rooted` would rewrite the model's own relation (422).
- **What this does *not* close, so nobody assumes it.** A cycle **hanging from the tree** (a node with
  two parents, `app` and a descendant of its own) is still fail-open — a grant inside it still grants
  upwards, and the mitigation is still the package's own cycle checks. What (c2r) does close is the
  **orphan** cycle: X→Y→X that hangs from nothing now grants nothing, not even inside itself.

### Lot 3b-2h — a poisoned outbox entry no longer freezes the tree, and the write path stops trusting the caller's spelling (auditor R2)

Eighth lot of the `facts` mode. It fixes three findings of the adversarial audit of R2
(`fase-3b-auditor-r2.md`), all of them in the **composition** the outbox introduced in 3b-2d, all of
them measured against the real server. Finding 🔴 1 (`scopes.detached` of an intermediate node is a
deny-removal primitive for its subtree) is **not** in this lot: it is a change of the (c2) model and
is being designed separately.

- **🔴 2 · One unappliable entry no longer blocks every tenant.** `attached(C, P)` enqueued and `P`
  deleted from the consumer's tree before the pass is legitimate, ordinary, and it can no longer be
  applied: the relay stopped at the first failure and `pending()` returns unapplied rows ordered by
  id, so the poisoned row was the head of the queue **on every later pass**. Measured: three passes
  later a new unit never received its `parent` edge, the deny of its organization never reached it
  (`facts=true`, `database=false`) and a later `detached` never purged. The window was not bounded
  by the relay cycle — it was infinite, and any tenant could open it in two requests. Now a failure
  **poisons the scopes the change names**: every later change naming one of them is `deferred`
  without being attempted (transitively), and everything else is applied. The order that mattered is
  preserved, because two changes that can interact always share a scope. The report grew
  `failures`, `deferred`, `dead` and `busy`; `failed` is still the first failure.
- **🔴 2 (b) · The queue converges.** `sqlScopeOutbox` **parks** an entry after `maxAttempts`
  failures (default 5): `pending()` stops offering it, `dead()` shows it, the relay reports it on
  **every** pass and the command exits non-zero while any exists. Parking is not forgetting — a
  parked entry is a permanent divergence of the store's tree — but a queue that only retries is a
  plug with a retry loop. The port gained an optional `dead(limit)` and `pending(limit, after)`
  (the cursor a pass needs once a row can be skipped).
- **🟠 3 · The uuid alias was fail-OPEN on the write path.** On the read path an alias does not find
  its facts (fail-closed, declared). On the write path, with the row **already deleted** — the
  supported order for `detached` — there is nothing to canonicalise with, so the caller's spelling
  was used: `purgeScope` proved zero over an object that does not exist, returned OK, and the real
  scope kept its `parent` and `binding`, granting for ever (measured on PostgreSQL 18, whose `uuid`
  column folds the dash-less spelling into the same row). Now a purge with no chain covers **every
  spelling the caller's uuid can be an alias of** (`scopeSpellings`): the dash-less 32-hex form also
  purges the canonical 8-4-4-4-12 one. Normalising instead of expanding would only move the leak,
  since without the row there is no way to tell which spelling is the real one. A consumer that
  passes uuids as its table stores them pays **nothing**.
- **🟠 4 · The relay is a single writer, and a tree write clash is not an outage.** The double-parent
  trigger the auditor suspected (two passes racing) was **not** reproduced end to end in ~50
  attempts — FGA's "cannot write a tuple which already exists" kills the losing pass first — but the
  same hole (no lease, batch never re-read) was measured doing something worse and silent: a
  straggling pass re-applies an old `attached` after the other applied the new `moved`, and the store
  is left with the **old parent and a single edge**, so `assertOneParent` never fires and the old
  tenant keeps `docs:write` over a subtree that is no longer theirs. The port gained an optional
  `acquire()` lease — a server-side lock on PostgreSQL and MySQL, process-wide on SQLite — and a
  second simultaneous pass now does nothing and says so (`busy`). And that losing pass used to die
  with a **503**, against invariant 6: `reparent` now re-reads and re-applies on a write race (the
  duplicate write, and the delete of a tuple another writer already removed), and a contention that
  does not yield is 409 `E_AUTHZ_WRITE_CONFLICT`, never a 503.
- **The README sentence lot 3b-2d wrote is corrected**, because it was false: a shorter relay cycle
  shortens the window **only for the changes the queue can actually apply**. What fails is not
  bounded by your cycle, and what is parked is never applied at all; the relay says so on every pass
  and in its exit code.

### Lot 3b-2g — the `scope#binding` edge means **"the role is visible here"** (judge root R1)

Seventh lot of the `facts` mode. It closes the second of the three roots left red in the judge's
`facts` harness: **the (c2) model does not know a role's LEVEL** (`scope_type`), so changing the
level of a role retired what it granted in `database` — where the rule is evaluated on every
question — and **kept granting** in `facts`. A divergence that bought nothing, so the owner's
decision of 2026-08-30 (2) was to fix it with the **same mechanism approved for the owner**:
sweeping `scope#binding` edges.

- **`projectCatalogRole` now rebuilds BOTH projections of a role**: what it grants
  (`role:<uuid>#permits_<P>`) and **where it is visible** (`scope#binding`). It is the hook for "a
  catalog write changed this role": the manager calls it after `defineScopedRole` /
  `updateScopedRole`, and a process that writes `authz_*` by hand owes it the same call it already
  owed for the permission mirror (without it, in `facts` a hand-written catalog change measures the
  mirror instead of the invariant).
- **One rule, one place.** Both sweeps — the owner's on `scopes.moved` (3b-2e) and the level's here —
  now classify an edge with `declaredRoleAt`, the very function `database` evaluates on every
  question: *the role must be declared for the level of that scope **and** be global or have its
  owner in the chain*. A consequence worth stating: the owner sweep can no longer resurrect an edge
  that the level forbids.
- **The conceptual price, documented and not hidden:** the `scope#binding` edge now means **"the
  role is visible here"**, not "this assignment exists". The assignment is the `assignee` tuple,
  which no sweep touches — which is why `hasRole`, `listRoles` and `listSubjects` still enumerate
  assignments filtered through the catalog and answer exactly as before.
- **Cost.** `scopes.moved` is unchanged (still **zero** requests when the catalog has no local
  roles). `projectCatalogRole` pays one extra `Read` (the role's bindings) and, only when the role
  is **local and has bindings**, the store chain of each distinct scope holding one; a role with no
  bindings — every `defineScopedRole` — costs no write.
- The judge's red case `parity between drivers (3D · N1)` is green in both harnesses (the in-memory
  tree and the SQL tree). The reds that remain are root **R2** — the store's tree decides without
  your chain — which is **declared, not fixed**: closing it would put `resolveChain` back in
  `authorize`'s hot path, which is the property this whole phase bought.

### Lot 3b-2f — the `grant` of (c2) is **one** atomic write (judge root R3)

Sixth lot of the `facts` mode. It fixes one of the three roots that lot 3b-2e left red in the
judge's `facts` harness: the `grant` of the (c2) model is **three** tuples (`assignee`,
`role_binding#role`, `scope#binding`) and they used to travel in **two** requests, so they were not
atomic. Against a concurrent `purgeScope` the `assignee` could survive without its edges: an
assignment `listRoles`/`hasRole` enumerate and `authorize` does not honour — worse than losing the
write. And a clash on the edges surfaced as a 503 ("the backend did not answer") when the backend
had answered perfectly well.

- **The three tuples travel in a single `Write`** (transactional in FGA): either all three land or
  none does. `revoke` is unchanged (the edges are structure and are shared by every holder of the
  same role in the same scope).
- **A write clash is never a 503 any more.** FGA reports a race two ways — `Aborted` (HTTP 409)
  when two transactional writes touch the same tuple, and `write_failed_due_to_invalid_input` (HTTP
  400, "cannot write a tuple which already exists") when the tuple was already there — and the
  driver treats both as "somebody else got here first": it re-reads and re-applies, so the last
  writer wins. Which of the two clashed (the assignment, or the shared edges) is decided by the
  **re-read**, not by the error, because the transactional conflict does not name any tuple. A
  contention that does not clear in three rounds is a new **409 `E_AUTHZ_WRITE_CONFLICT`**
  (exported), never a 503.
- **`purgeScope` deletes in a fixed order in `facts`**: the structure (`role_binding#role`,
  `scope#binding`) first — deterministic tuples, deleted blind, so this phase costs no reads —,
  then the `assignee` facts, then the scope's `denied_<P>`. With an atomic `grant` no interleaving
  can leave an assignment without its edges, and a purge that dies half way leaves denies **over**,
  never under (invariant 2). Phases 2 and 3 delete only what is theirs: an edge a concurrent grant
  rewrote is left alone (deleting it would orphan its assignment again) and shows up as residue,
  which is exactly what the proof of zero reports (500 `E_AUTHZ_PURGE_INCOMPLETE`).
- The judge's two red cases for this root are green (`two concurrent grants … 409, never 500/503`
  and `purgeScope concurrent with grant … never a half state`). The other three reds are roots R1
  and R2, which need the owner's decision and are untouched.

### Lot 3b-2e — declared capabilities, the local-role sweep on `moved`, `purgeRole`

Fifth lot of the `facts` mode.

**BREAKING — invariant 18: how a local role is retired when the tree moves.** Until now:
*"moving a unit out of its owner's subtree retires what the local role granted there **without any
write**"*. That is still true in `database`. In `openfga` with `hierarchy: 'facts'` the (c2) model
has no `owner`, so a `role_binding` would keep granting while its scope is reachable — a fail-open
measured in lot 3b-2c and decided by the owner on 2026-08-30. From this lot, **`scopes.moved`
writes**: it sweeps the `scope#binding` edges of the local roles whose owner is no longer in the
chain — across the **whole moved subtree**, not just the moved node — and rewrites them when the
owner is in the chain again. A **global** role is never touched, and neither is a local role whose
owner is still an ancestor. The write travels the same path as any other tree change: with
`scopes.outbox` it is applied by `authz:scopes:relay`, so it inherits the relay lag's temporary
fail-open (documented in *The scope tree*), and `authz:reconcile` reconciles it if the relay was
lost. If the catalog has no local roles at all the sweep costs **zero** requests. The acceptance
criterion is driver **parity**: the same `moved` in `database` and in `facts` must give the same
`authorize` answer.

**BREAKING — the drift gate now also runs in the manager.** The driver's gate checks *its*
`outbox` option, but the manager is what enqueues (it reads `config.scopes.outbox`), so declaring
the outbox on the driver alone left the mitigation switched off. When the resolved driver declares
`capabilities.hierarchyFacts`, the manager requires `scopes.outbox` **or** the new
`scopes.acceptScopeDriftRisk: true` **in the config**, or it throws 500
`E_AUTHZ_SCOPE_DRIFT_UNGUARDED`. Signing on the driver does not sign for the manager.

- **Declared capabilities on the port** (`driver.capabilities`): `hierarchyFacts`,
  `singleCheckAuthorize`, `roleInheritanceNative`, `listObjectsInherited`, `purgeRole`. Each
  declared value has a case in the contract suite — never a skip. `roleInheritanceNative` and
  `listObjectsInherited` are **`false` in both drivers, `facts` included**: the five membership
  reads still use `resolveChain`, and no `list*` enumerates inheritance. The README now carries the
  approved literal word for word, and **"no SQL in the hot path" is explicitly not a claim this
  package makes**.
- **`purgeRole` is supported by `openfga` in `facts` mode**, so `defineScopedRole` no longer
  refuses (it used to be 500 `E_AUTHZ_UNSUPPORTED` before writing anything). With (c2) a binding
  points at its role, so a role's bindings can be enumerated. Facts first, catalog second, and the
  purge proves zero before the role row is deleted. In `resolver` mode the method is still absent —
  which is the documented way of saying "I cannot purge".
- **`projectCatalogRole(roleUuid)`, a new optional port method.** In `facts` what a role grants are
  tuples, so a catalog write that does not touch them leaves a role that grants nothing
  (`defineScopedRole`) or one that keeps granting what it no longer links (`updateScopedRole`). The
  manager calls it after both.
- **Measured limits of (c2)**: the chain depth `can_<P>` resolves is **22 hops**
  (`FACTS_MAX_RESOLVE_DEPTH`) with the default `--resolve-node-limit`; at 23 the boundary is
  *probabilistic* (24 of 25 runs) and at 24 it always fails; `denied_<P>` reaches 25 and `ancestor`
  26. Past the ceiling it is a 503, never a silent `false`. The panel's "~23" came from a simpler
  model and had never been measured on (c2).

### Lot 3b-2d — the outbox, and the `facts` driver refuses to be built without it

Fourth lot of the `facts` mode. Closes S5 (drift and rollback), which the
panel scored as a 🔴 that would have disqualified `facts` if left unmitigated:
with the tree in OpenFGA and the tree in your database written separately, a
**rollback of your own transaction** leaves a persistent escalation that your
database cannot show you. Correct use leaks — no misuse required.

- **`ScopeOutbox` port** (`enqueue`/`pending`/`markApplied`/`markFailed`) plus
  `scopes.outbox` in the config. With it, `scopes.attached/moved/detached`
  **enqueue inside the consumer's own transaction** and do not touch the driver
  at all. Validations (cycle, parent, `within`) still run first, and the
  identity is canonicalised **at enqueue time** — by relay time a `detached`
  scope would no longer resolve.
- **`sqlScopeOutbox`** over Lucid, plus a migration stub that `configure` does
  **not** publish: the outbox is opt-in and the package imposes no table.
- **`authz:scopes:relay`** / `manager.relayScopeChanges()`: platform API,
  resumable, **stops at the first failure** (tree order matters), reports what
  it applied and exits non-zero, with an anti-loop bound if the outbox never
  marks anything applied.
- **Construction gate**: a driver in `hierarchy: 'facts'` with neither an
  outbox nor an explicit `acceptScopeDriftRisk: true` throws 500
  `E_AUTHZ_SCOPE_DRIFT_UNGUARDED` **at construction**, not at the first write.
- **The README says it in the words the risk deserves**: the relay lag is a
  **temporary fail-open** — the old tenant keeps access after a `moved`, and
  inherited denies do not apply after an `attached` — and a test pins those
  sentences so they cannot be softened later.

Demonstrated against a live server with a real SQL tree: without an outbox, a
rollback leaves `authorize` answering `true` for a holder of the old tenant;
with the outbox, the same script leaves the queue empty and `authorize` answers
`false`. The middle case is asserted too — after the commit and **before** the
relay, OpenFGA still answers with the old tree — because that is the exact
shape of the accepted 🟠 risk and it belongs in a test, not in a footnote.

**Known hole, declared rather than hidden**: the gate reads the `outbox` option
of the *driver*, but the component that enqueues is the manager, which reads
`config.scopes.outbox`. Declaring it only on the driver leaves the gate
satisfied and the mitigation switched off. Closing it properly requires the
manager to know the driver's `hierarchy`, which is the capabilities piece of
lot 3b-2e.

### Lot 3b-2c — `authorize` is one single `Check` in `facts` mode

Third lot of the `facts` mode. Additive: in `resolver` mode nothing changes.

- **`authorize` = one `Check`** of `can_<P>` on `scope:<key>`. Spy: **1**
  `check`, **0** `batchCheck`, **0** `resolveChain` — the chain is resolved by
  OpenFGA through `parent`, not by the package through the consumer's tables.
  The catalog memo guard is kept intact: an **unknown permission** is `false`
  (invariant 5) and never a 400 from the server turned into a 503.
- **`authorizeMany` = one `batchCheck` of N items**, one per distinct scope
  (repeats share an item), instead of the N scopes × M granting roles of the
  `resolver` mode. Any `error` on any check is still a 503.
- **`grant`** now writes the two new edges (`scope#binding`,
  `role_binding#role`) besides the `assignee`; **`revoke`** leaves the link in
  place — inert with no assignees, and another holder still uses it.
- **`deny`/`removeDeny`** become `scope:<key>#denied_<P>@<holder>` instead of
  the `deny_binding` type, and **their readers move with them**: `listDenies`,
  the deny filter of `listScopes`, and `purgeScope` (which in `facts` purges
  the `scope:<key>` object except `parent`, respecting the S6 order). Moving
  the writer without its readers would have left a fail-open in `listScopes`
  and a purge that "proves zero" while the deny was still standing.
- **Fixes a defect of lot 3b-2a**: `projectCatalog` read `Read({object:
  'role:'})` with no `user`, which the real server rejects with 400 (*"the
  object type field is required and both the object id and user cannot be
  empty"*), so `syncAuthzCatalog` with a projection was a 503 against any real
  store. The in-memory double of 2a accepted it and the projection had never
  been exercised against a live server. It now reads by holder wildcard, with
  a case that runs against the real server.

### Lot 3b-2b — the scope tree as facts (`hierarchy: 'facts'`, additive)

Second lot of the `facts` mode. Still additive: the driver defaults to
`hierarchy: 'resolver'` (today's behaviour, the package resolves the chain on
every question and `scopes.*` writes nothing to the store), `authorize` is
unchanged, and the five suites answer exactly as before.

- **New option `hierarchy?: 'resolver' | 'facts'`** on `OpenFgaDriverOptions`.
  With `'facts'`, `authorization.scopes.attached/moved/detached` maintain the
  tree in the store as **one** edge per node:
  `scope:<child>#parent@scope:<parent>`, with the *canonical* identity of both
  ends (`chain[0]`, invariant 17 — a uuid alias must not open a second branch).
  Re-attaching to the same parent writes nothing (invariant 6).
- **Anti-cycle checks live in the package, before writing, and are not
  optional** (panel 2, cross 3). Measured against OpenFGA v1.19 and reproduced
  in the suite: the server **accepts** an edge that closes a cycle, does not
  hang, answers in 2–7 ms, and inheritance becomes bidirectional — a grant on a
  descendant grants on its ancestor, and with the root inside the cycle it
  grants across the whole store. A silent fail-open with nothing to catch. The
  three checks (`child ≠ app`, the parent exists, `child ∉ ancestors(parent)`,
  all 422 with no edge written) already ran in the manager; the driver now
  repeats them, because `manager.driver()` is the documented way past every
  barrier in the package.
- **`moved` is one `Read` and one `Write`** (cross 8). The `Read` of the current
  parent is mandatory — FGA refuses to delete a tuple that does not exist — and
  the delete of the old parent travels with the write of the new one in the
  **same** request, which is atomic. Two requests, one mutation.
  `writeTuples()` + `deleteTuples()` stays forbidden.
- **New error `ScopeTreeDriftError`** (500, `E_AUTHZ_SCOPE_TREE_DRIFT`): more
  than one `parent` edge for the same scope means somebody else writes to the
  store. It is reported, never "fixed" — with two parents inheritance is
  already pulling facts from another branch and picking a survivor would be
  guessing which of two live grants is the right one. `detached`, which takes
  the node away entirely, does remove them all.
- **`detached`: facts first, edge last** (S6). The manager already purged the
  facts (`purgeScope`, which proves zero or throws) before notifying the
  driver; that order is now pinned by a case. Backwards, a purge that died
  half-way would leave live grants on a scope with no ancestor: the denies it
  inherited from its parent would stop applying and those permissions would
  become **undeniable** (invariant 2).

### Lot 3b-2a — the `facts` model generator and the catalog projection (additive)

First lot of the `facts` mode (panel 2, variant **(c2)**). Nothing on the hot
path changes: `authorize`, `grant` and the `list*` still work exactly as in
3b-1b, no store gets the new model on its own, and no tuple of the projection
is written unless a caller passes the new option. What lands is the piece the
rest of 3b-2 is built on, testable on its own.

- **`openFgaFactsModel(holderTypes, permissions)`** generates the (c2) model:
  `role#permits_<P>@<holder>:*` (the catalog as tuples, editable at runtime),
  `role_binding#<P> = assignee and permits_<P> from role`, and a `scope` type
  where `<P>` and `denied_<P>` inherit downwards through `parent`,
  `can_<P> = <P> but not denied_<P>` and `ancestor` gives `isWithin` /
  `descendantsOf` with zero extra tuples. Exported from
  `@jantstack/adonis-authz/openfga`. It is written against a real OpenFGA in
  the suite: a model the server rejects is a broken generator.
- **Family collisions are an error, never a silent collapse** (S4). Four
  families per permission (`<P>`, `can_<P>`, `denied_<P>`, `permits_<P>`) share
  one namespace, so `can_docs:read` and `docs:read` would generate the same
  relation — which used to publish a model where a deny did nothing. The
  generator keeps a name→origin map and throws 422 naming both permissions and
  the relation, before anything reaches the server.
- **`syncAuthzCatalog(catalog, { projection })`** — new *optional* option. The
  catalog stays local property (the rule is now: a driver **may** keep a
  derived projection if it is rebuildable, `reconcile` watches it and it is
  never read as catalog). With a projection, the sync (a) checks **before
  writing** that the resulting catalog is publishable — relation names ≤ 50,
  object ids ≤ 256, and the model under the server's 262,144-byte ceiling
  (500 `E_AUTHZ_MODEL_TOO_LARGE`, warning past 80 %) — and (b) mirrors the
  role→permission links as tuples once the transaction has committed, writing
  what is missing and **deleting** what the catalog no longer backs, in one
  `Write` per batch. Dropping one permission from one role with three holder
  types is three deletes in a single atomic request and no model rewrite; a
  second identical sync writes zero tuples.
- **New error `ModelTooLargeError`** (500, `E_AUTHZ_MODEL_TOO_LARGE`).
- The ceiling is measured the way the **server** measures it (the protobuf size
  of the model, verified byte-for-byte against OpenFGA v1.19 for four different
  catalog shapes), not on the JSON: the proto/JSON ratio swings between 0.33 and
  0.57 with slug length, so a JSON ceiling either lets through what the server
  rejects or rejects legal catalogs with twice the margin.

### Lot 3b-1b — an interrupted prune says what it already deleted (**breaking** for anyone catching the driver error)

Closes the two honesty findings of the phase-3b test review (§6.1, §6.2). §6.1
is the headline of lot 3b-1 above, corrected. §6.2 is here:

- **`pruneOrphanRoles` throws `PruneInterruptedError` (500,
  `E_AUTHZ_PRUNE_INTERRUPTED`) instead of letting the driver's error escape.**
  The sweep is not transactional *between* roles — this is documented and
  deliberate — so a `purgeRole` that fails half-way leaves the previous roles
  deleted for good. On that path the return value never happens, and 3b-0b
  justified `purged: CatalogRoleRef[]` precisely with *"whoever catches the
  error needs to know **which** ones went"* — which the caller could not know,
  because the error carried nothing. It now carries `purged` and `skipped` with
  the same shape as the return value, names in its message how many are already
  gone and that the next pass collects the rest, and wraps the driver's error as
  `cause`: the abstraction does not leak, and every error of the package has a
  `status` and a `code`. The `role_purged` events and `error.purged` are pinned
  to name **exactly** the same roles — there are no two truths about what was
  deleted.

### Lot 3b-1 — inherited debt from phase 3: the package stops promising what it does not check

Honesty lot. No new feature, and **one** behaviour change in `src/`: the diff
now accumulates the shadows of *every* catalog, which makes
`authz:catalog:diff --fail-on-shadows` exit non-zero on builds where it used to
exit `0` (a shadow caused by a role of catalog #2 was printed nowhere). Anyone
gating CI on that flag can see a green build turn red without touching their
code, and the shadow it names was already there. Everything else corrects
published sentences that the code does not sustain, and gives an oracle back to
the things that lost one. From the phase-3 security audit (D1–D3) and the
phase-3 test review.

- **Repairing a shadow takes rank over the *squatter*, and the owner of the
  tree may not have it (audit D1).** The degradation note published *"the
  residual damage … stays repairable by authority plus rank — an ancestor with
  rank above it defines its own role and shadows it"*. `rank` is **your**
  metadata (invariant 8) and nothing forces it to decrease with depth, so with a
  non-monotonic layout — a rank-60 role in a unit under the rank-50
  organization admin who owns that tree — the owner of the tree gets 422
  `E_AUTHZ_RANK_EXCEEDED` from **both** doors (defining its own homonym, and
  `deleteScopedRole`), and `scopes.detached` is not a third door either (since
  2.3 it purges facts and never the catalog). What is always true — and is what
  the sentence now says — is that the **platform** can: every local rank is
  bounded below the highest global rank (`0 < rank < min(actor, highest
  global)`), and `manager.driver().purgeRole(uuid)` measures no rank at all.
  Corrected in `README.md`, `CLAUDE.md` and the `#assertLevelUnderOwner`
  docblock, and fixed with a case.
- **"You only act on a role you outrank" is a write-time check, not an
  invariant (audit D3).** Whether one role shadows another is a function of
  *today's tree*, and the tree moves without asking the catalog:
  `scopes.moved` can drop a subtree under an organization that already holds a
  homonym, and the shadow appears with **no rank judged anywhere** — the owner
  of the moved subtree may then be unable to repair it, because their rank is
  measured on the chain of the shadowing role's owner, where they are nobody.
  2.2 wrote that rule into `CLAUDE.md`, `README.md` and this file as if it were
  an invariant; it is now written as what it is, with `scopes.moved` named as
  the route by which shadows appear unjudged, and fixed with a case.
- **The `resolveChain(victim's owner) === null` window is documented, not
  closed (audit D2).** `#shadowedBelow` treats "not provable" as "no shadow", so
  while the tree does not answer for the victim's owner — soft delete, lagging
  replica, a scope in "pending": the same states the rest of the package accepts
  as normal — a low-rank actor in an ancestor creates the homonym without
  passing the rank check, and once the tree comes back the shadow is real and
  permanent. **Deliberately not rejected**: since 2.3 a role whose owner does
  not resolve is *dormant* and the way out is `authz:catalog:prune-orphans`, so
  refusing here would turn a dormant role into a lock on its `(slug, level)` —
  exactly the mine 2.3 removed — on a condition the caller can neither see nor
  fix. What bounds it, and is now written down: the same actor gets the same
  denial by simply **going first** (the check only protects roles that already
  exist, and squatting a name first has always been free); nothing grants more
  (`authorize` never addresses by slug); `authz:catalog:diff` lists the shadow
  as `shadowedByAncestor` (`--fail-on-shadows` makes it drift); and an ancestor
  with rank — always the platform — removes it. Fixed with a case that pins the
  window, the permanence and the repair.

- **Observability of the diff: the shadows of *every* catalog, one line per
  shadowed role** (the one behaviour change of this lot, see the headline).
  `runCatalogDiff` only formatted the shadows of catalog **#1**,
  and one of the two sources of `shadowedByGlobal` depends on the spec (a spec
  role that shadows a local one), so a shadow caused by a role of catalog #2 was
  printed **nowhere**. They are now accumulated over every catalog with
  deduplication. And `CatalogDiff.shadowedByAncestor` reports **one entry per
  shadowed role** naming the most authoritative shadower (the highest ancestor)
  instead of one per pair: with nested owners `a > b > c` it printed three lines
  for three roles, and the third added nothing. `formatShadowedRoles` now takes
  just the two lists (`Pick<CatalogDiff, …>`), which any previous argument still
  satisfies.
- **Costs that were documented and unmeasured now have a test.** Three of them:
  `syncAuthzCatalog` looks up local homonyms in **one** batched query and not one
  per role of the spec (it runs with the `authz_catalog_version` row lock held, so
  a long critical section is what makes the concurrent `defineScopedRole` 503
  likely); a catalog write that **waits** on that lock past its deadline is 503
  `E_AUTHZ_BACKEND_TIMEOUT` naming `catalog.lock`, and writes nothing (PostgreSQL
  and MySQL — SQLite has no `FOR UPDATE`); and declaring `hooks.onWrite` costs one
  **fresh** `resolveChain` per write, which the `forRequest()` memo does not
  absorb. Nothing in `src/` changed for this.
- **Oracles returned to three published promises.** `purgeScope` purges by the
  **canonical** identity the tree returns and never by the one the caller brought
  (invariant 17) — the driver's own canonicalisation had no case in any engine, so
  a `detached` notified with a uuid alias could have left the facts alive; the
  `null` contract of the published `descendantsFrom` helper (`unknown scope`, not
  "no descendants") lost its case in 2.3 and has it back; and the 500
  `E_AUTHZ_UNSUPPORTED` of `pruneOrphanRoles` on a driver without `purgeRole` was
  only observed through the OpenFGA-only half of a capability pair — it is now
  measured with the `database` driver too, including "it says so **before**
  reading anything" (zero queries).
- **The test harness no longer leaks a database when a script calls
  `process.exit()`.** The non-deterministic PostgreSQL leak was not in the suite
  (which closes at zero, measured) but in ad-hoc scripts that boot the harness and
  exit without awaiting `teardown()`: `process.exit` waits for no promise, so each
  such run left exactly one orphan `authz_test_<8 hex>` (reproduced: 3 scripts ⇒ 3
  databases). `bootApp` now registers a synchronous `process.on('exit')` guard
  that destroys what it provisioned and **says so on stderr**, so a leak can never
  be silent again. Test-harness only; nothing in the published package.

### Lot 3b-0b — "dormant" does not mean "inert", and the sweeper stops trusting a blind resolver

Corrections from the security audit of 3b-0 (verdict: *fit, with corrections* —
no 🔴, no 🟠). All four findings are about the code 3b-0 had just added, so they
close here.

- **`stillGranting`: a dormant role is not necessarily an inert one.** The
  sentence published in three places — "a dormant role grants nothing, is
  nobody's membership and cannot be granted" — was **false, and it was the
  written justification for purging without an actor and without rank**. It is
  false from any **live descendant whose materialised path still goes through
  the owner**: the single visibility rule (invariant 18) asks for the owner to
  be in the chain of the scope you ask about, and that descendant's chain still
  has it. Measured: there the role grants, is a membership on all six read
  paths and **can be granted**, by slug and by uuid. That is the normal shape of
  a two-step delete. *Dormant* now means what it always should have meant:
  **not visible from any live scope whose chain does not pass through the
  owner**. Corrected in `README.md`, `CLAUDE.md` (invariant 18) and the
  docblocks of `manager.pruneOrphanRoles` and `authz:catalog:prune-orphans`.
  And the sweeper stops pretending those roles do not exist: every orphan is
  reported with `assignments` (live facts) and `stillGranting`, and the command
  lists them **apart, with a warning** — purging them revokes permissions that
  work today. The flag is conservative by design (it counts live facts; it does
  not re-resolve each fact's scope), so `false` means "grants nothing, for
  sure".
- **`E_AUTHZ_MASS_PURGE_REFUSED`: the dangerous input is your own resolver.**
  `pruneOrphanRoles` is public on the same manager a controller can reach, and
  it deliberately bypasses `requireActor`/`requireWithin`. The realistic
  accident is not a hand-written call: it is a `scopes.resolveChain` **filtered
  by the request's tenant** — a normal multi-tenant pattern — or running with no
  context (a command, a lagging replica). It answers `null` for everything, so
  every local role looks orphaned and one `--force` pass deletes the local
  catalog of every tenant (measured: 2 of 2 live roles). Now, if **all** distinct
  owners come out orphaned or the orphans are more than **50 %** of the local
  roles, `force` throws 500 `E_AUTHZ_MASS_PURGE_REFUSED` **before deleting
  anything**, naming the ratio; a real large prune passes `allowMassPurge: true`
  (`--allow-mass-purge`). The dry run does not throw — it is the diagnostic you
  need to be able to read — and reports `massPurge: true`. The method is
  documented as **platform API**, next to `manager.driver()`.
- **The owner is re-resolved fresh immediately before each `purgeRole`.** The
  pass used to resolve every owner in one loop and purge in another, so the
  window was the whole pass (N roles + N `resolveChain`), not an instant: a
  concurrent `scopes.attached` or restore deleted a role whose owner was
  already back (measured). A role whose owner came back is now skipped and
  reported: `skipped: [{ role, reason: 'owner-came-back' }]`.
- **BREAKING — `purged` is a list, not a counter** (`purged: CatalogRoleRef[]`).
  The set is not atomic and does not need to be, but if one `purgeRole` fails
  halfway the previous ones are already gone — and with the first bullet that
  can be a partial revocation of live permissions. Whoever catches the error
  needs to know **which** roles went.
- **Facts of live descendants survive `detached`, and wake up with the scope.**
  `scopes.detached` purges the facts of the **exact** scope (invariant 11), so
  an assignment held in a *descendant* whose path went through it is untouched;
  while the branch is gone it grants nothing (the descendant does not resolve
  either), but if the scope is **restored with the same uuid** — an undelete, a
  restore from the bin, re-creating the unit — it grants again **with no write
  of any kind**. Between 2.2's first cut and 2.3 the role took its assignments
  with it, so this *is* a behaviour change and the previous entry marked the lot
  breaking without saying so. It is deliberate: the tree of *today* decides
  (invariant 18). To get rid of those facts, notify `detached` for every node of
  the branch you delete — or wait for `authz:reconcile` (2.3), whose contract
  includes reporting and, with `--prune`, deleting the facts whose scope no
  longer resolves.
- `readLocalRoles()` gains a bound: `maxLocalRoles` (default 10 000) ⇒ 500
  `E_AUTHZ_TOO_MANY_LOCAL_ROLES`, never a partial list. The stale advice to
  "watch `truncated`" in `defineScopedRole`'s docblock is gone with the field.

### Lot 3b-0 — `scopes.detached` purges facts and only facts again; orphan roles are swept by the platform (**breaking**: `scopes.detached` returns `void`, `ScopeDetachOutcome` is gone)

First lot of phase 3b, and it **deletes** code. Five lots of phase 3 touched
`scopes.detached` and **three of that phase's four regressions were born
there**, every one of them by composing pieces that were correct on their own.
The reason was structural: purging *catalog* rows at the end of an operation
that a **tenant** triggers, about a scope that no longer resolves, needs a rank
policy with no chain to measure it on, a subtree enumeration and a degradation
for when that enumeration fails — three moving parts guarding one another. The
requirement behind it (a role whose owner disappears is undeletable and keeps
its `(slug, level)`) has a simpler answer.

- **BREAKING — `scopes.detached` purges facts and only facts** (invariant 11),
  and returns `void` again. Gone with it: the rank policy of the purge
  (`E_AUTHZ_RANK_EXCEEDED` no longer comes out of `scopes.detached`), the
  descendant enumeration for roles, the interaction with the `descendantsOf`
  degradation, the `truncated`/`reason` semantics for roles (both on the return
  value and on the `scope_purged` event) and the `ScopeDetachOutcome` type
  (removed from the public exports). `scopes.detached` no longer needs the
  port's `purgeRole` either: it never writes the catalog, so a driver without
  it (`openfga` until 3b) purges scopes normally.
- **A role whose owner left the tree is *dormant*.** Nothing changes in the
  visibility rule (invariant 18). *(Corrected in 3b-0b above: this bullet
  originally read "it grants nothing, is nobody's membership and cannot be
  granted", which is false from a live descendant whose chain still goes
  through the owner.)* It keeps occupying its `(slug, level)` where it is
  still seen, and `deleteScopedRole` cannot reach it (422
  `E_AUTHZ_UNKNOWN_SCOPE`).
- **New: `authz:catalog:prune-orphans`** (`manager.pruneOrphanRoles({ force })`).
  Lists the local roles whose owner no longer resolves and, with `--force`,
  purges them through `purgeRole` (assignments + links + row, atomically),
  notifying `role_purged` per role. `--dry-run` is the default. It is a
  **platform** operation — no actor, no rank — like `authz:catalog:sync`: the
  cleanup no longer hangs off a write a tenant triggers, which is what put the
  rank policy into the equation in the first place. Roles are read from the
  database (never from a `{ everyMs }` memo) in a stable order by uuid, so the
  listing and the events reproduce identically on the three engines; a driver
  without `purgeRole` says 500 `E_AUTHZ_UNSUPPORTED` before reading anything.
- **Three of the judge's four composition cases are gone with the surface they
  judged** (all three were `scopes.detached` purging roles: unknown ancestor
  with live descendants, bound exceeded with an actor without rank, and
  `descendantsOf` that fails). What replaces them is one case that fixes the
  new invariant: `scopes.detached` purges the facts, **does not touch the
  catalog**, and `pruneOrphanRoles` is the way out. The fourth case
  (`defineScopedRole` that shadows while the subtree overflows the bound) still
  composes two live rules and stays.
- The audit's D4 is resolved by making its premise **irrelevant**: "a role
  whose owner does not resolve is visible nowhere" was false (it is visible
  from any live descendant whose materialised path still goes through the
  owner), and nothing decides anything with it any more. The collision check of
  `defineScopedRole` was already blocking only on homonyms that are **visible**
  from the new owner, so a dormant role never blocks a `(slug, level)` it was
  not already occupying — no change was needed there.
- D7: the two stacked docblocks of `ScopeDescendantsResolver` (the older one
  contradicting the newer about what happens past `maxNodes`) are now one.

### Lot 3G — you only act on a role you outrank, also through the tree and also by shadowing (**breaking**: `defineScopedRole`/`updateScopedRole` now need rank over the roles they shadow)

Closing lot of phase 3. The audit of 3F came back **APTA CON CORRECCIONES**
with one 🟠 that was the **third regression in a row introduced while fixing**,
and all three had the same shape: *two pieces that are correct on their own and
break when composed*. So this lot fixes the 🟠 **and** attacks the cause — the
judge gains four composition cases, the ones that would have caught all three.

- **BREAKING (security) — the rank policy of `scopes.detached` is measured per
  role, on the chain of that role's own owner.** 3F let the purge proceed when
  the notified scope had no chain to measure rank on (so a deleted scope could
  be cleaned up at all), and 3E had made the purge reach the whole subtree with
  `scopes.descendantsOf`. Composed, `scopes.detached(parent)` after the parent's
  row was deleted destroyed the local roles of **live** descendants — of any
  rank, granting at that instant — with no check at all, while
  `deleteScopedRole` and `detached(theUnitItself)` refused the same operation
  with 422 (audit P1: a rank-40 role destroyed by a rank-20 actor,
  `authorize` going from `true` to `false`). Now every role about to be purged
  has its rank measured where it lives, exactly like `deleteScopedRole`, and
  the check is skipped **only** for the roles whose own owner does not resolve
  either — the genuinely unreachable ones, which is what the 3F change was for.
  All-or-nothing is unchanged: one role above the actor's rank and nothing is
  purged. The 422 no longer names a role's slug and rank when the actor has
  rank 0 in that chain (it was catalog enumeration of another tenant, audit P7).
- **`scopes.detached` no longer claims a purge was complete when it cannot
  show it.** The port asks **nothing** of `descendantsOf` about a scope
  `resolveChain` no longer knows — you own your table, so returning the
  children is as valid as returning `null`, and it is now written in the type's
  docblock. Consequence: if the scope does not resolve **and** nothing came
  back from below, `truncated` is `true` (it used to say `false` while the
  child unit's role was alive and granting, audit P2) and `reason` is present
  even with `purgedRoles: 0`.
- **BREAKING — shadowing a homonym takes rank, not just position.** 3F decided
  collisions by authority (global > local of an ancestor > local of a
  descendant) so the owner of a tree could always define its role. But
  authority alone let a **rank-3** actor in an organization make a **rank-40**
  unit role unusable by slug across its whole chain — and the victim could not
  undo it, because their rank is measured on the chain of the *shadowing*
  role's owner, where they are nobody (audit P3′). `defineScopedRole` and
  `updateScopedRole` now require the actor's rank to be **above** every role
  they would shadow (422 `E_AUTHZ_RANK_EXCEEDED`, nothing written), which makes
  the rule uniform across the API: *you only act on a role you outrank*. The
  422 does not name the shadowed role's rank or owner — an ancestor does not
  get to enumerate what is below it.
- **Four composition cases in the judge** (`since('2.2')`, under the
  `purgeRole` capability): `detached` of an unknown ancestor with live
  descendants of different ranks; `detached` with the descendants bound
  exceeded **and** an actor without rank (it must check before it degrades);
  `defineScopedRole` that shadows **and** overflows the bound at once; and
  `detached` of an unknown scope whose `descendantsOf` throws — degrading never
  grants more than enumerating. Each with both faces. The 2.2 count with
  `purgeRole: true` goes from 79 to 83.
- **The race of two `defineScopedRole` has two legal endings when the owners
  are ancestor and descendant** — and the judge said "exactly one winner",
  which passed only because the first of the array usually commits first: 2 ms
  of jitter flip it in PostgreSQL and in MySQL (contract tester). The
  authority rule is not commutative: if the ancestor's commits first the
  descendant's is 422; if the descendant's commits first the ancestor's no
  longer collides — it is written and shadows it. Both endings are now
  asserted, hard (what is in the database is exactly what was confirmed, uuid
  by uuid; never two roles with the same owner; if there are two, the one that
  coexists is the ancestor's and the slug is 422 inside the subtree), and the
  strong promise of `serializedCatalogWrites` is judged where it is true: two
  `defineScopedRole` **for the same owner** end with exactly one role and a 422
  for the loser. The README no longer promises more than that.
- `authz:catalog:diff --fail-on-shadows`: shadows stay out of the exit code by
  default (a tenant must not be able to keep the platform's CI gate red), but
  they mean the by-slug routes of a subtree are dead for everyone, so there is
  now an opt-in gate for whoever wants to hear about it (audit P5). And
  `classifyHomonyms` no longer stops looking at a group because it contains a
  global: a contradictory pair of locals inside it — the only real drift of
  that classification — was going undetected.
- Documented, not changed: the degradation of `descendantsOf` relaxes the level
  rule to the minimal one, the watched actor can trigger it by creating
  children (or by a resolver being down), and the residual squatting stays
  repairable by authority plus rank (audit P4). The message of
  `E_AUTHZ_AMBIGUOUS_ROLE` no longer sends the operator to look for an exit
  code that will not come (contract tester).

### Lot 3F — a scope that is already gone still purges; declaring `descendantsOf` never leaves you worse off; homonyms are ordered by authority (**breaking**: `scopes.detached` return value, `CatalogDiff.shadowedByAncestor`, `catalogInSync` no longer counts shadows)

Closing lot of phase 3: the security audit of 3E came back **APTA CON
CORRECCIONES** — no escalation, and the shadowing verified not to grant
anything extra — with two availability **regressions introduced by 3E itself**
and the residue of the slug mine. The theme, again: *the rules that protect the
platform must not be the thing that stops the platform.*

- **BREAKING — `scopes.detached` of a scope the tree no longer knows purges
  again, and returns what it did.** 3E measured the rank policy on the scope's
  current chain and answered 422 `E_AUTHZ_UNKNOWN_SCOPE` when there was no
  chain — so a consumer that deletes the row and *then* notifies (the order the
  package accepts, and the recipe until 3D) kept the local role, its
  assignments **and the scope's denies** alive, with no way out through the
  manager under `requireActor: true` (`detached` without an actor is 422
  `E_AUTHZ_ACTOR_REQUIRED`). Now the purge proceeds with the rank check
  *skipped* and says so: `scopes.detached` returns
  `ScopeDetachOutcome { purgedRoles, truncated, reason? }` instead of `void`,
  and the `scope_purged` event carries `reason: 'owner-detached-unknown'`. It
  opens nothing: a role whose owner is not in the tree is visible nowhere, and
  refusing only kept its `(slug, level)` blocked for the global catalog for
  ever. With the scope **still** in the tree the rank policy is unchanged.
- **Declaring `scopes.descendantsOf` never leaves you worse off than not
  declaring it.** It is what invariant 18 recommends so that `detached(parent)`
  reaches a grandchild's roles — and above `maxDescendants` (a config bound a
  call cannot raise) it turned `scopes.detached` into a 503 that purged
  **nothing, roles or facts**, and `defineScopedRole` towards a level below
  into a 503 too: the big tenant could no longer delegate downwards. Both now
  **degrade** instead of failing: the purge falls back to the exact scope and
  reports `truncated: true` (return value and event), and the level check falls
  back to the minimal rule (reject only an ancestor's levels), which is what
  every consumer without `descendantsOf` already runs. Neither degradation
  grants anything. A config error (`maxDescendants` out of range) is still 500.
- **BREAKING — homonym roles are ordered by AUTHORITY, and only what authority
  cannot order is drift.** *A more authoritative definition wins and shadows
  the less authoritative one*: **global > local of an ancestor > local of a
  descendant**. So `defineScopedRole` from an **ancestor** of the owner of a
  homonym is no longer 422: it creates its own and shadows the descendant's,
  reported in the `role_defined` event as `shadowedByAncestor` — the same deal
  the sync already gave globals. That was the last shape of the slug mine: a
  rank-5 actor could take a `(slug, level)` from the owner of the tree for good
  (a level that hangs from nobody is accepted by the minimal rule) and keep
  `authz:catalog:diff` — the CI gate of the deploy — red until somebody purged
  role by role. And the diff no longer counts a shadow as drift:
  `CatalogDiff` gains `shadowedByAncestor`, `catalogInSync` ignores it and
  `shadowedByGlobal`, both are printed as information (`formatShadowedRoles`,
  exported) and `ambiguousRoles` keeps only the pair nothing orders — two
  owners each claiming to be the other's ancestor, which is a broken tree.
  Collisions *upwards* (a global, or a local of an ancestor-or-self) are
  unchanged: 422 `E_AUTHZ_CATALOG_CONFLICT`, nothing written.
- **Documented, because it was measured and the text said otherwise.** The
  shadowing does not "only hurt the tenant that took the name": inside that
  chain the slug is dead **for everyone**, the platform included, and `{ uuid }`
  is the form that always answers (`listRoles` returns slugs and cannot tell a
  shadowed pair apart — branch on permissions, not on role names). Under lock
  contention the loser of two catalog writers can be 503
  `E_AUTHZ_BACKEND_TIMEOUT` rather than the 422 the `serializedCatalogWrites`
  capability promises; the sync's critical section is now one batched query for
  the shadow lookup instead of one per role. Switching a deployment to a driver
  without `purgeRole` **freezes** every scope that has local roles
  (`deleteScopedRole` and `scopes.detached` are 500 and the facts stay), and the
  README now carries the way out. `hooks.onWrite` costs a fresh `resolveChain`
  plus a catalog view per write.
- **Corrected, because a mutation run proved the text wrong.** The 3E notes
  claimed the judge asserted the "all or nothing" of `purgeRole` "through the
  port, not through the schema's `CASCADE`". It does not: a driver that
  *forgets* to delete the role→permission links passes the whole suite in
  SQLite, PostgreSQL and MySQL, because `authz_role_permissions.role_uuid` is
  `ON DELETE CASCADE` (and `authz_assignments.role_uuid` is `ON DELETE
  RESTRICT`) — an equivalent mutant under this schema. The guarantee is the
  **schema**, watched by the stub-vs-mirror guard; the link count documents the
  promise without being able to falsify it, and a third-party driver on a
  schema without those actions must delete the links itself. Said so in the
  README, in the judge's case and here.
- **Tests (from the 3E contract tester).** Five mutants that survived are now
  dead: the `AMBIGUOUS_ROLE` message no longer advises the impossible
  ("rename one of them" — the API forbids renaming a local role's slug) and
  `ROLE_NOT_VISIBLE` does not leak another tenant's scope key, role uuid or
  slug (a 422 is what a framework returns verbatim to the client), and
  `scopes.detached`'s "all or nothing" is now observable (a role the actor
  *could* purge is placed first, so a rank check done role by role fails the
  case). Two more of ours: `AuthzWriteEvent.roles` now judges that a `revoke`
  by slug names **every** homonym and that the `{ uuid }` route checks the
  owner before naming a role in the audit event. The transactional re-check's
  *unjudgeable* branch (a homonym owned by a sibling, which cannot be
  classified without resolving its chain while the catalog lock is held) gets
  a deterministic serial case instead of depending on the race. And
  `readRolesOwnedBy` orders by `uuid`, so the sequence of `role_purged`
  reproduces identically on the three engines.

### Lot 3E — global roles win and nothing is silent; a local role never lives above its owner; `scopes.detached` keeps its promise (**breaking**: `syncAuthzCatalog`/`syncCatalogs` return values, `AuthzWriteEvent.role` → `roles`, `purgeRole` optional)

Closing lot of phase 3: the security audit of 3D came back **APTA CON
CORRECCIONES** (V1/V2/V3 closed and demonstrated) with five availability
findings, plus eight from the code review and seven from the contract tester.
The theme of all of them: *a tenant with the lowest privilege in the system
could stop the platform's deploy, and a promise written in the invariants was
only true for the exact, canonical, memo-visible scope.*

- **BREAKING — `syncAuthzCatalog` no longer aborts because of a tenant.** A
  spec (global) role colliding with a local role of the same `(slug, level)`
  used to be 422 `E_AUTHZ_CATALOG_CONFLICT` and rolled the **whole catalog**
  back: an admin with rank 2 defining `admin@unit` inside their own unit
  stopped every future deploy of the platform, including roles that had
  nothing to do with the conflict (reproduced by the auditor in PostgreSQL).
  Now **the globals win**: the sync writes the global and *reports* the local
  roles it shadows. `syncAuthzCatalog` returns a `CatalogSyncReport`
  (`shadowedByGlobal`, `assignableAtViolations`) instead of `void`, and
  `syncCatalogs` returns `{ count, ...report }` instead of a number;
  `authz:catalog:sync` prints them as warnings and `authz:catalog:diff` lists
  them as drift (exit ≠ 0). Ambiguity is fail-closed since 3D, so from
  then on **every** by-slug route to that name inside that chain is 422 — the
  platform's own onboarding of its global role included — and `{ uuid }` is
  the form that answers (corrected in lot 3F, where it was measured; nothing
  grants more, a fact points at a role's uuid). `defineScopedRole` still
  refuses collisions *upwards*; see lot 3F for the descendant case.
- **The sync revalidates every role against a narrowed `assignableAt`.**
  Restricting the levels that may carry a permission only validated the roles
  *of the spec*, so local roles (and globals from another catalog) that
  already carried it kept carrying it and the diff did not mention them: the
  restriction landed half-applied and in silence. They are now reported
  (`assignableAtViolations`, in the sync and in the diff) and **not** deleted
  — what is assigned keeps granting (invariant 1), and the operator decides.
- **BREAKING — a local role may not live *above* its owner.** A `scopeType`
  that is the level of one of the owner's **ancestors** (`app` included) is
  422 `E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER` (new), in `defineScopedRole` and in
  `updateScopedRole`. Such a role is visible nowhere: it grants nothing, is
  nobody's membership, cannot be granted — it only *occupies* that
  `(slug, level)` for the tree owner and for the global catalog. It was the
  cleanest form of the slug mine (like `permissions: []`, closed in 3D). The
  check uses the owner's chain, which is already resolved: the owner's level
  is fine and any other level is assumed to be below, so delegating downwards
  keeps working without extra config; declaring `scopes.descendantsOf`
  tightens it to the levels that really hang below the owner today.
- **`scopes.detached` keeps the promise "a role whose owner leaves the tree
  does not survive".** Three holes, all silent: the facts were canonicalised
  and the roles were not (notifying the same scope through a dash-less alias
  of its uuid — which a PostgreSQL `uuid` column resolves to the same row —
  purged the facts and left the roles alive, blocking that `(slug, level)`
  for the global catalog for ever); the roles came from the catalog **memo**,
  so with `catalogRevalidate: { everyMs }` a role another process had just
  committed survived; and the purge never reached **descendant** owners, so
  `detached(parent)` — what a consumer notifies when it deletes a branch —
  orphaned the children's roles. Now the scope is canonicalised once for
  facts *and* roles, the roles are read from the database, and with
  `scopes.descendantsOf` declared the whole subtree goes. Without
  `descendantsOf` the promise is **bounded in writing** to the exact scope.
- **`scopes.detached` carries the rank policy of `deleteScopedRole`.** Since
  3D it destroys catalog objects, and invariant 15 invites `within` to come
  from a *tenant* session: an admin with rank 5 could tear down through the
  tree the rank-40 role the delegation API denies them. With an `actor`,
  every role about to be purged must have a rank below the actor's, checked
  over all of them before touching any (422 `E_AUTHZ_RANK_EXCEEDED`, nothing
  purged), measured on the scope's current chain. Without an `actor` it
  behaves as before: a platform operation.
- **BREAKING — `purgeRole` is optional in `AuthorizationDriver`, and
  `defineScopedRole` checks it before writing.** Declaring it mandatory broke
  every third-party 2.0/2.1 driver at compile time, and a driver that
  implemented it only to throw could not protect anyone: with the `openfga`
  driver, `defineScopedRole` happily created a local role that **nothing**
  could ever delete — `deleteScopedRole` *and* `scopes.detached` of that
  scope were dead for ever, facts included. Not implementing it is now the
  way to say "I cannot purge" (the `openfga` driver no longer does, until
  3b), and `defineScopedRole` answers 500 `E_AUTHZ_UNSUPPORTED` **before
  creating anything**, naming that scoped roles reach `openfga` with the
  `facts` mode of 3b. The judge's `whenFalse` case, which until now pinned
  that dead end as the expected behaviour, judges the opposite: the state is
  not created, and if it exists by another route (a catalog written by hand)
  the way out — delete the row, the catalog is yours and it is SQL — is
  demonstrated.
- **BREAKING — `AuthzWriteEvent.role` (a `RoleQuery`) → `roles`
  (`CatalogRoleRef[]`).** In 1.x it was `role: string` (the slug); 3D turned
  it into the raw `RoleQuery`, so an audit sink filtering by slug silently
  stopped matching — a loss of *auditing*, not only of types. The event now
  carries the **resolved** role(s): uuid, slug, level and owner. It is a list
  because a `revoke` by slug removes the facts of every homonym in that
  scope; it is absent when the role cannot be resolved (the event never
  guesses, the driver decides). Resolving costs nothing when no `onWrite`
  hook is configured. The `role_purged` events that `scopes.detached` drags
  carry the `actor` of that notification when there is one.
- **`effectivePermissions` no longer throws where it promises a list.** For a
  driver without the optional `rolesInChain`, the manager composes from
  `listRoles` (slugs) and used `roleVisible`, which throws 422 since 3D: a
  legitimate `scopes.moved` that joined two homonyms turned a read into an
  error. It now asks the driver by `{ uuid }` which homonym the holder
  actually has — no guessing, and no attributing the *other* role's
  permissions (the 3D escalation).
- **Errors that no longer name another tenant's identifiers.**
  `E_AUTHZ_ROLE_NOT_VISIBLE` printed the owner scope keys of every homonym,
  visible or not, and the `{ uuid }` route printed the slug and owner of a
  role from another tree — a 422 is what a framework returns to the client
  verbatim. They now say that the name exists but is not visible here, and
  nothing else; `E_AUTHZ_AMBIGUOUS_ROLE` only names roles visible in the
  chain that was asked (which the caller can already see), and no longer
  advises "rename one of them" — the API does not allow renaming: the way out
  is `{ uuid }` to keep operating and purging one to undo the ambiguity.
- `AmbiguousRoleError` is exported from the package root (the README asks you
  to catch it, and it was not reachable); a test now pins that *every* error
  class of `src/errors.ts` is exported.
- `diffAuthzCatalog` no longer dies with a 500 on the corrupt `assignable_at`
  row it exists to report (it read it with the strict parser while the sync
  already tolerated it), `dialectOf` recognises Lucid's `better-sqlite3` so
  the catalog lock's SQLite short-circuit actually fires, `runCatalogDiff` no
  longer recomputes a whole diff to extract the local roles (and prints them
  under their own heading instead of inside another catalog's differences),
  and `OpenFgaAuthorizationDriver.listSubjects` declares `RoleQuery` in its
  signature.
- **Judge.** New capability pair `serializedCatalogWrites` (3E · R2): with
  serialised catalog writes (PostgreSQL/MySQL) the race of two
  `defineScopedRole` must end with *exactly* one winner and a 422 for the
  loser — accepting `oneOf([422, 503])` everywhere left a mutant that turned
  the collision into a backend failure alive; SQLite, which serialises by
  locking the whole database, keeps the lax form. The serial part of that
  case now also exercises the **transactional re-check** (a homonym that
  appears without bumping the catalog version, which only a re-read of the
  database can catch). `purgeRole: true` also counts the
  role→permission links after the purge and judges that `scopes.detached`
  reaches a **descendant's** roles; the
  owner check on the `{ uuid }` route of `RoleQuery` gets its own assertions
  (three mutants that were alive). Counts: 75 cases at `'2.2'`, 79 with
  `purgeRole: true`.

### Lot 3D — the uuid is the role's identity in the *port* too; ambiguity is an error; catalog writes are serialised (**breaking**: `RoleQuery`, `rolesInChain`, delegation API)

The security audit of lots 3A+3B came back **NO APTA** with two reproduced
🔴, and both had the same root: *the slug was still the role's identity on
the decision and write paths, and "the closest owner wins" turned a homonym
into a privilege escalation.* The owner's decision (identity of a role =
uuid, always) now reaches the public port and the delegation policy.

- **BREAKING — ambiguity is an error, not a resolution rule.**
  `CatalogView.roleVisible(slug, level, chainKeys)` no longer picks "the
  local role whose owner is closest in the chain". It returns *the* visible
  role, `null` if there is none, and throws **422 `E_AUTHZ_AMBIGUOUS_ROLE`**
  (new) naming every uuid and owner if more than one is visible. Every route
  that addresses a role by slug — `grant`, `revoke`, `hasRole`,
  `listSubjects`, and the composition path for a driver without
  `rolesInChain` — therefore fails **closed**.
  Why: with roles local to a scope, a *legitimate* `scopes.moved` (the
  platform transfers a unit from tenant B to tenant A) puts two `lead@unit`
  in the same chain, and the admin of A handing out `lead` was handing out
  **B's** role — `authorize(victim, 'billing:write', U1) = true` on a role A
  never wrote. Two `defineScopedRole` in parallel, or one racing a
  `syncAuthzCatalog`, reached the same state without moving anything.
  `authorize` does **not** address by slug and keeps answering (invariant 1:
  what is assigned grants what its role links); `revoke` by slug does not
  choose either — it removes the facts of *every* homonym in that exact
  scope, because removing never grants.
- **BREAKING — the port speaks uuid.** `rolesInChain(subject, chain)` returns
  `Array<{ scope, role: CatalogRoleRef }>` (`uuid` + `slug` + `scopeType` +
  `owner`) instead of a slug, and the manager never goes back from a slug to
  the catalog on the policy path. Going back is what made
  `effectivePermissions` report the *homonym's* permissions: an actor whose
  role granted only `docs:read` was told they had `billing:write` — while
  `authorize` said `false` — and `defineScopedRole` then let them delegate it
  to a puppet. `effectivePermissions` is exactly `{p | authorize(p)}` again,
  and so is the actor's `rank`.
- **BREAKING — `RoleQuery` accepts `{ uuid }`** in `grant`, `revoke`,
  `hasRole` and `listSubjects` (manager and port): the exact form, the only
  one that answers where the slug is ambiguous. The uuid must be in the
  catalog (422 `E_AUTHZ_UNKNOWN_ROLE`) and visible in that scope — declared
  for its level, global or with its owner in the chain — (422
  `E_AUTHZ_ROLE_NOT_VISIBLE`). `{ uuid }` cannot be mixed with
  `slug`/`scopeType` (422). `listRoles` keeps returning slugs (it is a
  membership API) and now documents that they may have homonyms.
- **The uniqueness of `(slug, level)` per chain is enforced, not hoped for.**
  It used to be a read-then-write against the memo with no barrier in the
  database: the unique index is `(slug, scope_type, owner_scope_key)`, so two
  writers with different owners both inserted and the state was permanent. A
  row lock over the candidates does not close it either (there are no rows to
  lock — no gap locks in PostgreSQL). Now `withAuthzCatalogWrite` locks the
  `authz_catalog_version` row (`SELECT … FOR UPDATE`) as the **first**
  statement of its transaction — every write to `authz_*` goes through it, so
  catalog writers run one at a time; SQLite is exempt (it already serialises
  writes) — and `defineScopedRole` re-checks the collision **inside** that
  transaction, reading the database. The loser gets 422
  `E_AUTHZ_CATALOG_CONFLICT`. `authz:catalog:diff` reports homonyms visible
  in one chain as drift (`CatalogDiff.ambiguousRoles`, exit ≠ 0): the
  global+local pair always, the local+local pair when the command can pass
  your `scopes.resolveChain`.
- **BREAKING — the delegation API is the seventh, eighth and ninth write.**
  `defineScopedRole`, `updateScopedRole` and `deleteScopedRole` take
  `options?: ScopedWriteOptions` and check `within` against the role's
  **owner**; `requireWithin` covers them. Without it, a holder whose only
  role was at the **root** could create, edit and delete roles inside any
  tenant with the `ownerScope` that arrived in the request body — squatting a
  global `(slug, level)` included. The README's "all six writes" is now
  "all nine".
- **A role whose owner leaves the tree does not survive.**
  `scopes.detached(child)` purges the local roles owned by that scope —
  before the facts, so a driver that cannot purge roles says 500
  `E_AUTHZ_UNSUPPORTED` without having touched anything — and notifies
  `role_purged` for each (`AuthzCatalogWriteEvent.actor` becomes optional:
  the one on a tree notification may not be there). Before, the row survived,
  `deleteScopedRole` answered 422 `E_AUTHZ_UNKNOWN_SCOPE` (it resolves the
  owner fresh) and that `(slug, level)` was blocked for the global catalog
  for ever. A role with no owner is visible nowhere, so nothing is lost.
- **Hardening.** `owner_scope_key` must be `global` or `<type>|<uuid>` of a
  non-root scope: `app` written by hand is a corrupt row (500
  `E_AUTHZ_INTERNAL`), not a global in disguise visible in every chain. A
  permission's `assignableAt` must fit in `varchar(500)`, checked with 422 at
  **write** time, so a truncated JSON can never turn every `view()` into a
  500. `defineScopedRole` with `permissions: []` is 422 (a role that grants
  nothing only occupies its owner's `(slug, level)`).
  `updateScopedRole` with `slug`, `scopeType` or `owner` is 422
  `E_AUTHZ_INVALID_IDENTITY` instead of ignoring them silently.
- **Tests.** The schema mirror and the published stub now agree on the FK
  actions (`CASCADE`/`RESTRICT`), and the stub-vs-mirror guard compares
  `delete_rule`/`update_rule` (`information_schema.referential_constraints`,
  PostgreSQL and MySQL) — until now the "all or nothing" of `purgeRole` was
  proven by a difference between the test schema and the real one. New judge
  cases: the ambiguity after a `moved` in both drivers, `{ uuid }` resolving
  where the slug does not, `effectivePermissions` with a homonym in the
  chain, two `defineScopedRole` racing, `scopes.detached` purging the owner's
  roles, and driver parity when an assignment's role is declared for another
  level.

### Lot 3B — roles local to a scope (`owner_scope_key`), the delegation API, `purgeRole`, `assignableAt` (**breaking**: schema and port)

- **BREAKING — schema.** `authz_roles.owner_scope_key varchar(80) NOT NULL
  DEFAULT 'global'` (byte-wise collation, in the role unique index, which
  becomes `unique(slug, scope_type, owner_scope_key)`, plus an index by
  owner) and `authz_permissions.assignable_at varchar(500) NULL` (JSON).
  The upgrade recipe in the README carries both (PostgreSQL and MySQL) and
  the suite executes it over a 1.1.0 schema **with a role already in it**:
  the row ends up `global` and the next sync recognises it as the same role
  (*"un rol de 1.x queda con owner_scope_key = global tras la receta"*). The
  published migration is executed on a scratch database of each engine and
  compared column by column with the mirror, and the engine's own `DEFAULT`
  is observed (a row inserted without owner is global).

- **Roles have an owner; one visibility rule in both drivers (B2).**
  `authz_roles.owner_scope_key` is `global` (the config's catalog) or the
  key of the scope that defined the role (`<type>|<uuid>`, the same
  `scopeKey` as the OpenFGA binding ids; `'global'` is reserved and no scope
  produces it — the root gives `app`, everything else carries `|`; the root
  is never an owner). **An assignment in scope S of role R counts iff R is
  global or R's owner is in chain(S), S inclusive** — checked per level of
  the chain, in SQL for `database` (`authz_roles` joined into the
  `authorize` query: `owner_scope_key = 'global' OR IN (keys of the chain
  from that level)`, same number of fact queries) and per level in the
  catalog memo for `openfga` (a role of another tenant costs no check).
  `grant` resolves the role that **exists** in the target scope (global, or
  local to an ancestor-or-self) — else 422 `E_AUTHZ_ROLE_NOT_VISIBLE` when
  homonyms exist elsewhere, 422 `E_AUTHZ_UNKNOWN_ROLE` when none does;
  `revoke` removes the facts of every homonym in the exact scope (removing
  never grants); `hasRole`, `listRoles`, `listSubjects`, `listRoleScopes`,
  `listScopes`, `rolesInChain`, `effectivePermissions` and `authorizedScopes`
  apply the rule. **Problem.** With `unique(slug, scope_type)` two tenants
  could not both have `lead@unit`, and the only way to give a tenant its own
  role was to put it in the platform's config. **Decision.** The owner is a
  column, the rule is one sentence, and it is decided with the tree of
  *today*: moving a unit out of the owner's subtree retires what its local
  role granted there without any write, moving it back restores it (a
  contract case in both drivers). The `database` driver now also requires
  the role to be declared for the level of the assignment in `authorize`
  (`openfga` already did): the two drivers answer the same for a row written
  by hand at the wrong level. **Not done.** Local permissions — a tenant
  combines, never invents (panel decision); `assignableAt` in evaluation.
  Contract (`since('2.2')`, both drivers): *"un rol local de la organization
  A concede en A y sus units (también anidadas), no en B ni en app"*, *"dos
  tenants definen el mismo slug (lead@unit) con permisos distintos"*, *"la
  clave de owner 'global' está reservada"*, *"deny × rol local"*. The
  `CatalogView` carries `owner` and `rank` per role, `assignableAt` per
  permission, `roleVisible(slug, scopeType, chainKeys)` (nearest owner wins,
  then global), `rolesNamed`, `rolePermissionsOf(uuid)`, `topGlobalRank`;
  `role(slug, scopeType)` now means the **global** one and
  `rolePermissions(slug, scopeType)` is gone (ambiguous with owners).

- **`defineScopedRole` / `updateScopedRole` / `deleteScopedRole` (B3).** The
  delegation API of the manager, with a mandatory write-time policy, in
  this order and before anything is written: `actor` required (422
  `E_AUTHZ_ACTOR_REQUIRED` regardless of `requireActor`); owner a real,
  non-root scope, resolved **fresh** (never a `forRequest` memo — auditor
  C3: a unit that moved to another tenant during the request cannot receive
  a role from the old tenant's admin; the owner is written canonical); spec
  grammar (slug, level ≠ `app`, integer rank, permission slugs, name ≤ 100,
  description ≤ 500); every permission in `config.delegablePermissions`
  (whitelist, `[]` by default: nobody delegates anything until declared), in
  the catalog, composable at that level (`assignableAt`) and **effective for
  the actor in the owner** — granted by a role of theirs along the chain and
  not denied there (auditor C2: a deny is not laundered through a puppet) —
  else 422 `E_AUTHZ_PERMISSION_NOT_DELEGABLE`; `0 < rank < min(actor's rank,
  highest global rank)` else 422 `E_AUTHZ_RANK_EXCEEDED` (an actor whose
  roles have rank 0 delegates nothing; a local role of rank 500 written by
  hand still cannot delegate above the global ceiling); and no other
  `(slug, scopeType)` visible where the new role would be — global, local to
  an ancestor-or-self, or local to a **descendant** (it would shadow it) —
  else 422 `E_AUTHZ_CATALOG_CONFLICT` (siblings may share a slug). Update and
  delete require the actor's rank **above** the role's; a global role is 422
  `E_AUTHZ_ROLE_IMMUTABLE`. Writes go through `withAuthzCatalogWrite` (the
  shared version bumps in the same transaction; this process' memos are
  invalidated too, as the sync does), a no-op update writes nothing, and
  `hooks.onCatalogWrite` receives `role_defined` / `role_updated` /
  `role_purged` with `actor`, role, owner and permissions (a hook that
  throws is logged; the write stands). `rank` remains metadata for
  `authorize` (invariant 8: a rank-500 role grants only what it links).
  Without `listDenies`, `defineScopedRole` and a permission change are 500
  `E_AUTHZ_UNSUPPORTED` naming it (the policy will not assume "no denies").

- **`purgeRole(roleUuid)` in the port (B4), capability pair `purgeRole`.**
  `database`: every assignment of the role in every scope, its links and the
  row, in one transaction with the version bump last; re-creating the slug
  (another uuid) revives nothing; unknown uuid 422, malformed 422. `openfga`
  cannot enumerate a role's bindings without reading the whole store and
  **says so** (500 `E_AUTHZ_UNSUPPORTED`, nothing touched) until 3b
  (`facts` + `reconcile`); it declares `purgeRole: false` and the judge runs
  that face (*"sin purgeRole de verdad: el driver lo dice con 500"*).
  `deleteScopedRole` goes through it (500 with a third-party driver lacking
  it, catalog untouched).

- **`assignableAt` on permissions — composition, never evaluation (B5).**
  `{ slug: 'org:settings', assignableAt: ['app', 'organization'] }` declares
  the levels whose roles may carry it. `syncAuthzCatalog` (within the spec,
  before touching the base; and against a permission of another catalog,
  inside the transaction), `defineScopedRole`/`updateScopedRole` and — for a
  link written by hand — `grant` reject a role of another level carrying it
  (422 `E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT`, nothing written). `authorize`
  **never** looks at it: an assignment that exists keeps granting what its
  role links (invariant 1) — contract case in both drivers (*"assignableAt
  es control de COMPOSICIÓN, jamás de evaluación"*). The config wins over
  the stored value (`[]` and an invalid level are 422); the diff reports
  `assignableAt` drift (`assignableAtMismatches`, breaks `catalogInSync`).
  **Deviation from the lot plan, on purpose.** The plan placed `assignableAt`
  on `CatalogRoleSpec`; with a role having a single `scopeType` (its
  identity level), a per-role list can only be `[scopeType]` (a no-op) or
  `[]`. The panel's definition (architecture, H: *"¿en qué niveles puede un
  rol llevar este permiso?"*) and the real need ("a unit role must not carry
  `org.settings.write`") are per **permission**; the plan's observable
  behaviour is kept verbatim — `grant` at a level not allowed ⇒ 422
  `E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT` (the *role* is what is not assignable
  there), and an assignment already made keeps granting.

- **The sync only touches global roles (B6).** Upsert by `(slug,
  scope_type, owner = 'global')`, explicit owner on insert; a spec role with
  the name of a local role is 422 `E_AUTHZ_CATALOG_CONFLICT` in the sync and
  in the diff, nothing written; `prune: 'links'` and the rank rule never
  touch a local role. `diffAuthzCatalog` lists local roles as `scopedRoles`
  (informative; `runCatalogDiff` prints them as *"rol local (propio de
  …)"*), never as surplus.

- **The catalog memo loads the owner and the version channel carries the
  new role (B7).** `CatalogCache` loads `owner_scope_key`, `rank` and
  `assignable_at` (still three queries, one revalidation per question); a
  corrupt `assignable_at`/`owner_scope_key` row is 500 `E_AUTHZ_INTERNAL`,
  never "any level"/"global". A role defined in one manager is seen by a
  manager over another memo on its next question (contract, both drivers).

- **Judge.** `level: '2.2'` (73 cases with `listDenies: true`, 67 without,
  77 with the clock); `DriverCapabilities.purgeRole` (required; `true`
  below `'2.2'` throws); `CONTRACT_CATALOG` gains `org-admin@organization`
  (rank 50) and `org:settings` (`assignableAt: ['app', 'organization']`).
  New exports: `GLOBAL_OWNER_KEY`, `scopeKey`, `scopeFromKey`,
  `formatScopedRoles`, the five errors, and the types `CatalogRole`,
  `CatalogPermissionSpec`, `ScopedRoleSpec`, `ScopedRoleChanges`,
  `AuthzCatalogWriteEvent`, `CatalogPermission`.

### Lot 3A — role identity by uuid; OpenFGA binding ids by uuid (**breaking** for existing stores)

- **BREAKING — OpenFGA binding ids carry the catalog uuid, not the slug.**
  Tuples are now `role_binding:<scopeKey>|<roleUuid>#assignee` and
  `deny_binding:<scopeKey>|<permissionUuid>#denied`, where `<scopeKey>` is
  `app` or `<type>|<uuid>`. `parseBindingId` parses **from the right** (last
  component = uuid, the rest = scope key with 1 or 2 parts) and requires a
  canonical lowercase UUID; `encodeSlug`/`decodeSlug` (`:` → `~`) are gone,
  so `_` and `.` in a slug need no escape and **no `~` ever appears in an id**
  (pinned by a test that collects every object id the driver emits across
  `grant`/`revoke`/`deny`/`removeDeny`/`authorize`/`hasRole`/`listSubjects`/
  `purgeScope`, plus a source guard). **Problem.** The id was parsed by
  counting parts, which the owner scope of lot 3B makes ambiguous (a scope
  key has 1 or 2 parts — panel 2026-08-28 §2-C); the slug escape was not
  injective from the caller's side (L0.8a); and a role shared by slug across
  owners would have cost one check per homonym. **Decision.** The uuid is
  globally unique, so it *is* the id; the catalog — local in both drivers —
  resolves everything else, and `authorize` needs to know nothing about
  owners. **2.x does not read 1.x/2.0–2.1 tuples**: a store written with slug
  ids keeps its tuples, but they grant nothing, are no membership, are counted
  in `driver.diagnostics.unparseableBindings` (and logged), and
  `openfga:import --reconcile` reports them as `extra` (`--prune` deletes
  them) — *"un store con ids 1.x (slug en el id) no es leído por 2.2"*.
  **Not done.** No migration command, by the owner's decision (2026-08-28
  §2): there are no production stores; re-import with `openfga:import
  --reconcile --prune`.

- **Role identity by uuid in `database` (A2).** `findRoleOrFail` returns the
  whole catalog role (`{ uuid, slug, scopeType, owner }`); `hasRole` looks the
  role up per chain level in the catalog memo and queries by
  `(scope, role_uuid)` instead of joining on the slug; `listRoles` and
  `rolesInChain` read `role_uuid` and map it through the memo (a role retired
  from the catalog, or declared for another level, is no membership — D5, as
  before); `listSubjects` resolves the role first (unknown for that level ⇒
  `[]` with no fact query); `revoke` already deleted by uuid. Prepared for two
  roles sharing a slug with different owners (3B). Same answers, same number
  of fact queries (the catalog memo is not a fact query).

- **`CatalogView.roleByUuid(uuid)` and `rolesFor(scopeType, ownerKeys)` (A3).**
  `role()` now returns the full frozen `CatalogRole`; `GLOBAL_OWNER_KEY =
  'global'` and every role is global until 3B adds `owner_scope_key`
  (`rolesFor` already has its final shape: owner global or in `ownerKeys`).
  `syncAuthzCatalog` stays stable by `(slug, scopeType)` — a re-sync keeps the
  uuid even if the spec brings another — and a fixed `uuid` in a role spec
  must be a **canonical lowercase UUID** (422 `E_AUTHZ_INVALID_IDENTITY`,
  nothing written): PostgreSQL normalises it, MySQL/SQLite store it verbatim,
  and the `openfga` driver would not read back a binding id carrying it.
  `assertCatalogUuid`/`isCatalogUuid` live in `src/identity.ts`; the slug
  grammar (reserved names, `can_`/`denied_`/`permits_` families, ≤ 42, the
  `docs:write`/`docs_write` collision) is unchanged — slugs no longer travel
  in FGA ids, but they will be relations of the `facts` model (3b).
  `CatalogView.roleSlugs`/`roleLevels` (slug-keyed) are removed: nothing
  resolves by slug once inside the engine.

## [Unreleased] — 2.1.0

Phase 2 of the 2.0 roadmap: engine primitives and measured optimisation,
**additive** over the 2.0 port (a driver that implements only the 2.0 port
keeps passing the same suite). Lot 2A below is optimisation only — no answer
of the contract changes; what changes is the bill per question, pinned by
spies and by `scripts/bench_authorize.mjs`.

### Lot 2.5-B — closing corrections: the canonical chain (**breaking**), UTC expiry on MySQL, and the review findings

- **BREAKING — the tree resolver answers the canonical chain, and uuids are lowercase.**
  **Problem.** (Security auditor, 🔴.) The consumer's scope table canonicalises
  ids where `authz_*` does not: PostgreSQL's `uuid` type finds the row for
  `BBBB…` and for the 32-hex form without hyphens, MySQL's default `*_ci`
  collation merges case. `resolveAncestors` only returned the ancestors, so the
  chain was built with the caller's spelling, the ancestor's grant applied and
  the deny — written canonical (`utf8mb4_bin`, lot 2.5) — did not match:
  `authorize` went from `false` to `true` on PostgreSQL and MySQL, in both
  drivers, and the suite could not see it because the judge's tree was a JS
  `Map`. **Decision.** The port is now `ScopeChainResolver`
  (`config.scopes.resolveChain`, `resolveChain` on both drivers,
  `withChainResolver` on the port): it returns `[the scope as stored, ...ancestors,
  APP_SCOPE]` or `null`, and the engine uses `chain[0]` as the identity of every
  fact (`grant`, `deny`, `revoke`, `removeDeny`, `listRoles`, `listSubjects`,
  `listDenies`, `purgeScope`, the binding keys of `openfga`, the cycle check of
  `scopes.attached/moved`). The answer is validated (element 0 must be the asked
  scope up to case and hyphens; empty or malformed ⇒ 503 `E_AUTHZ_RESOLVER_FAILED`).
  `hierarchicalScopeResolver` takes `nodeOf` (the row: `{ self, parent }`) instead
  of `parentOf`; `memoryScopeTree`/`ContractScopeTree` expose `chainOf`
  (`resolveChainFrom`). Defence in depth: the identity grammar is
  `[a-z0-9._-]{1,36}` for **uuids too** — an upper-case uuid is 422
  `E_AUTHZ_INVALID_IDENTITY` before any catalog, tree or backend call, so the
  case alias dies at the gate and the canonical chain closes the hyphen alias.
  The judge gains *"un alias del uuid del scope … jamás evade un deny"* and, on
  PostgreSQL and MySQL, runs a second time with the tree in a real
  `demo_scopes` table (`sqlScopeTree`: `hierarchicalScopeResolver` +
  `sqlDescendantsOf`) — red on both engines before the fix. **Not done.** No
  automatic lower-casing of ids: an alias is rejected, never normalised in
  silence; and no `descendantsOf` in the chain — the descendants helper already
  returns rows.

- **MySQL `expires_at` no longer depends on the process time zone.**
  **Problem.** (Auditor 🟠.) `DATETIME(3)` has no zone and `mysql2` binds
  `Date` values with the process `TZ`: a writer in UTC and a reader in Caracas
  disagreed by four hours (Tokyo: nine, the other way). One process could not
  see it; two real processes could. **Decision.** On MySQL the `database`
  driver writes `expires_at` as an explicit UTC string, compares with `now`
  formatted the same way and reads it through `DATE_FORMAT` (`src/drivers/sql_expiry.ts`;
  `openfga:import` and the model trait use the same codec); PostgreSQL
  (`timestamptz(3)`) and SQLite are the identity. `tests/expiry_timezone.spec.ts`
  spawns child processes in `UTC`/`Asia/Tokyo`/`America/Caracas` over the same
  database with the default connection options, in both directions. The harness
  opens its own MySQL connection with `timezone: 'Z'`, which the driver does not
  need and the children do not inherit.

- **Ten review findings and five tester findings, each with its red.**
  `withAuthzScopes` casts a PostgreSQL `uuid` primary key to text against the
  `varchar` subquery (42883 before) and accepts `withAuthzScopes({ clock })`
  (K3, K6; new `tests/authz_scopes_trait.spec.ts`). A re-grant whose `UPDATE`
  touches no row (the row vanished under it) inserts instead of reporting
  `existed: true` over nothing (K4; the purge-vs-grant case asserts on the
  `GrantOutcome`). Audit stamps (`created_at`) use the system clock, not the
  injected one — with MySQL `TIMESTAMP` a clock in 2040 made writes fail (K5;
  the 2040 case now writes under that clock). Judge cases that observe the
  un-clocked driver use instants relative to today, not 2030/2031 (K7); the
  "milliseconds and 2040" case is two cases (K15). `scripts/bench_authorize.mjs`
  runs again (`bootApp` returns a `TestApp`) — `database` on SQLite p50 0.35 ms
  granted / 0.24 ms denied, `openfga` p50 2.48 ms / 0.06 ms (K8). One
  `current_time` per operation in `openfga`: every check of a `batchCheck` and
  both reads of `listScopes` share the instant (K9). CI runs `test:sqlite-file`
  (K10). The stub↔mirror guard executes the published migration on a scratch
  database and compares type, length, precision, nullability and collation per
  column on the three engines (K11). `withAuthzCatalogWrite` classifies a SQL
  client error that escapes `fn` as 503 (PostgreSQL's aborted transaction) and
  the README documents that MySQL/SQLite commit instead (K12).
  `authz_roles.scope_type` carries `utf8mb4_bin` like every identity column
  (⚪4); `maxScopes`/`maxDescendants` are capped at `MAX_SCOPE_BOUND`
  (10 000 000; ⚪6). The tester's `harness_cleanup.spec` (the spawned child
  destroys what it provisioned, K13) is in; the README's 1.x → 2.x upgrade
  recipe is now two literal `sql` blocks that the suite **executes** on the
  1.1.0 schema and compares with the published migration (K14, PostgreSQL and
  MySQL); `sqlite-file` pins `pool.max ≥ 2` with a read that must not wait for
  an open transaction (K16); the Caracas-process case is part of the time-zone
  spec (K17). Judge counts: 36 core / 49 at 2.0 / 66 at 2.1 (70 with the clock;
  60 without `listDenies`).

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
