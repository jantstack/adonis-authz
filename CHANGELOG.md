# Changelog

## [2.5.0-alpha.4] — 2026-10-22 (plan 2.5 · the «before the RC» lot)

### Sub-lot 1 · L11 — the pinned model is the one the config generates

Signed by the owner on 2026-10-17 (decisions (1) and (2) of the «before the RC» lot), on the judge's plan
(`loteRC-plan-juez.md` §1, grafts 2–9 and 15) after the F0 measurements (M-a(2), M-b). Every piece had its red first
and a mutant the corridor kills (`.claude/contexto/loteRC-L11-informe.md`).

**🔴 BREAKING (`openfga`) — `modelId` is required in both `openfga` drivers, always.** *Problem*: the guard that compares
the model with the config reads the model once; unpinned, the server evaluates every request with the *latest* model of
the store, so a `provision` from another process changed what was granted without any comparison seeing it. Until
alpha.3 the pin was required only with a deny type (D14) and by `decideMany` (two patches of the same hole).
*Decision*: `OpenFgaAuthorizationDriver` and `OpenFgaRelationsDriver` throw 500 `E_AUTHZ_CONFIG` at construction without
a non-empty `modelId`, with the recipe (`openfga:provision` prints `OPENFGA_MODEL_ID`); the option is now `modelId:
string` in both option types, and the published config stub requires `OPENFGA_MODEL_ID`. *Not done*: no fallback to
the latest model, not even behind a flag. `database` is not affected. README «Upgrading to 2.5.0-alpha.4».

**🔴 BREAKING (`openfga`) — one model gate per driver: equal in rules, type restrictions and conditions, per type.**
*Problem* (lineage L11, at least its 4th iteration: D-31 only in deny types → ⚪7 → ⚪N4 → R2 → D5-2 → C6-1): every
comparison so far looked at part of the model — the relations driver compared rules but not the type restrictions
(with their condition) nor the `conditions` map, accepted a model *mixed* relation by relation in a type without the
opt-in, and skipped reads and purges; the **roles driver compared no rule at all** (a `can_<P>` without `but not
denied_<P>`, a changed `rooted` or an `assignee` without `not_expired` granted or denied without an error). With C6-1
(auditor of closure 6 of D2) a hand-written `denied_viewer` admitting `group#member with inverted` made an expired-looking
deny live for the server and dead for the package. *Decision*: one pure function, `factsModelDifferences` (exported by
`/openfga`), canonicalises the served model (the proto3 noise of v1.19.0 — `module: ""`, `source_info: null`,
`condition: ""`, `generic_types: []`, `object: ""` — and the order of keys and of commutative children; never an empty
`{}`), regenerates the model from the config with the permissions the served model itself declares and the deny form per
**whole** type (D8), and lists the differences by path; a relation *more* than the config declares is drift. Each driver
runs it once per process (memo shared with its views, a 503 not memoised) and, before the first call of every
operation, answers 500 `E_AUTHZ_CONFIG` naming the differences with zero calls that evaluate or write. Relations compare
per operation (its types, `group` and the conditions; an operation on `group` compares every type); roles compare
`scope`, `role`, `role_binding`, the holders and the conditions. *No exemptions*: reads and purges pass the whole gate;
`enumerateRelations(Many)`/`enumerateFacts` — the source of a migration — pass only the `conditions` part. It replaces
D-31, R2, the per-relation D8 exception, `#modelDenied` and `#assertPinnedForDecideMany`. *Not done*: a type of a shared
store that belongs to neither the package nor your config is not compared (no generated rule references it; a case
proves it structurally); CI only runs OpenFGA v1.19.0 — another server version that serialises differently is caught by
the `provision` re-read, below, not by the suite.

**`openfga:provision` re-reads what it published.** *Problem*: the canonicaliser had no anchor against the real server
other than the suite. *Decision*: after `writeAuthorizationModel` the command reads the model by id and compares it whole
(both branches); different or unreadable ⇒ exit 1, `provision RELECTURA FALLIDA:`, «the model IS published, do NOT pin
it», and no `OPENFGA_MODEL_ID=` line. Its clients and `provisionOpenFgaStore` run with `maxRetry: 0` (SDK 0.9.6 retries
by default, and a retried `createStore` can orphan a store). *Not done*: the SDK floor (`>=0.9.6` in `peerDependencies`)
goes with sub-lot 5.

**A tuple's expiry has one reader, `fgaTupleExpiry`, with four states — and "unreadable" is no longer "permanent".**
*Problem*: six call sites read `condition?.context?.valid_until` with `new Date()`: any condition named anything was read
as `not_expired` (C6-1), a sub-millisecond fraction was truncated (C6-2: the package said "expired" one millisecond
before the server, measured 30/60 wrong), a decimal comma or a `±24:mm` offset that the server accepts became `NaN` ⇒
`null` ⇒ **permanent**, and a context without `valid_until` (a 400 for the server) was permanent too — and the reconcile
migrated it as a permanent grant. *Decision* (graft 2, measured in F0 · M-b): `not_expired` only with the context exactly
`{ valid_until }` and the server's grammar, rounded **up** to the millisecond (58/58 against the server); otherwise
`foreign` or `unparseable`, and a table of readers that fail closed: `relate`/`grant` on such a key ⇒ 409
`E_AUTHZ_RENEWAL_UNSAFE` with nothing written; a deny (or nesting edge) carrying it counts as alive in the renewal check;
the enumerations do not list it (warned and counted); `enumerateRelations` marks it (`RelationTuple.invalidCondition`,
optional) and `enumerateFacts` skips it; the reconcile plan classifies it as the new residue **`invalid-condition`** (L9):
not migrated from the source (a deny refuses the pass, 500 `E_AUTHZ_DENY_MIGRATION_REFUSED`), present and untouchable
in the destination (never pruned, its key never rewritten). `toExpiryDate` stays for SQL only. *Not done*: no attempt to
evaluate a foreign condition — the server ignores *another* condition under the generated model (M-a(1)) but evaluates a
`not_expired` that freezes its own `current_time` (H2, alive): where the package cannot tell, it counts the tuple alive
wherever it denies or counts (closure, below).

**Changed expectations (cases that turned red, on purpose).** The D14 case «without deny types an unpinned driver is
fine» is now the same 500; the `decideMany` memo case (🟡 3 of closure 1 of D1) cannot be built any more (no driver
without a pin) and now pins that check and `decideMany` use the same model; the letters of three D-31 cases name the
path that actually differs (`note#denied_editor (regla)`, `document#viewer (regla)`); the N9 case of a retired relation
pins the new config to the model the new config publishes (with the old model pinned the gate now refuses first: that
is the point of L11). The guard property `openfga.model.drift` becomes `openfga.model.equal`, with its three mutants
re-anchored, plus `fga.tuple.expiry`, `openfga.provision.reread`, `openfga.roles.model.equal` (by reflection over the
roles prototype) and the column `model` of the relations table (a probe and a mutant per `openfga` operation).

**Closure of L11 (reviews of the auditor and the contract tester on the diff).** Criterion signed by the owner: *when in
doubt, the option that never grants more*.
- *Problem* (🟠 A1 = H1): the roles gate is a 500 and the scope relay counted it as an attempt, so a deployment whose
  config generates another model parked queued `moved`/`detached` after `maxAttempts` — the old tenant kept its access
  until a manual `requeue` (persistent fail-open). *Decision*: brought forward from the signed decision (3) **only this
  piece**: the gate's error is marked as a deployment failure and the relay treats it as transient (no attempt, no
  parking; `last_error` written). The memo of both gates now keeps only what a *comparison* produced; a failure to *read*
  the model is never memoised, whatever its class (with R3 a 401/403 will be a 500 and must not stick for the process
  lifetime). The rest of `classifyFgaFailure` stays for R3.
- *Problem* (🟡 A2, measured in plan and against the server): a `group` membership with a `foreign` condition (alive on
  the server with a frozen `current_time`) that carries a deny was skipped as an allow, the partition was not refused,
  and the destination granted what the source denies. *Decision*: such a membership (source or destination) in a
  partition with any deny refuses the partition (`partitionsRefused`, new cause `invalid-condition`, its recipe; zero
  writes). `countRoleAssignments` counts `foreign`/`unparseable` assignees (3b-2j: "I don't know" never degrades to "does
  not grant"); the roles denies that decide `listScopes` count them alive (twin of the relations renewal check); a source
  deny whose key the roles destination holds with such a condition refuses the writing `authz:reconcile` (500
  `E_AUTHZ_DENY_MIGRATION_REFUSED`, the twin of relations); `enumerateRelations` emits them with `expiresAt` = the epoch
  (expired for a reader that ignores the mark: that fails closed for an allow but **open** for a deny or a membership
  carrying one — no date is safe for both, readers must check `invalidCondition` first).
- *Closure-2* (re-attack of the auditor): the refusal above blocked the roles **maintenance** pass itself (`--to=<active>`,
  source = the same store) on every run, and with it the repair of what is derived (root marker, tree, the
  `drift.roleVisibility` sweep of invariant 18). `enumerateFacts` now **marks** such a deny (`ReconcileFact.invalidCondition`)
  instead of emitting it clean; the maintenance pass does not count it as blocked, leaves it untouched and reports it
  (`invalid-condition`, drift); `--to=database` migrates it as a deny (fails closed) and declares it. The relay prints a
  deployment failure on its own line (`fallo de DESPLIEGUE #…`) instead of "the backend did not respond".
- *Smaller*: `openfga:provision` prints `provision RELECTURA OK:` when the re-read is equal; the gate of `attached`/
  `moved` runs before the edge is resolved (as in every other method); a relation or condition named `__proto__` is drift
  (canonical objects without prototype); README: the per-type rule, the relay, the counts row, the
  `E_AUTHZ_RENEWAL_UNSAFE` row, and a runbook note — a store deleted on OpenFGA v1.19 (memory engine) keeps serving and
  accepting writes.

### Sub-lot 2 · R3 — an OpenFGA failure says what it is (one classifier, three entry points)

Signed by the owner on 2026-10-17 (decisions (3) and (4) of the «before the RC» lot), on the judge's plan
(`loteRC-plan-juez.md` §2) with the auditor's H1, H9 and H10, after the F0 measurement M-d (41 error shapes of SDK 0.9.6
against OpenFGA v1.19.0). Red first, and a guard property with 15 mutants (`.claude/contexto/loteRC-R3-informe.md`).

**🔴 BREAKING (`openfga`) — a 4xx of the OpenFGA server is no longer a 503.** *Problem*: every failure that was not a
timeout came out of both `openfga` drivers as 503 `E_AUTHZ_BACKEND_UNAVAILABLE`, "the backend did not answer" — also a
401, a store or a pinned model that does not exist, or a relation the model does not declare, which answer the same on
every retry; a caller retried forever and an operator looked for an outage. *Decision*: one function,
`classifyFgaFailure` (`src/shared/backend_guard.ts`), called from the THREE places an OpenFGA error can come from — the
relations driver's `#guard`, the roles driver's client wrapper (`guardBackendErrors`) and `alignBatchResults` (the
per-check error of a 200 `batchCheck`, both drivers: until now it was a 503 whatever it said, so `checkMany`/`decideMany`/
`authorizeMany` diverged from `check`, auditor H9). It decides by **HTTP status + the server's error code against an
allowlist**, or by the key of the per-check error (`input_error`/`internal_error`) — **never by the message**, and never
by the JS class alone (408, 409, 418 and 501 are the same generic `FgaApiError`):
- transient — no answer, 5xx (501 included), 408, 429, `deadline_exceeded`, per-check `internal_error` ⇒ 503 as before;
- `authorization_model_resolution_too_complex` (decision 4) ⇒ **503 `E_AUTHZ_RESOLUTION_LIMIT`**, a new code and a
  subclass of `AuthorizationBackendError` (`ResolutionLimitError`, exported): it stays a 503 because at the edge it is
  probabilistic (23 hops fail 4–26 % of the time), and the message points to «Limits»;
- deployment or data the pinned model rejects — 401/403/404, 400 `validation_error`, `authorization_model_not_found`,
  `latest_authorization_model_not_found`, `exceeded_entity_limit`, the client's own validation — ⇒ **500
  `E_AUTHZ_CONFIG` "not transient"**, the server's error in `cause`;
- a race (409, 400 `write_failed_due_to_invalid_input`) ⇒ still re-read by `isDuplicateWrite`/`isTreeWriteRace` through
  `cause`; if it escapes, **409 `E_AUTHZ_WRITE_CONFLICT`** instead of a 503;
- any other 4xx ⇒ **500 `E_AUTHZ_CONFIG`** with `cause`.

*Not a parked outbox* (auditor H1): a 500 of deployment class — and the unknown 4xx — is marked as a deployment failure,
which the tree relay treats as transient (no attempt consumed, never parked; `authz:scopes:relay` prints it as `fallo de
DESPLIEGUE #…`). Parking a `moved` because a token rotated or a store id is wrong would have left the old parent in the
store until a manual `requeue`: a persistent fail-open on the path the outbox exists to protect. **The escaped race does
not count either** (closure of R3, auditor R3-A1; decision (3) said "race ⇒ as before", and before R3 an escaped race was a
transient 503): 409 for the caller, transient for the relay — `isTransientRelayFailure` (`src/errors.ts`) is now the one
rule the manager applies. The measured case: the `moved` sweep (`applyBindingSweep`) rewrites the `scope#binding` edge a
concurrent `grant` of the destination org's local role is writing; a `Write` with `Ignore` still gets FGA's 409 `Aborted`
(169/200 under contention), and five such passes parked the `moved`, keeping the old org's local roles granting in the
moved subtree and plugging its key. `reparent`'s 409 after three rounds is the same class and follows the same rule (its
message no longer blames "two passes" alone). `authz:scopes:relay` prints a race as `CARRERA en #…` and a graph too deep
as `límite de RESOLUCIÓN en #…` (both transient, neither "the backend did not answer"); `ScopeRelayFailure` carries the
error's `code`. A failure that stays transient forever never parks — watch the relay's exit and `--max-age`, not only
`dead()` (README).
The model gate of both drivers already memoised only a completed comparison (closure of L11); a deployment failure while
**reading** the pinned model is now a 500 that is not memoised either (a rotated token recovers without a restart).

*Also*: `isTimeoutLike` recognises the SDK's bare `FgaError` without a response (F0 · M-d note 1: axios' timeout arrives
without `code`, `cause` or `statusCode`); a refused connection has the same shape, and without reading the message the
two are not told apart, so both are the conservative class — **a timeout** (`E_AUTHZ_BACKEND_TIMEOUT`, `indeterminate:
true` on a write). Until now only the package's own deadline won that race. The 41 measured shapes are versioned in
`tests/fixtures/fga_errors/` and feed the cases without a server.

*A write cut by a deadline upstream is indeterminate* (closure of R3, auditor R3-A2; invariant 13): on a **write**, the
server's `deadline_exceeded` and a 504 from a gateway are now `E_AUTHZ_BACKEND_TIMEOUT` with `indeterminate: true` (the
`Write` may have committed after the response was cut); every other 5xx on a write keeps "did not happen", and on a read a
504 stays `E_AUTHZ_BACKEND_UNAVAILABLE`. The README sentence that promised "a 503 that is not a timeout did not happen"
says which 5xx are carved out.

*Exemption, signed*: `isDuplicateWrite`/`isTreeWriteRace` still read the message, for the race's SUB-type ("already
exists" vs "does not exist", the same code); the guard property `fga.errors.classify` sweeps the source and allows
exactly those two, by name — and, since the closure, any read of `message`/`apiErrorMessage`/`responseData` (`.includes`,
destructuring, `String(err)`, `JSON.stringify(err)`) in the classifier, its helpers and the two wrappers is red; the
poisoned fixtures now poison `apiErrorMessage` and `responseData.message` too. `store_id_not_found` left the allowlist and
a 422 is always "unknown 4xx" (both only measured otherwise; same public error). `relations:reconcile` no longer reports
a 401/404/unknown 4xx of `denyPhase` as `reason: 'model'` with the model's recipe: it propagates the 500 with its letter.

*Cases that turned red, on purpose*: S12 (a request without `current_time`, 503 ⇒ 500 `E_AUTHZ_CONFIG`: it shares
`validation_error` with "relation missing from the model" and is a defect of the package, not an outage); H1-6 of L11 (a
`modelId` that does not exist, provisional 503 ⇒ 500); the depth negative of `facts` (still 503, code
`E_AUTHZ_RESOLUTION_LIMIT`); the per-check `validation_error` of D1/A10 (503 ⇒ 500) and the 400 of a `grant` that is not
a race (503 ⇒ 500); the unreachable server of the contract (port closed: `E_AUTHZ_BACKEND_UNAVAILABLE` ⇒
`E_AUTHZ_BACKEND_TIMEOUT`, the conservative class).

*Not done*: the SQL twin (`guardSql`: a missing table or column is still a 503) is out of this release, as signed.
`openfga:provision`/`provisionOpenFgaStore` keep the SDK's error (explicit OpenFGA tools, outside the abstraction).

### Sub-lot 3 · F4 — a cut `moved` never leaves a state that grants past a deny (and the torn read and the races between writers, declared)

Signed by the owner on 2026-10-19 (decision (6b-estudio), option E of the judge, 71/100; decisions (6a) and (6b) of the
«before the RC» lot), on the 6b study panel (`loteRC-6b-estudio-{analista,auditor,tester,juez}.md`) and with the in-process
interpreter of the FGA model as the judge (`tests/helpers/fga_interpreter.ts`). Red first — the new guard property is red
on the previous driver — and six mutants the corridor kills (`.claude/contexto/loteRC-F4-informe.md`).

**🟠 `scopes.moved` of roles on `openfga` granted past a deny between its two writes.** *Problem*: with local roles in the
catalog, a `moved` (and an `attached` of a scope the tree already knows, which is a move) wrote the tree edge first and
swept the `scope#binding` edges of the local roles whose owner left the chain afterwards, in another `Write`. The state in
between — the moved unit under its new parent, the old owner's role still visible — was a **real state of the store**: it
granted to a user the old owner had denied (invariant 2), on 15.9 % of the concurrent checks (auditor of the study,
16.2 % the tester), and a sweep that failed after the edge (a 503 of the catalog, a store drift) kept it until the relay's
retry — or, inline without an outbox, until someone retried or reconciled. The README called it "the temporary fail-open of
the relay lag", which was false: that state gained access a deny had removed. *Decision*: one point of
passage, `reparent`: **(1)** sweep BEFORE the edge — delete the edges the rule of invariant 18 forbids with the NEW chain
(the new parent's chain in the store plus the child); only deletes: writing what the new chain requires before the edge
would grant under the OLD parent when a scope enters an owner that denies; **(2)** the edge; **(3)** the FULL sweep after
it — delete what the rule forbids and write what it requires. Deleting again is not redundant: a `grant` of the local role
that lands between (1) and (2) leaves its edge visible outside the owner, and only (3) removes it. A move cut anywhere now
fails **closed**: the user loses the local role early, never gains it; the idempotent shortcut of a retry (the edge already
there) runs the full sweep, so a relay retry converges from every cut. Since F4 an error after ≥ 1 `Write` of a move is
marked partial by the driver (`markPartialWrite`) — **nobody reads that mark today**: `scopes.moved`/`attached` inline do not
go through the manager's `#write` (no `indeterminate` event) and the relay classifies only by transient/not transient, so it
is not invariant 13 in effect, only the driver's mark, ready for a consumer. *Cost*: zero extra requests without local roles (still one `Read` + one
`Write`); with them, the deletion batches of the previous sweep, the edge, and the batches of the full sweep (with 150
bindings leaving the owner: 5 `Write`s, entering: 3). And one that F4 doubles: each `moved`/`attached` of an existing scope
reads the bindings of EVERY local role of the catalog in both sweeps, whether or not it has bindings in the subtree (2,008
`Read`s with 1,000 local roles and no binding; see the provisional row below).

*Twins* (line (a) of the closure): the `attached` of an existing child goes through the same `reparent` (case in the
property); the idempotent shortcut runs the full sweep (case); the maintenance pass of `authz:reconcile` does not have the
prefix and is not touched — it applies every delete (the old edge and the forbidden `scope#binding` together) before every
write, so until the new edge lands the child does not reach the root; a case against the real server cuts it after its
first `Write` and it does not grant, and a second guard property, **`openfga.roles.reconcile.order`**, judges it without a
server with ≥ 2 delete batches and the old edge in the first one — the shape in which the opposite order (writes first)
DOES grant (mutant `roles.reconcile.writes-first`, killed; with a single batch it survived, because the state in between has
two parents and inherits the old one's deny). `database` has no intermediate state (the rule is evaluated on every question); a
published contract case (F-1) fixes the same `authorize` in both drivers before, outside and back, with a deny in the owner.

*The judge*: the surface-guard property **`openfga.roles.moved.order`** runs `moved` and `attached` on an in-memory client
cut after every `Write`, leaving and entering the owner with 150 bindings (two batches), and checks with the interpreter of
the generated model that no prefix grants what neither end granted, that the same writes in the pre-F4 order DO give a
granting prefix (positive control), the partial mark, the convergence of the retry from every cut — in verdicts and in
tuples —, and the `grant` race; also the four combinations leaving/entering × `moved`/`attached`, a move INSIDE the owner (no
pre-sweep write, no cut loses what both ends grant) and a store cycle (422 with zero `Write`s: the pre-sweep runs after the
store's anti-cycle check). Mutants: `sweep-after-edge`, `writes-before-edge`, `post-writes-only`, `pre-sweep-old-chain`,
`no-partial`, `shortcut-no-sweep`, `pre-sweep-overdelete`, `pre-sweep-before-cycle` — all eight killed by the oracle (the
`Write` count is one more violation, no longer the first assertion to fire).

**The torn read is declared, not removed** (decisions (6a), (6b) and (6b-estudio)): a single `Check` that runs while a
write of the `openfga` drivers is in flight can read one relation of the model before it and another after it, and answer
`true` where neither state grants. Measured on OpenFGA v1.19 + postgres: **1.2–7.1 %** of the checks concurrent with a
role-tree change (`moved`/`attached`/`detached`, up to 7.1 % on a descendant), 1.4–1.8 % with a purge or a membership swap
in one `Write`, 0.02 % across two `Write`s of the relations reconcile, ~10⁻⁵ for any two writes spanned by one check on the
scope they touch. The two contiguous `Write`s of F4, measured by its auditor with the published model (c2r) and the real
driver (OpenFGA v1.19 + postgres, `HIGHER_CONSISTENCY`, 1 writer + 7 readers): **~1.8·10⁻³ on a descendant of the moved
scope when it leaves the owner** (180 in 100,000; 49 in 60,000 in a second run) and ~10⁻⁵ on the moved scope itself (1 in
100,000); a first draft of this entry said "1 in 50,000", a figure of another model (c3u) on the test harness. F4 removes the PREFIX, not that mix: "eliminates the prefix", never "0 grants". New row
**«Torn read»** in the README's Limits (it is caused by whoever writes — in a tree change, whoever moves scopes; one answer
of one check, never persisted; `database` has none). The letter that promised more is corrected: "one atomic `Write`" of
`moved` (README «The `openfga` driver *is* the `facts` mode»; the 2.3 entry of this changelog said "the same request, which
is atomic") and of the relations purge (README «Deny on relations» and its Limits row) now say **atomic for the writer**;
the docblocks of `#purgeByFilters`, `RELATIONS_PURGE_WRITE_MAX` and `onScopeMoved`, and the guarantee of
`relationTransitionOrder`, say **no PREFIX grants** (what the brute force proves) instead of "no intermediate state"; the
README's promise that an upsert would make `atomicRenewal` `true` is now "a candidate, once a concurrent-reader measurement
confirms it". A letter case (`tests/torn_read_docs.spec.ts`) fixes the row, the qualifier and the corrected sentences.
Removing the torn read needs a model or a mechanism change (the c3u model or a seqlock): a 2.6 panel.

**Declared as a PROVISIONAL limit — races between WRITERS of the `openfga` role driver** (owner's decision (F4-carreras),
2026-10-19, option A: a full panel, the fix goes into lot C, before the release candidate, under the "0 🟠 before the RC"
rule). The F4 audit reproduced, without a server and against the real driver (`.claude/reproducciones/loteRC-F4-auditor-races.ts`),
five interleavings that leave a **persistent** fail-open — a local role granting outside its owner, across tenants and past
the owner's deny, until an `authz:reconcile`: 🟠 `updateScopedRole`/`projectCatalogRole` concurrent with a `moved` (its level
sweep rewrites the edge the move removed); a `grant` that resolved the old chain and writes after the full sweep; a `grant`
during the relay lag of a unit entering the owner (which also makes false the README's "during the lag the old tree keeps
deciding"); two inline `moved` of a parent and its child; and the cost O(local roles of the whole catalog) per `moved`. None
is introduced by F4 and none is a prefix of one cut operation; the README's Limits carry them in a row of their own, and the
sentences "the sweep itself never grants" and "nothing crosses tenants" are gone or qualified.

*Also (closures left by R3)*:
- **⚪ RC-1 — the `write` mark of the relations driver is per call; now every call is watched.** The guard property
  `fga.errors.classify` enumerates, by reflection on the source, every `#guard` call whose body writes (`write`,
  `writeTuples`, `deleteTuples`): each must carry the mark, and each of the seven has a behavioural probe — a 504 of that
  write is 503 `E_AUTHZ_BACKEND_TIMEOUT` (indeterminate): `relate` (new, renewal delete, renewal write), `unrelate`, `deny`,
  `removeDeny` and the purge's `deleteTuples`. A new write site without its probe is red. Two new mutants (the mark removed
  from `deny` only, from the purge only) are killed; until now `npm test` stayed green with either.
- **⚪ RC-2 — the relay no longer says "the backend did not answer" of an expired deadline.** `authz:scopes:relay` prints a
  `E_AUTHZ_BACKEND_TIMEOUT` failure as `PLAZO VENCIDO en #…`: the deadline expired (the client's timeout, or a 504 /
  `deadline_exceeded` of the server or a proxy, which DID answer), a write may or may not have applied (INDETERMINADA), and
  the next pass re-reads; it still consumes no attempt.

*Cases that turned red, on purpose*: the case counts of the judge at level `'2.2'` (`contract_harness.spec.ts`: +1, the
published F-1 case) and the letter case of closure 5 of D2 that fixed "`atomicRenewal` will become `true`" (now "a
candidate"). The counts of `moved` without local roles (one `Read` + one `Write`) and the R3 relay case (the shape thrown by
the sweep's `Write`, five passes) stay as they were.

*Not done*: the c3u model (it removes the torn read of a single tree edge, not the exception of invariant 2 — purges,
reconcile and two writes stay — at −23 % of the permission ceiling and up to ×16 server CPU per deep `Check`): optional in
2.6 or default in 3.0, decided with COGNITIV's data. A hammer case (`AUTHZ_TORN_HAMMER`) was not added: a "0 in N" bounds a
rate, it does not prove the property, and F4's residue is not 0 by construction.

### Sub-lot 4 · R1 — group nesting has a ceiling, and each driver declares its own

Signed by the owner on 2026-10-17/19 (decision (5) «yes, a ceiling ACCORDING TO THE DRIVER», with contextual-tuple
calibration, and (5-bis) option (a) after F0 · M-c), on the «before the RC» panel (`loteRC-plan-*.md`, R1) and the two
variant reports (`loteRC-R1-variantes-{auditor,tester}.md`). Red first — the new rows of the surface guard were born red
with their names — and twelve mutants of the new property `relations.group.depth` plus one of the model column, all
killed by the corridor (`.claude/contexto/loteRC-R1-informe.md`).

**🟠 Nesting groups had no ceiling, and past OpenFGA's a whole object went 503 for everyone who is not a member.**
*Problem*: `relate(group:C#member, 'member', group:P)` accepted any depth in both drivers. On `openfga` a chain of nested
groups longer than the server resolves makes every `check` of a non-member a permanent 503 (a member resolves 24 hops on
v1.19 with the default `--resolve-node-limit`, a non-member with memberships of its own only 22, measured 200/200 at both
edges and independent of `includes` and of the deny), a denial of service within reach of whoever may nest groups.
*Decision*: **each driver declares its ceiling.** `openfga` **calibrates** it on first use — read-only, one `Check` per
probe with the whole chain as contextual tuples on ids that do not exist, `HIGHER_CONSISTENCY`, in the domain shape of the
first declared type (with `group#member` and one hop less when no type has a relation) — as the **minimum** of a member
probe and a non-member probe with memberships (a probe without memberships is blind: it answers `false` at any depth);
22 on v1.19 by default; only success is remembered. It is **on by default**. `database` has no technical ceiling and
none by default; it enforces one only with a separate switch, `database: { enforceGroupDepth: true }`, so that the
number set for an `openfga` CI never switches the gate on in a `database` production. The number is `maxGroupDepth` in
`defineRelationsConfig`: an integer 1..97 or `false`, validated when the config is defined (500 `E_AUTHZ_CONFIG` for `0`,
`NaN`, `''`, strings, non-integers, `Infinity`, `null`, `true`: values that would switch a gate off in silence); in
`openfga` it can only **lower** the calibrated ceiling (a larger one is 500 naming both numbers). On a write, the depth is
the **longest** path of `group ⊂ group` hops through the new edge, upwards from the parent and downwards from the child (a
breadth-first count would admit a DAG whose long branch 503s every non-member); an edge that exceeds it, closes a cycle or
walks more than `GROUP_DEPTH_MAX_NODES` (10,000) groups is **422 `E_AUTHZ_GROUP_DEPTH_LIMIT`** with zero writes and no
event — renewals and revivals included; `unrelate` is never gated. In `database` the graph is read through the same
client that writes: the caller's transaction, so one transaction that writes `A⊂B` and then `B⊂C` sees the first (read
through the engine's connection it would not). In `authz:relations:reconcile` the plan computes, per partition, the chain
the pass would leave — the source's live edges plus what the destination keeps (every live edge without `--prune`) —
against the destination's ceiling (`groupDepthLimit()`, a new optional method of the port, calibrated, so `--dry-run`
gives the same numbers) and **refuses the partition** that exceeds it (`partitionsRefused` with cause `too-deep`,
`report.tooDeep`, zero writes in it, exit ≠ 0; the rest migrates). A pre-existing cycle does not refuse a partition by
itself (OpenFGA evaluates it); its *k* groups count as *k − 1* hops.

**Letter.** The 422's `message` is for the tenant — the chain, the ceiling, `maxGroupDepth`, "nothing was written" — and
names no backend, the rule of `E_AUTHZ_SCOPE_DEPTH_LIMIT` since 2.4.0-alpha.8; why the ceiling exists and the server
knob, `OPENFGA_RESOLVE_NODE_LIMIT`, are in `error.details` (not enumerable). The 503 `E_AUTHZ_RESOLUTION_LIMIT` of a read
now names `maxGroupDepth` and `OPENFGA_RESOLVE_NODE_LIMIT` too (a 503 already names its driver).

*Rejected*: skipping in the reconcile the edges that exceed or close a cycle (the panel's first draft): the skipped edge
can carry a deny, and without it the destination grants what the source denies (🔴 C-1 of the auditor) — the partition is
refused instead, the pattern of decision A. The pass then writes without asking the destination's write gate again (a
module-private marker that only the package's reconcile sets — see the closure below for its form): the gate would refuse the edge that closes a
pre-existing cycle — which the owner decided to migrate — halfway through the pass, or trip on an intermediate state.
Writing the edge, probing and undoing it (V1): the obvious probe is blind, the
undo has no CAS and deletes an edge another writer already confirmed, and the edge is effective for 7–16 ms. A `Check`
probe at the top of the chain on every write: exponential cost on a legal DAG (seconds of server CPU per write with ~40
tuples, measured; it took the test machine down) — the count is linear. Reading environment variables from the package.

*Declared, not closed*: two writes running at the same time that each add half of a chain both pass (each reads the graph
without the other; no lock, in either driver — in `database`, two transactions do not see each other); an `openfga`-only
deployment has no pass that scans chains already in the store (a read-only verifier is planned for 2.6); `listObjects` is
not bound by the ceiling (past it, measured up to 100 hops, it lists correctly while `check` of the pair is 503); the
calibration is per process (since the second closure a limit LOWERED on the server is re-measured after a read's 503;
one RAISED still needs a restart).

*Placement of the knob (the owner's reading of decision (5), signed 2026-10-20: `relations.maxGroupDepth` ≡
`relations.config.maxGroupDepth`)*: it lives in `defineRelationsConfig` — `config.relations.config` — and not as a sibling
key of `relations` in `defineConfig`, because the gate lives in the DRIVERS (so that `manager.driver()`,
`reconcileRelations` and a hand-built driver are gated too) and the drivers already capture that config object; a sibling
key would need plumbing into every factory and would leave those three paths ungated. No alias: the literal path is a
500 that points to `defineRelationsConfig` (second closure, below).

*Cases that turned red, on purpose*: R3-3 of `relations_openfga.spec` built its 26-group chain with `relate`, which the
gate now cuts at hop 23 — it judges the READ side of a pre-existing chain, so it seeds with `maxGroupDepth: false`; the
reconcile case «destination pinned to a model without `denied_*`» answered the calibration's model gate (500
`E_AUTHZ_CONFIG`) before the deny gate — fixed in the code, not in the case: the plan asks for the ceiling only when some
nesting edge exists. The guard's inventory was red on the new `groupDepthLimit()` of both drivers until its rows, its
classification (`PORT_READS`) and its `INVOKE` entry existed, and L9 until the code was classified in `RELATION_REJECTIONS`. Its
F-05 cell is `na: signature` by a new, narrow entry of `NA_MATRIX` (a configuration method without arguments, like the
`withClock` view): there is no type or relation to judge.

**Closure of R1 (auditor and contract tester, 2026-10-20).** Reviews in `loteRC-R1-{auditor,tester}.md`, closure in
`loteRC-R1-cierre.md`; every point below has a case that fails without it, and the property `relations.group.depth` went
from 12 to 39 mutants, all killed by the corridor.
- *The `openfga` gate looked only downwards in every test* (🔴 A of the tester): an edge **below** an existing chain
  (`x ⊂ g0` under 22 hops) needs the upward `Read` (`user = group:<g>#member`, object type `group:`), which had never run
  against a server. It does on v1.19 (measured on :8090), and the edge is 422 with the fake client and with the real one;
  so is a cycle through the `openfga` driver.
- *Read amplification against the shared store* (🟠 1 of the auditor): the downward `Read` brings the group's holders
  too (the server rejects a `Read` filtered by user type: 400, measured), so whoever controls a nesting region made each
  `relate` pay O(groups × members/100) requests. The `openfga` check now runs on a budget per edge —
  `GROUP_DEPTH_MAX_READS` (2,000) requests, `GROUP_DEPTH_MAX_TUPLES` (50,000) tuples, `GROUP_DEPTH_DEADLINE_MS`
  (10,000 ms) in total, counted from AFTER the calibration, so a cold process's first write never pays it— and past any
  of them it is the same 422 (`too-many-groups`, `details.budget` names the bound).
- *The reconcile's marker could be forged* (🟡 2 of the auditor, 🟠 C of the tester): it was a module symbol in the
  options of `relate`, and a `Proxy` that answers `true` to every symbol switched the gate off in both drivers — the only
  way around a gate that lives in the driver precisely so that `manager.driver()` cannot skip it. It is now the
  **identity** of an options object registered in a module-private `WeakMap`, bound to the edge (partition, child,
  parent) and frozen; and the `RelationsManager` hands the driver a NEW object with only `transaction`, `actor` and
  `expiresAt`. The marker is judged with an `openfga` destination too (the real cutover direction): a pre-existing
  cycle migrates whole.
- *The plan undercounted the destination* (🟡 3 of the auditor): only the `invalid-condition` residue entered the final
  chain; every live residue tuple does now (`invalid-identity`, `undeclared`, …: nobody deletes it, not even `--prune`,
  and the server evaluates it); an expired one does not.
- *`NaN` from a spread config switched the gate off* (🟡 4 of the auditor): both drivers re-validate
  `maxGroupDepth`/`enforceGroupDepth` when built and on use (500 `E_AUTHZ_CONFIG`).
- *Letter* (🟡 5 of the auditor): the README now tells a `database` deployment that may migrate to switch
  `enforceGroupDepth` on with the `openfga` number before tenants nest groups, and that one `too-deep` partition blocks the
  whole cutover.
- *Smaller holes, now judged*: renewal gated in `openfga` too; the calibration fake now evaluates the contextual tuples
  (a negative probe without the outsider's membership — blind — and a server that answers the other way round, 500, both
  die); the `group#member` fallback minus one; the identical no-op stays BEFORE the gate in both drivers (invariant 6: a
  repeated `relate` of an edge inside a chain that already exceeds is not a 422); `maxGroupDepth` equal to the calibrated
  value is accepted; a partition exactly at the ceiling migrates; the node cut; a pre-existing cycle weighs *k − 1*;
  expired edges do not count in the `openfga` gate and unreadable conditions do; the destination-only chain is planned;
  the 503's letter. The `database` race case is an explicit skip outside pg/mysql (it used to `return` green). The
  published runner `runRelationsDriverContract` has its first R1 case (a driver that declares `groupDepthLimit()` must
  apply it upwards, downwards and on cycles, with no event): 30 → 31 core cases.

**Second closure of R1 — the six deviations, signed by the owner on 2026-10-20** (`loteRC-R1-desv-{analista,auditor,
tester,juez}.md`, closure in `loteRC-R1-cierre2.md`). Each point has a case that fails without it, and a mutant where it is
a guard.
- *D1 · where the knob lives*: `defineRelationsConfig({ maxGroupDepth, database: { enforceGroupDepth } })`, read as
  `relations.config.maxGroupDepth`; no alias. `defineConfig({ relations: { maxGroupDepth } })` (the literal path of the
  decision) and `relations.enforceGroupDepth` are 500 `E_AUTHZ_CONFIG` with a message that points to
  `defineRelationsConfig`, instead of the generic "unknown key". A case reaches the 422 through
  `container.make('authz.relations')`. **`saveRelationsConfig` no longer persists `maxGroupDepth`/`enforceGroupDepth`**:
  they are deployment keys, validated (same 500) and left out of the stored spec, which an alpha.2/alpha.3 process can
  still read with its key whitelist (nobody read them from the database: the reconcile's plan asks the destination
  driver).
- *D2 · the guard's doctrine*: "`f05` is never `na` except for operations WITHOUT a tuple, by name: `withClock` and
  `groupDepthLimit`" — a name lock separate from `NA_MATRIX` (a new matrix rule cannot open it; a meta case proves it), and
  the zero arity of `groupDepthLimit` is judged by the compiler (`Parameters<…>` is `[]` on the port and both drivers).
- *D3 · the reconcile's marker*: the list of option keys the `RelationsManager` hands the driver is exhaustive by type
  (`satisfies Record<keyof RelationWriteOptions, true>`): a new key does not compile until someone decides it. The
  forged-`Proxy` and other-edge cases now run on `database` too, and the frozen marker is pinned.
- *D4 · the letter*: written in the README as a rule — the 422 is neutral (both drivers share it), the 503 of a read names
  the backend's knob (it only comes from `openfga`).
- *D5 · calibration*: "at boot" means the config is validated; the calibration stays lazy, once per process, now with a
  wait after a failure (`GROUP_DEPTH_CALIBRATION_BACKOFF_MS`, 2,000 ms: the same error, no probing) and a re-calibration
  after a read's 503 `E_AUTHZ_RESOLUTION_LIMIT`, at most once per `GROUP_DEPTH_RECALIBRATION_MIN_INTERVAL_MS` (60,000 ms):
  lowering the server's limit no longer needs a restart, raising it still does (the 500 of a `maxGroupDepth` above the
  calibrated value says so). Two cold nesting writes share one calibration; nothing that is not a nesting edge calibrates.
  The README has a recipe to calibrate in a `ready` hook that logs the error and does not rethrow (a throwing `ready` would
  also take down `authz:relations:reconcile --to=database`, the way back).
- *D6 · invariant 6*: the `database` depth gate reads the graph through the caller's transaction — data of the write,
  like the "does it already exist?", no permission decided —, and under MySQL's REPEATABLE READ the window of the declared
  race is the whole life of that transaction; written in the README, and a new source guard (`database.trx.reads`) pins
  the closed list of methods of `src/**/database_*.ts` that read through the caller's transaction (the two "does it
  already exist?" of roles, the one of relations, and the depth gate).

**Third closure of R1 — the final re-attack** (`loteRC-R1-reataque.md`, closure in `loteRC-R1-cierre3.md`). Each point has
a case that fails without it, and a mutant where it is a guard.
- *R-1 · the D6 guard pins READS, not methods* (condition of the D6 signature; the letter is not lowered). *Problem*: the
  guard listed the methods that read through the caller's transaction, so an authority read slipped into a method already
  on the list (the freeze row inside `#upsert`), a `client.rawQuery(…)` or a module function handed the client all stayed
  green — measured with the auditor's three injections. *Decision*: `database.trx.reads` now classifies **every use** of the
  transaction's client in the reachable methods: a statement (`from`/`table` without `delete`/`insert`/`update` is a read
  of THAT table; any other method of the client — `rawQuery`, `raw`, `query`… — is a read), a hand-off to another method
  of the class (followed) or to a closure of the same method, or a declaration. `CALLER_TRX_READS` lists, per method, the
  multiset of read statements with their table; anything else — the client passed to a module function, an alias
  (`const c = trx`, the limit the second closure declared, now closed), a renaming destructuring, `options.transaction`
  read outside `writer()` — is red with its line. Four new mutants (the three injections and the alias) die.
- *R-2 · a slow server is a 503, not "flatten your nesting"*. *Problem*: the `deadline` bound of the `openfga` nesting
  budget measures the server's latency (another tenant of a shared store can cause it), not the data, and it was the same
  422 `too-many-groups` — which a client does not retry and which tells the tenant to flatten a nesting that is fine.
  *Decision* (the owner's signed rule (3): transient is 503): past `GROUP_DEPTH_DEADLINE_MS` the nesting `relate` is 503
  `E_AUTHZ_BACKEND_UNAVAILABLE` — not the timeout subclass: the write did not happen, so no `indeterminate` event and no
  event at all —, nothing written. The `reads`, `tuples` and `nodes` bounds are deterministic on the data and stay 422.
  *Not done*: decoupling the read bound from the deadline (at real latency the deadline is the effective bound).
- *R-3 · declared*: in `openfga` a group with more than `GROUP_DEPTH_MAX_TUPLES` (50,000) direct holders — and any group
  that contains it — cannot be nested nor have its nesting edge renewed (the downward `Read` brings the holders); whoever
  can add holders to a group can block nestings through it. `database` has no such bound. New row in «Limits».
- *R-5 · the wait after a failed calibration*: every call inside the wait gets a NEW error of the same class with the
  calibration's error as `cause` (sharing the instance shared any annotation a caller made), and a calibration **timeout**
  reaches them as a plain 503: they did not touch the network, so their write is not indeterminate (invariant 13).
- *R-6 · letter*: the errors table names the nesting budget; the misplaced-key tombstones are looked up with
  `Object.hasOwn` (a `constructor` key used to produce a 500 whose message was `function Object() { [native code] }`); the
  500 of `relations.maxGroupDepth` names `runRelationsReconcile`, not the primitive that left the public root.
- *R-4 · declared, unchanged*: any read's 503 `E_AUTHZ_RESOLUTION_LIMIT` (any tenant's) triggers the bounded
  re-calibration, and a spurious `resolution_too_complex` under load would lower the ceiling for the process (fail-closed)
  until the next one or a restart — one sentence in «Limits».

### Sub-lot 5 · 7.1–7.4 — Node 22, the SDK range, no source maps, and relation listings that do not page

Signed by the owner on 2026-10-17 (decisions (7.1–7.3) and (7.4) of the «before the RC» lot; 7.4 is option 4 of the
judge, `loteRC-74-paginacion-juez.md`, 88.5/100). Report: `.claude/contexto/loteRC-7x-informe.md`.

**7.1 · `engines.node` is `>=22`** (was `>=20.6.0`). *Problem*: the declared floor was older than anything the suite,
the CI (Node 24) or the first consumer runs; a promise nobody checks. *Decision*: declare what runs; the CI `compat`
job drops 20.x and now runs the suite (`:memory:`) on 22 and 24, not only `node --check` of the build. *Not done*: no
runtime check — npm's `engines` is the mechanism; AdonisJS 7 and Lucid 22 themselves declare Node ≥ 24 (README).

**7.2 · `@openfga/sdk` is a declared optional peer, `>=0.9.6 <0.10.0`.** *Problem*: only `peerDependenciesMeta` named
it, so npm accepted any version, including a 0.9.4 whose `batchCheck` drops `authorizationModelId` (fixed in 0.9.5) —
under L11 a pinned model that silently is not the one evaluated. *Decision*: the range the suite runs (0.9.6) up to the
next minor; `optional: true` stays, a `database`-only install needs nothing. *Not done*: no runtime version check.

**7.3 · no source maps in the tarball** (`sourceMap`/`declarationMap` off in `tsconfig.json`). Measured with
`npm pack --dry-run` (nothing published): **1,199,323 → 992,957 bytes gzipped (−17.2 %), 4,770,926 → 3,432,512
unpacked (−28.1 %), 279 → 145 files** (the 136 `.map` files gone; the "after" includes this sub-lot's code).
The `compat` job fails if the packed tarball lists a `.map` or the build carries a `sourceMappingURL`;
`tests/package_meta.spec.ts` pins the three `package.json`/`tsconfig.json` facts of 7.1–7.3. *Not done*: no `files`
exclusion trick — the maps are simply not emitted.

**7.4 · 🔴 BREAKING (type of the relations port) — `listObjects`/`listSubjects`/`listDenies`/`membersOf` take no
`page`, and `RelationObjectsPage`/`RelationSubjectsPage` have no `cursor`.** *Problem* (lineage L8, the mute partial
list; and L5, the inert input): the parameter was declared in phase 4 and never implemented — every driver ignored it
and returned everything. Kept, the real pagination of 2.6 would arrive as a silent change of meaning ("today the whole
set, tomorrow 10 and a cursor nobody reads"); made to work now, it was 35–50 h and an audit round before the RC.
*Decision*: out of the four signatures (public type, port, manager) and the `cursor` out of the two answer types — free
today (no driver emitted it, no caller read it), a major after 2.5.0. A page argument that reaches them anyway — anything
but `undefined`, so `null` and `{}` too; `undefined` passed explicitly is "no page" — is 500 `E_AUTHZ_UNSUPPORTED`
naming the operation, **with zero backend calls, in the manager and in both drivers and the `/testing` double**
(`assertNoListPage`, `src/relations/page.ts`), checked after F-05 and the partition (the identity of the question
first). The published runner gains two **core** cases (31 → 33): «without a page the four listings are exhaustive and
carry no cursor» with N = 150 — above the 100 of `enumerate*` and the 100 of OpenFGA's `Read` page, so a driver that
returns its first internal page is red; a `truncated` `listObjects` is accepted only with `listObjectsTruncation` — and
«a page in the four listings ⇒ 500 with zero driver calls» (manager layer; in 2.6 it becomes the `whenFalse` face of
each paging capability). *Also* (the judge's graft 4, tester H2/H3, auditor T-1) **`enumerateRelations(Many)` validate
their page** with one shared function (`assertEnumeratePage`): a `limit` that is not an integer ≥ 1 is the new **422
`E_AUTHZ_INVALID_PAGE`** (`InvalidRelationPageError`; until now `NaN` made knex emit a query **without** `LIMIT`), above
`RELATIONS_ENUMERATE_MAX_LIMIT` (1,000, exported with `RELATIONS_ENUMERATE_DEFAULT_LIMIT` = 100) it is clipped — with a
cursor, nothing lost, declared in «Limits»; an `after` on `database` that is not the canonical uuid that driver emits is
422 with zero statements (until now a foreign cursor was a **503** on PostgreSQL — the column is `uuid` — and a silent
end on MySQL/SQLite: invariant 5); on `openfga` and the double, which never emit a cursor, any `after` is 500. The
surface guard gets a tenth column, **`page`** (22 probe cells: the four listings and `enumerate*` in the four layers,
`openfga.membersOf` takes no arguments; one mutant each, all dead), and a type guard (`@ts-expect-error` on the old
calls and fields: putting `page` back is a red `npm run typecheck`). *Not done*: binding a cursor to its partition (a
cursor of A reused on B skips rows — needs a cursor envelope, lot C / 2.6); the paginated listings themselves (2.6, as
separate `*Page` methods with a capability per operation; the backlog entry is in the judge's verdict); the duplicate/skip
of `enumerate*` on `database` under concurrent renewals (keyset by `uuid`; a 2.6 measurement). A third-party driver that
still declares `page?` keeps compiling (an extra optional parameter is assignable) — the new core case pins the runtime
behaviour. README «Upgrading to 2.5.0-alpha.4: Node 22, the SDK range, no source maps, and relation listings without
`page`», «Limits» (two rows) and «Errors».

### Sub-lot 6 · `openfga` is EXPERIMENTAL in 2.5.x — a versioned opt-in, its open limits declared, closing in 2.6

Signed by the owner on 2026-10-21 (the 2.5.0 strategy, «(b) with a lock», judge 72/100; signatures 1, 2 and 4 of
`panel-estrategia-juez.md`). Report: `.claude/contexto/loteRC-candado-informe.md`.

**🔴 BREAKING (`openfga`) — both `openfga` drivers refuse to be built without `experimental: 'openfga@2.5'`.**
*Problem*: five panels on `openfga` in a row each opened a new 🟠 (F4 → races → TREE → the `permits_*` twin → the relay),
the criterion «0 🟠 before the RC» had no reachable end, and the only consumer goes to production with `database`. Saying
«experimental» only in the README fails open by omission: the published stub picks the driver from `AUTHZ_DRIVER`, so one
environment variable put into production, without a warning, a driver whose declared limits include fail-opens that
persist and can cross tenants — each under its own precondition (concurrent writers with a window of milliseconds, a
cached resolver in the relay, an inline deployment, two concurrent catalog syncs), each with a detector or, where
there is none yet, saying so —
and this package already ruled, for a smaller risk (the relay lag, `E_AUTHZ_SCOPE_DRIFT_UNGUARDED`), that a recommendation
is not a mechanism. *Decision*: `assertExperimentalOptIn` is the FIRST line of the constructors of
`OpenFgaAuthorizationDriver` and `OpenFgaRelationsDriver`: anything but the literal `'openfga@2.5'` — absent, `true`,
`'acknowledged'`, another version, the token trimmed or upper-cased, a non-string — is 500 `E_AUTHZ_CONFIG` naming the
driver, saying «experimental in 2.5.x, not production-ready», how to opt in and that it closes in 2.6, before any other
validation and before the client exists (zero requests). The token carries the version so that an opt-in given for 2.5
is not an opt-in for a later release with other limits. It lives in the constructor, not in the stub or in the
registration of the factory, so `manager.driver()` (and `authz:catalog:sync`), `authz:reconcile --to=openfga`,
`authz:relations:reconcile` and a direct `new` all go through it; a database-only config that registers an `openfga`
factory without using it boots and answers (factories are lazy). `openfga:provision` builds no driver (it creates the
store and publishes the model with the SDK), so it runs without the token and the first driver that serves does not. The `withClock` views inherit it (roles: a prototype
view; relations: rebuilt with the same options). New capability **`experimental`** on both ports (optional, normalised
to `false`, rule D15), `true` on both `openfga` drivers and `false` (explicit) on both `database` drivers, with its pair of
faces in both published judges (one case per face, in every level: the roles runner's literal counts +1, the relations
runner 33 → 34 core cases and 11 capabilities). A guard property, `openfga.experimental.gate`, walks the exports of
`./openfga` by reflection — each one is a driver constructor (by identity, with the gate) or is classified with a reason,
so a new export is born red with its name — and nine mutants of the corridor kill it (each driver without the gate, the
gate not first, `true` accepted, any version accepted, the token normalised, each capability off). The published config
stub keeps both `openfga` factories with the token **commented out** and the explanation. *Not done*: the subpath is not
renamed (two breaks instead of one, and nothing gained over the token); no `logger.warn` instead of the 500 (a warning
does not block, which is the whole point); the stub does not stop registering the factory (with the gate in the
constructor, switching the env is a 500 at first use — fail-closed — and a registered factory costs nothing).

**The open limits of `openfga` are declared, each with a case.** *Problem*: «experimental» without a list is a blank
cheque. *Decision* (signature 1, the new criterion 10 of CLAUDE.md for the stable release): every 🟠/🟡 of `openfga` that
goes to 2.6 is a row of README «Limits» marked *declared limit* — id, figure or "not measured", recipe, detector, the
version that closes it — listed in `tests/fixtures/openfga_declared_limits.json`, and characterised by a case titled
«límite declarado <id>: se voltea en 2.6» that reproduces today's behaviour without a server (the in-memory double and the
interpreter): the settle's transient window, the cost of a `moved` with local roles, two inline moves of the same scope,
a cached resolver in the relay (O-1), a restored scope without an edge (O-3), the orphan `assignee` resurrected by a
reused uuid (C2-1/R2-1), the ORPHAN-edge (C1-4) and the `permits_*` twin. The tree WITH the outbox is declared «closed in
code, not measured» (what is open is a measurement on PostgreSQL/MySQL); its case points at the existing control. A meta-case keeps ids, cases and
rows equal. The PROVISIONAL row «Races between writers… to be closed before the release candidate» is replaced by these
rows. *Not done*: none of them is fixed here — that is 2.6, and closing one now would reopen the series this decision
stops; the torn read keeps its own row (declared earlier) and is not duplicated.

**Closure 1 of sub-lot 6** (auditor `loteRC-candado-auditor.md`: 0 🔴, 4 🟡, 4 ⚪; the owner signed the six questions on
2026-10-21). *Problem → decision*, one line each:
- **Two more declared limits.** The projection of `authz:catalog:sync` is a THIRD writer of the `permits_*` twin (snapshot
  in the transaction, projection after the commit without re-reading): a removed permission comes back, and on a GLOBAL
  role in every tenant — `openfga.catalog.permits-sync`, reproduced in the double with its detector (the catalog phase of
  the dry run). And the `openfga` half of decision (8): `openfga:provision` only refuses a model that DROPS a `denied_*`,
  so narrowing an `includes` silently shrinks what a live deny cuts — `openfga.provision.deny-reach`, reproduced with the
  generated model and the interpreter; it has no automatic detector, said so. The `permits-twin` row stops claiming
  «within the tenant» for every path.
- **`openfga.relay.restored-without-edge` said the wrong effect.** Without a `parent` edge the scope is not `rooted`, so
  it denies everything (fail-closed, divergence from `database`), not «a grant that skips the ancestors' denies»; the
  case now asserts that effect with the real driver over the double.
- **`openfga.tree.outbox` has its case** — it points at the existing control (the relay's fresh parent, rule 7, and the
  `relay.trust-enqueued-parent` mutant); no declared limit is left without a case.
- **The README quick-start no longer opts in for you**: the token is commented there, as in the stub; «Upgrading» shows it
  live, and says that migrating OFF `openfga` (`--to=database`, `openfga` as the source) needs it too — the error says so.
- **«Outside the semver guarantee», bounded**: only the experimental parts of `openfga` — the token and the drivers'
  behaviour — may change in 2.6, a minor, without a major; the subpath, its exports and the rest of the package keep
  semver.
- **The gate never throws something else**: the value that came is described with `typeof` only (an
  `Object.create(null)` or a throwing `toString` was a `TypeError` instead of the 500); and the guard's classifier of
  `./openfga` exports walks the prototype chain and the names (an empty subclass of a driver, or a `create…Driver`
  factory, filed as «not a driver», now turns it red). Two more mutants, both dead.

### Sub-lot 7 · decision (8) — a config change cannot shrink what a live deny cuts (`database` guard, detectors for both drivers)

*Problem.* The reach of a live deny depends on the relations config: a deny on `editor` cuts every grant in
`down*(editor)` (the path cut of D5), so with `editor: { includes: ['owner'] }` it denies a direct `owner`. Narrowing that
`includes` to `[]` — or withdrawing `editor`, or the type — keeps every row and silently stops the deny from cutting
`owner`: what was denied is granted again, persistently (fail-open), with nothing in the reconcile or the model checks to
see it (every `denied_*` is still there). `openfga:provision` only refused a model that DROPS a `denied_*`
(`openfga.provision.deny-reach`, declared in sub-lot 6), and `database` had no guard at all. The first cut of this
sub-lot judged only orphans when nothing was persisted — the usual state of a `database` deploy — and its forced way out
was one boolean that, needed once to adopt, switched the whole guard off for good (owner's panel (8), 2026-10-22).

*Decision* (owner, 2026-10-15 (8) and the eight signatures of the panel (8), 2026-10-22; the property is «for every live
deny, new reach ⊇ old reach», not «the relation still exists»):
- **`database` · the guard.** `saveRelationsConfig` judges the persisted config (the baseline) against the new one over
  every `denied_*` row of `authz_relations`, inside its catalog transaction and before the first write, and refuses with
  **500 `E_AUTHZ_DENY_REACH_REFUSED`** — nothing written, neither the row nor the catalog version — one finding per type
  and relation, each with its line and recipe: `shrunk` («deny con alcance ENCOGIDO», an `includes` narrowed directly or
  transitively), `orphan` («deny HUÉRFANO», a relation or type withdrawn — judged even if the baseline already lacked it:
  an absence in a row that may be stale does not prove the fleet never served it) and **`no-baseline`** («deny SIN línea
  base»: no USABLE baseline — no row, or a row that cannot be typed — while denies live). The baseline is read
  **all-or-nothing**: only `objectTypes[].relations[].{name, includes}`, which must be strings and arrays of strings; any
  broken shape makes it unusable, it is never filtered (filtering underestimates the old reach and lets the narrowing
  through); a pre-2.5 row whose reach fields type is a baseline, so its documented recipe (re-save it) goes through.
  Widening is never refused, and while no deny lives the first row is created freely.
- **Two named ways out, apart.** `{ establishBaseline: true }` lifts only `no-baseline`, only when there is no usable
  baseline (inert otherwise) and still judges orphans — adopt once, with the spec the fleet serves today, in a release
  that does not change `relations.config`. `{ allowDenyReachShrink: ['note#editor'] }` (it was a boolean in the unreleased
  cut) exempts only the findings it names: an unnamed one in the same save is still refused. There is no global `true`:
  any other form of either option is 500 `E_AUTHZ_CONFIG`. And a name that exempts no `shrunk`/`orphan` finding of
  that very save (computed inside its transaction; matching only a `no-baseline` does not count) is 500
  `E_AUTHZ_CONFIG` with nothing written, naming the surplus key: the list switches itself off, so one left in the
  pipeline cannot silently exempt a later shrink of that relation (an inherited orphan is a finding on every save, so
  its name keeps matching until it is cleaned up).
- **One-driver detector.** New export `checkRelationsConfigDenyReach(served, options?)`: read-only, no lock, the same
  baseline reader, deny query and judgement as the guard, in **both directions** — persisted → served (what the guard
  would refuse; `no-baseline` counts) and served → persisted, the **stale baseline** («línea base RANCIA»: a row
  narrower than what is served, from which a narrowing back would look like no change). It returns `ok`, the findings and
  one line each. The recipe: in CI after the save and before serving, and in a cron — never a hard failure in `ready`.
  It is the detector of a `database`-only deploy, where `authz:relations:reconcile` cannot run (it needs two drivers).
- **Both drivers · `--dry-run`.** `authz:relations:reconcile --dry-run` runs the same judgement over the live denies the
  pass already enumerated — source and destination, per partition, zero extra reads — counting **distinct tuple keys**
  (a deny mirrored on both sides is one, it was two): «deny con alcance ENCOGIDO», «deny HUÉRFANO» and «línea base
  RANCIA» are drift (exit 1); without a baseline and with live denies it prints its own line, «alcance de denies: SIN
  línea base y N deny(s) vivos sin juzgar», and exits 0 (the cutover runbook does not persist the config, and does not
  change). In `openfga` this is detection only, until 2.6 (rule (ritmo)): `openfga.provision.deny-reach` names the
  detector and its precondition — a persisted baseline, saved on every provision —, with a case by the command kernel and
  one through the real `OpenFgaRelationsDriver` over a fake client.
- **Declared, `database` (yellow, closes in 2.6, each with its Limits row and characterisation case):** a stale baseline
  hides a narrowing back to it (S-B; the one-driver detector delates it, so persisting the config is a **mandatory
  release step if you use deny** — in the order of its case the CI step after the save does not see it, a cron running
  while the release that wrote the deny serves does); the rolling-deploy window, from the save to the last old pod (S-C); forcing a
  withdrawal and declaring it again resurrects the grants the deny cut (S-E; only recording the reach in the deny
  closes it, W does not).
- **Guard.** Five properties (four without OpenFGA): `database.deny-reach.guard`, `database.deny-reach.baseline`,
  `database.deny-reach.check`, `relations.deny-reach.detector` and `openfga.deny-reach.detector`, with 31 mutants (the
  guard off, the global `true` back, the named way out acting as global, «judge by delta» back, the tolerant read off or
  filtering, `establishBaseline` ignored, global or truthy, one direction only, the count summed, the `--dry-run` line
  missing or turned into drift, the detector blind to `kind: 'deny'`, a surplus name of the named way out accepted, a non-string `type` read as «type
  not declared»…), all dead.

*Not done, and why.* Checking the reach when the deny is WRITTEN (W), or recording it in the deny row, would close the
stale baseline and the window; it touches the hot path of `deny()`, the runbook and every consumer that uses deny before
the RC, so it goes to 2.6 — and becomes the RC's plan B if the system audit rotation rates the stale baseline orange.
Also to 2.6: a check on the driver's first use, persisting the accepted orphans (it needs storage outside the spec: an
unknown key in the persisted spec breaks a mixed deploy), the `openfga` guard against the published model, a guard on the
`connection` (today: save with the same one as the `database` relations driver) and a finding for a relation that enters
the `down*` of a deny with live grants. Withdrawing a type's `deny` opt-in does not change the reach in `database` and is
not judged (in `openfga`, `--allow-drop-deny` covers it). No command saves the config, so neither way out is a flag.

### Docs · the release steps if you use the deny, in one block

At the first consumer's request: README «Upgrading to 2.5.0-alpha.4: the release steps if you use the deny
(`database`)» puts in one place what the guard of decision (8) asks of every release — save the config the release
serves (the guard) → `checkRelationsConfigDenyReach(served)` and fail the job on `ok: false` → serve — plus the
one-time `establishBaseline`, the named `allowDenyReachShrink`, the scheduled check and the `database`-only detector.
No behaviour change.

## [2.5.0-alpha.3] — 2026-10-16 (plan 2.5 · lot D: the deny on relations)

### Plan 2.5 · lot D · D1 — the deny on relations (the core a consumer calls)

Decided by the judge of the tenancy panel (round 2, `panel-tenencia-2-juez.md` §1, §3, §4, row D) and signed by the owner
(2026-10-14: D3, D5, D8, D9, D10, D14, D15); M6 measured first (`m6-medicion.md`). Every piece had a red observed first and
a mutant the case kills (`.claude/contexto/loteD1-informe.md`). The migration and operation half (reconcile with `kind`,
the `provision` guard, the runbook steps, rollback) is lot D2 and is **not** in this block.

**Added — `deny` / `removeDeny` / `listDenies` / `decideMany` on the relations port.** *Problem*: the relations port could
only grant; a consumer that walked a chain of objects with `checkMany` could not tell "denied here" from "nothing here"
(auditor R2-1) and had no way to cut an inherited grant on one object. *Decision*: a deny is the tuple
`object#denied_<rel>@subject` (same table on `database`, same store on `openfga`), written through the same gates as
`relate` (`{ transaction }`, the freeze, F-05, `actor`, `assertWrite`, invariant 13, `onRelationWrite`), and **every read
honours it with a path cut** (D5): a deny on `Y` cuts every grant of `T` with `Y ∈ up*(T)` — a deny on `editor` voids an
`owner` grant entirely; only a direct `viewer` survives. The suite fixes the 192 answers of the 64-state table T1 on
`check`, and the same 64 objects on `checkMany`, `decideMany` and `listObjects`, in both drivers and both doubles, plus the
37 parity rows across the two drivers on the shared store. `decideMany(subject, relation, objects, partition)` →
`('allow' | 'deny' | 'none')[]` is the chain primitive (D9, broad: `deny` if any relation of `up*(down*(R))` is denied;
`allow` wins when `check` grants), with the guarantees of `checkMany` (1..50, `[]`/51 ⇒ 422, F-05 per item, one `now`, a
per-item error ⇒ 503 for the whole batch — never `none`). It answers by the partition of the object (COGNITIV's P-2). *Not
done*: no deny with expiry (below), no `*`, no deny on `group`; `listSubjects` keeps listing facts; `membersOf` (database) subtracts too: one `check` per candidate only when the object has a deny row.

**🔴 BREAKING (types) — `RelationRef.operation` and `RelationWriteEvent.operation` widened with `'deny' | 'removeDeny'`.**
*Problem* (auditor R2-14): a handler written against 2.4 as `if (op === 'unrelate') remove; else add` would index a deny as
a share — TypeScript does not warn about a widened union in an `if`/`else`. *Decision*: widen the union and say it in the
README: **a handler that treats everything that is not `unrelate` as an addition grants too much**; switch on the
operation. The deny event carries the public relation name (never `denied_<rel>`) and no `expiresAt`.

**Opt-in per type, in two phases (D10).** `defineRelationsConfig` takes `deny: 'read' | 'write'` on an object type.
`'read'`: the published model declares `denied_<rel>` and every read honours it, but `deny()` is still 422
`E_AUTHZ_RELATION_NOT_DENYABLE`; `'write'`: writes are accepted. *Why two values*: with one switch there is no safe rollout
with pods of two versions (auditor R2-2: a pod pinned to the old model ignores a deny another pod wrote). *Not done*: `deny:
true` does not exist — it is 422 naming the two phases. A relation of a deniable type is at most **43** characters
(`DENIABLE_RELATION_NAME_MAX`, so `denied_<rel>` fits FGA's 50); a type without `deny` keeps 50 (D-18). A type without
`deny` generates the 2.4.0-alpha.10 model **byte for byte** (D-29: the fused literal of the suite is untouched).

**`openfga`: a pinned `modelId` is mandatory with any deny type (D14), and the pinned model must declare the deny
(D-31).** *Problem*: the subtraction happens on the server with the model each pod pins; a pod floating to `latest`, or
pinned to a model republished without `denied_*`, grants over a denied object. *Decision*: 500 `E_AUTHZ_CONFIG` when
constructing the relations driver without `modelId` if any type has `deny`; and, once per process (shared with the
`withClock` views), the driver reads the pinned model and answers 500 `E_AUTHZ_CONFIG` — naming the missing relations, with
zero writes or checks — on first use of a deny type whose `denied_<rel>` the model lacks. *Not done*: a pod still running
code < 2.5 cannot be guarded (declared row S11; the rollout pins every pod before phase 2).

**`database` honours a `denied_*` row always (D8)**, also on a type without the opt-in: a deny row is a fact, so retiring
`deny` from a type with live denies does not switch them off; `removeDeny` and `listDenies` accept any declared type.
Without `denied_*` rows every answer is the one of 2.4.0-alpha.10 (the cut has nothing to cut).

**No expiry on a deny (D3).** `expiresAt` on `deny`/`removeDeny` — `null` included — is 422
`E_AUTHZ_DENY_EXPIRY_UNSUPPORTED`. *Why* (measured, M5, OpenFGA 1.19): FGA refuses delete+write of the same key in one
`Write` and `on_duplicate: ignore` with a different condition is 409, so changing a live deny's expiry opens a window in
which it does not block, and if the second `Write` fails the deny is gone. A deny can still travel through a group
membership that expires (M6, case C): live ⇒ deny, expired ⇒ the allow comes back, fixed in both drivers.

**`openfga` purges delete in one global order (D-26/S3).** *Problem*: each filter (type × subject) deleted in the order of
its `Read`, so a deny could fall before its allow and a purge cut halfway left an allow alive without its deny
(fail-open). *Decision*: read every filter, delete, then prove zero per filter; the cut purge stays marked as a partial
write (invariant 13). What a cut purge guarantees — and the order — is in *Closure 1 of sublot D1* below: "allows
first, denies last" alone was not enough (a group membership carries denies too).

**S12 per path (M6).** A spy that strips `context` from `check`, `checkMany`, `decideMany` and `listObjects` against the real
server gets **503** on each path — never `true`, `false`, `none` or a list —, with one mutant per path ("error ⇒
false/none/[]").

**Capability `relationDenies` (optional, normalised to `false` — rule D15)** with both faces in the published runner (22
cases on `true`; on `false` the four operations are 500 `E_AUTHZ_UNSUPPORTED` naming themselves, with zero calls).
`contractDenyRelationsConfig()` (published in `/testing`) is the contract config with deny; `contractRelationsConfig()` is
unchanged. The surface guard grew four rows per layer (`deny`, `removeDeny`, `listDenies`, `decideMany`), born red until
they had row, classification, `INVOKE`, F-05 variants and mutants (151 mutants, all dead).

**Declared rows, each with its case and a README line**: leaving a denied group, purging the group, or purging the
group's userset gives access back (S8–S10); an `openfga` pod pinned to the old model grants over a denied object (S11).

### Closure 1 of sublot D1 (auditor `loteD1-auditor.md`: 0 🔴, 1 🟠, 3 🟡, 3 ⚪)

Decided by the coordinator (`loteD1-cierre-coordinador.md`); every finding has a red observed first, a case and a mutant
that kills it (`.claude/contexto/loteD1-informe-cierre.md`).

**🟠 `openfga` purge cut halfway granted through a group membership — one `Write` when it fits, memberships in a `Write`
of their own otherwise.** *Problem* (executed against the server): the D1 order classified by prefix (`denied_*` last),
but `group:g#member@U` is not a deny and *carries* denies; with 100 more grants of `U` the membership fell in the first
`deleteTuples` and `U`'s own allow on the denied object in the second — cut between the two, `check` went from `false`
to `true`, a grant neither the state before nor the state after had (the twin: `purgeSubject(g#member)` with the nested
edge `group:h#member@group:g#member`). The published sentence "a purge cut halfway leaves denies in excess, never in
default" was false. *Decision*: (a) a purge that fits in the server's per-`Write` maximum is **one `Write`**, which FGA
applies atomically — `RELATIONS_PURGE_WRITE_MAX` = 100, measured on v1.19.0 (`--max-tuples-per-write` default: 101
deletes, or 50 writes + 51 deletes, is a 400 and nothing applies); (b) a larger one deletes allows on non-`group`
objects, then **the subject's `group:*#member` memberships in a `Write` of their own** (sorted by object, so the split
does not depend on the `Read`), then the `denied_*`; (c) the guarantee is now "a cut purge grants nothing that neither
the state before nor the state after granted", fixed by a truth table {direct, through a group, nested} × {fits, does
not fit} × {cut after write k} against the server. *Declared row*: with **more than 100 group memberships** of the
subject they do not fit in one `Write`, and one that carries a deny can fall in an earlier `Write` than one that carries
an allow — cut between the two, the subject grants until the purge is repeated (marked `indeterminate: true`). *Not
done*: refusing such a purge with a 500 before deleting — a purge does not wait (invariant 11), and a 500 would leave the
subject being offboarded with *all* its access. `purgeObject` goes through the same function (an object that is not a
`group` has no memberships; on `group:g` every tuple is a membership of g, so each member ends in its state before or
after).

**`decideMany` on `openfga` requires a pinned `modelId`, also without deny types (🟡).** *Problem*: unpinned (legal
without deny types), `decideMany` chose which `denied_*` to ask from the model it memoised once, while the server checks
with the latest model: after another pod republished the model with deny and wrote one, `check` answered `false` and
`decideMany` `none` — the caller's chain kept climbing and granted through the parent (measured: `["none"]`). *Decision*:
500 `E_AUTHZ_CONFIG` naming D14 and the recipe "provision → pin `modelId` → deploy", with zero calls; with the pin the
memo and the `Check` are the same model. *Not done*: re-reading the model per call (one more request per batch for a
case the pin already closes).

**`membersOf` on `database` with a deny: a declared bound and a total deadline (🟡).** *Problem*: one `denied_*` row on
the object made every candidate go through `check`, in series, without a bound or a total deadline — a cheap
amplification for whoever can write a deny. *Decision*: `RELATIONS_MEMBERS_DENY_CHECK_MAX` (1,000) ⇒ 500
`E_AUTHZ_MEMBERS_DENY_LIMIT` before the first `check` (never a partial list), and one deadline (`timeoutMs`) over the
whole loop ⇒ 503 `E_AUTHZ_BACKEND_TIMEOUT`, the loop stops. Both in «Limits». *Not done*: the single CTE that carries the
relation and subtracts in SQL (analyst §4.4) — more SQL per engine; the bound closes the amplification today.

**The opt-in gate of `deny` has teeth in every layer (🟡).** The surface guard grew a column `denyable`: `deny` on a type
without opt-in, on a type in phase `'read'` and on `group` is 422 `E_AUTHZ_RELATION_NOT_DENYABLE` with zero backend calls
in the manager, both drivers (base and `withClock` view) and the published double — one mutant per layer in the corridor
(155 mutants). Until now only cases entering through the manager judged it, and `manager.driver()` is not a way out.

**D-31 checks the shape, not only the name (⚪).** The pinned model has to declare `denied_<rel>` **and** `<rel>` has to
subtract it (`difference` with `subtract` = `denied_<rel>`); a hand-written model that declares `denied_viewer` and leaves
`viewer` without `but not` is 500 `E_AUTHZ_CONFIG` on first use.

**Third-party drivers: the published double changed its answer (⚪).** Since D1, `makeRelationsDriver` (in `/testing`)
answers `check(g#member, …)` walking up through the groups `g#member` is a member of, like `database` and FGA (it did not
before; nothing pinned the old answer). A suite that pinned the old answer of the double will see it change.

**Letter (⚪).** The D1 report said the D-31 guard does not cover `removeDeny`; it does, for a type **with** the opt-in
(500 before the delete if the pinned model lacks the deny). With the opt-in retired there is no guard and the delete
removes the deny for real — retiring stays reversible (the measured effect was already right; the docblock now says so).

### Closure 2 of sublot D1 (re-attack `loteD1-auditor-cierre.md`: 🟠 1 closed in code; 1 🟡, 3 ⚪ new)

Decided by the coordinator (`loteD1-cierre2-coordinador.md`); red observed, case and mutant per finding
(`.claude/contexto/loteD1-informe-cierre2.md`).

**The symmetric row of the cut purge (🟡).** *Problem*: the truth table of closure 1 had no row where a group membership
carries the **allow** and the deny is **direct**; the mutant "denies before memberships" (`[allows][deny][membership]`)
grants when cut after the deny (`false` before, `true` in between, `false` after — measured by the auditor) and left the
five cases of closure 1 green. The guarantee has two halves — memberships after the allows *and before the denies* — and
only the first had a tooth. *Decision*: the row, for a holder and for a `g#member` userset, measured against the server
(*"purgeSubject cortada, allow por grupo × deny DIRECTO (holder)"* and its userset twin). No code change: the order
was right.

**The purge-order mutants run in the published corridor (⚪, structural).** *Problem*: "a multi-step operation exposes an
intermediate state that grants what neither the state before nor the state after granted" is the third iteration of the
same lineage (3b-2f · R3, 3b-6 · P1, D1 · 🟠 1); the order mutants of closure 1 were run by hand, so the missing half
above went unnoticed. *Decision*: the surface guard gains **properties** next to its cells (`GUARD_PROPERTIES` in the
manifest): `openfga.purge.order` is judged by a pure case over `purgeWrites` — the single point both purges go through —
with the same rows as the server table and a minimal evaluator of the model (allow and deny, direct or through nested
`group#member`), in the `Read` order and its reverse. Its five mutants (`prefix-only`, `memberships-first`, `contiguous`,
`no-single-write`, `denies-before-memberships`) are entries of `tests/fixtures/guard_mutants.json`, so `npm run
check:guard-mutants` (the CI job, no OpenFGA needed) kills them on every run (160 mutants), and the property names its
mutants as a closed list (dropping one from the corridor is red). *Not done*: the twin in the roles driver
(`purgeScope` in `facts` orders structure → facts → denies, fixed by its own cases) is not a property of the guard yet.

**A server with `--max-tuples-per-write` below 100 (⚪).** *Problem*: the purge splits in `Write`s of
`RELATIONS_PURGE_WRITE_MAX` (100); on a server with a lower cap the `Write` that passes it is a 400 `exceeded_entity_limit`
— not necessarily the first, so earlier `Write`s had already deleted — and it came out as 503
`E_AUTHZ_BACKEND_UNAVAILABLE`: it looks transient, and repeated the purge asks for the same oversized `Write` and never
finishes. The docblock said "503 without deleting anything", false with several `Write`s. *Decision*: that 400 is **500
`E_AUTHZ_CONFIG`** naming the requirement (`--max-tuples-per-write` ≥ 100), marked as a partial write when an earlier
`Write` deleted (`indeterminate: true`); the requirement is in «Limits», tied to the constant. *Not done*: an option to
lower the split — the bound is the server's and the remedy is its start-up flag; the roles driver assumes the same 100
in `projectCatalog`/`reconcile` and was not touched.

**D-31 compares the rules, not only their shape (⚪).** *Problem*: closure 1 required `<rel>` to subtract
`denied_<rel>`, but not the closure `denied_X = this ∪ denied_P` for every `P` that includes `X` (the path cut, D5): a
hand-written model with `denied_editor: [user]` passed, and the server granted `editor` to an owner denied on `viewer`
where `database` denies. *Decision*: for a type with the opt-in, `<rel>` and `denied_<rel>` of the pinned model must be
**structurally equal** to what the package generates for that type (`factsRelationRewrites`, now the single source of the
generator), after a canonical form measured against v1.19.0 (the server returns other key order and `object: ""` on each
`computedUserset`; union children are commutative); anything else is 500 `E_AUTHZ_CONFIG` on first use. A type without
the opt-in keeps the shape check (there is no generated rule to compare with, D8).

**Letter (⚪).** `E_AUTHZ_MEMBERS_DENY_LIMIT` is 500 and not 422 because it is not an invalid question from the caller but
a bound of the deployment (precedent `E_AUTHZ_TOO_MANY_LOCAL_ROLES`) — in its docblock and in the README error table.

### Plan 2.5 · lot D · D2 — migrating and operating the deny (what an operator runs)

The half of lot D that D1 left out (`.claude/contexto/loteD2-informe.md`; design: tenancy panel round 2, analyst §4.6–4.7,
tester T3/S4–S6/S11/S17, auditor R2-2/R2-3/R2-5, judge row D). Until this block a `database → openfga` migration **did not
carry the denies**: `enumerateRelations` emitted `relation: 'denied_viewer'` and the reconcile counted it as an undeclared
relation. **alpha.3 is not to be published without it.**

**Changed — `authz:relations:reconcile` migrates denies as denies, in four phases.** *Problem*: the reconcile keyed on the
stored relation, so a deny was `skipped.undeclared` (and with `--prune` handed to `unrelate`); and nothing ordered the
writes, so a pass cut halfway could leave an allow in the destination without the deny that cut it. *Decision*:
`RelationTuple.kind` (`'allow' | 'deny'`, optional in the exported type, absent = allow) — both drivers and the published
double enumerate `denied_<rel>` as `{ relation: <rel>, kind: 'deny' }` through one function (`storedRelationKind`); the key
is `relationTupleKey` with that `kind`; per partition the pass writes **denies first** (`deny`), then allows, then with
`--prune` the leftover allows, and the leftover denies **last** (`removeDeny`, never `unrelate`). ~~A pass cut at any write
leaves denies in excess, never an allow without its deny~~ — *corrected in closure 1 below*: the deny tuple was there, the
group membership that carries it was not (🟠 1). A destination deny written by hand with an expiry that differs from the
source is rewritten permanent with `deny` **on `database` only** (D3; never delete+write, R2-8; `openfga` cannot — closure
1, 🟡 4). `report.denies` (a subset of the totals, its own `denies:` line) — and the totals now COUNT denies (closure 1,
⚪ 12). *Not done*: a deny is never moved by `relate`/`relateOrSkip`.

**Added — the deny gate of the DESTINATION, in the plan phase (S6, R2-5): 500 `E_AUTHZ_DENY_MIGRATION_REFUSED`.**
*Problem*: the opt-in is per type and per deployment; a destination driver with the capability but without `deny: 'write'`
in that type (or an `openfga` pod pinned to a model without `denied_*`) would reject the deny with a 422 that the old
`relateOrSkip` swallowed as `skipped` — and then write the allows: granting what the source denies. *Decision*: a new
optional port method `denyPhase(object, relation)` (F-05, zero writes; `openfga` also runs the D-31 model check) answers
for the destination's OWN config — never the persisted spec, which no production process writes. Before the first write in
any partition, every source deny is checked (`'write'` to write one, an opt-in to keep one already there); any refusal —
`no-capability`, `no-deny-phase`, `phase`, `undeclared`, `model`, `unmarked` (a source that does not mark `kind`),
`invalid` — is 500 with **zero writes**, never `skipped` (losing a deny is not a loss that can be declared). `--dry-run`
lists them (`report.denyRefused`, one `deny NO migrable (<reason>)` line each) and exits non-zero. `denyPhase` entered the
surface guard red (G-0, 🟡 E, G-R) and left it with rows, variants and three mutants. *Breaking for third-party drivers
declaring `relationDenies`*: to be the destination of denies they need `denyPhase` (without it: `no-deny-phase`).

**Added — the L9 lineage guard (owner's decision 2026-10-15 (7)).** *Problem*: three times a 422 was absorbed where the
plan should have classified it (R2-5, lot B decision 4, closure 3 N9). *Decision*: `RELATION_REJECTIONS` — every 422 class
the relations port can throw, by reflection over `src/errors.ts` and the port's sources, has exactly one entry
(`classified` with its bucket, `refused` with its refusal, or `unreachable` with why); a new 422 class without one is red
by name; every classified/refused entry has an executable case (plan classifies, driver never asked, same numbers in
`--dry-run` and real); `RELATION_422_REASONS` (the prune's layer 2) is derived from it.

**Added — the partial report per partition (roadmap 2.5, 🟡 3 of the alpha.6 audit).** `report.partitions` (status
`done`/`failed`/`pending` and counters per partition); a pass that blows up carries `error.report` with `partial: true`
and is marked `markPartialWrite` if it wrote anything; the command prints `pasada PARCIAL:` lines instead of a stack.

**Added — `openfga:provision --store-id` refuses to mutilate the model; `--allow-drop-deny` (judged by the flag mutants,
no longer `pending`).** *Problem*: `provision` publishes from the static config of the process that runs it; one without
the opt-in (or an older binary) dropped `denied_*` and switched every deny of the type off, silently, with "success".
*Decision*: before writing, read the store's current model; dropping a `<type>#denied_<rel>` of a relation type is exit 1
(`provision NEGADO:`) with zero writes. `--allow-drop-deny` sweeps the store (since closure 2 of D2, all of it, streamed,
no cap) and publishes only with zero live denies of those relations — the flag never switches a live deny off. An unreadable
current model is exit 1 too (not published blind). *Not done*: the `denied_<P>` of roles (`scope`) are not guarded —
retiring a permission is not retiring an opt-in. *Existing case changed*: R-1 of `command_flags_r.spec` (the `--store-id`
branch now reads the model first; the assertion on WHICH store is kept).

**Added — the deny steps of the cutover runbook (no `pending` left).** Step 20: provision → pin `modelId` → deploy
`'read'` (deny 422 on both drivers) → second deployment `'write'` (deny lands, migrated with `kind`, `check` false on both
drivers) and the S11 table (declared row: a pod not redeployed and pinned to the old model grants; with the new `modelId`
it does not; new config + old pin is 500). Step 21: the rollback below 2.5 is prohibited with live denies (D12/S17,
declared row) — the README count query says 1, `provision` without the opt-in exits 1 with and without
`--allow-drop-deny`; after `removeDeny` + `--prune` the count is 0 and `--allow-drop-deny` publishes. README «Upgrading to
2.5.0-alpha.3» with the order, the guard and the count query (executed in `upgrade_recipe.spec`, the three engines).

**Fixed — the roles twin of N3.** A server with `--max-tuples-per-write` below 100 rejects the 100-tuple `Write`s of the
roles driver (`projectCatalog`, `reconcile`, `purgeScope`) with a 400 `exceeded_entity_limit`; it came out as 503
`E_AUTHZ_BACKEND_UNAVAILABLE` ("retry"), and retried it fails forever. Now 500 `E_AUTHZ_CONFIG` naming the requirement, at
the single wrapping point of the client, with the same `isServerWriteLimit` as relations (moved to `src/shared`).

**Added — the order of `purgeScope` (roles, `facts`) as a surface-guard property** (`openfga.roles.purgeScope.order`):
measured that with the denies last no intermediate state grants; the mutant «denies first» grants after the first
`Write` and dies in the corridor.

### Plan 2.5 · lot D · Closure 1 of sublot D2 (the audit of D2: 2 🟠, 4 🟡, 6 ⚪)

(`.claude/contexto/loteD2-auditor.md`, `loteD2-cierre-coordinador.md`, `loteD2-informe-cierre.md`.)

**Fixed — 🟠 1 · a reconcile cut halfway could grant through a group: ONE ordering point for relation writes and
deletes, shared by the reconcile and the `openfga` purges (L10 lineage, 4th iteration ⇒ structural).** *Problem*: the D2
phases ordered the `denied_*` tuples, but the group memberships that CARRY a deny are allows, and they were written in the
SOURCE's enumeration order. `database` enumerates by uuid v7 (= creation order): a document shared with U on Monday and U
joining a denied group on Tuesday enumerates the direct allow first; a pass cut between the two left the destination with
the deny and the direct allow but not the membership — `check` true where the source denies (measured with a real
`database` source). The surface-guard row seeded the membership first, so it never saw it. *Decision*:
`src/relations/tuple_order.ts` — `relationWriteOrder`: denies → group memberships that carry a deny (the group's `#member`
is the subject of some deny, closed downwards over nested groups) → the other memberships → allows; `relationDeleteOrder`:
the reverse. `applyPartition` (reconcile, write and `--prune`) and `purgeWrites` (`purgeObject`/`purgeSubject` of
`openfga`) both use it; inside memberships the order is (object, subject), never the enumeration order. *What it
guarantees, exactly* (superseded by closure 2 · 🟡 N3 below): cut after any write, the pass leaves no state granting what neither the initial nor the final state
granted — **with one declared residue**: a group that carries both an allow and a deny can, while its memberships are being
written (or deleted), open an allow the destination ALREADY had before the deny-carrying membership of another such
group arrives (or after it leaves). The first migration into an empty destination has no residue (no allow over a
non-`group` object exists until every deny and every membership is in). The surface-guard properties
`relations.reconcile.order` and `openfga.purge.order` now judge that function, with the source enumerated in its order and
reversed, rows for direct / by-group / nested denies, carrier-first and carrier-last; the mutant «the source's enumeration
order» (the D2 code) dies, with ten more order mutants in `npm run check:guard-mutants`.

**Changed — 🟠 2 · the rollback procedure starts by moving the fleet to `deny: 'read'`.** *Problem*: the procedure counted
the live denies, took them to zero and published the model without the opt-in while the fleet was still in `'write'`: a
tenant's `deny()` in that window was switched off in silence, for good (on `database` a pod < 2.5 never reads `denied_*`;
on `openfga` the new model has no `denied_*`). *Decision*: step 0 is mandatory — deploy the whole fleet with the type in
`deny: 'read'` (every `deny()` is 422, reads still honour) **before** counting, sweeping or publishing; the count is
repeated at the end and must be 0. `openfga:provision --allow-drop-deny` re-counts right before
`writeAuthorizationModel` (TOCTOU: a deny that arrived during the O(store) sweep ⇒ exit 1 `provision NEGADO: el RECUENTO
…`, zero models) — that narrows the window; the guarantee is step 0. Runbook step 21 now has the EFFECT: with the fleet
still in `'write'` a late deny after the zero is detected (the final count is not 0 and `provision --allow-drop-deny`
exits 1 instead of publishing); with the fleet in `'read'` a concurrent `deny` is 422 on both drivers, the count reaches 0
and stays 0, and only then the model is published.

**Fixed — 🟡 3 · the `provision` guard judges the STORE's state, not the last published model.** A model published in
between without `denied_*` (a rollback rehearsal with an alpha.10 binary) made the next publish without the opt-in a
silent «success». Now every model of the store is read (`PROVISION_MODEL_HISTORY_MAX`, 10,000) and, if any of them
declared a `<type>#denied_<rel>` the new one does not, the store is swept: a live deny of those relations ⇒ exit 1 with or
without `--allow-drop-deny`; none ⇒ it publishes. The flag is still required to drop a `denied_*` the LATEST model declares
(the intent is said out loud). A sweep that fails halfway is `provision NEGADO:` too (⚪ 10 c), never the raw SDK error.

**Fixed — 🟡 4 · re-deny over a CONDITIONAL deny in `openfga` is 500 with the recipe, never a 503 that repeats.** A deny
with an expiry can only be written from outside the package (D3); OpenFGA cannot replace the same key in a `Write` (409
«already exists with a different condition», measured on v1.19.0). It came out as 503 (retry) forever and the deny
expired. Now `deny` re-reads the tuple and throws 500 `E_AUTHZ_CONFIG` (`AuthorizationConfigError.conditionalDeny`,
`denyConditional: true`) with the recipe `removeDeny` + `deny` and its declared window; the reconcile lists it as the
destination residue `deny-conditional` (own line, exit ≠ 0) and carries on. `--dry-run` cannot know it (the plan counts
it as «rewritten»; the destination decides in the real pass) — declared. `database` keeps rewriting it permanent.

**Changed — 🟡 5 · runbook step 20 also seeds a deny BY GROUP**, with the membership (with an expiry, M6) created after the
direct allow, and asserts `check` false on `openfga` after the migration, and true on both drivers once the membership
expires.

**Changed — 🟡 6 · one recipe per refusal reason** (`DenyRefusal.recipe`, in the 500's message and in each `deny NO
migrable` line). The generic one («or remove those denies from the source») was a 422 for `undeclared` (F-05 in
`removeDeny`). The `undeclared` recipe — re-declare the relation temporarily, `removeDeny`, retire it — is EXECUTED in a
case; `invalid` says «by hand», `unmarked` says «update the driver that does not mark `kind`».

**Changed — ⚪ 7–12.** ⚪ 7: the L9 reflection also scans `src/shared/` (two 422 classes named there are registered as
`unreachable` with why). ⚪ 8: a destination that enumerates a `denied_*` tuple without `kind` is the refusal `unmarked`
in the plan (500, zero writes), never planned as an allow nor pruned with `unrelate`. ⚪ 9: `runRelationsDriverContract`
judges `denyPhase` (the `relationDenies: true` face: the phase of the driver's own config per type, F-05, and the effect of
each phase on `deny()`; the `false` face: no phase is claimed) — one case more in the `true` face (22 → 23). ⚪ 10: a pass
that fails before writing anything has `report.partial: false` (no `markPartialWrite`) and prints `pasada FALLIDA sin
escribir nada:`, never «pasada PARCIAL: escritas 0». ⚪ 11: refusing a deny already present in a destination without the
opt-in is kept, and the line says why although `database` honours the row (D8). ⚪ 12: **`written`, `unchanged` and
`extra` of `authz:relations:reconcile` now INCLUDE denies** — a change of meaning, not an addition: whoever classified
residue by those totals (as COGNITIV does) must subtract `report.denies` to keep counting allows only.

### Plan 2.5 · lot D · Closure 2 of sublot D2 (the re-attack of closure 1: 1 🟠, 3 🟡, 2 ⚪)

(`.claude/contexto/loteD2-auditor-cierre.md`, `loteD2-cierre2-coordinador.md`, `loteD2-informe-cierre2.md`.)

**Fixed — 🟠 N1 · renewing a membership that CARRIES a deny on `openfga` is refused (409), and a renewal half-done is a
partial write (L10 lineage, promoted: 5th appearance).** *Problem*: `relate` on an existing tuple with another expiry is,
on `openfga`, two `Write`s — delete, then write (FGA does not replace the same key in one `Write`, M5). For a
`group:*#member` membership whose group is the subject of a live deny, the subject was granted between the two (measured:
a concurrent `check` answered `true`); if the second `Write` failed, the deny never reached the subject again, while the
error said «not written» (503 without `partialWrite`, no event), and the reconcile printed «pasada FALLIDA sin escribir
nada» with the destination changed. *Decision (owner, 2026-10-15 (9))*: on `openfga` that renewal — the group, or a group
containing it, is the subject of a live deny of the partition — is **409 `E_AUTHZ_RENEWAL_UNSAFE`** (new class
`RenewalUnsafeError`, exported) with **zero writes** and the recipe in the message (`unrelate` + `relate` accepting the
window explicitly, or retire the deny first). Cost: only on a membership renewal, one `Read` (by `user` + type, the filter
FGA admits) per deny type and one for the parents, per group up the nesting. Every other renewal stays two `Write`s; if
the second fails the error is marked **`markPartialWrite`** and `onRelationWrite` gets `indeterminate: true`. **New
capability `atomicRenewal`** (optional, normalised to `false`, rule D15; `database` `true` — one transaction —, `openfga`
`false`) with its pair in `runRelationsDriverContract` (the `false` face: the 409 with zero writes, direct and through a
containing group, and a membership without deny still renews; the `true` face: the renewal lands and the deny still
denies) — **a third-party driver that does not declare it must refuse that renewal**. `authz:relations:reconcile` never
asks a destination without `atomicRenewal` to renew a carrying membership: the PLAN lists it as the destination residue
**`renewal-unsafe`** (same numbers in `--dry-run` and the real pass; a line starting with `sin renovar (renewal-unsafe)
destino:` and the recipe; exit ≠ 0), and a pass that fails on a write the driver marked partial is `report.partial: true`
with a line saying the destination changed although the counters say 0. *Roles twin — does not apply*: `grant` with
another expiry in `facts` is also delete + write (`replaceAssignment`), but the roles deny is `scope#denied_<P>` with the
HOLDER as subject — it never travels through an `assignee`, so the window only takes a grant away (fail-closed); pinned by
a case on the generated model (`denied_<P>` exists only on `scope`, admits only direct holders — no userset, no `*` — and is
inherited only through `parent`): if it ever admitted `role_binding#assignee`, the case turns red and the twin applies.
*Concurrency*: the case on the real server puts a **barrier spy** between the two `Write`s (a `check` of the subject
right after a delete-only `Write`): it never fires for a carrying membership (there are no two `Write`s any more; with
the refusal removed it fires and answers `true`, measured) and fires — answering `false` — for the control renewal of a
membership without deny.
*Existing cases changed*: the harness counts (`relations_harness.spec`: core 29 → 30, capabilities 9 → 10) and the
capability key lists of `capabilities.spec` / `guard_surface.spec` (a new optional key).

**Fixed — 🟡 N3 · writes and deletes are ONE sequence, and the guarantee is DEMONSTRATED by brute force.** *Problem*:
every write went before every delete; with `--prune`, a former member composed with a new allow (U ∈ g leaves,
`g#member viewer X` arrives: cut after the first write, U was granted X — neither state granted it), which falsified the
universal sentence of closure 1. *Decision*: `relationTransitionOrder` (`src/relations/tuple_order.ts`, the single
ordering point; `relationWriteOrder`/`relationDeleteOrder` are thin wrappers of it, the purges use the latter) orders the
whole transition: new denies → leftover allows → the memberships that come in and go out, by a **precedence graph** (in
the union of both states, between memberships sharing a subject: a deny-bringing one before an allow-bringing one when
they come in; an allow-carrying one before a deny-carrying one when they go out; one that leaves before one that comes in
on the same nested path if the composed path would carry an allow; one that comes in with a deny before one that leaves
with a deny protecting an allow of the subject) → new allows and renewals → leftover denies. An allow is taken as cut by a
deny only with the destination's config (`toConfig`, D5 `up*`); without it, never (more precedences, never less
guarantee). *What it guarantees, exactly*: **if the precedence graph has no cycle, no prefix of the pass grants outside
initial ∪ final, and no subject denied in both is granted in any.** The residue is the cycle (two memberships of the same
pass whose constraints contradict each other — typically the same subject joining or leaving two groups at once, each
bringing a deny that cuts an allow of the other); the pass reports it (`report.orderResidue`, warning `orden SIN
garantía`; the final state is right). *Demonstration* (`tests/relations_order_exhaustive.spec.ts`, oracle = the package's
`cutPathAllows`): exhaustive over 1 user, 2 groups with one nesting level, 2 objects and one relation with deny — 10
possible tuples, 2,097,152 (initial, final) pairs with and without `--prune` in ~23 s: **0 pairs grant without a declared
residue**; 4,560 have a cycle, 828 of those grant in a prefix and 352 admit no safe order of the diff at all (measured by
dynamic programming over the subsets of the diff). Seeded samples (30,000 pairs per mode) of the 2-user universe with
direct and group allows and denies (21 tuples) and of a 3-group universe with two nesting levels (20 tuples): 0 without
residue. The orders DISCARDED, each with its counterexample in the spec: closure 1's (writes, then deletes) — C2 of the
re-attack; the candidate of the brief (denies → allow deletes → membership writes → membership deletes → allows →
denies) — `U ∈ h` comes in before `h ⊂ g` leaves and U reaches g's allow. New surface-guard property
**`relations.order.exhaustive`** (the brute force over a reduced universe, 131,072 pairs, pinned figures) with 13 order
mutants; `relations.reconcile.order` gains the rows of the former member, the nested composition, the deny-only group
(🟡 N2) and the allow deleted before the carrying membership, and the mutant «writes then prune» (closure 1's
`applyPartition`) dies there; its title, universal until now, names the residue («salvo el RESIDUO declarado …»), so
the guard says exactly what is demonstrated. This supersedes the guarantee and the residue written in closure 1 🟠 1
above.

**Fixed — 🟡 N2 · the residue sentence.** With the precedence graph the case of the re-attack (the other group only carries
a deny) is ordered and no longer a residue; the residue is the cycle, with its sentence (above).

**Fixed — 🟡 N4 · `openfga:provision --store-id` is never blocked forever.** The sweep for live denies of a dropped
relation stopped at 1,000,000 tuples (`PROVISION_DROP_DENY_SWEEP_MAX`, removed) and the store's model history keeps a
retired opt-in forever: a bigger store could never be provisioned again, whatever the flags. It is now **streamed** page
by page with no tuple cap, keeping a count and three examples (`countLiveDenies`, exported for its case); a repeated
continuation token — any token already seen, not only the immediate one: a cycle `a → b → a` would loop forever now
that there is no cap — or a page without `tuples` is still exit 1 (`provision NEGADO: el barrido … falló a medias`). It costs
O(store) per run — written in Limits.

**Changed — ⚪ N5 · the recount's sentence**: «the recount narrows the window, it does not close it: step 0 does» (README,
the `provision` block and step 3 of the rollback procedure), pinned by a case.

**Changed — ⚪ N6 · the L9 guard sees the residues that are not 422.** `RELATIONS_RECONCILE_DETAIL_REASONS` (the reasons
of `RelationsReconcileDetail`, at runtime) and `RELATION_RESIDUES` (where each one is classified: the PLAN, or the PASS
with its declared exception to «same numbers in `--dry-run`»): `deny-conditional` (pass) and `renewal-unsafe` (plan) have
their entry and an executable case; a new reason without an entry is red.

### Plan 2.5 · lot D · Closure 3 of sublot D2 (the review of closure 2: 1 🟠, 2 🟡, 2 ⚪)

(`.claude/contexto/loteD2-auditor-cierre2.md`, `loteD2-cierre3-coordinador.md`, `loteD2-informe-cierre3.md`.) The common
root of C2-1, C2-2 and C2-4: **a tuple expired at `now` was treated as live.**

**Fixed — 🟠 C2-1 · an EXPIRED carrying membership in the destination no longer leaves the destination granting to a
denied subject (a regression of closure 2).** *Problem*: the reconcile plan compared the destination tuple's expiry
without asking whether it was still valid: a membership expired in the destination and live in the source was a
«renewal», and on `openfga` a carrying one was `renewal-unsafe` (not written) while the new allow WAS written — the
destination granted to a subject the source denied, pass after pass (measured: `destAfter true`, second pass the same).
*Decision*: **a destination tuple expired at the pass's `now` is ABSENT for the plan** (`liveInDestination`, the single
point of the rule): rewriting it is a plain write — phase 3 if it is a membership —, never `toUpdate`/`renewal-unsafe`,
and it does not enter the order's context. With `--prune` the expired leftovers are deleted first and outside the order.
Cases: two per direction in `runRelationsReconcileContract` (`denies: true`; double ↔ double and `database` ↔ `openfga`
against the server): the destination denies before, never grants in a prefix (spy after every write), ends denying or
granting as the SOURCE does, and the second pass has an empty plan. The runner registers 20 cases with `denies: true`.

**Fixed — 🟡 C2-2 · the order's guarantee is demonstrated with VALIDITY in the universe.** *Problem*: the brute force
modelled presence, not validity, so the published guarantee silently assumed every destination tuple was live; with an
expired edge taken as live the self-cut dropped a precedence and a prefix WITHOUT residue granted (R7, both drivers), and
the «renewal» of an expired membership went to phase 4 behind the new allow (R5). Measured too, by the new brute force: an
expired DENY being pruned, inside the order, counted in the union graph as a deny that «already denies» and removed a
precedence. *Decision*: besides C2-1, the brute force has seven states per tuple (destination absent / expired / live ×
source absent / live with the same or another expiry), derives the plan through `liveInDestination`, and runs renewals as
steps (one write on an `atomicRenewal` destination; two `Write`s with the gap checked, and carrying memberships left as
`renewal-unsafe`, otherwise). **Exhaustive** over the reduced universe (8 tuples: 11,529,602 combinations per destination
kind, `AUTHZ_ORDER_VIGENCIA_EXHAUSTIVE=1`) and seeded samples of the four universes in the default suite: **0 grant
without a declared residue**; no new residue. The guard property `relations.order.exhaustive` adds a declared sample of
50,000 combinations per mode with validity (title updated); `relations.reconcile.order` adds four rows (expired carrier,
expired edge with the destination's config, expired leftover membership, expired leftover deny); two new mutants
(`rec.plan.vigencia-ignored`, `rec.apply.expired-deletes-in-order`).

**Fixed — 🟡 C2-3 · the TOCTOU of the carrier check stops being silent.** *Problem*: a `deny` written concurrently
between `#carriedDeny` (no deny) and the two `Write`s of a renewal did not reach the subject during the window — and for
good if the second `Write` failed, with an error that talked about the membership, not about the deny. *Decision*: the
driver re-checks after the two `Write`s (and after a failed second one). Renewal done + deny found ⇒ 409
`E_AUTHZ_RENEWAL_UNSAFE` marked partial, `renewalApplied: true`, `carriedDeny` (the final state is right; `onRelationWrite`
gets `indeterminate: true`). Second `Write` failed ⇒ the 503 keeps its class and code, is marked partial and carries
`carriedDeny` and the recipe (write the membership again: one `Write`). *What is NOT done*: closing the window — FGA has
no primitive to serialise a `deny` against a renewal; the window is declared in the README next to «Every other renewal
stays two `Write`s».

**Fixed — ⚪ C2-4 · `relate` renewing an ALREADY EXPIRED carrying membership is no longer 409.** It connects nothing, so
there is no window to protect; neither does a membership whose only path to a deny is an expired nesting edge
(`#carriedDeny` and the runner's double skip expired edges). Case in the `atomicRenewal: false` face of the runner.

**Fixed — ⚪ C2-5 · roles twin: a `grant` renewal whose second `Write` fails is a PARTIAL write.** `replaceAssignment`
(`openfga`, `deleteTuples` + `writeTuples`) marks the error `markPartialWrite` when the second fails (the `assignee` is
already gone: fail-closed), and the roles manager's `#write` notifies `onWrite` with `indeterminate: true` for a partial
write as well as for a timeout — the same branch as the `RelationsManager`. Until closure 3: a 503 «not written», no
event, the grant gone.

### Plan 2.5 · lot D · Closure 4 of sublot D2 (the review of closure 3: 1 🟠, 1 🟡, 2 ⚪ + the time horizon)

(`.claude/contexto/loteD2-auditor-cierre3.md`, `loteD2-cierre4-coordinador.md`, `loteD2-informe-cierre4.md`.) The
coordinator's rule: **when the reconcile cannot write a deny —or the membership that carries it— the destination must be
equal to or MORE restrictive than the source at every future instant, not only at `now`.**

**Fixed — 🟠 C3-1 · a `renewal-unsafe` membership no longer leaves a deferred grant.** *Problem*: a carrying membership
LIVE in the `openfga` destination with an expiry EARLIER than the source's was (rightly) not renewed, but the new allow
its deny cuts WAS written: when the old expiry passed, the destination granted to a subject the source denied, with no
pass in between (measured: `destAfterOldExpiry true`; a later pass towards the active driver is refused). *Decision*: the
plan **withholds** what a protection that does not travel would make grant — new destination residue
**`withheld-by-unsafe-deny`** (one line per tuple starting with `retenida (withheld-by-unsafe-deny) destino:`, naming its
cause and the date; drift, exit ≠ 0; same numbers in `--dry-run`): an allow (new or extended) the lost deny cuts for a
subject below the membership by a path not through it, a membership that gives them such an allow, and with `--prune`
the deletion of a deny (or of a deny-only membership) that protected them; for a SHORTENING, what would hang from the
membership kept longer. A missing membership that carries another deny is withheld in cascade; one that would have to be
withheld and cannot without granting (left over and granting something) refuses the pass with zero writes: new
`DenyRefusal` reason **`carrier-conflict`** (with its recipe: resolve the cause first). The single point is
`relationWithheldWrites` (`src/relations/tuple_order.ts`, pure), used by `planPartition` and by the brute force. The
`renewal-unsafe` line now gives both expiries and the date from which the destination would diverge. Case: the auditor's
reproduction in `runRelationsReconcileContract` (`denies: true`, per direction, double ↔ double and `database` ↔
`openfga`): without `atomicRenewal` nothing is written and the destination still denies after the old expiry (the
destination's clock moved with `withClock`, no sleeps); with it (`database`), it renews as before. The runner registers
22 cases with `denies: true`.

**Fixed — 🟡 the order's guarantee is demonstrated over the time HORIZON.** *Problem*: the brute force judged every
prefix and the final state at one `now`, so a `renewal-unsafe` membership left with its old expiry looked right. Measured
by the new brute force, also on `atomicRenewal` destinations: renewals ran last (phase 4), and a pass cut before them left
—once the shorter expiry passed— a membership that had become an exit (or entry) applied out of the precedence order, or
an allow that should have shortened still granting. *Decision*: **a membership renewal enters the precedence graph** as
the entry (extension) or exit (shortening) it becomes at the shorter of its two expiries; **an allow renewal that
shortens goes with the deletes of phase 2** (`RelationTransition.shortening`, new optional field). The brute force now has
8 states per tuple (the source's expiry can also be EARLIER), adds the denies that cannot be rewritten (C3-2), and judges
every prefix and the final state at `now`, `+30 min` and `+1 h` with each tuple's own expiry: at no instant does a prefix
grant outside initial ∪ source without an order residue, and the final state never grants what the source denies except
what the initial state already granted then (`preexisting`, only with a declared `renewal-unsafe`/`deny-conditional`).
**Exhaustive** over the reduced universe (8^8 × 2 = 33,554,432 combinations per destination kind,
`AUTHZ_ORDER_VIGENCIA_EXHAUSTIVE=1`) and the four seeded samples of the default suite (same sample sizes): **0 grant
without a declared residue**. The order residue (cycles) grows on `atomicRenewal` destinations, because renewals now take
part in the graph — declared, the final state is right. Guard: `relations.order.exhaustive` (title updated, figures per
mode) and `relations.reconcile.order` (two rows judged also at a later instant: C3-1 and C3-2).

**Fixed — 🟡 C3-2 · a CONDITIONAL deny the destination cannot rewrite is decided in the PLAN, and what it cuts is withheld.**
*Problem*: a destination deny with an expiry —here already EXPIRED— that the source has could not be rewritten on
`openfga` (M5); the pass listed it and wrote the allow anyway (the destination granted), and `--dry-run` reported a
different count (the verifier of the runbook is the dry-run). *Decision*: on a destination without `atomicRenewal`, a
destination deny with an expiry (live with another one, or expired) that the source has is the residue `deny-conditional`
decided in the plan (`RELATION_RESIDUES['deny-conditional'].where` is now `'plan'`: no exception to «same numbers in
`--dry-run`» is left), never rewritten, and what it cuts is withheld. A driver that declares `atomicRenewal` and still
answers the 500 `conditionalDeny` contradicts its capability: the error propagates (until closure 4 the pass carried on).

**Changed — ⚪ C3-3 · the renewal that WENT THROUGH has its own code: 409 `E_AUTHZ_RENEWAL_RACED`** (`RenewalRacedError`,
exported; `carriedDeny`, `renewalApplied: true`, marked partial). Until closure 4 it shared `E_AUTHZ_RENEWAL_UNSAFE`,
whose recipe (`unrelate` + `relate`) automated here would reopen the window with the deny inside the group.
`E_AUTHZ_RENEWAL_UNSAFE` now always means zero writes. `RenewalUnsafeError.raced` is gone (unreleased).

**Fixed — ⚪ C3-4 · `purgeScope` of roles on `openfga` cut after its first `Write` is a PARTIAL write** (`markPartialWrite`;
the roles manager notifies `indeterminate: true`), the twin of the relations purges. Until closure 4: a 503 «not written».

### Plan 2.5 · lot D · Closure 5 of sublot D2 (owner's decision: option A — refuse the partition; the review of closure 4: 1 🟠, 2 🟡, 2 ⚪; the «optimal package» panel: R2 🟠)

**Changed — a partition whose renewal the destination cannot do in one write is REFUSED, and the rest migrates.**
*Problem*: closure 4 withheld, tuple by tuple, what a protection that does not travel (`renewal-unsafe`,
`deny-conditional`) would make grant. Measured against OpenFGA by the auditor: a new membership carrying ANOTHER deny was
withheld in cascade and the destination kept granting NOW what that deny cuts and the source denies, while the line said
the opposite (🟠 D4-1); a withheld deletion left a subject member of a group the source removed (🟡 D4-2); and the
pass-wide refusal `carrier-conflict` could be forced by a tenant with ordinary writes in the source and, with `--prune`,
blocked every other tenant's partition (🟡 D4-3). *Decision* (owner, 2026-10-16, option A): a partition with at least one
`renewal-unsafe` or `deny-conditional` gets **zero writes and zero deletes** (with `--prune` too, expired leftovers
included); its destination stays exactly as it was, with its previous drift in view; the other partitions migrate.
Decided in the PLAN (same numbers in `--dry-run` and the real pass); `report.partitionsRefused`
(`RelationsPartitionRefusal`: `partition`, `causes`, `pending: { write, update, delete }`, `recipe`), the partition row
`status: 'refused'`, and one line per partition starting with **`partición NEGADA <partition>:`** (exit ≠ 0 while it
exists). *Removed* (unreleased): `relationWithheldWrites`, `HeldRenewal`, `WithholdInput`, `WithholdPlan`, the residue
`withheld-by-unsafe-deny` and the refusal reason `carrier-conflict`. *Kept*: the 409 `E_AUTHZ_RENEWAL_UNSAFE` with zero
writes for a live carrying membership on `openfga`, `E_AUTHZ_RENEWAL_RACED`, the partial marks, the order with renewals
and the horizon, `atomicRenewal` (it becomes `true` on `openfga` when OpenFGA offers an upsert). *Not done*: the
`member_alt` slot (option B) is in the 2.6 backlog.

**Changed — the recipe is honest.** On `openfga` there is NO window-free way to change the expiry of a membership that
carries a deny (no upsert: openfga/openfga#2151). The 409's message and the refused partition's recipe say so: the
recommended pattern is memberships without expiry in groups with a deny, ended with `unrelate`; `unrelate` + `relate` is
offered as accepting the window, said as such. «Retire the deny first, renew, write it again» is gone: it opens the same
window. README: new paragraph *The limit*, with the TOCTOU of N1 declared.

**Fixed — the order counts group MEMBERSHIP as a grant** (D4-2, found when the brute force's oracle started judging
`group:` objects): a pass cut between `+U ∈ h` and `−h ⊂ g` made U a member of g, which neither state did (1,920 pairs
without residue in the reduced universe). Precedence C3 no longer requires an effective allow at the end of the composed
path; C4 takes C2's exclusion (a subject that reaches the leaving membership only through the entering one had no deny to
keep). Figures, re-measured: E1 exhaustive 4,176 pairs with a cycle / 816 grant / 352 inherent (was 4,560 / 828 / 352);
E1-reduced 1,044 / 204 / 88 (was 1,140 / 210 / 88); U2 209 / 17; E3 4,188 / 155 (was 842 / 7: the declared price — more
cycles with two nesting levels, all reported as order residue). 0 pairs grant without a declared residue anywhere.

**Changed — the brute force with validity and horizon**: the general `preexisting` exclusion is gone (H2 of the panel's
tester); the only exclusion is a REFUSED partition (zero writes: its state is the initial one at every instant); for the
rest, no prefix and not the final state, at any instant of the horizon, grants what neither the initial state nor the
source grants, and the final state grants nothing the source denies. `walkVigencia` fixes one combination with validity;
the literal counterexamples of three mutants that only died by figures are now cases (C4 in U2, the shortening renewal in
E3, C3 with membership).

**Fixed — 🟠 R2 (the «optimal package» panel's auditor) · the model ↔ config guard (D-31) compares EVERY type, not only
the ones with a deny.** *Problem*: on a type without deny, a process whose config narrowed `viewer` (no longer `includes
editor`) and pinned an old model kept granting by the old rule, silently, where `database` with the same config denies.
*Decision*: the same model read (memoised per process) compares every declared type (and `group`) with what the package
generates; a difference is 500 `E_AUTHZ_CONFIG` when the type is used, naming the relations.

**Fixed — ⚪ D4-5 · `purgeScope` of roles on `openfga` counts deletions DONE, not requested**: the blind structure
deletion (`onMissingDeletes: Ignore`) counted keys that did not exist, and a purge that had deleted nothing came out
`indeterminate: true`. Now one read of the scope says which `#binding` edges exist (a `#role` edge without its `#binding`
changes no answer). Declared window: an edge a concurrent `grant` writes between that read and the deletion is deleted
without being counted. **Fixed — ⚪ D4-4**: the `orden SIN garantía` line says that a cycle can contain a RENEWAL and that
the cut can grant at a LATER instant.

**Changed — the mutant runner of the surface guard (no runtime change)**: per mutant it runs only the cases of its
`expectRed` (Japa `--tests`, exact title), in parallel (`--jobs`, one temporary tree per worker); `--full` runs the whole
spec per mutant (nightly CI job `guard-mutants-full`, with `collateral`); `--skip-db-independent` skips the mutants of
`tuple_order.ts`/`reconcile.ts` in the `sqlite-file` leg. Equivalence proven once: the 181 mutants give the same verdict
filtered and full (and the 19 engine-independent ones in `:memory:` and `sqlite-file`); `scripts/compare_guard_mutants.mjs`.
New mutants in the runner: the refused partition, the conditional deny in the pass, the shortening not passed, renewals
not changing, C3 needing an allow, C4 without the exclusion (precision, dies by figures), the roles `purgeScope` partial
mark (no mark / counting requested keys), and R2.

### Plan 2.5 · lot D · Closure 6 of sublot D2 (the review of closure 5: APTA with reservations — 2 🟡, 3 ⚪)

**Fixed — 🟡 D5-1 · an EXPIRED deny carries nothing, for the driver too.** *Problem*: the plan treats a destination
tuple expired at the pass's `now` as absent (no carrier), but `openfga`'s carrier check (`#carriedDeny`) counted every
`denied_*` tuple of the group's userset, expired or not. With an expired conditional deny on `group:G#member` in the
destination (written outside the package), the dry run said «done» and the real pass aborted with 409
`E_AUTHZ_RENEWAL_UNSAFE` («deny vivo», false), and the partitions after it did not migrate. *Decision*: the carrier check
ignores an expired deny (the same rule as closure 3's C2-4 for the nesting edge, and the plan's «expired = absent»):
dry == real again, and the rest migrates. *Not done*: a deny the plan does not see at all (e.g. a leftover on a relation
the destination no longer declares) can still reach the driver's 409 — not measured; the README no longer says «the
reconcile refuses that partition» as an absolute.

**Fixed — 🟡 D5-2 · the D8 exception of the model ↔ config guard requires the WHOLE deny form.** *Problem*: on a type
without opt-in, closure 5 accepted the deny form of `<rel>` (`base but not denied_<rel>`, D8: opt-in withdrawn with the
model still published) without comparing `denied_<rel>`; a hand-written model with `denied_editor = this` (no `or
denied_viewer`, the closure of the path cut) made `openfga` grant `editor` to a subject with a deny on `viewer`, where
`database` denies. *Decision*: the exception holds only if `denied_<rel>` is also the rule the package generates; and
`group` is compared in EVERY operation (a `group#member` that is not `this` changes membership, and with it what a
`check` on any type grants), not only in operations on `group`.

**Changed — ⚪ D5-3 · the letter of a refused partition.** «As it was» is not static: from the old expiry of an extended
carrying membership the destination stops carrying its deny and grants what that deny cuts (if another path grants it)
while the source denies. The `renewal-unsafe` line and the `partición NEGADA` line say when and what; the report carries
it as `partitionsRefused[].evolves` (`{ at, member, cut }`, optional). The recipe of a refused partition no longer offers
«memberships without expiry in the SOURCE» as a way out (measured: the next pass is still refused — the destination's
expiry still changes); the real ways out are `unrelate` in the source, `unrelate` + `relate` in the destination accepting
the window, or waiting for the destination's old expiry; the expiry-less pattern stays as advice for the future. The
stale comment about «withheld allows» in the pass is gone.

**Fixed — ⚪ D5-4 · `purgeScope` of roles on `openfga` over-notifies instead of under-notifying.** Since closure 5 the
counter adds only the structure edges a previous read saw; an edge a concurrent `grant` wrote between that read and the
blind deletion was deleted uncounted, and a failure right after (the next read or delete) came out without the partial
mark. Now the blind deletion of a key the read did not see is UNCERTAIN until phase 2 (the facts, which deletes and
counts that grant's `assignee`) finishes; a failure in between is marked partial (`indeterminate: true`). A purge that
fails in that stretch with no concurrent grant is also marked partial: over-notifying, never under-.

**Changed — ⚪ D5-5 · the filtered mutant runner has a FILTERED baseline (no runtime change).** In filtered mode a mutant
is judged by its `expectRed` titles run in isolation, so a case that is red in isolation without any mutation would
«kill» its mutants forever. Before judging, the runner runs every distinct `expectRed` set unmutated and isolated; any red
or unexecuted title ⇒ exit 1 without judging. **CI**: the nightly `schedule` now launches only `guard-mutants-full`
(every other job has `if: github.event_name != 'schedule'`).

## [2.5.0-alpha.2] — 2026-10-15 (plan 2.5 · lot B): the breaking changes that must land before the first 2.x stable

Nine pieces, decided by the judge of the tenancy panel (round 2, `panel-tenencia-2-juez.md` §1) and signed by the owner
(2026-10-14): what has to break **before** `2.5.0` and before the deny of lot D, because after the first stable each of
them is a major. Every piece has a red observed first, a mutant that the case kills, and its twins checked
(`.claude/contexto/loteB-informe.md`). No new capability for roles; one optional capability for the outbox contract (D15).

**🔴 BREAKING — B1: a cycle in `includes` is 422 `E_AUTHZ_RELATION_CONFIG`, naming the cycle.** *Problem* (measured by the
tester, H4, and the analyst, M3): `defineRelationsConfig` accepted `editor ⊇ viewer ⊇ editor`; the `database` driver *served*
it (the include expansion terminates by the `Set`) while `openfga:provision` cannot publish it (OpenFGA refuses any cycle), so
one config meant two behaviours — parity broken at the config. *Decision*: a DFS over the `includes` graph of each type at
`defineRelationsConfig`, before any driver exists, rejecting the direct cycle (`a ⊇ a`), the 2-cycle and the N-cycle with the
chain in the message (`document#editor → document#viewer → document#editor`, from the node that closes it, not from the entry
point); a diamond is not a cycle and still enters. *What is NOT done*: no driver-side check (it is config; the same 422 serves
both drivers) and no attempt to "serve what FGA would serve" (there is nothing FGA serves here).

**🔴 BREAKING — B2: an unknown key anywhere in the relations spec is 422 `E_AUTHZ_RELATION_CONFIG_UNKNOWN_KEY`; and the roles
`defineConfig` rejects unknown keys too (500 `E_AUTHZ_CONFIG`).** *Problem* (tester H3, measured; lineage L5 "silent inert
input", fifth iteration ⇒ universal property): `frozenTypes` copied only `type`/`relations` and `name`/`includes` and
**dropped everything else in silence** — a `denny: true` typo was an inert entry, and the `deny: true` of lot D read by a
2.4 process would have republished the model without `denied_*` without anyone noticing (auditor R2-3 ii). *Decision*: **no
key of a config spec is ever discarded**: an explicit allow-list per level (`RELATIONS_SPEC_KEYS`: root `objectTypes`,
`holderTypes`, `database`; type `type`, `relations`; relation `name`, `includes`; `database.membersOf`), the error names the
path (`objectTypes[1].deny`, `objectTypes[0].relations[1].denny`, `database.foo`) and the list; the keys of lot D enter the
list in the same commit as their effect. The twin in roles had the same hole — `defineConfig` was the identity — so it now
validates the root and the `openfga`/`scopes`/`relations`/`hooks` blocks against `AUTHORIZATION_CONFIG_KEYS` (500, the family's
status). `membersOf` at the root keeps its own 422 (it runs first). *What is NOT done*: no validation of VALUES beyond what
already existed (a wrong `resolveChain` is still judged by the manager when used), and no allow-list for `drivers`/`catalogs`
(open maps of the consumer).

**🔴 BREAKING — B3: a userset subject that is not `group#member` is 422 `E_AUTHZ_RELATION_USERSET_UNSUPPORTED` on every
operation that takes a subject, in the manager, both drivers and the published double, before any backend call.** *Problem*
(auditor [N 9], round 1): `{ object: document, relation: viewer }` as subject passed F-05 (declared type and relation) and
then `database` stored the row **inert** (no holder ever reaches it: principals expand only through `group#member`) while
`openfga` composed `document:<key>|<id>#viewer` as `user`, which the fused model does not admit — 400 from the server, surfaced
as a misclassified 503 (invariant 5: an invalid question is 422). *Decision*: one function, `assertUsersetSubject` (F-05 of the
pair, then `group#member` and only `group#member`), same class/code/message through every door (`#assertSubject` of the
manager, `#subjectColumns` of `database`, `#subjectUser` of `openfga`, the double), on `relate`/`unrelate`/`check`/`checkMany`/
`listObjects`/`purgeSubject`; it is a subclass of `RelationUnknownError`, so `reconcileRelations` counts such a tuple from a
pre-2.5 source in `skipped.undeclared` instead of aborting the pass. In the surface guard it is a new F-05 variant
(`usersetUnsupported`) on every cell with a subject, with one mutant per layer (manager, database, openfga, double). *What is
NOT done*: no new guard column (it is F-05's own grammar: "which subjects exist"); `listSubjects` still returns whatever the
store holds (output, not validated), so a pre-2.5 row with such a subject is listed but **no longer purgeable by
`purgeSubject(userset)`** — the README gives the SQL to find and delete those rows (`purgeObject` still removes them by object).

**🔴 BREAKING (letter) — B4: `listObjects` of `openfga` signals `truncated: true` also when the call takes ≥ 90 % of the
server's `ListObjects` deadline; the README no longer promises "never a mute partial list" of the cap alone.** *Problem*
(analyst M4, measured): OpenFGA's `--listObjects-deadline` (3 s by default) makes the server answer **200 with whatever it had
resolved and no signal**; the driver only signalled the cap, so the README's letter was false. Fifth iteration of lineage L8
(letter ≠ effect) and its first [N] ⇒ **M8**: universal property *"every enumeration that can be cut returns `truncated` or
throws"*, one chokepoint per list API — `#listObjectsPage` for `ListObjects` (cap **or** elapsed ≥
`LIST_OBJECTS_DEADLINE_RATIO` × `listObjectsDeadlineMs`, measured with a monotonic clock, injectable for tests only
through a symbol-keyed option — ⚪ 9 of closure 1) and `#readAll` for `Read` (exhaustive or 503: a response without
`tuples`, a token that does not advance, more than 10,000 pages). New driver option `listObjectsDeadlineMs` (default
`DEFAULT_LIST_OBJECTS_DEADLINE_MS` = 3,000): the server's **effective** cut of `ListObjects` — whichever is lowest of
`--listObjects-deadline` (when not 0), `--request-timeout` and, over HTTP, `--http-upstream-timeout`; declare that lowest
one, and never above the driver's own `timeoutMs` (closures 2 and 3 of this lot: 🟠 N1, ⚪ N10) — both constants exported
from `/openfga` and pinned in the README's Limits table. **Entry in the surface guard**:
a new column `truncation` with probes on the six `openfga` operations that enumerate (`listObjects` with the two causes and
the control; `listSubjects`, `enumerateRelations(Many)` and the two purges with a `Read` that cannot be exhaustive ⇒ 503 and
zero deletes) and three mutants (switch off the cap, switch off the deadline, "an empty page is the end"); `database` is
`exhaustive`, the manager `passthrough`, the double `double`. *Decision on the capability*: **no new one** — `listObjectsTruncation`
already means "the driver signals a cut"; the deadline is the second cause of the same signal (the docblock says so); the
signal is conservative on purpose (a slow-but-complete call may be flagged; a cut one never passes as complete). *What is NOT
done*: no retry, no partial-result cache, no attempt to read the server's deadline (it is not exposed) — you configure it.

**B5: `authz:relations:reconcile` treats a FAILED read of the persisted destination config as an error (exit 1, letter,
nothing built/frozen/written); `null` ("no config persisted") still enters.** *Problem* (analyst §4.7, auditor R2-5; lineage
L5): `readRelationsConfig().catch(() => undefined)` — a read failure silently continued without the destination's config, so
`--dry-run` stopped watching model drift and, with the deny of lot D, the 500 gate of the plan would have vanished. *Decision*:
three branches, each with its own line (CLAUDE.md point 7): failure ⇒ error naming `authz_relations_config` and "an unreadable
config is NOT 'no config'", exit 1 before building anything; `null` ⇒ "none persisted: drift is NOT watched in this pass";
read ⇒ "read from authz_relations_config (N types): drift is watched". Truth table {read, null, throws} × {dry-run, real}
executed through the ace kernel. *What is NOT done*: `runRelationsReconcile` (the function) is unchanged — it receives
`toConfig` from its caller and never reads the table; the roles command has no persisted config to read.

**🔴 BREAKING — B6: `sqlScopeOutbox({ requireTransaction })` is `true` by default.** *Problem*: the mitigation of the tree
outbox is *entirely* the `{ transaction }` you hand to `scopes.*`; a default `false` let a call enqueue outside your unit of
work in silence (the S5 leak on the correct-use path). It stayed `false` in 2.4 only because the published contract enqueued
without a transaction in `ctx()`. *Decision* (owner): default `true` since 2.5.0 and `requireTransaction: false` as the
explicit opt-out; **the prerequisite is met**: `runScopeOutboxContract` now enqueues inside a transaction of the harness in
every case — direct enqueues *and* through `scopes.*` of the manager — governed by a new optional capability
**`requiresTransaction`** (D15: `?:`, normalised to `false`): `true` ⇒ the judge passes the transaction everywhere and pins the
refusal (500 `E_AUTHZ_CONFIG` naming `requireTransaction`, zero rows, through the outbox alone and through the manager, driver
untouched); `false` ⇒ it pins that enqueueing without one enters; both faces run in `npm test` (the SQL outbox with the default
in `sqlite-file`/pg/mysql, the full in-memory double with a fake transaction in every mode). **The measure of the flip**
(what went red before the harnesses declared their opt-out, SQLite `:memory:`): 56 of 148 cases in `scope_outbox.spec`, 16 of
51 in the published contract, 4 in `command_flags`, 1 in `reconcile` — every one of them a harness enqueueing without a
transaction on purpose, now written as `requireTransaction: false` with the reason; the cutover runbook's child process
enqueues inside `db.transaction()` like the README recipe. **Declared limit**: `{ transaction }` through the manager needs a
pool ≥ 2 (the freeze barrier reads through another connection), so the SQL outbox of the `:memory:` harness declares
`requiresTransaction: false` and runs with the opt-out, and a `:memory:` deployment must do the same. *What is NOT done*: the
manager does not construct the outbox, so the option still lives in `sqlScopeOutbox`; no attempt to open a transaction on
the consumer's behalf.

**🔴 BREAKING — B7: `runRelationsReconcile` moves to its own subpath `@jantstack/adonis-authz/relations/reconcile`; the
module of the ace command no longer exports it (nor `RunRelationsReconcileOptions`).** *Problem*: the only public way to
reconcile relations from code was imported from `./commands/authz_relations_reconcile`, the ace command module — it drags
`@adonisjs/core/ace` and the `./commands/*` wildcard exists for the loader, not for API. *Decision*: a thin module
(`src/relations_reconcile.ts`: the function and its types, no ace, no command) with its own `exports` entry; the command imports
it from there; the old import is gone (a case pins that the command module does not export the function or the type, and that
the new module's imports touch neither ace nor `commands/`). The source-level guard of the primitive (`reconcileRelations`) now
names the new module and the `/testing` harness as its only importers. *What is NOT done*: no re-export from the root
(the function takes the manager; the root stays free of it) and no compatibility alias in the command module (that is the
break, decided before the stable).

**B8: the roles reconcile verifier reads the PINNED model (`options.modelId`), not the latest one.** *Problem* (auditor R2-10):
`modelPermissions()` read `readLatestAuthorizationModel()` while the pods serve with the pinned id; the pass certified against
a model nobody uses — a permission published after the pinned model was written under the pinned one (400 ⇒ 503 mid-pass),
and one removed from the latest was *counted* and left unprojected in the model that serves (fail-closed on a live permission).
*Decision*: with `modelId` the driver reads that model (`readAuthorizationModel()` with the client's configured id); without it,
the latest, as before. Both directions pinned against a real server. *What is NOT done*: the model is still never republished
inside a cutover window (runbook rule), and the relations twin reads the persisted spec (B5), not the model.

**B9 (letter):** `README` no longer describes `republishFusedModel` (retired in 4-8: the fused model is published by
`openfga:provision` from the static config, nothing republishes it behind your back; the persisted config's one reader is the
relations reconcile, B5); the `resourceAccess` heading says `2.4.0-alpha.1` (the version it shipped in), not "(2.5)";
`CLAUDE.md` point 10 is the criterion of **`2.5.0`** stable in one sentence; zero occurrences of `republishFusedModel` in
README, CLAUDE.md and `src/`.

**Surface guard figures**: 111 mutants (104 + 4 of B3 + 3 of B4), 171 cases, one new column; the outbox contract registers 18
cases per harness (17 + the `requiresTransaction` pair) over 9 capabilities.

### Closure 1 of lot B — the adversarial audit of the diff (`loteB-auditor.md`: 0 🔴, 2 🟠, 6 🟡, 6 ⚪, all in)

**🟠 1/🟠 2 — the pre-2.5 residue of B3 (`database` rows whose subject is a userset other than `group#member`) is
classified in the reconcile PLAN, never absorbed by the driver; decision 4 of the implementer (make
`RelationUsersetUnsupportedError` a subclass of `RelationUnknownError` so that `relateOrSkip` counts it) is
REJECTED.** *Problem* (auditor, reproduced): the subclass made `reconcileRelations` treat the residue as
`skipped.undeclared` — a false remedy ("declare it in the destination"), `--dry-run` reporting "would write 1" forever,
`details` empty — and, in the destination under `--prune`, the plan put it in `toDelete`, wrote the `toWrite`, then
`unrelate` answered 422 and the pass **aborted mid-way after a partial write**, on every retry. *Decision* (coordinator,
2026-10-15): one rule for every destination tuple the API does not admit — *listed, exit ≠ 0, deleted by hand*. The
class is its own 422; `planPartition` classifies the subject of every enumerated tuple (`assertSupportedUserset`, with or
without `toConfig`; with it, F-05 of the pair too): a source residue counts in **`skipped.usersetUnsupported`** (new
optional counter) and a destination residue counts in `extra`, **never enters `toDelete`** (no platform `DELETE` on a
row the API refuses) and carries `pruned: false` under `--prune` — in `--dry-run` as well; both sides go to `details`
with `reason: 'userset-unsupported'`; `--dry-run`, the real pass and the next `--dry-run` give the same numbers; the
driver never receives the `relate`; `relateOrSkip` rethrows the class (a driver that raises it for a tuple the plan
accepted is saying something else). `relationsReconcileLines` prints one error line per residue naming the side, the
tuple and the SQL recipe (the exact `DELETE` the README publishes), in the four modes (prune × dry-run): the verifier
stays red until the recipe runs, and says why. Pinned on the real `database` driver in the four test modes (three
engines) with the residue seeded by SQL, through the kernel (`--to=database --prune`: exit 1, no throw, the good
tuple written, the residue left), and the "does not swallow" case. *What is NOT done*: no `--prune-residue`, no
relaxation of `unrelate`'s grammar; the recipe is the only way out, and ⚪ 12 executes it.

**🟡 3 — the pool letter.** The 500 of `sqlScopeOutbox.enqueue` without `{ transaction }` now says that `{ transaction }`
through the manager needs a pool ≥ 2 (with one connection the freeze barrier is 503 at `freezeTimeoutMs`) and that
with **pool max 1 — knex's default for every SQLite connection, file or `:memory:`** — the way out is
`requireTransaction: false`; README (§Upgrading 9 and the `requireTransaction` paragraph) says "pool max 1", not
`:memory:`. *Not done*: detecting the pool size at construction — the package does not guess the pool (doctrine of
`transactionalWrites`, "the driver declares what its deployment can do"), and the 503 is raised by the manager's
barrier, not by the outbox.

**🟡 4 — M8 for a 200 without a body, on both ports.** `#listObjectsPage` throws 503 `E_AUTHZ_BACKEND_UNAVAILABLE` when
the response carries no `objects` array (it used to answer `{ objects: [] }` with no signal: the third mute partial
list); fourth face of the `truncation` probe in the surface guard and mutant `openfga.listObjects.truncation.noObjects`
(112 mutants; the probe stays one case). The roles driver gets the same rule through one chokepoint, `tuplesOrThrow`, in its three `Read`s
(`readAllTuples`, the reconcile dump, `enumerateFacts`): until now `response.tuples ?? []` read a bodiless 200 as an
empty enumeration and `purgeScope` **proved zero on it without deleting anything** (invariant 11); pinned with a
fake client (503, zero `deleteTuples`) and a source grep (no `tuples ?? []` left). Line (a) of the B4 closure that
called the roles `Read` "the same exhaustive-or-500 pattern" was false; it is true now.

**🟡 5 — B3 in the published runner.** New core case of `runRelationsDriverContract` (28 → **29**): a declared userset
other than `group#member` as subject is 422 `E_AUTHZ_RELATION_USERSET_UNSUPPORTED` on `relate`/`unrelate`/`check`/
`checkMany`/`listObjects`/`purgeSubject`, through the manager (zero driver calls, spied, zero events) **and** through the driver called directly; `group#member` still enters (control). A third-party driver that
stored the inert row passed the whole contract until now. README §Upgrading 2.

**🟡 6 — one chokepoint for the shape of the roles config, and a type guard.** `assertAuthorizationConfigShape` runs in
`defineConfig`, in the `AuthorizationManager` constructor (which covers the provider) and in `buildRelationsManager`:
`new AuthorizationManager({ requireWithing: true })` and a `config/authorization.ts` exported without `defineConfig`
are 500 too; a known block that is not an object (`scopes: true`) is 500 (⚪ 13, roles twin). The entry in the guard is
**the compiler**: `Record<Exclude<keyof AuthorizationConfig, KnownRootKey>, never> = {}` per level (root, `openfga`,
`scopes`, `relations`, `hooks`; in relations: spec root, `objectTypes[i]`, `relations[j]`, `database`) plus
`satisfies` on each list — a field added to the type without entering its allow-list breaks `npm run typecheck`
(measured both ways).

**🟡 7 — a persisted config that no longer validates is its own branch.** `readRelationsConfigSpec` turns corrupt JSON
into a 422 `RelationConfigError` (the read *did* finish), and `authz:relations:reconcile` separates *"la config
persistida en authz_relations_config NO valida en 2.5: <motivo> … re-guárdala con saveRelationsConfig(<spec
corregida>)"* (exit 1, nothing built) from *"la lectura falló"* (503) and from `null`; the B5 truth table has four
rows now (read / null / does not validate / read fails), executed through the kernel with the row seeded as a pre-2.5
`saveRelationsConfig` left it (`deny: true`) and with an `includes` cycle. README §Upgrading 5 and 8.

**🟡 8 / ⚪ 14 — `--listObjects-deadline=0` and the price.** This closure measured `0s` on OpenFGA v1.19.0 against a
whole list that returned in 5 ms and read it as "no deadline", publishing `listObjectsDeadlineMs: Infinity` for that
server. **That reading was wrong and the advice is withdrawn in closure 2 (🟠 N1, below)**: with the deadline at 0 the
server's `--request-timeout` (3 s by default) still cuts `ListObjects` with a mute 200. What stands from this item:
`0` on the driver stays 500; the Limits row states the price of the conservative signal (with the default, every
`ListObjects` ≥ 2,700 ms comes back `truncated`; a consumer that treats `truncated` as 503 pays that p99), and
"Third-party drivers" says the runner judges the cap only — **the runner does not judge the deadline**.

**⚪ 9 — `monotonic` leaves the published type.** The injectable monotonic clock is a symbol-keyed option
(`MONOTONIC_CLOCK`, exported by the driver module only, not by `/openfga`); the text key `monotonic` is 500 (an inert
option never falls into a default in silence); a case pins that the README does not document it. **⚪ 10** — a source
guard pins one `client.listObjects(` in the driver, inside `#listObjectsPage`. **⚪ 11** — the `purgeObject` letter of B3
is precise (the tuple's own object, together with its legitimate shares; the userset's object does not reach it).
**⚪ 12** — the B3 recipe (detector + `DELETE`, one `sql` block, the same two statements on the three engines) is
executed by `upgrade_recipe.spec` in the four test modes and pinned byte-for-byte to the constants the reconcile line
prints. **⚪ 13** — `database: true` is 422 naming the block, `includes: {}` is 422 (was a raw `TypeError`),
`defineRelationsConfig(<already defined>)` — hence `saveRelationsConfig(config.relations.config)` — is 422 with the hint
"looks like an already defined config; pass the spec".

**Figures after the closure**: surface guard 112 mutants / 171 cases (the fourth face lives inside the existing `listObjects` probe); relations runner 29 core cases per harness.

### Closure 2 of lot B — the auditor's re-attack on closure 1 (`loteB-auditor-cierre.md`: 0 🔴, 1 🟠, 3 🟡, 4 ⚪, all in)

**🟠 N1 — `listObjectsDeadlineMs: Infinity` is withdrawn; the option means the server's EFFECTIVE cut.** *Problem*
(auditor, measured on OpenFGA v1.19.0 with two disposable containers and 40,000 `document#editor@group:gN#member`
tuples): with `--listObjects-deadline=0` the `--request-timeout` interceptor (3 s by default) still cuts `ListObjects`
and the server answers **200 with whatever it had** — `--request-timeout=30ms` ⇒ `200`, 0 objects of 40,000, in 45–48 ms,
three runs; control with 30 s ⇒ 40,000 of 40,000 in 91–113 ms. In the source, `pkg/server/commands/list_objects.go`
only wraps the context in its own `WithTimeout` when the deadline is not 0 and otherwise inherits the caller's context,
which `cmd/run/run.go` wraps with `NewTimeoutInterceptor` when `--request-timeout > 0`, and the deadline error is elided
into the partial result. Closure 1 had measured a whole list returning in 5 ms, which cannot tell "no deadline" from
"deadline = request timeout", and published `Infinity` as the recipe for that server: with it the driver's own 5 s client
timeout lets the mute 200 through and the elapsed-time signal never fires — `{ objects: <partial or []>, truncated:
undefined }`, the mute complete list that B4/M8 exist to forbid; with the default (3,000) the same server does signal.
Strictly worse than doing nothing. *Decision* (coordinator, 2026-10-15): `Infinity` is **refused** — `Infinity`, `NaN`,
`0`, negatives and non-integers are 500 `E_AUTHZ_CONFIG` at construction with the letter *"the server always cuts at one
of the two; declare the lower one"* — and `listObjectsDeadlineMs` now means the server's **effective** cut: whichever is
lower of `--listObjects-deadline` (when not 0) and `--request-timeout`. Both at 0 is a **declared limit**, not a promise
(the HTTP gateway's `--http-upstream-timeout`, 5 s, could not be isolated for `ListObjects`: with an upstream of 30–100 ms
the gateway already breaks the `Write`s). README (relations paragraph, Limits row, Upgrading 7), the option's docblock and
the constant's docblock say so with the measurement and the version; the case that pinned "an hour-long call under
`Infinity` is not a cut" is rewritten (`Infinity` ⇒ 500; the effective cut of a deadline-0 server with
`--request-timeout=30ms` is declared as 30 and a 27 ms call signals) plus a source guard (no `=== Infinity` branch in the
driver). The README letter is pinned by `scope_depth.spec` (`listObjectsDeadlineMs: Infinity` absent, `--request-timeout`,
"whichever is lower", "both at 0 is not supported", "measured on OpenFGA v1.19.0"). Lineage L8 (letter ≠ effect), sixth
iteration under M8; mutant "accept `Infinity` again" ⇒ red. *What is NOT done*: no case against a real deadline-0 server
inside the suite (the measurement is the auditor's, cited verbatim with its method; the driver case runs with the injected
monotonic clock), and no attempt to make the driver "detect" the server's timeouts (the server does not expose them;
declaring the lower one is the operator's one line).

**🟡 N2 — in the reconcile plan the FORM of the userset is judged before the pair's F-05, with or without `toConfig`
(decision 3 of closure 1 rejected).** *Problem* (auditor, reproduced): a source residue whose userset names a type or a
relation the destination's persisted config does not declare (`document#viewer@folder:F#viewer`,
`document#viewer@document:E#reader`) went back to `skipped.undeclared` — no `details`, no recipe, and the false remedy
"declare them in the destination", which would not fix anything (declared, the next pass reclassifies it as residue) — so
the bucket depended on whether a config was persisted. *Decision*: `classifySubject` runs `assertSupportedUserset` first;
only a `group#member` whose pair F-05 rejects is `undeclared`. Case with three `toConfig`s (without the types, with them,
none): `skipped.usersetUnsupported 2`, `undeclared 0`, `modelDrift []`, dry = real, two lines with the recipe and never the
false advice. Mutant "F-05 first" ⇒ red. *What is NOT done*: the API order (`assertUsersetSubject`, the caller's question)
stays F-05 → form — both are 422 before any backend call and nothing is written either way; the plan is where the bucket
and the remedy are decided.

**🟡 N3 — one rule for every destination row the API does not admit: `invalid-identity` joins `userset-unsupported`, and
"repeat with `--prune`" is printed only for what `--prune` really deletes.** *Problem* (auditor): with a destination
residue the real pass printed *"no pasaste --prune: repite con --prune"* right under *"--prune NO lo borra"* — also when
`--prune` had been passed, because the report did not carry it and the line fired on `extra > 0` alone; and
`invalid-identity` in the destination was asked of the driver (both package drivers refuse it by their grammar in
`unrelate`, R-16), was a **warning with exit 0** without `--prune` ("repeat with --prune", which would not remove it
either) and came out `pruned: true` / "would be deleted" in a dry run. Two rules for one thing. *Decision* (coordinator,
2026-10-15, the auditor's condition on decision 1 of closure 1): a destination residue nobody in the package deletes —
`userset-unsupported` **and** `invalid-identity` — has the **same** semantics: `extra` + `details` with `pruned: false`
under `--prune` (in `--dry-run` as well), **never in `toDelete`** (the pass asks nobody: no `unrelate` by the port, no
platform `DELETE`), `error` with the stable prefix *"sobra (<reason>) destino:"*, exit ≠ 0 in the four modes, the recipe
on the line, and never "repeat with --prune". The report carries **`prune`** (optional; absent = not passed) and the
advice line counts `extra − destination residue`, only without `--prune`. Truth table {reason} × {prune} × {dry-run,
real} executed by `relations_reconcile_cli.spec` (letter) and `relations_reconcile.spec` (plan, with a grammar-less fake
destination that is never asked and with the real `database` driver). **Existing cases that changed**: the lot A ⚪ R2
cases that pinned `pruned: true` / `deleted 1` for a fake destination and the dry-run `pruned: true` for `database`
(rewritten: the `pruned: true` path no longer exists in the package), the ⚪ R2 letter case (no-prune `invalid-identity`
was `clean` with a warning, now `error` and drift). The `unrelate` catch that absorbed a 422 for an invalid tuple is gone — and the sentence this entry carried
until closure 3, *"everything in `toDelete` passed the grammar, so a 422 there is the driver contradicting the plan and
propagates"*, was **false**: a row can pass the grammar and still fail F-05 (a relation retired from the config with rows
still there; 🟠 N9 of the final audit, closure 3 below). Since closure 3 the prune loop classifies the 422s of the relations
family and propagates everything else.
`RelationsReconcileDetail.pruned` keeps its `boolean` type for compatibility; the command still prints "BORRADA" for a
`true` a third-party harness might construct. *What is NOT done*: a third-party driver that could delete such a row is not
asked either — the rule is by the row, not by the driver (the package drivers are the ones measured).

**🟡 N4 — the B3 case of the published runner observes the backend through the port.** *Problem* (auditor, measured):
a driver that validates after writing (`relate` stores the inert row, then throws the 422) passed `runRelationsDriverContract`
entire (58/58 with that mutant on the double); decision 8 of closure 1 ("the runner does not see a third party's backend")
was false — it sees it through `listSubjects` and `enumerateRelations`. *Decision*: after the attempts by manager and by
driver, the case asserts that `listSubjects('viewer', doc, S)` does not contain the stale userset and, with the capability,
that `enumerateRelations(S)` does not either. Mutant "store then throw" on the double ⇒ the runner goes red (measured) — **through a port the harness
declares**: with `usersetSubjects: false` and `enumerateRelations: false` the runner has no port through which to see the
stored row and stays green with that mutant; the limit is written in the runner's docblock and in README «Third-party
drivers» (⚪ N11 of closure 3).

**⚪ N5** — `readAssignment` (roles, the point read of `grant`) and `#readTuple` (relations, the point read of `relate`)
took a 200 without `tuples` for "absent" and wrote blind (a live expiry that cannot be seen is not preserved); both now go
through the exhaustive-or-503 rule (`tuplesOrThrow` — four call sites — and an `Array.isArray` in `#readTuple`): `grant`
with `expiresAt` omitted is 503 and zero `write`, `relate` is 503 and zero `write` (`unrelate` never reads: blind delete
with `IGNORE_MISSING_DELETES`, control). The source grep of the case is `tuples\s*(\?\?|\?\.\[)` over both drivers.
**⚪ N6** — a persisted `authz_relations_config` row whose JSON is valid but not an object (`null`, `0`, `false`, `""`,
`[]`) read as "no config persisted" and silently switched the model-drift watch off; it is now the "does NOT validate"
branch (422 `RelationConfigError`, "no es un objeto"); only the absent row is `null`. **⚪ N7** — `holderTypes` that is not
an array is 422 naming the key (a string was iterated by character and disarmed the ⚪4 collision with a homonymous object
type); for the roles config (`holderTypes: 'users'`, `drivers: 1`) the limit is declared: they fail later, when resolved.
**⚪ N8** — the R-17 refusal names each discarded reason (`skipped.undeclared`, `skipped.usersetUnsupported`,
`skipped.invalid`, expired) by its name and only when it counts; "todas de tipos que el destino no declara" was printed with
any `toConfig`, also when the only source rows were B3 residue.

**Decision 4 (CLAUDE.md, point 7)**: "own exit" = non-zero and different from success; the **branch** is identified by a
stable prefix of its line, named in the case. No exit codes are invented per branch.

### Closure 3 of lot B — the auditor's final pass on closure 2 (`loteB-auditor-cierre2.md`: 0 🔴, 1 🟠, 0 🟡, 3 ⚪, all in)

**🟠 N9 — a relation retired from the config, with rows still in the destination, made `--prune` throw mid-pass; the
prune loop now never throws for a 422 of the relations family.** *Problem* (auditor, reproduced on `database`; pre-existing
since L-0 / lot A, not a regression of closure 2): take `document#publisher` out of `objectTypes` while `authz_relations`
still holds its rows — normal evolution of a config, no SQL by hand. `enumerateRelations` filters by **type**, not by
relation, so the row reaches the plan; the plan judged only the grammar and the form of the userset, so it went into
`toDelete`; `unrelate` runs F-05 on its first line ⇒ 422 `E_AUTHZ_RELATION_UNKNOWN` **after** writing the new tuple and
deleting the stray one; the catch had been removed in closure 2 ("everything in `toDelete` passed the grammar") and the
command does not catch it ⇒ **raw stack**, destination half-done, `--dry-run --prune` reported `deleted 2, details []`
(dry ≠ real), and the next pass threw the same — `--prune` unusable for that partition for ever. The README's "one rule for
every destination row the API does not admit" and decision §6.1 of closure 2 declared it impossible. *Decision*
(coordinator, 2026-10-15): the row is classified **in the plan with the rule of N3**, and **the prune loop never throws for
a 422 of the relations family** — two layers. (1) With `toConfig` (the command always passes the persisted config when
there is one), `classifyDestinationRow` applies the destination's F-05 (`assertRelationDeclared`, the same function as the
driver's first line) to every destination row ⇒ `extra` + `details` (`side: 'destino'`, `reason: 'undeclared'`,
`pruned: false` under `--prune`, in `--dry-run` too), never `toDelete`, with the remedy "delete it by hand or declare the
relation again (and re-save the persisted config)"; `--dry-run` and the real pass give the same numbers. (2) Without
`toConfig` (`reconcileRelations` from code) — or when the driver contradicts the plan — the prune loop catches **only** the
422s of the relations family (`E_AUTHZ_RELATION_TYPE_UNKNOWN`, `E_AUTHZ_RELATION_UNKNOWN`,
`E_AUTHZ_RELATION_USERSET_UNSUPPORTED`, `E_AUTHZ_INVALID_IDENTITY`; by `code` and `status`, so a third-party class with the
same code counts), classifies each by code (`reason` derived from the code), goes on with the other rows, counts it in
`extra` with `pruned: false` and the command exits ≠ 0 with the stable prefix *"sobra (<motivo>) destino:"* (point 7). A
422 of **another** family or any other 4xx/5xx still propagates: that is the driver contradicting the plan for a reason
the report cannot count. `#enumerateRows`/`#sweep` are **not** filtered by relation on purpose: a row nobody lists is worse
(lineage L8). `RelationsReconcileDetail.reason` gains `'undeclared'` (destination only). Cases: dry/real/dry2 with and
without `toConfig` on the real `database` driver (three engines) and on `openfga` against the server (the auditor's "❓":
`#sweep` filters by type and `unrelate` runs F-05, same shape), the third-party double with the four family codes and the
three that must propagate, the letter table in `relations_reconcile_cli.spec`, a kernel case (`run.error` undefined,
exit 1, the line) and an **executed truth table** {reason} × {toConfig} × {dry, real} ⇒ bucket, details, line, exit.
Mutants: "no catch" ⇒ red; "no plan classification with `toConfig`" ⇒ red; "catch every error" ⇒ red; "catch any 422"
⇒ red. *Existing case that changed*: the lot-0 closure's ⚪ 10 case ("a destination whose driver still runs the old
config while the pass runs with the current `toConfig`": until now `--prune` deleted that row through the old driver) —
by the rule of N3 ("by the row, not by the driver") it is now `undeclared` residue, `deleted 0`, `extra 1`, and re-declaring
it in `toConfig` makes it an ordinary tuple again; the case is rewritten, not weakened. *Declared limit*: without
`toConfig` `--dry-run` cannot anticipate F-05 and counts the row in `deleted` (the same limit L-0 declares for `written`);
the real pass lists it. *What is NOT done*: no `--prune-undeclared` (lot D, roadmap 2.5) — nothing deletes a row the
destination does not declare.

**⚪ N10 — `listObjectsDeadlineMs` cannot exceed the client's `timeoutMs`, and the letter names the third cut.** *Problem*
(auditor): `Number.isInteger(Number.MAX_SAFE_INTEGER)` is `true`, so the N1 guard admitted "no deadline" under another
name; the B4 entry still said "set it to the server's" and named `monotonic` as an injectable option (withdrawn in ⚪ 9);
and "lower of the two" did not name the gateway's `--http-upstream-timeout` (5 s). *Decision* (coordinator): a structural
guard with no arbitrary ceiling — **`listObjectsDeadlineMs ≤ timeoutMs`** of the client (5 s by default), otherwise 500
`E_AUTHZ_CONFIG` with the letter *"la señal tiene que poder saltar antes de que el cliente corte"*: a deadline the client
cuts before the 0.9 threshold is a signal that can never fire, and if the server cuts earlier the mute list passes as
complete. The letter everywhere (README relations paragraph, Limits row, Upgrading 7, the option's and the constant's
docblocks, the B4 entry rewritten): *the effective cut is the lowest of `--listObjects-deadline` (when not 0),
`--request-timeout` and, over HTTP, `--http-upstream-timeout`; declare that lowest one*. Case (`MAX_SAFE_INTEGER`, 5,001,
the default with `timeoutMs: 2,999`; equal admitted) + mutant "drop the guard" ⇒ red. *Existing cases that changed*: the
alpha.3 · C4 mute-server case (`timeoutMs: 200`) and the surface guard's `fgaDriver` (`timeoutMs: 1000`) now declare a
deadline at or below their timeout. **Adapt**: a driver built with `timeoutMs` below 3,000 ms must declare
`listObjectsDeadlineMs` at or below it (until now the signal was silently unreachable there).

**⚪ N11 — the limit of the minimal harness is written where the report said it was.** A third-party driver declaring
`usersetSubjects: false` and `enumerateRelations: false` that stores the inert B3 row and then throws passes the runner
(the runner has no port through which to see the row; measured with the mutant). Written in the runner's docblock next to
the B3 case, in README «Third-party drivers» (pinned by `trx_docs.spec`) and in the N4 entry above.

**⚪ N12 — "Closure 2 of lot B" had landed under the `[2.5.0-alpha.1]` heading, a published version.** Moved to `[Unreleased]` after
"Closure 1 of lot B". A letter case (`relations_events_docs.spec`) pins that the closures live above the alpha.1 heading and
that the alpha.1 block does not change (its hash is fixed; a deliberate fix to a published block updates the hash in the
same commit).

**⚪ N13 / ⚪ N15 (the auditor's last pass on closure 3, `loteB-auditor-cierre3.md`; applied by the coordinator).** The prune
loop's capture table was consulted with a plain property lookup, so a 422 whose `code` happened to be a key of
`Object.prototype` (`constructor`, `toString`, `__proto__`) was absorbed with a garbage reason; the lookup is now
`Object.hasOwn` and the case lists those codes among the errors that must propagate. The same case now also fixes the
`status` half of the capture (a family `code` with status 500 propagates): the mutant that dropped `status === 422` used
to survive. ⚪ N14 is a declared limit (README §Upgrading 6): when the persisted config and the destination driver's config
differ — `saveRelationsConfig` is manual — `--dry-run` classifies with the persisted one and the real pass with the
driver's, so the numbers can differ in that window; re-save the config and they agree again. ⚪ N16 (nothing validates
`timeoutMs` itself) is left as is: it is the SDK's option and the guard above only relates the two.

**Figures after closure 3** (coordinator's own run on the exact tree of this release): `:memory:` 1734 · `sqlite-file` 1762 ·
pg 1859 · mysql 1861 (plus the N13/N15 case: +0, it extends an existing case); surface guard 112/112, flag mutants 36/36,
cutover runbook green on pg and sqlite-file.

## [2.5.0-alpha.1] — 2026-10-15 (plan 2.5 · lots 0, R and A)

**No `2.4.0` stable will be published.** The 2.4 alpha line ends at `2.4.0-alpha.10` and continues as `2.5.0-alpha.x`; the first 2.x stable will be `2.5.0` (see the plan in `.claude/contexto/panel-tenencia-2-juez.md`). Three new release gates exist from this version and are documented in `CLAUDE.md`: `npm run check:guard-mutants`, `npm run check:flag-mutants` and `npm run cutover-runbook`.

### Lot A — `createTestClock`, `relationTupleKey`, `checkMany`, D4 (canonical partition uuid), D13, F-R1–F-R3

**There is no `2.4.0` stable.** The 2.4 line ends at `2.4.0-alpha.10`; the next stable is **2.5.0** (owner's decision
2026-10-14: tenancy — deny, `decideMany`, `listObjectsForSubject` — ships in the same line, lots B, D and C). This alpha is
lot 0 (the surface guard, below) plus lot A.

**`checkMany(subject, relation, objects, partition): boolean[]`** (P4 of the 7th COGNITIV report). *Problem*: the ancestor
chain of an object needed N `check` round trips. *Decision*: one method on the `RelationsManager` and the port, by position,
with the **same semantics as N `check`** (includes, usersets, strict expiry decided with **one `now` for the batch**);
`database` answers in one query, `openfga` in one `batchCheck` aligned by `correlationId` (the roles driver's
`correlateBatchResults`, never by position); a driver without it is composed as N `check`s by the manager and the first 503
propagates with no boolean out. Batches are 1..50 (`RELATIONS_CHECK_MANY_MAX` = the server's `batchCheck` cap): 51 and `[]`
are 422 `E_AUTHZ_CHECK_MANY_BATCH` with zero calls; duplicates allowed, answered by position; mixed types with the same
relation, F-05 **per item** (a `role_binding` in position 21 of 21 is 422 with nothing asked); a per-item `error` is 503 for
the whole batch; a third-party answer that is not a `boolean[]` with one position per object is 500 `E_AUTHZ_INTERNAL`.
*What it is NOT*: `false` does not distinguish "denied here" from "nothing here", so it cannot implement deny-wins along
a chain you walk yourself — that is `decideMany` (lot D), and the README says so with those words. No new capability (the
judge's conflict 9). The surface guard was **red** when the method appeared without its row (G-0, all three layers): it got
its row, its probe (F-05 variant in position 1), `PORT_READS` and nine mutants; `contractRelationsConfig()` declares a second
object type (`workspace`) so the mixed-types case is observable (H10 — a harness asserting on that config's published model
sees one type more).

**`relationTupleKey()`** (P3): a pure, exported key over partition + object + relation + subject + `kind` — the expiry is not
part of it (renewing keeps the key; `database` changes the row uuid and that is not a key either). `kind` is `'allow'` by
default and travels in the key **from day one**, pinned by a golden literal, so the key of an allow does not change when the
deny arrives in lot D. `reconcileRelations` matches source and destination with it (no private `tupleKey`/`scopeKeyOf`
copies: `scopeKey`/`assertPartition` come from `identity.ts`, pinned by source). **`kind` is mandatory, with no default**
(audit closure, ⚪ A9): `allow` by omission was the dangerous failure mode — a deny enumerated by a driver that forgot `kind`
would match the allow in `reconcileRelations` — and object, relation and subject now go through the identity grammar, so the
two shapes the audit found that produced the *same* key (`relation: 'b@user:c#d'` vs a userset with `@` in its relation)
are 422, not a key.

**`createTestClock()`** (P5, **`/testing/clock`**): a stable function over a mutable instant (`set`/`advance`/`now`/`at`) for
the consumer's `config.clock`, documented in README «Testing expiry from your app» together with what else that clock decides
(the freeze barrier and the reconcile lease — and, in production, that **the lease is judged by the clock of the process that
reads the freeze row** against an `untilMs` written by the one that froze: a writer whose wall clock runs ahead by more than
the lease writes inside a running pass; pre-existing, now written down — ⚪ A11). It lives in its own light subpath
(`@jantstack/adonis-authz/testing/clock`, which imports nothing but `src/clock.ts`) because the README puts it in
`config/authorization.ts`, a file production loads, and `/testing` imports `@japa/runner` and `@adonisjs/lucid/services/db`
— on an `--omit=dev` deploy that import failed to resolve and the app did not start (🟡 A5). `/testing` still re-exports it;
a case pins the import graph of the subpath (P5-4). *Problem found by the tester (P5-1)*: deleting `clock: config.clock` in the
provider left the suite green — the relations manager silently fell back to wall time. Now a case turns red (a tuple expiring
exactly at the injected instant), a case pins that the same clock governs the freeze barrier of relations writes (lease
lapsed 16 s ahead), and `clock.spec` forbids any direct `systemClock()` call in `src/relations` and the relations drivers
(only the literal list of constructor defaults).

**🔴 BREAKING — D4: a relation partition uuid that is not in its canonical `8-4-4-4-12` spelling is 422
`E_AUTHZ_INVALID_IDENTITY`** in every operation that takes a partition (manager, both drivers, the in-memory double,
`reconcileRelations` / `--partition-uuid`), with zero backend calls and the canonical form in the message. The rule is "32 hex
once the dashes are removed, and not exactly `8-4-4-4-12`": the dashless spelling **and every other placement of the dashes**
(`8-4-4-16`, four groups of eight, the canonical form minus one dash — what PostgreSQL's `uuid` folds into the same row,
measured with `::uuid` on the suite's server). *Problem*: relations have no resolver chain to canonicalise against, so
`unit|<32 hex>` and `unit|<8-4-4-4-12>` were two partitions and the purge/enumeration had to sweep both spellings (🟡2) — and
the lot A audit (🟠 A2) showed the class was wider than "no dashes": an insider could write a share under `8-4-4-16` and
`purgeSubject(user, <canonical>)` never touched it. *Decision*: one rule in one place (`assertPartition`/`isNonCanonicalUuid`,
`src/identity.ts`), the two-spelling sweep removed from both drivers, the guard's `partition` column asserts the 422 with
**two probes per cell** (dashless and `8-4-4-16`) and two global mutants (switch the rule off; revert it to "dashless only"),
a truth table of forms, **and an upgrade recipe** in README «Upgrading to 2.5.0» executed verbatim by `upgrade_recipe.spec`
on PostgreSQL, MySQL and SQLite. **Declared, with its population named (🟡 A6)**: a consumer whose tenant ids are 32 hex
but not uuids (`randomBytes(16).toString('hex')`, md5) is rejected in every relations operation — that id is
indistinguishable from a dashless uuid, and accepting it would reopen the alias; object and subject ids are **not**
rejected (compared byte for byte, a case pins both directions), because a 32-hex object id may be a legitimate non-uuid id
and no engine folds it into a partition. **The recipe is fail-closed by default (🟠 A1 of the audit, owner's decision
2026-10-15)**: the first version re-keyed every non-canonical row to the canonical spelling and merged twins keeping the
*longer* expiry — and a row written dashless was precisely a grant the canonical purge had never seen, so the recipe
resurrected an offboarded user's share (`purgeSubject` by the canonical spelling ⇒ `check = false` ⇒ recipe ⇒ `true`;
pinned by the audit's repro and now by the inverted case on the three engines). **The recipe has three branches and the
default one writes nothing (🟡 R3 of the re-audit of the closure, owner's decision 2026-10-15 (2))**: the default is
the detector, the list and two counts (rows *with* a canonical twin / rows *without* one; pinned as zero writes on the
three engines) — the detector uses the same rule as `assertPartition` (pinned: what the API rejects, the detector
lists); **`--delete`** is the fail-closed branch for *population A* (uuids written with a non-canonical spelling: aliases
the canonical purge never saw); **`--rekey`** is the branch for *population B* (tenant ids that were never uuids — 32 hex
by construction, `randomBytes(16).toString('hex')`, md5 — whose signature is "the detector lists every partition"): it
keeps every relation under the `8-4-4-4-12` spelling of the same 32 hex (pinned: a population-B store keeps all its
tuples, userset included, and answers `check` by the dashed id; `dashedUuid` is exported), and a non-canonical row whose
canonical twin exists is dropped with the twin left untouched (an expiry is never extended, `NULL` does not win). The
closure's first version made the DELETE the default, which **emptied `authz_relations` for population B** while the README
implied non-uuid ids were safe; now no branch writes without its explicit statements and the README names both populations
and which branch is theirs. Both writing branches idempotent; with `--rekey` the audit's scenario grants again *as
reviewed*. The `--rekey` collision note now says which alias to delete by hand (keep the row with the nearest expiry;
`NULL` is the farthest — ⚪ R4). On `openfga` the same three branches with the SDK: list (`read({})`), `--delete`
(`write({ deletes })`), and the `--rekey` equivalent is `authz:relations:reconcile --from=database` on the canonical
partition plus the SDK delete (write before delete), executed against a real server.

**🔴 BREAKING for third-party harnesses — D13 second half**: `runRelationsDriverContract` now calls the harness **driver
directly** (no manager) and demands the same F-05 422s on the nine operations (`relate`/`unrelate`/`check`/`checkMany`/
`listObjects`/`listSubjects`/`purgeObject`/`purgeSubject`, and **`membersOf` when the driver declares `membersOfNative`** —
the audit found the list one short, 🟡 A7: a native `membersOf` without F-05 enumerates the assignees of a role binding in
the shared store), after lot 0 made the published double enforce it; `checkMany` called directly must also refuse 51 objects
and `[]` (⚪ A12). A harness that seeded undeclared types through its driver breaks on purpose; the two package drivers
already did this. `EXPECTED_CASES` 22 → 28 (+5 `checkMany`, +1 D13; the count is per face, H9).

**F-R1 / F-R2 / F-R3 (lineage L8, letter ≠ effect; found by the cutover runbook of lot R, owner's decision 2026-10-14 (3)):**
- **F-R1** `authz:reconcile --to=openfga --prune` in the **maintenance** pass (the origin is the store itself) deleted the
  facts of a scope that no longer resolves and *also* counted them in `skipped.unknown-scope` ⇒ "something this pass
  cannot fix alone", exit 1, on a pass that had fixed it. *Decision*: the bucket classifies the REAL state — with `prune`
  and `ReconcileFactsOrigin.self` those facts go to **`report.pruned[reason]`** (new, optional) and to `deleted`, never to
  `skipped`; the command prints them as "BORRADOS por --prune" (dry-run: "se BORRARÍAN", still drift because there is
  something to prune); without `prune`, or with another origin, `skipped` + the recipe as before. Truth table prune ×
  dryRun on a real server; the `cutover-runbook` job is green again (the finding stays as an assertion).
- **F-R2** `--allow-mass-delete` lifted the safeguard and the pass deleted, but the letter still said "would delete … in a
  real pass it is 500" with exit 1 (relations) — and the roles twin said "before using --allow-mass-delete" of a pass that
  had used it. Both reports now carry `allowMassDelete`; with it lifted the real pass says "se LEVANTÓ … se han borrado N"
  (warning, clean, exit 0) and a dry-run says the real pass WILL delete (drift). Truth tables massDelete × allowMassDelete ×
  dryRun in both commands.
- **F-R3** `authz:reconcile` surfaced a live freeze of another pass (423 `E_AUTHZ_FREEZE_HELD`) as a raw error while its
  relations twin printed the letter with exit 1. Both commands now treat 423 and the mass-delete 500 the same way: letter
  (holder, fence, how to lift it) and exit 1.

**Re-audit of cierre-2 (2026-10-15; `.claude/contexto/loteA-auditor-cierre2.md`, 0 🔴/🟠, 1 🟡 widened, 2 ⚪ — closed in this alpha, cierre-3; owner's decision 2026-10-15 (3)):**
- 🟡 C2-1/C2-2/C2-3 **the roles fan-out was wider than what PostgreSQL folds, and could reach a live scope of
  another tenant.** Cierre-2 made `scopeSpellings` use the partition rule `isNonCanonicalUuid`, which is a
  *superset* of what PostgreSQL's `uuid` folds: `-<32hex>`, `<32hex>-`, `a0e-ebc99…` (hyphen after three) and
  `8--24` are legal ids of the grammar that PostgreSQL rejects with "invalid input syntax" (measured against
  PostgreSQL 18; the docblock claimed "ALL the forms PG folds" and was false). On a consumer whose scope ids are
  *text* chosen by the tenant, a purge **without a chain** — `scopes.detached` without `within` on a row already
  gone, `revoke`/`removeDeny` on a scope the tree no longer knows — added the canonical form, which there *is* the
  live unit of another tenant: on `database`, `purgeScope` dropped its `authz_denies` while the inheritance from the
  org stayed (**fail-open cross-tenant**); on `facts` it dropped its `parent` edge (fail-closed DoS). The class
  pre-existed since 3b-2h with the dashless alias; cierre-2 widened it. Two decisions: **(1) two rules, one per
  purpose** — `pgFusedSpellings(uuid)` (new, exported) is *exactly* what PostgreSQL folds (hyphens only after groups
  of four hex digits: dashless, `8-4-4-16`, `8-8-8-8`, `12-4-4-12`, `8-24`; not the leading/trailing/odd/double
  hyphen forms) and is the rule of the roles fan-out, while the wide `isNonCanonicalUuid` stays **only** for the 422
  of relation partitions (a 422 too many is harmless and the caller sees it; a purge too many is not); truth table
  with both columns pinned in `relations_database.spec` (A2/C2-1) and the four non-folding forms pinned as *one*
  purge in `scope_outbox.spec` (R1/C2-1). **(2) structural**: the no-chain fan-out has a single point of passage,
  `canonicalScopeTargets` (`backend_guard.ts`; the manager's `detached` now goes through it too), and it **discards
  every spelling the resolver recognises as a live scope other than the one asked for** — a live scope that is not
  the one asked for is never purged; if the resolver throws while checking, the write is 503 `E_AUTHZ_RESOLVER_FAILED`
  and the driver is not called (never "purge just in case"); without a resolver only the root exists and the fan-out
  is whole. Pinned with the spy manager (live victim, dashless/`8-4-4-16`/`a0e-`; resolver failure ⇒ 503 and zero
  calls) and **against both real drivers**: the live victim keeps its deny (inherits the org grant and still does
  *not* grant), its own facts and — on `facts` — its `parent` edge, after `revoke`/`removeDeny`/`detached` by the
  alias. A mutant back to the wide rule turns the truth table and the non-folding rows red; a mutant without the
  liveness check turns the live-victim cases red on both drivers. "Removing never grants" (the old
  `canonicalScopeTargets` docblock) was false twice — removing a deny grants, and `purgeScope` on `database` deletes
  denies — and is rewritten.
- ⚪ C2-4 **forms PostgreSQL folds but longer than 36 chars** (`4×8`, 39 chars, the literal example of the PG docs)
  are rejected by `assertScope` (`IDENTITY_LIMITS.uuid = 36`) with a visible 422 before any fan-out — documented in
  `pgFusedSpellings`; no code change (noisy, not silent).
- ⚪ R2 **the dry-run line no longer suggests the real pass will fix an `invalid-identity` tuple**: with the package's
  drivers (`database`/`openfga`) the real `--prune` will *not* delete it (R-16 in `unrelate`) and exits 1 until it is
  deleted by hand; the dry-run now says so ("bórrala ya, no esperes a la pasada real"), pinned by letter.

**Re-audit of the closure (2026-10-15; `.claude/contexto/loteA-auditor-cierre.md`, 1 🟠, 1 🟡, 2 ⚪ — closed in this alpha, cierre-2):**
- 🟠 R1 **the roles twin of A2**: the closure said "roles: not affected — the resolver chain canonicalises (invariant
  17)", which is false exactly where there is *no* chain. `scopeSpellings` — the fan-out of `scopes.detached` after the
  consumer's row is gone and of `revoke`/`removeDeny` on a scope the tree no longer knows (`canonicalScopeTargets`) —
  only added the canonical form for the *dashless* alias (3b-2h · 🟠 3). With `8-4-4-16` (PostgreSQL folds it into the
  same `uuid`, measured in A2) the purge proved zero on a key with no facts and the real scope kept `parent` and
  `binding`: on `facts` it **granted forever**; on `database` the facts came back if the row was restored (invariant
  11, "nothing resurrects"). Now `scopeSpellings` uses the **same rule as partitions**, `isNonCanonicalUuid` (every dash
  placement that folds, not only the dashless form): pinned in the `detached` composition for the four forms (and a
  legal 32-char non-hex id stays one purge), through the outbox, in `revoke`/`removeDeny` on both drivers, and **against
  a real store: the scope stops granting** (`scope_outbox.spec` 3b-2h, `openfga_facts.spec` A4). A mutant back to
  "dashless only" turns those cases red, in memory and against OpenFGA.
- 🟡 R3: above, in D4 (three branches; the default writes nothing; both populations named).
- ⚪ R2 **a backend's garbage was sold as the caller's 422**: `relationTupleKey` validates every component (⚪ A9) and
  `reconcileRelations` applied it to the tuples it had *enumerated*, so one hand-written tuple outside the grammar
  (`document:<key>|ABC` through the SDK, a row with an upper-case `object_uuid`) made the whole partition's
  `authz:relations:reconcile` a 422 `E_AUTHZ_INVALID_IDENTITY`, `--dry-run --prune` included — invariant 5 says a 422 is
  the caller's malformed *question*, and nobody could sweep the tuple. Now the planner **classifies and lists** it
  (`report.details`, new optional field `RelationsReconcileDetail`: side, reason `invalid-identity`, the tuple, the
  grammar's message): on the destination it is `extra` with its reason, `--prune` asks the driver to delete it *as
  enumerated* and, if the driver refuses it through the port (R-16 in `unrelate`: both package drivers do, the in-memory
  double does not), the report says `pruned: false` and the command prints "NO se pudo borrar … bórrala a mano" with exit
  1 — never a throw; on the source it is `skipped.invalid` (the API cannot write it) and drift. One line per tuple in
  `relationsReconcileLines`, with the side, the reason and why; the dry-run says what the real pass will *ask* for. Pinned
  with a hand-inserted row on `database`, with the double (deleted) and on the source.
- ⚪ R4: the `--rekey` collision note names the alias to drop (above); the closure report's mutant count (43/42) corrected.

**Audit closure of lot A (2026-10-15; `.claude/contexto/loteA-auditor.md`, 2 🟠, 5 🟡, 5 ⚪ — all closed in this alpha):**
- 🟠 A1 / 🟠 A2 / 🟡 A6: above, in D4.
- 🟡 A3 **holes in a third-party answer**: `checkMany` (relations) and `authorizeMany` (roles, its twin) validated the driver's
  `boolean[]` with `Array#some`, which skips the holes of a sparse array — `new Array(n)` filled by correlation with one
  result missing had the right length and zero booleans, and the consumer got `undefined` where the port promises `boolean`
  (`if (out[i] === false) deny` let it through). Both now check **every position by index**: a hole is 500 `E_AUTHZ_INTERNAL`
  naming the position; a mutant back to `some` turns a case red in each manager.
- 🟡 A4 **what `--prune` deletes is listed again**: the F-R1 bucket (`report.pruned`) had taken the pruned facts out of
  `details`, so a half-blind resolver (null for the scopes of *one* tenant) pruned that tenant's assignments **and denies** with
  exit 0 and no list, in `--dry-run` too. `discard` now lists each fact with its `kind` and `pruned: true`
  (`ReconcileSkip.pruned`, optional); `authz:reconcile` prints "se BORRARÍA con --prune (reason) deny: …" in a dry-run and
  "BORRADO por --prune …" in the real pass, as `log`, never as "sin migrar".
- 🟡 A5 / ⚪ A11: above, in `createTestClock`.
- 🟡 A7 / ⚪ A12: above, in D13; `RelationsReconcileReport.allowMassDelete` is optional in the exported type (A12).
- ⚪ A8 **MySQL recursion hint**: in `checkMany` the `SET_VAR(cte_max_recursion_depth)` hint went *after* `DISTINCT` and the
  optimizer ignored it — with more than 1000 nested groups `check` answered and `checkMany` was `ERROR 3636` (503). Moved
  before `DISTINCT`, as in `listObjects`; a MySQL-only case with 1 002 nested groups pins `checkMany ≡ check`.
- ⚪ A9: above, in `relationTupleKey`.
- ⚪ A10 **one rule for "a per-item `error` is 503"**: `alignBatchResults` (exported from `/openfga`) is correlation by id plus
  that rule; both openfga drivers use it. A missing, duplicated or foreign result stays 500 `E_AUTHZ_INTERNAL` — it is not the
  backend down, it is an answer that does not match the request.

**Rule written down (D15, `CLAUDE.md`)**: from 2.5.0 every new key of `AuthorizationDriverCapabilities` /
`RelationsDriverCapabilities` is optional (`?:`), normalises to `false` and lands with its pair of faces — a mandatory key
would be a major for third-party drivers.

Verified: `npm test` / `test:sqlite-file` / `test:pg` / `test:mysql` against a real OpenFGA, `check:guard-mutants`
(103 mutants dead), `check:flag-mutants` (36/36) and `cutover-runbook` (pg + sqlite-file) green — see `loteA-informe.md`.

### Lot R — release-gate infrastructure (no runtime change)

`scripts/check_flag_mutants.mjs` makes every booted flag of every command inert in turn and requires an effect test to go red (36/36; on the previous HEAD, 9 flags had no effect test at all — cases R-1…R-8 added). `scripts/cutover_runbook.mjs` + `tests/cutover_runbook.spec.ts` execute the README cutover runbook step by step through the ace kernel (database → openfga → database in separate processes, with the aborted / expired / repeated states) against pg and sqlite-file with a real OpenFGA; a README `node ace …` line without an executable step turns the job red. Both run as CI jobs (`flag-mutants`, `cutover-runbook`). See `loteR-informe.md`.

### Lot 0 — surface guard for F-05 (reflection-based manifest, mutant runner)

No runtime change for consumers except one: **the in-memory double `makeRelationsDriver` (`/testing`) now applies
F-05 itself** — `relate`/`unrelate`/`check`/`listObjects`/`listSubjects`/`membersOf`/`purgeObject`/`purgeSubject` and
userset subjects reject an undeclared object type (422 `E_AUTHZ_RELATION_TYPE_UNKNOWN`) or relation (422
`E_AUTHZ_RELATION_UNKNOWN`) with the same two functions as the real drivers. Until now only the `RelationsManager`
cut, so a third-party driver modelled on the double could skip the check and still pass the contract (tester H8,
owner's decision D13). A harness that seeded undeclared tuples straight into the double breaks on purpose.

Why: F-05 («nobody touches `role_binding`/`scope`/`role` as a domain relation») had been closed five times, each time
on «the next operation» (`linajes.md` L1). The fix is structural: a **surface guard** (`tests/guard_surface.spec.ts`)
enumerates by reflection every public operation of the manager, both drivers, their `withClock` views, the double and
the package `exports`, and demands a row per operation in a manifest (F-05 / `{ transaction }` gate / freeze barrier /
`#write` / actor / canonical partition). A new method without a row is red; every probed cell has a mutant that kills
it (`scripts/check_guard_mutants.mjs`, 94 mutants over 105 probed cells, all dead in `:memory:` and `sqlite-file`); the only
exemptions are the five signed by the owner (D6), carried in a versioned extract (`tests/fixtures/exemptions_d6.json`) so the
guard decides the same in CI; `na` cells are admitted only by a closed layer×column matrix (`f05` never), every public
method — prototype chain, class fields, instance accessors and namespaces, statics, what the container actually serves
(`AuthzProvider.register` → `container.make('authz.relations')`), never a Proxy — is inventoried, and the `#write` column
covers the partial write (invariant 13) besides the deadline (auditor's re-attack, closed in the same lot). The guard cannot
be sidestepped through its own probes either (second re-attack, closed too): each probe runs on a Proxy that demands it
touches the probed operation and only that one, a whitelist probe only stands on the enumerations, `WRITES` is derived
from a mandatory `PORT_WRITES`/`PORT_READS` classification cross-checked with what the drivers actually execute (an
unclassified operation is red by name), and the one declared limit is written down: in CI and in worktrees there is no
decisions file, so the signature of an exemption there is the review of the diff of three versioned files. The hand-written list of «the eight operations» in `relations_database.spec.ts` is
gone. The canonical-partition column asserts today's branch (a 32-hex uuid without dashes is accepted); the 422 and the
canonicalisation recipe come in the next lot (D4).

## [2.4.0-alpha.10] — 2026-09-13

Sixth COGNITIV report (2026-09-13): they installed alpha.9 and **rehearsed the cutover there and back** against it
(`--dry-run` with zero writes, `--prune` respecting their 60 foreign tuples, half a `--partition-*` pair refused), and
came back with five details, one of them measured. Owner's decision 2026-09-13.

**🔴 BREAKING — towards the ACTIVE driver, the only source is the driver itself (both ports, closed structurally).**
With `openfga` serving, `--to=openfga --from=database` read `authz_*` — frozen since the cutover, because nothing
writes there any more — and **re-wrote into the live store every role revoked after the cutover**, with or without
`--prune` (and with it, deleted what was granted since). The mass-deletion safeguard stays silent: the source is not
empty, it is *stale*. It is the fourth defect of the same lineage: 3b-5 closed the default pass, the first fix drafted
for this release closed `--from`, and a system audit of alpha.9 found the two that were still open — with `database`
active, `--to=database` **without** `--from` picks `openfga` by elimination (the same stale direction, no flag to give it
away), and `authz:relations:reconcile --to=<active>` does it for relations out of the box (resurrects revoked shares
and, with `--prune`, deletes the new ones; published since alpha.1). Owner's rule: the third defect of a lineage is not
patched, it is fixed at the structure. So the guard does not look at the flag, it looks at the **resolved source**:
`manager.reconcile({ to })` with `to === config.default` and any resolved source other than `to` itself — `--from`,
elimination, or the `authz_*` tables — is **500 `E_AUTHZ_STALE_SOURCE_REFUSED`** before resolving the source, reading
anything or freezing the fleet; the maintenance pass (source = `to`) runs, and it is decided by the same predicate
that picks where the facts are read from, not by a copy. The four rows, pinned as a parametrised truth table:
maintenance — runs; initial cutover (`to` ≠ active) — runs; going back **before** switching `default` — runs; re-running
either **after** switching `default` — refused. `runRelationsReconcile` applies the same rule with the active relations
driver, **`relations.default ?? config.default`** (now one function, `activeRelationsDriverKey`, shared with the
provider); relations have no maintenance pass, so towards the active one no other source runs. The human decision is
`allowStaleSource: true` / `--allow-stale-source` in both commands. **`--dry-run` does not throw** — it flags
`report.staleSource = { to, from, allowed }` with the resolved source, prints a warning and exits ≠ 0. *Why breaking*:
a script that ran that direction on purpose now needs the flag; **`runRelationsReconcile` now takes keys, not
drivers** (see the closing lot below); and **`runMigrationContract` (`/testing`) passes `allowStaleSource: true` on both legs** — with one
manager, one leg always targets `config.default` — so a third-party harness whose `reconcile` builds its own options
instead of forwarding them gets the 500 on that leg (forward the option; measured: without it 4 of the 8
migration-contract cases are red against a real OpenFGA). Two tests of this package were encoding the defect and were
turned around: one migrated with a manager that already served from `openfga`, one treated an expired window as
"there never was one".

**🟠 An expired operator window was overwritten — and erased — by the next pass.** With `authz:freeze --lease-ms`
expired, `authz:reconcile` did not adopt it, took a 15 s freeze of its own, certified itself
(`lapsed: false`, exit 0) and, on release, set the operator's row to NULL — the only trace that writers had resumed
mid-cutover — after which `authz:unfreeze` said "nothing to lift" in green; and the output was identical, letter for
letter, to a pass that did run inside the operator window. Now `freeze()` — and with it both reconciles,
`withFrozenWrites` and `authz:freeze` — refuses to take over an **expired operator** row: **503
`E_AUTHZ_OPERATOR_WINDOW_EXPIRED`** naming when it expired; acknowledge it with `authz:unfreeze`, reopen with
`authz:freeze`. (A window lifted *early* by the operator leaves no row to detect — lifting is explicit and clears the
reason — so that variant is covered only by the output line below, not by the refusal.) An expired freeze of a *pass* is still taken over (that is the lease after a `SIGKILL`). And both
commands always say which window the pass ran in (`report.frozen.window = 'operator' | 'own' | 'enclosing'`): "inside
the operator window (fence N)" or "took its OWN window: there was no live operator window".

**🟠 The cutover runbook forgot `relations/`.** Relations switch driver with `config.default` unless `relations.default`
is set (which the README never mentioned): following the runbook left ReBAC with zero tuples — every `check` false —
while `authz:reconcile --dry-run` came out clean. The runbook now runs `authz:relations:reconcile` per partition inside
the window and documents `relations.default ?? config.default`.

**🟠 `authz:reconcile` said the maintenance pass "writes and deletes no fact at all", and with `--prune` it deletes
them** (measured by COGNITIV: that sentence, followed by `sobran 3, borradas 3`). The behaviour is the intended one —
the sentence was false. Now, command and README: the maintenance pass **writes no fact; with `--prune` it deletes the
facts of scopes that no longer resolve**, the expired ones, those of roles or permissions the catalog or the model no
longer has, and the leftovers (without `--prune` it deletes no assignment or deny — only the role-visibility edges
invariant 18 forbids — and reports them). Fixed with a letter case and an effect case against the real store
(maintenance `--prune` over a binding of a vanished organization: 3 extra, 3 deleted, the output no longer says
otherwise).

**🟠 `authz:unfreeze` reported success when the window had already EXPIRED.** `freezeStatus()` drops an expired row, so
`--lease-ms` expiring mid-cutover was indistinguishable from "there was never a window": the last step of a cutover
did not reveal that writes had resumed halfway — writes the new engine never saw. The row does tell them apart
(`releaseFreeze` clears the reason; an expired window keeps it with `untilMs` in the past), so there is a new
`manager.lastFreezeStatus()` (`freezeStatus()` is unchanged) and `authz:unfreeze` now prints an ERROR with when the
window expired (ISO), for how long the fleet was writing and what that means, **exits ≠ 0**, and clears the row, so a
second `authz:unfreeze` is a plain success. "There never was one / already lifted" is still success.

**🟡 An adopted operator window is reported with its expiry.** A pass running inside `authz:freeze --lease-ms` reported
`frozen.leaseMs: null` — "no expiry" — although the row had one (certification was right: `lapsed` reads the row).
`report.frozen` now carries `untilMs` for the adopted operator window and `leaseMs` is what the window had left when the
pass adopted it (`null` only when it does not expire); both reconcile commands say when it expires.

**🟡 `authz:relations:reconcile --partition-type=app --partition-uuid=<x>`** is a complete pair that silently
reconciled the root and dropped the uuid — the variant alpha.9's closing lot did not catch. Now exit ≠ 0: "the root
partition takes no uuid"; and its twin in the API, `reconcileRelations({ partition: { type: 'app', uuid: 'x' } })`, is
500 `E_AUTHZ_CONFIG`.

**🟡 `authz:scopes:relay` said things that were not true in mixed states** (system audit): `--dry-run` exited 0 with a
PARKED entry as long as there was also a pending one (README: "exits non-zero while any exists") — now ≠ 0; `--only=<id>`
with that entry deferred, or with a mistyped id, printed "the tree outbox is empty: nothing to propagate" in green —
now it names each requested id that did not land and a deferred one exits ≠ 0; and `--max-age=-1`/`1.5` was validated
*after* relaying (the pass applied entries, then the command died with a `TypeError` without saying what it applied) —
now it is rejected before touching the queue. Plus effect cases through the kernel for two flags that no case would
catch inert: `authz:relations:reconcile --dry-run` (zero writes) and `authz:reconcile --prune` (the leftover fact is
deleted, and without the flag it is not).

**Closing lot (audit of alpha.10: "fit, with changes").**

**🟠 BREAKING — `reconcileRelations` is no longer exported from the package root; `runRelationsReconcile` is the one
public way, and it takes keys.** The audit found the relations twin of the stale-direction guard one door short: the
README recommended the primitive `reconcileRelations({ partitions })` "from code" for K partitions, and that primitive
never saw the active driver nor took the durable window — a multi-tenant loop written after the cutover resurrected
revoked shares and, with `prune`, deleted the new ones, with the fleet still writing. It is the third iteration of
the same lineage, so it is not patched at the call site: the primitive cannot know the active driver (it lives in
`src/relations/`, which may not import the manager — purity rule 2) and a required "active driver" option would be
one more label for the caller to get wrong, so it leaves the root and every exported way of reconciling relations
goes through `runRelationsReconcile` (`@jantstack/adonis-authz/commands/authz_relations_reconcile`), where the guard
and the window live. A surface guard walks every subpath of `exports` and fails if any of them hands out the
primitive. **And the guard now judges the resolved driver, not labels**: until this lot the function received the
driver instances *and*, separately, `toKey`/`fromKey`/`activeKey`, and compared the strings — a loop with
`fromKey === toKey` copy-pasted, or an `activeKey` contradicting the manager, wrote the retired share into the active
driver. Now: `runRelationsReconcile(authorization, { toKey, fromKey, partition | partitions, dryRun?, prune?,
allowMassDelete?, allowStaleSource?, toConfig?, now? })` resolves both drivers **from the manager's own
`relations.drivers`** (new `manager.relationsDriverKeys()` / `relationsDriverFactory(key)`), two keys with the same
factory are the same driver (an alias of the active one is refused; source = destination is 500 `E_AUTHZ_CONFIG`),
the active driver is always `manager.relationsDriverKey()`, and passing `from`/`to` instances or `activeKey` is 500
`E_AUTHZ_CONFIG` instead of being silently ignored. Nothing is constructed before the guard. `authz:relations:reconcile`
resolves its keys through the service manager too (one config, not two). The roles twin had the same label
comparison — `drivers: { openfga: f, fga: f }` with `default: 'openfga'` let `--to=fga --from=database` through — and
now judges the resolved factory as well (guard, maintenance pass, `from === to` and pick-by-elimination). *Migrating*: replace
`reconcileRelations({ from, to, partitions })` and `runRelationsReconcile(authorization, { from, to, toKey, fromKey,
activeKey })` with `runRelationsReconcile(authorization, { toKey, fromKey, partitions })`.

**🟡 The expired-operator check was outside the atomic take.** `freeze()` read the row, checked "is this an expired
operator window?", and then ran the conditional `UPDATE` with a second clock reading: a window expiring between the
two was taken over with no 503 and its trace erased on release (deterministic with a two-reading clock). The
exclusion now lives **inside the `WHERE` of the same `UPDATE`** on PostgreSQL, MySQL and SQLite; the row is re-read
only to word the error.

**🟡 `authz:scopes:relay --dry-run --only=<id>`** still said "the tree outbox is empty" in green for a mistyped id —
the dry-run branch returned before the S6 block. It now names every requested id that is neither pending nor parked,
with the same per-id line as the applying pass and a summary line of its own (`--dry-run: none of the requested ids
is pending`); "empty" is printed only without `--only`. A missing id is still not exit 1 (same decision as S6).

**🟡 Declared limit: the stale-direction guard reads the config of the process that runs it.** "Active" is
`config.default` (roles) / `relations.default ?? config.default` (relations) **of the process running the pass**: a
migration job or pod started with a different environment believes another driver is active and the guard is off.
Run it with the fleet's config. A durable seal of the active driver is on the 2.5 list.

**The cutover runbook verifies before the switch.** There is deliberately no exception for `--from=<old>` towards the
active driver inside a live operator window: a check that is green only in that narrow moment teaches operators to
reach for `--allow-stale-source`. So the README's runbook now runs the `--dry-run` verifiers (roles and relations,
with `--from`) **before** switching `config.default`, and after the switch only the maintenance verifier
(`authz:reconcile --to=openfga --dry-run`, no `--from`). The recipe "the way out of a store written by the previous
version" (`--to=openfga --from=database --prune`) now says to run it while `database` is still the default, and
names the refusal and `--allow-stale-source`.

**Hygiene.** `authz:unfreeze` under a race: the expired branch said "the row is clean" without looking at whether
its conditional `UPDATE` matched, and the lift branch said "someone lifted it or its lease expired" in green (expiry
never makes that `UPDATE` fail); both now re-read the row and say what actually happened — lifted by someone else
(success), or the row changed hands (error naming the new holder, exit 1). A row with a reason and **no holder**
(legacy or written by hand) is published as holder `'?'` and could never be matched, so `authz:unfreeze` repeated its
expired warning forever; `'?'` is now that row's token (`freeze()` never writes it). With a single registered driver,
`authz:reconcile --to=<active>` without `--from` is still refused, but no longer talks about a source "picked by
elimination" that does not exist. The docblock of `E_AUTHZ_STALE_SOURCE_REFUSED` sat above another class (guarded
now). The "or lifted early" wording above overstated what the refusal covers.

**Second closing lot (re-attack of the closing lot: no 🔴/🟠, two 🟡 and five ⚪).**

**🟡 `authz:scopes:relay --only=a,b --limit=1` said "#b was neither pending nor parked: already applied, or it does
not exist" with `b` PENDING** — in `--dry-run` (a line the closing lot had copied from the applying pass) and in the
applying pass, which also exited 0 with `1 change propagated`. `missing` took every requested id that fell outside
the batch. Now `ScopeRelayReport` has an additive field, **`notEvaluated`**: requested ids that are still pending and
the pass never looked at because it reached `limit`; `missing` keeps only the ids that are not in the queue at all.
Telling them apart is one read of the queue filtered by the unseen ids, and only when there are some. The command
names each one ("is PENDING and this pass did NOT evaluate it", with the branch and the `--limit`) and exits ≠ 0 in
both modes; a case walks the truth table (state of the id × inside/outside `--limit` × `--dry-run`) with the real
manager and the SQL outbox. Its twin, the same false line for a **parked** id beyond the first `batchSize` of
`dead`, is fixed too (the requested parked entries come from the full census). *Migrating*: a `deepEqual` on a whole
relay report, or a hand-built `ScopeRelayReport`, needs the new field.

**🟡 Declared limit: the stale-direction guard compares factory REFERENCES, not backends.** The closing lot's "an alias
of the active one is refused" only holds for an alias registered with the **same** factory reference. Two different
factories that build the same backend — `openfga: () => new OpenFga…(…)` and `fga: () => new OpenFga…(…)` with the same
store id, the natural way to write an alias — are not detected, in either port: `--to=fga --from=database` passes and
resurrects what was revoked. Nothing is built before the guard, so there is nothing to compare. Declared in the README
(both ports), in the docblocks and here; a backend identity declared by the driver is on the 2.5 list, next to the
durable seal of the active driver.

**⚪ One rule for the `operator:` prefix, in SQL and in JS, on the three engines.** The atomic take excluded expired
operator windows with `NOT LIKE 'operator:%'` (case-insensitive in SQLite and in MySQL's default `_ai_ci`, which is
also accent-insensitive; case-sensitive in PostgreSQL) while `freezeKindOf` split on `:` in JS. An expired row with a
hand-written holder `OPERATOR:1:ab` was "operator" for the `UPDATE` and `unknown` for JS, so after the retry `freeze()`
threw 423 "a LIVE freeze of another owner" over an expired row, and PostgreSQL answered differently. Now
`isOperatorHolder` (internal, `src/freeze.ts`) — the first nine characters are exactly `operator:` — is the rule in
JS and, per engine, in the `WHERE` (`substr` in SQLite, `COLLATE "C"` in PostgreSQL, a `BINARY` comparison in MySQL),
with no `LIKE`; a case walks twelve holders on each engine. The retry that still finds a non-live row (only a row
changing twice between `UPDATE` and re-read) is now a retryable 503 that says so, never "LIVE".

**⚪ A hand-written holder `'?'` left `authz:unfreeze` in a loop.** `'?'` is how a row with no holder is published, and
also a literal holder; the token matched only `NULL`. It now matches `holder IS NULL OR holder = '?'` (still bound to
the fence, never a real holder). And when the conditional `UPDATE` does not match but the re-read row is the same
(holder, fence, reason), `authz:unfreeze` no longer says "another process changed it": it says the row did NOT change
and that it is a package defect.

**⚪ Hygiene.** The exports surface guard walks nested objects and a function's own properties, and a second guard by
source fails if any publishable module other than `commands/authz_relations_reconcile.ts` and the declared `/testing`
harness imports the primitive's module — its declared scope: it catches a re-export by identity at any depth and a new
importer; a `.bind` or a wrapper inside one of those two files is not detected. `relationsDriverFactory(key)` and
`relationsDriverKeys()` are now named in the README next to `driver()` as platform API, with the structural
`Pick<AuthorizationManager, …>` of `runRelationsReconcile` (a faked manager decides the active driver). The TOCTOU case
of `freeze()` pins one branch per deterministic clock (423 at T−1, 503 at T+1) instead of accepting either.
**`RelationsReconcileOptions` is no longer exported from the root** (type only): it described the primitive's options,
with `from`/`to` instances required, and invited `as any`; the public options are **`RunRelationsReconcileOptions`**,
exported next to the function from `./commands/authz_relations_reconcile`. The README's list of the `/openfga` subpath
no longer names `importAuthzFactsToOpenFga` and `openFgaAuthorizationModel` (deleted in 2.3).

**Minor breaking changes of this release, by name.** `unfreezePlan` (exported from `./commands/authz_unfreeze`)
gained `'expired'` in its action union and a third parameter `nowMs`; `report.frozen` gained `window` (both ports)
and `untilMs` (adopted operator window) — a `deepEqual` on `report.frozen` breaks (this package had to touch its own
case); `freeze()`/`withFrozenWrites()` can throw a new 503 `E_AUTHZ_OPERATOR_WINDOW_EXPIRED` besides the 423;
`reconcileRelations` left the root and `runRelationsReconcile` changed its options (above); second closing lot:
`ScopeRelayReport.notEvaluated` (new required field; ids that moved out of `missing`), the root no longer exports the
type `RelationsReconcileOptions` (use `RunRelationsReconcileOptions`), and a hand-written expired holder in capitals
(`OPERATOR:…`) is now taken over like any expired pass instead of answering 423; a hand-written holder without `:` (`operator`, `reconcile`, `platform`) is now kind `unknown`, so `authz:unfreeze` without `--fence` refuses to lift that row instead of lifting it; the double race between the take-over UPDATE and its re-read (the row changing twice in under a millisecond) now answers a retryable 503 instead of 423 `E_AUTHZ_FREEZE_HELD` — code that branches on `code` sees a different one; and `freeze()` on a dialect other than PostgreSQL, MySQL 8 or SQLite now throws 500 `E_AUTHZ_UNSUPPORTED_DIALECT` before touching the row (it used to fail inside the engine as a retryable 503).

**What this release does NOT do.** It does not add `--prune-undeclared` (2.5); `authz:scopes:relay --dry-run` is still
503 during a freeze, and the relations verifier still only sees model drift for a persisted config (both next lot).

## [2.4.0-alpha.9] — 2026-09-11

**Closing lot (audit of alpha.9).** Half a pair of flags is no longer silence: `authz:relations:reconcile --partition-uuid` without `--partition-type` (and the other way round) now exits ≠ 0 instead of reconciling the ROOT partition, writing zero and printing `[success]` — the same shape as the bug this release fixes, surviving a typo in a cutover runbook. The published model is now pinned against the allowlist (every object type `openFgaFactsModel` publishes must be governed by the facts reconcile, and every type the generator fuses for relations must not be), and the README's way out for the declared residue carries its two traps: the pass refuses with `E_AUTHZ_MASS_RECONCILE_REFUSED` when the source holds none of those tuples, and the flag that lifts it empties the live relations of whichever partition you point at.

**Every multi-word flag of the ace commands was INERT, and two of them were destructive (lot A; fourth and fifth
COGNITIV reports, 2026-09-11; owner's decision 2026-09-11).** `authz:reconcile --dry-run` **wrote** — 463 tuples into
an empty store — and came out through the SUCCESS branch: the verifier that this CHANGELOG published as *read-only by
contract* was not read-only, and a CI job that "verified" a destination was writing to it. `authz:relations:reconcile
--partition-type/--partition-uuid` were inert too, so every pass swept `{app, null}`: it **migrated zero tuples and
reported success**, which is the worst possible answer for a tenant migration. `authz:scopes:relay --dry-run` applied
the pending tree changes; `--max-age` never fired, so the queue-age alarm this package added in alpha.8 could not be
armed from the command line at all; `--batch-size`, `--wait-lease-ms`, `--lease-ms` and `--fail-on-shadows` were
ignored in silence; `--allow-mass-delete` and `--allow-mass-purge` failed to the safe side (the safeguard could not be
lifted).

**If you have run `authz:reconcile --dry-run` (or `authz:relations:reconcile --dry-run`) against a destination with
2.4.0-alpha.4 … alpha.8, go and look at that destination**: the pass wrote, and the output said it had not.

**The cause** is one line of `@adonisjs/ace` and it is not a bug of ace: `Command.defineFlag(name, options)` builds the
flag as `{ name, flagName: string.dashCase(name), required: false, ...options }` and hydrates the instance with
`Object.defineProperty(this, flag.name, { value: this.parsed.flags[flag.flagName] })`. Passing **`name: 'dry-run'` in
the OPTIONS overrides the name of the PROPERTY**: the parsed value lands on `this['dry-run']` and the typed
`this.dryRun` stays `undefined`, so `dryRun: this.dryRun === true` is always `false`. The option that renames the flag
on the command line is **`flagName`** — and without either of them `dashCase(property)` already produces `--dry-run`.

**The decision: `name:` is never passed in the options of a `@flags.*` of this package, and a static guard says so.**
The 18 declarations that carried it lost it (16 multi-word ones, which were the inert ones, plus `only` and `id`, which
worked by coincidence because `dashCase('only') === 'only'` — the same trap waiting for someone to rename the
property). **Not one public flag name changes**: `dashCase(property)` reproduces all 18 exactly, so every README, every
runbook and every cron line keeps working unchanged — verified declaration by declaration, before and after.

| command | flags that were inert |
|---|---|
| `authz:reconcile` | `--dry-run`, `--allow-mass-delete`, `--batch-size`, `--max-tuples` |
| `authz:relations:reconcile` | `--dry-run`, `--allow-mass-delete`, `--partition-type`, `--partition-uuid` |
| `authz:scopes:relay` | `--dry-run`, `--batch-size`, `--wait-lease-ms`, `--max-age` |
| `authz:scopes:requeue` | `--wait-lease-ms` |
| `authz:freeze` | `--lease-ms` |
| `authz:catalog:diff` | `--fail-on-shadows` |
| `authz:catalog:prune-orphans` | `--allow-mass-purge` |

(`--only` of `authz:scopes:relay` and `--id` of `authz:scopes:requeue` also carried `name:` and also lost it; they
were **not** inert and their behaviour does not change.)

**The blind spot that let it through, closed (`tests/command_flags.spec.ts`).** `commands.spec.ts` has run the ten
commands through a real ace kernel since alpha.4, but **never with a flag**, and the cases that set `cmd.dryRun = true`
by hand — which is what the package had — cannot see any of this; COGNITIV wrote that sentence down and it is now the
rule of the file. Every new case passes the real flag (`exec(['--dry-run'])`, `exec(['--max-age=1'])`) through the
kernel and asserts the **effect**: two pending outbox rows still `applied_at IS NULL` after `--dry-run`; exit ≠ 0 with
`--max-age=1` on an old queue head; zero writes at the destination of `authz:reconcile --dry-run` (and the dry-run
branch of the output, not the success one); the partition that reaches the relations engine being the one that was
asked for and not `{app, null}`; exit 1 of `authz:catalog:diff --fail-on-shadows`; the letter of `authz:freeze
--lease-ms`; and, where the effect is expensive, the **options that reach the manager**, which is the boundary where
the value is consumed — never `cmd.<property>`. Plus the static guard, in two directions: no `@flags.*` in `commands/`
may declare `name:`, and the effective public flag of every declaration must be exactly `dashCase(property)` — checked
both on the source and on the flags ace itself boots, so a new command born with the same mistake is red. Mutants:
putting `name: 'dry-run'` back on the relay kills 3 (its effect case and the two guards); a `flagName: 'seco'` that
does not match its property kills 3.

**What this lot does NOT do.** It does not touch the relations/facts `--prune` defect of the third 🔴 of the fifth
report (`familyOfTuple` has `return 'facts'` as a catch-all, so `authz:reconcile --prune` deletes the RELATION tuples
of a shared store, and `clean` can never be true there): that one collides with a published property, went to its own
panel, and is the lot below. It does not rename, deprecate or add a single flag, does not change any command's output beyond the branches
that the flags were never reaching, and does not touch the ports, the schema or the drivers.

**`authz:reconcile --prune` DELETED every relation tuple of a shared store, and reported `clean = true` with exit 0
(lot B; third 🔴 of the fifth COGNITIV report; panel `shared-store`, owner's decision 2026-09-11 (2)).** With the
`openfga` driver both subsystems of this package — the facts of `authorize` and the tuples of `relations/` — live in
**the same store**, and the facts reconcile has to read it whole (that is the only way to see what is left over).
`familyOfTuple` classified everything it did not recognise as a leftover *fact*, so every relation tuple landed in
`phases.facts.extra` and, with `--prune`, in `deletes`: **60 out of 60 measured** (`document`, `space` and the built-in
`group`, the userset type the model generator always emits — a `viewer` granted to a group evaporates with the rest),
the mass-deletion safeguard silent (the source did have facts), and the pass coming out through `[success]`. Two
aggravations the consumer's report did not name, both measured here: the **destructive** pass reports `clean = true`
because it deletes exactly what was making it dirty, so the operator gets no signal at all; and without `--prune` the
`skipped['extra-fact']` never empties, which means **`clean = false` for ever** on any deployment with relations — the
green CI verifier this CHANGELOG promises did not exist there.

**If you have run `authz:reconcile --prune` against a shared store with any 2.3 … 2.4.0-alpha.8, your relation tuples
are gone and nothing said so**: rebuild them with `authz:relations:reconcile --to=<driver> --from=<driver>` (per
partition), which is the documented way to refill that side.

**The decision: what this pass governs is an explicit, FROZEN list of object types, and nothing else is touched.**
`scope`, `role`, `role_binding` and the obsolete `deny_binding` — the deny of the ≤ 2.2 `resolver` mode, which the
current model does not even declare but `enumerateFacts` still **reads and emits** as a deny (so it is ours, even
though it can no longer be written; deleting it is what keeps the published promise that *one pass cleans a store
written by the previous version*). Anything else is **foreign**: never deleted, not even with `--prune`, never drift,
never in `skipped`. Three things that are part of the decision and not implementation detail:

- **The list is not `RESERVED_FACTS_TYPES`.** That set (`identity.ts`) means *nobody may declare this as a relations
  type* and it **includes `group`**; reusing it as the allowlist reproduces the bug for every userset. Two sets, similar
  names, different jobs — and a case fails if anyone swaps them. The rule that goes with it: a new object type of the
  `facts` model enters **both** lists in the same commit.
- **The deletion decision reads nothing at runtime** — not `relations.config`, not the published model, not a table. The
  process that runs a cutover is exactly the one that may not have the relations config wired (that was the consumer's
  case), and a permissive fallback would bring the mass deletion back precisely there.
- **`foreign` is a field of its own in the report** — `{ tuples, types, relations?, unknown? }` — **outside `skipped`**
  (so `clean` can be `true` again on a shared store) and **outside `details`**, whose 200-entry cap would otherwise be
  eaten by other people's tuples and drop the real `extra-fact` lines, which are the ones that grant. **`phases` does
  not grow**: it is a published type and a third-party driver builds it. The command now says out loud that the store
  is shared, with a per-type breakdown, and the destructive pass states what it respected instead of being silently
  green. When `relations.config` is wired, the manager passes the declared types (`ReconcileSource.relationTypes`) and
  `foreign` splits into `relations` and `unknown` — **for the report only**.

**What this lot does NOT do, and why.** It does not filter the `Read` by type: measured against v1.19.0, a read filtered
by object type without a `user` is a 400, and the full dump is a requirement of the algorithm anyway. It does not touch
`relations/`: the symmetric defect does not exist — that reconcile has always enumerated by an allowlist of types and
cannot see a fact (measured: 7 of 7 leftovers deleted, facts, tree and catalog untouched) — and it is the pattern
copied here. There is **no `--prune-foreign`**: a mass deletion of another subsystem's data, triggerable from CI, is not
a flag. And the **declared residue** that comes with the fix is written down in the README and on the 2.5 list instead
of being fixed in a hurry: the tuples of a relation type you **remove or rename** in `relations.config` are now swept by
nobody (`enumerateRelations` filters them out, `unrelate`/`purgeObject` are 422 by F-05) and **grant again if the type
is ever re-declared**; today the way out is to declare the type and run `authz:relations:reconcile --prune`.

Measured cost of the fix: `--prune` deletes 0 foreign tuples, the store stays byte for byte the same, `clean = true`,
and it is **faster**, not slower (fewer diff entries and zero `deleteTuples`). The published property is kept whole in
the same store: a 2.2 `deny_binding` and a 1.x `role_binding` id are **still deleted** by `--prune` while the foreign
tuples survive, which is the case that decides this lot.

## [2.4.0-alpha.8] — 2026-09-10

**Closing lot (audit of alpha.8, three 🟡).** `waitForLeaseMs` is capped (`RELAY_WAIT_LEASE_MAX_MS`, 60 s ⇒ 500 above) and counted in polls, so it terminates under a frozen injected clock (it did not); `authz:scopes:relay --max-age` is loud when entries are pending but the outbox does not report `createdAt` (warning without a threshold, error and exit ≠ 0 with one — before, silence); and `E_AUTHZ_SCOPE_DEPTH_LIMIT.details` is non-enumerable, so `JSON.stringify(error)` no longer names the backend or the server knob (the message was clean, the serialization was not). · the root `app` is not a scope key, a parked entry plugs only its child, `requeue --apply` closes the incident in one call, the relay can wait for the lease, the report says how old the queue is, and the `enumerateRelationsMany` fallback no longer loses tuples

Answers the third COGNITIV report (2026-09-10; panel relay 2: `panel-relay2-{analista,auditor,tester,juez}.md`,
owner's decisions 2026-09-10 (4)). Additive; no schema change; no port method removed or changed in signature
(`PendingScopeTreeChange.createdAt?` is a new *optional* field); `EXPECTED_CASES` of the outbox judge 15 → 17 (one new
core duty, O-07b, and one new capability pair, `createdAt`). Two lots: I (root, variant B, `apply`, `waitForLeaseMs`,
the fallback cursor, X-1) and II (queue age, `requireTransaction`, the minor items).

### Fixed

- **The root `app` was a scope key, and that made it a global mutex of tenant registration (the live problem).**
  The order rule of the relay contaminates by *scope key*: an entry that fails or is parked blocks every later
  `attached`/`moved` that names one of its scopes, and the keys of an `attached`/`moved` were `[child, parent]`. The
  parent of every tenant registration is `app`, so **every registration shared a key with every other one**. Measured
  three ways: (I) one parked `attached(orgA, app)` left the registration of orgB `deferred · parked:` on every pass —
  five cron passes with `applied = []`, exactly what the consumer reported; (II) **with nothing parked at all**, two
  concurrent registrations relayed inline with the documented recipe (`relayScopeChanges({ only })` right after the
  commit) left the second one `deferred · depends-on:` (PostgreSQL, 15 ms): the inline recipe was not usable for
  tenant registration, and under (c2r) that is fail-closed — the new organisation granted nothing until the cron ran;
  (III) `authz:scopes:requeue` of the parked one was refused with `E_AUTHZ_REQUEUE_REFUSED` as soon as another tenant
  had registered — a false conflict whose only shared key was `app` — so the documented way out of the incident pushed
  the operator to `--force`. The decision: **the root is never a key.** It never moves, is never purged and is never a
  child (`scopes.attached(APP_SCOPE, …)`, `scopes.moved(APP_SCOPE, …)`, `scopes.detached(APP_SCOPE)` are 422), so two
  changes whose only shared scope is `app` commute and there is no order to keep — the auditor looked for a pair whose
  order mattered and found none; the analyst measured five pairs (`m2-orden.ts`) and the only ones that changed are the
  two under the root. It is decided on the reference (`type === 'app'` and a null uuid), never on the string `'app'`,
  in **one** predicate used by the **three** places that build the list — the pass (`#changeKeys`), the `only` probe
  (`earlierPending`) and the requeue probe (`laterApplied`) — because exempting it in the first one alone left the
  mutex alive under `only`: the SQL of the probe matches `parent_type = 'app'` on its own (auditor 🟠 3, measured). It
  holds for blocks born from a real failure too (one rule, not two). The **port is untouched**: `sqlScopeOutbox` still
  knows how to match the root as a parent; the manager just never asks. The child's key still orders everything that
  matters, pinned as negatives: a failed `detached(orgA)` still holds back an `attached(orgA, app)` with the same uuid,
  and a failed `moved(unit, app)` still holds back a later `moved(unit, orgB)`. **Observable change**: an
  `attached`/`moved` under the root that used to come out `deferred` is now applied — that is the bug. Pinned with the
  minimal set the tester designed after measuring that *exempting the root left the whole suite green in the four
  engines* (zero existing cases died; the mechanism was covered, the root was not): the parked case, the inline case
  against the real SQL probe (with a spy proving the root never reaches `earlierPending`), the two-registrations case
  with nothing parked (SQL probe, memory probe and the paging fallback), the requeue case (spy on `laterApplied`), and
  the contract duty O-07b (two `attached` under `app` do not contaminate each other; under the same non-root parent
  they do) in the published judge. Mutants: root back as a key ⇒ 7 red; exemption only in `#changeKeys` ⇒ 3 red (the
  three SQL-probe cases: the inline mutex); "exempt every key" ⇒ 26 red.
- **A parked entry plugged the key of its *new parent* too, for no reason (owner's decision: variant B).** The
  parked census seeded the blocked set with both keys of the parked entry, so a parked `moved(unit → orgA)` deferred
  every later `moved(otherUnit → orgA)` and `attached(otherUnit, orgA)` — `orgA` is not touched by the failure, the two
  edges commute — and the store kept the old parent of everything under `orgA` with no expiry (measured,
  `m7-tapon.ts`; the fail-open variant the consumer described). A parked entry says the position of *its child* in the
  store is wrong, nothing about its new parent: the census now seeds **only the child's key**. What names the parked
  child — `attached(child, unit)`, `moved(unit → orgC)` — stays `deferred · parked:<id>` (the 1136 case), a
  `detached(unit)` still passes (invariant 11), and the auditor's 🔴 1 scenario (parked `moved(unit → orgA)`, then
  `attached(child, unit)`, then `moved(unit → orgB)`) stays fail-closed on every pass. **Only the seeding changed**:
  when two changes are *compared* (the blocked set, the paging fallback of the probe) both keys are still used —
  putting the variant inside `#changeKeys` would lose the 1136 protection in the fallback (a pending `attached(org,
  app)` would stop holding back `attached(unit, org)`); the judge found that trap and a case kills that mutant (26 red).
- **The fallback of `RelationsManager.enumerateRelationsMany` lost tuples when resumed with its cursor (🟠, new
  finding of the analyst).** A driver without the method fell back to K calls of `enumerateRelations`, concatenated,
  and the page carried **the cursor of the last partition that had more**; resuming with it applied `uuid > after` to
  *every* partition. Measured: 6 tuples in the store, 5 seen, `a9` lost — silently, and in the *source* of a migration
  that reads as "that tuple did not exist" (`authz:reconcile` of relations was not affected: `enumerateAllMany` pages
  per partition). Same doctrine as the single sweep of alpha.6 — *exhaustive or loud*: the fallback never hands out a
  cursor it cannot resume (a partition that returns one is 500 `E_AUTHZ_CONFIG` naming the method and the two ways out:
  implement `enumerateRelationsMany` in the driver, or page partition by partition with `enumerateRelations`), and an
  `after` reaching the fallback is 500 with zero driver calls. When no partition pages, the union is returned as before.
  Mutant "emit the last partition's cursor again" ⇒ red.

### Added

- **`enumerateRelationsMany` native in the `database` relations driver.** The same `SELECT` as `enumerateRelations`
  with `partition_key IN (every spelling of every partition)`, **one query per page**, total order by `uuid`, the same
  stable cursor (resuming sees every tuple exactly once, whatever K), and each tuple tagged with the partition you
  asked for (first reference of a key wins; two spellings of one uuid are one partition, as in `enumerateRelations`).
  `[]` is 500 with zero queries (parity with `openfga`). Pinned in the four engines: one query for three partitions (spy
  on knex), tuple-for-tuple parity with three `enumerateRelations`, resumption with `limit: 4` through the manager (six
  pages, 21 seen, none repeated). **No new capability** (`enumerateRelationsManyNative` is not added): with both
  published drivers native and the fallback loud, "am I on the fallback?" is no longer a question; if a third party
  needs it, 2.5 with its capability pair. Mutant "remove the native method" ⇒ 2 red.
- **`requeueScopeChanges(ids, { apply: true })` and `authz:scopes:requeue --id … --apply`.** Measured (tester P14):
  after `requeue` the entry returns with its *original* id, smaller than everything enqueued since, so the tenant's
  next `relayScopeChanges({ only })` found it in front and came out `deferred · depends-on:` — the incident did not
  close with a command. With `apply` the entry is requeued **and relayed in the same call**, under **one lease** taken
  first (the auditor measured that taking it twice — "requeue, then call `relayScopeChanges` inside" — is `busy` in
  green: `acquire()` is not re-entrant), **through the freeze barrier** before anything is touched (with `apply` the
  command writes the tree; the docblock that said `requeue` skips the barrier now says *without `apply`*), **never
  together with `force`** (500 `E_AUTHZ_CONFIG`: with both, reverting the tree over what was applied later would be a
  single call, auditor 🟠 6), and with an internal `only` that is **exactly the requeued ids** — dependants are not
  dragged along, they stay `deferred`/pending and the report says so (`only` is your receipt; the tester's "drag the
  dependants" surface is rejected and pinned as the negative). Lease held by another pass ⇒ `report.relay.busy`,
  **zero rows requeued**, command exit ≠ 0 (the alternative — requeue and say busy — leaves the entry with `attempts =
  maxAttempts − 1`, parked again by the next pass and poisoning its key once more). The anti-reversion probe runs
  before anything is requeued, as always (refusal = 500 with zero driver calls, lease released). If the cause is still
  broken the same call parks the entry again and says why; a 503 leaves it pending with `attempts = maxAttempts − 1`.
  `--apply` is explicit, never the default (the command would start writing to the backend and the meaning of its exit
  code would change silently). `ScopeRequeueReport.relay?` carries the relay's report. Mutants: double lease ⇒ 3 red;
  no barrier ⇒ red; requeue-then-busy ⇒ red; `apply` + `force` allowed ⇒ red.
- **`relayScopeChanges({ waitForLeaseMs })` and `--wait-lease-ms` (relay and requeue `--apply`).** Default **0** — one
  `acquire()` attempt and `busy` at once, so "two passes at once ⇒ busy" does not change (the "default > 0" mutant turns
  that case red). With a budget, `acquire()` is retried every `RELAY_LEASE_POLL_MS` (25 ms; 0.29 ms per busy poll in
  PostgreSQL, no connection held between polls) until the lease is free or the budget is spent, then `busy` — bounded,
  never a hang. Needs a **pool ≥ 2** (README), like `{ transaction }`. Pinned in process (the second pass enters when
  the first releases and applies what was left; timeout is bounded and observable; invalid values are 500) and
  **between processes** on PostgreSQL/MySQL (`scope_outbox_multiprocess.spec.ts` W-4: the child waits on the server's
  lock and enters when the parent releases). The clock is the injectable one — no `Date.now()` in `src/`.
- **`sqlScopeOutbox({ requireTransaction: true })` — enqueueing outside your transaction is 500 before the `INSERT`
  (lot II; panel relay 2, question 6; tester P13).** The whole mitigation of the outbox is the `{ transaction }` you
  pass to `scopes.*`; without it the row commits on its own and a later rollback of yours leaves the change in the queue
  for the relay to apply — SQL says one parent, the PDP another, on the correct-use path (the S5 leak, measured). With
  the option on, `enqueue` without an open transaction of the outbox's connection is 500 `E_AUTHZ_CONFIG` naming that
  leak (through the manager and through the outbox alone), zero rows; with it, unchanged. **Default `false` in 2.4**:
  the published `runScopeOutboxContract` enqueues without a transaction in its `ctx()` (`scope_outbox_contract.ts`) and
  a `true` default would turn every third-party outbox red — a contract change for third parties is major. **The
  default becomes `true` in 2.5** (owner's decision), and the prerequisite is registered with it: the contract's
  `ctx()` passes a transaction (with its capability pair) so the default can change. The published contract stays
  green today (17/17 with `ctx()` without a transaction). Mutant "check after the INSERT" ⇒ red (zero rows is
  asserted).
- **The report says how old the queue is: `report.queue.{oldestPendingAt, pendingAgeMs}`, `--max-age` (lot II; panel
  relay 2, question 5; auditor B2 of COGNITIV).** Measured: with the store down, ten relay passes in a row reported
  `attempts = 0` on every entry (a 503 does not consume an attempt since alpha.5), `dead = 0`, and no notion of time
  anywhere — the cron was red because of `failures`, and nobody could tell since when. Now every report (a pass, a
  `dryRun`, a `busy` one) carries the `createdAt` of the **oldest pending entry of the whole queue** and its age.
  Decisions, each pinned: it is the `pending(1)` the pass already ran for `remaining` (zero new queries; `MIN(created_at)`
  degrades with the queue, the judge measured 1.63 vs 1.59 ms); the age is `max(0, now − createdAt)` with the
  **manager's injectable clock** (`config.clock`; `tests/clock.spec.ts` greps `src/` for `Date.now()`: the ten-pass case
  runs with an injected clock and no `sleep`), clamped at zero because the stamp is *the clock of whoever enqueued*
  (another replica, with its skew); **always global, also under `only`** (it names nobody, it only says "there is
  backlog"; `remaining` and `dead` are global too — a per-`only` age would be a third policy); `null` in both fields
  when nothing is pending (empty queue, or only parked entries: those have `deadCount`) and when the port does not carry
  `createdAt` — a third-party outbox reads as `null`, **never `0` or "now"** (the `stillGranting` rule). The port gains
  `createdAt?: Date` on `PendingScopeTreeChange`, optional and covariant; `sqlScopeOutbox` returns the `created_at` it
  already stamped (as a `Date` in PostgreSQL/MySQL, from the millisecond number SQLite hands back). The judge gains the
  **`createdAt` capability pair** (`true`: a `Date`, non-decreasing, the report's head is that stamp; `false`: the field
  is absent and the report says `null`, pass green) — 17 cases per harness. `authz:scopes:relay` prints the age on every
  pass and **`--max-age=<ms>` exits ≠ 0 only with a threshold and only above it** (`queueAgeLines`, pure): without a
  threshold the age never fails the run — a cron red for ever over a queue that simply has backlog is a cron nobody
  reads. Mutants: no clamp ⇒ red (skew case); "degrade a missing `createdAt` to now/0" ⇒ 2 red; "age from the requested
  batch under `only`" ⇒ red; "exit ≠ 0 without threshold" ⇒ red.
- **`entries[].origin: 'parked' | 'pending' | 'failed'` on every `deferred` entry (lot II).** The origin of a key block
  was a boolean (`parked` or not) since the closing lot of alpha.5, so under `only` a `depends-on:<id>` did not
  distinguish "held by an earlier entry that is genuinely pending and was not requested" from "held by a real failure of
  this pass", and the distinction lived only in the Spanish prose of `deferred[].error`. The block now carries a
  tri-state origin with precedence `failed > pending > parked`, transitively (two hops report the root cause), and
  `origin` is **derived from the block, never parsed back from the prefix of `reason`** (the "prefix" mutant turns the
  `pending` case red). The apply/defer decision does not change: only `origin === 'parked'` exempts a `detached`
  (invariant 11), as before. `applied`, `failed` and `dead` entries carry no `origin`.
- **`report.deadCount`, always and global; under `only`, `dead[]` without `error` by default, `deadDetail: 'full'` to
  get it back (lot II; coordinator's decision, fail-closed).** `dead[]` is capped at `batchSize` (100), so `dead.length`
  *lied* once more than that was parked; `deadCount` comes from the census the pass already reads for the key plug (no
  extra query). Under `only` — the inline recipe, inside a tenant's request — each `dead[]` entry keeps `id`, `change`
  and `attempts` and drops `error` (text the backend wrote about *another* tenant's tree); `deadDetail: 'full'` returns
  what alpha.7 returned, and without `only` nothing changes. Correction to the consumer's premise, written in the README:
  **the actor never travels in `dead[]`** (`RelayedScopeChange` has no actor); what still identifies another tenant is
  `change`, so the rule "do not return the report over HTTP" stands — this narrows the leak, it does not close it, and
  `change?` is not made optional (it would break every reader at compile time; owner's addendum of 2026-09-10 (1)).
- **A transaction that is already committed or rolled back is 500 `E_AUTHZ_CONFIG`, not 503 (lot II).** Measured by
  the analyst: Lucid keeps `isTransaction === true` after `commit()`/`rollback()` and publishes `isCompleted`, so
  `assertCallerTransaction` let the finished `trx` through and the statement blew up inside knex as 503
  `E_AUTHZ_BACKEND_UNAVAILABLE` "the backend did not answer" — false: it is the caller's wiring. Fourth check of the
  shared guard (`isCompleted === true` ⇒ 500 naming the operation and "confirmada o revertida", zero statements), which
  reaches the **three** callers at once — `sqlScopeOutbox.enqueue`, the `database` roles driver (L-3) and the `database`
  relations driver (L-4) — each with its case, in the four engines (a finished transaction holds no connection, so the
  freeze barrier does not wait even on a pool of 1). Mutant "drop the check" ⇒ 3 red.
- **The 422 `E_AUTHZ_SCOPE_DEPTH_LIMIT` no longer names the backend in its public `message` (lot II).** It named
  `openfga`, `FACTS_MAX_RESOLVE_DEPTH (22)` and `OPENFGA_RESOLVE_NODE_LIMIT` — a 422 that reaches the tenant. The message
  keeps what the caller can act on (the depth reached, `scopes.maxDepth`, "nothing written or enqueued"); the *why* and
  the server knob go to `error.details` for the operator's log (pinned with `notInclude` ×3 and a `details` check).
  **How to size `maxDepth`, pinned by an executable case**: it counts `parent` hops from the child to `app`, so **a
  tree of N levels below the root needs `scopes.maxDepth = N`** — a three-level tree enters with `maxDepth: 3` and its
  third level is 422 with `maxDepth: 2` (`scope_depth.spec.ts` N-2). *Note for the record*: the panel's letter said
  "N + 1" and "`maxDepth: 3` ⇒ 422 on the third level"; measured against the code (`chain.length > maxDepth`, the
  parent's chain includes `app`) that is false, and the README carries the measured rule, not the panel's sentence. The
  semantics did not change (levels instead of hops would be breaking, and hops are what spend the FGA depth budget).
- **An unknown option is 500, never silence (X-1).** `relayScopeChanges` and `requeueScopeChanges` validate their
  option *keys*: an unknown one (a typo, `apply` on a version that did not have it) is 500 `E_AUTHZ_CONFIG` naming it,
  with nothing done. Until alpha.7 `{ apply: true }` and `{ waitForLeaseMs }` were ignored in silence (measured), so a
  JavaScript consumer believed it applied or waited when it did not. Prerequisite for publishing the two options above.

### What is NOT done, and why

- **"Supersede" (a later `moved` of the same child retires a parked one) — no, in no form** (judge 95/100 for "not
  done"). The auditor measured the fail-open it opens: with `#1 moved(unit → orgA)` parked, `#2 attached(child,
  unit)` and `#3 moved(unit → orgB)` pending, superseding `#1` frees the key, the pass applies `#2` and fails on `#3`
  (503, which by design does not consume an attempt) — the store ends `child → unit → orgV → app`: the holders of the
  organisation that is no longer the owner authorise over a scope created inside another one, and `dead()` is
  **empty**, so there is no alarm, indefinitely (today the same queue is fail-closed: `child` does not exist in the
  store). Writing "superseded" as `applied_at` would make `laterApplied` lie and push the operator to `--force`
  (measured too), and a real terminal state is a column in a table that is *yours* (a migration) plus a new port
  probe and `EXPECTED_CASES` 15 → 17. The requirement it stands for is registered as **`authz:reconcile` bounded by
  subtree/tenant with `--dry-run` (2.5)**; the published remedy is still `authz:reconcile --to=<driver>`, which
  recomputes with today's tree and reorders nothing.
- **`parkAfterMs` (park by age) — no.** It reintroduces, with another clock, exactly what alpha.5 removed (a 503 does
  not consume an attempt): parking by a cause that is common to every entry. Measured: with 50,000 entries parked
  by age the census hits `PARKED_CENSUS_MAX` and **every** pass is 500 in 91 ms — nothing drains, the `moved` keep
  the old parent and the `detached` never purge (fail-open, permanent, self-inflicted); `dead()` sees 10,000 of the
  50,000, so the rest cannot even be named in `requeue`; requeueing 200 costs 490 ms (one `laterApplied` per id). The
  blindness it was meant to fix (with the store down, ten passes with `attempts = 0`, `dead = 0` and no age anywhere
  in the report) is real and is fixed in the alarm, not by parking: queue age in the report and `--max-age` on the
  cron — lot II of this release.
- **`dead[].supersededBy` (read-only: the later applied change of the same child) — no, not cheap enough.** It would
  cost one `laterApplied` query per parked entry on **every** pass, under the lease, on the queue every tenant shares
  (the auditor measured `laterApplied` at ~2.5 ms each: 200 requeues = 490 ms; 100 parked entries would add ~250 ms to
  every cron pass). The judge's condition was "if it is cheap"; it is not. The way to answer "was this parked entry
  overtaken?" stays `authz:scopes:requeue --id` (its anti-reversion probe prints exactly that diff, without requeueing
  anything unless the probe is clean).
- **`scopes.requireOutboxTransaction` on the manager (the judge's second gate) — not added.** The manager does not
  build the outbox: `config.scopes.outbox` *is* the `ScopeOutbox` instance, so the option lives where the `INSERT`
  lives (`sqlScopeOutbox({ requireTransaction })`), and a third-party outbox enforces its own. If a manager-level gate is
  wanted for every port implementation, it is a 2.5 item next to the default flip. Nor does `warnOnOptInSecurity` warn
  when the option is off: the outbox has no logger and the README carries the letter.
- Also not done, by decision: `blockOnParentKey` as a config option (the root as a key preserves no order; there are
  no two legitimate behaviours to offer); `only` dragging the requeued dependants automatically; `--apply` as the
  command's default; the `enumerateRelationsManyNative` capability.

## [2.4.0-alpha.7] — 2026-09-10

**The legacy MySQL lock name is retired.** Since alpha.5 `acquire()` took both the old (64-char-truncated) and the new (stable, hashed) `GET_LOCK` names so that a rolling deploy mixing alpha.4 and alpha.5 processes kept a single writer. There is no consumer deploying from alpha.4 on MySQL (the first consumer runs PostgreSQL, whose advisory lock never had the problem), so the transition protected nobody: `SCOPE_OUTBOX_TAKES_LEGACY_LOCK` is now `false` and only the new name is taken. **What this means for you**: upgrading from `≤ 2.4.0-alpha.4` on MySQL is a full stop of the relay (cron and inline) and a restart, not a rolling deploy — a leftover alpha.4 relay holding the old name is not seen by this version (pinned by a case, on purpose). From alpha.5 or later, nothing to do. The version-pinned guard (`SCOPE_OUTBOX_LEGACY_LOCK_UNTIL`) stays as the record of when the transition ended.

## [2.4.0-alpha.6] — 2026-09-10

**Legacy MySQL lock name — retirement pinned to the version.** `acquire()` takes the old (64-char-truncated) `GET_LOCK` name only while `SCOPE_OUTBOX_TAKES_LEGACY_LOCK` is `true`, and the suite requires that flag to equal *«package.json ≤ `SCOPE_OUTBOX_LEGACY_LOCK_UNTIL`»* (`2.4.0-alpha.6`): the first version bump past it turns the suite red until the legacy name is dropped. Nothing is left to remember; the bump enforces it. It is not dropped in the same release that introduces the new name because, during a rolling deploy, alpha.4 processes hold the old name and new ones the new name — two writers at the worst moment. · one sweep for K partitions, and the purge exemption also under `only`

Closes the two items deferred from alpha.5 that could be closed without a new design (panel relay, analyst §3
and auditor 🔴 3 / 🟡 8; final audit of alpha.5, 🟡 A). Additive; no schema change; no port method removed.
**The old MySQL lock name (`scopeOutboxLockNames().legacy`) is still taken alongside the new one in this
version, on purpose (rolling deploy with alpha.4/alpha.5); it is retired in the next release.**

### Added

- **`enumerateRelationsMany(partitions)` on the `openfga` relations driver, and `reconcileRelations({ partitions })`.**
  `enumerateRelations(partition)` is, in `openfga`, a `Read({})` of the **whole store** filtered in memory —
  there is no other way: a `Read` by type without `user` is a 400, `pageSize > 100` is a 400, and a `Read` by
  *prefix* of the object id answers **200 with zero tuples**, silently (measured against the server; it is the
  first "optimisation" anyone would write, and in the *source* of a migration it reads as "this partition is
  empty"). So K partitions cost K sweeps. The new optional port method enumerates K partitions in **one**
  sweep — one `Read({})` paginated, each tuple tagged with the `partition` you asked for, matched by the
  **whole** partition key (`app` does not pull `appliance|…`, `org|U` does not pull `organization|U`, and each
  spelling of a uuid is its own partition) — and `reconcileRelations` accepts `partitions: ScopeRef[]`:
  source and destination are enumerated once, the K diffs are decided first (the mass-delete guard R-17 is
  evaluated for every partition **before** writing anything), then applied; the report is the sum. A driver
  without the method falls back to K calls of `enumerateRelations` (correct, K sweeps). `RelationsManager`
  exposes the same method with the same fallback. Measured against OpenFGA 1.19 with 3 partitions × 1,000
  tuples plus 2,000 foreign ones (5,000): **three sweeps = 150 reads, 502–558 ms; one sweep = 50 reads,
  170–209 ms**, byte-for-byte the same output per partition. Pinned with a spy on the **real** FGA client:
  the number of `read` calls equals the number of pages, whatever K, and **every `read` carries `{}`** —
  the prefix mutant turns red twice (the filter assertion and the parity). A cheap double of the client pins
  the shape of the cost in `npm test` without a server.
- **Exhaustive or loud.** A `Read` page with zero tuples *and* a continuation token is not the end of the
  sweep (the "empty page = end" mutant is red); a token that repeats, more than 10,000 pages, or a response
  without a `tuples` array is 503 `E_AUTHZ_BACKEND_UNAVAILABLE`, never a shorter enumeration; a tuple that
  cannot be parsed is still counted in `diagnostics.unparseableTuples` and skipped; `enumerateRelationsMany([])`
  and `reconcileRelations({ partitions: [] })` (or `partition` and `partitions` together, or neither) are 500
  `E_AUTHZ_CONFIG` with zero reads. The README table said a repeating token was "500 `E_AUTHZ_INTERNAL`";
  the code always threw 503 — the letter now says what the code does.
- **`RELAY_ORIGIN_MAX_HOPS` (100)** — exported; in the "Limits" table and tied to the constant by the suite.

### Fixed

- **Under `relayScopeChanges({ only })` the purge exemption now holds** (final audit of alpha.5, 🟡 A).
  The probe that finds an earlier unapplied entry sharing a scope key with the requested one marked every such
  deferral as a *real* block, so a `detached` behind an `attached` that was itself only waiting on a **parked**
  entry came out `deferred` (`depends-on:<id>`) on every inline pass — the purge waited for a full pass that a
  deployment relaying only inline never runs (measured). The probe now **inherits the origin of the block** of
  the earlier entry, the same rule the full pass applies (`blocked: Map<key, { id, parked }>`, closing lot of
  alpha.5), walked back over the entries it does not apply: a key already blocked by a real failure of this pass
  ⇒ real; an `attached`/`moved` naming a parked key (or a key blocked by a parked origin) ⇒ parked; otherwise
  its own earlier entry, recursively (ids strictly decreasing; memoised; at most `RELAY_ORIGIN_MAX_HOPS`, past
  which it assumes a real block). A requested `detached` whose earlier entry is parked-origin is **applied and
  purges**, at one hop and at two; a requested `attached`/`moved` behind that chain stays `deferred` (now with
  the parked origin, so a later `detached` of the same pass passes too). Two negatives pinned: an earlier entry
  that is genuinely pending (it would be applied by the full pass) and one held by a real failure still defer
  the purge — the "every earlier entry is parked" mutant turns both red. Entries not requested are not touched.

## [2.4.0-alpha.5] — 2026-09-10 · a 503 does not park an entry, a parked entry no longer lets its dependants through, the relay can apply only what you just enqueued, a parked entry can be requeued without reverting the tree, the limits are one table, and the single writer is observed between processes

**The problem, as reported (COGNITIV, 2026-09-09, second report on the relay, on `2.4.0-alpha.4` with the
inline relay recipe of the README).** Four observations, all four exact. (1) The relay report says *which* entries
were applied, but nothing links "what I just enqueued" to those ids — `enqueue` returned `void` and
`scopes.attached/moved/detached` returned `void` — so their code compared `applied[].change` keys by hand, which
cannot distinguish two identical changes enqueued twice, and with a backlog of another tenant ahead their entry was
not in *any* list of the report (`applied` 50 of 501, `remaining: true`, correct and useless). Measured: **4,507 ms
and 2,004 OpenFGA calls** to land one change behind 500 foreign entries. (2) `maxAttempts: 5` "is sized for a job,
not for the inline relay": with the store down, an entry is parked after five passes — and with the inline recipe
those are five *requests of anyone*, not five cycles of time. (3)/(4) are `enumerateRelations` and the depth
ceiling, handled in the next lots (`R0`/`R4`) and in 2.5.

**The live problem the panel found underneath — red, and with no change of theirs involved.** Parking an entry
took it out of `pending()`, so it stopped contaminating its scope keys, so *what depended on it was applied without
it* — fixed on purpose in `tests/scope_outbox.spec.ts` ("what depended on it finally moves on"), because the case
that fixed it had a *purge* moving on. The auditor measured the other shape (`relay-auditor-1.ts`): a parked
`moved(unit → orgB)` and a later `attached(child, unit)` ⇒ the child is attached under the **old** parent in the
store, **permanently** — the persistent escalation the outbox exists to prevent — and it takes five requests of
*another* tenant with the store down to get there. Two of the four changes requested (`only` as a filter of
`pending()`, and `requeue`) would reopen the same hole by a second door: measured against the real server, a
filtered `only: [attached]` wrote `child → unit` while the store still said `unit → orgA`, and
`authorize(A@orgA, docs:read, child) = true` with the report all green (`relay-auditor-2.ts`, 🔴 1).

**Decisions (lot I of alpha.5: R2a then R1; R2b `requeue`, docs and the guarantees follow in lot II).**

- **A 503 does not consume an attempt** (R2a, decided by the *nature* of the error, not by a flag of the call site).
  `ScopeOutbox.markFailed(id, error, options?: { transient?: boolean })` — third parameter, optional: a port
  implementation written against alpha.4 counts every failure, which is exactly the previous behaviour (degrades
  towards safe). The manager passes `transient: true` for an `AuthorizationBackendError` (the store did not answer,
  the deadline expired; `AuthorizationBackendTimeoutError` is one) and for any error with `status === 503`
  (the freeze, a resolver down); a 422, a 500, `E_AUTHZ_SCOPE_TREE_DRIFT`, a missing parent or a bare error from a
  third-party driver count as before. `sqlScopeOutbox` writes `last_error` in both cases — nothing goes silent —
  and increments `attempts` only when the failure is the entry's. `failures[]` and `failed` carry `transient`.
  Pinned with the auditor's reproduction as a case: five foreign inline passes with the store down leave the foreign
  entry at `attempts = 0` (before: `1, 2, 3, 4, 5` and parked), and when the store is back the `moved` lands before
  its `attached`; and with the real `openfga` driver against a dead port, without a spy. The mutant that counts
  everything turns the case red with the exact numbers of the report.
- **A parked entry blocks, by scope key, what grants or re-parents and lets through what retires** (R2a; **decision of
  the owner, 2026-09-09 (2)**: the semantics fixed in `scope_outbox.spec.ts` are split, not reverted). At the start
  of every pass the scope keys of `dead()` seed the blocked set — bounded to the *key*, which is the difference with
  the queue-wide plug of 3b-2h 🔴 2 — but they defer **only `attached`/`moved`** (`deferred` with reason
  `parked:<id>`, on every pass, until someone acts on the parked entry), never a `detached` (invariant 11: a purge
  never waits; a half-applied tree may leave denies in excess, never facts alive on a node nobody purges). What stays:
  a parked entry never returns to `pending()` and is reported on every pass (the queue converges). The old case is
  now two: (a) parked `attached` + later `detached` of the same key ⇒ the purge is applied; (b) parked `moved` +
  dependent `attached` ⇒ deferred, not applied with the old parent. Mutants: no seeding ⇒ (b) red with the auditor's
  exact outcome; seeding for every operation ⇒ (a) red (the purge blocked). The price, written in the README: one
  irreparable parked entry freezes the grants and moves of its key until a human acts — loud (`deferred` + `dead` +
  exit ≠ 0), never the queue. **Not done**: the queue-wide plug, `next_attempt_at`/backoff (a column and a migration
  on a stub consumers already deployed), raising `maxAttempts` as the answer.
- **The receipt** (R1). `ScopeOutbox.enqueue` returns `Promise<void | { id }>` — covariant: a third-party outbox that
  still returns `void` compiles and works. `sqlScopeOutbox.enqueue` returns `{ id }`, the id of the row (`returning`
  where the dialect supports it; measured on the four engines: `[id]` on SQLite/MySQL, `[{ id }]` on PostgreSQL) — the
  same id `pending()` returns. `manager.scopes.attached/moved/detached` return **`{ queued: Array<string | number> }`**
  (`ScopeEnqueueReceipt`, exported): plural because `detached` enqueues one row per spelling of the uuid when the
  consumer's row is already gone (invariant 17); empty without an outbox (applied inline, nothing to relay) and with
  an outbox without ids (never an invented id).
- **`relayScopeChanges({ only })` — a subset of ids IN THE PORT, plus a dependency probe against the WHOLE queue**
  (R1; the judge's synthesis, option D, 92.5/100). `ScopeOutbox.pending(limit, after, filter?: { ids })` — third
  parameter, optional: `sqlScopeOutbox` filters in SQL (`whereIn` on the primary key, 0.20 ms measured on a backlog
  of 501); an implementation that ignores it returns entries that were not asked for and the manager stops with
  500 `E_AUTHZ_CONFIG` naming the port method, before applying anything — filtering in memory is exactly the
  implementation that leaves the 50 existing cases green while fixing nothing (tester 1b-3: the suite spies on
  `pending` and asserts that the pass with `only` reads at most 3 rows out of 501). **The order by scope key is not
  relaxed.** Before applying each requested entry the manager asks the queue whether an *earlier* unapplied entry
  names one of its scopes — `ScopeOutbox.earlierPending?(id, scopes)`, optional in the port, one existence query in
  `sqlScopeOutbox` against the `(applied_at, id)` index (0.69 ms measured; a port without it is paged through
  `pending()` up to the entry, correct and O(queue), and refuses with 500 rather than guess if the queue does not fit
  in `RELAY_WINDOW_MAX_PAGES` batches) — and if there is one, the entry is `deferred` with `depends-on:<id>` and
  **never applied out of order**. One level is equivalent to the transitive closure: if a chain of pending
  dependencies reaches the entry, its last link shares a scope key with it by definition of the key contamination
  (the case with both links requested applies them in id order, not in the order of the array). Pinned against the
  `:8101` with the auditor's exact scenario: `only: [attached]` ⇒ `deferred`, `authorize(A@orgA, docs:read,
  child) = false`; `only: [moved, attached]` ⇒ in order, B authorises, A does not; and the timing of the `only`
  pass against draining the 500 foreign entries in the same run. `only: []` ⇒ 500 `E_AUTHZ_CONFIG` (tester 1c-4
  over the analyst's no-op: an empty `filter` on the consumer's side, or a receipt from an outbox without ids, must
  not end in a drain nor in an empty report in green). Ids of `only` that are neither pending nor parked come back in
  **`missing`** — already applied by an earlier pass (the inline recipe with a cron behind it) or unknown; the relay
  cannot tell and does not throw. **`remaining` and `dead` are never filtered** (measured trap: filtering
  `remaining` returned `false` with 500 pending). **The per-entry result**, `report.entries: Array<{ id, change,
  status: 'applied' | 'deferred' | 'failed' | 'dead', reason?, attempts? }>`, in processing order with the parked
  entries last, with and without `only` — so nobody has to compare change keys again. `authz:scopes:relay
  --only=12,13` (or repeated), output per entry, `missing` named, `parked:<id>` said as such, and a transient failure
  said as "does not consume an attempt". **Not done, on purpose**: a filter by tenant/`organization` — undecidable
  for `detached` (a row that no longer exists belongs to no organization: excluding it is a permanent fail-open,
  including it is "anyone relays anyone's `detached`") and biased for `moved` (attributed to the destination: the
  tenant relays what brings things *in* and leaves what takes them *out*); `only` that pulls its dependencies along
  (transitive ⇒ the whole queue); `only` from the request body (the relay is platform API); exposing the report over
  HTTP (it enumerates the tree activity of every tenant — the README says so, 🟡 7 of the auditor).
- **The outbox and relay types leave by the main entry.** `ScopeOutbox`, `ScopeOutboxContext`, `ScopeOutboxLease`,
  `ScopeTreeChange`, `PendingScopeTreeChange`, `RelayedScopeChange`, `ScopeRelayReport` — and the new
  `ScopeOutboxPendingFilter`, `ScopeOutboxFailure`, `ScopeRelayFailure`, `ScopeRelayEntry`, `ScopeRelayEntryStatus`,
  `ScopeEnqueueReceipt` — are exported from `@jantstack/adonis-authz`. Until alpha.5 none of them was: "or your own
  implementation of `ScopeOutbox`" in the README pointed at a type a consumer could not import. Additive.
- **The lease is not touched** (per pass, not per batch): with `only` the connection is held for the 19 ms of one
  entry instead of the 4,507 ms of the foreign backlog, which was the actual complaint.

**Decisions (lot II of alpha.5: R2b `requeue`, R0 docs and depth, the guarantees nobody observed).**

- **`authz:scopes:requeue --id=<id>` — a parked entry goes back to the queue, never on top of what was applied after
  it** (R2b). `ScopeOutbox.requeue?(ids)` and `ScopeOutbox.laterApplied?(id, scopes, limit)` — optional, the mirror of
  `earlierPending`. `sqlScopeOutbox.requeue` is all or nothing: every id must exist and be parked (unapplied, attempts
  exhausted) or it throws naming the offenders and touches **no row** (an applied entry never comes back: requeueing an
  applied `detached` would purge again); the entry returns to `pending()` with its old id and **`attempts =
  maxAttempts − 1`** (owner's decision, 2026-09-09 (2): neither `0` — five more passes of contamination for something
  irreparable, the auditor's "tap" — nor kept — that requeues nothing; no new column). **The anti-reversion probe lives
  in the manager** (`requeueScopeChanges(ids, { force })`, platform API next to `driver()`, never over HTTP): before
  touching the queue it asks `laterApplied` whether an entry applied *after* the parked one shares a scope key, and if
  so refuses with **500 `E_AUTHZ_REQUEUE_REFUSED`** carrying the diff (`conflicts`) and the remedy (`authz:reconcile
  --to=<driver>`). Measured by the auditor (`relay-auditor-5.ts`): a parked `moved(unit → orgB)` requeued after
  `moved(unit → orgC)` was applied leaves the store with the **old parent and a single edge** — `assertOneParent` does
  not see it and the old tenant regains access. The probe is the manager's because it needs the change keys, so a
  third-party outbox inherits it by implementing the two methods. **`--force` exists only in the ace command**: it
  prints the diff (the parked entry and every applied entry it would revert) and requeues anyway. A requeued entry whose
  cause is still broken is parked again after **one** pass and contaminates its key only in that pass (the purge of its
  parent lands on the next one); there is no loop. Mutants: no probe ⇒ the auditor's case red; `attempts = 0` ⇒ the
  "one pass, not five" case red. Note for lot I's finding: with the key plug of R2a, the auditor's script as written no
  longer reverts (the second `moved` is deferred while the first is parked); the dangerous shape survives in queues
  inherited from alpha.4 and behind a later `detached`, which is what the probe catches.
- **The limits are one table, tied to the constants** (R0; panel question 5). README `### Limits`: the scope-chain
  depth (`FACTS_MAX_RESOLVE_DEPTH` = 22 `parent` hops, `openfga` only, 503 past it), the model bytes, `batchCheck`,
  the `Read` page, **`enumerateRelations` = O(tuples in the store) per partition and per call — never from a tenant
  request; a single sweep for K partitions is scheduled for 2.5 — and there is no prefix `Read` (a prefix object answers
  200 with zero tuples, measured)**, the relay bounds, `maxAttempts`, `maxScopes`, `maxDescendants`, `maxLocalRoles`. The
  suite imports the constants and asserts that *those* numbers are in the table (the constant changed to 23 without the
  README ⇒ red), and "The scope tree" now says the 22 where the tree is designed, with a link.
- **`scopes.maxDepth` — the opt-in depth gate, in the config, declared partial** (R0). With it, `scopes.attached`/
  `scopes.moved` refuse with **422 `E_AUTHZ_SCOPE_DEPTH_LIMIT`** a child that would end up more than `maxDepth` `parent`
  hops from `app` (the parent's chain + 1), **before writing or enqueueing** (zero driver calls, zero outbox rows) and at
  zero extra I/O (the parent's chain is already resolved for the cycle check). Without it nothing changes (`database`
  pays nothing). In the config and not in `capabilities()` because a capability is a boolean by doctrine. **Partial**:
  it does not see the height of the subtree a `moved` drags along (measuring it would need `descendantsOf` on the write
  path); the reconcile report catches those. The same knob drives **`authz:reconcile`: chains above the ceiling are
  reported as drift** (`drift.tooDeep`, `drift.tooDeepLimit`; exit ≠ 0 — legal in `database`, a 503 in `facts`, so it
  belongs in CI), using `scopes.maxDepth` when declared and `FACTS_MAX_RESOLVE_DEPTH` otherwise. Code: the judge asked
  for a new code because `E_AUTHZ_SCOPE_TOO_DEEP` (500) already means "the resolver could not finish an existing chain".
- **The single writer is observed between real processes** (R6; the tester's 🔴). `tests/scope_outbox_multiprocess.spec.ts`
  + `helpers/relay_child.ts` (pattern of the durable freeze): a second process relays the same queue while the first
  holds `acquire()` ⇒ `busy`, zero writes on PostgreSQL and MySQL; released ⇒ it applies. The mutant "advisory lock →
  process `Set`" leaves the in-process case of `scope_outbox.spec.ts` **green on all four engines** (measured: 87/87 on
  pg with the mutant) and turns this one red. On `sqlite-file` the green is the *bad* behaviour on purpose: the second
  process applies over the first, and the README says with those words that SQLite is not the engine for two replicas
  of the relay. `:memory:` cannot observe any of this — declared in the file header; the pg/mysql CI jobs are not
  optional for this guarantee.
- **The MySQL lease name is a stable hash, with a two-lock transition** (R6). `GET_LOCK` takes 64 characters and the
  name `authz_scope_outbox:<connection>:<table>` was truncated: two deployments sharing the first 64 characters shared
  one lease and excluded each other forever, with `busy: true` — which does not throw — as the only symptom. Now the name
  is `authz_scope_outbox:<sha1 of the full name>` (59 characters, `scopeOutboxLockNames`, exported). **During alpha.5
  `acquire()` takes both the old and the new lock** (+0.56 ms), so a rolling deploy mixing alpha.4 and alpha.5 processes
  stays single-writer (pinned on MySQL: a session holding only the legacy lock makes alpha.5's `acquire()` return
  `null` without keeping the new one half-taken). **The legacy lock is retired in 2.5** — and only then do two tables
  sharing the first 64 characters stop sharing a lease: during the transition the collision on the *old* name is kept
  on purpose (the alternative was asking consumers to coordinate their rolling deploy).
- **`runScopeOutboxContract` in `/testing`** (R5; the tester's recommendation nº 1). The port's duties are a published
  judge: seven core cases (receipt, oldest first + identity + actor, `after`, idempotent `markApplied`, `markFailed`
  counts and keeps the row, the manager drains it, a failure defers by key and the next pass resumes from the queue) and
  **one face per capability** — `transactionalEnqueue`, `filter`, `transient`, `dead`, `acquire`, `earlierPending`,
  `requeue` — where the `true` face judges the duty and the `false` face judges that the manager *says so* or the
  implementation degrades towards safe, never a skip; a `true` without what it takes to observe it throws at
  registration. Fourteen cases per harness; the package runs it on `sqlScopeOutbox` over the four engines and on an
  in-memory double (`makeScopeOutbox`, exported) with all capabilities and with none. Mutants: a double ignoring
  `after` ⇒ red; `laterApplied` returning pending rows ⇒ red.

**Closing lot (the audit of alpha.5, two 🟠 in the key plug of R2a, both measured; `relay-auditor-{7,9}.ts`).**

- **The parked plug no longer freezes purges, at any distance** (🟠 1, a regression of R2a). With `#1 moved(unit →
  orgB)` parked and `#2 attached(child, unit)` correctly deferred `parked:#1`, the tenant deleting the unit enqueued
  `#3 detached(unit)` — and it came out `deferred/depends-on:#2` on every pass, because a deferral contaminated its keys
  for every operation: the deleted scope kept its facts and its edge in the store and kept granting, while the README
  promised "a purge never waits". The manager now records the **origin** of every key block: a block whose (transitive)
  root cause is a parked entry holds back only `attached`/`moved`; a block born from a real failure of the pass holds
  back everything, `detached` included, as since 2.0 (the order between a failed `attached` and the purge of that same
  node still matters). Pinned: the auditor's case with a grandchild (both purges land, both `attached` stay deferred),
  the control, and the negative (a `detached` behind a *failed* `attached` stays deferred). Mutant "every block is
  parked-origin" ⇒ the negative red.
- **The parked census is complete, whatever `limit`/`batchSize`** (🟠 2). The keys of `dead()` were read up to `limit`:
  with 101 parked entries and `--limit 50`, or the inline recipe `{ only, limit: 1 }`, the 101st did not plug its key —
  and the `only` probe cannot see it either (`earlierPending` excludes parked entries) — so the `attached` landed under
  the old parent. Now the census is read in full with its own cap, `PARKED_CENSUS_MAX` (50,000, exported): past it the
  pass refuses with 500 `E_AUTHZ_CONFIG` before applying anything — an incomplete plug is not a plug. The report still
  shows the first `batchSize` parked entries. No port change. Mutant "census = what the report read" ⇒ the auditor's
  case red.
- Three cheap ones from the same audit: the `--force` diff says when it is cut (`ScopeRequeueConflict.truncated`, "… y
  más" in the command; 100 listed per parked entry); the README says that **`laterApplied` only sees the outbox** — do
  not requeue after reconciling, the remedy is to reconcile again (a case pins the letter); and **`pending()` must
  return the whole unapplied queue, oldest first** is now a written duty of the port (docblock + README) with a
  contract case, O-08 (a double that hides one "tenant's" rows turns the contract red) — the order guarantee rests on
  it, and a port that filters on its own reopens the escalation of `relay-auditor-2.ts` with no guard able to see it.

**What did not change.** No column, no migration of `authz_scope_outbox` (the stub is already deployed in
consumers). No breaking change: the new port parameters and methods are optional and covariant, `scopes.*` returning a
receipt where they returned `void` is additive, the report only gains fields (`entries`, `missing`,
`failures[].transient`; `drift.tooDeep`/`tooDeepLimit` in reconcile), `scopes.maxDepth` is opt-in, and the tenth command
is new. The 50 cases of `scope_outbox.spec.ts` of alpha.4 pass unchanged except the one the owner decided to split.
**Not done, on purpose**: a filter by tenant, a `driver.limits` channel (2.5, owner's call), the single sweep of
`enumerateRelations` for K partitions (2.5), retiring the legacy MySQL lock (2.5), the lease per batch.

## [2.4.0-alpha.4] — 2026-09-09 · the commands actually load in a consumer, `openfga:provision` boots what it needs and nothing more, and `capabilities()` for tenant code

**The problem, as reported (COGNITIV, 2026-09-09, first real driver switch `database` → `openfga` on
`2.4.0-alpha.3`).** `node ace openfga:provision` died on its first line — `TypeError: Cannot read properties of
undefined (reading 'get')` at `commands/openfga_provision.ts:46` — in any consumer. `this.app.config` does not
exist until `app.boot()` (`Application.init()` never calls `ConfigManager.process()`; `boot()` does — the
docblock of `get config()` in `@adonisjs/application` 9.0.1 says "after init" and is false), and the ace ignitor
only runs `boot()`+`start()` for a command that declares `startApp: true`; `openfga:provision` was the only one
of the nine with `startApp: false`. They recommended `startApp: true` "like the other eight". Two questions
came with the report: a blessed way to read `transactionalWrites` at runtime without `driver()`, and a note
that `sqlScopeEdges` does not cover a tree spread over three tables.

**The problem the panel found underneath, worse than the one reported.** `@jantstack/adonis-authz/commands`
— the module `node ace configure` registers in the consumer's `adonisrc.ts` — **was not an ace loader**. Ace
treats the imported module as the loader and calls `getMetaData()`/`getCommand()` on its namespace; the barrel
exported nine classes and nothing else, so in a consumer configured exactly as documented **the whole
`node ace` crashed at boot** (`TypeError: loaderInstance.getMetaData is not a function`, measured against the
published `build/`), not just `openfga:provision`. COGNITIV only ever reached line 46 because they had
registered the commands their own way (wrapping the barrel in a `ListLoader(Object.values(m))` in their
`adonisrc.ts`). **Why the suite saw neither**: no case built an ace kernel or instantiated a `BaseCommand` —
each command was judged through the pure function it exports (`permissionsOfCatalogs`, `reconcileLines`,
`unfreezePlan`…) with the config passed by hand, and three modules under `commands/` were imported by no spec
at all. Good discipline ("the decision lives in a pure function") that became the exact blind spot: here the
decision *is* the lifecycle, and that cannot be extracted into a pure function.

**Decisions.**

- **`commands/main.ts` is a real ace loader.** It exports `getMetaData()` and `getCommand(meta)` built with
  `ListLoader` over the nine command classes, next to the named class exports it already had (importing a class
  by name keeps working). **No `default` export, on purpose**: ace calls `getMetaData()` on the module namespace
  and never unwraps `default` (same shape as `@adonisjs/core/commands` and `@adonisjs/lucid/commands`); adding
  one would be a lie waiting for someone to "fix" the loader against it. **Migration**: if you registered the
  commands by wrapping the barrel in a `ListLoader(Object.values(m))` — the only way it worked before alpha.4 —
  remove the wrapper and register the module directly, `() => import('@jantstack/adonis-authz/commands')`,
  which is what `node ace configure` writes; the wrapper now fails because `Object.values(m)` includes the two
  loader functions and `ListLoader.getMetaData()` calls `serialize()` on every value (README, "Install").
- **`openfga:provision` stays `startApp: false` and boots the app itself — up to `boot()`, never `start()`
  (option B, not A).** In `prepare()`: from `created` → `init()`, from `initiated` → `boot()`, from `booted`/`ready`
  nothing (idempotent); if `app.config` still does not exist afterwards it says so and exits 1 (`Application.boot()`
  is a silent no-op outside `initiated`, so a bare `boot()` would repeat the `TypeError` in disguise). **Why not A**,
  measured with a minimal Adonis app: `start()` runs `start()`/`ready()` of every provider of the consumer and
  imports its preloads (`start/routes.ts`, `start/kernel.ts`…) — a `ready()` that touches the database killed the
  command before `run()` with the database absent, which is precisely the situation this command exists for; a
  preload importing `services/relations` builds the relations driver, which asks for the `OPENFGA_STORE_ID` this
  command is supposed to produce (circular); `app_provider.ready()` demands a valid `config/encryption.ts`; and
  `@adonisjs/lucid/services/db` asks the container for `Database` as soon as the app is booted. What B needs is
  only `config/*`, which `boot()` gives (≈80 ms: `config/*` plus `register()`/`boot()` of the providers) — and
  **the honest limit is written in the docblock**: "before there is a database" stays true (zero connections,
  no `start`/`ready`, no preload), "before there is a `.env`" does not — every `config/*` must be importable.
  Verified on Node 22.23.2 and Node 24.19.0 (COGNITIV runs 24).
- **`authorization.capabilities()` / `relations.capabilities()`** (question 1). A read-only, frozen, normalised
  copy of what the *active* driver declares, typed as `AuthorizationDriverCapabilities` (now exported from the
  main entry — it was not; `RelationsDriverCapabilities` already was). The roles one is `async` and is
  `(await this.driver()).capabilities` **and nothing else**: capabilities belong to the instance (`database`
  decides `transactionalWrites` from its options), so it resolves — and it resolves *through `driver()`*, inheriting
  its two gates (`requireTransactionalWrites` ⇒ 500 `E_AUTHZ_CONFIG`; `facts` without outbox or signature ⇒
  500 `E_AUTHZ_SCOPE_DRIFT_UNGUARDED`) and its cache. The auditor's red finding was the "obvious" alternative — a
  reading that resolves the driver by its own path so that it never throws, and caches it — which leaves `driver()`
  serving an instance that never passed the gates: a permanent bypass of the drift gate. The first case of the
  suite pins it: `capabilities()` first ⇒ the same 500, and `driver()` afterwards still throws. The relations one is
  synchronous (the driver is eager, its gate already ran). Every known key is present and only `true` is `true` —
  the same reading the write gates apply — so a third-party driver with partial or no `capabilities` reads
  `false`, **never `undefined`** (returning `undefined` would repeat the `stillGranting` bug: "I don't know"
  degrading into "no"). Mutating the copy throws and changes nothing; `{ transaction }` to a `false` driver is
  still 500 `E_AUTHZ_UNSUPPORTED` whether or not you asked first. `forRequest()` views delegate to the parent.
- **`sqlScopeEdges` and a tree in more than one table** (question 2): documentation now, with the trap the
  analyst found. The helper `LEFT JOIN`s the table against itself and **skips in silence** a row whose parent is
  not in that table — it cannot tell an orphan from a parent that lives elsewhere — so composing one
  `sqlScopeEdges` per table does **not** emit the edges between tables, `authz:reconcile --prune` deletes them
  from the store, and by invariant 9 (`rooted`) the whole subtree denies. Fail-closed and noisy, but a day lost
  and a wrong helper looking right. The README says it in those words and gives the recipe (your own
  `enumerateEdges`: `UNION ALL` across the tables, cursor over the child uuid, `parent IS NULL` = `app`, verify
  with `--dry-run`), marked *recipe not verified by the suite*. A case pins the sentence.
- **`provisionOpenFgaStore` validates the model before creating the store.** Until now `createStore` ran first,
  so an invalid catalog (colliding slugs, non-injective `holderTypes`) or one over the 262,144-byte ceiling left an
  orphan store without a model on the server per attempt, and the ceiling surfaced as a raw SDK error instead of
  500 `E_AUTHZ_MODEL_TOO_LARGE`. Now `assertFactsModelPublishable` runs first: zero requests if it is not
  publishable.

**What the suite gains.** A real ace kernel in process (`tests/helpers/ace.ts`) with two measured rules —
`AppFactory`, never `IgnitorFactory` (its `createApp()` calls `setApp()` and replaces the global app the whole
suite hangs from); and `kernel.exec` **does not rethrow** (assertions go on `cmd.error`/`exitCode`, never
`assert.rejects`, which would pass without proving anything). `tests/commands.spec.ts`: the barrel registered
exactly as `createAceKernel` does lists the nine (red before: the loader `TypeError`); metadata of the nine;
a static tooth (every file under `commands/` is in the loader); `openfga:provision` through the kernel without a
server — a mute HTTP stub records `POST /stores` and a spy in `catalogs` proves it read *this* config — with the
letter of both bail-outs, `--url` precedence, a consumer provider whose `ready()` throws and is never called (the
case that separates B from A and turns red under `startApp: true`), idempotence on an already-started app, the
"config still missing after boot" guard; the six commands with a pre-database bail-out executed for real; and,
against `OPENFGA_TEST_URL`, exit 0 with the store created and the published model carrying the four relations
per permission (`can_<P>` with `rooted`) and the merged relation type, plus `--store-id` writing a new model into
the existing store. `tests/capabilities.spec.ts` (D-5 first). `tests/scope_edges_docs.spec.ts`.

**What is NOT done, and why.** `startApp: true` on `openfga:provision` (measured: it breaks the use case the
command declares). Homogenising the other eight commands (they read `authz_*`; `startApp: true` is right there).
Reading `config/*` from disk by hand (a second config loader, diverging from Adonis's). A `commands.json` via
`@adonisjs/assembler` (a build dependency for six lines). A "best-effort" `capabilities()` that never throws, or
one that exposes anything beyond the port's type (`driverName`, deployment flags). Touching `driver()`, its
docblock or the README sentence about grepping for it: what is added is a new door, not a softer old one.
Refactoring the gates to read from the normalised defaults (the "nothing (no capabilities)" nuance of the
`requireTransactionalWrites` message would be lost). `composeScopeEdges` / `parentTable` on `sqlScopeEdges`
(one consumer, already solved by them; new public API on the `--prune` path) — deferred to 2.6 with the
executable multi-table case. And the three commands without a pre-database bail-out (`authz:unfreeze`,
`authz:catalog:prune-orphans`, `authz:scopes:relay`) still have no execution case: they resolve the manager from
the *global* container, so the harness would be two-headed (config of one app, manager of another) — honest as
"does not crash", dishonest as end-to-end; 2.6.

No breaking change: `capabilities()` reads a field that was already optional on the port; a third-party driver
changes nothing.

## [2.4.0-alpha.3] — 2026-09-02 · the relation write event gives the same guarantees as the roles one

**The problem.** COGNITIV verified `2.4.0-alpha.2` in real consumption (`relations/` as a key store) and
reported two things about the write event: (1) the provider did not wire `assertWrite`/`onRelationWrite`
into the service `RelationsManager` (`authz.relations`) and `defineConfig` did not even accept them — so
through the service there was **no policy gate and no audit trail at all** (their note that `requireActor`
was not wired either was inexact: it was, inherited from the root); (2) `RelationWriteEvent` had no
`transactional` flag, while `README.md` — written in lot L-6 — already promised *"`onWrite`/`onRelationWrite`
fire … with `transactional: true`"*: true for roles since L-3, **false for relations since the day it was
written**, and no case pinned the sentence. Sweeping the whole shape ("what does the roles event have that
the relations one does not?") found two more holes — invariant 13 (`indeterminate: true` when the deadline
elapses) had **zero** mentions in `src/relations/manager.ts` although both relation drivers have a deadline
to elapse, and `purgeObject`/`purgeSubject` emitted **no event whatsoever** — and the contract tester found
four of its own, three of them fail-open or loss of audit, not cosmetics: **H1** `onRelationWrite` was
called with neither `await` nor `try/catch`, so a failing audit sink turned an already-applied `relate`
into an error for the caller (who would retry something done) and an `async` hook that rejected vanished as
an unhandled rejection; **H2** `assertWrite: async (ref) => { throw … }` compiles (a `Promise<void>` is
assignable to `void`), the promise was discarded and **the write went in** — a policy gate that refused
nothing, in silence, and exactly what COGNITIV had assumed the other way round; **H3** the `actor` was only
checked for *presence*, so `{ uuid: 'A#B' }` travelled to the event and `actor: {}` satisfied
`requireActor`; **H4** the README sentence above, published without its case.

**The decision (owner 2026-09-02 (2), the light procedure: contract tester before, red→green with mutants,
auditor on the diff).** Parity, by precedent, not by invention — every mechanism below is the one the
roles manager already has, replicated line for line (`#write`, `#notify`, `#logHookFailure`,
`#transactional`, `#writeOptions`' actor validation):

- **`RelationWriteEvent` mirrors `AuthzWriteEvent`**: one interface with optional fields
  (`transactional?: true`, `indeterminate?: true`, `subject?`, `object?`, `relation?`), **not** a
  discriminated union. `operation` is now `'relate' | 'unrelate' | 'purgeObject' | 'purgeSubject'`, so the
  event no longer `extends RelationRef` (whose `operation` stays `'relate' | 'unrelate'`: the published type
  of the R-13 hook is untouched). A sink that reads `event.object.id` without narrowing gets a type error
  under `strict` (`object` is absent on `purgeSubject`): narrow on `event.operation`, or `event.object?.id`.
- **`transactional: true`** on the four writes inside `{ transaction }`; absent — never `false` — otherwise;
  `{ transaction: undefined }`/`null` count as none. Pinned by the deferred-sink recipe the README sells
  (`trx.after('commit')`): rollback ⇒ zero firm records and zero tuples, commit ⇒ one and one, on SQLite
  (file), PostgreSQL and MySQL, for `relate`/`unrelate` and for the purges. The published runner
  (`runRelationsDriverContract`) now judges the **event** as the other face of `transactionalWrites`: with
  `true`, the eight events of the four writes inside a transaction carry the flag; with `false`, a refused
  write emits nothing.
- **Invariant 13 on the relations port**: an elapsed deadline notifies `onRelationWrite` with
  `indeterminate: true` **before** propagating the 503 `E_AUTHZ_BACKEND_TIMEOUT`, for the four writes,
  with the rest of the event intact; inside your transaction with `transactional: true` as well (PostgreSQL
  leaves it aborted, MySQL alive, SQLite cannot elapse a deadline — `SQLITE_BUSY`, no event — measured per
  engine); on `openfga` measured against a socket that accepts and never answers, without a server, and
  never with `transactional` (gate 1 makes `{ transaction }` impossible there). A 503 that is not a
  timeout, a 422, an `assertWrite` that throws and the freeze emit nothing and call nothing.
- **`purgeObject`/`purgeSubject` notify one event per call** — `{ operation: 'purgeObject', object,
  partition, actor? }` (no `subject`, no `relation`) and `{ operation: 'purgeSubject', subject, partition,
  actor? }` (no `object`, no `relation`) — even when the driver sweeps both spellings of the partition uuid
  (the relations manager does not canonicalise; `scopes.detached` emits one per spelling because there the
  manager does — a divergence on purpose, pinned), even when nothing is deleted (the auditable fact is the
  request), and **without a count**. New runner case **R-17** (20 → 21 cases; the runner runs four times in
  the suite).
- **H1 closed**: `onRelationWrite` is awaited, a throw or a rejection is logged naming the operation and
  swallowed; the write stands. **H2 closed, fail-closed**: an `assertWrite` that returns a thenable is
  **500 `E_AUTHZ_CONFIG` before the driver** (the message names `assertWrite`, "synchronous", the fail-open
  it prevents and the recipe: the policy that needs the actor, the database or an `await` goes in your
  service, before `relate`/`unrelate`), whether the promise would reject or resolve; the discarded promise
  does not surface as an unhandled rejection. **H3 closed**: the `actor` is validated with the same
  `assertSubject` as roles (422 `E_AUTHZ_INVALID_IDENTITY` before the driver, on the four writes) and only
  then required — `requireActor: true` + `actor: {}` is the identity 422. **H4 closed**: the sentence is
  now true and `tests/trx_docs.spec.ts` pins it.
- **Wiring, one home**: `relations.assertWrite`, `relations.onRelationWrite` and `relations.requireActor`
  in `defineConfig` (not in `hooks`; the stub declares them there and a case compiles it), passed by the
  provider. `relations.requireActor ?? requireActor`, exactly like `relations.requireTransactionalWrites`,
  with the three directions pinned (inherit, require here only, waive here only).

**BREAKING** (behaviour, only for a deployment that already had `requireActor: true`): **`requireActor` now
reaches `purgeObject`/`purgeSubject`** — a mass deletion of keys is the write that most needs an actor, as
`scopes.detached` already does on the roles port — so a purge without `actor` is 422 `E_AUTHZ_ACTOR_REQUIRED`
(fail-closed: stricter, never looser). The purges take **`RelationPurgeOptions`** (`transaction` + `actor`)
instead of `RelationTransactionOptions`; a caller passing only `{ transaction }` is unchanged.

**BREAKING** (behaviour, for any caller): **the reads throw**. `check`/`listSubjects`/`listObjects`/`membersOf`
with an object type or a relation **not declared** in `defineRelationsConfig` — or with the relation missing
(`undefined`) — are now 422 `E_AUTHZ_RELATION_TYPE_UNKNOWN` / `E_AUTHZ_RELATION_UNKNOWN` **instead of answering**
`false` / an empty page (F-05 on the reads, the alpha.3 closing lots). It is invariant 5 (*an invalid question
is a 422, never a silent `false`*) and it is what shut the enumeration of a real `role_binding` through the
relations port, but a consumer with `if (await authz.relations.check(…))` and no `try` around it now sees a
422 where it saw `false` for a typo in a relation name. Fix the name, or catch the 422.

**BREAKING** (behaviour, for any caller): **`actor: null` is 422 `E_AUTHZ_INVALID_IDENTITY`** on the four
relation writes, whatever `requireActor` says. In alpha.2 only the *presence* of the actor was checked, so
`relate(…, { actor: user ?? null })` went in as "no actor"; since the actor is validated as an identity
(H3), `null` is a malformed actor, not an absent one — the same rule as the roles port. Pass `undefined`
(or omit the key) to mean "no actor"; nothing is written and nothing is notified on the 422.

**What is NOT done, and why.** No count of deleted tuples in the purge event (it would break the port for
third-party drivers, and inside a transaction it would be a number a rollback contradicts — enumerate
before purging). The purges do not go through `assertWrite` (widening `RelationRef.operation` would change
the published type of the R-13 hook; a negative case pins it). `indeterminate` is not in the published
runner (no portable way to provoke a deadline in a third party's harness; the roles runner does not have
it either). `authz:relations:reconcile` still writes through the destination driver and emits no events
(the documented exit of the barriers). `RelationsManagerOptions.onRelationWrite` keeps its `void` return
type — a sink written as `(e) => events.push(e)` would stop compiling under `void | Promise<void>`, since a
free return is only assignable to bare `void`; the new `relations.onRelationWrite` key is typed
`void | Promise<void>`. `group#member` hardcoded (COGNITIV's third point) goes to the 2.7 backlog.

**What COGNITIV verified in our favour**: the other seven of their nine requirements held on alpha.2, and
`requireActor` was already wired through the service; the docs line they asked for (`assertWrite`
synchronous, pure, without `actor`) is in the README with its case — and now with a tooth.

### The closing lot · the auditor's NO APTA verdict on the alpha.3 diff (owner 2026-09-02 (2c))

**The problem.** The adversarial audit of the alpha.3 diff (`alpha3-auditor.md`, reproduced against the
real server) found one critical and two high findings, plus four medium/low ones:

- **🔴 F-05 did not cover `purgeObject`** — nor `purgeSubject`, `check`, `listObjects`, `listSubjects`.
  It was pre-existing in alpha.2 (F-05 was born for `relate`/`unrelate`, the two writes that *compose* a
  tuple), but sitting in the two functions alpha.3 had just rewritten and documented. In the documented `openfga`
  deployment — roles `facts` and relations in the **same store** — `purgeObject({ type: 'role_binding',
  id: R }, S)` composed, byte for byte, the id of the real binding and **deleted it with proof of zero**:
  `authorize(U, read, S)` went from `true` to `false`, zero tuples left, and a clean `purgeObject` audit
  event. Neither `assertWrite` (purges skip it) nor `requireActor` (a legitimate tenant actor suffices)
  stood in the way. **🟠** By the same hole `listSubjects('assignee', role_binding)` enumerated the holders
  assigned to a role in a scope through the relations port, with no catalog, no `within`, no
  `requireActor` and no role visibility.
- **🟠 `assertWrite` was still fail-open by the half H2 had not looked at**: `assertWrite: (ref) =>
  allowed.has(ref.object.type)` compiles under `--strict`, the returned `false` was ignored and **the write
  went in**; a thenable *function* (a lazy promise) dodged the `typeof result === 'object'` guard the same way.
- **🟡** The hook, now awaited, is on the critical path and — with `{ transaction }` — inside the caller's
  transaction, and nothing said so. **🟡** A purge on `openfga` is multi-request; one that failed after
  deleting part emitted **nothing**, while the README and the docblock promised *"that write did not
  happen"*. **⚪** `purgeSubject` did not validate its subject in the manager; the event aliased the caller's
  objects; `actor: null` had silently become a 422; `relations.requireActor: false` under a root `true` had
  no warning; invariant 13 is not judged by any published runner.

**The decision (owner, by precedent: L-0 / fail-closed / parity), what changed and how it is pinned:**

- **F-05 covers the eight operations of the port** — it runs first on `purgeObject` (the type),
  `purgeSubject` (the userset of its subject), `check`/`listSubjects`/`membersOf` (the pair), `listObjects`
  (the type it names and the relation it names), and on the userset of any subject, in the manager **and** in
  both drivers (defense in depth, as L-0 and L-5: `manager.driver()` is not an exit) — 422
  `E_AUTHZ_RELATION_TYPE_UNKNOWN`/`E_AUTHZ_RELATION_UNKNOWN`, zero client calls, zero events. The exploit is
  pinned against the shared store on the real server, by the manager and by the driver (`authorize` **stays**
  `true`, tuples intact, spy at zero), with the doubles, and on the `database` driver; the published runner
  (`runRelationsDriverContract`) plants it on the six for any third-party driver (new core case, 21 → 22; the
  runner runs four times). `reconcileRelations` is untouched: it reads through `enumerateRelations`, not
  through these.
  **Second pass (cierre-2, owner 2026-09-02 (2d)).** The first closing lot did this by making `relation`
  optional on the one shared function (`if (relation === undefined) return`), and the auditor's re-attack
  found the regression that opened: `relate(u, undefined, doc, p)` — a controller forwarding a missing
  `request.input('relation')` — no longer hit F-05 in the manager (before, `isDeclared('document',
  undefined)` was `false` ⇒ 422 with zero calls): the published double **wrote the tuple**, `openfga` sent
  the invalid question to the server and got a **503** back (invariant 5 inverted: an invalid question
  reported as a backend outage), and only the `database` driver's own grammar saved it (the two drivers
  answered differently); by the same root `listSubjects(undefined, doc, p)` returned the **union** of every
  relation's holders (the `Read` went out without a relation filter), and `membersOf` — the eighth
  operation with `(object, relation)` — had no F-05 at all, so a third-party driver declaring
  `membersOfNative: true` on a shared store reopened the enumeration. The fix is **two functions, not an
  optional**: `assertRelationDeclared(config, object, relation)` is strict again (a missing, empty or
  non-string relation is 422 `E_AUTHZ_RELATION_UNKNOWN`, zero calls) and `assertObjectTypeDeclared` (type
  only) serves the one operation that names no relation; `membersOf` runs the strict one before its
  capability check, in the manager and in the `database` driver. Pinned with the doubles, on `database`, on
  `openfga` against the real server (manager and driver: 422 with zero client calls where there was a 503,
  and the union gone), and in the published runner; the mutant (accept `undefined` again) puts the
  `relate`-without-relation case back in red. Two low findings closed with it: `markPartialWrite` on a frozen
  error no longer throws a `TypeError` that would replace the real 503 (it returns the original unmarked,
  losing only the `indeterminate` of that purge), and the `openfga` relations driver classifies a timeout with
  the strict `isTimeoutLike` of `backend_guard.ts` — the same one the roles driver imports — instead of a
  substring match on the message (an error whose text mentioned "timeout" was reported as 503
  `E_AUTHZ_BACKEND_TIMEOUT` with `indeterminate: true` without having deleted anything).
- **`assertWrite` does not return verdicts** — any returned value other than `undefined` is 500
  `E_AUTHZ_CONFIG` before the driver: a promise (the H2 message, unchanged), a thenable function (same
  message), `false`, `true`, `null`, a string, an object (a message naming "no devuelve veredictos" and the
  recipe). One condition closes the four shapes; the mutant (remove it) lets the write in.
- **The hook has no deadline, on purpose** (parity with `hooks.onWrite`; a deadline is a design decision of
  its own): the README now says the sink is awaited, on the critical path and inside your transaction, that
  a sink that never resolves keeps it open, and to defer anything slow to `trx.after('commit')` or a queue.
- **A purge that fails after deleting is `indeterminate: true`** (invariant 13, "may have happened"). The
  mechanism, the minimal one that does not touch the port's signatures: the `openfga` driver counts what
  each `deleteTuples` batch removed and, if the failure comes after the first one, propagates the error
  marked with **`markPartialWrite`** (exported; a non-enumerable `partialWrite: true` property — the class
  and the `code` are unchanged: 503 `E_AUTHZ_BACKEND_UNAVAILABLE`, 500 `E_AUTHZ_PURGE_INCOMPLETE`); the
  manager's `#write` notifies `indeterminate: true` for a timeout **or** a partial write, before propagating.
  Pinned against the `:8101` with a spy that fails the request following a `deleteTuples` (deleted ≥ 1 ⇒
  event with `indeterminate: true` and the 503), with its control (failure on the first `Read` ⇒ nothing
  deleted, no event), and with doubles. *"That write did not happen"* is now stated where it is true: a 422,
  `assertWrite`, the freeze; a 503 that is not a timeout on `relate`/`unrelate` and on any `database`
  write (one statement); on `openfga` purges only while nothing had been deleted. A third-party driver whose
  purge is multi-request has the same duty (documented on the port).
- **⚪ closed**: `purgeSubject` validates its subject in the manager (`assertSubject`, parity with H3: a
  malformed holder, `{}` or `null` is 422 before the driver and never reaches the event; `isRelUserset`
  tolerates `null`); the event is a **copy** of the caller's identities (mutating `object`, `partition`,
  `subject` or `actor` afterwards does not rewrite the audit record, and a hostile sink cannot reach the
  caller's constants — the `actor` keeps whatever extra fields it carries, by design); `actor: null` is
  announced as BREAKING above; the README says that `relations.requireActor: false` under a root `true`
  overrides the root **silently**. Invariant 13 in the published runners is registered for 2.6+ (it affects
  the roles runner too: its own lot).

**Numbers.** Suite with the `:8101`: 1074 / 1095 / 1190 / 1190 → **1107 / 1131 / 1226 / 1226** (sqlite /
sqlite-file / pg / mysql; +33 / +36 / +36 / +36 — the three extra outside `:memory:` are the real-transaction
cases B2, C3 and E4, which need a pool ≥ 2). Every new case was seen red first, and each mechanism has a
mutant that turns it red again (the lot report lists them). The closing lot adds 26 cases in every mode —
1133 / 1157 / 1252 / 1252 — each seen red first (the auditor's own reproductions, run as the red) and each
with its mutant (`alpha3-cierre-informe.md`); the second pass adds 8 more — **1141 / 1165 / 1260 / 1260** —
with the auditor's re-attack reproductions as the red and the "optional relation" mutant putting the
`relate`-without-relation case back in red (`alpha3-cierre2-informe.md`).

## [2.4.0-alpha.2] — 2026-09-02 · expiry on the relation tuple (R-15) and `{ transaction }` on both ports (the `{trx}` panel)

**The problem.** COGNITIV verified `2.4.0-alpha.1` against its nine requirements and got 7 ✅; the two ❌ were
**expiry on the relation tuple** (#5, deferred to 2.6 on an assumption that was false for the customer) and
**`{ transaction }` on the writes** (#6: "the key and its `pdp_version` in the same transaction"). The owner
brought both forward as `2.4.0-alpha.2`, with one framing for the second that decides the whole release:
*"it has to work whichever driver the client picks, and the client adjusts"* — no consumer's code is a
criterion, each driver declares what it can do. R-15 is additive and went straight in. `{ transaction }` went
through a panel (architect, adversarial auditor, judge) on the one question that matters: **an OpenFGA tuple
cannot enter a SQL transaction** — the store is another service and there is no two-phase commit — so what
can `openfga` honestly promise, and what does `database` have to prove before promising anything?

**The decision (the judge's verdict (C), 90/100; owner 2026-09-01 (3)).** `{ transaction }` **for real in
`database`, on both ports, and an active refusal in `openfga`**, with the capability declared and two gates:

- **`transactionalWrites`** on both capability interfaces, meaning **exactly** *"both or neither with YOUR
  transaction"* — never *"not lost"*, no intermediate value. `database` declares `true` (roles and relations);
  `openfga` declares `false` explicitly and cannot declare anything else.
- **The rule that governs every line of it: the write goes through your transaction; the authority never
  does.** The `INSERT`/`UPDATE`/`DELETE` and its own "does it exist?" read go through your open Lucid
  transaction of the driver's connection; the freeze barrier, the catalog, `resolveChain`, F-05 and
  `assertWrite` are read through the engine's own connection before the first statement on yours. The
  price is declared: **`{ transaction }` requires a pool of at least 2**; with a pool of 1 the write is 503
  `E_AUTHZ_BACKEND_TIMEOUT` at `freezeTimeoutMs` with zero statements on your transaction — never a hang,
  never a bypass. A pool-of-1 deployment declares `transactionalWrites: false` on the driver.
- **Gate 1, per call, always on**: `{ transaction }` on a driver declaring `false` is 500 `E_AUTHZ_UNSUPPORTED`
  naming driver and operation with zero driver calls, in the manager **and in the `openfga` drivers
  themselves** (`manager.driver()` is not a way out). **Gate 2, opt-in**: `requireTransactionalWrites: true`
  makes a wrong deployment fail **when the driver is resolved** — it does not start — without disabling a
  driver that is merely registered. Not "fails to construct", which both panelists rejected.
- **Judged by census, not by the answer**, on SQLite (file), PostgreSQL and MySQL: rollback ⇒ zero rows /
  zero tuples, commit ⇒ applied, the uncommitted write invisible to the authority, three foreign transactions
  ⇒ 500 with zero statements; both faces of the pair are mandatory in both published runners.
- **What the engines do when the write lives as long as your transaction, measured**: a UNIQUE clash or a
  deadlock inside your transaction is **409 `E_AUTHZ_WRITE_CONFLICT`** that *poisons* it (PostgreSQL leaves
  it aborted, MySQL leaves it alive, SQLite file answers `SQLITE_BUSY` at once as 503); a deadline elapsed
  inside it publishes `onWrite` with `indeterminate: true` *and* `transactional: true`.
- **Before a single line of `{ transaction }`, three holes of today were closed** (lots L-0 and L-1): F-05
  lived only in the `RelationsManager` while the port's docblock claimed the drivers re-validated
  (measured escalation through `manager.driver()` and through `reconcileRelations`); the freeze barrier was
  read through the caller's transaction (a snapshot taken before the freeze skipped it — measured on the
  three engines); `sqlScopeOutbox` ignored `connection` and accepted the whole `db` as a transaction; and
  nothing in `relations/` looked at the freeze.
- **What `openfga` offers instead**: a **recipe by direction** in the README — permissive writes after the
  commit, restrictive ones before or inside, in line — with which both failure modes land fail-closed. It is
  not "both or neither", **it does not compose** (a `grant` and a `revoke` of the same fact in one unit of
  work end up granting — measured), and **the package does not automate it** (pinned against the server: no
  commit hook, nothing lands later). And the README no longer says "atomic" of `openfga` in relation to the
  caller's transaction, in any form — a grep with teeth keeps it that way.

**What is NOT done, and why — with the numbers that decided it.**

- **No outbox of facts or relations for `openfga` (option (A), 20.5/100, disqualified by the stop rule).** It
  was measured, not argued: with facts enqueued in the consumer's transaction and drained by a relay, a
  `revoke`/`deny`/`unrelate` that is *queued* leaves the store answering `true` — **fail-open for 1.16 s median
  and 2.28 s tail** on the local server; the drain is a single writer (**131.5 entries/s, not parallelisable**),
  so a burst of **5,000** grants is a **38 s** window during which every revoke of any tenant waits behind
  them; an entry parked after `maxAttempts` (5) is a revoke that **never happens**, and in a `facts`
  deployment the maintenance pass writes and deletes no fact at all, so nothing repairs it; and the
  **resurrection** (auditor 🔴 1, measured): a `grant` enqueued, an inline `revoke` before the relay (a safe
  no-op — the tuple does not exist yet), the relay lands the grant ⇒ `authorize` is `true` for ever, where
  `database` answers `false`. A consumer's database would also become a privileged writer of the PDP.
- **No "accept `{ transaction }` in `openfga` and write outside it"** (option (B)): in `facts` a fact write
  touches zero SQL rows, so there is no SQL half to enrol — the parameter would do nothing. A signature that
  lies.
- **No provisional 30 s grant** (option (E)): its rollback leaves up to 30 s of access *created by the package*,
  and a provisional tuple with `valid_until = now + 30 s` is indistinguishable from a legitimate expiry, so
  the next `grant` with `expiresAt` omitted would *preserve* it (invariant 10) and make it permanent.
- **`resolveChain` does not receive the transaction** (§6.2 of the verdict): creating a scope and granting on
  it in the same transaction is 422 `E_AUTHZ_UNKNOWN_SCOPE`, fail-closed, and pinned as the correct answer.
  Handing the driver the transaction would put the authority back inside the caller's snapshot. The recipe
  (a resolver that closes over your transaction; notify `scopes.*` first when you move the tree and write
  facts together) is documentation; changing the config port would be breaking and is another phase.
- **The delegation API refuses `{ transaction }`**: `withAuthzCatalogWrite` is the cross-process serializer
  of the catalog (invariant 14) and moving it into the consumer's commit would defeat it.
- **The freeze window is now as long as the consumer's transaction** (§6.3): a write that passed the barrier
  commits when *its* transaction commits. Not a new defect — the freeze never promised "no write enters the
  window" — but the arm is longer and the README says so.
- **The `true` face runs only where a second connection exists** (`sqlite-file`, PostgreSQL, MySQL). The
  default suite (`:memory:`) judges the `false` face and pins the pool-of-1 503; the engine jobs of CI are
  not optional for this capability, and a third-party driver judged only on `:memory:` never sees those cases.
- **`package.json` still says `2.4.0-alpha.1`**: the release is the owner's.

**BREAKING, grouped.**

- **Deployment**: `{ transaction }` — on `scopes.attached/moved/detached` (the outbox) as well as on the
  fact and relation writes — **requires a connection pool of at least 2**; on a pool of 1 it is 503
  `E_AUTHZ_BACKEND_TIMEOUT` at `freezeTimeoutMs` (new config, default 5000 ms). The three outbox rollback
  cases of the suite moved off `:memory:` for that reason (L-1).
- **Port / types**: `transaction` is declared on `WriteOptions` and on `RelationTransactionOptions`;
  `revoke`/`deny`/`removeDeny` and `purgeObject`/`purgeSubject` receive `options`; `transactionalWrites` is a
  **mandatory** field of `AuthorizationDriverCapabilities` and `RelationsDriverCapabilities`, and both faces
  need a case (a third-party driver declares it or its harness fails at registration); the harness capability
  `transactions` is renamed `transactionalWrites`; new harness hooks `transactions` (`begin` + `census`)
  with Lucid defaults exported from `/testing` (L-2, L-3, L-4). `FreezeSqlOptions.client` is gone (L-1).
  `assertCallerTransaction` is exported from the root.
- **Behaviour**: the `openfga` drivers refuse `{ transaction }` also when called directly (`manager.driver()`),
  where until L-5 they wrote the tuple ignoring it (L-5); F-05 is enforced in both relations drivers —
  `relate`/`unrelate` of an undeclared type/relation are 422 through `manager.driver()` and through
  `reconcileRelations`, which now counts `skipped.undeclared` and exits ≠ 0 (L-0); relation writes pass the
  freeze barrier and `authz:relations:reconcile` runs under the durable window (L-1); inside the caller's
  transaction a UNIQUE clash / deadlock is 409, not re-read (L-3, L-4).
- **Schema**: `authz_relations.expires_at` (`DATETIME(3)` nullable, R-15) and
  `authz_relations.subject_relation NOT NULL DEFAULT ''` (L-4b: with `NULL` the unique index only guarded
  usersets, and two concurrent `relate`s of the same holder committed two rows). Both recipes are in the
  README, **in that order and in the same deploy** as the package upgrade (until the L-4b recipe runs, the
  old partition trigger refuses every holder `relate`); both are executed by the suite on the three engines.

**Deferred and registered.**

- **(F) — `authz_*` as a durable log of facts also in `facts`, with the store as a rebuildable projection** —
  is the only route by which `openfga` could one day have real `{ transaction }`; it derogates "the facts live
  in the PDP" (a signed decision of 2026-08-28) and still would not give "both or neither" in the PDP. **Registered
  as an open question for 3.0** (owner 2026-09-01 (3), decision 2); zero work now.
- `includes` with `from` in `relations/`; deny with expiry; read-only Lucid models — still 2.6+.

**Lots, newest first** (each with its own problem → decision → what is not done below): L-6 (docs with
teeth), L-5, L-4b, L-4, L-3, L-2, L-1, L-0, R-15.

### Lot L-6 · the docs of the `{trx}` stretch, with teeth (the `{trx}` panel's §7 · L-6, §1.3, §6.2, §6.3)

**The problem.** Six lots had each left their paragraph in the README — the L-3 section sat in the middle of
the outbox section, the L-4 paragraph repeated half of it, the 409 "poisons your transaction" was told three
times — and three things the verdict required were still missing: the recipe by direction for `openfga`, the
freeze sentence widened to the caller's transaction, the `resolveChain` limit with its recipe; plus a roadmap
line that was false since L-2 ("the manager fails to construct") and a changelog without a consolidated head.
Documentation with no case behind it is what this package calls a false promise.

**The decision.** One README section, [Writing inside your transaction](./README.md#writing-inside-your-transaction-240-alpha2),
that says what `{ transaction }` means on each call (writes / enqueues / refused), the rule, the pool
requirement, the per-engine table (facts and tuples in one table), the `resolveChain` limit with two recipes,
**the recipe by direction** for `openfga` with its limits, and what the suite can and cannot prove for a
third-party driver; the freeze paragraph gains the `{ transaction }` arm; the two migration recipes are
introduced together, in order. Every sentence is anchored to a case or a measurement of lots R-15…L-5, and
**three new cases** keep it so:

- **A grep with teeth** (`tests/trx_docs.spec.ts`): no line of the README says "atomic" of `openfga`/FGA/
  tuple/store and of the caller's transaction at once, and the recipe section does not contain the word in
  any form (mutant: one sentence "effectively atomic with your transaction" in the recipe ⇒ red).
- **The letter of the 500** (pattern of `freeze.spec.ts`): the gate's message names the driver, the
  operation, the reason, both ways out (`database`, `requireTransactionalWrites` — and
  `relations.requireTransactionalWrites` only on the relations port), "fails at boot" and "without
  `{ transaction }` the same call goes through"; the driver's own message adds "`manager.driver()` is not a
  way out", the tree outbox and "no outbox for facts and relations"; the manager throws that letter byte for
  byte; the README documents it (mutant: dropping the `database` way out from the letter ⇒ red).
- **The recipe, measured against the server** (`contract.spec.ts`, group L-6): **the package does not
  automate it** — `{ transaction }` on `openfga` registers no commit hook on the real transaction, calls the
  client zero times and lands nothing on commit (mutant: the driver hooks `after('commit')` instead of
  throwing ⇒ red) — and the recipe itself: permissive after commit (rollback ⇒ nothing granted), restrictive
  in line (rollback ⇒ revoked anyway, repairable), and **it does not compose** (`grant` + `revoke` of the same
  fact end up granting). Two measurements the recipe section now carries: Lucid's `after('commit')` runner
  **swallows** what the handler throws (a failed grant there is silent), and "inside" needs a pool of at
  least 2 even with `openfga` (the freeze barrier is SQL: a `revoke` inside an open transaction on a pool
  of 1 is the barrier's 503, not a revoke — on a pool of 1 the restrictive write goes *before*).

**Findings in the existing docs, corrected.** "The package's own suite does that" (a resolver closing over
the transaction, README since L-3, from §6.2 of the verdict) — no case does; rewritten as what it is (your
callback can read through `trx`; no case of this package exercises it). `CLAUDE.md`'s header still said the
published version was 1.1.0 / `2.0.0-alpha.1`. `roadmap-2.0.md` listed `listDenies` as deferred (it landed in
2.1) and `{trx}` as "fails to construct" (rejected by both panelists in L-2).

**What is NOT done.** No new runner case (the published contracts are unchanged since L-4; counts do not
move). The measured recipe runs only with `OPENFGA_TEST_URL` (it needs the real driver). No `version` bump.

### Lot L-5 · `openfga` refuses `{ transaction }` with teeth, on both ports (the `{trx}` panel's verdict (C), §7 · L-5)

**The problem.** L-2 put gate 1 in both managers and L-3/L-4 made `database` honour `{ transaction }` for real.
What was left for `openfga` was a declaration (`transactionalWrites: false`) enforced only by the manager: whoever
entered through `manager.driver()` — the documented exit from every barrier — or through `reconcileRelations` reached
a driver that **ignored** `transaction` and wrote the tuple anyway. That is a write that pretends to be inside your
transaction and that your rollback does not undo: exactly the fail-open the capability declares it cannot avoid. And
the refusal itself had only been observed on in-memory doubles, never against the real server.

**The decision — the package's reason, not any consumer's.** **An OpenFGA tuple cannot enter a SQL transaction**: the
store is another service and there is no 2PC. `transactionalWrites` means exactly "both or neither" with *your*
transaction; `openfga` cannot promise it and says so with an **explicit** `false` (own property, not an omission).
The consumer reads the capability and adjusts. Enforced, now, by two gates in depth:

- **The driver re-validates** (same lesson as F-05 in L-0): `grant`/`revoke`/`deny`/`removeDeny` and
  `relate`/`unrelate`/`purgeObject`/`purgeSubject` of the `openfga` drivers refuse `{ transaction }` as their **first
  line** — before identity, catalog, F-05, `Read` or `Write` — with the same class, `code` (500
  `E_AUTHZ_UNSUPPORTED`) and letter as gate 1, plus the sentence that entering through `manager.driver()` is not a
  way out (`UnsupportedOperationError.transactionalDriver`). `revoke`/`deny`/`removeDeny` (roles) and
  `purgeObject`/`purgeSubject` (relations) now accept the `options` the port already declared since L-2.
- **Measured against the real server (`:8101`), never a double**: a spy on the driver's real FGA client
  (`tests/helpers/fga_spy.ts`) proves **zero calls** — not one `Write`, `Read`, `Check` or `BatchCheck` — through the
  manager and through the driver directly, with no `onWrite`/`onRelationWrite`; without `transaction` the same call
  enters. **Mutant**: with the manager's gate switched off the cases stay green because the driver refuses by itself;
  with both switched off they go red with a real write in the store.
- **Boot**: `requireTransactionalWrites: true` + `default: 'openfga'` with the real driver does not start — 500
  `E_AUTHZ_CONFIG` when resolving (roles: `driver()`, `authorize`, `grant`) and when building the `RelationsManager`
  through the provider (root flag or `relations.requireTransactionalWrites`), naming the driver and the capability,
  zero calls to the store. And `default: 'database'` with `openfga` merely **registered** starts: the factory is never
  invoked (gate 2 does not disable a driver that is only registered — this is what killed the roadmap's "fails to
  construct").
- **A parity case that fixes the asymmetry on purpose** (`relations_bridge.spec.ts`, same catalog, same tree, same
  call inside ONE consumer transaction): `grant(alice, 'r0', app, { transaction })` and
  `relate(u, 'viewer', doc, p, { transaction })` are **200 in `database`** (written through your transaction,
  committed with it, seen by the census) and **500 in `openfga`** (zero client calls, the store without the tuple) —
  **and that is the correct answer**. It is the first capability of the package that is not portable between
  drivers, and the owner's framing makes it the design, not a defect. In `:memory:` (pool 1) the `database` half shows
  what pool 1 honestly gives (503 at the freeze barrier, zero statements through the transaction) and the `openfga`
  half is identical in all four modes; no branch is a skip.
- **A grep** fixes that the `openfga` sources and docblocks never say "atomic" of the consumer's transaction (the
  lines that say a FGA `Write` is atomic *inside the store* — invariant 6 — stay), that both drivers declare
  `transactionalWrites: false` literally, and that the comment beside it names the reason (no 2PC) and the alternative
  that does exist: `scopes.outbox` for the **tree** (enqueues in your transaction, `authz:scopes:relay` applies). For
  **facts and relations there is no outbox** — discarded by the panel (measured fail-open during the lag).

**What is NOT done, and why.** No outbox for facts or relations (above). `openfga` does not "accept and write outside
the transaction": that would be the silent write the capability forbids. The README recipe by direction, the
sentence about the freeze window and `roadmap-2.0.md:103` are lot L-6. The published runners are unchanged (their
`whenFalse` face already runs against the real store); the counts of `contract_harness`/`relations_harness` do not
move.

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

### R-15 · expiry on the relation tuple (the first lot of the release; additive)

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
