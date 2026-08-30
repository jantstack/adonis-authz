# Changelog

## [Unreleased] — 2.2.0

Phase 3 of the 2.0 roadmap: `catalog/` — roles global or local to a scope.
Lot 3A below is the prerequisite: the internal identity of a role is its
**uuid** in both drivers, and the OpenFGA binding ids carry that uuid. No
answer of the contract changes (the judge passes identically); the store
format does. Lot 3B adds the owner, and lot 3D makes that uuid the identity
of a role in the **public port** too.

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
