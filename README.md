# @jantstack/adonis-authz

Driver-based **authorization engine for AdonisJS 7 + Lucid**: hierarchical scopes with downward-only inheritance, explicit denies that always win, expiring assignments and polymorphic holders — behind a single contract, so the backend is a config choice, not an architectural commitment.

Ships two drivers that pass **the same executable contract suite**:

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

## Install

```bash
npm i @jantstack/adonis-authz
node ace configure @jantstack/adonis-authz
node ace migration:run
```

`configure` registers the provider, the commands and the `appAccess` middleware, defines the env variables, and **publishes into your project** what belongs to you: the migration for the `authz_*` tables and two config files (`config/authorization.ts` for drivers, `config/app_acl.ts` for your role catalog).

For the OpenFGA driver, also install its SDK (optional peer): `npm i @openfga/sdk`.

## Semantics (what every driver guarantees)

1. **Hierarchical scopes, inheritance only downward.** A grant on a scope authorizes on that scope and all its descendants — never on siblings or ancestors. The engine only reserves the root (`app`); every other level is yours, declared by the `resolveAncestors` resolver you inject.
2. **Explicit deny wins.** A deny anywhere in the scope chain blocks the permission even if a role grants it. Removing the deny restores it.
3. **Expiry is observable.** An assignment past its `expiresAt` grants nothing — enforced in SQL by the `database` driver and by an FGA *condition* in `openfga`, so no scheduler is needed.
4. **Polymorphic holders.** Users, admins, API integrations — any model with a morph name. Two holders with the same uuid and different type never cross.
5. **Deny by default.** Unknown permission, role without it, or no valid assignment → `false`. `authorize()` never throws.
6. **Idempotent writes.** Re-granting doesn't duplicate (it refreshes the expiry); re-revoking is a safe no-op.

These aren't prose promises: they're `tests/…` cases in the contract suite below.

## Your domain stays yours

Nothing about your model is hardcoded. Three seams:

```ts
// config/authorization.ts (published by configure)
export default defineConfig({
  default: env.get('AUTHZ_DRIVER', 'database'),

  // 1. Your guards → FGA types (only the openfga driver uses this)
  holderTypes: { users: 'user', admins: 'admin', integrations: 'integration' },

  drivers: {
    // 2. Your scope tree: organization → unit, project → site, whatever
    database: () => new DatabaseAuthorizationDriver({ resolveAncestors }),
  },

  // 3. Your side-effects on every write (audit, events, notifications)
  hooks: { onWrite: (event) => audit(event) },
})
```

`onWrite` runs *after* the write succeeded, so a hook that throws is logged and swallowed: propagating it would report a failure for an operation that did happen, and invite the caller to retry it.

`ScopeType` is an open `string`, so define your own union for type safety and let `resolveAncestors` describe the tree. The engine never queries your tables.

## Enforcing in routes

```ts
router
  .get('/admin/audit-log', [AuditLogsController, 'index'])
  .use(middleware.appAccess({ permission: 'audit:read' }))
```

The middleware resolves the authenticated holder from its morph name and asks the engine. Identity decides *what you may do*; if you also issue scoped API tokens, that's an orthogonal check — the token narrows, it never widens.

Two things it does **not** do. It only checks the **`app` scope** — enforcing per-organization (or per-unit) access is your controller's or your own middleware's job, because only your domain knows which scope a given route belongs to. And it requires the holder to expose `uuid`: the engine identifies holders by uuid, not by the model's primary key, so a model with a numeric PK is rejected with an explicit error.

## The catalog

Roles and permissions are config-driven and synced idempotently:

```ts
// config/app_acl.ts
permissions: [{ slug: 'audit:read' }, { slug: 'admin:manage' }],
roles: [{ slug: 'superadmin', rank: 100, permissions: '*' }],
```

```ts
import { syncAuthzCatalog } from '@jantstack/adonis-authz'
await syncAuthzCatalog(appAclCatalog())   // additive, safe to re-run
```

`rank` is metadata for *your* assignment policy ("nobody grants a role at or above their own rank"). The engine stores it; enforcing a privilege ceiling is a decision only your domain can make — the engine is mechanism, not policy.

## Custom drivers, judged by the same suite

Implement `AuthorizationDriver`, register its factory, and prove it:

```ts
import { runAuthorizationDriverContract } from '@jantstack/adonis-authz/testing'

runAuthorizationDriverContract({
  name: 'my-driver',
  makeDriver: () => new MyDriver(),
  seedCatalog: (catalog) => syncAuthzCatalog(catalog),
  cleanup: () => wipeEverything(),
})
```

A driver that passes honors the semantics above, so call-sites never change when you swap backends.

The package runs that suite on itself: `npm test` judges the `database` driver over in-memory SQLite — no host application, no Postgres — and `OPENFGA_TEST_URL=… npm test` adds the `openfga` driver to the same verdict. CI runs both before anything ships.

## OpenFGA tooling

```bash
node ace openfga:provision            # creates a store + writes the model from your holderTypes
node ace openfga:import --dry-run     # copies assignments/denies from the database driver
node ace openfga:import
```

The import **copies**, it doesn't move: your `authz_*` tables stay intact, so rolling back is setting `AUTHZ_DRIVER=database` again.

### Operational notes for this driver

Two properties are worth knowing before you put it in front of production traffic — neither can grant access that wasn't granted, both fail towards *denied*:

- **Re-granting is not atomic.** FGA rejects deleting and writing the same tuple key in one transaction, so refreshing an assignment's expiry is a delete followed by a write. Between the two, `authorize()` answers `false`, and a crash in that window loses the assignment. Re-running the grant restores it (writes are idempotent).
- **Expiry follows the app server's clock.** The `not_expired` condition is evaluated against a `current_time` your process sends with each check, so a skewed clock makes assignments expire early or late. Keep NTP running — the same requirement your JWTs already have.

The `database` driver has neither property: both are consequences of the facts living in another system.

## Compatibility

| | |
|---|---|
| Node | ≥ 20.6 |
| AdonisJS | ^7 (peer) · Lucid ^22 (peer) |
| OpenFGA SDK | ^0.9 (optional peer, only for that driver) |
| Databases | PostgreSQL, MySQL, SQLite |
| Module format | ESM only |

## Scope and maintenance

Extracted from the [adonis7-base](https://github.com/JantStack/adonis7-base) chassis, where it runs in production-shaped projects. Maintained according to that chassis's needs.

## License

MIT
