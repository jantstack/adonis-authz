/**
 * **Rotación 2 · cierre 3 — el lector rasgado de `database`** (firma del dueño 2026-10-22, «(rotación 2 · cierre 3 ·
 * lector rasgado de database)»; brief `rotacion-2-cierre3-brief.md`, informe `rotacion-2-cierre3-informe.md`). 4.ª
 * aparición del linaje **L12 «lector rasgado»**: hasta aquí `DatabaseAuthorizationDriver.authorize` leía denies y
 * asignaciones en DOS sentencias, y las composiciones del manager (`effectivePermissions`, `authorizedScopes`, la policy
 * de delegación de `defineScopedRole`/`updateScopedRole`) en DOS métodos del puerto, sin foto común: una escritura que
 * caía ENTRE las dos lecturas daba una respuesta que ningún estado real daba (la repro
 * `.claude/reproducciones/database-authorize-rasgado.spec.ts`, 5/5 en pg y mysql, que afirmaba el DEFECTO; aquí afirma
 * lo correcto).
 *
 * Propiedad universal: **toda DECISIÓN de `database` que combina concesión y deny se lee en UNA foto** — UNA sentencia
 * SQL (`readFoto` del driver), y `readSnapshot` (método opcional del puerto) para las composiciones del manager.
 *
 * El ESPÍA va en el embudo de TODA sentencia del driver (`sql(operation, fn)`): ejecuta `between` justo DESPUÉS de la
 * primera sentencia de lectura de la decisión, sea cual sea su nombre. Con el código de antes eso caía ENTRE las dos
 * lecturas (rojo); con la foto cae DESPUÉS de la única lectura, así que la decisión responde el estado ANTERIOR (verde).
 * Cada caso exige además que el espía SE DISPARÓ y que la escritura ATERRIZÓ (la pregunta siguiente ve el estado
 * posterior): un caso que pasa porque el espía no corrió no prueba nada.
 *
 * Los casos con `{ transaction }` exigen pool ≥ 2 (invariante 14); los de llamadas sueltas corren en los cuatro motores
 * (también en `:memory:`: la foto es UNA sentencia, no retiene conexión mientras corre `between`).
 *
 * **Cierre 3b** (segunda vuelta, firma 2026-10-23): la propiedad es del MOTOR ENTERO —también `membersOf` de relaciones,
 * con el espía en `rawQuery` del `database` inyectable del driver—; el manager decide por la CAPACIDAD
 * `snapshotDecisions` (H3); la composición de respaldo tiene casos sin OpenFGA (T1, T4); y el espía del juez publicado
 * cuenta solo las llamadas del manager.
 */
import { test } from '@japa/runner'
import db from '@adonisjs/lucid/services/db'
import { v7 as uuidv7 } from 'uuid'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { AuthorizationManager } from '../src/manager.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { descendantsFrom, memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import type { CatalogSpec, ScopeRef } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { testEngine } from './helpers/app.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { contractDenyRelationsConfig } from '../src/testing/relations_contract.js'
import { registerAuthorizationDriverContract } from '../src/testing/contract.js'
import type { DriverCapabilities } from '../src/testing/main.js'

const DELEGABLE = ['docs:read', 'docs:write']

const CATALOG: CatalogSpec = {
  permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
  roles: [
    { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] },
    { slug: 'org-admin', scopeType: 'organization', rank: 50, permissions: DELEGABLE },
    { slug: 'superadmin', scopeType: 'app', rank: 100, permissions: DELEGABLE },
  ],
}

/** Las sentencias de ESCRITURA del driver (su «¿ya existe?» incluido): el espía no se arma con ellas. */
const WRITE_OPERATION = /^(grant|revoke|deny|removeDeny|purge|reconcile)/

function worker() {
  const tree = memoryScopeTree()
  const driver: any = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })
  const manager = new AuthorizationManager({
    default: 'database',
    drivers: { database: () => driver },
    holderTypes: { users: 'user' },
    scopes: { resolveChain: resolveChainFrom(tree), descendantsOf: descendantsFrom(tree) },
    delegablePermissions: DELEGABLE,
    warnOnOptInSecurity: false,
  } as any)
  return { manager, driver, tree }
}

/**
 * Arma el espía en el embudo `sql()` del driver: `between` corre justo después de la PRIMERA sentencia de lectura que
 * se ejecute a partir de ahora (una vez). Devuelve `fired()`: si llegó a correr.
 */
function afterFirstRead(driver: any, between: () => Promise<void>): { fired: () => boolean; operations: string[] } {
  const original = driver.sql.bind(driver)
  const operations: string[] = []
  let armed = true
  let fired = false
  driver.sql = async (operation: string, fn: () => Promise<unknown>) => {
    const out = await original(operation, fn)
    operations.push(operation)
    if (armed && !WRITE_OPERATION.test(operation)) {
      armed = false
      fired = true
      await between()
    }
    return out
  }
  return { fired: () => fired, operations }
}

test.group('rotación 2 · cierre 3 · L12 · authorize de database lee concesión y deny en UNA foto', (group) => {
  let org: ScopeRef
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog(CATALOG)
    org = { type: 'organization', uuid: uuidv7() }
    return cleanAuthzTables
  })

  if (testEngine() !== 'sqlite') {
    test('R1 (repro 1) · grant + deny en UNA trx que confirma entre lecturas ⇒ false (ni antes ni después concede)', async ({ assert }) => {
      const { manager, driver, tree } = worker()
      await tree.attach(org, APP_SCOPE)
      const bob = { type: 'users', uuid: uuidv7() }
      assert.isFalse(await manager.authorize(bob, 'docs:read', org), 'ANTES: sin grant no concede')
      const spy = afterFirstRead(driver, async () => {
        await db.transaction(async (trx) => {
          await manager.grant(bob, 'org-editor', org, { transaction: trx })
          await manager.deny(bob, 'docs:read', org, { transaction: trx })
        })
      })
      const answer = await manager.authorize(bob, 'docs:read', org)
      assert.isTrue(spy.fired(), 'el espía corrió')
      assert.isFalse(answer, 'ROJO (L12): una foto rasgada concedió lo que ningún estado real concedía')
      assert.isFalse(await manager.authorize(bob, 'docs:read', org), 'DESPUÉS: el deny gana')
      assert.lengthOf(await manager.listDenies(bob, org), 1, 'la escritura aterrizó')
    })

    test('R1 · CONTROL: revoke + removeDeny en UNA trx entre lecturas ⇒ false (antes deny, después nada)', async ({ assert }) => {
      const { manager, driver, tree } = worker()
      await tree.attach(org, APP_SCOPE)
      const bob = { type: 'users', uuid: uuidv7() }
      await manager.grant(bob, 'org-editor', org)
      await manager.deny(bob, 'docs:read', org)
      const spy = afterFirstRead(driver, async () => {
        await db.transaction(async (trx) => {
          await manager.revoke(bob, 'org-editor', org, { transaction: trx })
          await manager.removeDeny(bob, 'docs:read', org, { transaction: trx })
        })
      })
      assert.isFalse(await manager.authorize(bob, 'docs:read', org))
      assert.isTrue(spy.fired())
    })
  }

  test('R4 (repro 4) · deny y DESPUÉS grant, dos llamadas sueltas (el orden prudente), entre lecturas ⇒ false', async ({ assert }) => {
    const { manager, driver, tree } = worker()
    await tree.attach(org, APP_SCOPE)
    const bob = { type: 'users', uuid: uuidv7() }
    const spy = afterFirstRead(driver, async () => {
      await manager.deny(bob, 'docs:read', org)
      await manager.grant(bob, 'org-editor', org)
    })
    const answer = await manager.authorize(bob, 'docs:read', org)
    assert.isTrue(spy.fired(), 'el espía corrió')
    assert.isFalse(answer, 'ROJO (L12): none → deny → deny+grant no concede en ningún estado')
    assert.isFalse(await manager.authorize(bob, 'docs:read', org), 'DESPUÉS: el deny gana')
    assert.deepEqual(await manager.listRoles(bob, org), ['org-editor'], 'la escritura aterrizó')
  })

  test('R4 · CONTROL POSITIVO: solo un grant entre lecturas ⇒ la decisión es la del estado ANTERIOR (false) y la siguiente concede', async ({ assert }) => {
    // Prueba que el espía cae DESPUÉS de la lectura y que la foto es la de ANTES: no un `false` por otra razón.
    const { manager, driver, tree } = worker()
    await tree.attach(org, APP_SCOPE)
    const bob = { type: 'users', uuid: uuidv7() }
    const spy = afterFirstRead(driver, async () => {
      await manager.grant(bob, 'org-editor', org)
    })
    assert.isFalse(await manager.authorize(bob, 'docs:read', org))
    assert.isTrue(spy.fired())
    assert.isTrue(await manager.authorize(bob, 'docs:read', org), 'el estado posterior concede')
  })

  test('authorizeMany (composición de N authorize) · el mismo entrelazado por posición ⇒ [false]', async ({ assert }) => {
    const { manager, driver, tree } = worker()
    await tree.attach(org, APP_SCOPE)
    const bob = { type: 'users', uuid: uuidv7() }
    const spy = afterFirstRead(driver, async () => {
      await manager.deny(bob, 'docs:read', org)
      await manager.grant(bob, 'org-editor', org)
    })
    assert.deepEqual(await manager.authorizeMany(bob, 'docs:read', [org]), [false], 'ROJO (L12): la posición se leyó rasgada')
    assert.isTrue(spy.fired())
    assert.deepEqual(await manager.authorizeMany(bob, 'docs:read', [org]), [false])
  })

  test('listScopes del driver · offboarding suelto (revoke y luego removeDeny) entre lecturas ⇒ [] (antes deny, después nada)', async ({ assert }) => {
    const { manager, driver, tree } = worker()
    await tree.attach(org, APP_SCOPE)
    const bob = { type: 'users', uuid: uuidv7() }
    await manager.grant(bob, 'org-editor', org)
    await manager.deny(bob, 'docs:read', org)
    assert.deepEqual(await manager.listScopes(bob, 'docs:read'), [], 'ANTES: el deny bloquea')
    const spy = afterFirstRead(driver, async () => {
      await manager.revoke(bob, 'org-editor', org)
      await manager.removeDeny(bob, 'docs:read', org)
    })
    const answer = await manager.listScopes(bob, 'docs:read')
    assert.isTrue(spy.fired())
    assert.deepEqual(answer, [], 'ROJO (L12): listScopes listó un scope que ningún estado real concedía')
    assert.deepEqual(await manager.listRoles(bob, org), [], 'la escritura aterrizó')
  })
})

test.group('rotación 2 · cierre 3 · L12 · composiciones del manager sobre database en UNA foto (readSnapshot)', (group) => {
  let org: ScopeRef
  let unit: ScopeRef
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog(CATALOG)
    org = { type: 'organization', uuid: uuidv7() }
    unit = { type: 'unit', uuid: uuidv7() }
    return cleanAuthzTables
  })

  test('R5 (repro 5) · effectivePermissions · offboarding suelto (revoke y luego removeDeny) entre sus lecturas ⇒ []', async ({ assert }) => {
    const { manager, driver, tree } = worker()
    await tree.attach(org, APP_SCOPE)
    const bob = { type: 'users', uuid: uuidv7() }
    await manager.grant(bob, 'org-editor', org)
    await manager.deny(bob, 'docs:read', org)
    assert.deepEqual(await manager.effectivePermissions(bob, org), [], 'ANTES: el deny resta')
    const spy = afterFirstRead(driver, async () => {
      await manager.revoke(bob, 'org-editor', org)
      await manager.removeDeny(bob, 'docs:read', org)
    })
    const answer = await manager.effectivePermissions(bob, org)
    assert.isTrue(spy.fired())
    assert.deepEqual(answer, [], 'ROJO (L12): ningún estado real daba docs:read')
    assert.deepEqual(await manager.listRoles(bob, org), [], 'la escritura aterrizó')
  })

  test('effectivePermissions · onboarding prudente (deny y luego grant) entre sus lecturas ⇒ [] ; CONTROL: solo grant ⇒ [] y la siguiente lo lista', async ({ assert }) => {
    const { manager, driver, tree } = worker()
    await tree.attach(org, APP_SCOPE)
    const bob = { type: 'users', uuid: uuidv7() }
    const spy = afterFirstRead(driver, async () => {
      await manager.deny(bob, 'docs:read', org)
      await manager.grant(bob, 'org-editor', org)
    })
    assert.deepEqual(await manager.effectivePermissions(bob, org), [])
    assert.isTrue(spy.fired())
    assert.deepEqual(await manager.effectivePermissions(bob, org), [], 'DESPUÉS: el deny resta')

    const alice = { type: 'users', uuid: uuidv7() }
    const control = afterFirstRead(driver, async () => {
      await manager.grant(alice, 'org-editor', org)
    })
    assert.deepEqual(await manager.effectivePermissions(alice, org), [], 'la foto es la de ANTES')
    assert.isTrue(control.fired())
    assert.deepEqual(await manager.effectivePermissions(alice, org), ['docs:read'], 'control positivo: el estado posterior lo da')
  })

  test('authorizedScopes · rama some: offboarding (revoke en la org, removeDeny en la unit) entre lecturas ⇒ none (la unit nunca estuvo concedida)', async ({ assert }) => {
    const { manager, driver, tree } = worker()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const bob = { type: 'users', uuid: uuidv7() }
    await manager.grant(bob, 'org-admin', org)
    await manager.deny(bob, 'docs:write', unit)
    assert.deepEqual(await manager.authorizedScopes(bob, 'docs:write', 'unit'), { kind: 'none' }, 'ANTES: la unit está denegada')
    const spy = afterFirstRead(driver, async () => {
      await manager.revoke(bob, 'org-admin', org)
      await manager.removeDeny(bob, 'docs:write', unit)
    })
    const answer = await manager.authorizedScopes(bob, 'docs:write', 'unit')
    assert.isTrue(spy.fired())
    assert.deepEqual(answer, { kind: 'none' }, 'ROJO (L12): authorizedScopes listó una unit que ningún estado real concedía')
    assert.deepEqual(await manager.authorizedScopes(bob, 'docs:write', 'unit'), { kind: 'none' }, 'DESPUÉS: sin rol')
  })

  test('authorizedScopes · rama all: offboarding (revoke en app, removeDeny en la unit) entre lecturas ⇒ all CON la unit excluida (nunca un all sin el deny vivo de la foto)', async ({ assert }) => {
    const { manager, driver, tree } = worker()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const bob = { type: 'users', uuid: uuidv7() }
    await manager.grant(bob, 'superadmin', APP_SCOPE)
    await manager.deny(bob, 'docs:write', unit)
    const before = { kind: 'all', excludedSubtrees: [{ scope: unit, includesDescendants: true }] }
    assert.deepEqual(await manager.authorizedScopes(bob, 'docs:write', 'unit'), before as any)
    const spy = afterFirstRead(driver, async () => {
      await manager.revoke(bob, 'superadmin', APP_SCOPE)
      await manager.removeDeny(bob, 'docs:write', unit)
    })
    const answer = await manager.authorizedScopes(bob, 'docs:write', 'unit')
    assert.isTrue(spy.fired())
    assert.deepEqual(answer, before as any, 'ROJO (L12): un all sin excluir la unit que ningún estado real concedía')
    assert.deepEqual(await manager.authorizedScopes(bob, 'docs:write', 'unit'), { kind: 'none' })
  })

  test('defineScopedRole · #assertDelegable: offboarding del actor (revoke y luego removeDeny) entre lecturas ⇒ 422 E_AUTHZ_PERMISSION_NOT_DELEGABLE y NADA escrito', async ({ assert }) => {
    const { manager, driver, tree } = worker()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const admin = { type: 'users', uuid: uuidv7() }
    await manager.grant(admin, 'org-admin', org)
    await manager.deny(admin, 'docs:read', org)
    const spec = { slug: 'lead', scopeType: 'unit', rank: 10, permissions: ['docs:read'] }
    const spy = afterFirstRead(driver, async () => {
      await manager.revoke(admin, 'org-admin', org)
      await manager.removeDeny(admin, 'docs:read', org)
    })
    let error: any
    try {
      await manager.defineScopedRole(admin, org, spec as any)
    } catch (caught) {
      error = caught
    }
    assert.isTrue(spy.fired())
    assert.equal(error?.code, 'E_AUTHZ_PERMISSION_NOT_DELEGABLE', `ROJO (L12): delegó un permiso que el actor no tenía efectivo en ningún estado real (${error?.message ?? 'sin error'})`)
    assert.include(error.message, 'DENEGADO', 'la foto es la de ANTES: el deny')
    const written = await db.from('authz_roles').where('slug', 'lead').select('uuid')
    assert.lengthOf(written, 0, 'nada escrito')
  })

  test('updateScopedRole · #assertDelegable: offboarding del actor entre lecturas ⇒ 422 y los permisos del rol NO cambian', async ({ assert }) => {
    const { manager, driver, tree } = worker()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const admin = { type: 'users', uuid: uuidv7() }
    await manager.grant(admin, 'org-admin', org)
    const role = await manager.defineScopedRole(admin, org, { slug: 'lead', scopeType: 'unit', rank: 10, permissions: ['docs:write'] } as any)
    await manager.deny(admin, 'docs:read', org)
    const spy = afterFirstRead(driver, async () => {
      await manager.revoke(admin, 'org-admin', org)
      await manager.removeDeny(admin, 'docs:read', org)
    })
    let error: any
    try {
      await manager.updateScopedRole(admin, role.uuid, { permissions: ['docs:read', 'docs:write'] })
    } catch (caught) {
      error = caught
    }
    assert.isTrue(spy.fired())
    assert.equal(error?.code, 'E_AUTHZ_PERMISSION_NOT_DELEGABLE', `ROJO (L12): actualizó con un permiso que el actor no tenía efectivo en ningún estado real (${error?.message ?? 'sin error'})`)
    const links = await db
      .from('authz_role_permissions as rp')
      .join('authz_permissions as p', 'p.uuid', 'rp.permission_uuid')
      .where('rp.role_uuid', role.uuid)
      .select('p.slug')
    assert.deepEqual(links.map((row: any) => row.slug), ['docs:write'], 'los permisos del rol no cambiaron')
  })
})

test.group('rotación 2 · cierre 3 · límite declarado database · cadena frente a hechos (README «Limits», fila «Torn read»)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog(CATALOG)
    return cleanAuthzTables
  })

  /**
   * Un `resolveChain` que ejecuta `between` justo DESPUÉS de resolver (una vez, armado a mano): es el entrelazado que la
   * foto NO cubre —el árbol es del consumidor y se lee ANTES de la foto—. Lo mismo para el driver y el manager.
   */
  async function chainVsFacts() {
    const tree = memoryScopeTree()
    const base = resolveChainFrom(tree)
    let between: (() => Promise<void>) | null = null
    const resolveChain = async (scope: ScopeRef) => {
      const chain = await base(scope)
      const run = between
      between = null
      if (run) await run()
      return chain
    }
    const driver = new DatabaseAuthorizationDriver({ resolveChain })
    const manager = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => driver },
      scopes: { resolveChain },
      warnOnOptInSecurity: false,
    } as any)
    const orgA: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const orgB: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const unit: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(unit, orgA)
    const bob = { type: 'users', uuid: uuidv7() }
    await manager.grant(bob, 'org-editor', orgA)
    await manager.deny(bob, 'docs:read', orgA)
    return { tree, manager, orgA, orgB, unit, bob, arm: (fn: () => Promise<void>) => (between = fn) }
  }

  test('límite declarado database · cadena frente a hechos: un moved (la unit sale de A) y DESPUÉS el removeDeny en A, entre el resolveChain y la foto ⇒ true UNA vez (ningún estado real concedía); se voltea si el árbol entra en la foto', async ({ assert }) => {
    const { tree, manager, orgA, orgB, unit, bob, arm } = await chainVsFacts()
    assert.isFalse(await manager.authorize(bob, 'docs:read', unit), 'ANTES: el deny de A gana')
    arm(async () => {
      await tree.move(unit, orgB)
      await manager.removeDeny(bob, 'docs:read', orgA)
    })
    const torn = await manager.authorize(bob, 'docs:read', unit)
    assert.isTrue(torn, 'CARACTERIZACIÓN: la cadena vieja (unit bajo A) con los hechos nuevos (rol en A, sin deny) concede una vez')
    assert.isFalse(await manager.authorize(bob, 'docs:read', unit), 'DESPUÉS: la unit está bajo B, donde nada concede')
  })

  test('receta del límite: los HECHOS primero y el moved después ⇒ la respuesta es la de un estado REAL (el intermedio: unit aún en A y sin deny)', async ({ assert }) => {
    const { tree, manager, orgA, orgB, unit, bob, arm } = await chainVsFacts()
    arm(async () => {
      await manager.removeDeny(bob, 'docs:read', orgA)
      await tree.move(unit, orgB)
    })
    // Cadena leída antes de las dos escrituras (unit en A) + hechos sin deny = el estado intermedio, que EXISTIÓ (y que
    // el escritor eligió al ordenar así): concede, y es una respuesta linealizable.
    assert.isTrue(await manager.authorize(bob, 'docs:read', unit))
    assert.isFalse(await manager.authorize(bob, 'docs:read', unit), 'DESPUÉS: bajo B')
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * Rotación 2 · cierre 3b — segunda vuelta (firma del dueño 2026-10-23, «(rotación 2 · cierre 3b · segunda vuelta)»).
 * Casos del tester (T1–T4, `.claude/reproducciones/cierre3b-tester/`), H3/H4 del auditor y el espía del juez.
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Una vista del driver `database` SIN los métodos indicados y declarando `snapshotDecisions: false` (lo que vería el
 * manager con un driver de terceros sin la capacidad): el manager recorre la composición de respaldo.
 */
function viewWithout(tree: ReturnType<typeof memoryScopeTree>, hidden: string[], extra: Record<string, unknown> = {}) {
  const base = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })
  const view = Object.create(base)
  for (const name of hidden) Object.defineProperty(view, name, { value: undefined, enumerable: false })
  for (const [name, value] of Object.entries(extra)) Object.defineProperty(view, name, { value, enumerable: false })
  Object.defineProperty(view, 'capabilities', { value: Object.freeze({ ...base.capabilities, snapshotDecisions: false }), enumerable: false })
  return { base, view }
}

function managerOn(tree: ReturnType<typeof memoryScopeTree>, driver: unknown) {
  return new AuthorizationManager({
    default: 'database',
    drivers: { database: () => driver as any },
    holderTypes: { users: 'user' },
    scopes: { resolveChain: resolveChainFrom(tree), descendantsOf: descendantsFrom(tree) },
    delegablePermissions: DELEGABLE,
    warnOnOptInSecurity: false,
  } as any)
}

async function caught(run: () => Promise<unknown>): Promise<any> {
  return run().then(
    (value) => ({ value }),
    (error) => error
  )
}

test.group('rotación 2 · cierre 3b · composición de respaldo, H3 y H4 (driver sin snapshotDecisions)', (group) => {
  let org: ScopeRef
  let unit: ScopeRef
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog(CATALOG)
    org = { type: 'organization', uuid: uuidv7() }
    unit = { type: 'unit', uuid: uuidv7() }
    return cleanAuthzTables
  })

  test('T1 (tester) · fallback DECLARADO (driver sin readSnapshot): effectivePermissions, authorizedScopes y la policy de define SIGUEN restando los denies', async ({ assert }) => {
    const tree = memoryScopeTree()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { view } = viewWithout(tree, ['readSnapshot'])
    const manager = managerOn(tree, view)
    assert.isUndefined((await manager.driver()).readSnapshot, 'el caso recorre el fallback')
    const bob = { type: 'users', uuid: uuidv7() }
    await manager.grant(bob, 'superadmin', APP_SCOPE)
    await manager.deny(bob, 'docs:write', unit)
    assert.deepEqual(await manager.effectivePermissions(bob, unit), ['docs:read'])
    assert.deepEqual(await manager.authorizedScopes(bob, 'docs:write', 'unit'), {
      kind: 'all',
      excludedSubtrees: [{ scope: unit, includesDescendants: true }],
    } as any)
    const admin = { type: 'users', uuid: uuidv7() }
    await manager.grant(admin, 'org-admin', org)
    await manager.deny(admin, 'docs:read', org)
    const error = await caught(() => manager.defineScopedRole(admin, org, { slug: 'lead', scopeType: 'unit', rank: 10, permissions: ['docs:read'] } as any))
    assert.equal(error?.code, 'E_AUTHZ_PERMISSION_NOT_DELEGABLE')
  })

  test('B (tester, cierre 3c) · fallback DECLARADO (driver sin readSnapshot, CON purgeRole): updateScopedRole que AÑADE un permiso denegado al actor ⇒ 422 E_AUTHZ_PERMISSION_NOT_DELEGABLE y los permisos del rol NO cambian', async ({ assert }) => {
    // Centinela solo-database del respaldo de `updateScopedRole`: T1 cubre effectivePermissions/authorizedScopes/define;
    // la delegación de update cuelga de `purgeRole` (un par de '2.2'), así que ningún harness '2.1' del juez la recorre.
    const tree = memoryScopeTree()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { view } = viewWithout(tree, ['readSnapshot'])
    const manager = managerOn(tree, view)
    const driver = await manager.driver()
    assert.isUndefined(driver.readSnapshot, 'el caso recorre el fallback')
    assert.typeOf(driver.purgeRole, 'function', 'con purgeRole: el manager delega')
    const admin = { type: 'users', uuid: uuidv7() }
    await manager.grant(admin, 'org-admin', org)
    const role = await manager.defineScopedRole(admin, org, { slug: 'lead', scopeType: 'unit', rank: 10, permissions: ['docs:write'] } as any)
    await manager.deny(admin, 'docs:read', org)
    const error = await caught(() => manager.updateScopedRole(admin, role.uuid, { permissions: ['docs:read', 'docs:write'] }))
    assert.equal(error?.code, 'E_AUTHZ_PERMISSION_NOT_DELEGABLE', `el respaldo de update ignoró el deny del actor (${error?.code ?? 'sin error'} ${error?.message ?? ''})`)
    const links = await db
      .from('authz_role_permissions as rp')
      .join('authz_permissions as p', 'p.uuid', 'rp.permission_uuid')
      .where('rp.role_uuid', role.uuid)
      .select('p.slug')
    assert.deepEqual(links.map((row: any) => row.slug), ['docs:write'], 'los permisos del rol no cambiaron')
    // CONTROL: sin el deny el mismo update entra (el 422 era el deny, no otra regla).
    await manager.removeDeny(admin, 'docs:read', org)
    await manager.updateScopedRole(admin, role.uuid, { permissions: ['docs:read', 'docs:write'] })
    assert.sameMembers((await manager.effectivePermissions(admin, unit)).filter((p: string) => p.startsWith('docs:')), ['docs:read', 'docs:write'])
  })

  test('T2 (tester) · authorize · offboarding SUELTO (revoke y luego removeDeny) entre lecturas ⇒ false (espejo de R4 para el orden «concesiones primero», corre en :memory:)', async ({ assert }) => {
    const { manager, driver, tree } = worker()
    await tree.attach(org, APP_SCOPE)
    const bob = { type: 'users', uuid: uuidv7() }
    await manager.grant(bob, 'org-editor', org)
    await manager.deny(bob, 'docs:read', org)
    const spy = afterFirstRead(driver, async () => {
      await manager.revoke(bob, 'org-editor', org)
      await manager.removeDeny(bob, 'docs:read', org)
    })
    const answer = await manager.authorize(bob, 'docs:read', org)
    assert.isTrue(spy.fired())
    assert.equal(spy.operations[0], 'authorize', 'el espía cae tras la foto de authorize')
    assert.isFalse(answer, 'ROJO (L12): grant+deny → deny → nada; ninguno concede')
    assert.deepEqual(await manager.listRoles(bob, org), [], 'el revoke aterrizó')
    assert.deepEqual(await manager.listDenies(bob, org), [], 'el removeDeny aterrizó')
  })

  test('T3 (tester) · readSnapshot que responde sin una clave pedida ⇒ 500 E_AUTHZ_INTERNAL nombrando readSnapshot (nunca «sin denies»)', async ({ assert }) => {
    const tree = memoryScopeTree()
    await tree.attach(org, APP_SCOPE)
    const base = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })
    const view = Object.create(base)
    Object.defineProperty(view, 'readSnapshot', {
      value: async (subject: any, reads: any) => {
        const answer: any = await base.readSnapshot(subject, reads)
        delete answer.listDenies
        return answer
      },
      enumerable: false,
    })
    const manager = managerOn(tree, view)
    const bob = { type: 'users', uuid: uuidv7() }
    await manager.grant(bob, 'org-editor', org)
    await manager.deny(bob, 'docs:read', org)
    const error = await caught(() => manager.effectivePermissions(bob, org))
    assert.equal(error?.status, 500, `respondió ${JSON.stringify(error?.value)}`)
    assert.equal(error?.code, 'E_AUTHZ_INTERNAL')
    assert.include(error.message, 'readSnapshot')
    assert.include(error.message, 'listDenies')
  })

  test('T4 (tester) · 3E · R3 con el camino que dice probar: driver SIN rolesInChain NI readSnapshot ⇒ effectivePermissions por slug, restando denies', async ({ assert }) => {
    const tree = memoryScopeTree()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const { view } = viewWithout(tree, ['rolesInChain', 'readSnapshot'])
    const manager = managerOn(tree, view)
    const driver: any = await manager.driver()
    assert.isUndefined(driver.rolesInChain)
    assert.isUndefined(driver.readSnapshot)
    const bob = { type: 'users', uuid: uuidv7() }
    await manager.grant(bob, 'org-editor', org)
    await manager.deny(bob, 'docs:read', unit)
    assert.deepEqual(await manager.effectivePermissions(bob, org), ['docs:read'])
    assert.deepEqual(await manager.effectivePermissions(bob, unit), [])
  })

  test('H3 · decide la CAPACIDAD: un driver que declara snapshotDecisions: false con un método readSnapshot homónimo (otra cosa) NO lo ve llamado y compone restando denies', async ({ assert }) => {
    const tree = memoryScopeTree()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    let calls = 0
    const { view } = viewWithout(tree, [], {
      readSnapshot: async () => {
        calls++
        return { otraCosa: true }
      },
    })
    const manager = managerOn(tree, view)
    assert.isFalse((await manager.capabilities()).snapshotDecisions)
    const bob = { type: 'users', uuid: uuidv7() }
    await manager.grant(bob, 'superadmin', APP_SCOPE)
    await manager.deny(bob, 'docs:write', unit)
    assert.deepEqual(await manager.effectivePermissions(bob, unit), ['docs:read'])
    assert.deepEqual(await manager.authorizedScopes(bob, 'docs:write', 'unit'), { kind: 'all', excludedSubtrees: [{ scope: unit, includesDescendants: true }] } as any)
    assert.equal(calls, 0, 'el manager no llamó al readSnapshot de un driver que no declara la capacidad')
  })

  test('H3 · declarar snapshotDecisions: true SIN traer readSnapshot ⇒ 500 E_AUTHZ_CONFIG nombrándolo, antes de leer hechos', async ({ assert }) => {
    const tree = memoryScopeTree()
    await tree.attach(org, APP_SCOPE)
    const base = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })
    const view = Object.create(base)
    Object.defineProperty(view, 'readSnapshot', { value: undefined, enumerable: false })
    assert.isTrue(view.capabilities.snapshotDecisions, 'hereda la capacidad true')
    const manager = managerOn(tree, view)
    const bob = { type: 'users', uuid: uuidv7() }
    await manager.grant(bob, 'org-editor', org)
    // Cierre 3c (J3), DECLARADO: el driver se resuelve y lo que no compone sigue respondiendo; el 500 sale en la primera
    // decisión compuesta.
    assert.isTrue(await manager.hasRole(bob, 'org-editor', org))
    const runs = [
      () => manager.effectivePermissions(bob, org),
      () => manager.authorizedScopes(bob, 'docs:read', 'organization'),
      () => manager.forRequest().effectivePermissions(bob, org),
    ]
    for (const run of runs) {
      const error = await caught(run)
      assert.equal(error?.status, 500, `respondió ${JSON.stringify(error?.value)}`)
      assert.equal(error?.code, 'E_AUTHZ_CONFIG')
      assert.include(error.message, 'snapshotDecisions: true')
      assert.include(error.message, 'readSnapshot')
      // Cierre 3c (J3): nombra el driver que lo EMITIÓ (clave y clase), no solo `config.default`.
      assert.include(error.message, "el driver 'database' (DatabaseAuthorizationDriver)")
    }
  })

  test('H4 · updateScopedRole con permisos sobre un driver SIN listDenies: el 422 de rango sale ANTES que el 500 E_AUTHZ_UNSUPPORTED (el orden de antes del cierre 3)', async ({ assert }) => {
    const tree = memoryScopeTree()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    const full = managerOn(tree, new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) }))
    const admin = { type: 'users', uuid: uuidv7() }
    await full.grant(admin, 'org-admin', org)
    const role = await full.defineScopedRole(admin, org, { slug: 'lead', scopeType: 'unit', rank: 10, permissions: ['docs:write'] } as any)
    const { view } = viewWithout(tree, ['listDenies', 'readSnapshot'])
    const legacy = managerOn(tree, view)
    const nobody = { type: 'users', uuid: uuidv7() }
    const rank = await caught(() => legacy.updateScopedRole(nobody, role.uuid, { permissions: ['docs:read'] }))
    assert.equal(rank?.code, 'E_AUTHZ_RANK_EXCEEDED', `${rank?.code} ${rank?.message}`)
    // Con rank suficiente, el 500 de siempre (sin listDenies no hay policy de delegación honesta).
    const unsupported = await caught(() => legacy.updateScopedRole(admin, role.uuid, { permissions: ['docs:read'] }))
    assert.equal(unsupported?.code, 'E_AUTHZ_UNSUPPORTED', `${unsupported?.code} ${unsupported?.message}`)
    assert.include(unsupported.message, 'listDenies')
  })
})

/**
 * El juez publicado, capturado (Japa no deja registrar grupos desde un test en marcha): se registra contra una API que
 * guarda los casos y el `setup` del grupo, y `run(prefijo)` ejecuta UNO con el `assert` del caso que lo llama.
 */
function capturedJudge(makeDriver: (tree: any) => unknown, options: { snapshotDecisions?: boolean; name?: string } = {}) {
  const tests = new Map<string, (ctx: { assert: any }) => Promise<void>>()
  const setups: Array<() => unknown> = []
  const capabilities: DriverCapabilities = {
    hierarchyFacts: false,
    transactionalWrites: false,
    truncationSignal: false,
    singleCheckAuthorize: false,
    injectableClock: false,
    exhaustiveLists: true,
    listDenies: true,
    // Cierre 3c (A/J1): la parte de delegación de las caras de `snapshotDecisions` solo se registra con `purgeRole: true`,
    // que es un par de '2.2' (de ahí el nivel): así el caso del espía sigue recorriendo también `defineScopedRole`.
    purgeRole: true,
    countRoleAssignments: true,
    serializedCatalogWrites: false,
    roleInheritanceNative: false,
    listObjectsInherited: false,
    canonicalScopeReads: false,
    enumerateFacts: false,
    // Cierre 3d (E del tester): parametrizable, para juzgar también la cara `false` CON delegación sin OpenFGA.
    snapshotDecisions: options.snapshotDecisions ?? true,
  }
  registerAuthorizationDriverContract(
    {
      name: options.name ?? 'database (readSnapshot que llama a sus métodos)',
      level: '2.2',
      capabilities,
      makeDriver: makeDriver as any,
      seedCatalog: (catalog) => syncAuthzCatalog(catalog),
      cleanup: cleanAuthzTables,
    },
    {
      group: (_title, define) => define({ each: { setup: (fn: () => unknown) => setups.push(fn) }, teardown: () => {} } as any),
      test: (title, fn) => {
        tests.set(title, fn as any)
        return { timeout: () => {} }
      },
    }
  )
  return {
    async run(prefix: string, assert: any) {
      const found = [...tests].filter(([title]) => title.startsWith(prefix))
      assert.lengthOf(found, 1, `un solo caso del juez empieza por «${prefix}»`)
      for (const setup of setups) await setup()
      await found[0][1]({ assert })
    },
  }
}

/**
 * Anota el rol de cada `grant` que pase por la vista (cierre 3d): el juez solo concede `org-admin` en la parte de
 * DELEGACIÓN de las caras de `snapshotDecisions`, así que verlo en la lista prueba que esa parte corrió. `configurable`
 * por lo mismo que `readSnapshot` del espía (la invariante de `get` de un Proxy no decide el rojo).
 */
function recordGrants(view: any, base: any, granted: string[]) {
  Object.defineProperty(view, 'grant', {
    value: (...args: any[]) => {
      granted.push(String(args[1]))
      return base.grant.apply(view, args)
    },
    enumerable: false,
    configurable: true,
  })
}

test.group('rotación 2 · cierre 3b · el espía del juez cuenta solo las llamadas del MANAGER (tester 🟡 6)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    return cleanAuthzTables
  })

  test('un readSnapshot correcto que llama a SUS métodos por dentro (this.rolesInChain/listScopes/listDenies) pasa la cara true del juez «UNA llamada a readSnapshot»', async ({ assert }) => {
    let internal = 0
    const granted: string[] = []
    const judge = capturedJudge((tree) => {
      const base = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })
      const view = Object.create(base)
      // Un tercero que implementa la foto como una transacción REPEATABLE READ y llama a sus propios métodos dentro: el
      // juez no puede contarlas como «el manager compuso».
      Object.defineProperty(view, 'readSnapshot', {
        value: async function (this: any, subject: any, reads: any) {
          internal++
          const out: any = {}
          if (reads.rolesInChain) out.rolesInChain = await this.rolesInChain(subject, reads.rolesInChain)
          if (reads.listScopes !== undefined) out.listScopes = await this.listScopes(subject, reads.listScopes)
          if (reads.listDenies) out.listDenies = await this.listDenies(subject)
          return out
        },
        enumerable: false,
        // Cierre 3c (C del tester): configurable, para que el espía VIEJO (Proxy sobre el driver) dé rojo por la CUENTA
        // (+3 llamadas internas) y no por la invariante de `get` de un Proxy con una propiedad no configurable.
        configurable: true,
      })
      recordGrants(view, base, granted)
      return view
    })
    await judge.run('snapshotDecisions:true · el manager compone', assert)
    assert.isAbove(internal, 0, 'el readSnapshot de pega corrió (el caso no es vacío)')
    // Cierre 3d (E del tester): lo que dice el comentario de `capturedJudge` —«sigue recorriendo también
    // `defineScopedRole`»— se afirma: la parte de delegación de la cara (el `grant` de `org-admin` al actor) corrió.
    assert.include(granted, 'org-admin', 'la parte de delegación de la cara true corrió (no es vacía)')
  })
})

/**
 * Cierre 3d (E del tester, firma 2026-10-23): la cara `false` del juez CON delegación (`'2.2'` + `purgeRole: true` +
 * `snapshotDecisions: false`) no la ejercía ningún harness de `database` desde 3c (solo `openfga`, contra `:8090`). Aquí
 * se corre sin OpenFGA sobre una vista SIN `readSnapshot`, por el título de la variante CON delegación, y se afirma que la
 * parte de delegación corrió (la vista anota cada `grant`; el juez concede `org-admin` al actor solo en esa parte).
 */
test.group('rotación 2 · cierre 3d · la cara false del juez CON delegación corre sin OpenFGA (tester E)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    return cleanAuthzTables
  })

  test('E · snapshotDecisions:false con purgeRole (2.2, driver sin readSnapshot): la cara del juez juzga la policy de defineScopedRole por la composición de respaldo, restando el deny del actor', async ({ assert }) => {
    const granted: string[] = []
    const judge = capturedJudge(
      (tree) => {
        const { base, view } = viewWithout(tree, ['readSnapshot'])
        recordGrants(view, base, granted)
        return view
      },
      { snapshotDecisions: false, name: 'database 2.2 sin readSnapshot (cara false con delegación)' }
    )
    await judge.run('snapshotDecisions:false · authorization.capabilities().snapshotDecisions es false y el manager compone effectivePermissions, authorizedScopes y la policy de defineScopedRole', assert)
    assert.include(granted, 'org-admin', 'la parte de delegación de la cara false corrió (no es vacía)')
  })
})

/**
 * El gemelo de RELACIONES (H1 del auditor, 🟠 1 del tester): `DatabaseRelationsDriver.membersOf` leía los candidatos
 * (sentencia 1) y DESPUÉS, en otra sentencia, «¿hay algún `denied_*` vigente en el objeto?»; sin deny devolvía los
 * candidatos de la primera SIN juzgarlos. El espía va en `rawQuery` del `database` inyectable del driver (2.º argumento
 * del constructor) y corre `between` justo DESPUÉS de la primera sentencia.
 */
function interleavedDatabase() {
  let between: (() => Promise<void>) | null = null
  let fired = false
  const texts: string[] = []
  const database = {
    primaryConnectionName: (db as any).primaryConnectionName,
    connection(name?: string) {
      const real: any = db.connection(name)
      return new Proxy(real, {
        get(target, prop) {
          if (prop === 'rawQuery') {
            return async (text: string, bindings: unknown[]) => {
              const out = await target.rawQuery(text, bindings)
              texts.push(text)
              const run = between
              between = null
              if (run) {
                fired = true
                await run()
              }
              return out
            }
          }
          const value = Reflect.get(target, prop, target)
          return typeof value === 'function' ? value.bind(target) : value
        },
      })
    },
  }
  return { database, arm: (fn: () => Promise<void>) => (between = fn), fired: () => fired, texts }
}

function relationRow(p: ScopeRef, docId: string, relation: string, subject: string) {
  return {
    uuid: uuidv7(),
    partition_key: `${p.type}|${p.uuid}`,
    object_type: 'document',
    object_uuid: docId,
    relation,
    subject_type: 'user',
    subject_uuid: subject,
    subject_relation: '',
    subject_partition: null,
    created_at: new Date(),
  }
}

test.group('rotación 2 · cierre 3b · L12 · gemelo de relaciones: membersOf de database en UNA foto', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
    return async () => {
      await db.from('authz_relations').delete()
    }
  })

  test('H1 (auditor) · offboarding suelto (unrelate y luego removeDeny) entre sentencias ⇒ membersOf NO lista a U (S0, S1 y S2: U no es miembro en ninguno)', async ({ assert }) => {
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const u = uuidv7()
    const v = uuidv7()
    await db.table('authz_relations').multiInsert([relationRow(p, doc.id, 'viewer', u), relationRow(p, doc.id, 'denied_viewer', u), relationRow(p, doc.id, 'viewer', v)])
    const plain = new DatabaseRelationsDriver(contractDenyRelationsConfig(), { transactionalWrites: false })
    assert.sameMembers((await plain.membersOf(doc, 'viewer', p)).subjects.map((s: any) => s.uuid), [v], 'S0: U denegado no es miembro')
    const spy = interleavedDatabase()
    spy.arm(async () => {
      await db.from('authz_relations').where({ relation: 'viewer', subject_uuid: u }).delete()
      await db.from('authz_relations').where({ relation: 'denied_viewer', subject_uuid: u }).delete()
    })
    const torn = new DatabaseRelationsDriver(contractDenyRelationsConfig(), { transactionalWrites: false }, spy.database as any)
    const answer = (await torn.membersOf(doc, 'viewer', p)).subjects.map((s: any) => s.uuid)
    assert.isTrue(spy.fired(), 'el entrelazado se disparó')
    assert.match(spy.texts[0], /WITH RECURSIVE grp/, 'el espía cayó tras la sentencia de candidatos')
    assert.notInclude(answer, u, 'ROJO (L12, gemelo en relaciones): membersOf listó a U, que no es miembro en ningún estado real')
    assert.sameMembers(answer, [v])
    assert.sameMembers((await plain.membersOf(doc, 'viewer', p)).subjects.map((s: any) => s.uuid), [v], 'S2: el offboarding aterrizó')
    assert.isFalse(await plain.check({ type: 'user', uuid: u }, 'viewer', doc, p))
  })

  test('membersOf (tester) · offboarding del ÚNICO miembro (quita la membresía y DESPUÉS el deny) entre sentencias ⇒ []', async ({ assert }) => {
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const alice = uuidv7()
    await db.table('authz_relations').multiInsert([relationRow(p, doc.id, 'viewer', alice), relationRow(p, doc.id, 'denied_viewer', alice)])
    const spy = interleavedDatabase()
    const driver = new DatabaseRelationsDriver(contractDenyRelationsConfig(), { transactionalWrites: false }, spy.database as any)
    assert.deepEqual((await driver.membersOf(doc, 'viewer', p)).subjects, [], 'ANTES: el deny lo resta')
    spy.arm(async () => {
      await db.from('authz_relations').where('relation', 'viewer').where('subject_uuid', alice).delete()
      await db.from('authz_relations').where('relation', 'denied_viewer').where('subject_uuid', alice).delete()
    })
    const torn = (await driver.membersOf(doc, 'viewer', p)).subjects
    assert.isTrue(spy.fired(), 'el espía corrió')
    assert.lengthOf(await db.from('authz_relations').select('uuid'), 0, 'el offboarding aterrizó')
    assert.deepEqual(torn, [], `ROJO (L12, gemelo en relaciones): membersOf listó ${JSON.stringify(torn)}`)
  })

  test('membersOf · CONTROL POSITIVO: solo un relate entre sentencias ⇒ la foto es la de ANTES ([]) y la siguiente lo lista; sin deny es UNA sentencia', async ({ assert }) => {
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const alice = uuidv7()
    const spy = interleavedDatabase()
    const driver = new DatabaseRelationsDriver(contractDenyRelationsConfig(), { transactionalWrites: false }, spy.database as any)
    spy.arm(async () => {
      await db.table('authz_relations').insert(relationRow(p, doc.id, 'viewer', alice))
    })
    assert.deepEqual((await driver.membersOf(doc, 'viewer', p)).subjects, [])
    assert.isTrue(spy.fired())
    assert.lengthOf(spy.texts, 1, 'una sola sentencia: candidatos y puerta de denies juntos')
    assert.deepEqual((await driver.membersOf(doc, 'viewer', p)).subjects.map((s: any) => s.uuid), [alice], 'el estado posterior lo lista')
  })
})
