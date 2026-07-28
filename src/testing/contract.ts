import '@japa/assert'
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import type {
  AuthorizationDriver,
  CatalogSpec,
  ScopeRef,
  SubjectRef,
} from '../types.js'
import { APP_SCOPE } from '../types.js'

/**
 * Suite de contrato del sistema de autorización — EL JUEZ.
 *
 * Cualquier driver (database, openfga, custom del consumidor) debe pasar
 * estos casos sin modificarlos: son la definición ejecutable de la semántica
 * documentada en `#services/authorization/types`. Para enchufar un driver:
 *
 *   runAuthorizationDriverContract({
 *     name: 'mi-driver',
 *     makeDriver: () => new MiDriver(),
 *     seedCatalog: (catalog) => ...,   // materializa roles/permisos
 *     cleanup: () => ...,              // borra hechos + catálogo entre tests
 *   })
 *
 * `seedCatalog`/`cleanup` son del harness (no del contrato) porque cada
 * backend materializa el catálogo a su manera (tablas propias, FGA model...).
 */

export interface DriverContractHarness {
  name: string
  makeDriver: () => AuthorizationDriver | Promise<AuthorizationDriver>
  seedCatalog: (catalog: CatalogSpec) => Promise<void>
  cleanup: () => Promise<void>
}

/** Catálogo de prueba: roles a nivel app y a nivel organization. */
const CONTRACT_CATALOG: CatalogSpec = {
  permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }, { slug: 'billing:read' }],
  roles: [
    { slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'docs:write'] },
    { slug: 'viewer', scopeType: 'app', permissions: ['docs:read'] },
    { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read', 'docs:write'] },
  ],
}

function subject(type: string = 'users'): SubjectRef {
  return { type, uuid: uuidv7() }
}

function orgScope(uuid: string = uuidv7()): ScopeRef {
  return { type: 'organization', uuid }
}

export function runAuthorizationDriverContract(harness: DriverContractHarness) {
  test.group(`authorization contract [${harness.name}]`, (group) => {
    let driver: AuthorizationDriver

    group.each.setup(async () => {
      await harness.cleanup()
      await harness.seedCatalog(CONTRACT_CATALOG)
      driver = await harness.makeDriver()
    })

    group.teardown(async () => {
      await harness.cleanup()
    })

    test('grant de un rol concede sus permisos (authorize true)', async ({ assert }) => {
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })

    test('sin asignación → authorize false (denegación por defecto)', async ({ assert }) => {
      assert.isFalse(await driver.authorize(subject(), 'docs:read', APP_SCOPE))
    })

    test('permiso fuera del rol → false; permiso desconocido → false sin throw', async ({
      assert,
    }) => {
      const bob = subject()
      await driver.grant(bob, 'viewer', APP_SCOPE)
      assert.isTrue(await driver.authorize(bob, 'docs:read', APP_SCOPE))
      assert.isFalse(await driver.authorize(bob, 'docs:write', APP_SCOPE))
      assert.isFalse(await driver.authorize(bob, 'no:existe', APP_SCOPE))
    })

    test('revoke retira el permiso', async ({ assert }) => {
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.revoke(alice, 'editor', APP_SCOPE)
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('grant de rol inexistente para el scope lanza', async ({ assert }) => {
      await assert.rejects(() => driver.grant(subject(), 'no-existe', APP_SCOPE))
      // org-editor existe pero a nivel organization, no app:
      await assert.rejects(() => driver.grant(subject(), 'org-editor', APP_SCOPE))
    })

    test('deny explícito gana sobre el rol; removeDeny lo restaura', async ({ assert }) => {
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.deny(alice, 'docs:write', APP_SCOPE)

      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
      // El deny es quirúrgico: solo bloquea ese permiso.
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))

      await driver.removeDeny(alice, 'docs:write', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })

    test('deny de permiso desconocido lanza (error de programación)', async ({ assert }) => {
      await assert.rejects(() => driver.deny(subject(), 'no:existe', APP_SCOPE))
    })

    test('asignación expirada no concede; expiración futura sí', async ({ assert }) => {
      const past = subject()
      await driver.grant(past, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() - 60_000),
      })
      assert.isFalse(await driver.authorize(past, 'docs:read', APP_SCOPE))

      const future = subject()
      await driver.grant(future, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() + 60_000),
      })
      assert.isTrue(await driver.authorize(future, 'docs:read', APP_SCOPE))
    })

    test('scope aislado: grant en una org NO autoriza en app ni en otra org', async ({
      assert,
    }) => {
      const alice = subject()
      const orgA = orgScope()
      const orgB = orgScope()
      await driver.grant(alice, 'org-editor', orgA)

      assert.isTrue(await driver.authorize(alice, 'docs:write', orgA))
      assert.isFalse(await driver.authorize(alice, 'docs:write', orgB))
      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })

    test('herencia hacia abajo: grant a nivel app autoriza dentro de una org', async ({
      assert,
    }) => {
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:write', orgScope()))
    })

    test('deny en el scope cercano bloquea el grant heredado, solo ahí', async ({ assert }) => {
      const alice = subject()
      const orgA = orgScope()
      const orgB = orgScope()
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.deny(alice, 'docs:write', orgA)

      assert.isFalse(await driver.authorize(alice, 'docs:write', orgA))
      assert.isTrue(await driver.authorize(alice, 'docs:write', orgB))
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })

    test('holder polimórfico: mismo uuid con distinto type no se cruzan', async ({ assert }) => {
      const uuid = uuidv7()
      const asUser: SubjectRef = { type: 'users', uuid }
      const asAdmin: SubjectRef = { type: 'admins', uuid }
      await driver.grant(asUser, 'editor', APP_SCOPE)

      assert.isTrue(await driver.authorize(asUser, 'docs:read', APP_SCOPE))
      assert.isFalse(await driver.authorize(asAdmin, 'docs:read', APP_SCOPE))
    })

    test('grant duplicado es idempotente (y refresca expiresAt)', async ({ assert }) => {
      const alice = subject()
      // Primera vez expirada, re-grant sin expiración: debe quedar vigente y única.
      await driver.grant(alice, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() - 60_000),
      })
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.grant(alice, 'editor', APP_SCOPE)

      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      const holders = await driver.listSubjects('editor', APP_SCOPE)
      assert.lengthOf(
        holders.filter((h) => h.uuid === alice.uuid),
        1
      )
    })

    test('hasRole respeta scope, herencia y expiración', async ({ assert }) => {
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)

      assert.isTrue(await driver.hasRole(alice, 'editor', APP_SCOPE))
      // Herencia hacia abajo: el rol de app "vale" dentro de una org.
      assert.isTrue(await driver.hasRole(alice, 'editor', orgScope()))
      assert.isFalse(await driver.hasRole(alice, 'viewer', APP_SCOPE))

      await driver.revoke(alice, 'editor', APP_SCOPE)
      assert.isFalse(await driver.hasRole(alice, 'editor', APP_SCOPE))

      const expired = subject()
      await driver.grant(expired, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() - 60_000),
      })
      assert.isFalse(await driver.hasRole(expired, 'editor', APP_SCOPE))
    })

    test('listSubjects: holders vigentes del rol en el scope exacto', async ({ assert }) => {
      const alice = subject()
      const bob = subject()
      const expired = subject()
      const otherScope = orgScope()

      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.grant(bob, 'editor', APP_SCOPE)
      await driver.grant(expired, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() - 60_000),
      })
      await driver.grant(subject(), 'org-editor', otherScope)

      const holders = await driver.listSubjects('editor', APP_SCOPE)
      const uuids = holders.map((h) => h.uuid)
      assert.includeMembers(uuids, [alice.uuid, bob.uuid])
      assert.notInclude(uuids, expired.uuid)
    })

    test('listScopes: scopes directos que conceden el permiso, sin los denegados', async ({
      assert,
    }) => {
      const alice = subject()
      const orgA = orgScope()
      const orgB = orgScope()
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.grant(alice, 'org-editor', orgA)
      await driver.grant(alice, 'org-editor', orgB)
      await driver.deny(alice, 'docs:write', orgB)

      const scopes = await driver.listScopes(alice, 'docs:write')
      const keys = scopes.map((s) => `${s.type}:${s.uuid ?? ''}`)
      assert.includeMembers(keys, ['app:', `organization:${orgA.uuid}`])
      assert.notInclude(keys, `organization:${orgB.uuid}`)
    })

    test('revoke/removeDeny inexistentes son no-ops seguros', async ({ assert }) => {
      const ghost = subject()
      await driver.revoke(ghost, 'editor', APP_SCOPE)
      await driver.removeDeny(ghost, 'docs:read', APP_SCOPE)
      assert.isFalse(await driver.authorize(ghost, 'docs:read', APP_SCOPE))
    })

    test('listRoles: roles directos vigentes en el scope exacto', async ({ assert }) => {
      const alice = subject()
      const orgA = orgScope()
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.grant(alice, 'viewer', APP_SCOPE, {
        expiresAt: new Date(Date.now() - 60_000), // expirado: no cuenta
      })
      await driver.grant(alice, 'org-editor', orgA)

      const appRoles = await driver.listRoles(alice, APP_SCOPE)
      assert.deepEqual(appRoles.sort(), ['editor'])

      // El scope exacto manda: en la org NO aparece el rol de app (eso es
      // herencia de authorize/hasRole, no membresía directa).
      const orgRoles = await driver.listRoles(alice, orgA)
      assert.deepEqual(orgRoles, ['org-editor'])

      assert.deepEqual(await driver.listRoles(subject(), APP_SCOPE), [])
    })

    test('listRoleScopes: scopes del tipo con algún rol directo vigente', async ({ assert }) => {
      const alice = subject()
      const orgA = orgScope()
      const orgB = orgScope()
      await driver.grant(alice, 'org-editor', orgA)
      await driver.grant(alice, 'org-editor', orgB, {
        expiresAt: new Date(Date.now() - 60_000), // expirado: fuera
      })
      await driver.grant(alice, 'editor', APP_SCOPE)

      const orgs = await driver.listRoleScopes(alice, 'organization')
      assert.deepEqual(
        orgs.map((s) => s.uuid),
        [orgA.uuid]
      )
      // El tipo filtra: el grant a nivel app no aparece como organization.
      const apps = await driver.listRoleScopes(alice, 'app')
      assert.lengthOf(apps, 1)
      assert.isNull(apps[0].uuid)
    })
  })
}
