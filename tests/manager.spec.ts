/**
 * El manager es la fachada del motor: resuelve el driver del config y avisa
 * de cada escritura al consumidor. Lo que se prueba aquí es el borde con ese
 * consumidor — la semántica de autorización la juzga contract.spec.ts.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { AuthorizationManager } from '../src/manager.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { syncAuthzCatalog, diffAuthzCatalog, catalogInSync, runCatalogDiff } from '../src/catalog.js'
import { APP_SCOPE } from '../src/types.js'
import type { AuthzWriteEvent } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { memoryScopeTree, resolveAncestorsFrom } from '../src/testing/main.js'
import type { ContractScopeTree } from '../src/testing/main.js'
import type { ScopeRef } from '../src/types.js'

/**
 * Recoge lo que el motor manda a `console.error` mientras corre `fn`.
 *
 * Fuera de una app con logger en el contenedor —como esta suite— el registro
 * del fallo cae a `console.error`. Capturarlo sirve para dos cosas: afirmar
 * que el fallo SE REPORTA (tragárselo no es lo mismo que ocultarlo) y no
 * llenar la salida de trazas alarmantes que son el comportamiento correcto.
 */
async function captureErrorLog(fn: () => Promise<void>): Promise<string[]> {
  const lines: string[] = []
  const original = console.error
  console.error = (...args: unknown[]) => void lines.push(args.map(String).join(' '))
  try {
    await fn()
  } finally {
    console.error = original
  }
  return lines
}

function makeManager(onWrite?: (event: AuthzWriteEvent) => Promise<void> | void) {
  return new AuthorizationManager({
    default: 'database',
    drivers: { database: () => new DatabaseAuthorizationDriver() },
    hooks: onWrite ? { onWrite } : undefined,
  } as any)
}

test.group('manager', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  test('grant/revoke delegan en el driver y notifican al consumidor', async ({ assert }) => {
    const events: AuthzWriteEvent[] = []
    const manager = makeManager((event) => {
      events.push(event)
    })
    const holder = { type: 'users', uuid: uuidv7() }

    await manager.grant(holder, 'editor', APP_SCOPE)
    assert.isTrue(await manager.authorize(holder, 'docs:read', APP_SCOPE))

    await manager.revoke(holder, 'editor', APP_SCOPE)
    assert.isFalse(await manager.authorize(holder, 'docs:read', APP_SCOPE))

    assert.deepEqual(
      events.map((e) => e.action),
      ['granted', 'revoked']
    )
  })

  test("cambiar la caducidad de una asignación existente notifica 'extended' con la anterior", async ({
    assert,
  }) => {
    // L0.4. Un re-grant que alarga, acorta o quita la caducidad es un evento
    // distinto de "concedido": quien audita necesita ver de qué caducidad se
    // pasó a cuál. Un re-grant sin opciones sobre una vigente no cambia nada
    // y sigue siendo 'granted' (idempotente).
    const events: AuthzWriteEvent[] = []
    const manager = makeManager((event) => void events.push(event))
    const holder = { type: 'users', uuid: uuidv7() }
    const expiresAt = new Date(Date.now() + 3_600_000)

    await manager.grant(holder, 'editor', APP_SCOPE, { expiresAt })
    await manager.grant(holder, 'editor', APP_SCOPE)
    await manager.grant(holder, 'editor', APP_SCOPE, { expiresAt: null })

    assert.deepEqual(
      events.map((e) => e.action),
      ['granted', 'granted', 'extended']
    )
    const extended = events[2]
    assert.closeTo(extended.previousExpiresAt!.getTime(), expiresAt.getTime(), 1_000)
    assert.isNull(extended.expiresAt)
    // El 'granted' intermedio informa la caducidad que quedó (la preservada).
    assert.closeTo((events[1] as any).expiresAt.getTime(), expiresAt.getTime(), 1_000)
  })

  test('un hook que lanza NO tumba la escritura que ya se aplicó', async ({ assert }) => {
    // El contrato dice "el hook no debe lanzar", pero nada lo impedía: un
    // fallo al auditar propagaba el error al llamante DESPUÉS de que el grant
    // estuviera en la base — el llamante ve un error y el permiso concedido.
    const manager = makeManager(() => {
      throw new Error('el sistema de auditoría está caído')
    })
    const holder = { type: 'users', uuid: uuidv7() }

    const logged = await captureErrorLog(async () => void (await manager.grant(holder, 'editor', APP_SCOPE)))

    assert.isTrue(await manager.authorize(holder, 'docs:read', APP_SCOPE))
    // Tragarse el fallo NO es lo mismo que ocultarlo: tiene que quedar registro.
    assert.isNotEmpty(logged)
    assert.include(logged.join(' '), 'granted')
  })

  test('un hook async que rechaza tampoco propaga', async ({ assert }) => {
    const manager = makeManager(async () => {
      throw new Error('timeout escribiendo el log')
    })
    const holder = { type: 'users', uuid: uuidv7() }

    const logged = await captureErrorLog(() => manager.deny(holder, 'docs:read', APP_SCOPE))

    assert.isFalse(await manager.authorize(holder, 'docs:read', APP_SCOPE))
    assert.isNotEmpty(logged)
    assert.include(logged.join(' '), 'denied')
  })

  test('el manager rechaza una identidad inválida sin llamar al driver ni al hook', async ({
    assert,
  }) => {
    // L0.5: la validación vive en el manager (una vez, no por driver). Un
    // driver de terceros que no valide sigue protegido detrás de la fachada.
    const driverCalls: string[] = []
    const events: AuthzWriteEvent[] = []
    const fakeDriver: any = {}
    for (const method of ['authorize', 'grant', 'revoke', 'hasRole', 'deny', 'removeDeny', 'listSubjects', 'listRoles', 'listRoleScopes', 'listScopes']) {
      fakeDriver[method] = async () => {
        driverCalls.push(method)
        return true
      }
    }
    const manager = new AuthorizationManager({
      default: 'fake',
      drivers: { fake: () => fakeDriver },
      hooks: { onWrite: async (event: AuthzWriteEvent) => void events.push(event) },
    } as any)

    const bad: Array<[string, () => Promise<unknown>]> = [
      ['uuid undefined', () => manager.grant({ type: 'users', uuid: undefined as any }, 'editor', APP_SCOPE)],
      ['uuid con #', () => manager.authorize({ type: 'users', uuid: 'u#x' }, 'docs:read', APP_SCOPE)],
      ['app con uuid', () => manager.deny({ type: 'users', uuid: uuidv7() }, 'docs:read', { type: 'app', uuid: 'X' })],
      ['centinela', () => manager.hasRole({ type: 'users', uuid: uuidv7() }, 'editor', { type: 'organization', uuid: '00000000-0000-0000-0000-000000000000' })],
      ['rol con ~', () => manager.revoke({ type: 'users', uuid: uuidv7() }, 'docs~read', APP_SCOPE)],
      ['permiso con |', () => manager.removeDeny({ type: 'users', uuid: uuidv7() }, 'docs|read', APP_SCOPE)],
      ['scopeType vacío', () => manager.listRoleScopes({ type: 'users', uuid: uuidv7() }, '')],
    ]
    for (const [label, call] of bad) {
      try {
        await call()
        assert.fail(`${label}: debería haber rechazado`)
      } catch (error: any) {
        assert.equal(error.status, 422, label)
        assert.match(String(error.code), /^E_AUTHZ_INVALID_(IDENTITY|SLUG)$/, label)
      }
    }
    assert.deepEqual(driverCalls, [])
    assert.deepEqual(events, [])
  })

  test('sin resolutor de ancestros, cualquier scope que no sea app es 422 E_AUTHZ_NO_SCOPE_RESOLVER', async ({
    assert,
  }) => {
    // L0.3. El default plano (`todo cuelga de app`) desaparece: un driver sin
    // `resolveAncestors` solo sabe de la raíz. Con él, una organization no
    // "cuelga de app" en silencio — hoy eso hacía que un grant a nivel app
    // valiera en un scope inventado. No es un `false` (sería ocultar un
    // despliegue mal configurado) ni un 500 (la app sigue sirviendo `app`).
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] }],
    })
    const manager = makeManager()
    const holder = { type: 'users', uuid: uuidv7() }
    const org = { type: 'organization', uuid: uuidv7() }
    const expected = { status: 422, code: 'E_AUTHZ_NO_SCOPE_RESOLVER' }

    for (const [label, call] of [
      ['grant', () => manager.grant(holder, 'org-editor', org)],
      ['authorize', () => manager.authorize(holder, 'docs:read', org)],
      ['hasRole', () => manager.hasRole(holder, 'org-editor', org)],
      ['deny', () => manager.deny(holder, 'docs:read', org)],
    ] as Array<[string, () => Promise<unknown>]>) {
      try {
        await call()
        assert.fail(`${label}: debería haber rechazado`)
      } catch (error: any) {
        assert.equal(error.status, expected.status, `${label}: ${error.message}`)
        assert.equal(error.code, expected.code, label)
      }
    }
    // La raíz sigue funcionando sin resolutor.
    await manager.grant(holder, 'editor', APP_SCOPE)
    assert.isTrue(await manager.authorize(holder, 'docs:read', APP_SCOPE))
  })

  test('un driver no registrado falla con la lista de los que sí', async ({ assert }) => {
    const manager = new AuthorizationManager({
      default: 'no-existe',
      drivers: { database: () => new DatabaseAuthorizationDriver() },
    } as any)

    await assert.rejects(
      () => manager.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE),
      /no registrado/
    )
  })
})

test.group('catálogo', (group) => {
  group.each.setup(cleanAuthzTables)

  test('sincronizar es idempotente', async ({ assert }) => {
    const catalog = {
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'docs:write'] }],
    }
    await syncAuthzCatalog(catalog)
    await syncAuthzCatalog(catalog)

    const { default: db } = await import('@adonisjs/lucid/services/db')
    const roles = await db.from('authz_roles').select('uuid')
    const perms = await db.from('authz_permissions').select('uuid')
    const links = await db.from('authz_role_permissions').select('uuid')
    assert.lengthOf(roles, 1)
    assert.lengthOf(perms, 2)
    assert.lengthOf(links, 2)
  })

  test('un slug inválido se rechaza antes de escribir nada', async ({ assert }) => {
    await assert.rejects(() =>
      syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }],
        roles: [{ slug: 'rol|invalido', scopeType: 'app', permissions: ['docs:read'] }],
      })
    )

    const { default: db } = await import('@adonisjs/lucid/services/db')
    assert.lengthOf(await db.from('authz_permissions').select('uuid'), 0)
  })

  test('slugs reservados, familias, longitud y colisión tras codificar ⇒ 422 sin escribir', async ({
    assert,
  }) => {
    // L0.8a / S4 / S13 / S14. El catálogo es la puerta de entrada de los
    // slugs: lo que pase aquí termina como nombre de relación FGA. `parent`
    // invalidaría el modelo entero; `can_docs_write` colapsaría con la
    // relación derivada de `docs:write` y anularía su deny; `docs_write` y
    // `docs:write` serían UNA relación.
    const { default: db } = await import('@adonisjs/lucid/services/db')
    const bad: Array<[string, Parameters<typeof syncAuthzCatalog>[0]]> = [
      ['reservado', { permissions: [{ slug: 'parent' }], roles: [] }],
      ['familia can_', { permissions: [{ slug: 'can_docs_write' }], roles: [] }],
      ['familia denied_ en rol', { permissions: [], roles: [{ slug: 'denied_x', scopeType: 'app', permissions: [] }] }],
      ['101 caracteres', { permissions: [{ slug: 'a'.repeat(101) }], roles: [] }],
      ['43 caracteres (42 + prefijo permits_ > 50)', { permissions: [{ slug: 'a'.repeat(43) }], roles: [] }],
      ['colisión docs:write / docs_write', { permissions: [{ slug: 'docs:write' }, { slug: 'docs_write' }], roles: [] }],
      ['rol con :', { permissions: [], roles: [{ slug: 'org:editor', scopeType: 'app', permissions: [] }] }],
    ]
    for (const [label, catalog] of bad) {
      try {
        await syncAuthzCatalog(catalog)
        assert.fail(`${label}: debería haber rechazado`)
      } catch (error: any) {
        assert.equal(error.status, 422, `${label}: ${error.message}`)
        assert.equal(error.code, 'E_AUTHZ_INVALID_SLUG', label)
      }
    }
    assert.lengthOf(await db.from('authz_permissions').select('uuid'), 0)
    assert.lengthOf(await db.from('authz_roles').select('uuid'), 0)

    // Frontera: 42 cabe; la gramática con un ':' también.
    await syncAuthzCatalog({ permissions: [{ slug: 'a'.repeat(42) }, { slug: 'docs:write' }], roles: [] })
    assert.lengthOf(await db.from('authz_permissions').select('uuid'), 2)
  })

  test('un fallo a mitad no deja el catálogo aplicado a medias', async ({ assert }) => {
    // Dos roles con el MISMO uuid explícito: el primero entra, el segundo
    // viola la primary key. Sin transacción quedaban escritos el permiso y el
    // primer rol — holders con un rol que no concede lo que el config decía.
    const collidingUuid = uuidv7()

    await assert.rejects(() =>
      syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }],
        roles: [
          { slug: 'editor', scopeType: 'app', uuid: collidingUuid, permissions: ['docs:read'] },
          { slug: 'viewer', scopeType: 'app', uuid: collidingUuid, permissions: ['docs:read'] },
        ],
      })
    )

    const { default: db } = await import('@adonisjs/lucid/services/db')
    assert.lengthOf(await db.from('authz_permissions').select('uuid'), 0)
    assert.lengthOf(await db.from('authz_roles').select('uuid'), 0)
    assert.lengthOf(await db.from('authz_role_permissions').select('uuid'), 0)
  })

  test('quitar un permiso de un rol y re-sincronizar lo retira (prune: links por defecto)', async ({
    assert,
  }) => {
    // L0.9 / N1. Reproducción del panel: `authorize docs:write TRAS el sync
    // que lo quitó: true`. El config era la única fuente de verdad visible y
    // mentía sobre los permisos efectivos.
    const { default: db } = await import('@adonisjs/lucid/services/db')
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'docs:write'] }],
    })
    const manager = makeManager()
    const holder = { type: 'users', uuid: uuidv7() }
    await manager.grant(holder, 'editor', APP_SCOPE)
    assert.isTrue(await manager.authorize(holder, 'docs:write', APP_SCOPE))

    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })

    assert.isFalse(await manager.authorize(holder, 'docs:write', APP_SCOPE))
    assert.isTrue(await manager.authorize(holder, 'docs:read', APP_SCOPE))
    assert.lengthOf(await db.from('authz_role_permissions').select('uuid'), 1)
    // Nunca borra roles ni permisos: `docs:write` sigue en el catálogo.
    assert.lengthOf(await db.from('authz_permissions').select('uuid'), 2)
    assert.lengthOf(await db.from('authz_roles').select('uuid'), 1)
  })

  test('dos catálogos coexisten: sincronizar uno no toca los vínculos del otro', async ({
    assert,
  }) => {
    const { default: db } = await import('@adonisjs/lucid/services/db')
    const platform = {
      permissions: [{ slug: 'audit:read' }],
      roles: [{ slug: 'support', scopeType: 'app', permissions: ['audit:read'] }],
    }
    const tenant = {
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read', 'docs:write'] }],
    }
    await syncAuthzCatalog(platform)
    await syncAuthzCatalog(tenant)
    // Re-sync del primero con la poda activa: el segundo queda intacto.
    await syncAuthzCatalog(platform)
    await syncAuthzCatalog({ ...platform, roles: [{ ...platform.roles[0], permissions: [] }] })

    const links = await db
      .from('authz_role_permissions as rp')
      .join('authz_roles as r', 'r.uuid', 'rp.role_uuid')
      .join('authz_permissions as p', 'p.uuid', 'rp.permission_uuid')
      .select('r.slug as role', 'p.slug as permission')
    assert.deepEqual(
      links.map((l: any) => `${l.role}→${l.permission}`).sort(),
      ['org-editor→docs:read', 'org-editor→docs:write']
    )
  })

  test("prune: 'none' conserva los vínculos que el spec ya no lista", async ({ assert }) => {
    const { default: db } = await import('@adonisjs/lucid/services/db')
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'docs:write'] }],
    })
    await syncAuthzCatalog(
      {
        permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
        roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
      },
      { prune: 'none' }
    )
    assert.lengthOf(await db.from('authz_role_permissions').select('uuid'), 2)
  })

  test('un rol que concede un permiso que no existe en ningún catálogo es 422 E_AUTHZ_UNKNOWN_PERMISSION, sin escribir', async ({
    assert,
  }) => {
    // Antes se saltaba en silencio (`if (!permUuid) continue`): el config
    // decía que el rol concedía algo que en la base no existía. Un permiso
    // sincronizado por OTRO catálogo sí vale (coexistencia).
    const { default: db } = await import('@adonisjs/lucid/services/db')
    let caught: any
    try {
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }],
        roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'no:existe'] }],
      })
      assert.fail('debería haber rechazado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 422)
    assert.equal(caught.code, 'E_AUTHZ_UNKNOWN_PERMISSION')
    assert.lengthOf(await db.from('authz_permissions').select('uuid'), 0)
    assert.lengthOf(await db.from('authz_roles').select('uuid'), 0)

    await syncAuthzCatalog({ permissions: [{ slug: 'audit:read' }], roles: [] })
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'audit:read'] }],
    })
    assert.lengthOf(await db.from('authz_role_permissions').select('uuid'), 2)
  })

  test('diffAuthzCatalog: lista lo que falta y los vínculos sobrantes; runCatalogDiff falla si hay diferencias', async ({
    assert,
  }) => {
    // Lo que hace `authz:catalog:diff` (el comando es un envoltorio fino).
    const before = {
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [{ slug: 'editor', scopeType: 'app', rank: 10, permissions: ['docs:read', 'docs:write'] }],
    }
    await syncAuthzCatalog(before)
    assert.isTrue(catalogInSync(await diffAuthzCatalog(before)))

    const after = {
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }, { slug: 'billing:read' }],
      roles: [
        { slug: 'editor', scopeType: 'app', rank: 20, permissions: ['docs:read', 'billing:read'] },
        { slug: 'auditor', scopeType: 'app', permissions: ['billing:read'] },
      ],
    }
    const diff = await diffAuthzCatalog(after)
    assert.isFalse(catalogInSync(diff))
    assert.deepEqual(diff.missingPermissions, ['billing:read'])
    assert.deepEqual(diff.missingRoles, [{ slug: 'auditor', scopeType: 'app' }])
    assert.deepEqual(diff.missingLinks, [
      { role: 'editor', scopeType: 'app', permission: 'billing:read' },
      { role: 'auditor', scopeType: 'app', permission: 'billing:read' },
    ])
    assert.deepEqual(diff.extraLinks, [{ role: 'editor', scopeType: 'app', permission: 'docs:write' }])
    assert.deepEqual(diff.rankMismatches, [{ role: 'editor', scopeType: 'app', expected: 20, actual: 10 }])

    const failing = await runCatalogDiff([async () => before, async () => after])
    assert.isFalse(failing.inSync)
    assert.include(failing.lines.join('\n'), 'editor')
    assert.include(failing.lines.join('\n'), 'docs:write')

    await syncAuthzCatalog(after)
    const ok = await runCatalogDiff([async () => after])
    assert.isTrue(ok.inSync)
  })

  test('el rank del config manda sobre el almacenado', async ({ assert }) => {
    await syncAuthzCatalog({
      permissions: [],
      roles: [{ slug: 'admin', scopeType: 'app', rank: 10, permissions: [] }],
    })
    await syncAuthzCatalog({
      permissions: [],
      roles: [{ slug: 'admin', scopeType: 'app', rank: 50, permissions: [] }],
    })

    const { default: db } = await import('@adonisjs/lucid/services/db')
    const role = await db.from('authz_roles').where('slug', 'admin').first()
    assert.equal(role.rank, 50)
  })
})

/**
 * `scopes.attached/moved/detached`: el consumidor notifica los cambios de su
 * árbol y el PAQUETE valida (raíz, existencia del padre, ciclos) antes de
 * tocar el driver — FGA acepta ciclos y los evalúa (S2), así que la única
 * barrera es esta. `detached` purga los hechos (N7) y lo audita.
 */
test.group('manager.scopes', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [
        { slug: 'editor', scopeType: 'app', permissions: ['docs:read'] },
        { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] },
      ],
    })
  })

  const org = (): ScopeRef => ({ type: 'organization', uuid: uuidv7() })
  const unit = (): ScopeRef => ({ type: 'unit', uuid: uuidv7() })

  /** Driver falso que anota qué se le llama; el manager no debe llamarlo si la validación falla. */
  function fakeDriver() {
    const calls: string[] = []
    const driver: any = {}
    for (const method of ['authorize', 'grant', 'revoke', 'hasRole', 'deny', 'removeDeny', 'listSubjects', 'listRoles', 'listRoleScopes', 'listScopes', 'purgeScope', 'onScopeAttached', 'onScopeMoved', 'onScopeDetached']) {
      driver[method] = async () => void calls.push(method)
    }
    return { driver, calls }
  }

  function managerOver(tree: ContractScopeTree, driver: any, onWrite?: (e: AuthzWriteEvent) => void) {
    return new AuthorizationManager({
      default: 'fake',
      drivers: { fake: () => driver },
      scopes: { resolveAncestors: resolveAncestorsFrom(tree) },
      hooks: onWrite ? { onWrite: async (e: AuthzWriteEvent) => void onWrite(e) } : undefined,
    } as any)
  }

  async function rejects(assert: any, fn: () => Promise<unknown>, expected: { status: number; code: string }, label: string) {
    try {
      await fn()
      assert.fail(`${label}: debería haber rechazado`)
    } catch (error: any) {
      assert.equal(error.status, expected.status, `${label}: ${error.message}`)
      assert.equal(error.code, expected.code, label)
    }
  }

  test('un ciclo es 422 E_AUTHZ_SCOPE_CYCLE en el paquete, sin llamar al driver', async ({ assert }) => {
    // N9 / S2. `attached(orgA, unitA1)` con unitA1 bajo orgA cerraría el
    // ciclo app ← orgA ← unitA1 ← orgA: FGA lo aceptaría y un grant en orgA
    // concedería en la raíz. Aquí no llega ni al driver.
    const tree = memoryScopeTree()
    const orgA = org()
    const unitA1 = unit()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(unitA1, orgA)
    const { driver, calls } = fakeDriver()
    const manager = managerOver(tree, driver)
    const cycle = { status: 422, code: 'E_AUTHZ_SCOPE_CYCLE' }

    await rejects(assert, () => manager.scopes.attached(orgA, unitA1), cycle, 'attached ancestro bajo descendiente')
    await rejects(assert, () => manager.scopes.moved(orgA, unitA1), cycle, 'moved ancestro bajo descendiente')
    await rejects(assert, () => manager.scopes.attached(orgA, orgA), cycle, 'attached a sí mismo')
    await rejects(assert, () => manager.scopes.moved(unitA1, unitA1), cycle, 'moved a sí mismo')
    assert.deepEqual(calls, [])
  })

  test('la raíz no cuelga de nada y un padre desconocido es 422 E_AUTHZ_UNKNOWN_SCOPE', async ({ assert }) => {
    const tree = memoryScopeTree()
    const orgA = org()
    await tree.attach(orgA, APP_SCOPE)
    const { driver, calls } = fakeDriver()
    const manager = managerOver(tree, driver)

    await rejects(assert, () => manager.scopes.attached(APP_SCOPE, orgA), { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }, 'app como hijo')
    await rejects(assert, () => manager.scopes.moved(APP_SCOPE, orgA), { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }, 'mover app')
    await rejects(assert, () => manager.scopes.detached(APP_SCOPE), { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }, 'borrar app')
    await rejects(assert, () => manager.scopes.attached(unit(), org()), { status: 422, code: 'E_AUTHZ_UNKNOWN_SCOPE' }, 'padre fantasma')
    await rejects(assert, () => manager.scopes.moved(orgA, org()), { status: 422, code: 'E_AUTHZ_UNKNOWN_SCOPE' }, 'mover a padre fantasma')
    await rejects(assert, () => manager.scopes.attached({ type: 'app', uuid: 'X' } as any, orgA), { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }, 'identidad rota')
    assert.deepEqual(calls, [])
  })

  test('sin config.scopes.resolveAncestors, usar scopes.* es 500 E_AUTHZ_CONFIG', async ({ assert }) => {
    const { driver, calls } = fakeDriver()
    const manager = new AuthorizationManager({ default: 'fake', drivers: { fake: () => driver } } as any)
    const orgA = org()
    const expected = { status: 500, code: 'E_AUTHZ_CONFIG' }
    await rejects(assert, () => manager.scopes.attached(orgA, APP_SCOPE), expected, 'attached')
    await rejects(assert, () => manager.scopes.moved(orgA, APP_SCOPE), expected, 'moved')
    await rejects(assert, () => manager.scopes.detached(orgA), expected, 'detached')
    assert.deepEqual(calls, [])
  })

  test('attached/moved válidos avisan al driver (hooks opcionales) y a nada más', async ({ assert }) => {
    const tree = memoryScopeTree()
    const orgA = org()
    const orgB = org()
    const unitA1 = unit()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    const { driver, calls } = fakeDriver()
    const events: AuthzWriteEvent[] = []
    const manager = managerOver(tree, driver, (e) => events.push(e))

    await manager.scopes.attached(unitA1, orgA)
    await tree.attach(unitA1, orgA)
    await manager.scopes.moved(unitA1, orgB)
    assert.deepEqual(calls, ['onScopeAttached', 'onScopeMoved'])
    assert.deepEqual(events, [])

    // Un driver sin hooks (database) también vale: son opcionales.
    const bare: any = { purgeScope: async () => {} }
    const plain = managerOver(tree, bare)
    await plain.scopes.attached(unit(), orgA)
  })

  test('detached purga los hechos del scope (driver real), avisa al driver y notifica scope_purged', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = org()
    const orgB = org()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    const events: AuthzWriteEvent[] = []
    const hooks: string[] = []
    const real = new DatabaseAuthorizationDriver({ resolveAncestors: resolveAncestorsFrom(tree) })
    ;(real as any).onScopeDetached = async () => void hooks.push('onScopeDetached')
    const manager = managerOver(tree, real, (e) => events.push(e))
    const holder = { type: 'users', uuid: uuidv7() }
    await manager.grant(holder, 'org-editor', orgA)
    await manager.grant(holder, 'org-editor', orgB)
    await manager.deny(holder, 'docs:read', orgA)

    await manager.scopes.detached(orgA)

    assert.deepEqual(await manager.listRoles(holder, orgA), [])
    assert.deepEqual(await manager.listRoles(holder, orgB), ['org-editor'])
    assert.deepEqual(hooks, ['onScopeDetached'])
    const purged = events.find((e) => e.action === 'scope_purged')
    assert.exists(purged)
    assert.deepEqual(purged!.scope, orgA)
    // El árbol del consumidor se actualiza aparte; al quitar la arista, nada resucita.
    await tree.detach(orgA)
    await tree.attach(orgA, APP_SCOPE)
    assert.isFalse(await manager.authorize(holder, 'docs:read', orgA))
    assert.deepEqual(await manager.listRoles(holder, orgA), [])
  })
})
