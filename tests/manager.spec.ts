/**
 * El manager es la fachada del motor: resuelve el driver del config y avisa
 * de cada escritura al consumidor. Lo que se prueba aquí es el borde con ese
 * consumidor — la semántica de autorización la juzga contract.spec.ts.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { AuthorizationManager } from '../src/manager.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { APP_SCOPE } from '../src/types.js'
import type { AuthzWriteEvent } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'

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

  test('un hook que lanza NO tumba la escritura que ya se aplicó', async ({ assert }) => {
    // El contrato dice "el hook no debe lanzar", pero nada lo impedía: un
    // fallo al auditar propagaba el error al llamante DESPUÉS de que el grant
    // estuviera en la base — el llamante ve un error y el permiso concedido.
    const manager = makeManager(() => {
      throw new Error('el sistema de auditoría está caído')
    })
    const holder = { type: 'users', uuid: uuidv7() }

    const logged = await captureErrorLog(() => manager.grant(holder, 'editor', APP_SCOPE))

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
