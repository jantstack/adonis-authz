/**
 * El manager es la fachada del motor: resuelve el driver del config y avisa
 * de cada escritura al consumidor. Lo que se prueba aquí es el borde con ese
 * consumidor — la semántica de autorización la juzga contract.spec.ts.
 */

import { test } from '@japa/runner'
import { withTableMissing } from './helpers/table_missing.js'
import { v7 as uuidv7 } from 'uuid'
import { AuthorizationManager } from '../src/manager.js'
import { AuthorizationBackendError, AuthorizationBackendTimeoutError } from '../src/errors.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { syncAuthzCatalog, diffAuthzCatalog, catalogInSync, runCatalogDiff, syncCatalogs } from '../src/catalog.js'
import { APP_SCOPE } from '../src/types.js'
import type { AuthzWriteEvent } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { descendantsFrom, memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
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
    warnOnOptInSecurity: false,
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

  test('un driver de terceros cuyo grant no devuelve GrantOutcome sigue notificando granted', async ({
    assert,
  }) => {
    // `GrantOutcome` es obligatorio en 2.0 para los drivers del paquete, pero
    // el manager no puede romperse con un driver externo que aún devuelva
    // `void`: sin outcome no hay caducidad anterior que contar, así que el
    // evento es 'granted' con lo que pidió el llamante. Y la firma no miente
    // (E1, tester §6.1): el manager NORMALIZA el `void` a
    // `{ existed: false, expiresAt: options?.expiresAt ?? null }`.
    const events: AuthzWriteEvent[] = []
    const fakeDriver: any = { grant: async () => undefined }
    const manager = new AuthorizationManager({
      default: 'fake',
      drivers: { fake: () => fakeDriver },
      hooks: { onWrite: async (event: AuthzWriteEvent) => void events.push(event) },
      warnOnOptInSecurity: false,
    } as any)
    const holder = { type: 'users', uuid: uuidv7() }
    const expiresAt = new Date(Date.now() + 3_600_000)

    const outcome = await manager.grant(holder, 'editor', APP_SCOPE, { expiresAt })
    assert.deepEqual(outcome, { existed: false, expiresAt })
    assert.deepEqual(await manager.grant(holder, 'editor', APP_SCOPE), { existed: false, expiresAt: null })
    assert.deepEqual(
      events.map((e) => e.action),
      ['granted', 'granted']
    )
    assert.equal(events[0].expiresAt?.getTime(), expiresAt.getTime())
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

  test('una escritura que vence el deadline notifica onWrite con indeterminate: true ANTES de propagar el 503', async ({
    assert,
  }) => {
    // D2 (auditor H1). Un timeout no significa "no ocurrió": la petición
    // puede aterrizar en el backend después de que el paquete devolviera 503.
    // Quien audita necesita saber que el resultado es DESCONOCIDO; un
    // silencio se lee como "no pasó nada" y deja un privilegio sin rastro.
    const events: AuthzWriteEvent[] = []
    const timeout = () => new AuthorizationBackendTimeoutError('fake', 'grant', 5)
    const fakeDriver: any = {
      grant: async () => {
        throw timeout()
      },
      deny: async () => {
        throw timeout()
      },
      revoke: async () => {
        throw new AuthorizationBackendError('fake', 'revoke', new Error('ECONNREFUSED'))
      },
    }
    const manager = new AuthorizationManager({
      default: 'fake',
      drivers: { fake: () => fakeDriver },
      hooks: { onWrite: async (event: AuthzWriteEvent) => void events.push(event) },
      warnOnOptInSecurity: false,
    } as any)
    const holder = { type: 'users', uuid: uuidv7() }
    const expiresAt = new Date(Date.now() + 3_600_000)

    for (const [label, call] of [
      ['grant', () => manager.grant(holder, 'editor', APP_SCOPE, { expiresAt })],
      ['deny', () => manager.deny(holder, 'docs:read', APP_SCOPE)],
    ] as Array<[string, () => Promise<unknown>]>) {
      let caught: any
      try {
        await call()
        assert.fail(`${label}: debería haber rechazado`)
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 503, label)
      assert.equal(caught.code, 'E_AUTHZ_BACKEND_TIMEOUT', label)
    }
    assert.deepEqual(
      events.map((e) => [e.action, e.indeterminate]),
      [
        ['granted', true],
        ['denied', true],
      ]
    )
    assert.equal(events[0].expiresAt?.getTime(), expiresAt.getTime())
    assert.deepEqual(events[0].subject, holder)

    // Un 503 que NO es timeout sí significa "no ocurrió": sin evento.
    await assert.rejects(() => manager.revoke(holder, 'editor', APP_SCOPE))
    assert.lengthOf(events, 2)
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
      warnOnOptInSecurity: false,
    } as any)

    const bad: Array<[string, () => Promise<unknown>]> = [
      ['uuid undefined', () => manager.grant({ type: 'users', uuid: undefined as any }, 'editor', APP_SCOPE)],
      ['uuid con #', () => manager.authorize({ type: 'users', uuid: 'u#x' }, 'docs:read', APP_SCOPE)],
      ['app con uuid', () => manager.deny({ type: 'users', uuid: uuidv7() }, 'docs:read', { type: 'app', uuid: 'X' })],
      ['centinela', () => manager.hasRole({ type: 'users', uuid: uuidv7() }, 'editor', { type: 'organization', uuid: '00000000-0000-0000-0000-000000000000' })],
      ['rol con ~', () => manager.revoke({ type: 'users', uuid: uuidv7() }, 'docs~read', APP_SCOPE)],
      ['permiso con |', () => manager.removeDeny({ type: 'users', uuid: uuidv7() }, 'docs|read', APP_SCOPE)],
      ['scopeType vacío', () => manager.listRoleScopes({ type: 'users', uuid: uuidv7() }, '')],
      ['RoleQuery objeto en grant', () => manager.grant({ type: 'users', uuid: uuidv7() }, { slug: 'editor', scopeType: 'app' } as any, APP_SCOPE)],
      ['RoleQuery objeto en revoke', () => manager.revoke({ type: 'users', uuid: uuidv7() }, { slug: 'editor', scopeType: 'app' } as any, APP_SCOPE)],
      ['RoleQuery objeto en listSubjects', () => manager.listSubjects({ slug: 'editor', scopeType: 'app' } as any, APP_SCOPE)],
      ['expiresAt string', () => manager.grant({ type: 'users', uuid: uuidv7() }, 'editor', APP_SCOPE, { expiresAt: '2026-12-31' as any })],
      ['expiresAt Invalid Date', () => manager.grant({ type: 'users', uuid: uuidv7() }, 'editor', APP_SCOPE, { expiresAt: new Date('x') })],
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
    // `resolveChain` solo sabe de la raíz. Con él, una organization no
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

  test('forRequest(): comparte el driver con el padre y, sin resolutor o con un driver de terceros, lee sin memo (2A · A3)', async ({
    assert,
  }) => {
    // Un driver de terceros que solo implementa el puerto 2.0 (sin
    // `withChainResolver`) sigue funcionando detrás de una vista: las
    // lecturas van al driver tal cual. Y la factory corre UNA vez: la vista
    // no crea otro driver.
    let factories = 0
    const seen: string[] = []
    const fakeDriver: any = {
      authorize: async () => {
        seen.push('authorize')
        return true
      },
      grant: async () => {
        seen.push('grant')
        return { existed: false, expiresAt: null }
      },
    }
    const holder = { type: 'users', uuid: uuidv7() }

    // Sin `scopes.resolveChain`: no hay nada que memoizar.
    const bare = new AuthorizationManager({
      default: 'fake',
      drivers: {
        fake: () => {
          factories += 1
          return fakeDriver
        },
      },
      warnOnOptInSecurity: false,
    } as any)
    const view = bare.forRequest()
    assert.isTrue(await view.authorize(holder, 'docs:read', APP_SCOPE))
    await view.grant(holder, 'editor', APP_SCOPE)
    assert.isTrue(await bare.authorize(holder, 'docs:read', APP_SCOPE))
    assert.strictEqual(await view.driver(), fakeDriver)
    assert.equal(factories, 1)
    assert.deepEqual(seen, ['authorize', 'grant', 'authorize'])

    // Con resolutor pero driver sin `withChainResolver`: lo mismo.
    const withTree = new AuthorizationManager({
      default: 'fake',
      drivers: { fake: () => fakeDriver },
      scopes: { resolveChain: async (scope: ScopeRef) => [scope, APP_SCOPE] },
      warnOnOptInSecurity: false,
    } as any)
    assert.isTrue(
      await withTree.forRequest().authorize(holder, 'docs:read', { type: 'organization', uuid: uuidv7() })
    )
    assert.deepEqual(seen, ['authorize', 'grant', 'authorize', 'authorize'])
  })

  test('forRequest(): la vista valida identidad y notifica onWrite igual que el manager', async ({
    assert,
  }) => {
    const events: AuthzWriteEvent[] = []
    const manager = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver() },
      hooks: { onWrite: async (event: AuthzWriteEvent) => void events.push(event) },
      warnOnOptInSecurity: false,
    } as any)
    const view = manager.forRequest()
    const holder = { type: 'users', uuid: uuidv7() }
    await view.grant(holder, 'editor', APP_SCOPE)
    assert.isTrue(await view.authorize(holder, 'docs:read', APP_SCOPE))
    await view.revoke(holder, 'editor', APP_SCOPE)
    assert.isFalse(await view.authorize(holder, 'docs:read', APP_SCOPE))
    assert.deepEqual(
      events.map((e) => e.action),
      ['granted', 'revoked']
    )
    let caught: any
    try {
      await view.authorize({ type: 'users', uuid: 'x#y' }, 'docs:read', APP_SCOPE)
      assert.fail('debería haber rechazado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 422)
    assert.equal(caught.code, 'E_AUTHZ_INVALID_IDENTITY')
  })

  test('un driver no registrado falla con la lista de los que sí', async ({ assert }) => {
    const manager = new AuthorizationManager({
      default: 'no-existe',
      drivers: { database: () => new DatabaseAuthorizationDriver() },
      warnOnOptInSecurity: false,
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
    // `scopeType` también se valida (E4): es identidad, en minúsculas.
    for (const [label, scopeType] of [
      ['scopeType vacío', ''],
      ['scopeType con |', 'org|x'],
      ['scopeType en mayúsculas', 'Organization'],
      ['scopeType de 21', 'a'.repeat(21)],
      ['scopeType no string', 42],
    ] as Array<[string, any]>) {
      try {
        await syncAuthzCatalog({ permissions: [], roles: [{ slug: 'x', scopeType, permissions: [] }] })
        assert.fail(`${label}: debería haber rechazado`)
      } catch (error: any) {
        assert.equal(error.status, 422, `${label}: ${error.message}`)
        assert.equal(error.code, 'E_AUTHZ_INVALID_IDENTITY', label)
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

  test('un rol o un permiso declarado en dos catálogos es 422 E_AUTHZ_CATALOG_CONFLICT, sin escribir', async ({
    assert,
  }) => {
    // D3 (auditor H5, CR2). La identidad de un rol es `(slug, scopeType)`:
    // si dos catálogos declaran `support@app` con permisos distintos, el sync
    // del segundo poda los vínculos del primero (el prune es por rol), y el
    // último en el orden gana en silencio. Un rol pertenece a exactamente un
    // catálogo; la contradicción se detecta ANTES de tocar la base, también
    // en el diff.
    const { default: db } = await import('@adonisjs/lucid/services/db')
    const platform = {
      permissions: [{ slug: 'audit:read' }],
      roles: [{ slug: 'support', scopeType: 'app', permissions: ['audit:read'] }],
    }
    const tenant = {
      permissions: [{ slug: 'tenant:read' }],
      roles: [{ slug: 'support', scopeType: 'app', permissions: ['tenant:read'] }],
    }
    const expected = { status: 422, code: 'E_AUTHZ_CATALOG_CONFLICT' }
    for (const [label, call] of [
      ['sync', () => syncCatalogs([async () => platform, async () => tenant])],
      ['diff', () => runCatalogDiff([async () => platform, async () => tenant])],
    ] as Array<[string, () => Promise<unknown>]>) {
      let caught: any
      try {
        await call()
        assert.fail(`${label}: debería haber rechazado`)
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, expected.status, `${label}: ${caught.message}`)
      assert.equal(caught.code, expected.code, label)
      assert.include(caught.message, 'support@app')
    }
    assert.lengthOf(await db.from('authz_roles').select('uuid'), 0)
    assert.lengthOf(await db.from('authz_permissions').select('uuid'), 0)

    // El mismo permiso en dos catálogos también es un conflicto.
    let caught: any
    try {
      await syncCatalogs([
        async () => ({ permissions: [{ slug: 'docs:read' }], roles: [] }),
        async () => ({ permissions: [{ slug: 'docs:read' }], roles: [] }),
      ])
      assert.fail('permiso repetido: debería haber rechazado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.code, 'E_AUTHZ_CATALOG_CONFLICT')
    assert.include(caught.message, 'docs:read')
    assert.lengthOf(await db.from('authz_permissions').select('uuid'), 0)

    // Dos catálogos disjuntos siguen coexistiendo.
    assert.equal(await syncCatalogs([async () => platform, async () => ({ ...tenant, roles: [] })]), 2)
  })

  test('la colisión tras codificar se comprueba también contra los permisos ya en la base', async ({
    assert,
  }) => {
    // D3 (auditor H5-A). `docs:write` sincronizado por un catálogo y
    // `docs_write` por otro se proyectan a la MISMA relación FGA; validar
    // solo dentro del spec dejaba pasar la colisión repartida.
    const { default: db } = await import('@adonisjs/lucid/services/db')
    await syncAuthzCatalog({ permissions: [{ slug: 'docs:write' }], roles: [] })
    let caught: any
    try {
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs_write' }],
        roles: [{ slug: 'writer', scopeType: 'app', permissions: ['docs_write'] }],
      })
      assert.fail('debería haber rechazado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 422)
    assert.equal(caught.code, 'E_AUTHZ_INVALID_SLUG')
    assert.include(caught.message, 'docs_write')
    assert.deepEqual(
      (await db.from('authz_permissions').select('slug')).map((p: any) => p.slug),
      ['docs:write']
    )
    assert.lengthOf(await db.from('authz_roles').select('uuid'), 0)
  })

  test('el catálogo con la base caída es 503 E_AUTHZ_BACKEND_UNAVAILABLE, no un error crudo (D15)', async ({
    assert,
  }) => {
    // Auditor H15/H16. `syncAuthzCatalog` corre en el arranque de un
    // despliegue: un `SqliteError` sin status ni code se leía como bug.
    const spec = { permissions: [{ slug: 'docs:read' }], roles: [] }
    for (const [label, call] of [
      ['sync', () => syncAuthzCatalog(spec)],
      ['diff', () => diffAuthzCatalog(spec)],
    ] as Array<[string, () => Promise<unknown>]>) {
      let caught: any
      await withTableMissing('authz_permissions', async () => {
        try {
          await call()
          assert.fail(`${label}: debería haber lanzado`)
        } catch (error) {
          caught = error
        }
      })
      assert.equal(caught.status, 503, `${label}: ${caught.message}`)
      assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', label)
      assert.exists(caught.cause, label)
    }
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

    // (Un mismo rol en dos catálogos ya no es un diff: es 422 E_AUTHZ_CATALOG_CONFLICT, D3.)
    const failing = await runCatalogDiff([async () => after])
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
      scopes: { resolveChain: resolveChainFrom(tree) },
      hooks: onWrite ? { onWrite: async (e: AuthzWriteEvent) => void onWrite(e) } : undefined,
      warnOnOptInSecurity: false,
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

  test('el anti-ciclo usa la identidad CANÓNICA del hijo: un alias del uuid (guiones quitados, como el tipo uuid de PG) no cuela una arista que cierra el ciclo (2.5-B · K1)', async ({
    assert,
  }) => {
    // K1d. `#assertEdge` canoniza al hijo ANTES de contrastar la cadena del
    // padre. Con `memoryScopeTree` (byte a byte) el alias es sencillamente
    // otro scope y el agujero no se puede mostrar; con un árbol que funde
    // las dos formas —el tipo `uuid` de PostgreSQL encuentra la fila de
    // `bbbb-…` con `bbbb…`— colgar `orgA` ESCRITO SIN GUIONES de su propio
    // descendiente `unitA1` cerraría app ← orgA ← unitA1 ← orgA, y el
    // anti-ciclo comparando el alias contra la cadena canónica no lo vería:
    // a partir de ahí un grant en orgA concede en la raíz. Solo lo observa
    // el `resolveChain` del hijo; sin él, únicamente cambia un conteo de
    // llamadas (`spies.spec`), que no es la promesa.
    const orgA = org()
    const unitA1 = unit()
    /** Clave del árbol de un consumidor cuya columna funde el alias con la fila. */
    const fused = (scope: ScopeRef) => `${scope.type}\u001f${(scope.uuid ?? '').replaceAll('-', '')}`
    const rows = new Map<string, { self: ScopeRef; parent: ScopeRef }>([
      [fused(orgA), { self: orgA, parent: APP_SCOPE }],
      [fused(unitA1), { self: unitA1, parent: orgA }],
    ])
    /** Devuelve la cadena CANÓNICA (la fila leída), como exige el puerto. */
    const resolveChain = async (scope: ScopeRef): Promise<ScopeRef[] | null> => {
      const chain: ScopeRef[] = []
      let current: ScopeRef = scope
      for (let depth = 0; depth < 10; depth++) {
        if (current.type === 'app') return [...chain, APP_SCOPE]
        const row = rows.get(fused(current))
        if (!row) return null
        chain.push(row.self)
        current = row.parent
      }
      return null
    }
    const aliasOrgA: ScopeRef = { type: 'organization', uuid: orgA.uuid!.replaceAll('-', '') }
    const aliasUnitA1: ScopeRef = { type: 'unit', uuid: unitA1.uuid!.replaceAll('-', '') }
    // Precondición: el árbol de este consumidor funde alias y fila, y responde canónico.
    assert.notEqual(aliasOrgA.uuid, orgA.uuid)
    assert.deepEqual(await resolveChain(aliasOrgA), [orgA, APP_SCOPE], 'el alias resuelve a la fila canónica')

    const { driver, calls } = fakeDriver()
    const manager = new AuthorizationManager({
      default: 'fake',
      drivers: { fake: () => driver },
      scopes: { resolveChain },
      warnOnOptInSecurity: false,
    } as any)
    const cycle = { status: 422, code: 'E_AUTHZ_SCOPE_CYCLE' }

    await rejects(assert, () => manager.scopes.attached(aliasOrgA, unitA1), cycle, 'attached: el alias del hijo desciende del padre')
    await rejects(assert, () => manager.scopes.moved(aliasOrgA, unitA1), cycle, 'moved: el alias del hijo desciende del padre')
    await rejects(assert, () => manager.scopes.attached(aliasOrgA, aliasOrgA), cycle, 'attached: el alias de sí mismo')
    assert.deepEqual(calls, [], 'ninguna arista que cierra un ciclo llega al driver')

    // Y el inverso: una arista LEGÍTIMA escrita con el alias sigue pasando —
    // el anti-ciclo canoniza, no rechaza todo lo que no sea la forma exacta.
    await manager.scopes.attached(aliasUnitA1, orgA)
    assert.deepEqual(calls, ['onScopeAttached'])
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

  test('sin config.scopes.resolveChain, usar scopes.* es 500 E_AUTHZ_CONFIG', async ({ assert }) => {
    const { driver, calls } = fakeDriver()
    const manager = new AuthorizationManager({ default: 'fake', drivers: { fake: () => driver }, warnOnOptInSecurity: false } as any)
    const orgA = org()
    const expected = { status: 500, code: 'E_AUTHZ_CONFIG' }
    await rejects(assert, () => manager.scopes.attached(orgA, APP_SCOPE), expected, 'attached')
    await rejects(assert, () => manager.scopes.moved(orgA, APP_SCOPE), expected, 'moved')
    await rejects(assert, () => manager.scopes.detached(orgA), expected, 'detached')
    assert.deepEqual(calls, [])
  })

  test('H1: moved/attached contrastan within también con la cadena ACTUAL del hijo: una unit de B no se lleva a A con within: orgA (422 E_AUTHZ_NOT_WITHIN, sin llamar al driver)', async ({
    assert,
  }) => {
    // 2E · H1 (auditor 1). Solo se miraba el DESTINO: el admin de A podía
    // anexionarse la unit de B declarando `within: orgA`, y tras el
    // movimiento heredaba todo el subárbol robado. Ahora el origen (la cadena
    // actual del hijo, en fresco) también tiene que estar dentro; por eso el
    // consumidor notifica ANTES de recolgar su fila.
    const tree = memoryScopeTree()
    const orgA = org()
    const orgB = org()
    const unitA1 = unit()
    const unitA2 = unit()
    const unitB1 = unit()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(unitA1, orgA)
    await tree.attach(unitA2, orgA)
    await tree.attach(unitB1, orgB)
    const { driver, calls } = fakeDriver()
    const manager = managerOver(tree, driver)
    const expected = { status: 422, code: 'E_AUTHZ_NOT_WITHIN' }

    // Destino dentro, ORIGEN fuera: rechazado en los dos verbos.
    await rejects(assert, () => manager.scopes.moved(unitB1, orgA, { within: orgA }), expected, 'moved: origen fuera')
    await rejects(assert, () => manager.scopes.attached(unitB1, orgA, { within: orgA }), expected, 'attached de un hijo existente = move: origen fuera')
    await rejects(assert, () => manager.scopes.attached(unitB1, unitA1, { within: orgA }), expected, 'attached bajo una unit de A')
    // Origen dentro, destino fuera: sigue rechazado (F2).
    await rejects(assert, () => manager.scopes.moved(unitA1, orgB, { within: orgA }), expected, 'moved: destino fuera')
    // Un hijo que el árbol no conoce no tiene origen que contrastar: 422 UNKNOWN_SCOPE en `moved`…
    await rejects(assert, () => manager.scopes.moved(unit(), orgA, { within: orgA }), { status: 422, code: 'E_AUTHZ_UNKNOWN_SCOPE' }, 'moved de un hijo desconocido')
    assert.deepEqual(calls, [])

    // …y en `attached` es un nodo NUEVO: solo cuenta el padre.
    await manager.scopes.attached(unit(), orgA, { within: orgA })
    // Origen y destino dentro del mismo tenant: se mueve.
    await manager.scopes.moved(unitA1, unitA2, { within: orgA })
    // La raíz contiene ambos: la plataforma sí puede cruzar tenants.
    await manager.scopes.moved(unitB1, orgA, { within: APP_SCOPE })
    // Sin `within` (config laxa) no se consulta el origen.
    await manager.scopes.moved(unitB1, orgA)
    assert.deepEqual(calls, ['onScopeAttached', 'onScopeMoved', 'onScopeMoved', 'onScopeMoved'])
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
    const real = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })
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

/**
 * Lote 2B. Las primitivas que el manager COMPONE sobre el puerto: `actor`,
 * `within`, `authorizeMany`, `effectivePermissions`, `authorizedScopes`. La
 * semántica en ambos drivers la juzga el contrato (`since('2.1')`); aquí se
 * fija el borde con el consumidor (config, eventos, errores, driver falso).
 */
test.group('manager — lote 2B (2.1)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [
        { slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'docs:write'] },
        { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] },
      ],
    })
  })

  const org = (): ScopeRef => ({ type: 'organization', uuid: uuidv7() })
  const user = () => ({ type: 'users', uuid: uuidv7() })

  /** Driver falso que anota qué se le llama. */
  function fakeDriver(extra: Record<string, any> = {}) {
    const calls: string[] = []
    const driver: any = {}
    for (const method of ['authorize', 'grant', 'revoke', 'hasRole', 'deny', 'removeDeny', 'listSubjects', 'listRoles', 'listRoleScopes', 'listScopes', 'purgeScope']) {
      driver[method] = async () => {
        calls.push(method)
        return method === 'grant' ? { existed: false, expiresAt: null } : method.startsWith('list') ? [] : undefined
      }
    }
    Object.assign(driver, extra)
    return { driver, calls }
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

  /** Captura `console.warn` durante `fn`. */
  function captureWarn(fn: () => void): string[] {
    const lines: string[] = []
    const original = console.warn
    console.warn = (...args: unknown[]) => void lines.push(args.map(String).join(' '))
    try {
      fn()
    } finally {
      console.warn = original
    }
    return lines
  }

  test('B7: el evento onWrite lleva actor en todas las escrituras, validado como identidad', async ({ assert }) => {
    const tree = memoryScopeTree()
    const orgA = org()
    await tree.attach(orgA, APP_SCOPE)
    const events: AuthzWriteEvent[] = []
    const manager = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) }) },
      scopes: { resolveChain: resolveChainFrom(tree) },
      hooks: { onWrite: async (e: AuthzWriteEvent) => void events.push(e) },
      warnOnOptInSecurity: false,
    })
    const alice = user()
    const admin = { type: 'admins', uuid: uuidv7() }

    await manager.grant(alice, 'org-editor', orgA, { actor: admin })
    await manager.deny(alice, 'docs:read', orgA, { actor: admin })
    await manager.removeDeny(alice, 'docs:read', orgA, { actor: admin })
    await manager.revoke(alice, 'org-editor', orgA, { actor: admin })
    await manager.scopes.detached(orgA, { actor: admin })
    // Sin actor, el evento no lo lleva (no se inventa).
    await manager.grant(alice, 'editor', APP_SCOPE)

    assert.deepEqual(
      events.map((e) => [e.action, e.actor?.uuid]),
      [
        ['granted', admin.uuid],
        ['denied', admin.uuid],
        ['deny_removed', admin.uuid],
        ['revoked', admin.uuid],
        ['scope_purged', admin.uuid],
        ['granted', undefined],
      ]
    )
  })

  test('B7: requireActor: una escritura sin actor es 422 E_AUTHZ_ACTOR_REQUIRED sin llamar al driver ni al hook', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = org()
    await tree.attach(orgA, APP_SCOPE)
    const { driver, calls } = fakeDriver()
    const events: AuthzWriteEvent[] = []
    const manager = new AuthorizationManager({
      default: 'fake',
      drivers: { fake: () => driver },
      scopes: { resolveChain: resolveChainFrom(tree) },
      hooks: { onWrite: async (e: AuthzWriteEvent) => void events.push(e) },
      requireActor: true,
      warnOnOptInSecurity: false,
    })
    const alice = user()
    const expected = { status: 422, code: 'E_AUTHZ_ACTOR_REQUIRED' }
    await rejects(assert, () => manager.grant(alice, 'editor', APP_SCOPE), expected, 'grant')
    await rejects(assert, () => manager.revoke(alice, 'editor', APP_SCOPE), expected, 'revoke')
    await rejects(assert, () => manager.deny(alice, 'docs:read', APP_SCOPE), expected, 'deny')
    await rejects(assert, () => manager.removeDeny(alice, 'docs:read', APP_SCOPE), expected, 'removeDeny')
    await rejects(assert, () => manager.scopes.attached(org(), orgA), expected, 'scopes.attached')
    await rejects(assert, () => manager.scopes.moved(orgA, APP_SCOPE), expected, 'scopes.moved')
    await rejects(assert, () => manager.scopes.detached(orgA), expected, 'scopes.detached')
    // Un actor mal formado tampoco vale: 422 de identidad, antes del driver.
    const bad = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
    await rejects(assert, () => manager.grant(alice, 'editor', APP_SCOPE, { actor: { type: 'admins', uuid: 'x#y' } }), bad, 'actor inválido')
    await rejects(assert, () => manager.deny(alice, 'docs:read', APP_SCOPE, { actor: { type: 'Admins', uuid: uuidv7() } as any }), bad, 'actor con tipo en mayúsculas')
    assert.deepEqual(calls, [])
    assert.deepEqual(events, [])

    // Con actor, todo pasa y el evento lo lleva; las lecturas no exigen actor.
    const admin = { type: 'admins', uuid: uuidv7() }
    await manager.grant(alice, 'editor', APP_SCOPE, { actor: admin })
    await manager.scopes.attached(org(), orgA, { actor: admin })
    assert.deepEqual(calls, ['grant'])
    assert.deepEqual(events.map((e) => [e.action, e.actor?.uuid]), [['granted', admin.uuid]])
    await manager.authorize(alice, 'docs:read', APP_SCOPE)
    assert.deepEqual(calls, ['grant', 'authorize'])
  })

  test('B7/B1: requireWithin y requireActor son opt-in: sin declararlos el manager avisa UNA vez por config; con warnOnOptInSecurity: false, calla', ({
    assert,
  }) => {
    const { driver } = fakeDriver()
    const config = { default: 'fake', drivers: { fake: () => driver } }
    const warned = captureWarn(() => {
      const manager = new AuthorizationManager(config)
      manager.forRequest()
      new AuthorizationManager(config)
    })
    assert.lengthOf(warned, 1)
    assert.include(warned[0], 'requireWithin')
    assert.include(warned[0], 'requireActor')

    assert.lengthOf(captureWarn(() => new AuthorizationManager({ ...config, warnOnOptInSecurity: false })), 0)
    assert.lengthOf(captureWarn(() => new AuthorizationManager({ ...config, requireWithin: true, requireActor: true })), 0)
    // Con uno solo declarado, el aviso nombra el que falta.
    const partial = captureWarn(() => new AuthorizationManager({ ...config, requireWithin: true }))
    assert.lengthOf(partial, 1)
    assert.include(partial[0], 'requireActor')
    assert.notInclude(partial[0], 'requireWithin')
  })

  test('B5: un driver de terceros sin listDenies ⇒ listDenies y effectivePermissions lanzan 500 E_AUTHZ_UNSUPPORTED nombrando el método (no un [] silencioso)', async ({
    assert,
  }) => {
    // Regla 4 del lote: el puerto 2.0 sigue bastando para todo lo de 2.0; lo
    // que una primitiva de 2.1 necesite y el driver no tenga se dice, no se
    // simula. Un `[]` aquí sería "sin denies" = fail-open en `effectivePermissions`.
    const tree = memoryScopeTree()
    const orgA = org()
    await tree.attach(orgA, APP_SCOPE)
    const { driver, calls } = fakeDriver({ listRoles: async () => ['editor'] })
    const manager = new AuthorizationManager({
      default: 'fake',
      drivers: { fake: () => driver },
      scopes: { resolveChain: resolveChainFrom(tree) },
      warnOnOptInSecurity: false,
    })
    const alice = user()
    const expected = { status: 500, code: 'E_AUTHZ_UNSUPPORTED' }
    for (const [label, call] of [
      ['listDenies', () => manager.listDenies(alice, orgA)],
      ['effectivePermissions', () => manager.effectivePermissions(alice, orgA)],
    ] as Array<[string, () => Promise<unknown>]>) {
      try {
        await call()
        assert.fail(`${label}: debería haber rechazado`)
      } catch (error: any) {
        assert.equal(error.status, expected.status, `${label}: ${error.message}`)
        assert.equal(error.code, expected.code, label)
        assert.include(error.message, 'listDenies', label)
      }
    }
    assert.notInclude(calls, 'listDenies')
    // Las lecturas del puerto 2.0 siguen funcionando con ese driver.
    assert.deepEqual(await manager.listRoles(alice, orgA), ['editor'])
  })

  test('B6: sin authorizeMany en el driver, el manager compone N authorize por posición; vacío ⇒ [] con 0 llamadas; un authorize que rechaza lo rechaza entero', async ({
    assert,
  }) => {
    const seen: string[] = []
    const { driver, calls } = fakeDriver({
      authorize: async (_s: any, _p: string, scope: ScopeRef) => {
        seen.push(scope.uuid ?? 'app')
        if (scope.uuid === 'boom') throw new AuthorizationBackendError('fake', 'authorize', new Error('x'))
        return scope.type === 'organization'
      },
    })
    const manager = new AuthorizationManager({ default: 'fake', drivers: { fake: () => driver }, warnOnOptInSecurity: false })
    const alice = user()
    const orgA = org()
    const orgB = org()
    const unitX = { type: 'unit', uuid: uuidv7() }
    assert.deepEqual(await manager.authorizeMany(alice, 'docs:read', [orgA, unitX, APP_SCOPE, orgA, orgB]), [true, false, false, true, true])
    assert.deepEqual(seen, [orgA.uuid, unitX.uuid, 'app', orgA.uuid, orgB.uuid])
    seen.length = 0
    assert.deepEqual(await manager.authorizeMany(alice, 'docs:read', []), [])
    assert.deepEqual(seen, [])
    await rejects(assert, () => manager.authorizeMany(alice, 'docs:read', [orgA, { type: 'unit', uuid: 'boom' }, orgB]), { status: 503, code: 'E_AUTHZ_BACKEND_UNAVAILABLE' }, 'una posición que falla')
    assert.notInclude(calls, 'authorizeMany')

    // Con `authorizeMany` en el driver, el manager delega (una llamada) y respeta el orden.
    const batched = fakeDriver({
      authorizeMany: async (_s: any, _p: string, scopes: ScopeRef[]) => scopes.map((s) => s.type === 'unit'),
    })
    const delegating = new AuthorizationManager({ default: 'fake', drivers: { fake: () => batched.driver }, warnOnOptInSecurity: false })
    assert.deepEqual(await delegating.authorizeMany(alice, 'docs:read', [orgA, unitX, unitX]), [false, true, true])
    assert.notInclude(batched.calls, 'authorize')
  })

  test('B3: authorizedScopes clasifica las respuestas de descendantsOf: más de maxDescendants ⇒ 422 TOO_MANY; lanza o responde mal ⇒ 503; sin listDenies ⇒ 500 UNSUPPORTED', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = org()
    await tree.attach(orgA, APP_SCOPE)
    const alice = user()
    const real = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })
    await real.grant(alice, 'org-editor', orgA)
    const over = (descendantsOf: any, extra: Record<string, unknown> = {}) =>
      new AuthorizationManager({
        default: 'database',
        drivers: { database: () => real },
        scopes: { resolveChain: resolveChainFrom(tree), descendantsOf, ...extra },
        warnOnOptInSecurity: false,
      })

    // Ignora maxNodes y devuelve de más: el manager lanza (nunca lista parcial).
    const tooMany = over(async () => Array.from({ length: 5 }, () => ({ type: 'unit', uuid: uuidv7() })), { maxDescendants: 4 })
    await rejects(assert, () => tooMany.authorizedScopes(alice, 'docs:read', 'unit'), { status: 422, code: 'E_AUTHZ_TOO_MANY_SCOPES' }, 'de más')
    // El maxNodes que recibe el resolutor es maxDescendants. Las units tienen
    // que colgar de orgA también para `resolveChain` (2D · F3): un
    // descendiente que el árbol de ancestros no cuelga de ahí es 503.
    const units: ScopeRef[] = []
    for (let i = 0; i < 4; i++) {
      const unit = { type: 'unit', uuid: uuidv7() }
      await tree.attach(unit, orgA)
      units.push(unit)
    }
    let received: number | undefined
    const exact = over(async (_s: any, o: any) => {
      received = o.maxNodes
      return units
    }, { maxDescendants: 4 })
    assert.equal((await exact.authorizedScopes(alice, 'docs:read', 'unit')).kind, 'some')
    assert.equal(received, 4)

    const boom = over(async () => {
      throw new Error('árbol caído')
    })
    await rejects(assert, () => boom.authorizedScopes(alice, 'docs:read', 'unit'), { status: 503, code: 'E_AUTHZ_RESOLVER_FAILED' }, 'lanza')
    for (const bad of ['no-es-un-array', [{ type: 'app', uuid: 'X' }], [{ type: 'Unit', uuid: uuidv7() }]]) {
      await rejects(assert, () => over(async () => bad).authorizedScopes(alice, 'docs:read', 'unit'), { status: 503, code: 'E_AUTHZ_RESOLVER_FAILED' }, JSON.stringify(bad))
    }
    // `null` de descendantsOf = scope desconocido para el árbol de descendientes: nada debajo.
    assert.deepEqual(await over(async () => null).authorizedScopes(alice, 'docs:read', 'organization'), { kind: 'some', scopes: [orgA] })
    // maxScopes inválido es config rota (500), no una cota.
    await rejects(assert, () => over(async () => []).authorizedScopes(alice, 'docs:read', 'unit', { maxScopes: 0 }), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'maxScopes 0')

    const { driver } = fakeDriver({ listScopes: async () => [orgA] })
    const noDenies = new AuthorizationManager({
      default: 'fake',
      drivers: { fake: () => driver },
      scopes: { resolveChain: resolveChainFrom(tree), descendantsOf: async () => [] },
      warnOnOptInSecurity: false,
    })
    await rejects(assert, () => noDenies.authorizedScopes(alice, 'docs:read', 'organization'), { status: 500, code: 'E_AUTHZ_UNSUPPORTED' }, 'sin listDenies')
  })

  test('F8: authorizedScopes corta en cuanto el conteo del tipo supera maxScopes (no pasea el resto del árbol) y la cota por llamada no puede superar la del config', async ({
    assert,
  }) => {
    // Antes se recorrían TODOS los subárboles y se acotaba al final: con
    // 100 orgs de 10 000 units cada una, 1 M de nodos para lanzar un 422.
    const tree = memoryScopeTree()
    const orgs: ScopeRef[] = []
    const alice = user()
    const real = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })
    for (let i = 0; i < 5; i++) {
      const o = org()
      await tree.attach(o, APP_SCOPE)
      for (let j = 0; j < 3; j++) await tree.attach({ type: 'unit', uuid: uuidv7() }, o)
      orgs.push(o)
      await real.grant(alice, 'org-editor', o)
    }
    let calls = 0
    const full = descendantsFrom(tree)
    const manager = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => real },
      scopes: {
        resolveChain: resolveChainFrom(tree),
        descendantsOf: (s, o) => {
          calls += 1
          return full(s, o)
        },
        maxScopes: 4,
      },
      warnOnOptInSecurity: false,
    })
    // 5 orgs directas > 4: 422 antes de bajar a ningún subárbol.
    await rejects(assert, () => manager.authorizedScopes(alice, 'docs:read', 'organization'), { status: 422, code: 'E_AUTHZ_TOO_MANY_SCOPES' }, 'directas')
    assert.equal(calls, 0)
    // Units: 15 en total > 4 ⇒ 422 tras bajar como mucho a 2 orgs (3 + 3 > 4), no a las 5.
    calls = 0
    await rejects(assert, () => manager.authorizedScopes(alice, 'docs:read', 'unit'), { status: 422, code: 'E_AUTHZ_TOO_MANY_SCOPES' }, 'units')
    assert.isAtMost(calls, 2)
    // La cota por llamada solo baja: pedir 100 con config 4 sigue siendo 4.
    await rejects(assert, () => manager.authorizedScopes(alice, 'docs:read', 'organization', { maxScopes: 100 }), { status: 422, code: 'E_AUTHZ_TOO_MANY_SCOPES' }, 'por llamada')
    // Y por debajo de la cota, responde entero.
    const three = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => real },
      scopes: { resolveChain: resolveChainFrom(tree), descendantsOf: full, maxScopes: 3 },
      warnOnOptInSecurity: false,
    })
    const bob = user()
    await real.grant(bob, 'org-editor', orgs[0])
    assert.lengthOf(((await three.authorizedScopes(bob, 'docs:read', 'unit')) as any).scopes, 3)
    await rejects(assert, () => three.authorizedScopes(bob, 'docs:read', 'unit', { maxScopes: 2 }), { status: 422, code: 'E_AUTHZ_TOO_MANY_SCOPES' }, 'por llamada más baja')
  })

  test('F10: expandExcludedSubtrees devuelve cada scope excluido y su subárbol; un subárbol que descendantsOf no conoce es 503 (no se resta a medias); más de maxScopes ⇒ 422', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const orgA = org()
    const unitA1 = { type: 'unit', uuid: uuidv7() }
    const unitA2 = { type: 'unit', uuid: uuidv7() }
    const teamA1a = { type: 'team', uuid: uuidv7() }
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(unitA1, orgA)
    await tree.attach(unitA2, orgA)
    await tree.attach(teamA1a, unitA1)
    const full = descendantsFrom(tree)
    const over = (descendantsOf: any, extra: Record<string, unknown> = {}) =>
      new AuthorizationManager({
        default: 'database',
        drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) }) },
        scopes: { resolveChain: resolveChainFrom(tree), descendantsOf, ...extra },
        warnOnOptInSecurity: false,
      })
    const keys = (scopes: ScopeRef[]) => scopes.map((s) => `${s.type}:${s.uuid}`).sort()
    const excluded = [{ scope: unitA1, includesDescendants: true as const }]
    assert.deepEqual(keys(await over(full).expandExcludedSubtrees(excluded)), keys([unitA1, teamA1a]))
    assert.deepEqual(await over(full).expandExcludedSubtrees([]), [])
    // Duplicados y anidados: una vez cada scope.
    assert.deepEqual(
      keys(await over(full).expandExcludedSubtrees([...excluded, { scope: orgA, includesDescendants: true }])),
      keys([orgA, unitA1, unitA2, teamA1a])
    )
    await rejects(assert, () => over(async () => null).expandExcludedSubtrees(excluded), { status: 503, code: 'E_AUTHZ_RESOLVER_FAILED' }, 'null')
    // Y un descendiente MAL FORMADO devuelto por descendantsOf tampoco se
    // cuela en la exclusión: aquí no hay contraste con `resolveChain`
    // que lo tape (a diferencia de `authorizedScopes`), así que sin la
    // gramática el consumidor recibiría un ScopeRef que el motor rechazaría.
    for (const bad of [[{ type: 'Unit', uuid: uuidv7() }], [{ type: 'app', uuid: 'X' }], [{ type: 'unit', uuid: null }]]) {
      await rejects(
        assert,
        () => over(async () => bad).expandExcludedSubtrees(excluded),
        { status: 503, code: 'E_AUTHZ_RESOLVER_FAILED' },
        `descendiente mal formado ${JSON.stringify(bad)}`
      )
    }
    await rejects(assert, () => over(full, { maxScopes: 1 }).expandExcludedSubtrees(excluded), { status: 422, code: 'E_AUTHZ_TOO_MANY_SCOPES' }, 'cota')
    await rejects(assert, () => over(full).expandExcludedSubtrees(excluded, { maxScopes: 1 }), { status: 422, code: 'E_AUTHZ_TOO_MANY_SCOPES' }, 'cota por llamada')
    await rejects(assert, () => over(full).expandExcludedSubtrees([{ scope: { type: 'app', uuid: 'X' } } as any]), { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }, 'scope inválido')
    // Sin descendantsOf no se puede expandir: 500, nunca la lista corta.
    const none = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver() },
      scopes: { resolveChain: resolveChainFrom(tree) },
      warnOnOptInSecurity: false,
    })
    await rejects(assert, () => none.expandExcludedSubtrees(excluded), { status: 500, code: 'E_AUTHZ_NO_DESCENDANTS_RESOLVER' }, 'sin descendantsOf')
  })

  test('F5: authorizeMany valida la respuesta de un driver de terceros: longitud distinta o elemento no booleano ⇒ 500 E_AUTHZ_INTERNAL nombrando el driver', async ({
    assert,
  }) => {
    // Un `boolean[]` desalineado se leería por posición: un `true` de menos
    // o un `undefined` (falsy) parecerían respuestas. Es un bug del driver,
    // no una decisión.
    const alice = user()
    const orgA = org()
    const orgB = org()
    const bad = (answer: unknown) => {
      const { driver } = fakeDriver({ authorizeMany: async () => answer })
      return new AuthorizationManager({ default: 'terceros', drivers: { terceros: () => driver }, warnOnOptInSecurity: false })
    }
    for (const answer of [[true], [true, false, true], [true, 'yes'], [true, undefined], 'true,false', null, { 0: true, 1: false, length: 2 }]) {
      try {
        await bad(answer).authorizeMany(alice, 'docs:read', [orgA, orgB])
        assert.fail(`${JSON.stringify(answer)}: debería haber rechazado`)
      } catch (error: any) {
        assert.equal(error.status, 500, JSON.stringify(answer))
        assert.equal(error.code, 'E_AUTHZ_INTERNAL', JSON.stringify(answer))
        assert.include(error.message, 'terceros', JSON.stringify(answer))
      }
    }
    assert.deepEqual(await bad([true, false]).authorizeMany(alice, 'docs:read', [orgA, orgB]), [true, false])
  })

  test('F9: una vista de forRequest() caduca: leer tras maxAgeMs (default 30 s) es 500 E_AUTHZ_VIEW_EXPIRED; maxAgeMs: 0 la deja sin límite; las escrituras siguen (resuelven en fresco)', async ({
    assert,
  }) => {
    // Auditor 5: una vista guardada por error fuera del request servía la
    // cadena vieja para siempre (cruce de tenant tras un `moved`). Ahora es
    // ruidosa: un 500 en la primera lectura tardía, no un `true` viejo.
    const tree = memoryScopeTree()
    const orgA = org()
    const orgB = org()
    const unit: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(unit, orgA)
    const resolver = resolveChainFrom(tree)
    const manager = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain: resolver }) },
      scopes: { resolveChain: resolver, descendantsOf: descendantsFrom(tree) },
      warnOnOptInSecurity: false,
    })
    const alice = user()
    await manager.grant(alice, 'org-editor', orgA)

    const view = manager.forRequest({ maxAgeMs: 1 })
    assert.isTrue(await view.authorize(alice, 'docs:read', unit))
    await tree.move(unit, orgB)
    await new Promise((resolve) => setTimeout(resolve, 5))
    const expired = { status: 500, code: 'E_AUTHZ_VIEW_EXPIRED' }
    await rejects(assert, () => view.authorize(alice, 'docs:read', unit), expired, 'authorize')
    await rejects(assert, () => view.hasRole(alice, 'org-editor', unit), expired, 'hasRole')
    await rejects(assert, () => view.listRoles(alice, unit), expired, 'listRoles')
    await rejects(assert, () => view.listRoleScopes(alice, 'unit'), expired, 'listRoleScopes')
    await rejects(assert, () => view.listScopes(alice, 'docs:read'), expired, 'listScopes')
    await rejects(assert, () => view.listSubjects('org-editor', orgA), expired, 'listSubjects')
    await rejects(assert, () => view.listDenies(alice), expired, 'listDenies')
    await rejects(assert, () => view.authorizeMany(alice, 'docs:read', [unit]), expired, 'authorizeMany')
    await rejects(assert, () => view.effectivePermissions(alice, unit), expired, 'effectivePermissions')
    await rejects(assert, () => view.authorizedScopes(alice, 'docs:read', 'unit'), expired, 'authorizedScopes')
    // I2 (auditor 10): `expandExcludedSubtrees` es una lectura más de la vista y caduca con ella.
    await rejects(assert, () => view.expandExcludedSubtrees([{ scope: orgA, includesDescendants: true }]), expired, 'expandExcludedSubtrees')
    // Las escrituras y `isWithin` resuelven en fresco: no dependen de la vista.
    assert.isTrue(await view.isWithin(unit, orgB))
    await view.grant(alice, 'org-editor', orgB, { within: orgB })
    // Una vista nueva responde con el árbol de ahora.
    assert.isTrue(await manager.forRequest().authorize(alice, 'docs:read', unit))
    assert.isFalse(await manager.forRequest().hasRole(alice, { slug: 'org-editor', scopeType: 'organization' }, orgA) === false)

    // Default 30 s, con el reloj MONÓTONO inyectado (`now`, solo tests);
    // `maxAgeMs: 0` = sin límite, explícito.
    let tick = 1_000_000
    const now = () => tick
    const thirty = manager.forRequest({ now })
    const endless = manager.forRequest({ maxAgeMs: 0, now })
    assert.isTrue(await thirty.authorize(alice, 'docs:read', unit))
    tick = 1_000_000 + 29_999
    assert.isTrue(await thirty.authorize(alice, 'docs:read', unit))
    tick = 1_000_000 + 30_000
    await rejects(assert, () => thirty.authorize(alice, 'docs:read', unit), expired, 'default 30 s')
    tick = 1_000_000 + 86_400_000
    assert.isTrue(await endless.authorize(alice, 'docs:read', unit))

    // H3 (auditor 3): la vida se mide con `performance.now()`, no con
    // `Date.now()`. Un reloj de pared que retrocede una hora (NTP, snapshot)
    // ni resucita una vista caducada ni alarga una viva.
    const wall = Date.now
    try {
      const short = manager.forRequest({ maxAgeMs: 10 })
      assert.isTrue(await short.authorize(alice, 'docs:read', unit))
      await new Promise((resolve) => setTimeout(resolve, 15))
      Date.now = () => wall() - 3_600_000
      await rejects(assert, () => short.authorize(alice, 'docs:read', unit), expired, 'reloj de pared hacia atrás: sigue caducada')
      // Y con `Date.now` ya atrasado al crearla tampoco vive de más.
      const born = manager.forRequest({ maxAgeMs: 10 })
      assert.isTrue(await born.authorize(alice, 'docs:read', unit))
      await new Promise((resolve) => setTimeout(resolve, 15))
      await rejects(assert, () => born.authorize(alice, 'docs:read', unit), expired, 'reloj de pared atrasado: caduca igual')
    } finally {
      Date.now = wall
    }
    // La vista de 30 s (reloj inyectado) sigue caducada: `Date.now` nunca intervino.
    await rejects(assert, () => thirty.authorize(alice, 'docs:read', unit), expired, 'la vista de 30 s sigue caducada')
    // Opciones inválidas: config rota (500), no una vista eterna por accidente.
    for (const bad of [-1, Number.NaN, 'x', 1.5]) {
      assert.throws(() => manager.forRequest({ maxAgeMs: bad as any }), /maxAgeMs/)
    }
    assert.throws(() => manager.forRequest({ now: 'reloj' as any }), /now/)
  })

  /**
   * Espía que SOBREVIVE a `withChainResolver`: el driver devuelve una
   * vista (`Object.create(this)`) derivada del target real, no del Proxy, asi
   * que un espía que no se re-envuelva deja de ver todo lo que pasa por
   * `forRequest()` — que es justo el camino de `authorizeMany`. Sin esto, un
   * "cero llamadas al driver" es vacuo.
   */
  function spyDriver(target: any, touched: string[]): any {
    return new Proxy(target, {
      get: (t, prop, receiver) => {
        const value = Reflect.get(t, prop, receiver)
        if (typeof value !== 'function' || typeof prop !== 'string') return value
        return (...args: any[]) => {
          touched.push(prop)
          const result = (value as any).apply(t, args)
          return prop === 'withChainResolver' ? spyDriver(result, touched) : result
        }
      },
    })
  }

  test('B6: authorizeMany valida TODAS las posiciones antes de tocar el driver, y el vacío no lo resuelve siquiera', async ({
    assert,
  }) => {
    // El mutante «quitar `assertIdentity` por scope del manager» sobrevivía:
    // el 422 llegaba igual (defensa en profundidad del driver) pero DESPUÉS
    // de haber preguntado por la posición 0. Lo que se fija aquí es el orden.
    const tree = memoryScopeTree()
    const orgA = org()
    await tree.attach(orgA, APP_SCOPE)
    const resolver = resolveChainFrom(tree)
    const touched: string[] = []
    const manager = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => spyDriver(new DatabaseAuthorizationDriver({ resolveChain: resolver }), touched) },
      scopes: { resolveChain: resolver },
      warnOnOptInSecurity: false,
    })
    const alice = user()

    await rejects(
      assert,
      () => manager.authorizeMany(alice, 'docs:read', [orgA, { type: 'app', uuid: 'X' } as ScopeRef]),
      { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' },
      'identidad inválida en la posición 1'
    )
    assert.deepEqual(touched, [], 'ni un authorize de la posición 0 antes del 422')

    // Lista vacía: `[]` sin resolver el driver siquiera.
    assert.deepEqual(await manager.authorizeMany(alice, 'docs:read', []), [])
    assert.deepEqual(touched, [], 'el vacío no toca el driver')

    // Y con todo válido sí se pregunta (el caso no pasa por estar muerto).
    assert.deepEqual(await manager.authorizeMany(alice, 'docs:read', [orgA]), [false])
    assert.include(touched, 'authorize')
  })

  test('B1/A3: la contención de una escritura resuelve el árbol en FRESCO, aunque la vista ya tenga memoizada la cadena vieja', async ({
    assert,
  }) => {
    // README, "Primitives": «checked against your tree *fresh* — the
    // per-request memo is never used to decide a write». Sin este caso, un
    // `#freshResolver()` que devolviera el memo de la vista pasaba la suite
    // entera: `grant`/`deny` sin `within` no consultan el árbol desde el
    // manager, y `isWithin` no se ejercitaba nunca dentro de una vista.
    const tree = memoryScopeTree()
    const orgA = org()
    const orgB = org()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    const sub: ScopeRef = { type: 'organization', uuid: uuidv7() }
    await tree.attach(sub, orgA)
    const resolver = resolveChainFrom(tree)
    const manager = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain: resolver }) },
      scopes: { resolveChain: resolver },
      warnOnOptInSecurity: false,
    })
    const alice = user()
    const view = manager.forRequest()

    // La vista memoiza la cadena de `sub`: [sub, orgA, app].
    assert.isFalse(await view.authorize(alice, 'docs:read', sub))
    assert.isTrue(await view.isWithin(sub, orgA))

    // El consumidor mueve `sub` de orgA a orgB en mitad de la request.
    await tree.move(sub, orgB)

    assert.isFalse(await view.isWithin(sub, orgA), 'isWithin no responde desde el memo')
    assert.isTrue(await view.isWithin(sub, orgB))
    await rejects(
      assert,
      () => view.grant(alice, 'org-editor', sub, { within: orgA }),
      { status: 422, code: 'E_AUTHZ_NOT_WITHIN' },
      'grant within orgA tras el movimiento'
    )
    await rejects(
      assert,
      () => view.deny(alice, 'docs:read', sub, { within: orgA }),
      { status: 422, code: 'E_AUTHZ_NOT_WITHIN' },
      'deny within orgA tras el movimiento'
    )
    // Y con el padre nuevo sí escribe (el caso no pasa por rechazarlo todo).
    await view.grant(alice, 'org-editor', sub, { within: orgB })
    assert.isTrue(await view.authorize(alice, 'docs:read', sub))
  })
})

/**
 * `config.clock` (2.5 · J1): el reloj de pared del motor se declara UNA vez
 * y el manager lo aplica al resolver el driver. Lo que se fija aquí es el
 * borde con el consumidor: un reloj que no es función y un driver que no
 * sabe recibirlo son config rota (500), nunca un reloj ignorado en silencio.
 * Que las decisiones lo usen lo juzga el contrato (par `injectableClock`).
 */
test.group('manager — config.clock (2.5 · J1)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  test('clock que no es función ⇒ 500 E_AUTHZ_CONFIG al construir', ({ assert }) => {
    for (const bad of [new Date(), 'now', 123, {}]) {
      let caught: any
      try {
        new AuthorizationManager({
          default: 'database',
          drivers: { database: () => new DatabaseAuthorizationDriver() },
          clock: bad as any,
          warnOnOptInSecurity: false,
        })
        assert.fail(`${String(bad)}: debería haber lanzado`)
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 500, String(bad))
      assert.equal(caught.code, 'E_AUTHZ_CONFIG', String(bad))
    }
  })

  test('clock declarado sobre un driver sin withClock ⇒ 500 E_AUTHZ_CONFIG al resolver el driver, nombrándolo', async ({
    assert,
  }) => {
    const bare: any = { authorize: async () => true }
    const manager = new AuthorizationManager({
      default: 'bare',
      drivers: { bare: () => bare },
      clock: () => new Date('2030-01-01T00:00:00Z'),
      warnOnOptInSecurity: false,
    })
    let caught: any
    try {
      await manager.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_CONFIG')
    assert.include(caught.message, 'withClock')
    assert.include(caught.message, "'bare'")
    // `driver()` tampoco entrega un driver sin el reloj.
    await assert.rejects(() => manager.driver(), /withClock/)
  })

  test('el manager resuelve el driver UNA vez con el reloj aplicado; driver() y las vistas de forRequest comparten esa instancia', async ({
    assert,
  }) => {
    let applied = 0
    const clock = () => new Date('2030-01-01T00:00:00Z')
    const base = new DatabaseAuthorizationDriver()
    const original = base.withClock.bind(base)
    base.withClock = (now) => {
      applied += 1
      assert.strictEqual(now, clock)
      return original(now)
    }
    const manager = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => base },
      clock,
      warnOnOptInSecurity: false,
    })
    const resolved = await manager.driver()
    assert.notStrictEqual(resolved, base, 'es la vista con reloj, no el driver desnudo')
    assert.strictEqual(Object.getPrototypeOf(resolved), base)
    assert.strictEqual(await manager.driver(), resolved)
    assert.strictEqual(await manager.forRequest().driver(), resolved)
    assert.strictEqual(await manager.forRequest().forRequest().driver(), resolved)
    assert.equal(applied, 1)
  })

  test("un driver rechaza un 'now' que no es función (opciones y withClock) con 500 E_AUTHZ_CONFIG", ({ assert }) => {
    for (const bad of [new Date(), 'now', 5]) {
      assert.throws(() => new DatabaseAuthorizationDriver({ now: bad as any }), /debe ser una función \(\) => Date/)
      assert.throws(() => new DatabaseAuthorizationDriver().withClock(bad as any), /debe ser una función \(\) => Date/)
    }
    let caught: any
    try {
      new DatabaseAuthorizationDriver({ now: 'ayer' as any })
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_CONFIG')
  })
})

test.group('manager — cotas de enumeración con tope sano (2.5-B · ⚪6)', () => {
  test('maxDescendants por encima de 10 000 000 (o maxScopes) es 500 E_AUTHZ_CONFIG antes de tocar nada: por encima, el hint de MySQL sale de rango y un ciclo deja de ser el 422 del contrato', async ({
    assert,
  }) => {
    // Auditor ⚪6: `maxDescendants` era un entero ≥ 1 sin tope; con
    // ~4,29e9 el `SET_VAR(cte_max_recursion_depth)` de MySQL sale del rango
    // y un ciclo en la tabla pasaba de 422 «posible ciclo» a 503 (y con
    // 1e6 ya costaba 2 s de CPU por llamada). La cota sale del config, nunca
    // de la petición: el tope es de configuración, 500.
    const tree = memoryScopeTree()
    let asked = 0
    const make = (scopes: Record<string, unknown>) =>
      new AuthorizationManager({
        default: 'database',
        drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) }) },
        scopes: {
          resolveChain: resolveChainFrom(tree),
          descendantsOf: async (scope, options) => {
            asked += 1
            return descendantsFrom(tree)(scope, options)
          },
          ...scopes,
        },
        warnOnOptInSecurity: false,
      })
    const alice = { type: 'users', uuid: uuidv7() }
    for (const bad of [10_000_001, 4_294_967_293, Number.MAX_SAFE_INTEGER]) {
      for (const key of ['maxDescendants', 'maxScopes']) {
        let caught: any
        try {
          await make({ [key]: bad }).authorizedScopes(alice, 'docs:read', 'organization')
          assert.fail(`${key}=${bad}: debería haber rechazado`)
        } catch (error) {
          caught = error
        }
        assert.equal(caught?.status, 500, `${key}=${bad}: ${caught?.message}`)
        assert.equal(caught?.code, 'E_AUTHZ_CONFIG', `${key}=${bad}`)
        assert.include(String(caught?.message), '10000000', `${key}=${bad}: el mensaje dice el tope`)
      }
    }
    assert.equal(asked, 0, 'ninguna llamada a descendantsOf con una cota fuera de rango')
    // El tope exacto vale.
    assert.deepEqual(await make({ maxDescendants: 10_000_000, maxScopes: 10_000_000 }).authorizedScopes(alice, 'docs:read', 'organization'), { kind: 'none' })
  })
})
