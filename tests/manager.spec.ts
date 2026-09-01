/**
 * El manager es la fachada del motor: resuelve el driver del config y avisa
 * de cada escritura al consumidor. Lo que se prueba aquí es el borde con ese
 * consumidor — la semántica de autorización la juzga contract.spec.ts.
 */

import { test } from '@japa/runner'
import { withTableMissing } from './helpers/table_missing.js'
import { v7 as uuidv7 } from 'uuid'
import { AuthorizationManager } from '../src/manager.js'
import {
  AuthorizationBackendError,
  AuthorizationBackendTimeoutError,
  PruneInterruptedError,
} from '../src/errors.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { syncAuthzCatalog, diffAuthzCatalog, catalogInSync, runCatalogDiff, syncCatalogs } from '../src/catalog/catalog.js'
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
      // 3D · M1: `{ slug, scopeType }` y `{ uuid }` ya son legales en las
      // cuatro rutas; lo que sigue siendo 422 es el objeto MAL formado.
      ['RoleQuery sin slug en grant', () => manager.grant({ type: 'users', uuid: uuidv7() }, {} as any, APP_SCOPE)],
      ['RoleQuery con slug en mayúsculas en revoke', () => manager.revoke({ type: 'users', uuid: uuidv7() }, { slug: 'Editor', scopeType: 'app' } as any, APP_SCOPE)],
      ['RoleQuery sin scopeType en listSubjects', () => manager.listSubjects({ slug: 'editor' } as any, APP_SCOPE)],
      ['RoleQuery con uuid mal formado en grant', () => manager.grant({ type: 'users', uuid: uuidv7() }, { uuid: 'editor' } as any, APP_SCOPE)],
      ['RoleQuery que mezcla uuid y slug en hasRole', () => manager.hasRole({ type: 'users', uuid: uuidv7() }, { uuid: uuidv7(), slug: 'editor' } as any, APP_SCOPE)],
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
    assert.equal((await syncCatalogs([async () => platform, async () => ({ ...tenant, roles: [] })])).count, 2)
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

  test('B5: assignableAt de un permiso es composición: un rol del spec de otro nivel que lo lleve ⇒ 422 E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT sin escribir (también contra un permiso de OTRO catálogo ya en la base); el config manda sobre el valor almacenado; [] o un nivel inválido ⇒ 422', async ({
    assert,
  }) => {
    const { default: db } = await import('@adonisjs/lucid/services/db')
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const notAssignable = { status: 422, code: 'E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT' }
    // Dentro del spec, antes de tocar la base.
    await rejectsCode(assert, () =>
      syncAuthzCatalog({
        permissions: [{ slug: 'org:settings', assignableAt: ['app', 'organization'] }],
        roles: [{ slug: 'unit-editor', scopeType: 'unit', permissions: ['org:settings'] }],
      }), notAssignable)
    assert.lengthOf(await db.from('authz_permissions').select('uuid'), 0)
    // Contra un permiso de otro catálogo ya en la base: dentro de la transacción, nada queda escrito.
    await syncAuthzCatalog({ permissions: [{ slug: 'org:settings', assignableAt: ['app', 'organization'] }], roles: [] })
    await rejectsCode(assert, () =>
      syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }],
        roles: [{ slug: 'unit-editor', scopeType: 'unit', permissions: ['docs:read', 'org:settings'] }],
      }), notAssignable)
    assert.lengthOf(await db.from('authz_roles').select('uuid'), 0)
    assert.lengthOf(await db.from('authz_permissions').where('slug', 'docs:read').select('uuid'), 0, 'la transacción se revirtió entera')
    // Un rol del nivel permitido sí; y el memo expone los niveles.
    await syncAuthzCatalog({ permissions: [], roles: [{ slug: 'org-admin', scopeType: 'organization', permissions: ['org:settings'] }] })
    assert.deepEqual((await new CatalogCache().view()).permission('org:settings'), { uuid: (await db.from('authz_permissions').where('slug', 'org:settings').first()).uuid, assignableAt: ['app', 'organization'] })
    // El config manda: ampliar los niveles se refleja; quitar la restricción (omitirlo) también.
    await syncAuthzCatalog({ permissions: [{ slug: 'org:settings', assignableAt: ['unit', 'organization', 'app'] }], roles: [] })
    assert.deepEqual((await new CatalogCache().view()).permission('org:settings')!.assignableAt, ['app', 'organization', 'unit'])
    await syncAuthzCatalog({ permissions: [{ slug: 'org:settings' }], roles: [] })
    assert.isNull((await new CatalogCache().view()).permission('org:settings')!.assignableAt)
    // Gramática.
    const invalid = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
    await rejectsCode(assert, () => syncAuthzCatalog({ permissions: [{ slug: 'x:y', assignableAt: [] }], roles: [] }), invalid)
    await rejectsCode(assert, () => syncAuthzCatalog({ permissions: [{ slug: 'x:y', assignableAt: ['Org'] }], roles: [] }), invalid)
    await rejectsCode(assert, () => syncAuthzCatalog({ permissions: [{ slug: 'x:y', assignableAt: 'app' as any }], roles: [] }), invalid)
    assert.lengthOf(await db.from('authz_permissions').where('slug', 'x:y').select('uuid'), 0)
  })

  test('B6: el sync solo toca roles GLOBALES: un rol local con el (slug, scopeType) de un global del spec lo ENSOMBRECE (3E · P1 b: el global gana y se reporta, ya no es 422); el prune de vínculos y el rank no tocan roles locales; el diff los lista como propios de un scope, no como sobrantes, y falla por assignableAt distinto', async ({
    assert,
  }) => {
    const { default: db } = await import('@adonisjs/lucid/services/db')
    const { withAuthzCatalogWrite, CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const base = {
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [{ slug: 'unit-editor', scopeType: 'unit', rank: 5, permissions: ['docs:read', 'docs:write'] }],
    }
    await syncAuthzCatalog(base)
    // Un rol LOCAL `lead@unit` (owner organization|org-a) con docs:write, y otro local `unit-editor@organization` (otro nivel: no colisiona).
    const lead = uuidv7()
    const owner = 'organization|org-a'
    await withAuthzCatalogWrite(async (trx) => {
      const perm: any = (await trx.from('authz_permissions').where('slug', 'docs:write').select('uuid'))[0]
      const now = new Date()
      await trx.table('authz_roles').insert({ uuid: lead, slug: 'lead', name: 'lead', scope_type: 'unit', rank: 33, owner_scope_key: owner, created_at: now, updated_at: now })
      await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: lead, permission_uuid: perm.uuid, created_at: now })
      await trx.table('authz_roles').insert({ uuid: uuidv7(), slug: 'unit-editor', name: 'x', scope_type: 'organization', rank: 1, owner_scope_key: owner, created_at: now, updated_at: now })
    })
    // El diff del spec base sigue en sync y lista los locales como propios de un scope.
    const diff = await diffAuthzCatalog(base)
    assert.isTrue(catalogInSync(diff))
    assert.deepEqual(diff.scopedRoles.map((r) => `${r.slug}@${r.scopeType}:${r.owner}`).sort(), [`lead@unit:${owner}`, `unit-editor@organization:${owner}`])
    const report = await runCatalogDiff([async () => base])
    assert.isTrue(report.inSync)
    assert.include(report.lines.join('\n'), `rol local (propio de ${owner}): lead@unit`)
    // 3E · P1 b: un spec que quiera `lead@unit` global YA NO revienta el
    // deploy (auditor A1: un tenant de rank 2 lo paraba para siempre). El
    // diff lo anuncia como ensombrecido —deriva, exit ≠ 0— y el sync escribe
    // el global, deja el local donde estaba y lo reporta.
    const clashing = { ...base, roles: [...base.roles, { slug: 'lead', scopeType: 'unit', permissions: ['docs:read'] }] }
    const anuncio = await diffAuthzCatalog(clashing)
    assert.isFalse(catalogInSync(anuncio))
    assert.deepEqual(anuncio.shadowedByGlobal, [{ slug: 'lead', scopeType: 'unit', owner }])
    const sombra = await syncAuthzCatalog(clashing)
    assert.deepEqual(sombra.shadowedByGlobal.map((r) => `${r.slug}@${r.scopeType}:${r.owner}`), [`lead@unit:${owner}`])
    assert.equal(sombra.shadowedByGlobal[0].uuid, lead, 'el reporte identifica al local por uuid')
    const roles = await db.from('authz_roles').where('slug', 'lead').select('uuid', 'owner_scope_key')
    assert.lengthOf(roles, 2, 'el global entra y el local sigue')
    assert.deepEqual(roles.map((r: any) => r.owner_scope_key).sort(), ['global', owner])
    // Vuelta al estado anterior para el resto del caso (el global se va).
    await withAuthzCatalogWrite(async (trx) => {
      const globalLead: any = (await trx.from('authz_roles').where('slug', 'lead').where('owner_scope_key', 'global').select('uuid'))[0]
      await trx.from('authz_role_permissions').where('role_uuid', globalLead.uuid).delete()
      await trx.from('authz_roles').where('uuid', globalLead.uuid).delete()
    })
    assert.lengthOf(await db.from('authz_roles').where('slug', 'lead').select('uuid'), 1)
    // Re-sync con prune (quitando docs:write del global unit-editor) y otro rank: el local conserva vínculos y rank.
    await syncAuthzCatalog({ ...base, roles: [{ slug: 'unit-editor', scopeType: 'unit', rank: 9, permissions: ['docs:read'] }] })
    const view = await new CatalogCache().view()
    assert.deepEqual([...view.rolePermissionsOf(lead)], ['docs:write'])
    assert.equal(view.roleByUuid(lead)!.rank, 33)
    assert.equal(view.role('unit-editor', 'unit')!.rank, 9)
    assert.deepEqual([...view.rolePermissionsOf(view.role('unit-editor', 'unit')!.uuid)], ['docs:read'])
    assert.equal(view.roleVisible('unit-editor', 'organization', [owner])!.rank, 1, 'el local unit-editor@organization sigue con su rank')
    // assignableAt distinto entre config y base es deriva: el diff lo nombra y runCatalogDiff falla.
    await syncAuthzCatalog({ permissions: [{ slug: 'docs:write', assignableAt: ['unit'] }], roles: [] })
    const drift = await diffAuthzCatalog(base)
    assert.isFalse(catalogInSync(drift))
    assert.deepEqual(drift.assignableAtMismatches, [{ permission: 'docs:write', expected: null, actual: ['unit'] }])
    const failing = await runCatalogDiff([async () => base])
    assert.isFalse(failing.inSync)
    assert.include(failing.lines.join('\n'), 'assignableAt distinto: docs:write spec=cualquiera base=unit')
  })

  test('3E · P6: estrechar assignableAt revalida TODOS los roles que ya llevaban el permiso (locales y globales de otro catálogo): el sync los reporta y no rompe en silencio, el diff los lista y no se borra ningún vínculo', async ({
    assert,
  }) => {
    // Code-review 3E · P6: el sync solo validaba los roles DEL SPEC, así que
    // estrechar `assignableAt` dejaba vivos los vínculos que la restricción
    // nueva prohíbe —en los roles locales de los tenants y en los globales de
    // otro catálogo— sin decir una palabra: la restricción entraba a medias.
    // Política única con P1 b: reportar y seguir (no se borra nada; lo
    // asignado sigue concediendo, invariante 1).
    const { default: db } = await import('@adonisjs/lucid/services/db')
    const { withAuthzCatalogWrite } = await import('../src/catalog/catalog_cache.js')
    const base = {
      permissions: [{ slug: 'docs:write' }],
      roles: [{ slug: 'unit-editor', scopeType: 'unit', permissions: ['docs:write'] }],
    }
    await syncAuthzCatalog(base)
    const local = uuidv7()
    const owner = 'organization|org-a'
    await withAuthzCatalogWrite(async (trx) => {
      const perm: any = (await trx.from('authz_permissions').where('slug', 'docs:write').select('uuid'))[0]
      const now = new Date()
      await trx.table('authz_roles').insert({ uuid: local, slug: 'lead', name: 'lead', scope_type: 'unit', rank: 3, owner_scope_key: owner, created_at: now, updated_at: now })
      await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: local, permission_uuid: perm.uuid, created_at: now })
    })

    // El config estrecha el permiso a `organization`. El spec no declara
    // roles (los suyos ya no podrían llevarlo).
    const estrecho = { permissions: [{ slug: 'docs:write', assignableAt: ['organization'] as any }], roles: [] }
    const anuncio = await diffAuthzCatalog(estrecho)
    assert.isFalse(catalogInSync(anuncio), 'el diff lo dice ANTES del deploy')
    assert.deepEqual(
      anuncio.assignableAtViolations.map((v) => `${v.role}@${v.scopeType}:${v.owner}→${v.permission}`).sort(),
      [`lead@unit:${owner}→docs:write`, 'unit-editor@unit:global→docs:write']
    )
    const report = await syncAuthzCatalog(estrecho)
    assert.deepEqual(
      report.assignableAtViolations.map((v) => `${v.role.slug}@${v.role.scopeType}:${v.role.owner}→${v.permission}`).sort(),
      [`lead@unit:${owner}→docs:write`, 'unit-editor@unit:global→docs:write']
    )
    assert.equal(report.assignableAtViolations.find((v) => v.role.slug === 'lead')!.role.uuid, local)
    assert.lengthOf(await db.from('authz_role_permissions').select('uuid'), 2, 'no se borra ningún vínculo: lo asignado sigue concediendo')
    const lineas = (await runCatalogDiff([async () => estrecho])).lines.join('\n')
    assert.include(lineas, `vínculo fuera de assignableAt: lead@unit (owner ${owner}) → docs:write`)
    // Un rol del nivel admitido no aparece; y ampliar el assignableAt cierra el informe.
    const ancho = { permissions: [{ slug: 'docs:write', assignableAt: ['organization', 'unit'] as any }], roles: [] }
    assert.deepEqual((await syncAuthzCatalog(ancho)).assignableAtViolations, [])
    assert.isTrue(catalogInSync(await diffAuthzCatalog(ancho)))
  })

  test('3E · P5/Q6: una fila corrupta de assignable_at es una DIFERENCIA del diff (no un 500: el diff existe para reportarla) y el sync la repara; y las líneas de roles locales salen bajo su propio epígrafe, no dentro del bloque de otro catálogo', async ({
    assert,
  }) => {
    // Code-review 3E · P5: `diffAuthzCatalog` leía `assignable_at` con
    // `parseAssignableAt` (500 con una fila ilegible) mientras el SYNC ya la
    // trataba como distinta (`storedAssignableAt`): el comando que iba a
    // repararla moría antes de decir qué reparar.
    const { default: db } = await import('@adonisjs/lucid/services/db')
    const { withAuthzCatalogWrite } = await import('../src/catalog/catalog_cache.js')
    const base = {
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'viewer', scopeType: 'unit', permissions: ['docs:read'] }],
    }
    await syncAuthzCatalog(base)
    assert.isTrue(catalogInSync(await diffAuthzCatalog(base)))
    await withAuthzCatalogWrite(async (trx) => {
      await trx.from('authz_permissions').where('slug', 'docs:read').update({ assignable_at: 'no-es-json' })
    })

    const diff = await diffAuthzCatalog(base)
    assert.isFalse(catalogInSync(diff))
    assert.deepEqual(diff.assignableAtMismatches, [{ permission: 'docs:read', expected: null, actual: null, corrupt: true }])
    const report = await runCatalogDiff([async () => base])
    assert.isFalse(report.inSync)
    assert.include(report.lines.join('\n'), 'assignableAt CORRUPTO en la base: docs:read')
    // El sync la repara (y el memo vuelve a leerla sin 500).
    await syncAuthzCatalog(base)
    assert.isNull((await db.from('authz_permissions').where('slug', 'docs:read').first()).assignable_at)
    assert.isTrue(catalogInSync(await diffAuthzCatalog(base)))

    // Q6: con DOS catálogos, uno en sync y otro con deriva, las líneas de los
    // roles locales no se cuelan indentadas dentro del bloque del segundo.
    const otro = { permissions: [{ slug: 'billing:read' }], roles: [{ slug: 'pagador', scopeType: 'app', permissions: ['billing:read'] }] }
    await withAuthzCatalogWrite(async (trx) => {
      const now = new Date()
      await trx.table('authz_roles').insert({ uuid: uuidv7(), slug: 'lead', name: 'lead', scope_type: 'unit', rank: 3, owner_scope_key: 'organization|org-a', created_at: now, updated_at: now })
    })
    const dos = await runCatalogDiff([async () => base, async () => otro])
    assert.isFalse(dos.inSync)
    const idx = dos.lines.findIndex((l) => l.startsWith('roles locales'))
    assert.isAbove(idx, 0, 'las líneas informativas van bajo su propio epígrafe')
    assert.equal(dos.lines[idx - 1], '  vínculo ausente en la base: pagador@app → billing:read', 'el bloque del catálogo #2 termina en sus diferencias')
    assert.include(dos.lines[idx + 1], 'rol local (propio de organization|org-a): lead@unit')
  })

  test('3D · M2 d + 3F · S3: el diff clasifica los homónimos visibles en una misma cadena por AUTORIDAD (global > local de un ancestro > local de un descendiente): los ENSOMBRECIDOS se listan y NO son deriva; solo lo que la autoridad no ordena deja el gate de CI en rojo', async ({
    assert,
  }) => {
    const { withAuthzCatalogWrite } = await import('../src/catalog/catalog_cache.js')
    const base = {
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'viewer', scopeType: 'unit', permissions: ['docs:read'] }],
    }
    await syncAuthzCatalog(base)
    assert.isTrue(catalogInSync(await diffAuthzCatalog(base)))

    // (1) Un local homónimo del GLOBAL: el global se ve en todas partes, así
    // que conviven en la cadena del owner. Gana el global (autoridad) y el
    // local queda ENSOMBRECIDO: se lista, no es deriva — un tenant de rank 2
    // no puede dejar el `authz:catalog:diff` de la plataforma en rojo (3F ·
    // S3 b, auditor N1).
    const orgA = 'organization|org-a'
    const unitA1 = 'unit|unit-a1'
    const local = uuidv7()
    await withAuthzCatalogWrite(async (trx) => {
      const now = new Date()
      await trx.table('authz_roles').insert({ uuid: local, slug: 'viewer', name: 'viewer', scope_type: 'unit', rank: 1, owner_scope_key: unitA1, created_at: now, updated_at: now })
    })
    const specVacio = { permissions: [{ slug: 'docs:read' }], roles: [] }
    const ensombrecido = await diffAuthzCatalog(base)
    assert.isTrue(catalogInSync(ensombrecido), 'el spec sigue en sync: la sombra no es una diferencia con el config')
    assert.deepEqual(ensombrecido.shadowedByGlobal, [{ slug: 'viewer', scopeType: 'unit', owner: unitA1 }])
    const conGlobal = await diffAuthzCatalog(specVacio)
    assert.isTrue(catalogInSync(conGlobal), 'y tampoco desde un spec que ni lo menciona')
    assert.deepEqual(conGlobal.ambiguousRoles, [], 'la pareja global+local la ordena la autoridad')
    assert.deepEqual(conGlobal.shadowedByGlobal, [{ slug: 'viewer', scopeType: 'unit', owner: unitA1 }])
    const reporte = await runCatalogDiff([async () => specVacio])
    assert.isTrue(reporte.inSync, 'exit 0')
    assert.include(reporte.lines.join('\n'), 'rol local ENSOMBRECIDO por un global homónimo: viewer@unit')
    assert.include(reporte.lines.join('\n'), 'la plataforma incluida')

    // (2) Dos LOCALES homónimos: solo conviven si un owner está en la cadena
    // del otro, y eso lo sabe el árbol del consumidor. Gana el ANCESTRO.
    await withAuthzCatalogWrite(async (trx) => {
      const now = new Date()
      const globalViewer: any = (await trx.from('authz_roles').where('slug', 'viewer').where('owner_scope_key', 'global').select('uuid'))[0]
      await trx.from('authz_role_permissions').where('role_uuid', globalViewer.uuid).delete()
      await trx.from('authz_roles').where('uuid', globalViewer.uuid).delete()
      await trx.table('authz_roles').insert({ uuid: uuidv7(), slug: 'viewer', name: 'viewer', scope_type: 'unit', rank: 1, owner_scope_key: orgA, created_at: now, updated_at: now })
    })
    const sinArbol = await diffAuthzCatalog(specVacio)
    assert.deepEqual(sinArbol.ambiguousRoles, [], 'sin resolutor, la pareja de locales no se juzga')
    assert.deepEqual(sinArbol.shadowedByAncestor, [])
    const disjuntos = async (scope: any) =>
      scope.type === 'app' ? [APP_SCOPE] : [scope, APP_SCOPE]
    const enDisjuntos = await diffAuthzCatalog(specVacio, { resolveChain: disjuntos })
    assert.deepEqual(enDisjuntos.shadowedByAncestor, [], 'subárboles disjuntos: legal')
    // 3b-1 · T-3b 4 (tester 3F · §6.4): la aserción que se perdió al pasar
    // este caso de `ambiguousRoles` a `shadowedByAncestor`. Sin ella nadie
    // miraba que un árbol disjunto NO genere deriva, que es lo que el caso
    // se llama a sí mismo.
    assert.deepEqual(enDisjuntos.ambiguousRoles, [], 'subárboles disjuntos: tampoco es deriva')
    assert.isTrue(catalogInSync(enDisjuntos), 'exit 0')
    const anidados = async (scope: any) =>
      scope.type === 'app'
        ? [APP_SCOPE]
        : scope.uuid === 'unit-a1'
          ? [scope, { type: 'organization', uuid: 'org-a' }, APP_SCOPE]
          : [scope, APP_SCOPE]
    const cruzados = await diffAuthzCatalog(specVacio, { resolveChain: anidados })
    assert.deepEqual(cruzados.shadowedByAncestor, [{ slug: 'viewer', scopeType: 'unit', owner: unitA1, shadowedBy: orgA }])
    assert.deepEqual(cruzados.ambiguousRoles, [], 'el ancestro manda: no es deriva')
    assert.isTrue(catalogInSync(cruzados))
    const conArbol = await runCatalogDiff([async () => specVacio], { resolveChain: anidados })
    assert.isTrue(conArbol.inSync, 'exit 0 con la mina puesta')
    assert.include(conArbol.lines.join('\n'), `rol local ENSOMBRECIDO por el de un ancestro: viewer@unit (owner ${unitA1}, ensombrecido por ${orgA})`)

    // (3) Lo que la autoridad NO ordena sigue siendo deriva: un árbol que se
    // contradice (cada owner se declara ancestro del otro) deja el gate rojo.
    const contradictorio = async (scope: any) =>
      scope.type === 'app'
        ? [APP_SCOPE]
        : scope.uuid === 'unit-a1'
          ? [scope, { type: 'organization', uuid: 'org-a' }, APP_SCOPE]
          : [scope, { type: 'unit', uuid: 'unit-a1' }, APP_SCOPE]
    const sinOrden = await diffAuthzCatalog(specVacio, { resolveChain: contradictorio })
    assert.deepEqual(sinOrden.ambiguousRoles, [{ slug: 'viewer', scopeType: 'unit', owners: [orgA, unitA1].sort() }])
    assert.isFalse(catalogInSync(sinOrden))
    const roto = await runCatalogDiff([async () => specVacio], { resolveChain: contradictorio })
    assert.isFalse(roto.inSync)
    assert.include(roto.lines.join('\n'), `owners=${[orgA, unitA1].sort().join(', ')}`)

    // (4) 3G · X3 (auditor P5): el gate opcional. Que un tenant no pueda
    // dejar en rojo el CI de la plataforma tiene un precio —nadie se entera
    // por CI de que las rutas por slug de ese subárbol están muertas—, y
    // `--fail-on-shadows` es la forma de elegir enterarse.
    const conFlag = await runCatalogDiff([async () => specVacio], { resolveChain: anidados, failOnShadows: true })
    assert.isFalse(conFlag.inSync, 'con --fail-on-shadows, lo ensombrecido SÍ es deriva')
    assert.include(conFlag.lines.join('\n'), '--fail-on-shadows')
    const sinFlag = await runCatalogDiff([async () => specVacio], { resolveChain: anidados })
    assert.isTrue(sinFlag.inSync, 'y sin el flag, el default no cambia')

    // (5) 3G · X3 b: un GLOBAL en el grupo ya no ciega la pareja de locales.
    // Hasta aquí `classifyHomonyms` hacía `continue` en cuanto había un
    // global, así que una pareja contradictoria dentro de ese mismo
    // (slug, nivel) —la única deriva de verdad— dejaba de detectarse.
    await syncAuthzCatalog(base)
    const conGlobalYContradiccion = await diffAuthzCatalog(specVacio, { resolveChain: contradictorio })
    assert.deepEqual(
      conGlobalYContradiccion.shadowedByGlobal.map((r) => r.owner).sort(),
      [orgA, unitA1].sort(),
      'el global sigue ensombreciendo a los dos locales'
    )
    assert.deepEqual(
      conGlobalYContradiccion.ambiguousRoles,
      [{ slug: 'viewer', scopeType: 'unit', owners: [orgA, unitA1].sort() }],
      'y la contradicción entre los dos locales se sigue viendo'
    )
    assert.isFalse(catalogInSync(conGlobalYContradiccion), 'sigue siendo deriva')
  })

  test('3b-1 · T-3b (tester 3F · §6.1 y §6.3): runCatalogDiff acumula las sombras de TODOS los catálogos (no solo las del #1) y shadowedByAncestor da UNA línea por rol ensombrecido, nombrando al más autorizado', async ({
    assert,
  }) => {
    const { default: db } = await import('@adonisjs/lucid/services/db')
    const { withAuthzCatalogWrite } = await import('../src/catalog/catalog_cache.js')
    const orgA = 'organization|org-a'
    const unitA1 = 'unit|unit-a1'
    const teamA = 'team|team-a'

    // §6.1 — la sombra la causa un rol del catálogo #2. `diff.shadowedByGlobal`
    // tiene una fuente DEPENDIENTE del spec (un rol del spec homónimo de un
    // local), así que tomarla solo del índice 0 la perdía por completo: no
    // salía como línea de sombras ni como diferencia de ese catálogo.
    await withAuthzCatalogWrite(async (trx) => {
      const now = new Date()
      await trx.table('authz_roles').insert([
        { uuid: uuidv7(), slug: 'viewer', name: 'viewer', scope_type: 'unit', rank: 1, owner_scope_key: unitA1, created_at: now, updated_at: now },
        { uuid: uuidv7(), slug: 'lead', name: 'lead', scope_type: 'unit', rank: 1, owner_scope_key: unitA1, created_at: now, updated_at: now },
      ])
    })
    const uno = { permissions: [{ slug: 'docs:read' }], roles: [{ slug: 'viewer', scopeType: 'unit' as const, permissions: ['docs:read'] }] }
    const dos = { permissions: [{ slug: 'billing:read' }], roles: [{ slug: 'lead', scopeType: 'unit' as const, permissions: ['billing:read'] }] }
    const reporte = await runCatalogDiff([async () => uno, async () => dos])
    const texto = reporte.lines.join('\n')
    assert.include(texto, 'rol local ENSOMBRECIDO por un global homónimo: viewer@unit', 'la del catálogo #1')
    assert.include(texto, 'rol local ENSOMBRECIDO por un global homónimo: lead@unit', 'y la del catálogo #2')
    assert.lengthOf(texto.split('rol local ENSOMBRECIDO').slice(1), 2, 'sin duplicar')
    // Los roles locales (que NO dependen del spec) se siguen listando una vez.
    assert.lengthOf(texto.split('rol local (propio de').slice(1), 2)

    // §6.3 — owners ANIDADOS a > b > c: hasta aquí salían tres líneas para
    // tres roles (a→b, a→c, b→c). Cada rol ensombrecido sale UNA vez, con el
    // más autorizado de sus ensombrecedores (el ancestro más alto).
    await db.from('authz_role_permissions').delete()
    await db.from('authz_roles').delete()
    await withAuthzCatalogWrite(async (trx) => {
      const now = new Date()
      await trx.table('authz_roles').insert(
        [orgA, unitA1, teamA].map((owner) => ({
          uuid: uuidv7(), slug: 'jefe', name: 'jefe', scope_type: 'team', rank: 1,
          owner_scope_key: owner, created_at: now, updated_at: now,
        }))
      )
    })
    const anidados = async (scope: any) =>
      scope.type === 'app'
        ? [APP_SCOPE]
        : scope.type === 'team'
          ? [scope, { type: 'unit', uuid: 'unit-a1' }, { type: 'organization', uuid: 'org-a' }, APP_SCOPE]
          : scope.type === 'unit'
            ? [scope, { type: 'organization', uuid: 'org-a' }, APP_SCOPE]
            : [scope, APP_SCOPE]
    const diff = await diffAuthzCatalog({ permissions: [], roles: [] }, { resolveChain: anidados })
    assert.deepEqual(
      [...diff.shadowedByAncestor].sort((x, y) => x.owner.localeCompare(y.owner)),
      [
        { slug: 'jefe', scopeType: 'team', owner: teamA, shadowedBy: orgA },
        { slug: 'jefe', scopeType: 'team', owner: unitA1, shadowedBy: orgA },
      ],
      'una línea por ensombrecido, y el ensombrecedor es el ancestro MÁS ALTO (el más autorizado)'
    )
    assert.deepEqual(diff.ambiguousRoles, [], 'la autoridad ordena la cadena entera: no es deriva')
    assert.isTrue(catalogInSync(diff))
  })
})

async function rejectsCode(assert: any, fn: () => Promise<unknown>, expected: { status: number; code: string }): Promise<void> {
  try {
    await fn()
  } catch (error: any) {
    assert.equal(error?.status, expected.status, `status de ${error?.message ?? error}`)
    assert.equal(error?.code, expected.code, `code de ${error?.message ?? error}`)
    return
  }
  assert.fail('debería haber rechazado')
}

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
    // 3E · Q7/R4 (auditor A8, tester): el evento lleva el rol RESUELTO
    // —uuid + slug + nivel + owner—, no el `RoleQuery` que se preguntó: un
    // sink que filtraba por slug volvió a casar, y además tiene el uuid, que
    // es lo único que identifica un rol desde 3A.
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const catalogo = await new CatalogCache().view()
    const orgEditor = catalogo.role('org-editor', 'organization')!
    const ref = (event: AuthzWriteEvent) => event.roles?.map((r) => ({ uuid: r.uuid, slug: r.slug, scopeType: r.scopeType, owner: r.owner }))
    assert.deepEqual(ref(events[0]), [{ uuid: orgEditor.uuid, slug: 'org-editor', scopeType: 'organization', owner: 'global' }])
    assert.deepEqual(ref(events[3]), ref(events[0]), 'el revoke por slug nombra el mismo rol')
    assert.deepEqual(ref(events[5]), [{ uuid: catalogo.role('editor', 'app')!.uuid, slug: 'editor', scopeType: 'app', owner: 'global' }])
    assert.isUndefined(events[1].roles, 'un deny va por permiso')
    assert.isUndefined(events[4].roles, 'un scope_purged no es de un rol')
    // Preguntando por { uuid } sale exactamente igual (la forma es la resuelta).
    await manager.grant(alice, { uuid: orgEditor.uuid }, orgA, { actor: admin })
    assert.deepEqual(ref(events.at(-1)!), ref(events[0]))
    // Un rol que no existe no inventa nada en el evento (y la escritura falla).
    await rejects(assert, () => manager.grant(alice, 'no-existe', orgA), { status: 422, code: 'E_AUTHZ_UNKNOWN_ROLE' }, 'rol desconocido')
    assert.lengthOf(events, 7, 'una escritura que no ocurre no notifica')
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

/**
 * Roles locales a un scope (3B · B3): `defineScopedRole`/`updateScopedRole`/
 * `deleteScopedRole` son la API de DELEGACIÓN del manager, con policy de
 * escritura obligatoria. Lo que se prueba aquí es la policy (permiso ajeno,
 * lista blanca, deny del actor, rank, globales inmutables, colisiones, owner
 * inválido, C3) sobre el driver `database`; que el rol creado concede en su
 * owner en AMBOS drivers lo juzga el contrato.
 */
test.group('manager — roles locales a un scope (3B · B3)', (group) => {
  const orgA: ScopeRef = { type: 'organization', uuid: uuidv7() }
  const orgB: ScopeRef = { type: 'organization', uuid: uuidv7() }
  const unitA1: ScopeRef = { type: 'unit', uuid: uuidv7() }
  const unitA1x: ScopeRef = { type: 'unit', uuid: uuidv7() }
  const unitB1: ScopeRef = { type: 'unit', uuid: uuidv7() }
  let tree: ContractScopeTree
  let events: any[]
  let admin: { type: string; uuid: string }
  let adminB: { type: string; uuid: string }
  const DELEGABLE = ['docs:read', 'docs:write', 'billing:read', 'org:settings']

  function localManager(overrides: Record<string, unknown> = {}) {
    return new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) }) },
      scopes: { resolveChain: resolveChainFrom(tree), descendantsOf: descendantsFrom(tree) },
      delegablePermissions: DELEGABLE,
      hooks: { onCatalogWrite: async (event: any) => void events.push(event) },
      warnOnOptInSecurity: false,
      ...overrides,
    } as any)
  }

  async function rejects(assert: any, fn: () => Promise<unknown>, expected: { status: number; code: string }): Promise<any> {
    try {
      await fn()
    } catch (error: any) {
      assert.equal(error?.status, expected.status, `status de ${error?.message ?? error}`)
      assert.equal(error?.code, expected.code, `code de ${error?.message ?? error}`)
      return error
    }
    assert.fail('debería haber rechazado')
  }

  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [
        { slug: 'docs:read' },
        { slug: 'docs:write' },
        { slug: 'billing:read' },
        { slug: 'org:settings', assignableAt: ['app', 'organization'] },
        { slug: 'app:manage' },
      ],
      roles: [
        { slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'docs:write'] },
        { slug: 'org-admin', scopeType: 'organization', rank: 50, permissions: DELEGABLE },
        { slug: 'org-editor', scopeType: 'organization', rank: 10, permissions: ['docs:read', 'docs:write'] },
        { slug: 'unit-editor', scopeType: 'unit', permissions: ['docs:write'] },
        { slug: 'superadmin', scopeType: 'app', rank: 100, permissions: ['app:manage', ...DELEGABLE] },
      ],
    })
    tree = memoryScopeTree()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(unitA1, orgA)
    await tree.attach(unitA1x, unitA1)
    await tree.attach(unitB1, orgB)
    events = []
    admin = { type: 'users', uuid: uuidv7() }
    adminB = { type: 'users', uuid: uuidv7() }
    const driver = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })
    await driver.grant(admin, 'org-admin', orgA)
    await driver.grant(adminB, 'org-admin', orgB)
  })

  test('defineScopedRole escribe el rol local (owner canónico) con sus vínculos, sube la versión compartida, notifica role_defined con actor, y el rol concede en el owner y sus descendientes; updateScopedRole cambia lo que concede; deleteScopedRole lo purga (role_purged) sin dejar asignaciones', async ({
    assert,
  }) => {
    const { readAuthzCatalogVersion, CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const authz = localManager()
    const bob = { type: 'users', uuid: uuidv7() }
    const before = await readAuthzCatalogVersion()

    const lead = await authz.defineScopedRole(admin, orgA, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'], name: 'Lead' })
    assert.deepEqual(lead, { uuid: lead.uuid, slug: 'lead', scopeType: 'unit', owner: `organization|${orgA.uuid}`, rank: 20 })
    assert.equal(await readAuthzCatalogVersion(), before + 1, 'la versión compartida sube en la misma transacción')
    assert.deepEqual(events, [{ action: 'role_defined', actor: admin, role: lead, owner: orgA, permissions: ['docs:write'] }])
    // Otro memo (otro proceso) lo ve en su siguiente pregunta.
    assert.deepEqual((await new CatalogCache().view()).roleByUuid(lead.uuid), lead)

    await authz.grant(bob, 'lead', unitA1, { within: orgA })
    assert.isTrue(await authz.authorize(bob, 'docs:write', unitA1))
    assert.isTrue(await authz.authorize(bob, 'docs:write', unitA1x))
    assert.isFalse(await authz.authorize(bob, 'docs:read', unitA1))
    assert.deepEqual(await authz.effectivePermissions(bob, unitA1x), ['docs:write'])
    const fuera = await rejects(assert, () => authz.grant(bob, 'lead', unitB1), { status: 422, code: 'E_AUTHZ_ROLE_NOT_VISIBLE' })
    // 3E · Q2 (auditor A6, tester 3E): un 422 es lo que el framework devuelve
    // TAL CUAL al cliente, así que no puede nombrar identificadores de otro
    // árbol. El rol existe, pero su owner (orgA) no está en la cadena de
    // unitB1: el mensaje dice que el nombre existe y no dice de quién es.
    assert.notInclude(fuera.message, orgA.uuid!, 'el 422 no regala la clave de scope del otro tenant')
    assert.notInclude(fuera.message, lead.uuid, 'ni el uuid del rol ajeno')

    const updated = await authz.updateScopedRole(admin, lead.uuid, { permissions: ['docs:read', 'billing:read'], rank: 25, name: 'Lead 2' })
    assert.deepEqual(updated, { ...lead, rank: 25 })
    assert.equal(await readAuthzCatalogVersion(), before + 2)
    assert.deepEqual(events[1], { action: 'role_updated', actor: admin, role: updated, owner: orgA, permissions: ['billing:read', 'docs:read'] })
    assert.isFalse(await authz.authorize(bob, 'docs:write', unitA1), 'el vínculo podado deja de conceder')
    assert.isTrue(await authz.authorize(bob, 'billing:read', unitA1x))
    assert.deepEqual((await authz.effectivePermissions(bob, unitA1x)).sort(), ['billing:read', 'docs:read'])
    // Un update sin cambios es un no-op (idempotente): ni versión ni evento.
    await authz.updateScopedRole(admin, lead.uuid, { permissions: ['billing:read', 'docs:read'], rank: 25 })
    assert.equal(await readAuthzCatalogVersion(), before + 2)
    assert.lengthOf(events, 2)

    await authz.deleteScopedRole(admin, lead.uuid)
    assert.equal(await readAuthzCatalogVersion(), before + 3)
    assert.deepEqual(events[2], { action: 'role_purged', actor: admin, role: updated, owner: orgA, permissions: ['billing:read', 'docs:read'] })
    assert.isFalse(await authz.authorize(bob, 'billing:read', unitA1x))
    assert.deepEqual(await authz.listRoles(bob, unitA1), [])
    assert.isNull((await new CatalogCache().view()).roleByUuid(lead.uuid))
    await rejects(assert, () => authz.grant(bob, 'lead', unitA1), { status: 422, code: 'E_AUTHZ_UNKNOWN_ROLE' })
    // Recrear el slug (otro uuid) no revive la asignación purgada.
    await authz.defineScopedRole(admin, orgA, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
    assert.isFalse(await authz.hasRole(bob, 'lead', unitA1))
    assert.isFalse(await authz.authorize(bob, 'docs:write', unitA1))
  })

  test('policy de permisos: fuera de delegablePermissions ⇒ 422 E_AUTHZ_PERMISSION_NOT_DELEGABLE (default []: nadie delega hasta declararla); que el actor no tiene efectivo ⇒ 422; que el actor tiene DENEGADO ⇒ 422 (C2: el deny no se lava vía un títere); desconocido ⇒ 422 E_AUTHZ_UNKNOWN_PERMISSION; nada escrito', async ({
    assert,
  }) => {
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const notDelegable = { status: 422, code: 'E_AUTHZ_PERMISSION_NOT_DELEGABLE' }
    const spec = { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] }

    // Lista blanca vacía por defecto: el actor tiene docs:write y aun así no lo delega.
    const closed = localManager({ delegablePermissions: undefined })
    const error = await rejects(assert, () => closed.defineScopedRole(admin, orgA, spec), notDelegable)
    assert.include(error.message, 'delegablePermissions')
    // Fuera de la lista blanca aunque el actor lo tenga (app:manage lo tiene el superadmin).
    const root = { type: 'users', uuid: uuidv7() }
    await (await localManager().driver()).grant(root, 'superadmin', APP_SCOPE)
    await rejects(assert, () => localManager().defineScopedRole(root, orgA, { ...spec, permissions: ['app:manage'] }), notDelegable)
    // En la lista blanca pero el actor no lo tiene: org-editor (rank 10) no tiene billing:read.
    const editorB = { type: 'users', uuid: uuidv7() }
    await (await localManager().driver()).grant(editorB, 'org-editor', orgB)
    const missing = await rejects(assert, () => localManager().defineScopedRole(editorB, orgB, { ...spec, rank: 5, permissions: ['docs:read', 'billing:read'] }), notDelegable)
    assert.include(missing.message, 'billing:read')
    // Un permiso que el actor tiene POR ROL pero DENEGADO en el owner (auditor C2).
    await localManager().deny(admin, 'docs:write', orgA)
    const denied = await rejects(assert, () => localManager().defineScopedRole(admin, orgA, spec), notDelegable)
    assert.include(denied.message, 'docs:write')
    // Efectivo en el owner, no en otro sitio: el admin de A no delega en B.
    await rejects(assert, () => localManager().defineScopedRole(admin, orgB, { ...spec, permissions: ['docs:read'] }), notDelegable)
    // Desconocido para el catálogo (aunque esté en la lista blanca).
    await rejects(
      assert,
      () => localManager({ delegablePermissions: [...DELEGABLE, 'no:existe'] }).defineScopedRole(admin, orgA, { ...spec, permissions: ['no:existe'] }),
      { status: 422, code: 'E_AUTHZ_UNKNOWN_PERMISSION' }
    )
    assert.deepEqual((await new CatalogCache().view()).rolesNamed('lead', 'unit'), [])
    assert.lengthOf(events, 0)
    // Con los permisos que sí tiene efectivos (y sin el denegado), escribe.
    const ok = await localManager().defineScopedRole(admin, orgA, { ...spec, permissions: ['docs:read', 'billing:read'] })
    assert.equal(ok.slug, 'lead')
  })

  test('3D · N2/N3: owner_scope_key corrupto (incluido \'app\') ⇒ 500 E_AUTHZ_INTERNAL y nunca un rol visible en toda la cadena; updateScopedRole con slug/scopeType/owner ⇒ 422 E_AUTHZ_INVALID_IDENTITY en vez de ignorarlos en silencio; permissions: [] ⇒ 422', async ({
    assert,
  }) => {
    // Tester H5/H6 y auditor V7. Las tres eran promesas del README sin test
    // (`owner_scope_key` corrupto ⇒ 500, «never slug, level or owner») o
    // agujeros conocidos (`'app'` como owner = un global disfrazado que el
    // sync no gobierna; un rol vacío que ocupa el (slug, nivel)).
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const { default: db } = await import('@adonisjs/lucid/services/db')
    const { withAuthzCatalogWrite } = await import('../src/catalog/catalog_cache.js')
    const authz = localManager()
    const invalid = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }

    // (a) permissions: [] ⇒ 422, nada escrito.
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { slug: 'vacio', scopeType: 'unit', rank: 20, permissions: [] }), invalid)
    assert.deepEqual((await new CatalogCache().view()).rolesNamed('vacio', 'unit'), [])

    const lead = await authz.defineScopedRole(admin, orgA, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })

    // (b) updateScopedRole no cambia slug, nivel ni owner: lo DICE.
    for (const changes of [{ slug: 'otro' }, { scopeType: 'organization' }, { owner: `organization|${orgB.uuid}` }, { rank: 10, slug: 'otro' }]) {
      await rejects(assert, () => authz.updateScopedRole(admin, lead.uuid, changes as any), invalid)
    }
    const intacto = (await new CatalogCache().view()).roleByUuid(lead.uuid)!
    assert.deepEqual(intacto, lead, 'ni renombrado ni con otro rank: no se escribió nada')

    // (c) owner_scope_key corrupto: 500 E_AUTHZ_INTERNAL en el memo, y `app`
    // cuenta como corrupto (la raíz está en TODAS las cadenas: sería un
    // global disfrazado, visible en cualquier tenant).
    for (const owner of ['basura', 'app', '']) {
      await withAuthzCatalogWrite(async (trx) => {
        await trx.from('authz_roles').where('uuid', lead.uuid).update({ owner_scope_key: owner })
      })
      let caught: any
      try {
        await new CatalogCache().view()
        assert.fail(`owner '${owner}': debería haber lanzado`)
      } catch (error: any) {
        caught = error
      }
      assert.equal(caught?.status, 500, `owner '${owner}'`)
      assert.equal(caught?.code, 'E_AUTHZ_INTERNAL', `owner '${owner}'`)
      assert.include(caught?.message, 'owner_scope_key')
      // Y por el camino de la API tampoco se relaja: el manager no lo lee.
      await rejects(assert, () => authz.updateScopedRole(admin, lead.uuid, { rank: 10 }), { status: 500, code: 'E_AUTHZ_INTERNAL' })
    }
    // Restaurado, todo vuelve a funcionar.
    await withAuthzCatalogWrite(async (trx) => {
      await trx.from('authz_roles').where('uuid', lead.uuid).update({ owner_scope_key: `organization|${orgA.uuid}` })
    })
    assert.equal((await authz.updateScopedRole(admin, lead.uuid, { rank: 10 })).rank, 10)
    assert.lengthOf(await db.from('authz_roles').where('uuid', lead.uuid).select('uuid'), 1)
  })

  test('3D · N3: un assignableAt que no cabe en authz_permissions.assignable_at (varchar 500) es 422 al ESCRIBIR, no un 500 al leer en cada view()', async ({
    assert,
  }) => {
    // Auditor V7: con muchos niveles, un MySQL no estricto truncaría el JSON
    // y `parseAssignableAt` respondería 500 en cada pregunta — un corte de
    // servicio total por un dato de config. Se rechaza donde se puede
    // arreglar: en el sync (y en el diff, que valida la misma gramática).
    const invalid = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
    const enorme = Array.from({ length: 30 }, (_, i) => `nivel-larguisimo-de-scope-${i}`)
    const spec = { permissions: [{ slug: 'docs:read', assignableAt: enorme }], roles: [] }
    await rejects(assert, () => syncAuthzCatalog(spec), invalid)
    await rejects(assert, () => diffAuthzCatalog(spec), invalid)
    const { default: db } = await import('@adonisjs/lucid/services/db')
    assert.lengthOf(await db.from('authz_permissions').where('slug', 'docs:read').select('uuid'), 1, 'el catálogo del setup sigue intacto')
    // Justo por debajo del tope sí entra.
    const cabe = Array.from({ length: 5 }, (_, i) => `nivel-${i}`)
    await syncAuthzCatalog({ permissions: [{ slug: 'docs:read', assignableAt: cabe }], roles: [] })
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    assert.deepEqual([...(await new CatalogCache().view()).permission('docs:read')!.assignableAt!], cabe.slice().sort())

    // 3D · N5: el sync y el diff normalizan IGUAL. Un valor desordenado a
    // mano salía «en sync» en el diff y el sync lo reescribía — un diff
    // limpio tiene que significar que el sync sería un no-op.
    const { withAuthzCatalogWrite } = await import('../src/catalog/catalog_cache.js')
    const crudo = '["organization","app"]'
    await withAuthzCatalogWrite(async (trx) => {
      await trx.from('authz_permissions').where('slug', 'docs:read').update({ assignable_at: crudo })
    })
    const mismo = { permissions: [{ slug: 'docs:read', assignableAt: ['app', 'organization'] }], roles: [] }
    assert.isTrue(catalogInSync(await diffAuthzCatalog(mismo)), 'el orden no es deriva')
    await syncAuthzCatalog(mismo)
    const fila: any[] = await db.from('authz_permissions').where('slug', 'docs:read').select('assignable_at')
    assert.equal(fila[0].assignable_at, crudo, 'el sync no reescribe lo que el diff da por bueno')
  })

  test('3D · M3: la API de delegación es la SÉPTIMA, OCTAVA y NOVENA escritura y también toma within: requireWithin las exige, un within que no contiene al owner es 422 E_AUTHZ_NOT_WITHIN y la raíz como within es 422 con non-root — nada escrito', async ({
    assert,
  }) => {
    // Auditor V4 (reproducido en PG): con `requireWithin: 'non-root'` un
    // holder cuyo único rol estaba en la RAÍZ creaba, editaba y borraba roles
    // dentro de CUALQUIER tenant pasando el `ownerScope` en el cuerpo de la
    // petición — la policy de efectivos contiene al admin de un tenant, no al
    // holder con rol raíz, y el README prometía «las seis escrituras».
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const rolesDe = async (slug: string) => (await new CatalogCache().view()).rolesNamed(slug, 'unit')
    const spec = { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] }

    // (a) requireWithin exige `within` en las tres.
    const estricto = localManager({ requireWithin: 'non-root' })
    const lead = await localManager().defineScopedRole(admin, orgA, spec)
    await rejects(assert, () => estricto.defineScopedRole(admin, orgA, { ...spec, slug: 'lead2' }), {
      status: 422,
      code: 'E_AUTHZ_WITHIN_REQUIRED',
    })
    await rejects(assert, () => estricto.updateScopedRole(admin, lead.uuid, { rank: 10 }), {
      status: 422,
      code: 'E_AUTHZ_WITHIN_REQUIRED',
    })
    await rejects(assert, () => estricto.deleteScopedRole(admin, lead.uuid), {
      status: 422,
      code: 'E_AUTHZ_WITHIN_REQUIRED',
    })
    assert.deepEqual((await rolesDe('lead2')), [], 'nada escrito')
    assert.lengthOf(await rolesDe('lead'), 1)

    // (b) La raíz no acota con 'non-root'.
    await rejects(assert, () => estricto.defineScopedRole(admin, orgA, { ...spec, slug: 'lead2' }, { within: APP_SCOPE }), {
      status: 422,
      code: 'E_AUTHZ_WITHIN_ROOT_FORBIDDEN',
    })

    // (c) Un `within` que NO contiene al owner: 422, sin escribir. Es lo que
    // le faltaba al escenario del auditor (orgB tomado del cuerpo).
    const laxo = localManager()
    await rejects(assert, () => laxo.defineScopedRole(admin, orgB, { ...spec, slug: 'lead2' }, { within: orgA }), {
      status: 422,
      code: 'E_AUTHZ_NOT_WITHIN',
    })
    await rejects(assert, () => laxo.updateScopedRole(admin, lead.uuid, { rank: 10 }, { within: orgB }), {
      status: 422,
      code: 'E_AUTHZ_NOT_WITHIN',
    })
    await rejects(assert, () => laxo.deleteScopedRole(admin, lead.uuid, { within: orgB }), {
      status: 422,
      code: 'E_AUTHZ_NOT_WITHIN',
    })
    assert.deepEqual(await rolesDe('lead2'), [])
    assert.equal((await new CatalogCache().view()).roleByUuid(lead.uuid)!.rank, 20, 'el update no pasó')

    // (d) Con el `within` correcto (el owner o un ancestro suyo) pasan las tres.
    const lead2 = await estricto.defineScopedRole(admin, unitA1, { ...spec, slug: 'lead2' }, { within: orgA })
    assert.equal(lead2.owner, `unit|${unitA1.uuid}`)
    const actualizado = await estricto.updateScopedRole(admin, lead.uuid, { rank: 10 }, { within: orgA })
    assert.equal(actualizado.rank, 10)
    await estricto.deleteScopedRole(admin, lead2.uuid, { within: unitA1 })
    assert.deepEqual(await rolesDe('lead2'), [])
  })

  test('lo efectivo del actor se mide en TODA la cadena del owner: un permiso que solo tiene HEREDADO de app (un rol global de nivel app) sí se delega, y un deny en el owner lo vuelve a cerrar; la lista blanca sigue mandando sobre lo heredado', async ({
    assert,
  }) => {
    // Hueco §4 del panel del tester: «effectivePermissions heredado» era una
    // decisión de producto sin caso. El README lo promete —«granted by a role
    // of theirs along the owner's chain»— y `#rolesAlong` recorre la cadena
    // entera, `app` incluida: aquí queda fijado en las dos direcciones.
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const authz = localManager()
    const chief = { type: 'users', uuid: uuidv7() }
    // `chief` NO tiene nada en orgA: su único rol es global y de nivel app.
    await (await authz.driver()).grant(chief, 'superadmin', APP_SCOPE)
    assert.deepEqual(await authz.listRoles(chief, orgA), [], 'no tiene ningún rol directo en el owner')
    assert.include(await authz.effectivePermissions(chief, orgA), 'billing:read', 'lo tiene heredado de app')

    const lead = await authz.defineScopedRole(chief, orgA, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['billing:read'] })
    assert.equal(lead.owner, `organization|${orgA.uuid}`)
    assert.deepEqual([...(await new CatalogCache().view()).rolePermissionsOf(lead.uuid)], ['billing:read'])

    // Lo heredado no escapa de la lista blanca: `app:manage` es del superadmin
    // y NO está en delegablePermissions.
    await rejects(assert, () => authz.defineScopedRole(chief, orgA, { slug: 'lead2', scopeType: 'unit', rank: 20, permissions: ['app:manage'] }), {
      status: 422,
      code: 'E_AUTHZ_PERMISSION_NOT_DELEGABLE',
    })
    // Y un deny EN EL OWNER cierra lo heredado (C2 también hacia arriba).
    await authz.deny(chief, 'billing:read', orgA)
    const denied = await rejects(assert, () => authz.defineScopedRole(chief, orgA, { slug: 'lead3', scopeType: 'unit', rank: 20, permissions: ['billing:read'] }), {
      status: 422,
      code: 'E_AUTHZ_PERMISSION_NOT_DELEGABLE',
    })
    assert.include(denied.message, 'DENEGADO')
    assert.deepEqual((await new CatalogCache().view()).rolesNamed('lead2', 'unit'), [])
    assert.deepEqual((await new CatalogCache().view()).rolesNamed('lead3', 'unit'), [])
  })

  test('policy de rank: 0 < rank < min(rank del actor, rank máximo global) ⇒ si no, 422 E_AUTHZ_RANK_EXCEEDED; rank = actor − 1 vale; actor sin rank no delega; rank no entero ⇒ 422 E_AUTHZ_INVALID_IDENTITY; y el motor sigue sin evaluar rank en authorize (invariante 8)', async ({
    assert,
  }) => {
    const authz = localManager()
    const exceeded = { status: 422, code: 'E_AUTHZ_RANK_EXCEEDED' }
    const spec = { slug: 'lead', scopeType: 'unit', permissions: ['docs:write'] }
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, rank: 50 }), exceeded) // = actor
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, rank: 51 }), exceeded)
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, rank: 0 }), exceeded)
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, rank: -1 }), exceeded)
    for (const rank of [1.5, '10', undefined, Number.NaN]) {
      await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, rank: rank as any }), { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' })
    }
    const lead = await authz.defineScopedRole(admin, orgA, { ...spec, rank: 49 })
    assert.equal(lead.rank, 49)
    // Un actor cuyo rol tiene rank 0 no puede definir nada (0 < rank < 0 es vacío).
    const editor = { type: 'users', uuid: uuidv7() }
    await (await authz.driver()).grant(editor, 'unit-editor', unitA1)
    await rejects(assert, () => authz.defineScopedRole(editor, unitA1, { slug: 'sub', scopeType: 'unit', rank: 1, permissions: ['docs:write'] }), exceeded)
    // El techo global: un actor con rank (por un rol local escrito a mano) por encima del máximo global (100) no supera ese máximo.
    const { withAuthzCatalogWrite } = await import('../src/catalog/catalog_cache.js')
    const { default: db } = await import('@adonisjs/lucid/services/db')
    const mighty = { type: 'users', uuid: uuidv7() }
    const mightyRole = uuidv7()
    await withAuthzCatalogWrite(async (trx) => {
      const perm: any = (await trx.from('authz_permissions').where('slug', 'docs:write').select('uuid'))[0]
      await trx.table('authz_roles').insert({ uuid: mightyRole, slug: 'mighty', name: 'mighty', scope_type: 'organization', rank: 500, owner_scope_key: `organization|${orgA.uuid}`, created_at: new Date(), updated_at: new Date() })
      await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: mightyRole, permission_uuid: perm.uuid, created_at: new Date() })
    })
    await (await authz.driver()).grant(mighty, 'mighty', orgA)
    await rejects(assert, () => authz.defineScopedRole(mighty, orgA, { slug: 'lead2', scopeType: 'unit', rank: 100, permissions: ['docs:write'] }), exceeded)
    const capped = await authz.defineScopedRole(mighty, orgA, { slug: 'lead2', scopeType: 'unit', rank: 99, permissions: ['docs:write'] })
    assert.equal(capped.rank, 99)
    // Invariante 8: rank es metadata; un rol de rank alto no concede lo que no tiene.
    assert.isFalse(await authz.authorize(mighty, 'billing:read', orgA))
    assert.isTrue(await authz.authorize(mighty, 'docs:write', orgA))
    assert.equal((await db.from('authz_roles').where('slug', 'lead').first())?.rank, 49)
  })

  test('los roles GLOBALES son inmutables por esta API: updateScopedRole/deleteScopedRole sobre uno ⇒ 422 E_AUTHZ_ROLE_IMMUTABLE; uuid desconocido o mal formado ⇒ 422; y solo toca un rol local quien tiene rank mayor que el del rol', async ({
    assert,
  }) => {
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const authz = localManager()
    const globalRole = (await new CatalogCache().view()).role('org-editor', 'organization')!
    const immutable = { status: 422, code: 'E_AUTHZ_ROLE_IMMUTABLE' }
    await rejects(assert, () => authz.updateScopedRole(admin, globalRole.uuid, { rank: 1 }), immutable)
    await rejects(assert, () => authz.deleteScopedRole(admin, globalRole.uuid), immutable)
    await rejects(assert, () => authz.updateScopedRole(admin, uuidv7(), { rank: 1 }), { status: 422, code: 'E_AUTHZ_UNKNOWN_ROLE' })
    await rejects(assert, () => authz.deleteScopedRole(admin, uuidv7()), { status: 422, code: 'E_AUTHZ_UNKNOWN_ROLE' })
    await rejects(assert, () => authz.deleteScopedRole(admin, 'org-editor'), { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' })
    assert.equal((await new CatalogCache().view()).role('org-editor', 'organization')!.rank, 10, 'el global sigue igual')

    // Un rol local de rank 40; quien tiene rank 40 o menos no lo toca.
    const lead = await authz.defineScopedRole(admin, orgA, { slug: 'lead', scopeType: 'unit', rank: 40, permissions: ['docs:write'] })
    const peer = { type: 'users', uuid: uuidv7() }
    await authz.defineScopedRole(admin, orgA, { slug: 'peer-admin', scopeType: 'organization', rank: 40, permissions: ['docs:write', 'docs:read'] })
    await (await authz.driver()).grant(peer, 'peer-admin', orgA)
    const exceeded = { status: 422, code: 'E_AUTHZ_RANK_EXCEEDED' }
    await rejects(assert, () => authz.updateScopedRole(peer, lead.uuid, { permissions: ['docs:read'] }), exceeded)
    await rejects(assert, () => authz.deleteScopedRole(peer, lead.uuid), exceeded)
    // Y subir un rol por encima del propio rank tampoco.
    await rejects(assert, () => authz.updateScopedRole(admin, lead.uuid, { rank: 50 }), exceeded)
    // El admin de B no puede tocar un rol de A (no lo tiene efectivo en A: ningún rol suyo en esa cadena).
    await rejects(assert, () => authz.updateScopedRole(adminB, lead.uuid, { permissions: ['docs:read'] }), exceeded)
    await rejects(assert, () => authz.deleteScopedRole(adminB, lead.uuid), exceeded)
    assert.deepEqual((await new CatalogCache().view()).roleByUuid(lead.uuid), lead)
  })

  test('colisiones ⇒ 422 E_AUTHZ_CATALOG_CONFLICT sin escribir: con un rol global del mismo (slug, scopeType) y con un local de un ancestro; dos orgs hermanas sí pueden compartir slug; con un local de un DESCENDIENTE ya NO colisiona (3F · S3: la autoridad manda, el del descendiente queda ensombrecido y se reporta); y el SYNC tampoco (3E · P1 b: el global gana, el local se reporta ensombrecido y el deploy entra entero)', async ({
    assert,
  }) => {
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const authz = localManager()
    const conflict = { status: 422, code: 'E_AUTHZ_CATALOG_CONFLICT' }
    // Con un global.
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { slug: 'org-editor', scopeType: 'organization', rank: 5, permissions: ['docs:read'] }), conflict)
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { slug: 'unit-editor', scopeType: 'unit', rank: 5, permissions: ['docs:read'] }), conflict)
    // Un slug de global en OTRO nivel no colisiona.
    await authz.defineScopedRole(admin, orgA, { slug: 'unit-editor', scopeType: 'organization', rank: 5, permissions: ['docs:read'] })
    // Local de un ancestro: orgA define lead@unit; el admin de unitA1 (un lead-admin local) no puede redefinirlo.
    const lead = await authz.defineScopedRole(admin, orgA, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
    await authz.defineScopedRole(admin, orgA, { slug: 'unit-admin', scopeType: 'unit', rank: 30, permissions: ['docs:write', 'docs:read'] })
    const unitAdmin = { type: 'users', uuid: uuidv7() }
    await (await authz.driver()).grant(unitAdmin, 'unit-admin', unitA1)
    await rejects(assert, () => authz.defineScopedRole(unitAdmin, unitA1, { slug: 'lead', scopeType: 'unit', rank: 10, permissions: ['docs:read'] }), conflict)
    // 3F · S3 (auditor N1): un local de un DESCENDIENTE ya NO colisiona — la
    // AUTORIDAD manda (global > local de un ancestro > local de un
    // descendiente). Hasta 3E, el admin de la unit le ocupaba el nombre al
    // DUEÑO del árbol con un `scribe@unit` cualquiera; ahora orgA define el
    // suyo y el del descendiente queda ENSOMBRECIDO, y se REPORTA.
    const squat = await authz.defineScopedRole(unitAdmin, unitA1, { slug: 'scribe', scopeType: 'unit', rank: 10, permissions: ['docs:read'] })
    const propio = await authz.defineScopedRole(admin, orgA, { slug: 'scribe', scopeType: 'unit', rank: 10, permissions: ['docs:write'] })
    assert.deepEqual(
      events.filter((e) => e.action === 'role_defined' && e.role.uuid === propio.uuid).map((e) => e.shadowedByAncestor?.map((r: any) => r.uuid)),
      [[squat.uuid]],
      'el evento dice a quién acaba de ensombrecer'
    )
    // Dentro del subárbol del ocupante el slug es AMBIGUO (fail-closed, M1) y
    // se opera por { uuid }; fuera, el rol del dueño responde por su nombre.
    await rejects(assert, () => authz.grant(admin, 'scribe', unitA1), { status: 422, code: 'E_AUTHZ_AMBIGUOUS_ROLE' })
    await authz.grant(admin, { uuid: propio.uuid }, unitA1)
    assert.isTrue(await authz.authorize(admin, 'docs:write', unitA1))
    // Y hacia ARRIBA no se ensombrece a nadie: el ocupante no puede volver a
    // definirlo (su ancestro ya lo tiene) ni tocar el del ancestro.
    await rejects(assert, () => authz.defineScopedRole(unitAdmin, unitA1, { slug: 'scribe', scopeType: 'unit', rank: 9, permissions: ['docs:read'] }), conflict)
    // Hermanas: orgB define su propio lead@unit.
    const leadB = await authz.defineScopedRole(adminB, orgB, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:read'] })
    assert.notEqual(leadB.uuid, lead.uuid)
    assert.lengthOf((await new CatalogCache().view()).rolesNamed('lead', 'unit'), 2)
    assert.lengthOf((await new CatalogCache().view()).rolesNamed('scribe', 'unit'), 2, 'el del ancestro y el ensombrecido')
    // 3E · P1 b: el SYNC ya no colisiona — los globales GANAN. Escribe el
    // global, reporta los locales ensombrecidos y sigue (el resto del deploy
    // entra). El tenant que ocupó el nombre se perjudica solo a sí mismo:
    // desde ya su slug es 422 AMBIGUO en su cadena y le queda `{ uuid }`.
    const report = await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [
        { slug: 'lead', scopeType: 'unit', permissions: ['docs:read'] },
        { slug: 'rol-del-deploy', scopeType: 'organization', permissions: ['docs:read'] },
      ],
    })
    assert.deepEqual(
      report.shadowedByGlobal.map((r) => `${r.slug}@${r.scopeType}:${r.owner}`).sort(),
      [`lead@unit:organization|${orgA.uuid}`, `lead@unit:organization|${orgB.uuid}`]
    )
    const conGlobal = await new CatalogCache().view()
    assert.isNotNull(conGlobal.role('lead', 'unit'), 'el global entró')
    assert.isNotNull(conGlobal.role('rol-del-deploy', 'organization'), 'y el resto del deploy también')
    assert.isNotNull(conGlobal.roleByUuid(lead.uuid), 'el local sigue en la base')
    // Y ahora ese slug es AMBIGUO en la cadena de su owner (fail-closed, M1).
    const ambiguo = await rejects(assert, () => authz.grant(admin, 'lead', unitA1), { status: 422, code: 'E_AUTHZ_AMBIGUOUS_ROLE' })
    // 3E · Q1: el mensaje ya no aconseja lo IMPOSIBLE (la API prohíbe
    // renombrar un rol local); dice la salida real: `{ uuid }` para seguir
    // operando y purgar uno para deshacer la ambigüedad.
    assert.notInclude(ambiguo.message, 'renombra uno de ellos', 'la API no deja renombrar: aconsejarlo era mandar al llamante a un 422')
    assert.include(ambiguo.message, 'no se renombra')
    assert.include(ambiguo.message, 'PURGAR')
    assert.include(ambiguo.message, '{ uuid }')
    // Y desde 3F · S3 tampoco puede mandar al operador a buscar un exit ≠ 0
    // que ya no va a salir: un homónimo ensombrecido por autoridad NO es
    // deriva para `authz:catalog:diff` (se lista y sale 0).
    assert.notInclude(ambiguo.message, 'como deriva', 'el diff ya no cuenta como deriva lo ensombrecido por autoridad')
    // 3E · Q2: solo se nombran los homónimos VISIBLES en la cadena preguntada
    // (el global y el de orgA). El de orgB no está en esta cadena: su uuid no
    // puede salir en un 422 que el tenant A recibe tal cual.
    assert.include(ambiguo.message, lead.uuid)
    assert.notInclude(ambiguo.message, leadB.uuid, 'el 422 no enumera el rol de la organización hermana')
    assert.notInclude(ambiguo.message, orgB.uuid!)
    // Y la ruta por `{ uuid }` tampoco es una sonda del catálogo ajeno: con el
    // uuid de un rol de orgB, el 422 no devuelve su slug ni su owner.
    const sonda = await rejects(assert, () => authz.grant(admin, { uuid: leadB.uuid }, unitA1), { status: 422, code: 'E_AUTHZ_ROLE_NOT_VISIBLE' })
    assert.notInclude(sonda.message, orgB.uuid!, 'el uuid de un rol ajeno no revela su owner')
    assert.notInclude(sonda.message, "'lead'", 'ni su slug')
    await authz.grant(admin, { uuid: lead.uuid }, unitA1)
    assert.isTrue(await authz.authorize(admin, 'docs:write', unitA1))
  })

  test('3G · W3 (auditor P3′): ENSOMBRECER exige rango, no solo posición — un actor de rank bajo en un ancestro ya NO puede inutilizar por slug el rol de más rango de un descendiente (422 E_AUTHZ_RANK_EXCEEDED sin escribir y sin nombrar el rank ajeno); con rango suficiente sí, el ensombrecido sigue vivo por { uuid }, y updateScopedRole exige lo mismo', async ({
    assert,
  }) => {
    // La autoridad de 3F · S3 era solo POSICIÓN: un rank 3 en la
    // organization dejaba `critico@unit` (rank 40, de una unit) en 422
    // AMBIGUOUS_ROLE para toda su cadena —y la víctima no podía repararlo,
    // porque su rango se mide en la cadena del owner del rol que
    // ensombrece—. Regla uniforme: sobre un rol solo actúa quien lo supera
    // en rango, también para ensombrecerlo.
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const authz = localManager()
    const holder = { type: 'users', uuid: uuidv7() }
    const otro = { type: 'users', uuid: uuidv7() }
    const pobre = { type: 'users', uuid: uuidv7() }
    await (await authz.driver()).grant(pobre, 'org-editor', orgA) // rank 10 en la ORG
    const critico = await authz.defineScopedRole(admin, unitA1, { slug: 'critico', scopeType: 'unit', rank: 40, permissions: ['docs:read'] })
    await authz.grant(holder, { uuid: critico.uuid }, unitA1)
    assert.isTrue(await authz.authorize(holder, 'docs:read', unitA1))

    const flojo = await rejects(
      assert,
      () => authz.defineScopedRole(pobre, orgA, { slug: 'critico', scopeType: 'unit', rank: 5, permissions: ['docs:read'] }),
      { status: 422, code: 'E_AUTHZ_RANK_EXCEEDED' }
    )
    assert.notInclude(String(flojo.message), '40', 'el 422 no es una sonda del catálogo de abajo: no dice el rank del ensombrecido')
    assert.notInclude(String(flojo.message), unitA1.uuid!, 'ni su owner')
    assert.lengthOf((await new CatalogCache().view()).rolesNamed('critico', 'unit'), 1, 'no se escribió nada')
    assert.isTrue(await authz.hasRole(holder, 'critico', unitA1), 'el slug del descendiente sigue vivo y sin ambigüedad')

    // Con rango suficiente, la autoridad del ancestro sigue intacta (S3).
    const sombra = await authz.defineScopedRole(admin, orgA, { slug: 'critico', scopeType: 'unit', rank: 30, permissions: ['docs:write'] })
    assert.deepEqual(
      events.filter((e) => e.action === 'role_defined' && e.role.uuid === sombra.uuid).map((e) => e.shadowedByAncestor?.map((r: any) => r.uuid)),
      [[critico.uuid]]
    )
    // El ensombrecido no pierde nada: sigue concediendo y se opera por uuid.
    await rejects(assert, () => authz.hasRole(holder, 'critico', unitA1), { status: 422, code: 'E_AUTHZ_AMBIGUOUS_ROLE' })
    assert.isTrue(await authz.authorize(holder, 'docs:read', unitA1), 'authorize no direcciona por slug')
    await authz.grant(otro, { uuid: critico.uuid }, unitA1)
    assert.isTrue(await authz.authorize(otro, 'docs:read', unitA1))

    // updateScopedRole exige lo mismo: `pobre` supera a la SOMBRA (rank 30 >
    // ... no: rank 10 no la supera) — con un rol de rank 5 sí la superaría,
    // así que se comprueba con uno que sí puede tocar la sombra pero no lo
    // que la sombra ensombrece.
    const critico2 = await authz.defineScopedRole(admin, unitA1x, { slug: 'critico2', scopeType: 'unit', rank: 40, permissions: ['docs:read'] })
    const sombraFloja = await authz.defineScopedRole(admin, orgA, { slug: 'critico2', scopeType: 'unit', rank: 2, permissions: ['docs:write'] })
    assert.isAbove(10, sombraFloja.rank, 'pobre (rank 10) supera a la sombra…')
    await rejects(assert, () => authz.updateScopedRole(pobre, sombraFloja.uuid, { name: 'renombrada' }), { status: 422, code: 'E_AUTHZ_RANK_EXCEEDED' })
    assert.isNotNull((await new CatalogCache().view()).roleByUuid(critico2.uuid))
    // …y quien SÍ supera al ensombrecido puede seguir editándola.
    const editada = await authz.updateScopedRole(admin, sombraFloja.uuid, { rank: 3 })
    assert.equal(editada.rank, 3)
  })

  test('3b-1 · D1 (auditor 3G): la reparación por ensombrecimiento exige superar el rango DEL SQUATTER — con ranks no monótonos (un rank 60 en la unit bajo un admin de rank 50) el DUEÑO del árbol no puede ni ensombrecer ni borrar, y el recurso es la PLATAFORMA', async ({
    assert,
  }) => {
    // X1 publicaba «la mina residual la repara autoridad + rango: un ancestro
    // con rango por encima define el suyo y lo ensombrece». El ancestro DUEÑO
    // del árbol puede no tener ese rango: `rank` es metadata del consumidor
    // (invariante 8) y nada obliga a que decrezca con la profundidad.
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const authz = localManager()
    const plataforma = { type: 'users', uuid: uuidv7() }
    const boss = { type: 'users', uuid: uuidv7() }
    const driver = await authz.driver()
    await driver.grant(plataforma, 'superadmin', APP_SCOPE) // rank 100, en toda cadena

    // La plataforma le da a la unit una capa de rank 60, POR ENCIMA del
    // rank 50 del org-admin que es dueño del árbol.
    const unitBoss = await authz.defineScopedRole(plataforma, unitA1, { slug: 'unit-boss', scopeType: 'unit', rank: 60, permissions: ['docs:read'] })
    await authz.grant(boss, { uuid: unitBoss.uuid }, unitA1)
    // …y el actor de la unit ocupa el nombre con un rank 59.
    const mina = await authz.defineScopedRole(boss, unitA1, { slug: 'mina', scopeType: 'unit', rank: 59, permissions: ['docs:read'] })

    // Las dos vías que el paquete publica para el dueño del árbol: las dos 422.
    await rejects(
      assert,
      () => authz.defineScopedRole(admin, orgA, { slug: 'mina', scopeType: 'unit', rank: 40, permissions: ['docs:read'] }),
      { status: 422, code: 'E_AUTHZ_RANK_EXCEEDED' }
    )
    await rejects(assert, () => authz.deleteScopedRole(admin, mina.uuid), { status: 422, code: 'E_AUTHZ_RANK_EXCEEDED' })
    assert.isNotNull((await new CatalogCache().view()).roleByUuid(mina.uuid), 'nada se escribió')
    // Y `scopes.detached` ya no es una tercera vía: desde 3b-0 · Z1 purga
    // HECHOS y no mira el catálogo, así que el rol sobrevive igual.
    await authz.scopes.detached(unitA1, { actor: admin })
    assert.isNotNull((await new CatalogCache().view()).roleByUuid(mina.uuid), 'detached no toca el catálogo')

    // El recurso es la PLATAFORMA, y siempre lo tiene: `#assertRank` acota
    // todo rank local por debajo del techo global, así que quien lleva el
    // rol global de mayor rank supera a cualquier squatter.
    const sombra = await authz.defineScopedRole(plataforma, orgA, { slug: 'mina', scopeType: 'unit', rank: 60, permissions: ['docs:read'] })
    assert.deepEqual(
      events.filter((e) => e.action === 'role_defined' && e.role.uuid === sombra.uuid).map((e) => e.shadowedByAncestor?.map((r: any) => r.uuid)),
      [[mina.uuid]]
    )
    // …o la purga de plataforma, la salida documentada de todas las barreras.
    await driver.purgeRole!(mina.uuid)
    assert.isNull((await new CatalogCache().view()).roleByUuid(mina.uuid))
  })

  test('3b-1 · D2 (auditor 3G): la VENTANA de W3 está documentada, no cerrada — con resolveChain(owner de la víctima) === null en ese instante #shadowedBelow no ve la sombra y el define entra; al volver el árbol la sombra es permanente y la víctima no la repara (sí el dueño del árbol). El mismo atacante consigue lo mismo YENDO PRIMERO, sin trampa', async ({
    assert,
  }) => {
    // Decisión de 3b-1: NO se rechaza. Desde 3b-0 un rol cuyo owner no
    // resuelve está DORMIDO y se barre con `prune-orphans`; rechazar aquí
    // convertiría un rol dormido en un BLOQUEO de slug, que es justo lo que
    // Z1 quitó. Se documenta la ventana y se fija con este caso.
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const oculto = new Set<string>()
    const resolver = async (scope: any) =>
      oculto.has(`${scope.type}|${scope.uuid ?? ''}`) ? null : tree.chainOf(scope)
    const authz = localManager({
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain: resolver }) },
      scopes: { resolveChain: resolver, descendantsOf: descendantsFrom(tree) },
    })
    const plataforma = { type: 'users', uuid: uuidv7() }
    const boss = { type: 'users', uuid: uuidv7() }
    const pobre = { type: 'users', uuid: uuidv7() }
    const holder = { type: 'users', uuid: uuidv7() }
    const driver = await authz.driver()
    await driver.grant(plataforma, 'superadmin', APP_SCOPE)
    await driver.grant(pobre, 'org-editor', orgA) // rank 10 en la ORG

    const unitBoss = await authz.defineScopedRole(plataforma, unitA1, { slug: 'unit-boss', scopeType: 'unit', rank: 60, permissions: ['docs:read'] })
    await authz.grant(boss, { uuid: unitBoss.uuid }, unitA1)
    const victima = await authz.defineScopedRole(boss, unitA1, { slug: 'critico', scopeType: 'unit', rank: 40, permissions: ['docs:read'] })
    await authz.grant(holder, { uuid: victima.uuid }, unitA1)

    // Control: con el árbol respondiendo, W3 funciona.
    await rejects(
      assert,
      () => authz.defineScopedRole(pobre, orgA, { slug: 'critico', scopeType: 'unit', rank: 5, permissions: ['docs:read'] }),
      { status: 422, code: 'E_AUTHZ_RANK_EXCEEDED' }
    )

    // La ventana: soft-delete, réplica atrasada, scope «pending»… El owner
    // de la víctima no resuelve EN ESE INSTANTE y la sombra no se demuestra.
    oculto.add(`unit|${unitA1.uuid}`)
    const sombra = await authz.defineScopedRole(pobre, orgA, { slug: 'critico', scopeType: 'unit', rank: 5, permissions: ['docs:read'] })
    oculto.delete(`unit|${unitA1.uuid}`)
    assert.equal(sombra.rank, 5, 'entra: «no demostrable» se trata como «no hay sombra»')
    assert.lengthOf((await new CatalogCache().view()).rolesNamed('critico', 'unit'), 2)

    // Con el árbol restaurado la sombra es real y permanente.
    await rejects(assert, () => authz.hasRole(holder, 'critico', unitA1), { status: 422, code: 'E_AUTHZ_AMBIGUOUS_ROLE' })
    assert.isTrue(await authz.authorize(holder, 'docs:read', unitA1), 'authorize no direcciona por slug: nadie pierde permisos')
    // La VÍCTIMA no la repara: su rango se mide en la cadena del owner de la
    // sombra (orgA), donde no vale nada — aunque en su unit sea rank 60.
    await rejects(assert, () => authz.deleteScopedRole(boss, sombra.uuid), { status: 422, code: 'E_AUTHZ_RANK_EXCEEDED' })
    // El dueño del árbol sí (rank 50 > 5): la ventana no deja un estado
    // irrecuperable, y el diff la enseña como `shadowedByAncestor`.
    const { diffAuthzCatalog } = await import('../src/catalog/catalog.js')
    const diff = await diffAuthzCatalog({ permissions: [], roles: [] } as any, { resolveChain: resolver })
    assert.deepEqual(
      diff.shadowedByAncestor.filter((d: any) => d.slug === 'critico'),
      [{ slug: 'critico', scopeType: 'unit', owner: `unit|${unitA1.uuid}`, shadowedBy: `organization|${orgA.uuid}` }]
    )
    await authz.deleteScopedRole(admin, sombra.uuid)
    assert.isTrue(await authz.hasRole(holder, 'critico', unitA1), 'reparada')

    // Y lo honesto: el mismo atacante consigue la MISMA denegación yendo
    // PRIMERO, con el árbol entero respondiendo. W3 solo protege a los roles
    // que YA existen; ocupar el nombre antes es gratis y siempre lo fue.
    await authz.defineScopedRole(pobre, orgA, { slug: 'antes', scopeType: 'unit', rank: 5, permissions: ['docs:read'] })
    await rejects(
      assert,
      () => authz.defineScopedRole(boss, unitA1, { slug: 'antes', scopeType: 'unit', rank: 40, permissions: ['docs:read'] }),
      { status: 422, code: 'E_AUTHZ_CATALOG_CONFLICT' }
    )
  })

  test('3b-1 · D3 (auditor 3G): «sobre un rol solo actúa quien lo supera en rango» es COMPROBACIÓN DE ESCRITURA, no un invariante — scopes.moved crea la sombra sin juzgar ningún rango, y el dueño del subárbol movido no puede repararla', async ({
    assert,
  }) => {
    const authz = localManager()
    const pobre = { type: 'users', uuid: uuidv7() }
    const holder = { type: 'users', uuid: uuidv7() }
    await (await authz.driver()).grant(pobre, 'org-editor', orgA) // rank 10 en orgA

    // `lejano@unit` rank 40 vive bajo orgB; `pobre` (rank 10 en orgA) define
    // su homónimo rank 5 en orgA. Legal y SIN sombra: unitB1 no cuelga de
    // orgA, así que #shadowedBelow no encuentra nada que ensombrecer.
    const lejano = await authz.defineScopedRole(adminB, unitB1, { slug: 'lejano', scopeType: 'unit', rank: 40, permissions: ['docs:read'] })
    await authz.grant(holder, { uuid: lejano.uuid }, unitB1)
    const sombra = await authz.defineScopedRole(pobre, orgA, { slug: 'lejano', scopeType: 'unit', rank: 5, permissions: ['docs:read'] })
    assert.isTrue(await authz.hasRole(holder, 'lejano', unitB1), 'antes del move el slug es de uno solo')

    // El consumidor mueve unitB1 de orgB a orgA (función normal de producto)
    // y lo notifica. Ningún rango se comprueba: `moved` no juzga el catálogo.
    await tree.move(unitB1, orgA)
    await authz.scopes.moved(unitB1, orgA, { actor: admin })
    await rejects(assert, () => authz.hasRole(holder, 'lejano', unitB1), { status: 422, code: 'E_AUTHZ_AMBIGUOUS_ROLE' })
    await rejects(assert, () => authz.grant(holder, 'lejano', unitB1), { status: 422, code: 'E_AUTHZ_AMBIGUOUS_ROLE' })
    assert.isTrue(await authz.authorize(holder, 'docs:read', unitB1), 'nadie pierde permisos: authorize no direcciona por slug')

    // Y el dueño del subárbol movido no la repara: su rango (50 en orgB) se
    // mide en la cadena del owner de la SOMBRA (orgA), donde vale 0.
    await rejects(assert, () => authz.deleteScopedRole(adminB, sombra.uuid), { status: 422, code: 'E_AUTHZ_RANK_EXCEEDED' })
    // La sombra apareció sin juicio de rango, pero es RUIDOSA.
    const { diffAuthzCatalog } = await import('../src/catalog/catalog.js')
    const diff = await diffAuthzCatalog({ permissions: [], roles: [] } as any, { resolveChain: resolveChainFrom(tree) })
    assert.deepEqual(
      diff.shadowedByAncestor.filter((d: any) => d.slug === 'lejano'),
      [{ slug: 'lejano', scopeType: 'unit', owner: `unit|${unitB1.uuid}`, shadowedBy: `organization|${orgA.uuid}` }]
    )
  })

  test('3b-0 · Z1: scopes.detached purga los HECHOS del scope —con la identidad CANÓNICA, un alias del uuid incluido— y NO toca el catálogo: los roles locales del owner y los del subárbol sobreviven DORMIDOS, sin policy de rango que medir ni subárbol que enumerar; ningún actor los destruye por esta vía', async ({
    assert,
  }) => {
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    // Un árbol de consumidor que funde el alias con la fila (el tipo `uuid`
    // de PostgreSQL) y responde SIEMPRE la identidad canónica, como el
    // puerto exige (invariante 17).
    const fused = (scope: ScopeRef) => `${scope.type}\u001f${(scope.uuid ?? '').replaceAll('-', '')}`
    const rows = new Map<string, { self: ScopeRef; parent: ScopeRef }>([
      [fused(orgA), { self: orgA, parent: APP_SCOPE }],
      [fused(unitA1), { self: unitA1, parent: orgA }],
      [fused(unitA1x), { self: unitA1x, parent: unitA1 }],
    ])
    const chainOf = async (scope: ScopeRef): Promise<ScopeRef[] | null> => {
      const chain: ScopeRef[] = []
      let current = scope
      for (let depth = 0; depth < 10; depth++) {
        if (current.type === 'app') return [...chain, APP_SCOPE]
        const row = rows.get(fused(current))
        if (!row) return null
        chain.push(row.self)
        current = row.parent
      }
      return null
    }
    const below = async (scope: ScopeRef): Promise<ScopeRef[] | null> => {
      const canonical = rows.get(fused(scope))?.self
      if (!canonical) return null
      const result: ScopeRef[] = []
      for (const row of rows.values()) {
        if (fused(row.self) === fused(canonical)) continue
        const chain = await chainOf(row.self)
        if (chain?.some((s) => s.type === canonical.type && s.uuid === canonical.uuid)) result.push(row.self)
      }
      return result
    }
    const authz = localManager({
      requireActor: true,
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain: chainOf }) },
      scopes: { resolveChain: chainOf, descendantsOf: below },
    })
    const caro = await authz.defineScopedRole(admin, unitA1, { slug: 'caro', scopeType: 'unit', rank: 40, permissions: ['docs:write'] }, { actor: admin })
    const nieto = await authz.defineScopedRole(admin, unitA1x, { slug: 'nieto', scopeType: 'unit', rank: 6, permissions: ['docs:read'] }, { actor: admin })
    const holder = { type: 'users', uuid: uuidv7() }
    await authz.grant(holder, { uuid: caro.uuid }, unitA1, { actor: admin })
    await authz.grant(holder, { uuid: nieto.uuid }, unitA1x, { actor: admin })
    await authz.deny(holder, 'docs:read', unitA1, { actor: admin })
    assert.isTrue(await authz.authorize(holder, 'docs:write', unitA1))

    // El `detached` con el uuid SIN GUIONES y con un actor de rank 0: el
    // rango ya no pinta nada aquí (purgar hechos lo gobierna `within`, como
    // en las otras ocho escrituras) y la identidad de los hechos es la
    // CANÓNICA, así que el alias purga de verdad.
    const forastero = { type: 'users', uuid: uuidv7() }
    const alias: ScopeRef = { type: 'unit', uuid: unitA1.uuid!.replaceAll('-', '') }
    assert.notEqual(alias.uuid, unitA1.uuid)
    assert.isUndefined(await authz.scopes.detached(alias, { actor: forastero }), 'no devuelve nada que declarar a medias')
    assert.isFalse(await authz.authorize(holder, 'docs:write', unitA1), 'los hechos del scope, purgados por el alias')
    assert.deepEqual(await (await authz.driver()).listDenies!(holder), [], 'los denies también')
    assert.isTrue(await authz.authorize(holder, 'docs:read', unitA1x), 'y el hecho del nieto, intacto: la purga es quirúrgica')

    // El CATÁLOGO no se toca: ni el rol del scope, ni el del subárbol
    // (`descendantsOf` está declarado y ya no se llama para esto).
    const vista = await new CatalogCache().view()
    assert.isNotNull(vista.roleByUuid(caro.uuid), 'el rol del owner sobrevive: el árbol no escribe el catálogo')
    assert.isNotNull(vista.roleByUuid(nieto.uuid), 'ni el del subárbol')
    assert.isEmpty(events.filter((e) => e.action === 'role_purged'), 'ninguna purga de rol se notificó')

    // Y sigue siendo el mismo rol de siempre mientras su owner esté en el
    // árbol: se puede volver a asignar y concede.
    await authz.grant(holder, { uuid: caro.uuid }, unitA1, { actor: admin })
    assert.isTrue(await authz.authorize(holder, 'docs:write', unitA1))
  })

  test('3b-0 · Z2: pruneOrphanRoles (authz:catalog:prune-orphans) lista los roles locales cuyo owner ya no resuelve y solo borra con force; lee la BASE y no el memo con ventana; notifica role_purged sin actor y en orden estable; los roles con owner vivo no se tocan', async ({
    assert,
  }) => {
    const { CatalogCache, withAuthzCatalogWrite } = await import('../src/catalog/catalog_cache.js')
    const authz = localManager()
    const holder = { type: 'users', uuid: uuidv7() }
    const caro = await authz.defineScopedRole(admin, unitA1, { slug: 'caro', scopeType: 'unit', rank: 40, permissions: ['docs:write'] })
    const nieto = await authz.defineScopedRole(admin, unitA1x, { slug: 'nieto', scopeType: 'unit', rank: 6, permissions: ['docs:read'] })
    const deOrg = await authz.defineScopedRole(admin, orgA, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:read'] })
    await authz.grant(holder, { uuid: caro.uuid }, unitA1)

    // Con todo el árbol en pie no hay ningún huérfano.
    assert.deepEqual((await authz.pruneOrphanRoles()).orphans, [], 'todos los owners resuelven')
    // Y sin árbol NO se barre: sin `resolveChain` solo existe la raíz, así que
    // TODO owner local «no resolvería» y la pasada se llevaría el catálogo
    // local entero. 500 antes de leer nada.
    const sinArbol = localManager({ scopes: undefined })
    await rejects(assert, () => sinArbol.pruneOrphanRoles({ force: true }), { status: 500, code: 'E_AUTHZ_CONFIG' })

    // El consumidor borra la rama y notifica: los hechos se van, los roles
    // quedan DORMIDOS (su owner ya no está en ninguna cadena).
    await authz.scopes.detached(unitA1)
    await tree.detach(unitA1)
    assert.isFalse(await authz.authorize(holder, 'docs:write', unitA1))
    // `deleteScopedRole` no alcanza a un rol sin owner (lo resuelve en
    // fresco): esa es la razón de ser del comando.
    await rejects(assert, () => authz.deleteScopedRole(admin, caro.uuid), { status: 422, code: 'E_AUTHZ_UNKNOWN_SCOPE' })

    // A2 bis: un rol que OTRO proceso confirmó mientras este tenía el memo
    // en ventana (`everyMs`) también sale: la lista viene de la BASE.
    const stale = localManager({ drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree), catalogRevalidate: { everyMs: 120_000 } }) } })
    await stale.authorize(admin, 'docs:read', orgA) // calienta la foto SIN el rol nuevo
    const tardio = uuidv7()
    await withAuthzCatalogWrite(async (trx) => {
      const perm: any = (await trx.from('authz_permissions').where('slug', 'docs:read').select('uuid'))[0]
      const now = new Date()
      await trx.table('authz_roles').insert({ uuid: tardio, slug: 'tardio', name: 'tardio', scope_type: 'unit', rank: 5, owner_scope_key: `unit|${unitA1x.uuid}`, created_at: now, updated_at: now })
      await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: tardio, permission_uuid: perm.uuid, created_at: now })
    })

    // `--dry-run` (el default): lista y NO escribe.
    const seco = await stale.pruneOrphanRoles()
    assert.isTrue(seco.dryRun)
    assert.deepEqual(seco.purged, [])
    assert.deepEqual(seco.skipped, [])
    assert.deepEqual(seco.orphans.map((o) => o.role.slug).sort(), ['caro', 'nieto', 'tardio'], 'la purga lee la base, no la foto')
    assert.deepEqual(seco.orphans.map((o) => `${o.owner.type}:${o.owner.uuid}`).sort(), [`unit:${unitA1.uuid}`, `unit:${unitA1x.uuid}`, `unit:${unitA1x.uuid}`].sort(), 'cada uno con SU owner')
    assert.isNotNull((await new CatalogCache().view()).roleByUuid(caro.uuid), 'el default no borra nada')
    assert.isEmpty(events.filter((e) => e.action === 'role_purged'))

    // `--force`: purga, notifica y libera el (slug, nivel). Aquí 3 de los 4
    // roles locales están huérfanos (>50 %), así que la cota de purga masiva
    // (3b-0b · AA2) pide la bandera explícita: es una poda real, no un
    // resolutor ciego, y quien la corre lo dice.
    assert.isTrue(seco.massPurge, '3 de 4 roles locales: la pasada tiene la firma de una purga masiva')
    await rejects(assert, () => stale.pruneOrphanRoles({ force: true }), { status: 500, code: 'E_AUTHZ_MASS_PURGE_REFUSED' })
    assert.isNotNull((await new CatalogCache().view()).roleByUuid(caro.uuid), 'el rechazo no borra nada')
    assert.isEmpty(events.filter((e) => e.action === 'role_purged'), 'ni notifica')
    const purga = await stale.pruneOrphanRoles({ force: true, allowMassPurge: true })
    assert.deepEqual({ dryRun: purga.dryRun, purged: purga.purged.map((r: any) => r.slug).sort() }, { dryRun: false, purged: ['caro', 'nieto', 'tardio'] })
    assert.deepEqual(purga.skipped, [], 'ningún owner volvió durante la pasada')
    const vista = await new CatalogCache().view()
    assert.isNull(vista.roleByUuid(caro.uuid))
    assert.isNull(vista.roleByUuid(nieto.uuid))
    assert.isNull(vista.roleByUuid(tardio))
    assert.deepEqual(vista.rolesNamed('caro', 'unit'), [], 'ese (slug, nivel) vuelve a estar libre')
    assert.isNotNull(vista.roleByUuid(deOrg.uuid), 'el rol de la organization, que sigue en el árbol, no se toca')
    // El evento es de PLATAFORMA: sin actor, con el owner de cada rol y en
    // orden estable por uuid (3F · U5: el mismo en los tres motores).
    const purgados = events.filter((e) => e.action === 'role_purged')
    assert.deepEqual(purgados.map((e) => e.role.slug).sort(), ['caro', 'nieto', 'tardio'])
    assert.deepEqual(purgados.map((e) => e.actor), [undefined, undefined, undefined], 'nadie firma una purga de plataforma')
    assert.deepEqual(
      purgados.filter((e) => e.role.slug === 'nieto').map((e) => `${e.owner.type}:${e.owner.uuid}`),
      [`unit:${unitA1x.uuid}`],
      'el evento del nieto lleva SU owner'
    )
    const uuids = purgados.map((e) => e.role.uuid)
    assert.deepEqual(uuids, [...uuids].sort(), 'el orden de role_purged se reproduce igual en los tres motores')
    // Y el (slug, nivel) libre: un global del deploy entra sin ensombrecer a nadie.
    const report = await syncAuthzCatalog({ permissions: [{ slug: 'docs:read' }], roles: [{ slug: 'nieto', scopeType: 'unit', permissions: ['docs:read'] }] })
    assert.deepEqual(report.shadowedByGlobal, [])
    // Segunda pasada: idempotente (y sin huérfanos ya no hay purga masiva
    // que rechazar).
    assert.deepEqual((await stale.pruneOrphanRoles({ force: true })).purged, [])
  })

  test("3b-0b · AA1 (auditor 3b-0): «dormido» = no visible desde ningún scope vivo cuya cadena NO pase por el owner — con un descendiente vivo el rol CONCEDE, es membresía por los seis caminos y SE PUEDE ASIGNAR; el barrido lo marca (stillGranting + assignments) y un huérfano sin hechos no concede nada", async ({
    assert,
  }) => {
    // La frase publicada en 3b-0 («un rol dormido no concede, no es membresía
    // y no se puede asignar») era FALSA y era la justificación escrita de
    // purgar sin actor y sin rango. Este caso fija los DOS lados: el árbol
    // del consumidor borra la fila del owner pero el descendiente conserva su
    // ruta materializada por él (borrado en dos pasos: lo normal).
    const chains = new Map<string, ScopeRef[]>([
      [`organization|${orgA.uuid}`, [orgA, APP_SCOPE]],
      [`unit|${unitA1.uuid}`, [unitA1, orgA, APP_SCOPE]],
      [`unit|${unitA1x.uuid}`, [unitA1x, unitA1, orgA, APP_SCOPE]],
    ])
    const resolveChain = async (scope: ScopeRef) =>
      scope.type === 'app' ? [APP_SCOPE] : (chains.get(`${scope.type}|${scope.uuid}`) ?? null)
    const descendantsOf = async (scope: ScopeRef) =>
      [...chains.values()]
        .filter((chain) => chain.slice(1).some((s) => s.type === scope.type && s.uuid === scope.uuid))
        .map((chain) => chain[0])
    const authz = localManager({
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain }) },
      scopes: { resolveChain, descendantsOf },
    })
    const holder = { type: 'users', uuid: uuidv7() }
    const otro = { type: 'users', uuid: uuidv7() }
    const lead = await authz.defineScopedRole(admin, unitA1, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
    const mudo = await authz.defineScopedRole(admin, unitA1, { slug: 'mudo', scopeType: 'unit', rank: 19, permissions: ['docs:read'] })
    await authz.grant(holder, { uuid: lead.uuid }, unitA1x)
    assert.isTrue(await authz.authorize(holder, 'docs:write', unitA1x))

    // El owner desaparece del árbol; el NIETO sigue vivo con el owner en su
    // cadena. El rol está "dormido" y sin embargo:
    chains.delete(`unit|${unitA1.uuid}`)
    assert.isNull(await resolveChain(unitA1), 'el owner ya no resuelve')
    assert.isTrue(await authz.authorize(holder, 'docs:write', unitA1x), 'CONCEDE')
    assert.isTrue(await authz.hasRole(holder, { uuid: lead.uuid } as any, unitA1x), 'es membresía por uuid')
    assert.isTrue(await authz.hasRole(holder, { slug: 'lead', scopeType: 'unit' } as any, unitA1x), 'y por slug')
    assert.deepEqual(await authz.listRoles(holder, unitA1x), ['lead'])
    assert.deepEqual(await authz.effectivePermissions(holder, unitA1x), ['docs:write'])
    assert.lengthOf(await authz.listSubjects({ uuid: lead.uuid } as any, unitA1x), 1)
    assert.deepEqual(await authz.authorizedScopes(holder, 'docs:write', 'unit'), { kind: 'some', scopes: [unitA1x] })
    // Y SE PUEDE ASIGNAR, por uuid y por slug.
    await authz.grant(otro, { uuid: lead.uuid }, unitA1x)
    await authz.grant(otro, { slug: 'lead', scopeType: 'unit' } as any, unitA1x)
    assert.isTrue(await authz.authorize(otro, 'docs:write', unitA1x))

    // Por eso el barrido MARCA lo que todavía concede en vez de suponer que
    // no existe: `stillGranting` cuenta hechos vigentes (conservador).
    const seco = await authz.pruneOrphanRoles()
    assert.deepEqual(
      seco.orphans.map((o: any) => ({ slug: o.role.slug, assignments: o.assignments, stillGranting: o.stillGranting })).sort((a: any, b: any) => a.slug.localeCompare(b.slug)),
      [
        { slug: 'lead', assignments: 2, stillGranting: true },
        { slug: 'mudo', assignments: 0, stillGranting: false },
      ],
      'el huérfano con hechos vivos se distingue del inerte'
    )

    // El otro lado: sin ningún scope vivo cuya cadena pase por el owner, el
    // rol no concede en ninguna parte — que es lo que la frase quería decir.
    chains.delete(`unit|${unitA1x.uuid}`)
    assert.isFalse(await authz.authorize(holder, 'docs:write', unitA1x))
    assert.isFalse(await authz.hasRole(holder, { uuid: lead.uuid } as any, unitA1x))
    assert.deepEqual(await authz.listRoles(holder, unitA1x), [])
    // Y un huérfano sin hechos no concedía nada ni antes ni ahora.
    assert.isFalse(await authz.authorize(holder, 'docs:read', unitA1x))
  })

  test("3b-2j: un driver SIN countRoleAssignments deja stillGranting (y assignments) en `undefined`, JAMÁS en `false` — «no lo sé» no puede degradar a «no concede» justo antes de un borrado destructivo", async ({
    assert,
  }) => {
    // Decisión del dueño del 2026-08-31 (3), consecuencia 1. El campo nació
    // (3b-0b · AA1) para avisar de que una purga puede estar revocando
    // permisos VIVOS, y su contrato publicado dice «falso ⇒ no concede
    // SEGURO». Un driver de terceros escrito para 2.2 —o el `openfga` en modo
    // `resolver`— no trae el método nuevo del puerto: entonces el barrido no
    // lo sabe, y decirlo con `false` es exactamente el fail-dangerous que el
    // lote 2i midió (los hechos del driver `openfga` no viven en
    // `authz_assignments`, así que contarlas ahí decía `false` sobre un rol
    // que concedía).
    const chains = new Map<string, ScopeRef[]>([
      [`organization|${orgA.uuid}`, [orgA, APP_SCOPE]],
      [`unit|${unitA1.uuid}`, [unitA1, orgA, APP_SCOPE]],
      [`unit|${unitA1x.uuid}`, [unitA1x, unitA1, orgA, APP_SCOPE]],
    ])
    const resolveChain = async (scope: ScopeRef) =>
      scope.type === 'app' ? [APP_SCOPE] : (chains.get(`${scope.type}|${scope.uuid}`) ?? null)
    const real = new DatabaseAuthorizationDriver({ resolveChain })
    // El driver de terceros: trae `purgeRole` (si no, `pruneOrphanRoles` es
    // 500 antes de leer nada) y NO trae el método nuevo.
    const tercero: any = Object.create(real)
    Object.defineProperty(tercero, 'countRoleAssignments', { value: undefined, enumerable: false })
    const authz = localManager({
      drivers: { database: () => tercero },
      scopes: { resolveChain },
    })
    const holder = { type: 'users', uuid: uuidv7() }
    const lead = await authz.defineScopedRole(admin, unitA1, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
    await authz.grant(holder, { uuid: lead.uuid }, unitA1x)
    assert.isTrue(await authz.authorize(holder, 'docs:write', unitA1x), 'el rol concede HOY')

    chains.delete(`unit|${unitA1.uuid}`)
    const seco = await authz.pruneOrphanRoles()
    assert.deepEqual(seco.orphans.map((o: any) => o.role.uuid), [lead.uuid])
    const [huerfano] = seco.orphans as any[]
    assert.isUndefined(huerfano.stillGranting, 'sin el método del puerto no se sabe: undefined')
    assert.notStrictEqual(huerfano.stillGranting, false, '«no lo sé» NUNCA es «no concede»')
    assert.isUndefined(huerfano.assignments, 'y el contador que lo respalda tampoco se inventa')
    // Y el rol SIGUE concediendo mientras el nieto conserve al owner en su
    // cadena: el `false` de antes era falso, no conservador.
    assert.isTrue(await authz.authorize(holder, 'docs:write', unitA1x))
  })

  test('3b-0b · AA2 (auditor 3b-0): la cota de purga masiva — un resolutor ciego (todos los owners huérfanos) es 500 E_AUTHZ_MASS_PURGE_REFUSED sin borrar nada; con allowMassPurge purga; un ratio bajo purga sin bandera', async ({
    assert,
  }) => {
    // El peligro medido no es que alguien llame al método a mano: es un
    // `resolveChain` filtrado por el tenant de la petición —patrón normal en
    // multi-tenant— o sin contexto (comando, réplica atrasada). Devuelve
    // `null` para todo, así que TODO rol local parece huérfano y una pasada
    // con `--force` se lleva el catálogo local de todos los tenants.
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    let ciego = false
    const resolveChain = async (scope: ScopeRef) => (ciego ? null : resolveChainFrom(tree)(scope))
    const authz = localManager({
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain }) },
      scopes: { resolveChain },
      requireActor: true,
      requireWithin: true,
    })
    const deA1 = await authz.defineScopedRole(admin, unitA1, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] }, { actor: admin, within: orgA })
    const deOrg = await authz.defineScopedRole(admin, orgA, { slug: 'jefe', scopeType: 'unit', rank: 21, permissions: ['docs:read'] }, { actor: admin, within: orgA })
    const deB = await authz.defineScopedRole(adminB, unitB1, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:read'] }, { actor: adminB, within: orgB })

    // Ratio bajo: 1 huérfano de 3 roles locales, 1 owner de 3 ⇒ pasa sin
    // bandera. La cota no estorba al barrido legítimo.
    await tree.detach(unitA1)
    const baja = await authz.pruneOrphanRoles()
    assert.isFalse(baja.massPurge)
    assert.deepEqual((await authz.pruneOrphanRoles({ force: true })).purged.map((r: any) => r.uuid), [deA1.uuid])

    // Resolutor ciego: 2 de 2 roles y 2 de 2 owners. Es la firma exacta del
    // accidente, y con `requireActor`/`requireWithin` puestos el método sigue
    // sin exigir actor ni within (es API de PLATAFORMA): la cota es la única
    // barrera, y para.
    ciego = true
    const dry = await authz.pruneOrphanRoles()
    assert.isTrue(dry.massPurge, 'el dry-run no lanza —es el diagnóstico— pero lo marca')
    assert.lengthOf(dry.orphans, 2)
    const error = await rejects(assert, () => authz.pruneOrphanRoles({ force: true }), { status: 500, code: 'E_AUTHZ_MASS_PURGE_REFUSED' })
    assert.include(String(error.message), '2 de 2 roles locales', 'el mensaje nombra el ratio')
    const vista = await new CatalogCache().view()
    assert.isNotNull(vista.roleByUuid(deOrg.uuid), 'no se borró nada')
    assert.isNotNull(vista.roleByUuid(deB.uuid), 'ni el catálogo local del otro tenant')
    assert.deepEqual(
      events.filter((e) => e.action === 'role_purged').map((e: any) => e.role.uuid),
      [deA1.uuid],
      'el rechazo no notifica: el único role_purged es el de la poda legítima de antes'
    )

    // Con la bandera —decisión humana— sí purga: la cota avisa, no prohíbe.
    const masiva = await authz.pruneOrphanRoles({ force: true, allowMassPurge: true })
    assert.deepEqual(masiva.purged.map((r: any) => r.uuid).sort(), [deOrg.uuid, deB.uuid].sort())
  })

  test('3b-1b (tester · AB3): una pasada de pruneOrphanRoles que falla A MITAD deja lo anterior BORRADO — el error lo nombra (PruneInterruptedError.purged) sin filtrar el del driver, y la siguiente pasada recoge el resto', async ({
    assert,
  }) => {
    // El CHANGELOG justifica `purged: CatalogRoleRef[]` con «si un purgeRole
    // falla a mitad, los anteriores ya están borrados … quien recoge el error
    // necesita saber CUÁLES se fueron». Por ese camino el valor de retorno no
    // llega a producirse, así que la lista viaja EN el error
    // (`PruneInterruptedError.purged`) y además en el hilo de auditoría: las
    // dos fuentes tienen que nombrar EXACTAMENTE lo mismo, ni uno más.
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    let ciego = false
    const resolveChain = async (scope: ScopeRef) => (ciego ? null : resolveChainFrom(tree)(scope))
    let rompe = false
    let intentos = 0
    const authz = localManager({
      drivers: {
        database: () => {
          const driver: any = new DatabaseAuthorizationDriver({ resolveChain })
          const real = driver.purgeRole.bind(driver)
          driver.purgeRole = async (uuid: string) => {
            intentos += 1
            if (rompe && intentos === 2) throw new Error('el motor se cayó a mitad de la pasada')
            return real(uuid)
          }
          return driver
        },
      },
      scopes: { resolveChain },
    })
    const uno = await authz.defineScopedRole(admin, unitA1, { slug: 'uno', scopeType: 'unit', rank: 10, permissions: ['docs:read'] })
    const dos = await authz.defineScopedRole(admin, orgA, { slug: 'dos', scopeType: 'unit', rank: 11, permissions: ['docs:read'] })
    const tres = await authz.defineScopedRole(adminB, unitB1, { slug: 'tres', scopeType: 'unit', rank: 12, permissions: ['docs:read'] })
    // El orden de purga es estable por uuid (3F · U5) y los uuid v7 son
    // crecientes: se va el primero definido, revienta el segundo.
    assert.deepEqual([uno.uuid, dos.uuid, tres.uuid], [uno.uuid, dos.uuid, tres.uuid].sort(), 'uuid v7: el orden de creación ES el de purga')

    ciego = true
    rompe = true
    const fallo: any = await authz
      .pruneOrphanRoles({ force: true, allowMassPurge: true })
      .then(
        () => null,
        (e: any) => e
      )
    assert.instanceOf(fallo, PruneInterruptedError, 'la interrupción es un error del paquete, no el del motor crudo')
    assert.equal(fallo.status, 500)
    assert.equal(fallo.code, 'E_AUTHZ_PRUNE_INTERRUPTED')
    // Lo que el consumidor necesita para no volver a preguntarle a la BD:
    assert.deepEqual(fallo.purged.map((r: any) => r.uuid), [uno.uuid], 'el error nombra lo YA borrado, ni el que falló ni el que no se intentó')
    assert.deepEqual(fallo.skipped, [])
    // Y el del driver no se pierde ni se filtra: viaja como causa.
    assert.match((fallo.cause as Error).message, /a mitad de la pasada/)

    // La pasada NO es atómica y se dice: el primero ya no está.
    const vista = await new CatalogCache().view()
    assert.isNull(vista.roleByUuid(uno.uuid), 'lo purgado antes del fallo está purgado de verdad')
    assert.isNotNull(vista.roleByUuid(dos.uuid), 'el que falló no se borró')
    assert.isNotNull(vista.roleByUuid(tres.uuid), 'y la pasada se detuvo ahí: el tercero ni se intentó')
    assert.deepEqual(
      events.filter((e: any) => e.action === 'role_purged').map((e: any) => e.role.uuid),
      [uno.uuid],
      'el hilo de auditoría nombra EXACTAMENTE lo que se fue: ni el que falló ni el que no se intentó'
    )
    assert.deepEqual(
      fallo.purged.map((r: any) => r.uuid),
      events.filter((e: any) => e.action === 'role_purged').map((e: any) => e.role.uuid),
      'las dos fuentes (error y eventos) dicen lo mismo: no hay dos verdades sobre qué se borró'
    )

    // Y la promesa que hace que la purga parcial sea recuperable: la
    // siguiente pasada recoge lo que quedó, sin repetir lo ya purgado.
    rompe = false
    const segunda = await authz.pruneOrphanRoles({ force: true, allowMassPurge: true })
    assert.deepEqual(segunda.purged.map((r: any) => r.uuid).sort(), [dos.uuid, tres.uuid].sort(), 'una pasada interrumpida la recoge la siguiente')
    assert.deepEqual(segunda.skipped, [])
  })

  test("3b-0b · AA3 (auditor 3b-0): TOCTOU — el owner se re-resuelve EN FRESCO justo antes de cada purgeRole; si volvió durante la pasada el rol se salta y se reporta (skipped: owner-came-back)", async ({
    assert,
  }) => {
    // La ventana entre leer y borrar es TODA la pasada (N roles + N
    // resolveChain), no un instante: un `scopes.attached` o un restore
    // concurrente borraba un rol cuyo owner YA resolvía, y es irreversible.
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    let llamadas = 0
    let armado = false
    const vuelve = `unit|${unitA1.uuid}`
    const resolveChain = async (scope: ScopeRef) => {
      if (armado && scope.type !== 'app' && `${scope.type}|${scope.uuid}` === vuelve) {
        llamadas += 1
        // La primera lectura (la del barrido) no lo ve; cuando llega el
        // momento de purgarlo, ya está de vuelta en el árbol.
        return llamadas > 1 ? [unitA1, orgA, APP_SCOPE] : null
      }
      return resolveChainFrom(tree)(scope)
    }
    const authz = localManager({
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain }) },
      scopes: { resolveChain },
    })
    const caro = await authz.defineScopedRole(admin, unitA1, { slug: 'caro', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
    await authz.defineScopedRole(admin, orgA, { slug: 'jefe', scopeType: 'unit', rank: 21, permissions: ['docs:read'] })
    armado = true

    const pasada = await authz.pruneOrphanRoles({ force: true })
    armado = false
    assert.deepEqual(pasada.orphans.map((o: any) => o.role.uuid), [caro.uuid], 'la lectura lo vio huérfano')
    assert.deepEqual(pasada.purged, [], 'y aun así no se borró')
    assert.deepEqual(pasada.skipped, [{ role: pasada.orphans[0].role, reason: 'owner-came-back' }])
    assert.isNotNull((await new CatalogCache().view()).roleByUuid(caro.uuid), 'el rol de un owner VIVO sobrevive a la pasada')
    assert.isEmpty(events.filter((e) => e.action === 'role_purged'), 'y nadie audita una purga que no ocurrió')
    // El rol sigue siendo el de siempre: concede en su owner.
    const holder = { type: 'users', uuid: uuidv7() }
    await authz.grant(holder, { uuid: caro.uuid }, unitA1)
    assert.isTrue(await authz.authorize(holder, 'docs:write', unitA1))
  })

  test('3b-0b · AA4 (auditor 3b-0): scopes.detached purga el scope EXACTO — los hechos de un descendiente cuya ruta pasaba por él sobreviven y vuelven a conceder si el scope se restaura con el mismo uuid; limpiarlos es notificar detached por nodo', async ({
    assert,
  }) => {
    // Entre 3D y 3G el rol se llevaba sus asignaciones consigo, así que esto
    // es un cambio de comportamiento y el CHANGELOG lo dice. Es coherente con
    // el invariante 11 (el scope EXACTO) y con el 18 (decide el árbol de HOY).
    const authz = localManager()
    const holder = { type: 'users', uuid: uuidv7() }
    const caro = await authz.defineScopedRole(admin, unitA1, { slug: 'caro', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
    await authz.grant(holder, { uuid: caro.uuid }, unitA1x) // el hecho vive en el NIETO
    assert.isTrue(await authz.authorize(holder, 'docs:write', unitA1x))

    // El consumidor borra la rama y notifica por el ancestro, como decía el
    // docblock. Los hechos del nieto NO se tocan.
    await authz.scopes.detached(unitA1)
    await tree.detach(unitA1)
    assert.isFalse(await authz.authorize(holder, 'docs:write', unitA1x), 'con la rama fuera del árbol no concede: el nieto no resuelve')
    const { default: db } = await import('@adonisjs/lucid/services/db')
    assert.deepEqual(
      (await db.from('authz_assignments').where('role_uuid', caro.uuid).select('scope_uuid')).map((r: any) => String(r.scope_uuid)),
      [unitA1x.uuid],
      'pero el hecho del nieto sigue en la base: la purga fue del scope EXACTO'
    )

    // RESTORE con el mismo uuid (undelete, papelera, recrear la unit): vuelve
    // a conceder SIN ninguna escritura.
    await tree.attach(unitA1, orgA)
    await tree.attach(unitA1x, unitA1)
    assert.isTrue(await authz.authorize(holder, 'docs:write', unitA1x), 'el árbol de HOY decide: el hecho despierta con el scope')

    // La limpieza es notificar `detached` por NODO de la rama que se borra
    // (o, desde 3b-3, `authz:reconcile --prune`).
    await authz.scopes.detached(unitA1x)
    await authz.scopes.detached(unitA1)
    await tree.detach(unitA1)
    await tree.attach(unitA1, orgA)
    await tree.attach(unitA1x, unitA1)
    assert.isFalse(await authz.authorize(holder, 'docs:write', unitA1x), 'purgado nodo a nodo, el restore ya no resucita nada')
  })

  test('3b-0 · Z1 (tester): la identidad CANÓNICA de scopes.detached también sale del manager — el evento scope_purged y el onScopeDetached del puerto llevan chain[0], nunca el alias del uuid que trajo el llamante (invariantes 17 y 18)', async ({
    assert,
  }) => {
    // La aserción «el alias purga de verdad» del caso Z1 la sostiene el
    // DRIVER, que canoniza por su cuenta (`canonicalOrSelf` dentro de
    // `purgeScope`): pasa igual con un manager que no resuelva la cadena.
    // Hasta 3G esa línea del manager tenía otro consumidor —la purga de
    // roles leía por `scopeKey(purged)` y con el alias no encontraba
    // ninguno—, así que el mutante moría. Borrada la purga, lo único que
    // depende de ella es lo que el manager pasa HACIA FUERA: el evento de
    // auditoría y el `onScopeDetached` del puerto, por donde un driver de
    // terceros (y el modo `facts` de 3b) borra lo suyo por `scopeKey`.
    const fused = (scope: ScopeRef) => `${scope.type}|${(scope.uuid ?? '').replaceAll('-', '')}`
    const rows = new Map<string, { self: ScopeRef; parent: ScopeRef }>([
      [fused(orgA), { self: orgA, parent: APP_SCOPE }],
      [fused(unitA1), { self: unitA1, parent: orgA }],
    ])
    const chainOf = async (scope: ScopeRef): Promise<ScopeRef[] | null> => {
      const chain: ScopeRef[] = []
      let current = scope
      for (let depth = 0; depth < 10; depth++) {
        if (current.type === 'app') return [...chain, APP_SCOPE]
        const row = rows.get(fused(current))
        if (!row) return null
        chain.push(row.self)
        current = row.parent
      }
      return null
    }
    const avisados: ScopeRef[] = []
    class ConAviso extends DatabaseAuthorizationDriver {
      async onScopeDetached(child: ScopeRef): Promise<void> {
        avisados.push(child)
      }
    }
    const escrituras: any[] = []
    const authz = localManager({
      drivers: { database: () => new ConAviso({ resolveChain: chainOf }) },
      scopes: { resolveChain: chainOf },
      hooks: { onCatalogWrite: async (e: any) => void events.push(e), onWrite: async (e: any) => void escrituras.push(e) },
    })
    const alias: ScopeRef = { type: 'unit', uuid: unitA1.uuid!.replaceAll('-', '') }
    assert.notEqual(alias.uuid, unitA1.uuid, 'el alias NO es la identidad de la fila')

    await authz.scopes.detached(alias)

    assert.deepEqual(
      escrituras.filter((e) => e.action === 'scope_purged').map((e) => e.scope.uuid),
      [unitA1.uuid],
      'la auditoría nombra la fila, no el alias: un sink que agrega por scope no ve dos scopes donde hay uno'
    )
    assert.deepEqual(avisados.map((s) => s.uuid), [unitA1.uuid], 'y el puerto recibe la misma identidad')
    // Y un scope que el árbol YA NO conoce se purga IGUAL y se notifica tal
    // cual (3F · S1): `detached` limpia DESPUÉS de borrar la fila y no
    // necesita cadena para nada. Ese caso se fue con la purga de roles, y sin
    // esto exigirle la cadena (un `assertKnownScope`) no pone rojo nada.
    const ajeno: ScopeRef = { type: 'unit', uuid: uuidv7() }
    rows.set(fused(ajeno), { self: ajeno, parent: orgA })
    const holder = { type: 'users', uuid: uuidv7() }
    await authz.grant(holder, 'unit-editor', ajeno)
    assert.isTrue(await authz.authorize(holder, 'docs:write', ajeno))
    rows.delete(fused(ajeno)) // el consumidor borra la fila y avisa después
    await authz.scopes.detached(ajeno)
    assert.deepEqual(avisados.map((s) => s.uuid), [unitA1.uuid, ajeno.uuid])
    rows.set(fused(ajeno), { self: ajeno, parent: orgA }) // vuelve a mirarse el hueco
    assert.deepEqual(await (await authz.driver()).listRoles(holder, ajeno), [], 'se purgó sin cadena y nada resucita')
    assert.isFalse(await authz.authorize(holder, 'docs:write', ajeno))
  })

  test('3b-0 · Z1 (tester): el cambio de política declarado tiene las DOS caras — con requireWithin: false un actor sin rango purga los hechos de un scope ajeno CON roles locales (antes 422 por la policy de rango), y con requireWithin: non-root la misma llamada sigue cerrada sin tocar nada', async ({
    assert,
  }) => {
    // §3.3 del informe de 3b-0. La cara ABIERTA la fija Z1; la CERRADA no
    // estaba fijada sobre un scope CON roles locales, que es justo donde
    // antes había una protección accidental. Las dos juntas, para que
    // revertir la decisión en cualquiera de los dos sentidos ponga rojo.
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const lax = localManager()
    const forastero = { type: 'users', uuid: uuidv7() } // rank 0 en toda cadena
    const holder = { type: 'users', uuid: uuidv7() }
    const caro = await lax.defineScopedRole(admin, unitA1, { slug: 'caro', scopeType: 'unit', rank: 40, permissions: ['docs:write'] })
    await lax.grant(holder, { uuid: caro.uuid }, unitA1)
    assert.isTrue(await lax.authorize(holder, 'docs:write', unitA1))

    // (b) CERRADA: las tres puertas de `within`, y los hechos intactos.
    const estricto = localManager({ requireActor: true, requireWithin: 'non-root' })
    await rejects(assert, () => estricto.scopes.detached(unitA1, { actor: forastero }), { status: 422, code: 'E_AUTHZ_WITHIN_REQUIRED' })
    await rejects(assert, () => estricto.scopes.detached(unitA1, { actor: forastero, within: APP_SCOPE }), { status: 422, code: 'E_AUTHZ_WITHIN_ROOT_FORBIDDEN' })
    await rejects(assert, () => estricto.scopes.detached(unitA1, { actor: forastero, within: orgB }), { status: 422, code: 'E_AUTHZ_NOT_WITHIN' })
    assert.isTrue(await lax.authorize(holder, 'docs:write', unitA1), 'nada purgado')

    // (a) ABIERTA con el default documentado: el mismo forastero de rank 0
    // purga los HECHOS —la barrera de esta operación es `within`
    // (invariante 15), no el rango— y el rol de rank 40 sigue en el catálogo.
    await localManager({ requireActor: true }).scopes.detached(unitA1, { actor: forastero })
    assert.isFalse(await lax.authorize(holder, 'docs:write', unitA1))
    assert.isNotNull((await new CatalogCache().view()).roleByUuid(caro.uuid), 'el catálogo no se escribe desde el árbol')
  })

  test('3b-0 · Z3 (tester): el rol DORMIDO no bloquea el (slug, nivel) del hermano de su owner ni el de un ancestro, pero SÍ el del descendiente VIVO cuya ruta sigue pasando por el owner — 422 E_AUTHZ_CATALOG_CONFLICT, y quien lo libera es prune-orphans', async ({
    assert,
  }) => {
    // 3b-0 decide, a propósito, NO tocar `#assertNoRoleCollision` («hacerla
    // más permisiva era el fail-open») y lo mide a mano. Sin este caso esa
    // decisión no tiene juez: una versión que se salte el homónimo cuyo
    // owner ya no resuelve pasa la suite entera, y en unitA1x quedarían dos
    // `jefe@unit` VISIBLES con toda ruta por slug muerta ahí abajo.
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const unitA2: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await tree.attach(unitA2, orgA)
    const oculto = new Set<string>()
    const cadena = resolveChainFrom(tree)
    // La fila del owner se borró, pero los hijos conservan su ruta
    // materializada (el árbol incoherente de D4).
    const oculta = (s: ScopeRef) => (oculto.has(`${s.type}|${s.uuid}`) ? Promise.resolve(null) : cadena(s))
    const authz = localManager({
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain: oculta as any }) },
      scopes: { resolveChain: oculta, descendantsOf: descendantsFrom(tree) },
    })
    const spec = { slug: 'jefe', scopeType: 'unit', rank: 20, permissions: ['docs:write'] }
    const conflict = { status: 422, code: 'E_AUTHZ_CATALOG_CONFLICT' }
    const jefe = await authz.defineScopedRole(admin, unitA1, spec)
    // Control con el árbol entero: el descendiente no repite el (slug, nivel) de su ancestro.
    await rejects(assert, () => authz.defineScopedRole(admin, unitA1x, spec), conflict)

    // El consumidor purga y borra la fila: el rol queda DORMIDO e inalcanzable.
    await authz.scopes.detached(unitA1)
    oculto.add(`unit|${unitA1.uuid}`)
    assert.isNull(await oculta(unitA1), 'el owner ya no resuelve')
    assert.lengthOf((await cadena(unitA1x))!, 4, 'y la ruta del descendiente sigue pasando por él')
    await rejects(assert, () => authz.deleteScopedRole(admin, jefe.uuid), { status: 422, code: 'E_AUTHZ_UNKNOWN_SCOPE' })

    // (c) El descendiente VIVO sigue bloqueado: ahí el rol NO está dormido.
    await rejects(assert, () => authz.defineScopedRole(admin, unitA1x, spec), conflict)
    // (a) El HERMANO del owner huérfano entra.
    const delHermano = await authz.defineScopedRole(admin, unitA2, spec)
    await authz.deleteScopedRole(admin, delHermano.uuid)
    // (b) Y un ANCESTRO también, sin ensombrecer al dormido (un owner que no
    //     resuelve no está debajo de nadie).
    const delAncestro = await authz.defineScopedRole(admin, orgA, spec)
    assert.deepEqual(
      events.filter((e) => e.action === 'role_defined' && e.role.uuid === delAncestro.uuid).map((e) => e.shadowedByAncestor),
      [undefined]
    )
    await authz.deleteScopedRole(admin, delAncestro.uuid)

    // La salida determinista es el barrido de plataforma, no relajar la regla.
    // (3b-0b · AA2: aquí el único rol local es el huérfano —1 de 1 owners—,
    // que es la firma de un resolutor ciego, así que la cota de purga masiva
    // pide la bandera explícita. El barrido sigue siendo la salida; lo que
    // cambia es que la decide un humano.)
    await rejects(assert, () => authz.pruneOrphanRoles({ force: true }), { status: 500, code: 'E_AUTHZ_MASS_PURGE_REFUSED' })
    assert.deepEqual((await authz.pruneOrphanRoles({ force: true, allowMassPurge: true })).purged.map((r: any) => r.uuid), [jefe.uuid])
    assert.isNull((await new CatalogCache().view()).roleByUuid(jefe.uuid))
    const suyo = await authz.defineScopedRole(admin, unitA1x, spec)
    assert.deepEqual((await new CatalogCache().view()).rolesNamed('jefe', 'unit').map((r) => r.uuid), [suyo.uuid])
  })

  test('3F · U4 (tester 3E · §4.5): AuthzWriteEvent.roles — un revoke por slug notifica TODOS los homónimos visibles, no uno; y por { uuid } el evento solo nombra el rol si es visible en ese scope (el uuid de un rol ajeno no filtra su slug ni su owner al sink de auditoría)', async ({
    assert,
  }) => {
    // Q7 fijaba la FORMA del evento (uuid + slug + nivel + owner) pero no las
    // dos cosas que la justifican: la pluralidad del `revoke` por slug y la
    // comprobación de owner en la ruta `{ uuid }` — que es Q2 por la puerta
    // del hook: `rolesToRevoke` por uuid no comprueba el owner a propósito
    // (quitar nunca concede), así que la escritura ocurre y notifica.
    const escritos: any[] = []
    const authz = localManager({
      hooks: { onCatalogWrite: async (e: any) => void events.push(e), onWrite: async (e: any) => void escritos.push(e) },
    })
    const leadA = await authz.defineScopedRole(admin, orgA, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:read'] })
    const leadB = await authz.defineScopedRole(adminB, unitB1, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
    const holder = { type: 'users', uuid: uuidv7() }
    await authz.grant(holder, { uuid: leadB.uuid }, unitB1)
    // Un `scopes.moved` legítimo junta los dos homónimos en la misma cadena.
    await authz.scopes.moved(unitB1, orgA)
    await tree.move(unitB1, orgA)
    await authz.grant(holder, { uuid: leadA.uuid }, unitB1)
    assert.deepEqual((await authz.effectivePermissions(holder, unitB1)).sort(), ['docs:read', 'docs:write'])

    escritos.length = 0
    await authz.revoke(holder, 'lead', unitB1)
    const revocados = escritos.filter((e) => e.action === 'revoked')
    assert.lengthOf(revocados, 1)
    assert.deepEqual(
      revocados[0].roles.map((r: any) => r.uuid).sort(),
      [leadA.uuid, leadB.uuid].sort(),
      'el revoke por slug quita los hechos de TODOS los homónimos, y el evento los lleva TODOS'
    )
    assert.deepEqual(await authz.effectivePermissions(holder, unitB1), [], 'y de verdad se quitaron los dos')

    // El uuid de un rol que NO es visible en ese scope (owner fuera de la
    // cadena): la escritura ocurre —es un no-op— y el evento no nombra nada.
    escritos.length = 0
    await authz.revoke(holder, { uuid: leadB.uuid }, unitA1)
    const ajeno = escritos.filter((e) => e.action === 'revoked')
    assert.lengthOf(ajeno, 1, 'el revoke por uuid no comprueba el owner (quitar nunca concede): la escritura ocurre')
    assert.isUndefined(ajeno[0].roles, 'pero el evento no filtra el slug ni el owner de un rol que no es visible ahí')
  })

  test('3F · S4 (auditor N4): con un rol GLOBAL ensombreciendo a un local homónimo, dentro de esa cadena TODA ruta por slug muere para TODOS —la plataforma incluida—, no solo para el tenant que ocupó el nombre; fuera del subárbol el slug sigue vivo y { uuid } funciona siempre', async ({
    assert,
  }) => {
    // El README decía «the tenant that took the name only hurts itself» y lo
    // medido es otra cosa: dentro del subárbol ocupado la PLATAFORMA pierde
    // las rutas por slug de SU rol global (5/5 en el ataque del auditor).
    // No hay escalada —el hecho apunta al uuid del rol— pero el onboarding
    // por slug deja de funcionar ahí hasta que alguien purgue.
    const authz = localManager()
    const holderLocal = { type: 'users', uuid: uuidv7() }
    const nuevo = { type: 'users', uuid: uuidv7() }
    const local = await authz.defineScopedRole(admin, unitA1, { slug: 'soporte', scopeType: 'unit', rank: 2, permissions: ['docs:read'] })
    await authz.grant(holderLocal, { uuid: local.uuid }, unitA1)

    // El deploy trae el global homónimo (con MÁS permisos) y lo reporta.
    const report = await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }, { slug: 'billing:read' }, { slug: 'org:settings', assignableAt: ['app', 'organization'] }, { slug: 'app:manage' }],
      roles: [
        { slug: 'org-admin', scopeType: 'organization', rank: 50, permissions: DELEGABLE },
        { slug: 'soporte', scopeType: 'unit', rank: 80, permissions: ['docs:read', 'docs:write'] },
      ],
    })
    assert.deepEqual(report.shadowedByGlobal.map((r) => r.uuid), [local.uuid])

    // La PLATAFORMA, dentro del subárbol ocupado: toda ruta por slug es 422.
    const ambigua = { status: 422, code: 'E_AUTHZ_AMBIGUOUS_ROLE' }
    for (const scope of [unitA1, unitA1x]) {
      await rejects(assert, () => authz.grant(nuevo, 'soporte', scope), ambigua)
      await rejects(assert, () => authz.hasRole(nuevo, 'soporte', scope), ambigua)
      await rejects(assert, () => authz.listSubjects('soporte', scope), ambigua)
    }
    // (`revoke` por slug no elige ni falla: quita los hechos de TODOS los
    // homónimos del scope exacto — quitar nunca concede, 3B.)
    await authz.revoke(nuevo, 'soporte', unitA1)
    // Fuera del subárbol del ocupante, el slug del global sigue vivo.
    assert.deepEqual(await authz.grant(nuevo, 'soporte', unitB1), { existed: false, expiresAt: null })
    assert.isTrue(await authz.authorize(nuevo, 'docs:write', unitB1))
    // Y dentro, la forma que SIEMPRE funciona es { uuid }.
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const global = (await new CatalogCache().view()).role('soporte', 'unit')!
    await authz.grant(nuevo, { uuid: global.uuid }, unitA1)
    assert.isTrue(await authz.authorize(nuevo, 'docs:write', unitA1), 'el rol global concede por uuid')
    // Sin escalada: el holder del LOCAL no hereda nada del global homónimo.
    assert.isFalse(await authz.authorize(holderLocal, 'docs:write', unitA1))
    assert.deepEqual(await authz.effectivePermissions(holderLocal, unitA1), ['docs:read'])
  })

  test('3F · S2 (auditor N3): un subárbol que no se puede enumerar DEGRADA la regla de nivel a la MÍNIMA, nunca tumba la operación; por debajo de la cota, el comportamiento fuerte intacto y lo que la regla mínima sí cierra sigue cerrado', async ({
    assert,
  }) => {
    // Regresión de 3E · P1: declarar `scopes.descendantsOf` dejaba al tenant
    // GRANDE peor que no declararlo — por encima de `maxDescendants`,
    // `defineScopedRole` hacia abajo era 503.
    // (La otra mitad de S2 —la degradación de `scopes.detached`— desapareció
    // en 3b-0 · Z1 junto con la purga de roles desde el árbol: esa operación
    // ya no enumera nada, así que no tiene nada que degradar.)
    // orgA tiene 2 descendientes (unitA1, unitA1x): con la cota en 1 el árbol
    // del harness lanza al pasarse (503 dentro), y un `descendantsOf` que
    // devuelve la lista entera lo caza `#descendants` (422 TOO_MANY). Los dos
    // degradan igual.
    const cortito = localManager({
      scopes: { resolveChain: resolveChainFrom(tree), descendantsOf: descendantsFrom(tree), maxDescendants: 1 },
    })
    const desbordado = localManager({
      scopes: {
        resolveChain: resolveChainFrom(tree),
        descendantsOf: async (scope: any) => (scope.type === 'organization' ? [unitA1, unitA1x] : []),
        maxDescendants: 1,
      },
    })

    // La regla de nivel cae a la MÍNIMA: un nivel que no es de un ancestro se
    // acepta (es lo que hace un consumidor sin `descendantsOf`). Con la cota
    // ancha, el árbol de hoy manda y 'team' no cuelga de orgA.
    const above = { status: 422, code: 'E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER' }
    await rejects(assert, () => localManager().defineScopedRole(admin, orgA, { slug: 'fantasma', scopeType: 'team', rank: 2, permissions: ['docs:read'] }), above)
    const flojo = await cortito.defineScopedRole(admin, orgA, { slug: 'fantasma', scopeType: 'team', rank: 2, permissions: ['docs:read'] })
    assert.equal(flojo.scopeType, 'team', 'con el subárbol sin enumerar se acepta, como sin descendantsOf')
    const flojo2 = await desbordado.defineScopedRole(admin, orgA, { slug: 'fantasma2', scopeType: 'team', rank: 2, permissions: ['docs:read'] })
    assert.equal(flojo2.scopeType, 'team', 'igual cuando la cota la caza el manager (422 TOO_MANY dentro)')
    // Y lo que la regla mínima SÍ cierra sigue cerrado: el nivel de un ancestro.
    const unitAdmin = { type: 'users', uuid: uuidv7() }
    await cortito.defineScopedRole(admin, unitA1, { slug: 'unit-admin', scopeType: 'unit', rank: 30, permissions: ['docs:read', 'docs:write'] })
    await (await cortito.driver()).grant(unitAdmin, 'unit-admin', unitA1)
    await rejects(assert, () => cortito.defineScopedRole(unitAdmin, unitA1, { slug: 'mina', scopeType: 'organization', rank: 2, permissions: ['docs:read'] }), above)
  })

  test('3E · R5 (tester): defineScopedRole contra syncAuthzCatalog EN PARALELO: o el define pierde con 422 y solo queda el global, o el sync lo ENSOMBRECE y lo reporta — nunca dos globales ni un local silencioso', async ({
    assert,
  }) => {
    // El README prometía esta carrera y la suite solo tenía la secuencial.
    // Con 3E · P1 b tiene DOS finales legítimos (los dos escritores pasan por
    // el cerrojo del catálogo, así que van en serie): si el sync confirma
    // primero, el re-chequeo del define ve el global y choca; si confirma
    // primero el define, el sync escribe el global igual y REPORTA al local
    // ensombrecido. Lo que nunca puede pasar es que el local quede sin decir.
    const { default: db } = await import('@adonisjs/lucid/services/db')
    const authz = localManager()
    const spec = { permissions: [{ slug: 'docs:read' }], roles: [{ slug: 'lead', scopeType: 'unit', permissions: ['docs:read'] }] }
    const [sync, define] = await Promise.allSettled([
      syncAuthzCatalog(spec),
      authz.defineScopedRole(admin, orgA, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] }),
    ])
    const filas = await db.from('authz_roles').where('slug', 'lead').where('scope_type', 'unit').select('uuid', 'owner_scope_key')
    assert.lengthOf(filas.filter((r: any) => r.owner_scope_key === 'global'), 1, 'el global del deploy entra, pase lo que pase')
    if (define.status === 'rejected') {
      assert.oneOf((define.reason as any)?.status, [422, 503], String((define.reason as any)?.message))
      if ((define.reason as any)?.status === 422) assert.equal((define.reason as any)?.code, 'E_AUTHZ_CATALOG_CONFLICT')
      assert.lengthOf(filas, 1, 'el local no se escribió')
    } else {
      assert.lengthOf(filas, 2, 'el local ya estaba: el global lo ensombrece')
      assert.equal(sync.status, 'fulfilled')
      assert.deepEqual(
        (sync as PromiseFulfilledResult<any>).value.shadowedByGlobal.map((r: any) => r.uuid),
        [define.value.uuid],
        'y el sync lo DICE: nunca en silencio'
      )
    }
  })

  test('3E · R3 (tester): un driver sin rolesInChain compone la lectura por slug sin elegir homónimo — effectivePermissions devuelve la LISTA (no un 422 E_AUTHZ_AMBIGUOUS_ROLE) y solo los permisos del rol que el holder tiene de verdad', async ({
    assert,
  }) => {
    // `rolesInChain` es OPCIONAL en el puerto: sin él el manager compone con
    // `listRoles`, que devuelve SLUGS. Ese camino —el de un driver de
    // terceros escrito para 2.0/2.1— usaba `roleVisible`, que desde 3D · M1
    // lanza 422 con dos homónimos visibles: `effectivePermissions`, que
    // promete una lista, explotaba. Y elegir uno sería la escalada del
    // auditor V1. Se pregunta por `{ uuid }`, que es exacto.
    const sinRolesInChain = () => {
      const view = Object.create(new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) }))
      Object.defineProperty(view, 'rolesInChain', { value: undefined, enumerable: false })
      return view
    }
    const authz = localManager()
    const leadA = await authz.defineScopedRole(admin, orgA, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:read'] })
    const leadB = await authz.defineScopedRole(adminB, unitB1, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
    const holder = { type: 'users', uuid: uuidv7() }
    await authz.grant(holder, { uuid: leadB.uuid }, unitB1)
    // Un `scopes.moved` legítimo junta los dos homónimos en la misma cadena.
    await authz.scopes.moved(unitB1, orgA)
    await tree.move(unitB1, orgA)

    const compuesto = localManager({ drivers: { database: () => sinRolesInChain() } })
    assert.isUndefined((await compuesto.driver()).rolesInChain, 'el driver de este caso NO trae el método opcional')
    assert.deepEqual(await compuesto.effectivePermissions(holder, unitB1), ['docs:write'], 'lo que tiene, y solo eso')
    assert.deepEqual(await localManager().effectivePermissions(holder, unitB1), ['docs:write'], 'igual que con rolesInChain')
    // Y con los dos asignados, la unión (es lo que authorize responde).
    await authz.grant(holder, { uuid: leadA.uuid }, unitB1)
    assert.deepEqual((await compuesto.effectivePermissions(holder, unitB1)).sort(), ['docs:read', 'docs:write'])
    assert.isTrue(await compuesto.authorize(holder, 'docs:read', unitB1))
  })

  test('3E · P1 (auditor A1): un rol local nunca vive POR ENCIMA de su owner ⇒ 422 E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER sin escribir (la mina de slug: un rol invisible que solo ocupa el nombre); delegar hacia ABAJO sigue funcionando sin scopes.descendantsOf, y con él se endurece al árbol de hoy; updateScopedRole revalida el rol que ya existe', async ({
    assert,
  }) => {
    // Auditor A1: `subU9`, admin de una unit con rank 9, definía
    // `operador@organization` con owner su unit — un rol de nivel POR ENCIMA
    // del owner: no es visible en ninguna parte, no concede nada y nadie lo
    // puede asignar. Lo único que hacía era ocupar ese (slug, nivel) para el
    // dueño del árbol y para el catálogo GLOBAL de la plataforma.
    const { CatalogCache, withAuthzCatalogWrite } = await import('../src/catalog/catalog_cache.js')
    const authz = localManager()
    const above = { status: 422, code: 'E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER' }
    const unitAdmin = { type: 'users', uuid: uuidv7() }
    await authz.defineScopedRole(admin, unitA1, { slug: 'unit-admin', scopeType: 'unit', rank: 30, permissions: ['docs:read', 'docs:write'] })
    await (await authz.driver()).grant(unitAdmin, 'unit-admin', unitA1)

    const mina = await rejects(assert, () => authz.defineScopedRole(unitAdmin, unitA1, { slug: 'operador', scopeType: 'organization', rank: 2, permissions: ['docs:read'] }), above)
    assert.include(mina.message, "POR ENCIMA de su owner")
    assert.deepEqual((await new CatalogCache().view()).rolesNamed('operador', 'organization'), [], 'nada escrito')
    // El nivel del owner sí.
    await authz.defineScopedRole(unitAdmin, unitA1, { slug: 'operador', scopeType: 'unit', rank: 2, permissions: ['docs:read'] })
    // Con `descendantsOf` declarado se ENDURECE: un nivel que no aparece bajo
    // el owner en el árbol de hoy tampoco (no colgaría de nadie).
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { slug: 'fantasma', scopeType: 'team', rank: 2, permissions: ['docs:read'] }), above)

    // SIN `scopes.descendantsOf` (el stub publicado no lo declara) la regla es
    // la mínima que cierra la mina: se rechaza el nivel de un ANCESTRO y se
    // presume descendiente todo lo demás. El caso común —una organization
    // define `lead@unit`— tiene que seguir funcionando.
    const sinArbol = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) }) },
      scopes: { resolveChain: resolveChainFrom(tree) },
      delegablePermissions: DELEGABLE,
      warnOnOptInSecurity: false,
    } as any)
    const jefe = await sinArbol.defineScopedRole(admin, orgA, { slug: 'jefe', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
    assert.equal(jefe.scopeType, 'unit', 'sin descendantsOf, delegar hacia abajo sigue siendo legal')
    assert.isTrue(await authz.authorize(admin, 'docs:write', unitA1))
    // Y la mina sigue cerrada sin `descendantsOf`: la cadena del owner basta.
    const sinMina = await rejects(assert, () => sinArbol.defineScopedRole(unitAdmin, unitA1, { slug: 'jefazo', scopeType: 'organization', rank: 2, permissions: ['docs:read'] }), above)
    assert.include(sinMina.message, "POR ENCIMA de su owner")
    // El nivel de la RAÍZ es siempre el de un ancestro; muere aún antes, en el
    // spec (la raíz no cuelga de ningún owner): 422 de identidad.
    await rejects(assert, () => sinArbol.defineScopedRole(admin, orgA, { slug: 'raiz', scopeType: 'app', rank: 2, permissions: ['docs:read'] }), { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' })
    assert.deepEqual((await new CatalogCache().view()).rolesNamed('raiz', 'app'), [])

    // Un rol con el nivel por encima del owner escrito A MANO (o antes de 3E)
    // no se perpetúa: `updateScopedRole` lo rechaza igual — lo que toca es
    // purgarlo, y eso sí se puede.
    const heredado = uuidv7()
    await withAuthzCatalogWrite(async (trx) => {
      const perm: any = (await trx.from('authz_permissions').where('slug', 'docs:read').select('uuid'))[0]
      const now = new Date()
      await trx.table('authz_roles').insert({ uuid: heredado, slug: 'viejo', name: 'viejo', scope_type: 'organization', rank: 5, owner_scope_key: `unit|${unitA1.uuid}`, created_at: now, updated_at: now })
      await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: heredado, permission_uuid: perm.uuid, created_at: now })
    })
    await rejects(assert, () => authz.updateScopedRole(admin, heredado, { rank: 4 }), above)
    await authz.deleteScopedRole(admin, heredado)
    assert.isNull((await new CatalogCache().view()).roleByUuid(heredado))
  })

  test('el owner y el spec se validan antes de tocar nada: la raíz, el centinela, un scope desconocido, scopeType app, slug inválido, permissions que no es lista, actor ausente o inválido ⇒ 422 con su código; assignableAt del permiso ⇒ 422 E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT', async ({
    assert,
  }) => {
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const authz = localManager()
    const spec = { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] }
    const invalid = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
    await rejects(assert, () => authz.defineScopedRole(admin, APP_SCOPE, spec), invalid)
    await rejects(assert, () => authz.defineScopedRole(admin, { type: 'organization', uuid: '00000000-0000-0000-0000-000000000000' }, spec), invalid)
    await rejects(assert, () => authz.defineScopedRole(admin, { type: 'app', uuid: 'x' } as any, spec), invalid)
    await rejects(assert, () => authz.defineScopedRole(admin, { type: 'organization', uuid: uuidv7() }, spec), { status: 422, code: 'E_AUTHZ_UNKNOWN_SCOPE' })
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, scopeType: 'app' }), invalid)
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, scopeType: 'Unit' }), invalid)
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, slug: 'Lead' }), { status: 422, code: 'E_AUTHZ_INVALID_SLUG' })
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, slug: 'parent' }), { status: 422, code: 'E_AUTHZ_INVALID_SLUG' })
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, permissions: 'docs:write' as any }), invalid)
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, permissions: ['docs~write'] }), { status: 422, code: 'E_AUTHZ_INVALID_SLUG' })
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, name: 'x'.repeat(101) }), invalid)
    await rejects(assert, () => authz.defineScopedRole(undefined as any, orgA, spec), { status: 422, code: 'E_AUTHZ_ACTOR_REQUIRED' })
    await rejects(assert, () => authz.defineScopedRole({ type: 'users', uuid: 'X#Y' }, orgA, spec), invalid)
    // B5: org:settings solo pueden llevarlo roles de app/organization.
    await rejects(assert, () => authz.defineScopedRole(admin, orgA, { ...spec, permissions: ['org:settings'] }), { status: 422, code: 'E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT' })
    // Un rol de organization sí puede llevarlo; al de unit tampoco se le puede AÑADIR después.
    const orgLead = await authz.defineScopedRole(admin, orgA, { slug: 'org-lead', scopeType: 'organization', rank: 20, permissions: ['org:settings'] })
    assert.equal(orgLead.scopeType, 'organization')
    const lead = await authz.defineScopedRole(admin, orgA, spec)
    await rejects(assert, () => authz.updateScopedRole(admin, lead.uuid, { permissions: ['docs:write', 'org:settings'] }), { status: 422, code: 'E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT' })
    assert.deepEqual([...(await new CatalogCache().view()).rolePermissionsOf(lead.uuid)], ['docs:write'])
    assert.lengthOf(events, 2)
  })

  test('C3: defineScopedRole resuelve el owner en FRESCO aunque la vista de forRequest tenga memoizada la cadena vieja: la unit que ya es de B no recibe un rol delegado por el admin de A; y el owner se escribe con la identidad canónica del árbol', async ({
    assert,
  }) => {
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const authz = localManager()
    const view = authz.forRequest()
    // La vista memoiza la cadena de unitA1 (bajo A).
    assert.isTrue(await view.authorize(admin, 'docs:write', unitA1))
    // La unit se mueve a B durante el request.
    await tree.move(unitA1, orgB)
    assert.isTrue(await view.authorize(admin, 'docs:write', unitA1), 'la vista sigue leyendo la cadena memoizada (por diseño, una lectura)')
    // La escritura NO: el admin de A no tiene nada efectivo en la unit (ahora de B).
    await rejects(assert, () => view.defineScopedRole(admin, unitA1, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] }), {
      status: 422,
      code: 'E_AUTHZ_PERMISSION_NOT_DELEGABLE',
    })
    assert.deepEqual((await new CatalogCache().view()).rolesNamed('lead', 'unit'), [])
    // El admin de B sí, y el owner queda con la forma canónica del árbol.
    const lead = await view.defineScopedRole(adminB, { type: 'unit', uuid: unitA1.uuid }, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
    assert.equal(lead.owner, `unit|${unitA1.uuid}`)
  })

  test('requireActor y el hook: defineScopedRole exige actor siempre (aunque requireActor sea false); un onCatalogWrite que lanza no revierte la escritura; un driver sin purgeRole hace que deleteScopedRole sea 500 E_AUTHZ_UNSUPPORTED sin tocar el catálogo', async ({
    assert,
  }) => {
    const { CatalogCache } = await import('../src/catalog/catalog_cache.js')
    const loud = localManager({
      hooks: {
        onCatalogWrite: async () => {
          throw new Error('auditoría caída')
        },
      },
    })
    const logs = await captureErrorLog(async () => {
      const lead = await loud.defineScopedRole(admin, orgA, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
      assert.isNotNull((await new CatalogCache().view()).roleByUuid(lead.uuid))
    })
    assert.isNotEmpty(logs)
    assert.include(logs.join('\n'), 'onCatalogWrite')

    const lead = (await new CatalogCache().view()).rolesNamed('lead', 'unit')[0]
    const real = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })
    const noPurge: any = Object.create(real)
    Object.defineProperty(noPurge, 'purgeRole', { value: undefined, enumerable: false })
    const limited = localManager({ drivers: { database: () => noPurge } })
    const error = await rejects(assert, () => limited.deleteScopedRole(admin, lead.uuid), { status: 500, code: 'E_AUTHZ_UNSUPPORTED' })
    assert.include(error.message, 'purgeRole')
    assert.deepEqual((await new CatalogCache().view()).roleByUuid(lead.uuid), lead)

    // 3b-1 (⚪ 3 de 3b-0b): el mismo 500 de `pruneOrphanRoles` solo se
    // observaba en la cara `whenFalse` del par `purgeRole` del juez, que solo
    // corre con OpenFGA: en los cuatro modos sin `:8101` era INVISIBLE. Aquí
    // se ve con el driver `database`, y con la promesa entera —«lo dice ANTES
    // de leer nada»— medida en consultas.
    const { countQueries } = await import('./helpers/spies.js')
    for (const options of [{}, { force: true }, { force: true, allowMassPurge: true }]) {
      const { queries } = await countQueries(async () => {
        const fallo = await rejects(assert, () => limited.pruneOrphanRoles(options), { status: 500, code: 'E_AUTHZ_UNSUPPORTED' })
        assert.include(fallo.message, 'purgeRole')
        assert.include(fallo.message, 'pruneOrphanRoles')
      })
      assert.lengthOf(queries, 0, `${JSON.stringify(options)}: ni siquiera lee los roles locales`)
    }
    assert.deepEqual((await new CatalogCache().view()).roleByUuid(lead.uuid), lead, 'y nada se purgó')
  })
})

/**
 * 3b-2j · El comando `authz:catalog:prune-orphans` reparte los huérfanos en
 * TRES cubos, no en dos (decisión del dueño del 2026-08-31 (3) ·
 * consecuencia 2). El reparto es lo único que el comando DECIDE, así que es
 * una función pura con su caso.
 */
test.group('3b-2j · authz:catalog:prune-orphans lista aparte lo que concede Y lo que no se puede demostrar', () => {
  const orphan = (slug: string, stillGranting: boolean | undefined, assignments: number | undefined) => ({
    role: { uuid: `uuid-${slug}`, slug, scopeType: 'unit', rank: 20 },
    owner: { type: 'unit', uuid: 'owner-uuid' },
    permissions: ['docs:write'],
    assignments,
    stillGranting,
  })

  test('`false` es la única línea normal: `true` sale con TODAVÍA CONCEDE, `undefined` con NO SE SABE, y cada cubo lleva su aviso final', async ({
    assert,
  }) => {
    const { orphanLines } = await import('../commands/authz_catalog_prune_orphans.js')
    const lines = orphanLines(
      [orphan('inerte', false, 0), orphan('vivo', true, 2), orphan('dudoso', undefined, undefined)],
      new Set(['uuid-inerte']),
      new Set()
    )
    assert.deepEqual(
      lines.map((l) => ({ level: l.level, head: l.message.split(':')[0] })),
      [
        { level: 'log', head: 'purgado' },
        { level: 'warning', head: 'huérfano · TODAVÍA CONCEDE' },
        { level: 'warning', head: 'huérfano · NO SE SABE SI CONCEDE' },
        { level: 'warning', head: '1 rol(es) huérfano(s) siguen teniendo asignaciones vigentes' },
        { level: 'warning', head: '1 rol(es) huérfano(s) SIN demostración de que no concedan' },
      ],
      'el `undefined` NO se lista como si no concediera: es el fallo que 3b-2j cierra'
    )
    assert.include(lines[1].message, 'asignaciones VIGENTES: 2')
    assert.notInclude(lines[2].message, 'asignaciones VIGENTES', 'no se inventa un contador que nadie ha contado')
    assert.include(lines[4].message, 'countRoleAssignments', 'y dice QUÉ le falta al driver')

    // Sin huérfanos dudosos no aparece su aviso (y al revés).
    assert.lengthOf(orphanLines([orphan('inerte', false, 0)], new Set(), new Set()), 1)
    const soloDudoso = orphanLines([orphan('dudoso', undefined, undefined)], new Set(), new Set(['uuid-dudoso']))
    assert.lengthOf(soloDudoso, 2)
    assert.include(soloDudoso[0].message, 'saltado (el owner volvió) · NO SE SABE SI CONCEDE')
  })
})

/* ── L-2 · `{ transaction }`: la capacidad `transactionalWrites` y las dos puertas (roles) ── */

test.group('L-2 · {transaction} — la capacidad transactionalWrites y las dos puertas (puerto de roles)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
  })

  const org = (): ScopeRef => ({ type: 'organization', uuid: uuidv7() })
  const user = () => ({ type: 'users', uuid: uuidv7() })
  /** Lo que un `TransactionClientContract` de Lucid le enseña al paquete (la forma, no un motor). */
  const fakeTrx = () => ({ from() {}, table() {}, isTransaction: true as const, connectionName: 'sqlite' })

  /** Driver falso que anota qué se le llama y con qué opciones; `capabilities` a elección. */
  function fakeDriver(capabilities?: Record<string, boolean>) {
    const calls: Array<{ method: string; options?: unknown }> = []
    const driver: any = capabilities === undefined ? {} : { capabilities: Object.freeze({ ...capabilities }) }
    for (const method of ['authorize', 'grant', 'revoke', 'hasRole', 'deny', 'removeDeny', 'listRoles', 'purgeScope', 'onScopeAttached']) {
      driver[method] = async (...args: unknown[]) => {
        calls.push({ method, options: args.at(-1) })
        return method === 'grant' ? { existed: false, expiresAt: null } : method === 'listRoles' ? [] : method === 'authorize' ? false : undefined
      }
    }
    return { driver, calls }
  }

  const NONE_CAPS = {
    hierarchyFacts: false,
    singleCheckAuthorize: false,
    roleInheritanceNative: false,
    listObjectsInherited: false,
    purgeRole: false,
    countRoleAssignments: false,
    canonicalScopeReads: false,
    enumerateFacts: false,
  }

  function managerOver(driver: any, extra: Record<string, unknown> = {}, tree: ContractScopeTree = memoryScopeTree()) {
    const events: AuthzWriteEvent[] = []
    const manager = new AuthorizationManager({
      default: 'fake',
      drivers: { fake: () => driver },
      scopes: { resolveChain: resolveChainFrom(tree) },
      hooks: { onWrite: async (e: AuthzWriteEvent) => void events.push(e) },
      warnOnOptInSecurity: false,
      ...extra,
    } as any)
    return { manager, events }
  }

  async function rejects(assert: any, fn: () => Promise<unknown>, expected: { status: number; code: string }, label: string): Promise<any> {
    try {
      await fn()
    } catch (error: any) {
      assert.equal(error.status, expected.status, `${label}: ${error.message}`)
      assert.equal(error.code, expected.code, `${label}: ${error.message}`)
      return error
    }
    assert.fail(`ROJO: ${label} aceptó { transaction } sin que el driver declare transactionalWrites (debería haber lanzado)`)
  }

  test('puerta 1 · un driver con transactionalWrites: false (o sin capabilities) + { transaction } en grant/revoke/deny/removeDeny ⇒ 500 E_AUTHZ_UNSUPPORTED nombrando driver y operación, CERO llamadas al driver y sin onWrite', async ({
    assert,
  }) => {
    const alice = user()
    const orgA = org()
    const tree = memoryScopeTree()
    await tree.attach(orgA, APP_SCOPE)
    for (const caps of [{ ...NONE_CAPS, transactionalWrites: false }, undefined]) {
      const { driver, calls } = fakeDriver(caps)
      const { manager, events } = managerOver(driver, {}, tree)
      const ops: Array<[string, () => Promise<unknown>]> = [
        ['grant', () => manager.grant(alice, 'editor', orgA, { transaction: fakeTrx() } as any)],
        ['revoke', () => manager.revoke(alice, 'editor', orgA, { transaction: fakeTrx() } as any)],
        ['deny', () => manager.deny(alice, 'docs:read', orgA, { transaction: fakeTrx() } as any)],
        ['removeDeny', () => manager.removeDeny(alice, 'docs:read', orgA, { transaction: fakeTrx() } as any)],
      ]
      for (const [op, run] of ops) {
        const error = await rejects(assert, run, { status: 500, code: 'E_AUTHZ_UNSUPPORTED' }, `${op} (caps=${JSON.stringify(caps?.transactionalWrites)})`)
        assert.include(error.message, `'fake'`, `${op}: nombra el driver`)
        assert.include(error.message, op, `${op}: nombra la operación`)
        assert.include(error.message, 'requireTransactionalWrites', `${op}: la letra lleva la salida (fallar al arrancar)`)
        assert.include(error.message, 'transactionalWrites', `${op}: nombra la capacidad`)
      }
      assert.deepEqual(calls, [], 'cero llamadas al driver')
      assert.deepEqual(events, [], 'una escritura que no ocurre no notifica')
      // Y sin `transaction` la misma llamada llega al driver: la puerta es del parámetro, no del driver.
      await manager.revoke(alice, 'editor', orgA)
      assert.deepEqual(calls.map((c) => c.method), ['revoke'])
    }
  })

  test('puerta 1 · encolar ≠ escribir: scopes.attached con { transaction } NO pasa por la puerta (su transacción ENCOLA en la outbox; sin outbox no hace nada) y llega al driver', async ({
    assert,
  }) => {
    const orgA = org()
    const tree = memoryScopeTree()
    const { driver, calls } = fakeDriver({ ...NONE_CAPS, transactionalWrites: false })
    const { manager } = managerOver(driver, {}, tree)
    await tree.attach(orgA, APP_SCOPE)
    await manager.scopes.attached(orgA, APP_SCOPE, { transaction: fakeTrx() })
    assert.deepEqual(calls.map((c) => c.method), ['onScopeAttached'], 'la notificación del árbol no es una escritura de hechos')
  })

  test('puerta 1 · con transactionalWrites: true la puerta se abre: { transaction } llega al driver tal cual (lo que haga con ella es L-3)', async ({
    assert,
  }) => {
    const alice = user()
    const orgA = org()
    const tree = memoryScopeTree()
    await tree.attach(orgA, APP_SCOPE)
    const { driver, calls } = fakeDriver({ ...NONE_CAPS, transactionalWrites: true })
    const { manager, events } = managerOver(driver, {}, tree)
    const trx = fakeTrx()
    await manager.grant(alice, 'editor', orgA, { transaction: trx } as any)
    await manager.deny(alice, 'docs:read', orgA, { transaction: trx } as any)
    assert.deepEqual(calls.map((c) => c.method), ['grant', 'deny'])
    assert.strictEqual((calls[0].options as any)?.transaction, trx, 'el driver recibe la transacción del llamante')
    assert.deepEqual(events.map((e) => e.action), ['granted', 'denied'])
  })

  test('puerta 1 · la API de delegación NO recibe { transaction } (fuera de alcance, §1.4: withAuthzCatalogWrite serializa el catálogo): 500 E_AUTHZ_UNSUPPORTED antes de tocar nada, también con un driver capaz', async ({
    assert,
  }) => {
    const admin = user()
    const orgA = org()
    const tree = memoryScopeTree()
    await tree.attach(orgA, APP_SCOPE)
    const { driver, calls } = fakeDriver({ ...NONE_CAPS, transactionalWrites: true, purgeRole: true })
    const { manager } = managerOver(driver, { delegablePermissions: ['docs:read'] }, tree)
    const spec = { slug: 'lead', scopeType: 'organization', permissions: ['docs:read'], rank: 1 }
    const ops: Array<[string, () => Promise<unknown>]> = [
      ['defineScopedRole', () => manager.defineScopedRole(admin, orgA, spec as any, { transaction: fakeTrx() } as any)],
      ['updateScopedRole', () => manager.updateScopedRole(admin, uuidv7(), { rank: 2 }, { transaction: fakeTrx() } as any)],
      ['deleteScopedRole', () => manager.deleteScopedRole(admin, uuidv7(), { transaction: fakeTrx() } as any)],
    ]
    for (const [op, run] of ops) {
      const error = await rejects(assert, run, { status: 500, code: 'E_AUTHZ_UNSUPPORTED' }, op)
      assert.include(error.message, op)
      assert.include(error.message, 'withAuthzCatalogWrite', `${op}: dice POR QUÉ no entra en tu transacción`)
    }
    assert.deepEqual(calls, [])
  })

  test('puerta 2 · requireTransactionalWrites: true + un driver que declara false (o nada) ⇒ 500 E_AUTHZ_CONFIG al RESOLVER el driver (también las lecturas: el despliegue no arranca); con un driver capaz resuelve; sin el flag, el driver incapaz resuelve (opt-in)', async ({
    assert,
  }) => {
    const alice = user()
    for (const caps of [{ ...NONE_CAPS, transactionalWrites: false }, undefined]) {
      const { driver, calls } = fakeDriver(caps)
      const { manager } = managerOver(driver, { requireTransactionalWrites: true })
      const error = await rejects(assert, () => manager.driver(), { status: 500, code: 'E_AUTHZ_CONFIG' }, `driver() (caps=${JSON.stringify(caps?.transactionalWrites)})`)
      assert.include(error.message, `'fake'`)
      assert.include(error.message, 'transactionalWrites')
      assert.include(error.message, 'requireTransactionalWrites')
      // Es al RESOLVER: una lectura tampoco pasa, y el driver no se toca.
      await rejects(assert, () => manager.authorize(alice, 'docs:read', APP_SCOPE), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'authorize')
      await rejects(assert, () => manager.grant(alice, 'editor', APP_SCOPE), { status: 500, code: 'E_AUTHZ_CONFIG' }, 'grant sin transaction')
      assert.deepEqual(calls, [])
      // Sin el flag es opt-in: el mismo driver resuelve.
      assert.strictEqual(await managerOver(driver).manager.driver(), driver)
    }
    const capable = fakeDriver({ ...NONE_CAPS, transactionalWrites: true })
    assert.strictEqual(await managerOver(capable.driver, { requireTransactionalWrites: true }).manager.driver(), capable.driver)
  })
})
