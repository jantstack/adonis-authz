/**
 * El middleware `resourceAccess` es el borde HTTP del acceso A UN RECURSO
 * concreto: compone el `authorize` que ya existe sobre el `{ scope }` que el
 * consumidor devuelve al CARGAR el recurso. Lo que se prueba aquí NO es la
 * decisión (eso lo juzga el contrato del driver) sino el ORDEN de las
 * respuestas, que ES la propiedad de seguridad:
 *
 *   401 (sin usuario) → 403 (gate del consumidor) → 404 (contenedor) →
 *   404 (recurso ausente, MISMO cuerpo) → authorize (false ⇒ 404, MISMO cuerpo).
 *
 * Un 403 donde debería ir un 404 filtra qué recursos existen (enumeración);
 * un `AuthorizationBackendError` disfrazado de 404 confunde «no pude comprobar»
 * con «no existe». Ninguno de los dos puede pasar.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import ResourceAccessMiddleware from '../src/http/resource_access_middleware.js'
import authorization from '../services/main.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { APP_SCOPE } from '../src/types.js'
import { AuthorizationBackendError } from '../src/errors.js'
import { cleanAuthzTables } from './helpers/schema.js'

/**
 * Doble del `HttpContext` de Adonis para el borde HTTP. Registra:
 *  - el ORDEN de las respuestas (`responses`, con su status y cuerpo),
 *  - un `next` con contador (`nextCalls`) — el camino feliz llama a `next`
 *    UNA sola vez y nada más,
 *  - lo que se PROPAGA al controlador (`ctx[resource]`),
 *  - los `params` de ruta y el método HTTP que el middleware consulta.
 */
function fakeCtx(opts: {
  user?: any
  params?: Record<string, any>
  method?: string
} = {}) {
  const responses: Array<{ status: number; body: any }> = []
  const ctx: any = {
    auth: { user: opts.user },
    params: opts.params ?? {},
    request: { method: () => opts.method ?? 'GET' },
    response: {
      unauthorized: (body: any) => responses.push({ status: 401, body }),
      forbidden: (body: any) => responses.push({ status: 403, body }),
      notFound: (body: any) => responses.push({ status: 404, body }),
    },
  }
  let nextCalls = 0
  const next = async () => void nextCalls++
  return { ctx, responses, next, get nextCalls() { return nextCalls } }
}

function holder(uuid: string | undefined, morph = 'users') {
  return { uuid, __morphMapName: morph }
}

/** `load` que devuelve el recurso en `app` y cuenta cuántas veces se le llamó. */
function loaderAt(scope = APP_SCOPE) {
  let calls = 0
  const load: any = async () => {
    calls++
    return { id: 'r1', scope }
  }
  // defineProperty conserva el GETTER (Object.assign lo aplanaría a un valor).
  Object.defineProperty(load, 'calls', { get: () => calls })
  return load as (() => Promise<{ id: string; scope: typeof scope }>) & { readonly calls: number }
}

function baseOptions(over: Partial<Record<string, any>> = {}) {
  return {
    resource: 'document',
    param: 'id',
    permission: 'docs:write',
    readPermission: 'docs:read',
    load: loaderAt(),
    ...over,
  }
}

test.group('middleware resourceAccess', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [
        { slug: 'reader', scopeType: 'app', permissions: ['docs:read'] },
        { slug: 'writer', scopeType: 'app', permissions: ['docs:read', 'docs:write'] },
      ],
    })
  })

  // ── Configuración (500, antes de mirar si hay usuario) ──────────────────

  test('sin `permission` en las opciones es un error de programación (500)', async ({ assert }) => {
    const { ctx, responses, next } = fakeCtx({ user: holder(uuidv7()) })
    let caught: any
    try {
      await new ResourceAccessMiddleware().handle(ctx, next, { param: 'id', load: async () => null } as any)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_CONFIG')
    assert.lengthOf(responses, 0)
  })

  test('sin `param` o sin `load` es 500 E_AUTHZ_CONFIG', async ({ assert }) => {
    for (const opts of [
      { permission: 'docs:write', load: async () => null },
      { permission: 'docs:write', param: 'id' },
    ]) {
      const { ctx, next } = fakeCtx({ user: holder(uuidv7()) })
      let caught: any
      try {
        await new ResourceAccessMiddleware().handle(ctx, next, opts as any)
        assert.fail('debería haber lanzado')
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 500)
      assert.equal(caught.code, 'E_AUTHZ_CONFIG')
    }
  })

  test('resourceAccess({ role }) es 500 E_AUTHZ_ROLE_IS_NOT_ACCESS con la receta', async ({
    assert,
  }) => {
    // Como appAccess: `role` es membresía y el deny no la gobierna. Prohibido,
    // lanza antes de mirar si hay usuario, aunque venga con `permission`.
    const { ctx, responses, next } = fakeCtx({ user: holder(uuidv7()) })
    let caught: any
    try {
      await new ResourceAccessMiddleware().handle(ctx, next, baseOptions({ role: 'writer' }) as any)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_ROLE_IS_NOT_ACCESS')
    assert.include(caught.message, '{ permission')
    assert.lengthOf(responses, 0)
  })

  // ── 1. 401 ──────────────────────────────────────────────────────────────

  test('sin autenticar responde 401 y no carga el recurso', async ({ assert }) => {
    const load = loaderAt()
    const h = fakeCtx({ params: { id: 'r1' } })
    await new ResourceAccessMiddleware().handle(h.ctx, h.next, baseOptions({ load }))
    assert.equal(h.responses[0].status, 401)
    assert.equal(load.calls, 0)
    assert.equal(h.nextCalls, 0)
  })

  test('un holder sin @MorphMap o sin uuid es 500, no un 404', async ({ assert }) => {
    for (const user of [{ uuid: uuidv7() }, holder(undefined)]) {
      const { ctx, next } = fakeCtx({ user, params: { id: 'r1' } })
      await assert.rejects(() =>
        new ResourceAccessMiddleware().handle(ctx, next, baseOptions())
      )
    }
  })

  // ── 2. 403 gate ─────────────────────────────────────────────────────────

  test('el gate del consumidor niega ⇒ 403, sin cargar el recurso ni autorizar', async ({
    assert,
  }) => {
    const load = loaderAt()
    let authorized = 0
    const orig = authorization.authorize.bind(authorization)
    authorization.authorize = async (...a: any[]) => {
      authorized++
      return (orig as any)(...a)
    }
    try {
      const h = fakeCtx({
        user: holder(uuidv7()),
        params: { id: 'r1' },
      })
      await new ResourceAccessMiddleware().handle(
        h.ctx,
        h.next,
        baseOptions({ load, gate: async () => false })
      )
      assert.equal(h.responses[0].status, 403)
      assert.equal(load.calls, 0, 'el gate va ANTES de cargar el recurso')
      assert.equal(authorized, 0)
      assert.equal(h.nextCalls, 0)
    } finally {
      authorization.authorize = orig
    }
  })

  // ── 3. 404 contenedor (antes que el recurso) ────────────────────────────

  test('contenedor ausente ⇒ 404 y NO se carga el recurso (contenedor antes que recurso)', async ({
    assert,
  }) => {
    const load = loaderAt()
    const { ctx, responses, next } = fakeCtx({ user: holder(uuidv7()), params: { id: 'r1' } })
    await new ResourceAccessMiddleware().handle(
      ctx,
      next,
      baseOptions({ load, containerParam: 'orgId' })
    )
    assert.equal(responses[0].status, 404)
    assert.equal(load.calls, 0, 'el contenedor se comprueba ANTES de cargar el recurso')
  })

  // ── 4. 404 recurso (mismo cuerpo que el contenedor) ─────────────────────

  test('recurso ausente (load ⇒ null) es 404 con el MISMO cuerpo que el contenedor', async ({
    assert,
  }) => {
    // Contenedor ausente
    const c = fakeCtx({ user: holder(uuidv7()), params: { id: 'r1' } })
    await new ResourceAccessMiddleware().handle(
      c.ctx,
      c.next,
      baseOptions({ containerParam: 'orgId' })
    )
    // Recurso ausente
    const r = fakeCtx({ user: holder(uuidv7()), params: { id: 'r1' } })
    await new ResourceAccessMiddleware().handle(r.ctx, r.next, baseOptions({ load: async () => null }))

    assert.equal(c.responses[0].status, 404)
    assert.equal(r.responses[0].status, 404)
    assert.deepEqual(r.responses[0].body, c.responses[0].body)
  })

  // ── 5. authorize false ⇒ 404 (NO 403), mismo cuerpo ─────────────────────

  test('authorize false es 404 (no 403) con el MISMO cuerpo — que no lo veas no revela que existe', async ({
    assert,
  }) => {
    // El holder no tiene el permiso: la decisión es negativa, pero la
    // respuesta NO puede ser un 403 (eso confirmaría que el recurso existe).
    const r = fakeCtx({ user: holder(uuidv7()), params: { id: 'r1' }, method: 'POST' })
    await new ResourceAccessMiddleware().handle(r.ctx, r.next, baseOptions())

    // Cuerpo idéntico al 404 de un recurso ausente
    const absent = fakeCtx({ user: holder(uuidv7()), params: { id: 'r1' } })
    await new ResourceAccessMiddleware().handle(
      absent.ctx,
      absent.next,
      baseOptions({ load: async () => null })
    )

    assert.equal(r.responses[0].status, 404)
    assert.notEqual(r.responses[0].status, 403)
    assert.deepEqual(r.responses[0].body, absent.responses[0].body)
  })

  // ── AuthorizationBackendError (503) NUNCA disfrazado de 404 ──────────────

  test('backend caído en authorize ⇒ 503 propagado, jamás un 404', async ({ assert }) => {
    const orig = authorization.authorize.bind(authorization)
    authorization.authorize = async () => {
      throw new AuthorizationBackendError('database', 'authorize', new Error('down'))
    }
    try {
      const { ctx, responses, next } = fakeCtx({ user: holder(uuidv7()), params: { id: 'r1' } })
      let caught: any
      try {
        await new ResourceAccessMiddleware().handle(ctx, next, baseOptions())
        assert.fail('debería haber propagado el 503')
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 503)
      assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
      assert.lengthOf(responses, 0, 'no se disfraza de 404')
    } finally {
      authorization.authorize = orig
    }
  })

  test('un `load` que LANZA (no pudo comprobar) propaga, no se convierte en 404', async ({
    assert,
  }) => {
    // Distingue «no existe» (load ⇒ null ⇒ 404) de «no pude comprobar»
    // (load lanza ⇒ el error sube tal cual).
    const load = async () => {
      throw new AuthorizationBackendError('database', 'load', new Error('down'))
    }
    const { ctx, responses, next } = fakeCtx({ user: holder(uuidv7()), params: { id: 'r1' } })
    let caught: any
    try {
      await new ResourceAccessMiddleware().handle(ctx, next, baseOptions({ load }))
      assert.fail('debería haber propagado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 503)
    assert.lengthOf(responses, 0)
  })

  // ── readPermission (GET) vs permission (POST) ───────────────────────────

  test('un GET usa readPermission; un POST usa permission (una sola autorización)', async ({
    assert,
  }) => {
    const seen: Array<{ permission: string }> = []
    const orig = authorization.authorize.bind(authorization)
    authorization.authorize = async (subject: any, permission: string, scope: any) => {
      seen.push({ permission })
      return (orig as any)(subject, permission, scope)
    }
    try {
      const uuid = uuidv7()
      await authorization.grant({ type: 'users', uuid }, 'writer', APP_SCOPE)

      const g = fakeCtx({ user: holder(uuid), params: { id: 'r1' }, method: 'GET' })
      await new ResourceAccessMiddleware().handle(g.ctx, g.next, baseOptions())
      assert.equal(g.nextCalls, 1)

      const p = fakeCtx({ user: holder(uuid), params: { id: 'r1' }, method: 'POST' })
      await new ResourceAccessMiddleware().handle(p.ctx, p.next, baseOptions())
      assert.equal(p.nextCalls, 1)

      assert.deepEqual(
        seen.map((s) => s.permission),
        ['docs:read', 'docs:write'],
        'GET ⇒ readPermission, POST ⇒ permission'
      )
      assert.lengthOf(seen, 2, 'una sola autorización por request')
    } finally {
      authorization.authorize = orig
    }
  })

  test('sin readPermission, un GET cae en `permission` (una lectura nunca es gratis)', async ({
    assert,
  }) => {
    const seen: string[] = []
    const orig = authorization.authorize.bind(authorization)
    authorization.authorize = async (subject: any, permission: string, scope: any) => {
      seen.push(permission)
      return (orig as any)(subject, permission, scope)
    }
    try {
      const g = fakeCtx({ user: holder(uuidv7()), params: { id: 'r1' }, method: 'GET' })
      await new ResourceAccessMiddleware().handle(
        g.ctx,
        g.next,
        baseOptions({ readPermission: undefined })
      )
      assert.deepEqual(seen, ['docs:write'])
    } finally {
      authorization.authorize = orig
    }
  })

  // ── Camino feliz: next una vez + scope propagado + un solo authorize ────

  test('camino feliz: next UNA vez, el recurso propagado al controlador, un solo authorize', async ({
    assert,
  }) => {
    let authorized = 0
    const orig = authorization.authorize.bind(authorization)
    authorization.authorize = async (...a: any[]) => {
      authorized++
      return (orig as any)(...a)
    }
    try {
      const uuid = uuidv7()
      await authorization.grant({ type: 'users', uuid }, 'writer', APP_SCOPE)

      const load = loaderAt()
      const h = fakeCtx({
        user: holder(uuid),
        params: { id: 'r1' },
        method: 'POST',
      })
      await new ResourceAccessMiddleware().handle(h.ctx, h.next, baseOptions({ load }))

      assert.lengthOf(h.responses, 0, 'ninguna respuesta de error')
      assert.equal(h.nextCalls, 1, 'next exactamente una vez')
      assert.equal(load.calls, 1)
      assert.equal(authorized, 1, 'authorize se llama UNA vez, no re-autoriza')
      // El recurso cargado (con su scope) llega al controlador
      assert.deepEqual((h.ctx as any).document, { id: 'r1', scope: APP_SCOPE })
    } finally {
      authorization.authorize = orig
    }
  })

  test('un deny explícito sobre el recurso concedido es 404 (no 403)', async ({ assert }) => {
    const uuid = uuidv7()
    await authorization.grant({ type: 'users', uuid }, 'writer', APP_SCOPE)
    await authorization.deny({ type: 'users', uuid }, 'docs:write', APP_SCOPE)

    const { ctx, responses, next } = fakeCtx({
      user: holder(uuid),
      params: { id: 'r1' },
      method: 'POST',
    })
    await new ResourceAccessMiddleware().handle(ctx, next, baseOptions())
    assert.equal(responses[0].status, 404)
  })
})
