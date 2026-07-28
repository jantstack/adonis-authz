/**
 * El middleware `appAccess` es el borde HTTP del motor: traduce el holder
 * autenticado a un subject y pregunta. Lo que importa aquí es que falle
 * CERRADO y que, cuando falla por configuración, lo diga.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import AppAccessMiddleware from '../src/middleware/app_access_middleware.js'
import authorization from '../services/main.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { APP_SCOPE } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'

function fakeCtx(user?: any) {
  const responses: Array<{ status: number; body: any }> = []
  const ctx: any = {
    auth: { user },
    response: {
      unauthorized: (body: any) => responses.push({ status: 401, body }),
      forbidden: (body: any) => responses.push({ status: 403, body }),
    },
  }
  return { ctx, responses }
}

function holder(uuid: string | undefined, morph = 'users') {
  return { uuid, __morphMapName: morph }
}

test.group('middleware appAccess', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  test('sin permiso ni rol en las opciones es un error de programación', async ({ assert }) => {
    const { ctx } = fakeCtx(holder(uuidv7()))
    await assert.rejects(() => new AppAccessMiddleware().handle(ctx, async () => {}, {}))
  })

  test('sin autenticar responde 401', async ({ assert }) => {
    const { ctx, responses } = fakeCtx(undefined)
    let advanced = false
    await new AppAccessMiddleware().handle(ctx, async () => void (advanced = true), {
      permission: 'docs:read',
    })

    assert.isFalse(advanced)
    assert.equal(responses[0].status, 401)
  })

  test('un holder sin @MorphMap no es un holder válido', async ({ assert }) => {
    const { ctx } = fakeCtx({ uuid: uuidv7() })
    await assert.rejects(
      () => new AppAccessMiddleware().handle(ctx, async () => {}, { permission: 'docs:read' }),
      /MorphMap/
    )
  })

  test('un holder sin uuid lo dice, en vez de reventar en la capa de SQL', async ({ assert }) => {
    // Un modelo con primary key numérica llega con uuid undefined. Fallaba
    // igual (cerrado), pero con un error de Knex que no señalaba la causa.
    const { ctx } = fakeCtx(holder(undefined))
    await assert.rejects(
      () => new AppAccessMiddleware().handle(ctx, async () => {}, { permission: 'docs:read' }),
      /no expone 'uuid'/
    )
  })

  test('sin el permiso requerido responde 403 y no continúa', async ({ assert }) => {
    const { ctx, responses } = fakeCtx(holder(uuidv7()))
    let advanced = false
    await new AppAccessMiddleware().handle(ctx, async () => void (advanced = true), {
      permission: 'docs:read',
    })

    assert.isFalse(advanced)
    assert.equal(responses[0].status, 403)
  })

  test('con el rol concedido continúa', async ({ assert }) => {
    const uuid = uuidv7()
    await authorization.grant({ type: 'users', uuid }, 'editor', APP_SCOPE)

    const { ctx, responses } = fakeCtx(holder(uuid))
    let advanced = false
    await new AppAccessMiddleware().handle(ctx, async () => void (advanced = true), {
      permission: 'docs:read',
    })

    assert.isTrue(advanced)
    assert.lengthOf(responses, 0)
  })

  test('un deny explícito gana sobre el rol concedido', async ({ assert }) => {
    const uuid = uuidv7()
    await authorization.grant({ type: 'users', uuid }, 'editor', APP_SCOPE)
    await authorization.deny({ type: 'users', uuid }, 'docs:read', APP_SCOPE)

    const { ctx, responses } = fakeCtx(holder(uuid))
    let advanced = false
    await new AppAccessMiddleware().handle(ctx, async () => void (advanced = true), {
      permission: 'docs:read',
    })

    assert.isFalse(advanced)
    assert.equal(responses[0].status, 403)
  })

  test('el mismo uuid con otro morph no se cuela', async ({ assert }) => {
    const uuid = uuidv7()
    await authorization.grant({ type: 'users', uuid }, 'editor', APP_SCOPE)

    const { ctx, responses } = fakeCtx(holder(uuid, 'admins'))
    let advanced = false
    await new AppAccessMiddleware().handle(ctx, async () => void (advanced = true), {
      permission: 'docs:read',
    })

    assert.isFalse(advanced)
    assert.equal(responses[0].status, 403)
  })
})
