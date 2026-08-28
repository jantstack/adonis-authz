/**
 * Unitarios del driver database que no caben en el contrato: bordes internos
 * que hoy ningún call-site alcanza pero que Fase 2 (`descendantsOf`,
 * `authorizedScopes`) volverá alcanzables. Se fijan ANTES.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { DatabaseAuthorizationDriver, whereScopeIn } from '../src/drivers/database_driver.js'
import { AuthorizationBackendError } from '../src/errors.js'
import { APP_SCOPE } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { countQueries } from './helpers/spies.js'

test.group('database — whereScopeIn con conjunto vacío (L0.1)', () => {
  test('en lectura devuelve null sin ejecutar ninguna consulta', async ({ assert }) => {
    // La asimetría que lo hace peligroso: sin filtro de scope, la consulta
    // de denies sobre-bloquea (cerrado) pero la de asignaciones concede en
    // CUALQUIER scope (abierto). Un conjunto vacío no puede llegar a SQL.
    const { result, queries } = await countQueries(async () =>
      whereScopeIn(db.from('authz_assignments'), 'scope', [], 'read')
    )
    assert.isNull(result)
    assert.lengthOf(queries, 0)
  })

  test('en escritura lanza 500 E_AUTHZ_INTERNAL: es un bug, no un no-op', async ({ assert }) => {
    let caught: any
    try {
      whereScopeIn(db.from('authz_assignments'), 'scope', [], 'write')
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_INTERNAL')
  })

  test('con scopes sí filtra y ejecuta exactamente una consulta', async ({ assert }) => {
    const { queries } = await countQueries(async () => {
      const query = whereScopeIn(db.from('authz_assignments'), 'scope', [APP_SCOPE], 'read')
      assert.isNotNull(query)
      await query!.first()
    })
    assert.lengthOf(queries, 1)
    assert.include(queries[0].sql, 'scope_type')
    assert.include(queries[0].sql, 'scope_uuid')
  })
})

/**
 * Renombra una tabla `authz_*` mientras corre `fn` (y la restaura): la forma
 * más barata de simular "la base no responde" en SQLite en memoria sin cerrar
 * el pool (que es de una sola conexión para toda la suite).
 */
export async function withTableMissing<T>(table: string, fn: () => Promise<T>): Promise<T> {
  const knex = db.connection().getWriteClient()
  await knex.schema.renameTable(table, `${table}_missing`)
  try {
    return await fn()
  } finally {
    await knex.schema.renameTable(`${table}_missing`, table)
  }
}

test.group('database — la base local caída es un 503, no un error crudo (L0.11)', () => {
  test('authorize con el catálogo inaccesible lanza AuthorizationBackendError', async ({ assert }) => {
    // Hoy escapaba un `SqliteError` sin status ni code: el manejador de
    // Adonis respondía 500 y distinguir "backend caído" obligaba a importar
    // el error de Lucid — justo lo que `errors.ts` existe para evitar.
    const driver = new DatabaseAuthorizationDriver()
    let caught: any
    await withTableMissing('authz_permissions', async () => {
      try {
        await driver.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE)
        assert.fail('debería haber lanzado')
      } catch (error) {
        caught = error
      }
    })
    assert.instanceOf(caught, AuthorizationBackendError)
    assert.equal(caught.status, 503)
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    assert.exists(caught.cause)
  })

  test('las escrituras también: grant sin la tabla de roles ⇒ 503', async ({ assert }) => {
    const driver = new DatabaseAuthorizationDriver()
    let caught: any
    await withTableMissing('authz_roles', async () => {
      try {
        await driver.grant({ type: 'users', uuid: uuidv7() }, 'editor', APP_SCOPE)
        assert.fail('debería haber lanzado')
      } catch (error) {
        caught = error
      }
    })
    assert.equal(caught.status, 503)
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
  })

  test('un error semántico no se disfraza de caída: rol inexistente sigue siendo 422', async ({
    assert,
  }) => {
    await cleanAuthzTables()
    const driver = new DatabaseAuthorizationDriver()
    let caught: any
    try {
      await driver.grant({ type: 'users', uuid: uuidv7() }, 'no-existe', APP_SCOPE)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 422)
  })
})

test.group('database — deadline en cada consulta (L0.13)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  test('toda consulta sale con el timeout configurado (default 5000 ms)', async ({ assert }) => {
    // SQLite en memoria es síncrono: el deadline nunca vence aquí, así que lo
    // observable es que CADA consulta lo lleva puesto (es lo que PG/MySQL
    // ejecutarán). Un call-site nuevo que se olvide del `sql()` aparecería
    // aquí con `timeout: false`.
    const alice = { type: 'users', uuid: uuidv7() }
    const byDefault = new DatabaseAuthorizationDriver()
    const { queries } = await countQueries(async () => {
      await byDefault.grant(alice, 'editor', APP_SCOPE)
      await byDefault.authorize(alice, 'docs:read', APP_SCOPE)
      await byDefault.deny(alice, 'docs:read', APP_SCOPE)
      await byDefault.listScopes(alice, 'docs:read')
      await byDefault.listRoles(alice, APP_SCOPE)
      await byDefault.listSubjects('editor', APP_SCOPE)
      await byDefault.listRoleScopes(alice, 'app')
      await byDefault.hasRole(alice, 'editor', APP_SCOPE)
      await byDefault.removeDeny(alice, 'docs:read', APP_SCOPE)
      await byDefault.revoke(alice, 'editor', APP_SCOPE)
    })
    assert.isAbove(queries.length, 10)
    assert.deepEqual(
      queries.map((q) => q.timeout),
      queries.map(() => 5_000)
    )

    const configured = new DatabaseAuthorizationDriver({ timeoutMs: 250 })
    const { queries: fast } = await countQueries(() =>
      configured.authorize(alice, 'docs:read', APP_SCOPE)
    )
    assert.isNotEmpty(fast)
    assert.deepEqual(
      fast.map((q) => q.timeout),
      fast.map(() => 250)
    )
  })
})
