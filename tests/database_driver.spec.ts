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
import type { ScopeRef } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { countQueries } from './helpers/spies.js'
import { withTableMissing } from './helpers/table_missing.js'

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
      // La purga va en transacción y una transacción no es un builder: los
      // DELETE salían sin deadline (D4, auditor H13).
      await byDefault.purgeScope({ type: 'organization', uuid: uuidv7() })
    })
    assert.isAbove(queries.length, 10)
    assert.isNotEmpty(queries.filter((q) => /^delete/i.test(q.sql) && /authz_denies/.test(q.sql)))
    // `BEGIN;`/`COMMIT;` los emite knex al abrir y cerrar la transacción de la
    // purga: no son consultas del driver y no admiten `.timeout()`. Todo lo
    // demás —los DELETE incluidos— sale con el deadline.
    const built = queries.filter((q) => !/^(BEGIN|COMMIT|ROLLBACK)/i.test(q.sql))
    assert.equal(queries.length - built.length, 2)
    assert.deepEqual(
      built.map((q) => q.timeout),
      built.map(() => 5_000)
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


/**
 * Gemelo en `database` de la promesa del README ("Operational": un rol
 * retirado del catálogo ⇒ la asignación que quedó no concede nada). Aquí no
 * hay tupla en otro sistema: la asignación vive en la misma base, así que lo
 * que se fija es que el mapa permiso→rol se lee SIEMPRE del catálogo y una
 * asignación sin vínculo vigente no puede conceder.
 */
test.group('database — un rol retirado del catálogo no concede', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  test('quitar el vínculo rol→permiso deja la asignación sin nada que conceder', async ({
    assert,
  }) => {
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))

    const role: any = await db.from('authz_roles').where('slug', 'editor').first()
    await db.from('authz_role_permissions').where('role_uuid', role.uuid).delete()

    // La membresía sigue (es un hecho), el acceso no.
    assert.isTrue(await driver.hasRole(alice, 'editor', APP_SCOPE))
    assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
  })
})

/**
 * Gemelo del caso «la raíz no se purga: 422» que openfga ya tenía. En
 * `database` la guarda existía sin caso: sin ella, `purgeScope(APP_SCOPE)`
 * traduce la raíz al uuid centinela y BORRA todas las asignaciones y denies
 * del nivel plataforma. El manager lo impide por su lado, pero el driver es
 * público (el juez y un consumidor pueden llamarlo directo).
 */
test.group('database — la raíz no se purga', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [
        { slug: 'editor', scopeType: 'app', permissions: ['docs:read'] },
        // Para el caso de M13, que necesita hechos en un scope intermedio.
        { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] },
      ],
    })
  })

  test('purgeScope(APP_SCOPE) es 422 y no toca los hechos del nivel app', async ({ assert }) => {
    const driver = new DatabaseAuthorizationDriver()
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    await driver.deny(alice, 'docs:read', APP_SCOPE)

    let caught: any
    try {
      await driver.purgeScope(APP_SCOPE)
      assert.fail('debería haber rechazado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 422)
    assert.equal(caught.code, 'E_AUTHZ_INVALID_IDENTITY')

    assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), ['editor'])
    assert.lengthOf(await db.from('authz_denies').select('uuid'), 1)
  })

  test('3b-1 · M13: purgeScope purga por la identidad CANÓNICA del árbol (canonicalScope), no por la que trajo el llamante — y sin árbol, o con un scope que el árbol no conoce, purga la forma tal cual sin tocar la canónica', async ({
    assert,
  }) => {
    // La canonización que hace el DRIVER dentro de `purgeScope` (invariante
    // 17) no tenía oráculo en ningún motor: `chain[0]` la fija para grant /
    // deny / list*, y el caso del contrato que mira el alias (2.5-B · K1)
    // solo la observa donde el árbol canoniza de verdad (el tipo `uuid` de
    // PostgreSQL). Aquí el árbol canoniza SIEMPRE: un resolutor que funde el
    // alias sin guiones con la fila real, que es exactamente lo que hace PG.
    const canonico: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const alias: ScopeRef = { type: 'organization', uuid: canonico.uuid!.replaceAll('-', '') }
    const resolveChain = async (scope: ScopeRef) => {
      if (scope.type === 'app') return [APP_SCOPE]
      if (scope.uuid === canonico.uuid || scope.uuid === alias.uuid) return [canonico, APP_SCOPE]
      return null
    }
    const driver = new DatabaseAuthorizationDriver({ resolveChain })
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'org-editor', canonico)
    await driver.deny(alice, 'docs:read', canonico)
    const filas = async () => ({
      asignaciones: (await db.from('authz_assignments').select('scope_uuid')).map((r: any) => String(r.scope_uuid)),
      denies: (await db.from('authz_denies').select('scope_uuid')).map((r: any) => String(r.scope_uuid)),
    })
    assert.deepEqual(await filas(), { asignaciones: [canonico.uuid], denies: [canonico.uuid] }, 'los hechos se escriben bajo chain[0]')

    // Un scope que el árbol NO conoce: `canonicalScope` deja la forma tal
    // cual y se purga esa; los hechos canónicos no se tocan.
    await driver.purgeScope({ type: 'organization', uuid: uuidv7() })
    assert.deepEqual(await filas(), { asignaciones: [canonico.uuid], denies: [canonico.uuid] }, 'un scope ajeno no arrastra nada')

    // El ALIAS resuelve a la fila canónica ⇒ purga los hechos canónicos.
    await driver.purgeScope(alias)
    assert.deepEqual(await filas(), { asignaciones: [], denies: [] }, 'purgeScope(alias) purga la forma CANÓNICA')

    // Y sin resolutor (`rootOnlyResolver`) la forma tal cual es la que manda:
    // el scope no se puede canonizar, y purgar el alias NO puede llevarse los
    // hechos del canónico (los borraría a ciegas).
    const sinArbol = new DatabaseAuthorizationDriver()
    await driver.grant(alice, 'org-editor', canonico)
    await sinArbol.purgeScope(alias)
    assert.deepEqual((await filas()).asignaciones, [canonico.uuid], 'sin árbol no se inventa una canonización')
    await sinArbol.purgeScope(canonico)
    assert.deepEqual((await filas()).asignaciones, [], 'y la forma exacta sí purga')
  })
})

/**
 * `hasRole` filtra por NIVEL con `r.scope_type = a.scope_type` (L0.6). Hoy
 * `grant` ya garantiza la correspondencia (resuelve el rol para el tipo del
 * scope), así que la cláusula es defensa en profundidad y ningún caso del
 * contrato la alcanza: se prueba con una fila escrita a mano, que es lo que
 * dejaría una migración vieja o un import mal hecho.
 */
test.group('database — una asignación con el rol de OTRO nivel no cuenta', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [
        { slug: 'owner', scopeType: 'app', permissions: ['docs:read'] },
        { slug: 'owner', scopeType: 'organization', permissions: ['docs:read'] },
      ],
    })
  })

  test('un rol de nivel app asignado a un scope de organización no da hasRole', async ({
    assert,
  }) => {
    const org = { type: 'organization', uuid: uuidv7() }
    const driver = new DatabaseAuthorizationDriver({
      resolveChain: async (scope) => (scope.type === 'organization' ? [scope, APP_SCOPE] : null),
    })
    const bob = { type: 'users', uuid: uuidv7() }

    const appOwner: any = await db
      .from('authz_roles')
      .where('slug', 'owner')
      .where('scope_type', 'app')
      .first()

    // Fila imposible por la API: el rol es de nivel `app` y el scope es una org.
    await db.table('authz_assignments').insert({
      uuid: uuidv7(),
      holder_type: bob.type,
      holder_uuid: bob.uuid,
      role_uuid: appOwner.uuid,
      scope_type: org.type,
      scope_uuid: org.uuid,
      expires_at: null,
      created_at: new Date(),
    })

    assert.isFalse(await driver.hasRole(bob, 'owner', org))
    assert.isFalse(await driver.hasRole(bob, { slug: 'owner', scopeType: 'organization' }, org))
  })
})

test.group('database — la identidad de un scope es una cadena, no un UUID del motor (2.5 · J3, 2.5-B · K1)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] }],
    })
  })

  test("un scope con id que no es UUID ('org-tenant-a') se escribe, concede, se lista y se purga en todos los motores", async ({
    assert,
  }) => {
    // Vivía en el juez; con el árbol SQL del harness (columna `uuid` en PG)
    // un id así no puede colgarse, y aquí el árbol es un mapa: lo que se
    // observa es `scope_uuid varchar(64)` en `authz_*`, en los tres motores.
    const org: ScopeRef = { type: 'organization', uuid: 'org-tenant-a' }
    const driver = new DatabaseAuthorizationDriver({
      resolveChain: async (scope) => (scope.type === 'organization' && scope.uuid === org.uuid ? [org, APP_SCOPE] : null),
    })
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'org-editor', org)
    assert.isTrue(await driver.authorize(alice, 'docs:read', org))
    assert.deepEqual(await driver.listRoles(alice, org), ['org-editor'])
    assert.deepEqual(await driver.listRoleScopes(alice, 'organization'), [org])
    assert.deepEqual(await driver.listScopes(alice, 'docs:read'), [org])
    await driver.deny(alice, 'docs:read', org)
    assert.isFalse(await driver.authorize(alice, 'docs:read', org))
    await driver.purgeScope(org)
    assert.deepEqual(await driver.listRoles(alice, org), [])
    assert.isFalse(await driver.authorize(alice, 'docs:read', org))
  })
})

test.group('database — re-grant sobre una fila que desaparece entre la lectura y el UPDATE (2.5-B · K4)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  test('si el UPDATE no toca ninguna fila (otro proceso la borró), el grant inserta en vez de responder existed: true sobre nada', async ({
    assert,
  }) => {
    // CR#3. `refreshAssignment` ignoraba el conteo del UPDATE: con la fila
    // borrada por una purga concurrente devolvía `{ existed: true }` —una
    // caducidad «extendida» que no está escrita— y el holder se quedaba sin
    // asignación. Aquí la carrera es determinista: `grant.find` ve una fila
    // que ya no existe.
    const alice = { type: 'users', uuid: uuidv7() }
    const later = new Date(Date.now() + 3_600_000)
    const driver: any = Object.create(new DatabaseAuthorizationDriver())
    const realFirst = Object.getPrototypeOf(driver).first
    let phantom = true
    driver.first = function (operation: string, fn: () => unknown) {
      // La PRIMERA lectura ve una fila que otro proceso borra acto seguido; las siguientes, la realidad.
      if (operation === 'grant.find' && phantom) {
        phantom = false
        return Promise.resolve({ uuid: uuidv7(), expires_at: null })
      }
      return realFirst.call(this, operation, fn)
    }
    const outcome = await driver.grant(alice, 'editor', APP_SCOPE, { expiresAt: later })
    assert.isFalse(outcome.existed, 'no había fila que refrescar: es una inserción')
    assert.equal(outcome.expiresAt?.getTime(), later.getTime())
    const real = new DatabaseAuthorizationDriver()
    assert.deepEqual(await real.listRoles(alice, APP_SCOPE), ['editor'], 'la asignación está escrita')
    assert.isTrue(await real.authorize(alice, 'docs:read', APP_SCOPE))
    assert.equal((await real.grant(alice, 'editor', APP_SCOPE)).previousExpiresAt?.getTime(), later.getTime(), 'con la caducidad pedida')
  })
})
