/**
 * El trait `withAuthzScopes` (scopes de query `whereRoles`/`wherePermissions`
 * sobre un modelo de holder), en los tres motores (2.5-B · K3, K6).
 *
 * K3 (CR#2): el subquery selecciona `a.holder_uuid` (`varchar(64)`) y la
 * clave primaria del modelo del consumidor es, en PostgreSQL, un `uuid`
 * nativo: `uuid IN (SELECT varchar)` es el error 42883 («operator does not
 * exist: uuid = character varying»). En SQLite y MySQL la comparación se
 * coacciona y nadie lo veía. La tabla de holders de este test tiene la clave
 * como `uuid` a propósito.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { compose } from '@adonisjs/core/helpers'
import db from '@adonisjs/lucid/services/db'
import { withAuthzScopes } from '../src/traits/authz_scopes.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { APP_SCOPE } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'

const TABLE = 'demo_users'

class DemoUser extends compose(BaseModel, withAuthzScopes) {
  public static table = TABLE
  public static primaryKey = 'id'
  public static selfAssignPrimaryKey = true

  @column({ isPrimary: true })
  declare id: string

  @column()
  declare name: string
}
// Lo que estampa `@MorphMap('users')` en un proyecto: aquí a mano, sin el decorador del consumidor.
;(DemoUser.prototype as any).__morphMapName = 'users'

async function createDemoUsersTable(): Promise<void> {
  const schema = db.connection().schema
  if (await schema.hasTable(TABLE)) await schema.dropTable(TABLE)
  await db.connection().schema.createTable(TABLE, (table) => {
    // `uuid` nativo: en PG es el tipo `uuid`, no un varchar (K3).
    table.uuid('id').primary().notNullable()
    table.string('name', 50).notNullable()
  })
}

test.group('withAuthzScopes — whereRoles / wherePermissions (2.5-B · K3)', (group) => {
  group.setup(async () => {
    await createDemoUsersTable()
  })
  group.teardown(async () => {
    await db.connection().schema.dropTable(TABLE)
  })
  group.each.setup(async () => {
    await cleanAuthzTables()
    await db.from(TABLE).delete()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }, { slug: 'audit:read' }],
      roles: [
        { slug: 'editor', scopeType: 'app', permissions: ['docs:read'] },
        { slug: 'auditor', scopeType: 'app', permissions: ['audit:read'] },
      ],
    })
  })

  test('filtra los holders del morph con asignación VIGENTE del rol o del permiso, con la clave primaria uuid nativa del modelo (PG: uuid IN (varchar))', async ({
    assert,
  }) => {
    const editor = uuidv7()
    const auditor = uuidv7()
    const expired = uuidv7()
    const nobody = uuidv7()
    await DemoUser.createMany([
      { id: editor, name: 'editor' },
      { id: auditor, name: 'auditor' },
      { id: expired, name: 'expired' },
      { id: nobody, name: 'nobody' },
    ])
    const driver = new DatabaseAuthorizationDriver()
    await driver.grant({ type: 'users', uuid: editor }, 'editor', APP_SCOPE)
    await driver.grant({ type: 'users', uuid: auditor }, 'auditor', APP_SCOPE)
    await driver.grant({ type: 'users', uuid: expired }, 'editor', APP_SCOPE, { expiresAt: new Date(Date.now() - 60_000) })
    // Otro morph con el MISMO uuid: no es este holder (invariante 4).
    await driver.grant({ type: 'admins', uuid: nobody }, 'editor', APP_SCOPE)

    const ids = (rows: DemoUser[]) => rows.map((u) => u.id).sort()
    assert.deepEqual(ids(await DemoUser.query().withScopes((s) => s.whereRoles('editor'))), [editor])
    assert.deepEqual(ids(await DemoUser.query().withScopes((s) => s.whereRoles('editor', 'auditor'))), [editor, auditor].sort())
    assert.deepEqual(ids(await DemoUser.query().withScopes((s) => s.wherePermissions('docs:read'))), [editor])
    assert.deepEqual(ids(await DemoUser.query().withScopes((s) => s.wherePermissions('audit:read'))), [auditor])
    assert.deepEqual(ids(await DemoUser.query().withScopes((s) => s.wherePermissions('docs:read', 'audit:read'))), [editor, auditor].sort())
    assert.deepEqual(await DemoUser.query().withScopes((s) => s.whereRoles('no-existe')), [])
  })

  test('K6: withAuthzScopes({ clock }) decide la vigencia con ESE reloj; sin él, con el reloj del sistema (y nunca con el del manager)', async ({
    assert,
  }) => {
    // 2.5-B · K6 (CR#5). El trait leía `systemClock()` mientras el README
    // prometía «un solo reloj»: un consumidor que fija `config.clock` en
    // 2030 veía `authorize` caducar y `whereRoles` seguir listando. El
    // trait no ve el manager: el reloj se le pasa como opción del compose.
    const T = new Date('2030-06-15T12:00:00.000Z')
    class ClockedUser extends compose(BaseModel, withAuthzScopes({ clock: () => T })) {
      public static table = TABLE
      public static primaryKey = 'id'
      public static selfAssignPrimaryKey = true

      @column({ isPrimary: true })
      declare id: string

      @column()
      declare name: string
    }
    ;(ClockedUser.prototype as any).__morphMapName = 'users'

    const until2029 = uuidv7()
    const until2031 = uuidv7()
    await DemoUser.createMany([
      { id: until2029, name: 'hasta 2029' },
      { id: until2031, name: 'hasta 2031' },
    ])
    const driver = new DatabaseAuthorizationDriver()
    await driver.grant({ type: 'users', uuid: until2029 }, 'editor', APP_SCOPE, { expiresAt: new Date('2029-01-01T00:00:00.000Z') })
    await driver.grant({ type: 'users', uuid: until2031 }, 'editor', APP_SCOPE, { expiresAt: new Date('2031-01-01T00:00:00.000Z') })

    const ids = (rows: Array<{ id: string }>) => rows.map((u) => u.id).sort()
    // Con el reloj en 2030: la de 2029 ya venció.
    assert.deepEqual(ids(await ClockedUser.query().withScopes((s) => s.whereRoles('editor'))), [until2031])
    assert.deepEqual(ids(await ClockedUser.query().withScopes((s) => s.wherePermissions('docs:read'))), [until2031])
    // Sin reloj inyectado (hoy): las dos están vigentes.
    assert.deepEqual(ids(await DemoUser.query().withScopes((s) => s.whereRoles('editor'))), [until2029, until2031].sort())
    // Y con el reloj en 2032 no queda ninguna.
    class LaterUser extends compose(BaseModel, withAuthzScopes({ clock: () => new Date('2032-01-01T00:00:00.000Z') })) {
      public static table = TABLE
      public static primaryKey = 'id'
      public static selfAssignPrimaryKey = true

      @column({ isPrimary: true })
      declare id: string
    }
    ;(LaterUser.prototype as any).__morphMapName = 'users'
    assert.deepEqual(await LaterUser.query().withScopes((s) => s.whereRoles('editor')), [])
    // Un `clock` que no es función es config rota.
    assert.throws(() => withAuthzScopes({ clock: 'ahora' as any }), /clock/)
  })
})
