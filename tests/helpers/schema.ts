/**
 * Esquema de las tablas `authz_*` para la suite del paquete.
 *
 * Es un ESPEJO de `stubs/migration.stub` (lo que se publica en el proyecto
 * consumidor). El stub sigue siendo la fuente para quien instala el paquete —
 * una migración debe ser una foto congelada, no una llamada a código que
 * cambia con la versión. Para que el espejo no se despiste hay un test que
 * compara ambos: `tests/migration_stub.spec.ts`.
 *
 * Las decisiones de motor (2.5 · J3) son las del stub y por las mismas
 * razones: identidad `varchar(64)` con `utf8mb4_bin` (solo MySQL compila la
 * collation), `expires_at` como `DATETIME(3)`.
 */

import type { Database } from '@adonisjs/lucid/database'

export async function createAuthzSchema(db: Database): Promise<void> {
  // Un builder NUEVO por tabla: `connection.schema` memoiza el suyo y
  // reutilizarlo reejecuta las sentencias ya acumuladas (el índice único de
  // la tabla anterior vuelve a crearse y revienta).
  const schema = () => db.connection().schema

  await schema().createTable('authz_roles', (table) => {
    table.uuid('uuid').primary().notNullable()
    table.string('slug', 100).notNullable().collate('utf8mb4_bin')
    table.string('name', 100).notNullable()
    table.string('description', 500).nullable()
    table.string('scope_type', 20).notNullable()
    table.integer('rank').notNullable().defaultTo(0)
    table.timestamp('created_at').notNullable()
    table.timestamp('updated_at').notNullable()
    table.unique(['slug', 'scope_type'], 'authz_roles_slug_scope_uq')
  })

  await schema().createTable('authz_permissions', (table) => {
    table.uuid('uuid').primary().notNullable()
    table.string('slug', 100).notNullable().unique().collate('utf8mb4_bin')
    table.string('description', 500).nullable()
    table.timestamp('created_at').notNullable()
    table.timestamp('updated_at').notNullable()
  })

  await schema().createTable('authz_role_permissions', (table) => {
    table.uuid('uuid').primary().notNullable()
    table.uuid('role_uuid').notNullable().references('uuid').inTable('authz_roles')
    table.uuid('permission_uuid').notNullable().references('uuid').inTable('authz_permissions')
    table.timestamp('created_at').notNullable()
    table.unique(['role_uuid', 'permission_uuid'], 'authz_role_perms_uq')
  })

  await schema().createTable('authz_assignments', (table) => {
    table.uuid('uuid').primary().notNullable()
    table.string('holder_type', 50).notNullable().collate('utf8mb4_bin')
    table.string('holder_uuid', 64).notNullable().collate('utf8mb4_bin')
    table.uuid('role_uuid').notNullable().references('uuid').inTable('authz_roles')
    table.string('scope_type', 20).notNullable().collate('utf8mb4_bin')
    table.string('scope_uuid', 64).notNullable().collate('utf8mb4_bin')
    table.datetime('expires_at', { precision: 3 }).nullable()
    table.timestamp('created_at').notNullable()
    table.unique(
      ['holder_type', 'holder_uuid', 'role_uuid', 'scope_type', 'scope_uuid'],
      'authz_asg_holder_role_scope_uq'
    )
    table.index(['holder_type', 'holder_uuid'], 'authz_asg_holder_idx')
    table.index(['scope_type', 'scope_uuid'], 'authz_asg_scope_idx')
  })

  await schema().createTable('authz_denies', (table) => {
    table.uuid('uuid').primary().notNullable()
    table.string('holder_type', 50).notNullable().collate('utf8mb4_bin')
    table.string('holder_uuid', 64).notNullable().collate('utf8mb4_bin')
    table.uuid('permission_uuid').notNullable().references('uuid').inTable('authz_permissions')
    table.string('scope_type', 20).notNullable().collate('utf8mb4_bin')
    table.string('scope_uuid', 64).notNullable().collate('utf8mb4_bin')
    table.timestamp('created_at').notNullable()
    table.unique(
      ['holder_type', 'holder_uuid', 'permission_uuid', 'scope_type', 'scope_uuid'],
      'authz_deny_holder_perm_scope_uq'
    )
    table.index(['holder_type', 'holder_uuid'], 'authz_deny_holder_idx')
  })

  await schema().createTable('authz_catalog_version', (table) => {
    table.integer('id').primary().notNullable()
    table.bigInteger('version').notNullable().defaultTo(0)
    table.timestamp('updated_at').notNullable()
  })
  await db.table('authz_catalog_version').insert({ id: 1, version: 0, updated_at: new Date() })
}

/**
 * Borra los hechos y el catálogo entre tests (orden de FK). Usa el mismo
 * singleton `db` que el motor, así que no hay que pasear la instancia. La
 * fila de `authz_catalog_version` se conserva: es la versión compartida, y
 * cada `syncAuthzCatalog` del setup la sube.
 */
export async function cleanAuthzTables(): Promise<void> {
  const { default: db } = await import('@adonisjs/lucid/services/db')
  await db.from('authz_denies').delete()
  await db.from('authz_assignments').delete()
  await db.from('authz_role_permissions').delete()
  await db.from('authz_roles').delete()
  await db.from('authz_permissions').delete()
}

/**
 * Tabla FICTICIA del harness para `sqlDescendantsOf` (2.1, B2): la forma
 * mínima de un árbol del consumidor — un uuid, el tipo del nodo y el uuid del
 * padre (`NULL` = cuelga de `app`). No es parte del esquema publicado (el
 * paquete no conoce el árbol del consumidor): existe solo para probar la CTE.
 */
export async function createDemoScopesTable(db: Database): Promise<void> {
  await db.connection().schema.createTable('demo_scopes', (table) => {
    table.uuid('uuid').primary().notNullable()
    table.string('type', 20).notNullable()
    table.uuid('parent_uuid').nullable()
  })
}
