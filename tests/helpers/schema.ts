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
import { BaseSchema } from '@adonisjs/lucid/schema'
import { testEngine } from './app.js'

/** Las tablas del motor (2.x). */
export const AUTHZ_TABLES = [
  'authz_roles',
  'authz_permissions',
  'authz_role_permissions',
  'authz_assignments',
  'authz_denies',
  'authz_catalog_version',
] as const

/** Una columna tal como la describe el motor: lo que se compara entre esquemas (2.5-B · K11). */
export interface ColumnShape {
  table: string
  column: string
  type: string
  length: number | null
  precision: number | null
  nullable: boolean
  collation: string | null
}

/**
 * Describe las tablas `authz_*` de una base leyendo el catálogo del motor:
 * `information_schema.columns` (PG: tipo, longitud, precisión; MySQL:
 * `column_type` completo y collation) o `PRAGMA table_info` (SQLite).
 * Normalizado para poder comparar dos bases del mismo motor con `deepEqual`.
 */
export async function describeAuthzSchema(db: Database, tables: readonly string[] = AUTHZ_TABLES): Promise<ColumnShape[]> {
  const engine = testEngine()
  const rowsOf = (result: any): any[] => (Array.isArray(result) ? (Array.isArray(result[0]) ? result[0] : result) : (result?.rows ?? []))
  const shapes: ColumnShape[] = []
  if (engine === 'pg') {
    const rows = rowsOf(
      await db.rawQuery(
        `select table_name, column_name, data_type, character_maximum_length, datetime_precision, is_nullable, collation_name
         from information_schema.columns where table_schema = current_schema() and table_name = any(?) order by table_name, column_name`,
        [tables as string[]]
      )
    )
    for (const r of rows) {
      shapes.push({
        table: r.table_name,
        column: r.column_name,
        type: r.data_type,
        length: r.character_maximum_length === null ? null : Number(r.character_maximum_length),
        precision: r.datetime_precision === null ? null : Number(r.datetime_precision),
        nullable: r.is_nullable === 'YES',
        collation: r.collation_name ?? null,
      })
    }
  } else if (engine === 'mysql') {
    const placeholders = tables.map(() => '?').join(', ')
    const rows = rowsOf(
      await db.rawQuery(
        `select table_name, column_name, column_type, character_maximum_length, datetime_precision, is_nullable, collation_name
         from information_schema.columns where table_schema = database() and table_name in (${placeholders}) order by table_name, column_name`,
        [...tables]
      )
    )
    for (const r of rows) {
      const get = (k: string) => r[k] ?? r[k.toUpperCase()]
      shapes.push({
        table: get('table_name'),
        column: get('column_name'),
        type: String(get('column_type')),
        length: get('character_maximum_length') === null ? null : Number(get('character_maximum_length')),
        precision: get('datetime_precision') === null ? null : Number(get('datetime_precision')),
        nullable: get('is_nullable') === 'YES',
        collation: get('collation_name') ?? null,
      })
    }
  } else {
    for (const table of tables) {
      const rows = rowsOf(await db.rawQuery(`PRAGMA table_info(${table})`))
      for (const r of rows) {
        const match = /^(\w+)(?:\((\d+)\))?/.exec(String(r.type))
        shapes.push({
          table,
          column: r.name,
          type: (match?.[1] ?? String(r.type)).toLowerCase(),
          length: match?.[2] ? Number(match[2]) : null,
          precision: null,
          nullable: Number(r.notnull) === 0,
          collation: null,
        })
      }
      shapes.sort((a, b) => (a.table + a.column).localeCompare(b.table + b.column))
    }
  }
  return shapes.sort((a, b) => a.table.localeCompare(b.table) || a.column.localeCompare(b.column))
}

/**
 * Ejecuta el `up()` de una migración escrita como stub de Lucid (la
 * publicada en `stubs/migration.stub` o la de 1.1.0 en `tests/fixtures`) en
 * una base dada, sin escribir ficheros: se quita la cabecera del stub y el
 * `import`/`export`, se elimina el azúcar de TypeScript (`public`) y la clase
 * se evalúa con `BaseSchema` real, así que corren el schema builder de knex y
 * los `defer` tal como lo harían en el proyecto del consumidor.
 */
export async function runMigrationSource(db: Database, source: string): Promise<void> {
  const body = source
    .replace(/^\{\{\{[\s\S]*?\}\}\}\s*/, '')
    .replace(/^import .*$/m, '')
    .replace('export default class', 'return class')
    .replace(/\bpublic\s+/g, '')
  const Migration = new Function('BaseSchema', body)(BaseSchema) as typeof BaseSchema
  const migration = new Migration(db.connection() as any, 'migration.ts')
  await migration.execUp()
}

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
    table.string('scope_type', 20).notNullable().collate('utf8mb4_bin')
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
