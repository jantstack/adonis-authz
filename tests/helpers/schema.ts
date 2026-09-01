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
import { relationPartitionTrigger } from '../../src/relation_partition_trigger.js'

/** Las tablas del motor (2.x + `authz_relations` de la Fase 4). */
export const AUTHZ_TABLES = [
  'authz_roles',
  'authz_permissions',
  'authz_role_permissions',
  'authz_assignments',
  'authz_denies',
  'authz_catalog_version',
  'authz_relations_config',
  'authz_relations',
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

/** Una clave ajena tal como la describe el motor (3D · M6): a qué apunta y qué hace al borrar/actualizar. */
export interface ForeignKeyShape {
  table: string
  column: string
  referencedTable: string
  referencedColumn: string
  deleteRule: string
  updateRule: string
}

/**
 * Describe las claves ajenas de `authz_*` con sus ACCIONES
 * (`information_schema.referential_constraints`), en PG y MySQL (3D · M6 b,
 * tester H3).
 *
 * K11 comparaba tipo, longitud, precisión, nulabilidad y collation, pero no
 * `delete_rule`/`update_rule`: el espejo de tests se quedó sin `onDelete` y
 * el stub publicado tenía `CASCADE`/`RESTRICT`, y lo que mataba a un mutante
 * de `purgeRole` era esa diferencia accidental. Sobre el esquema REAL, un
 * `purgeRole` que olvidara los vínculos habría pasado.
 *
 * SQLite no expone las acciones en `information_schema` (`PRAGMA
 * foreign_key_list` sí, pero el harness de K11 solo compara motores donde
 * hay dos bases de trabajo): devuelve `[]` y el guard se salta ahí.
 */
export async function describeAuthzForeignKeys(db: Database, tables: readonly string[] = AUTHZ_TABLES): Promise<ForeignKeyShape[]> {
  const engine = testEngine()
  const rowsOf = (result: any): any[] => (Array.isArray(result) ? (Array.isArray(result[0]) ? result[0] : result) : (result?.rows ?? []))
  const keys: ForeignKeyShape[] = []
  if (engine === 'pg') {
    const rows = rowsOf(
      await db.rawQuery(
        `select kcu.table_name, kcu.column_name, ccu.table_name as referenced_table, ccu.column_name as referenced_column,
                rc.delete_rule, rc.update_rule
         from information_schema.referential_constraints rc
         join information_schema.key_column_usage kcu
           on kcu.constraint_name = rc.constraint_name and kcu.constraint_schema = rc.constraint_schema
         join information_schema.constraint_column_usage ccu
           on ccu.constraint_name = rc.constraint_name and ccu.constraint_schema = rc.constraint_schema
         where rc.constraint_schema = current_schema() and kcu.table_name = any(?)`,
        [tables as string[]]
      )
    )
    for (const r of rows) {
      keys.push({
        table: r.table_name,
        column: r.column_name,
        referencedTable: r.referenced_table,
        referencedColumn: r.referenced_column,
        deleteRule: String(r.delete_rule).toUpperCase(),
        updateRule: String(r.update_rule).toUpperCase(),
      })
    }
  } else if (engine === 'mysql') {
    const placeholders = tables.map(() => '?').join(', ')
    const rows = rowsOf(
      await db.rawQuery(
        `select kcu.table_name, kcu.column_name, kcu.referenced_table_name, kcu.referenced_column_name,
                rc.delete_rule, rc.update_rule
         from information_schema.referential_constraints rc
         join information_schema.key_column_usage kcu
           on kcu.constraint_name = rc.constraint_name and kcu.constraint_schema = rc.constraint_schema
         where rc.constraint_schema = database() and kcu.table_name in (${placeholders})`,
        [...tables]
      )
    )
    for (const r of rows) {
      const get = (k: string) => r[k] ?? r[k.toUpperCase()]
      keys.push({
        table: get('table_name'),
        column: get('column_name'),
        referencedTable: get('referenced_table_name'),
        referencedColumn: get('referenced_column_name'),
        deleteRule: String(get('delete_rule')).toUpperCase(),
        updateRule: String(get('update_rule')).toUpperCase(),
      })
    }
  }
  return keys.sort((a, b) => (a.table + a.column).localeCompare(b.table + b.column))
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
    table.string('owner_scope_key', 80).notNullable().defaultTo('global').collate('utf8mb4_bin')
    table.timestamp('created_at').notNullable()
    table.timestamp('updated_at').notNullable()
    table.unique(['slug', 'scope_type', 'owner_scope_key'], 'authz_roles_slug_scope_owner_uq')
    table.index(['owner_scope_key'], 'authz_roles_owner_idx')
  })

  await schema().createTable('authz_permissions', (table) => {
    table.uuid('uuid').primary().notNullable()
    table.string('slug', 100).notNullable().unique().collate('utf8mb4_bin')
    table.string('description', 500).nullable()
    table.string('assignable_at', 500).nullable()
    table.timestamp('created_at').notNullable()
    table.timestamp('updated_at').notNullable()
  })

  await schema().createTable('authz_role_permissions', (table) => {
    table.uuid('uuid').primary().notNullable()
    // Las acciones de FK son parte del espejo desde 3D · M6: sin ellas, el
    // esquema de test y el publicado se comportaban distinto (`CASCADE` vs
    // NO ACTION) y lo que mataba a un mutante de `purgeRole` era ESA
    // diferencia accidental, no una aserción (tester H3).
    table.uuid('role_uuid').notNullable().references('uuid').inTable('authz_roles').onDelete('CASCADE')
    table.uuid('permission_uuid').notNullable().references('uuid').inTable('authz_permissions').onDelete('CASCADE')
    table.timestamp('created_at').notNullable()
    table.unique(['role_uuid', 'permission_uuid'], 'authz_role_perms_uq')
  })

  await schema().createTable('authz_assignments', (table) => {
    table.uuid('uuid').primary().notNullable()
    table.string('holder_type', 50).notNullable().collate('utf8mb4_bin')
    table.string('holder_uuid', 64).notNullable().collate('utf8mb4_bin')
    table.uuid('role_uuid').notNullable().references('uuid').inTable('authz_roles').onDelete('RESTRICT')
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
    table.uuid('permission_uuid').notNullable().references('uuid').inTable('authz_permissions').onDelete('CASCADE')
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
    table.string('freeze_reason', 255).nullable()
    table.string('freeze_holder', 120).nullable()
    table.bigInteger('freeze_until_ms').nullable()
    table.bigInteger('freeze_fence').notNullable().defaultTo(0)
  })
  await db.table('authz_catalog_version').insert({ id: 1, version: 0, updated_at: new Date() })
  // La fila `id = 2` es el freeze DURABLE (3b-7): sin ella toda escritura es 503.
  await db.table('authz_catalog_version').insert({ id: 2, version: 0, updated_at: new Date() })

  // `authz_relations_config` — la config de relaciones persistida (Fase 4-5,
  // 🟡3): bajo el gate de versión, para que quien republique el modelo lea los
  // tipos de la BASE. Espeja `stubs/migration.stub`.
  await db.connection().schema.createTable('authz_relations_config', (table) => {
    table.integer('id').primary().notNullable()
    table.text('spec').notNullable()
    table.string('model_id', 64).nullable()
    table.timestamp('updated_at').notNullable()
  })

  // `authz_relations` — las tuplas de ReBAC (Fase 4, lote 4-3), INSERT/DELETE-ONLY
  // (con `expires_at` desde R-15, 2.4.0-alpha.2: renovar es delete+insert).
  // Sin FK: las relaciones no cuelgan del catálogo. Identidad byte a byte
  // (`utf8mb4_bin`) como el resto, por las mismas razones de 2.5 · J3.
  await createAuthzRelationsTable(db)
}

/**
 * La tabla `authz_relations` + su trigger de partición POR DIALECTO (defensa
 * en profundidad para el escritor «a mano»). Espeja `stubs/migration.stub`.
 */
export async function createAuthzRelationsTable(db: Database): Promise<void> {
  await db.connection().schema.createTable('authz_relations', (table) => {
    table.uuid('uuid').primary().notNullable()
    // La partición (tenant): la clave del scope, `app` o `<tipo>|<uuid>`.
    table.string('partition_key', 64).notNullable().collate('utf8mb4_bin')
    table.string('object_type', 50).notNullable().collate('utf8mb4_bin')
    table.string('object_uuid', 64).notNullable().collate('utf8mb4_bin')
    table.string('relation', 50).notNullable().collate('utf8mb4_bin')
    table.string('subject_type', 50).notNullable().collate('utf8mb4_bin')
    table.string('subject_uuid', 64).notNullable().collate('utf8mb4_bin')
    // Vacío/NULL = holder; con valor = userset (`group:g#member`).
    table.string('subject_relation', 50).nullable().collate('utf8mb4_bin')
    // La partición del userset: el trigger exige que sea la de la fila.
    table.string('subject_partition', 64).nullable().collate('utf8mb4_bin')
    // R-15: la caducidad de la tupla (NULL = no caduca). MISMO tipo que
    // `authz_assignments.expires_at` (DATETIME(3), 2.5 · J3) y mismo codec.
    table.datetime('expires_at', { precision: 3 }).nullable()
    table.timestamp('created_at').notNullable()

    table.unique(
      ['partition_key', 'object_type', 'object_uuid', 'relation', 'subject_type', 'subject_uuid', 'subject_relation'],
      'authz_rel_tuple_uq'
    )
    table.index(['partition_key', 'object_type', 'object_uuid', 'relation'], 'authz_rel_object_idx')
    table.index(['partition_key', 'subject_type', 'subject_uuid'], 'authz_rel_subject_idx')
  })
  // El trigger va como sentencia RAW ENTERA (su `BEGIN…END` lleva `;` dentro):
  // nunca por un runner que trocea por `;`.
  const dialect: string = db.connection().dialect.name
  for (const statement of relationPartitionTrigger(dialect)) {
    await db.connection().rawQuery(statement)
  }
}

/**
 * Borra los hechos y el catálogo entre tests (orden de FK). Usa el mismo
 * singleton `db` que el motor, así que no hay que pasear la instancia. La
 * fila de `authz_catalog_version` se conserva: es la versión compartida, y
 * cada `syncAuthzCatalog` del setup la sube.
 */
export async function cleanAuthzTables(): Promise<void> {
  const { default: db } = await import('@adonisjs/lucid/services/db')
  await db.from('authz_relations').delete()
  await db.from('authz_relations_config').delete()
  await db.from('authz_denies').delete()
  await db.from('authz_assignments').delete()
  await db.from('authz_role_permissions').delete()
  await db.from('authz_roles').delete()
  await db.from('authz_permissions').delete()
  // Y el FREEZE (3b-7): un freeze que se escapa de un caso envenena a todos
  // los siguientes (todas sus escrituras serían 503). El `fence` se conserva:
  // es el número de generación, no un dato.
  await db
    .from('authz_catalog_version')
    .where('id', 2)
    .update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null })
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

/**
 * Tabla de la OUTBOX del árbol (3b-2d). No es del motor: es lo que el
 * consumidor publica si usa `sqlScopeOutbox`, y el harness la crea porque el
 * espejo de `stubs/scopes_outbox_migration.stub` se vigila igual que el de
 * `stubs/migration.stub` (`tests/scope_outbox.spec.ts`). Mismas decisiones de
 * motor que 2.5 · J3: identidad `varchar(64)` con `utf8mb4_bin` (un alias del
 * uuid no debe fundirse con otra fila) y tipos `varchar(20)`.
 */
export async function createScopeOutboxTable(db: Database): Promise<void> {
  await db.connection().schema.createTable('authz_scope_outbox', (table) => {
    table.increments('id').primary()
    table.string('op', 10).notNullable().collate('utf8mb4_bin')
    table.string('child_type', 20).notNullable().collate('utf8mb4_bin')
    table.string('child_uuid', 64).notNullable().collate('utf8mb4_bin')
    table.string('parent_type', 20).nullable().collate('utf8mb4_bin')
    table.string('parent_uuid', 64).nullable().collate('utf8mb4_bin')
    table.string('actor_type', 50).nullable().collate('utf8mb4_bin')
    table.string('actor_uuid', 64).nullable().collate('utf8mb4_bin')
    table.integer('attempts').notNullable().defaultTo(0)
    table.text('last_error').nullable()
    table.timestamp('created_at').notNullable()
    table.timestamp('applied_at').nullable()
    table.index(['applied_at', 'id'], 'authz_scope_outbox_pending_idx')
  })
}

/** Vacía la outbox entre tests. */
export async function cleanScopeOutbox(db: Database): Promise<void> {
  await db.from('authz_scope_outbox').delete()
}
