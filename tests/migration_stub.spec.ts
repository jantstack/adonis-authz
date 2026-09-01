/**
 * El esquema con el que corre la suite (tests/helpers/schema.ts) es un espejo
 * de la migración que `configure` publica en el proyecto consumidor. Un
 * espejo sin vigilancia se despista: este test compara ambos y falla si el
 * stub gana (o pierde) una tabla o una columna que el harness no tiene.
 *
 * Sin él, la suite podría estar validando un esquema que ya nadie instala.
 */

import { test } from '@japa/runner'
import { readFile } from 'node:fs/promises'
import db from '@adonisjs/lucid/services/db'
import { openScratchDatabase } from './helpers/app.js'
import { describeAuthzForeignKeys, describeAuthzSchema, runMigrationSource } from './helpers/schema.js'

/** Tablas y columnas declaradas en el stub, leídas del texto de la migración. */
async function parseStub(): Promise<Map<string, string[]>> {
  const source = await readFile(new URL('../stubs/migration.stub', import.meta.url), 'utf8')
  const tables = new Map<string, string[]>()

  const tableRe = /createTable\('(\w+)',\s*\(table\)\s*=>\s*\{([\s\S]*?)\n {4}\}\)/g
  for (const [, tableName, body] of source.matchAll(tableRe)) {
    const columns: string[] = []
    // Solo el PRIMER método de cada cadena declara la columna: lo que sigue
    // (.notNullable(), .references('uuid')…) son modificadores. El prettier
    // parte las cadenas largas, así que el `.uuid(...)` puede caer en la
    // línea siguiente al `table`.
    const columnRe = /^\s*table\s*(?:\r?\n\s*)?\.(?!unique|index|primary)\w+\('(\w+)'/gm
    for (const [, column] of body.matchAll(columnRe)) columns.push(column)
    tables.set(tableName, columns)
  }

  return tables
}

test.group('la migración publicada y el esquema de la suite coinciden', () => {
  test('el stub declara las ocho tablas del motor (las seis de 2.x + authz_relations y authz_relations_config de la Fase 4)', async ({ assert }) => {
    const stub = await parseStub()
    assert.deepEqual(
      [...stub.keys()].sort(),
      [
        'authz_assignments',
        'authz_catalog_version',
        'authz_denies',
        'authz_permissions',
        'authz_relations',
        'authz_relations_config',
        'authz_role_permissions',
        'authz_roles',
      ]
    )
  })

  test('cada columna del stub existe en el esquema con el que se prueba', async ({ assert }) => {
    const stub = await parseStub()

    for (const [table, columns] of stub) {
      // `columnsInfo` es la introspección portable de knex: la suite corre
      // en SQLite, PG y MySQL (2.5 · J2) y `PRAGMA` solo existe en el primero.
      const info = await db.connection().columnsInfo(table)
      const actual = Object.keys(info)
      assert.isNotEmpty(actual, `la tabla ${table} no existe en el harness`)

      for (const column of columns) {
        assert.include(actual, column, `${table}.${column} está en el stub pero no en el harness`)
      }
      assert.deepEqual(
        actual.sort(),
        [...columns].sort(),
        `el harness y el stub difieren en las columnas de ${table}`
      )
    }
  })

  test('el stub lleva las decisiones de motor de 2.5 · J3: identidad varchar(64) con utf8mb4_bin y expires_at DATETIME(3)', async ({
    assert,
  }) => {
    // Lo que el harness observa por comportamiento en PG/MySQL (el juez:
    // ids que no son UUID, mayúsculas que no se cruzan, caducidad al
    // milisegundo y más allá de 2038) tiene que estar en lo que se PUBLICA.
    const source = await readFile(new URL('../stubs/migration.stub', import.meta.url), 'utf8')
    for (const column of ['holder_uuid', 'scope_uuid']) {
      const declarations = [...source.matchAll(new RegExp(`table\\.string\\('${column}', 64\\)[^\\n]*collate\\('utf8mb4_bin'\\)`, 'g'))]
      assert.lengthOf(declarations, 2, `${column}: varchar(64) + utf8mb4_bin en assignments y denies`)
      assert.notMatch(source, new RegExp(`\\.uuid\\('${column}'\\)`), `${column} ya no es uuid`)
    }
    // `holder_type` en assignments y denies; `scope_type` además en roles
    // (2.5-B, auditor ⚪4: era la única columna de identidad sin la decisión).
    assert.lengthOf([...source.matchAll(/table\.string\('holder_type', \d+\)[^\n]*collate\('utf8mb4_bin'\)/g)], 2, 'holder_type')
    assert.lengthOf([...source.matchAll(/table\.string\('scope_type', \d+\)[^\n]*collate\('utf8mb4_bin'\)/g)], 3, 'scope_type (roles, assignments, denies)')
    assert.lengthOf([...source.matchAll(/table\.string\('slug', 100\)[^\n]*collate\('utf8mb4_bin'\)/g)], 2, 'slug en roles y permissions')
    assert.match(source, /table\.datetime\('expires_at', \{ precision: 3 \}\)\.nullable\(\)/)
    assert.notMatch(source, /timestamp\('expires_at'/)
  })

  test('B1 (3B): el stub declara authz_roles.owner_scope_key varchar(80) NOT NULL DEFAULT global (byte a byte), el unique (slug, scope_type, owner_scope_key), el índice por owner y authz_permissions.assignable_at', async ({
    assert,
  }) => {
    // Fase 3 · B1. El owner de un rol es una clave de scope (`app` no vale:
    // `<tipo>|<uuid>`, ≤ 57) o `global`; es identidad y se compara byte a
    // byte como el resto (J3). El unique viejo `(slug, scope_type)` deja de
    // valer: dos tenants pueden definir `lead@unit` cada uno.
    const source = await readFile(new URL('../stubs/migration.stub', import.meta.url), 'utf8')
    assert.match(source, /table\.string\('owner_scope_key', 80\)\.notNullable\(\)\.defaultTo\('global'\)\.collate\('utf8mb4_bin'\)/)
    assert.match(source, /table\.unique\(\['slug', 'scope_type', 'owner_scope_key'\], 'authz_roles_slug_scope_owner_uq'\)/)
    assert.notMatch(source, /'authz_roles_slug_scope_uq'/, 'el unique de dos columnas ya no existe')
    assert.match(source, /table\.index\(\['owner_scope_key'\], 'authz_roles_owner_idx'\)/)
    // B5: los niveles cuyos roles pueden llevar un permiso (JSON, opcional).
    assert.match(source, /table\.string\('assignable_at', 500\)\.nullable\(\)/)
  })

  test('K11: el esquema que CONSTRUYE el stub y el espejo del harness son el mismo según el motor (tipo, longitud, precisión, nulabilidad, collation y ACCIONES de las claves ajenas), en los tres motores', async ({
    assert,
  }) => {
    // CR#10. El guard comparaba solo NOMBRES de columnas: un espejo con
    // `varchar(64)` y un stub con `uuid`, o `DATETIME(3)` frente a
    // `TIMESTAMP`, pasaban igual. Aquí la migración publicada se EJECUTA en
    // una base de trabajo del mismo motor y se compara lo que el motor dice
    // de cada columna (`information_schema` / `PRAGMA`) con el espejo.
    const scratch = await openScratchDatabase()
    try {
      const source = await readFile(new URL('../stubs/migration.stub', import.meta.url), 'utf8')
      await runMigrationSource(scratch.db, source)
      const fromStub = await describeAuthzSchema(scratch.db)
      const mirror = await describeAuthzSchema(db)
      assert.isNotEmpty(fromStub)
      assert.deepEqual(fromStub, mirror)
      // 3D · M6 (tester H3): las ACCIONES de las FK también. El espejo se
      // había quedado sin `onDelete` mientras el stub publicado tenía
      // CASCADE/RESTRICT, así que los mutantes de `purgeRole` morían por una
      // diferencia accidental entre el esquema de test y el real.
      const fkStub = await describeAuthzForeignKeys(scratch.db)
      const fkMirror = await describeAuthzForeignKeys(db)
      assert.deepEqual(fkStub, fkMirror)
      if (process.env.TEST_DB === 'pg' || process.env.TEST_DB === 'mysql') {
        assert.isNotEmpty(fkStub, 'PG y MySQL sí exponen referential_constraints')
        const rule = (table: string, column: string) => fkStub.find((k) => k.table === table && k.column === column)!
        assert.equal(rule('authz_role_permissions', 'role_uuid').deleteRule, 'CASCADE')
        assert.equal(rule('authz_role_permissions', 'permission_uuid').deleteRule, 'CASCADE')
        // La que sostiene el «todo o nada» de purgeRole: borrar un rol con
        // asignaciones vivas es un error del motor, nunca un borrado parcial.
        assert.equal(rule('authz_assignments', 'role_uuid').deleteRule, 'RESTRICT')
        assert.equal(rule('authz_denies', 'permission_uuid').deleteRule, 'CASCADE')
      }
      // Y el stub deja sembrada la versión (id = 1, versión 0).
      const seeded: any[] = await scratch.db.from('authz_catalog_version').where('id', 1).select('version')
      assert.lengthOf(seeded, 1)
      assert.equal(Number(seeded[0].version), 0)
      // 3b-7: y la fila del FREEZE durable (id = 2), libre y con el fence a 0.
      // Sin ella, TODA escritura del manager es 503 «migración 2.0 no
      // aplicada» — la fila ausente jamás se lee como «no congelado».
      const freeze: any[] = await scratch.db
        .from('authz_catalog_version')
        .where('id', 2)
        .select('freeze_reason', 'freeze_holder', 'freeze_until_ms', 'freeze_fence')
      assert.lengthOf(freeze, 1)
      assert.isNull(freeze[0].freeze_reason)
      assert.isNull(freeze[0].freeze_holder)
      assert.isNull(freeze[0].freeze_until_ms)
      assert.equal(Number(freeze[0].freeze_fence), 0)
      // Lo que el motor dice de las decisiones J3/⚪4, para que el guard no sea una tautología:
      const shape = (table: string, column: string) => fromStub.find((c) => c.table === table && c.column === column)!
      assert.equal(shape('authz_assignments', 'holder_uuid').length, 64)
      assert.equal(shape('authz_denies', 'scope_uuid').length, 64)
      // B1 (3B): el owner del rol, con su default puesto por el MOTOR (una
      // fila insertada sin owner es global) y el unique de tres columnas.
      assert.equal(shape('authz_roles', 'owner_scope_key').length, 80)
      assert.isFalse(shape('authz_roles', 'owner_scope_key').nullable)
      assert.equal(shape('authz_permissions', 'assignable_at').length, 500)
      assert.isTrue(shape('authz_permissions', 'assignable_at').nullable)
      const now = new Date()
      await scratch.db.table('authz_roles').insert({ uuid: '0192a000-0000-7000-8000-000000000001', slug: 'lead', name: 'lead', scope_type: 'unit', rank: 0, created_at: now, updated_at: now })
      const inserted: any[] = await scratch.db.from('authz_roles').where('slug', 'lead').select('owner_scope_key')
      assert.equal(inserted[0].owner_scope_key, 'global')
      // Mismo (slug, scope_type) con OTRO owner: cabe; con el MISMO owner: el unique lo rechaza.
      await scratch.db.table('authz_roles').insert({ uuid: '0192a000-0000-7000-8000-000000000002', slug: 'lead', name: 'lead', scope_type: 'unit', rank: 0, owner_scope_key: 'organization|org-a', created_at: now, updated_at: now })
      await assert.rejects(() =>
        scratch.db.table('authz_roles').insert({ uuid: '0192a000-0000-7000-8000-000000000003', slug: 'lead', name: 'lead', scope_type: 'unit', rank: 0, owner_scope_key: 'organization|org-a', created_at: now, updated_at: now })
      )
      if (process.env.TEST_DB === 'mysql') {
        assert.equal(shape('authz_assignments', 'expires_at').type, 'datetime(3)')
        for (const [table, column] of [['authz_roles', 'scope_type'], ['authz_roles', 'slug'], ['authz_roles', 'owner_scope_key'], ['authz_assignments', 'holder_uuid'], ['authz_denies', 'scope_type']]) {
          assert.equal(shape(table, column).collation, 'utf8mb4_bin', `${table}.${column}`)
        }
      } else if (process.env.TEST_DB === 'pg') {
        assert.equal(shape('authz_assignments', 'expires_at').type, 'timestamp with time zone')
        assert.equal(shape('authz_assignments', 'expires_at').precision, 3)
      }
    } finally {
      await scratch.drop()
    }
  }).timeout(60_000)

  test('R-15: authz_relations lleva expires_at DATETIME(3) nullable en el stub Y en el espejo (la caducidad de relaciones, aditiva)', async ({
    assert,
  }) => {
    // R-15 (2.4.0-alpha.2): la caducidad de la tupla de relación. La columna
    // es la MISMA decisión de motor que `authz_assignments.expires_at` (2.5 ·
    // J3: `DATETIME(3)` en MySQL —milisegundos, sin el tope de 2038—,
    // `timestamptz(3)` en PG) y la lee/escribe el MISMO codec (`sqlExpiryCodec`).
    // Es ADITIVA: un consumidor que ya migró la 2.4.0-alpha.1 la añade con la
    // receta `ALTER TABLE` del CHANGELOG.
    const stub = await parseStub()
    assert.include(stub.get('authz_relations') ?? [], 'expires_at', 'el stub declara authz_relations.expires_at')
    const source = await readFile(new URL('../stubs/migration.stub', import.meta.url), 'utf8')
    const relationsBlock = /createTable\('authz_relations',[\s\S]*?\n {4}\}\)/.exec(source)?.[0] ?? ''
    assert.match(relationsBlock, /table\.datetime\('expires_at', \{ precision: 3 \}\)\.nullable\(\)/)
    // Y el espejo (el esquema con el que corre la suite) la tiene, con la forma del motor.
    const info = await db.connection().columnsInfo('authz_relations')
    assert.include(Object.keys(info), 'expires_at')
    const [shape] = (await describeAuthzSchema(db, ['authz_relations'])).filter((c) => c.column === 'expires_at')
    assert.isTrue(shape.nullable, 'nullable: sin caducidad = NULL')
    if (process.env.TEST_DB === 'mysql') {
      assert.equal(shape.type, 'datetime(3)')
    } else if (process.env.TEST_DB === 'pg') {
      assert.equal(shape.type, 'timestamp with time zone')
      assert.equal(shape.precision, 3)
    }
  })

  test('el stub siembra la fila de la versión compartida del catálogo, igual que el harness', async ({ assert }) => {
    // Sin la fila `id = 1`, `bumpAuthzCatalogVersion` la crea igual; pero la
    // migración publicada la siembra para que la primera pregunta de un
    // despliegue no tenga que hacerlo. El harness hace lo mismo.
    const source = await readFile(new URL('../stubs/migration.stub', import.meta.url), 'utf8')
    assert.match(source, /table\('authz_catalog_version'\)\.insert\(\{ id: 1, version: 0/)
    const rows = await db.from('authz_catalog_version').where('id', 1).select('version')
    assert.lengthOf(rows, 1)
  })
})
