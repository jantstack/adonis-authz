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
  test('el stub declara las seis tablas del motor', async ({ assert }) => {
    const stub = await parseStub()
    assert.deepEqual(
      [...stub.keys()].sort(),
      [
        'authz_assignments',
        'authz_catalog_version',
        'authz_denies',
        'authz_permissions',
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
    for (const column of ['holder_type', 'scope_type']) {
      assert.lengthOf([...source.matchAll(new RegExp(`table\\.string\\('${column}', \\d+\\)[^\\n]*collate\\('utf8mb4_bin'\\)`, 'g'))], 2, column)
    }
    assert.lengthOf([...source.matchAll(/table\.string\('slug', 100\)[^\n]*collate\('utf8mb4_bin'\)/g)], 2, 'slug en roles y permissions')
    assert.match(source, /table\.datetime\('expires_at', \{ precision: 3 \}\)\.nullable\(\)/)
    assert.notMatch(source, /timestamp\('expires_at'/)
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
