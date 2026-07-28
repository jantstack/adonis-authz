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
  test('el stub declara las cinco tablas del motor', async ({ assert }) => {
    const stub = await parseStub()
    assert.deepEqual(
      [...stub.keys()].sort(),
      [
        'authz_assignments',
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
      const info = await db.rawQuery(`PRAGMA table_info('${table}')`)
      const actual = info.map((row: any) => row.name)
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
})
