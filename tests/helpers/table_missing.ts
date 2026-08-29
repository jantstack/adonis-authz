/**
 * Renombra una tabla `authz_*` mientras corre `fn` (y la restaura): la forma
 * más barata de simular "la base no responde" sin cerrar el pool (que en la
 * suite de SQLite en memoria es de una sola conexión).
 *
 * Vive en helpers (no en un .spec) para que ningún spec dependa del orden de
 * carga de otro: importar un .spec desde otro registra sus grupos con el
 * runner ya en marcha y rompe `--files` (H6 del tester, Fase 2.5-B).
 */
import db from '@adonisjs/lucid/services/db'

export async function withTableMissing<T>(table: string, fn: () => Promise<T>): Promise<T> {
  const knex = db.connection().getWriteClient()
  await knex.schema.renameTable(table, `${table}_missing`)
  try {
    return await fn()
  } finally {
    await knex.schema.renameTable(`${table}_missing`, table)
  }
}
