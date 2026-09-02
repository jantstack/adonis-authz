/**
 * **La DDL del trigger de partición de `authz_relations` por dialecto** (Fase 4,
 * lote 4-3) — módulo PURO, sin dependencia del servicio `db` de Lucid, para que
 * lo pueda importar tanto el driver `database` de relaciones como el espejo del
 * esquema de la suite (que se carga ANTES de bootear la app).
 *
 * El trigger es la defensa en profundidad contra un escritor «a mano» que meta
 * en `authz_relations` una fila cuyo USERSET (sujeto con `subject_relation`)
 * pertenece a OTRA partición que la de la fila. Cada sentencia se ejecuta
 * ENTERA (su cuerpo `BEGIN…END` lleva `;` dentro): nunca por un runner que
 * trocea por `;`.
 *
 * **L-4b**: «es userset» es `subject_relation <> ''`, no `IS NOT NULL`. Desde
 * L-4b un holder lleva `''` (la columna es `NOT NULL DEFAULT ''` para que el
 * UNIQUE lo defienda: NULL ≠ NULL en los tres motores); con `IS NOT NULL` el
 * trigger dispararía en CADA holder (`subject_partition` NULL ≠ `partition_key`).
 * Una fila vieja con NULL que nadie rellenó tampoco dispara: `NULL <> ''` es
 * NULL —falso— en SQLite, PG y MySQL (tolerancia a NULL, coherente con el
 * driver, que también lo lee como holder).
 *
 * La forma es RADICALMENTE distinta en cada motor (medido por el analista, y
 * probado en INSERT **y** UPDATE):
 *  - **SQLite**: `CREATE TRIGGER … BEFORE INSERT/UPDATE … WHEN … BEGIN SELECT
 *    RAISE(ABORT, …); END` — un trigger por evento; `IS NOT` es el distinto
 *    null-safe.
 *  - **PostgreSQL**: exige una FUNCIÓN plpgsql SEPARADA (`RAISE EXCEPTION`) y
 *    un `CREATE TRIGGER … EXECUTE FUNCTION` que la invoca; un solo trigger
 *    `BEFORE INSERT OR UPDATE`. `IS DISTINCT FROM` es el distinto null-safe.
 *  - **MySQL**: `SIGNAL SQLSTATE '45000'` dentro de `IF … THEN … END IF`; un
 *    trigger por evento; `<=>` es el igual null-safe (`NOT (a <=> b)` = distinto).
 *
 * Cualquier otro dialecto ⇒ 500 `E_AUTHZ_UNSUPPORTED_DIALECT` (nunca una tabla
 * sin defensa), exactamente como `sqlDescendantsOf`.
 */
import { UnsupportedDialectError } from './errors.js'

const RELATIONS_TABLE = 'authz_relations'
const TRIGGER_MESSAGE = 'authz_relations: un userset no puede pertenecer a otra partición que su tupla'

type TriggerDialect = 'sqlite' | 'postgres' | 'mysql'

export function triggerDialectOf(dialect: string): TriggerDialect {
  if (dialect === 'sqlite3' || dialect === 'better-sqlite3') return 'sqlite'
  if (dialect === 'postgres') return 'postgres'
  if (dialect === 'mysql' || dialect === 'mysql2') return 'mysql'
  throw new UnsupportedDialectError(
    `relationPartitionTrigger: dialecto '${dialect}' sin observación en la suite ` +
      `(hoy: PostgreSQL, MySQL 8 y SQLite). El trigger de partición defiende al escritor a mano, ` +
      `y su DDL no se declara igual en dos motores: mídelo antes de dar por buena una tabla sin defensa.`
  )
}

/** Las sentencias a EJECUTAR (enteras) para crear el trigger de partición. */
export function relationPartitionTrigger(dialect: string): string[] {
  const kind = triggerDialectOf(dialect)
  if (kind === 'sqlite') {
    const body = (event: 'INSERT' | 'UPDATE') =>
      `CREATE TRIGGER authz_relations_partition_b${event === 'INSERT' ? 'i' : 'u'} ` +
      `BEFORE ${event} ON ${RELATIONS_TABLE} FOR EACH ROW ` +
      `WHEN NEW.subject_relation <> '' AND NEW.subject_partition IS NOT NEW.partition_key ` +
      `BEGIN SELECT RAISE(ABORT, '${TRIGGER_MESSAGE}'); END`
    return [body('INSERT'), body('UPDATE')]
  }
  if (kind === 'postgres') {
    return [
      `CREATE OR REPLACE FUNCTION authz_relations_partition_guard() RETURNS trigger LANGUAGE plpgsql AS $authz$ ` +
        `BEGIN ` +
        `IF NEW.subject_relation <> '' AND NEW.subject_partition IS DISTINCT FROM NEW.partition_key THEN ` +
        `RAISE EXCEPTION '${TRIGGER_MESSAGE} (subject_partition=%, partition_key=%)', NEW.subject_partition, NEW.partition_key; ` +
        `END IF; RETURN NEW; END; $authz$`,
      `CREATE TRIGGER authz_relations_partition_biu BEFORE INSERT OR UPDATE ON ${RELATIONS_TABLE} ` +
        `FOR EACH ROW EXECUTE FUNCTION authz_relations_partition_guard()`,
    ]
  }
  // mysql
  const body = (event: 'INSERT' | 'UPDATE') =>
    `CREATE TRIGGER authz_relations_partition_b${event === 'INSERT' ? 'i' : 'u'} ` +
    `BEFORE ${event} ON ${RELATIONS_TABLE} FOR EACH ROW ` +
    `BEGIN ` +
    `IF NEW.subject_relation <> '' AND NOT (NEW.subject_partition <=> NEW.partition_key) THEN ` +
    `SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '${TRIGGER_MESSAGE}'; ` +
    `END IF; END`
  return [body('INSERT'), body('UPDATE')]
}

/** Las sentencias para soltar el trigger (y, en PG, su función) en el `down()`. */
export function relationPartitionTriggerDrops(dialect: string): string[] {
  const kind = triggerDialectOf(dialect)
  if (kind === 'postgres') {
    return [
      `DROP TRIGGER IF EXISTS authz_relations_partition_biu ON ${RELATIONS_TABLE}`,
      'DROP FUNCTION IF EXISTS authz_relations_partition_guard()',
    ]
  }
  return [
    'DROP TRIGGER IF EXISTS authz_relations_partition_bi',
    'DROP TRIGGER IF EXISTS authz_relations_partition_bu',
  ]
}
