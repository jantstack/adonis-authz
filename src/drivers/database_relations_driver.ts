/**
 * Driver `database` del puerto `RelationsDriver` — ReBAC sobre SQL propio
 * (Fase 4, lote 4-3).
 *
 * Los hechos de relación viven en la tabla `authz_relations` (una fila por
 * tupla, INSERT/DELETE-ONLY, decisión (c) del dueño): NO hay `expires_at` y no
 * hay «renovar = delete+insert» (la caducidad de relaciones —R-15— quedó FUERA
 * de la 2.4, default del dueño). La resolución de `check`/`membersOf`/
 * `listObjects` —includes de un nivel y usersets de grupos anidados— es una
 * **CTE recursiva por dialecto** (mismo patrón que `sql_descendants.ts`), y el
 * cruce de particiones lo defiende, además, el trigger `relationPartitionTrigger`
 * (defensa en profundidad para el escritor «a mano»; el corte primario es la
 * columna `partition_key` en cada consulta).
 *
 * Pureza: este módulo vive en `drivers/` y NO importa `openfga` (regla 3 de
 * `check_purity.mjs`) ni el `manager`. Consume solo el puerto (`../types.js`),
 * los errores, la gramática compartida (`../identity.js`), el guard SQL y el
 * TIPO de la config de relaciones (`../relations/define_relations_config.js`).
 */
import db from '@adonisjs/lucid/services/db'
import { v7 as uuidv7 } from 'uuid'
import { InvalidIdentityError, UnsupportedDialectError } from '../errors.js'
import { assertScope, assertSubject, scopeKey, scopeSpellings } from '../identity.js'
import { relationPartitionTrigger, relationPartitionTriggerDrops } from '../relation_partition_trigger.js'
import { systemClock } from '../clock.js'
import type { Clock } from '../clock.js'
import { guardSql } from './backend_guard.js'
import { isRelUserset } from '../types.js'
import type {
  RelObject,
  RelSubject,
  RelationObjectsPage,
  RelationSubjectsPage,
  RelationPage,
  RelationsDriver,
  RelationsDriverCapabilities,
  RelationWriteOptions,
  ScopeRef,
  SubjectRef,
} from '../types.js'
import type { RelationsConfig, RelationObjectTypeSpec } from '../relations/define_relations_config.js'

const DEFAULT_TIMEOUT_MS = 5_000
const RELATIONS_TABLE = 'authz_relations'
/** Longitud máxima del id de un objeto/holder de relación (columna `varchar(64)`). */
const RELATION_ID_MAX = 64
/** El tipo BUILT-IN portador de usersets (declarado por el generador, no por el consumidor). */
const GROUP_TYPE = 'group'
const GROUP_MEMBER = 'member'

/** Formato de id de relación: minúsculas, dígitos y `._-`; sin separadores del store. */
const RELATION_ID_FORMAT = /^[a-z0-9_.-]+$/

/**
 * Metadatos SQL por dialecto: el carácter de cita de identificadores y cómo se
 * castea un literal a texto en el ANCLA de la CTE (MySQL/PG exigen que la
 * columna del término no-recursivo y la del recursivo tengan el MISMO tipo, o
 * la CTE recursiva no compila; SQLite es laxo pero el CAST no le molesta).
 */
interface DialectMeta {
  quote: '"' | '`'
  /** Castea `expr` a un texto lo bastante ancho para casar con las columnas de la tabla. */
  text(expr: string): string
  /** Hint de MySQL para no cortar la recursión a 1000 iteraciones (como en `sql_descendants`). */
  hint: string
}

const DIALECTS: Record<string, DialectMeta> = {
  postgres: { quote: '"', text: (e) => `CAST(${e} AS varchar(64))`, hint: '' },
  sqlite3: { quote: '"', text: (e) => `CAST(${e} AS text)`, hint: '' },
  'better-sqlite3': { quote: '"', text: (e) => `CAST(${e} AS text)`, hint: '' },
  mysql: { quote: '`', text: (e) => `CAST(${e} AS CHAR(64))`, hint: '/*+ SET_VAR(cte_max_recursion_depth = 50000) */ ' },
  mysql2: { quote: '`', text: (e) => `CAST(${e} AS CHAR(64))`, hint: '/*+ SET_VAR(cte_max_recursion_depth = 50000) */ ' },
}

// La DDL del trigger de partición vive en el módulo PURO
// `../relation_partition_trigger.js` (sin dependencia del servicio `db`, para
// que lo importe también el espejo del esquema, cargado antes de bootear la
// app). Se re-exporta aquí por comodidad del consumidor del driver.
export { relationPartitionTrigger, relationPartitionTriggerDrops }

export interface DatabaseRelationsDriverOptions {
  /** Nombre de la conexión Lucid (default: la primaria). */
  connection?: string
  /** Deadline de cada consulta en ms (default 5000): vencido ⇒ 503. */
  timeoutMs?: number
  /** Reloj de pared (sello de `created_at`); default `systemClock`. */
  now?: Clock
}

interface RelationRow {
  uuid: string
  partition_key: string
  object_type: string
  object_uuid: string
  relation: string
  subject_type: string
  subject_uuid: string
  subject_relation: string | null
  subject_partition: string | null
  created_at: Date
}

/**
 * El driver `database` de relaciones. Toda consulta pasa por `guardSql`: un
 * fallo del cliente SQL sale como `AuthorizationBackendError` (503), nunca como
 * el error crudo de knex (invariante 5).
 */
export class DatabaseRelationsDriver implements RelationsDriver {
  /**
   * Lo que declara (cada valor tiene su cara en `runRelationsDriverContract`):
   *  - `singleCheckRelations`: `check` es UNA consulta (la CTE resuelve includes
   *    + usersets anidados en un round-trip).
   *  - `listObjectsInherited: false`: los `list*` no abren un subárbol (invariante 7).
   *  - `usersetSubjects`: `listSubjects` incluye los usersets directos (`group#member`).
   *  - `membersOfNative`: la membresía TRANSITIVA la resuelve la CTE recursiva.
   *  - `enumerateRelations: false`: ser ORIGEN de `authz:reconcile` de relaciones es 4-5.
   *  - `listObjectsTruncation: false`: sin tope de servidor, `listObjects` es exhaustiva.
   */
  readonly capabilities: RelationsDriverCapabilities = Object.freeze({
    singleCheckRelations: true,
    listObjectsInherited: false,
    usersetSubjects: true,
    membersOfNative: true,
    enumerateRelations: false,
    listObjectsTruncation: false,
  })

  readonly #config: RelationsConfig
  readonly #connectionName?: string
  readonly #timeoutMs: number
  readonly #now: Clock
  /** Inyectable para probar el dialecto ajeno sin servidor. */
  readonly #database: { connection(name?: string): any }

  constructor(
    config: RelationsConfig,
    options: DatabaseRelationsDriverOptions = {},
    database: { connection(name?: string): any } = db
  ) {
    this.#config = config
    this.#connectionName = options.connection
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.#now = options.now ?? systemClock
    this.#database = database
  }

  /* ── Infraestructura ──────────────────────────────────────────────────── */

  #connection(): any {
    return this.#database.connection(this.#connectionName)
  }

  #dialectMeta(): DialectMeta {
    const connection = this.#connection()
    const name: string = connection?.dialect?.name ?? connection?.client?.driverName ?? 'desconocido'
    const meta = DIALECTS[name]
    if (!meta) {
      throw new UnsupportedDialectError(
        `DatabaseRelationsDriver: dialecto '${name}' sin observación en la suite ` +
          `(hoy: PostgreSQL, MySQL 8 y SQLite). La CTE recursiva del check no se declara igual en dos ` +
          `motores; impleméntala a mano para este motor.`
      )
    }
    return meta
  }

  #sql<T>(operation: string, fn: () => Promise<T>): Promise<T> {
    return guardSql('database-relations', operation, this.#timeoutMs, fn)
  }

  #raw(operation: string, text: string, bindings: unknown[]): Promise<any> {
    return this.#sql(operation, () => this.#connection().rawQuery(text, bindings))
  }

  /* ── Validación de identidad (defensa en profundidad) ─────────────────── */

  /** El objeto es `{ type, id }` bien formado (el `type` ya pasó F-05 en el manager). */
  #assertObject(object: RelObject): void {
    if (!object || typeof object !== 'object') {
      throw new InvalidIdentityError(`Objeto de relación inválido: llegó ${typeof object}`)
    }
    this.#assertId('el tipo de objeto', object.type, RELATION_ID_MAX)
    this.#assertId(`el id del objeto '${object.type}'`, object.id, RELATION_ID_MAX)
  }

  #assertId(kind: string, value: unknown, max: number): void {
    if (typeof value !== 'string' || value.length === 0 || value.length > max || !RELATION_ID_FORMAT.test(value)) {
      throw new InvalidIdentityError(
        `${kind} inválido: se esperaba una cadena de 1-${max} caracteres en minúsculas, dígitos y '._-' ` +
          `(llegó ${JSON.stringify(value)})`
      )
    }
  }

  /** Valida el sujeto (holder o userset) y devuelve sus columnas. */
  #subjectColumns(subject: RelSubject, partitionKey: string): {
    type: string
    uuid: string
    relation: string | null
    partition: string | null
  } {
    if (isRelUserset(subject)) {
      this.#assertObject(subject.object)
      this.#assertId(`la relación del userset '${subject.object.type}'`, subject.relation, RELATION_ID_MAX)
      // El userset comparte la partición de la tupla (el manager así lo exige);
      // se materializa en `subject_partition` para que el trigger lo defienda.
      return { type: subject.object.type, uuid: subject.object.id, relation: subject.relation, partition: partitionKey }
    }
    assertSubject(subject)
    return { type: subject.type, uuid: subject.uuid, relation: null, partition: null }
  }

  /* ── Expansión de includes (un nivel, hacia ABAJO desde la relación) ──── */

  #expandDown(objectType: string, relation: string): string[] {
    const out = new Set<string>([relation])
    const type = this.#config.objectTypes.find((t: RelationObjectTypeSpec) => t.type === objectType)
    const queue = [relation]
    while (queue.length) {
      const current = queue.pop()!
      const def = type?.relations.find((r) => r.name === current)
      for (const inc of def?.includes ?? []) {
        if (!out.has(inc)) {
          out.add(inc)
          queue.push(inc)
        }
      }
    }
    return [...out]
  }

  /* ── Escrituras ───────────────────────────────────────────────────────── */

  async relate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    _options?: RelationWriteOptions
  ): Promise<void> {
    assertScope(partition)
    this.#assertObject(object)
    this.#assertId(`la relación de '${object.type}'`, relation, RELATION_ID_MAX)
    const partitionKey = scopeKey(partition)
    const s = this.#subjectColumns(subject, partitionKey)
    // Transacción INTERNA: la atomicidad trigger+insert (el trigger corre en el
    // mismo INSERT; el check-then-insert idempotente va dentro de la misma
    // transacción). `{trx}` NO se expone en el puerto (decisión (b), diferido).
    await this.#sql('relate', () =>
      this.#connection().transaction(async (trx: any) => {
        const existing = await trx
          .from(RELATIONS_TABLE)
          .where('partition_key', partitionKey)
          .where('object_type', object.type)
          .where('object_uuid', object.id)
          .where('relation', relation)
          .where('subject_type', s.type)
          .where('subject_uuid', s.uuid)
          .where((b: any) => (s.relation === null ? b.whereNull('subject_relation') : b.where('subject_relation', s.relation)))
          .limit(1)
        if (existing.length > 0) return // idempotente (invariante 6): no duplica.
        await trx.table(RELATIONS_TABLE).insert({
          uuid: uuidv7(),
          partition_key: partitionKey,
          object_type: object.type,
          object_uuid: object.id,
          relation,
          subject_type: s.type,
          subject_uuid: s.uuid,
          subject_relation: s.relation,
          subject_partition: s.partition,
          created_at: this.#now(),
        } satisfies RelationRow)
      })
    )
  }

  async unrelate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    _options?: RelationWriteOptions
  ): Promise<void> {
    assertScope(partition)
    this.#assertObject(object)
    this.#assertId(`la relación de '${object.type}'`, relation, RELATION_ID_MAX)
    const partitionKey = scopeKey(partition)
    const s = this.#subjectColumns(subject, partitionKey)
    await this.#sql('unrelate', () =>
      this.#connection()
        .from(RELATIONS_TABLE)
        .where('partition_key', partitionKey)
        .where('object_type', object.type)
        .where('object_uuid', object.id)
        .where('relation', relation)
        .where('subject_type', s.type)
        .where('subject_uuid', s.uuid)
        .where((b: any) => (s.relation === null ? b.whereNull('subject_relation') : b.where('subject_relation', s.relation)))
        .delete()
    )
  }

  /* ── Lecturas ─────────────────────────────────────────────────────────── */

  async check(subject: RelSubject, relation: string, object: RelObject, partition: ScopeRef): Promise<boolean> {
    assertScope(partition)
    this.#assertObject(object)
    const partitionKey = scopeKey(partition)
    const s = this.#subjectColumns(subject, partitionKey)
    const relations = this.#expandDown(object.type, relation)
    const meta = this.#dialectMeta()
    const q = (name: string) => `${meta.quote}${name}${meta.quote}`

    const { cte, bindings: cteBindings } = this.#principalCte(meta, q, s, partitionKey)
    const relPlaceholders = relations.map(() => '?').join(', ')
    const sql =
      cte +
      ` SELECT ${meta.hint}1 FROM ${q(RELATIONS_TABLE)} r ` +
      `JOIN principal p ON r.${q('subject_type')} = p.p_type AND r.${q('subject_uuid')} = p.p_uuid ` +
      `AND COALESCE(r.${q('subject_relation')}, '') = p.p_rel ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = ? AND r.${q('object_uuid')} = ? ` +
      `AND r.${q('relation')} IN (${relPlaceholders}) LIMIT 1`
    const bindings = [...cteBindings, partitionKey, object.type, object.id, ...relations]
    const rows = rowsOf(await this.#raw('check', sql, bindings))
    return rows.length > 0
  }

  async listObjects(
    subject: RelSubject,
    relation: string,
    objectType: string,
    partition: ScopeRef,
    _page?: RelationPage
  ): Promise<RelationObjectsPage> {
    assertScope(partition)
    this.#assertId('el tipo de objeto', objectType, RELATION_ID_MAX)
    const partitionKey = scopeKey(partition)
    const s = this.#subjectColumns(subject, partitionKey)
    const relations = this.#expandDown(objectType, relation)
    const meta = this.#dialectMeta()
    const q = (name: string) => `${meta.quote}${name}${meta.quote}`

    const { cte, bindings: cteBindings } = this.#principalCte(meta, q, s, partitionKey)
    const relPlaceholders = relations.map(() => '?').join(', ')
    const sql =
      cte +
      ` SELECT ${meta.hint}DISTINCT r.${q('object_uuid')} AS ${q('object_uuid')} FROM ${q(RELATIONS_TABLE)} r ` +
      `JOIN principal p ON r.${q('subject_type')} = p.p_type AND r.${q('subject_uuid')} = p.p_uuid ` +
      `AND COALESCE(r.${q('subject_relation')}, '') = p.p_rel ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = ? ` +
      `AND r.${q('relation')} IN (${relPlaceholders})`
    const bindings = [...cteBindings, partitionKey, objectType, ...relations]
    const rows = rowsOf(await this.#raw('listObjects', sql, bindings))
    const objects: RelObject[] = rows
      .map((row: any): RelObject => ({ type: objectType, id: String(row.object_uuid) }))
      .sort((a: RelObject, b: RelObject) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    return { objects }
  }

  async listSubjects(
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    _page?: RelationPage
  ): Promise<RelationSubjectsPage> {
    assertScope(partition)
    this.#assertObject(object)
    const partitionKey = scopeKey(partition)
    // DIRECTOS del relation EXACTO (invariante 7): ni transitivo (eso es
    // `membersOf`) ni derivado por includes. `usersetSubjects: true` ⇒ los
    // usersets (`group#member`) salen junto con los holders.
    const rows: any[] = await this.#sql('listSubjects', () =>
      this.#connection()
        .from(RELATIONS_TABLE)
        .where('partition_key', partitionKey)
        .where('object_type', object.type)
        .where('object_uuid', object.id)
        .where('relation', relation)
        .select('subject_type', 'subject_uuid', 'subject_relation')
    )
    const subjects: RelSubject[] = rows.map((row: any) => this.#rowToSubject(row))
    return { subjects }
  }

  /**
   * Membresía TRANSITIVA de un objeto-grupo: todos los HOLDERS que son `member`
   * directa o a través de grupos anidados (usersets `group#member`). CTE
   * recursiva hacia ABAJO por los usersets. DISTINTA de `listSubjects` (hechos
   * directos): en un grupo con `member(g1#member, g2)`, `membersOf(g2)` trae a
   * los holders de g1 y `listSubjects(member, g2)` solo el userset `g1#member`.
   */
  async membersOf(
    object: RelObject,
    relation: string,
    partition: ScopeRef,
    _page?: RelationPage
  ): Promise<RelationSubjectsPage> {
    assertScope(partition)
    this.#assertObject(object)
    const partitionKey = scopeKey(partition)
    const relations = this.#expandDown(object.type, relation)
    const meta = this.#dialectMeta()
    const q = (name: string) => `${meta.quote}${name}${meta.quote}`
    const relPlaceholders = relations.map(() => '?').join(', ')

    // `grp`: los grupos alcanzables por usersets desde (object, RS) —directos y
    // anidados—. Ancla de UN solo SELECT (MySQL no mezcla UNION ALL con la
    // recursión): los usersets directos del objeto para cualquier rel de RS.
    const sql =
      `WITH RECURSIVE grp(g_uuid) AS ( ` +
      `SELECT r.${q('subject_uuid')} FROM ${q(RELATIONS_TABLE)} r ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = ? AND r.${q('object_uuid')} = ? ` +
      `AND r.${q('relation')} IN (${relPlaceholders}) AND r.${q('subject_type')} = '${GROUP_TYPE}' ` +
      `AND r.${q('subject_relation')} = '${GROUP_MEMBER}' ` +
      `UNION ` +
      `SELECT r.${q('subject_uuid')} FROM ${q(RELATIONS_TABLE)} r ` +
      `JOIN grp ON r.${q('object_uuid')} = grp.g_uuid ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = '${GROUP_TYPE}' ` +
      `AND r.${q('relation')} = '${GROUP_MEMBER}' AND r.${q('subject_type')} = '${GROUP_TYPE}' ` +
      `AND r.${q('subject_relation')} = '${GROUP_MEMBER}' ` +
      `) ` +
      // Holders directos del objeto para RS, UNION holders directos de cualquier grupo de `grp`.
      `SELECT ${meta.hint}${q('subject_type')} AS ${q('subject_type')}, ${q('subject_uuid')} AS ${q('subject_uuid')} ` +
      `FROM ${q(RELATIONS_TABLE)} r ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = ? AND r.${q('object_uuid')} = ? ` +
      `AND r.${q('relation')} IN (${relPlaceholders}) AND r.${q('subject_relation')} IS NULL ` +
      `UNION ` +
      `SELECT r.${q('subject_type')}, r.${q('subject_uuid')} FROM ${q(RELATIONS_TABLE)} r ` +
      `JOIN grp ON r.${q('object_uuid')} = grp.g_uuid ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = '${GROUP_TYPE}' ` +
      `AND r.${q('relation')} = '${GROUP_MEMBER}' AND r.${q('subject_relation')} IS NULL`
    const bindings = [
      // grp ancla
      partitionKey, object.type, object.id, ...relations,
      // grp recursiva
      partitionKey,
      // holders directos del objeto
      partitionKey, object.type, object.id, ...relations,
      // holders de los grupos
      partitionKey,
    ]
    const rows = rowsOf(await this.#raw('membersOf', sql, bindings))
    const subjects: RelSubject[] = rows.map(
      (row: any): SubjectRef => ({ type: String(row.subject_type), uuid: String(row.subject_uuid) })
    )
    return { subjects }
  }

  /* ── Purga (invariante 11): el DELETE demuestra el cero ───────────────── */

  async purgeObject(object: RelObject, partition: ScopeRef): Promise<void> {
    assertScope(partition)
    this.#assertObject(object)
    const partitionKeys = this.#partitionSpellings(partition)
    await this.#sql('purgeObject', () =>
      this.#connection()
        .from(RELATIONS_TABLE)
        .whereIn('partition_key', partitionKeys)
        .where('object_type', object.type)
        .where('object_uuid', object.id)
        .delete()
    )
  }

  async purgeSubject(subject: RelSubject, partition: ScopeRef): Promise<void> {
    assertScope(partition)
    const partitionKeys = this.#partitionSpellings(partition)
    const s = this.#subjectColumns(subject, scopeKey(partition))
    await this.#sql('purgeSubject', () =>
      this.#connection()
        .from(RELATIONS_TABLE)
        .whereIn('partition_key', partitionKeys)
        .where('subject_type', s.type)
        .where('subject_uuid', s.uuid)
        .where((b: any) => (s.relation === null ? b.whereNull('subject_relation') : b.where('subject_relation', s.relation)))
        .delete()
    )
  }

  /* ── Helpers privados ─────────────────────────────────────────────────── */

  /**
   * **Barre AMBAS ortografías del uuid de partición** (🟡2 del auditor,
   * paridad con el fix del lote 3b-2h): un motor que funde `aaa…` con `aaa-…`
   * (tipo `uuid` de PG, collation `*_ci`) haría del `DELETE` un no-op sobre el
   * alias y la fila real seguiría concediendo. `scopeSpellings` da la del
   * llamante Y la canónica de la que puede ser alias; se convierten a clave.
   */
  #partitionSpellings(partition: ScopeRef): string[] {
    const keys = scopeSpellings(partition).map((s) => scopeKey(s))
    return [...new Set(keys)]
  }

  /**
   * La CTE `principal`: el conjunto de identidades `(p_type, p_uuid, p_rel)` que
   * el SUJETO «es» —él mismo (holder ⇒ `p_rel = ''`; userset ⇒ su relación) más
   * cada `group#member` del que es miembro, transitivamente (grupos anidados)—.
   * Un `check`/`listObjects` casa un hecho directo del objeto contra cualquiera
   * de esas identidades. Devuelve el `WITH RECURSIVE …` (sin el SELECT final) y
   * sus bindings.
   */
  #principalCte(
    meta: DialectMeta,
    q: (name: string) => string,
    s: { type: string; uuid: string; relation: string | null },
    partitionKey: string
  ): { cte: string; bindings: unknown[] } {
    const baseRel = s.relation ?? ''
    const cte =
      `WITH RECURSIVE principal(p_type, p_uuid, p_rel) AS ( ` +
      `SELECT ${meta.text('?')}, ${meta.text('?')}, ${meta.text('?')} ` +
      `UNION ` +
      `SELECT ${meta.text(`'${GROUP_TYPE}'`)}, r.${q('object_uuid')}, ${meta.text(`'${GROUP_MEMBER}'`)} ` +
      `FROM ${q(RELATIONS_TABLE)} r ` +
      `JOIN principal p ON r.${q('subject_type')} = p.p_type AND r.${q('subject_uuid')} = p.p_uuid ` +
      `AND COALESCE(r.${q('subject_relation')}, '') = p.p_rel ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = '${GROUP_TYPE}' ` +
      `AND r.${q('relation')} = '${GROUP_MEMBER}' )`
    return { cte, bindings: [s.type, s.uuid, baseRel, partitionKey] }
  }

  #rowToSubject(row: any): RelSubject {
    if (row.subject_relation === null || row.subject_relation === undefined) {
      return { type: String(row.subject_type), uuid: String(row.subject_uuid) }
    }
    return { object: { type: String(row.subject_type), id: String(row.subject_uuid) }, relation: String(row.subject_relation) }
  }
}

/**
 * Forma del resultado crudo por cliente: pg `{ rows }`, sqlite `rows[]`,
 * mysql2 `[rows[], fields[]]` (2.5 · J3).
 */
function rowsOf(result: any): any[] {
  if (Array.isArray(result)) {
    return result.length === 2 && Array.isArray(result[0]) && Array.isArray(result[1]) ? result[0] : result
  }
  return result?.rows ?? []
}
