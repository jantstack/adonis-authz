/**
 * Driver `database` del puerto `RelationsDriver` — ReBAC sobre SQL propio
 * (Fase 4, lote 4-3).
 *
 * Los hechos de relación viven en la tabla `authz_relations` (una fila por
 * tupla, INSERT/DELETE-ONLY, decisión (c) del dueño). **La caducidad (R-15,
 * 2.4.0-alpha.2)** es la columna `expires_at` (NULL = no caduca), con los
 * MISMOS tres estados de `expiresAt` que `grant` (invariante 10), caducidad
 * ESTRICTA (`expires_at > now`, la que vence ahora ya no cuenta), el MISMO
 * codec por dialecto que `authz_assignments` (`sqlExpiryCodec`, 2.5-B · K2) y
 * el reloj inyectable `withClock` (2.5 · J1). **Renovar la caducidad es
 * delete+insert, nunca UPDATE** (decisión (c) del juez: un solo trigger por
 * evento, menos superficie de divergencia de motor; observable: la fila cambia
 * de `uuid`). La resolución de `check`/`membersOf`/`listObjects` —includes de
 * un nivel y usersets de grupos anidados— es una **CTE recursiva por dialecto**
 * (mismo patrón que `sql_descendants.ts`) que solo recorre hechos VIGENTES, y
 * el cruce de particiones lo defiende, además, el trigger
 * `relationPartitionTrigger` (defensa en profundidad para el escritor «a mano»;
 * el corte primario es la columna `partition_key` en cada consulta).
 *
 * Pureza: este módulo vive en `drivers/` y NO importa `openfga` (regla 3 de
 * `check_purity.mjs`) ni el `manager`. Consume solo el puerto (`../types.js`),
 * los errores, la gramática compartida (`../identity.js`), el guard SQL y el
 * TIPO de la config de relaciones (`../relations/define_relations_config.js`).
 */
import db from '@adonisjs/lucid/services/db'
import { v7 as uuidv7 } from 'uuid'
import {
  AuthorizationConfigError,
  InvalidIdentityError,
  UnsupportedDialectError,
  UnsupportedOperationError,
  WriteConflictError,
} from '../errors.js'
import { assertScope, assertSubject, assertExpiresAt, scopeKey, scopeSpellings } from '../identity.js'
import { relationPartitionTrigger, relationPartitionTriggerDrops } from '../relation_partition_trigger.js'
import { isClock, systemClock } from '../clock.js'
import type { Clock } from '../clock.js'
import { resolveGrantExpiry, sameInstant } from '../expiry.js'
import { sqlExpiryCodec } from '../shared/sql_expiry.js'
import type { ExpiryCodec } from '../shared/sql_expiry.js'
import { guardSql, isDeadlock, isUniqueViolation } from '../shared/backend_guard.js'
import { assertCallerTransaction } from '../shared/transaction_guard.js'
import { isRelUserset } from '../types.js'
import type {
  RelObject,
  RelSubject,
  RelationObjectsPage,
  RelationSubjectsPage,
  RelationPage,
  RelationTuple,
  RelationTuplePage,
  RelationsDriver,
  RelationsDriverCapabilities,
  RelationTransactionOptions,
  RelationWriteOptions,
  ScopeRef,
  SubjectRef,
} from '../types.js'
import { assertRelationDeclared } from '../relations/define_relations_config.js'
import type { RelationsConfig, RelationObjectTypeSpec } from '../relations/define_relations_config.js'

const DEFAULT_TIMEOUT_MS = 5_000
const RELATIONS_TABLE = 'authz_relations'
/** Longitud máxima del id de un objeto/holder de relación (columna `varchar(64)`). */
const RELATION_ID_MAX = 64
/** El tipo BUILT-IN portador de usersets (declarado por el generador, no por el consumidor). */
const GROUP_TYPE = 'group'
const GROUP_MEMBER = 'member'
/**
 * L-4b: lo que lleva `subject_relation` un HOLDER. Cadena vacía y no NULL
 * porque el UNIQUE `authz_rel_tuple_uq` incluye la columna y NULL ≠ NULL en
 * los tres motores (con NULL, dos `relate` concurrentes del mismo holder
 * confirmaban DOS filas). Cadena vacía y no un centinela (`'-'`) porque la
 * gramática de una relación (`[a-z0-9._-]{1,50}`) no admite la vacía: ningún
 * userset puede colisionar con ella.
 */
const HOLDER_RELATION = ''
/** Tamaño de página por defecto y tope de `enumerateRelations` (origen de reconcile). */
const DEFAULT_ENUMERATE_LIMIT = 100
const MAX_ENUMERATE_LIMIT = 1_000

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
  /**
   * Reloj de pared que DECIDE la caducidad (R-15, 2.5 · J1): `expires_at > now`
   * en cada lectura y los tres estados de `expiresAt` en `relate`. Default
   * `systemClock`; en producción lo aplica el `RelationsManager` con `clock`
   * (`withClock`). Los sellos (`created_at`) NO lo usan: son auditoría, no
   * decisiones (2.5-B · K5), y llevan el reloj del sistema.
   */
  now?: Clock
  /**
   * Lo que este despliegue DECLARA sobre `{ transaction }` (L-4, panel
   * `{trx}`; la misma opción que `DatabaseDriverOptions.transactionalWrites`
   * de roles, L-3). Default `true`: `relate`/`unrelate`/`purgeObject`/
   * `purgeSubject` escriben dentro de la transacción ABIERTA del llamante
   * (`TransactionClientContract` de Lucid de la conexión de ESTE driver —la
   * de `connection`, o la primaria—, `assertCallerTransaction`), «los dos o
   * ninguno». Eso **exige pool ≥ 2**: la autoridad (la barrera del freeze del
   * `RelationsManager`) se lee por la conexión del motor mientras el llamante
   * sostiene la suya, y con pool 1 (SQLite `:memory:`) la barrera sale 503
   * `E_AUTHZ_BACKEND_TIMEOUT` a `freezeTimeoutMs` — fail-closed, nunca un
   * bypass, pero un 503 tardío. Un despliegue con pool 1 declara `false` aquí
   * y la puerta 1 del manager responde 500 `E_AUTHZ_UNSUPPORTED` al instante
   * y con cero sentencias.
   */
  transactionalWrites?: boolean
}

interface RelationRow {
  uuid: string
  partition_key: string
  object_type: string
  object_uuid: string
  relation: string
  subject_type: string
  subject_uuid: string
  /**
   * L-4b: `''` = holder, con valor = userset. La columna es `NOT NULL DEFAULT ''`
   * para que el UNIQUE `authz_rel_tuple_uq` defienda también al holder (NULL ≠
   * NULL en los tres motores). El driver NUNCA escribe NULL; en LECTURA tolera
   * una fila vieja con NULL (backfill no aplicado) y la trata como holder.
   */
  subject_relation: string
  subject_partition: string | null
  /** R-15: la caducidad (NULL = no caduca), escrita/leída por `ExpiryCodec`. */
  expires_at: unknown
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
   *  - `enumerateRelations: true` (4-5): es ORIGEN de `authz:reconcile` de
   *    relaciones — enumera los hechos DIRECTOS de la partición (`authz_relations`),
   *    paginados por la PK, sin filtrar ni derivar (invariante 7 + higiene de
   *    reconcile): la caña la ve el destino tal cual la escribió el origen.
   *  - `listObjectsTruncation: false`: sin tope de servidor, `listObjects` es exhaustiva.
   *  - `injectableClock: true` (R-15): `withClock(now)` fija el reloj que decide
   *    la caducidad (`expires_at > now`), como el driver `database` de roles.
   *  - `transactionalWrites: true` (L-4, default): las cuatro escrituras van
   *    por la transacción ABIERTA del llamante (`#writer()`,
   *    `assertCallerTransaction` contra la conexión de este driver). Lo que
   *    NO viaja por ella: la barrera del freeze y F-05 (autoridad). Un
   *    despliegue con pool 1 lo declara `false` (ver las opciones).
   */
  readonly capabilities: Readonly<RelationsDriverCapabilities>
  /**
   * Con `transactionalWrites: false` declarado por el despliegue, un
   * `{ transaction }` que llegara igual (un llamante que se salta el manager)
   * se rechaza aquí también: no se ignora en silencio.
   */
  readonly #transactionalWrites: boolean

  readonly #config: RelationsConfig
  readonly #connectionName?: string
  readonly #timeoutMs: number
  readonly #now: Clock
  /** Inyectable para probar el dialecto ajeno sin servidor. */
  readonly #database: { connection(name?: string): any; primaryConnectionName?: string }
  #expiryCodec?: ExpiryCodec

  constructor(
    config: RelationsConfig,
    options: DatabaseRelationsDriverOptions = {},
    database: { connection(name?: string): any; primaryConnectionName?: string } = db
  ) {
    this.#config = config
    this.#connectionName = options.connection
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.#now = options.now ?? systemClock
    this.#database = database
    this.#transactionalWrites = options.transactionalWrites ?? true
    this.capabilities = Object.freeze({
      singleCheckRelations: true,
      listObjectsInherited: false,
      usersetSubjects: true,
      membersOfNative: true,
      enumerateRelations: true,
      listObjectsTruncation: false,
      injectableClock: true,
      transactionalWrites: this.#transactionalWrites,
    })
  }

  /**
   * Vista de este driver con OTRO reloj de pared (R-15, paridad con
   * `AuthorizationDriver.withClock`): misma conexión, config y deadline; solo
   * cambia el `now` que decide la caducidad. El driver no tiene estado propio
   * (la conexión es del servicio `db`), así que la vista es una instancia nueva.
   */
  withClock(now: Clock): RelationsDriver {
    if (!isClock(now)) {
      throw new AuthorizationConfigError(`withClock: now debe ser una función () => Date (llegó ${typeof now})`)
    }
    return new DatabaseRelationsDriver(
      this.#config,
      { connection: this.#connectionName, timeoutMs: this.#timeoutMs, now, transactionalWrites: this.#transactionalWrites },
      this.#database
    )
  }

  /* ── Infraestructura ──────────────────────────────────────────────────── */

  #connection(): any {
    return this.#database.connection(this.#connectionName)
  }

  /** El codec de `expires_at` por dialecto (K2): se decide una vez por driver, sin consulta. */
  get #expiry(): ExpiryCodec {
    this.#expiryCodec ??= sqlExpiryCodec(this.#connection())
    return this.#expiryCodec
  }

  /**
   * El predicado SQL de VIGENCIA (R-15, caducidad ESTRICTA): sin caducidad o
   * con caducidad FUTURA — la que vence en `now` ya no cuenta. Para el SQL
   * crudo de las CTEs (`q` cita el identificador; la binding es `bind(now)`
   * del codec, con UN solo `now` por operación, 2.5-B · K9).
   */
  #activeSql(q: (name: string) => string, alias: string): string {
    return `(${alias}.${q('expires_at')} IS NULL OR ${alias}.${q('expires_at')} > ?)`
  }

  /** El mismo predicado, para el query builder. */
  #whereActive(query: any, at: Date): any {
    const bound = this.#expiry.bind(at)
    return query.where((b: any) => b.whereNull('expires_at').orWhere('expires_at', '>', bound))
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

  /** La conexión de quien ESCRIBE: la declarada, o la primaria de Lucid (`undefined` con un `db` doble sin ella). */
  #ownerConnection(): string | undefined {
    return this.#connectionName ?? this.#database.primaryConnectionName
  }

  /**
   * Por dónde escribe `operation` (L-4, el MISMO patrón que `writer()` del
   * driver de roles, L-3): la transacción ABIERTA del llamante si llegó en
   * `options.transaction` —validada contra la conexión de ESTE driver por
   * `assertCallerTransaction`: otra conexión, un `QueryClient` o el `db`
   * entero son 500 `E_AUTHZ_CONFIG` ANTES de tocar nada—, o la conexión del
   * driver. `external` dice cuál de los dos.
   *
   * Solo la ESCRITURA va por ella (y la lectura «¿ya existe?» de `relate`,
   * que forma parte de la misma escritura: un `relate` y su renovación en la
   * misma transacción tienen que verse). La AUTORIDAD no: la barrera del
   * freeze la lee el `RelationsManager` por la conexión del motor, y F-05 y la
   * gramática cortan antes de llegar aquí.
   */
  #writer(operation: string, options: RelationTransactionOptions | undefined): { client: any; external: boolean } {
    if (options?.transaction === undefined || options.transaction === null) {
      return { client: this.#connection(), external: false }
    }
    if (!this.#transactionalWrites) {
      throw new UnsupportedOperationError(
        'transactionalWrites',
        operation,
        'database',
        'Este despliegue declara transactionalWrites: false en las opciones del driver de relaciones (pool 1): ' +
          '{ transaction } no se admite. Quita la opción (exige pool ≥ 2) o no pases transaction.'
      )
    }
    const trx = assertCallerTransaction(`database-relations.${operation}`, options.transaction, {
      connection: this.#ownerConnection(),
    })
    return { client: trx, external: true }
  }

  /**
   * Una sentencia que falla DENTRO de la transacción del llamante no se
   * absorbe (L-4, paridad con `poisoned()` de roles): en PostgreSQL la
   * transacción ya está ABORTADA (toda sentencia posterior es `25P02` hasta
   * el rollback) y en REPEATABLE READ una relectura no vería al ganador. Así
   * que un choque del UNIQUE de `authz_relations` (dos `relate` del mismo
   * hecho en dos transacciones abiertas) y un **deadlock** (dos transacciones
   * que escriben dos relaciones en orden cruzado: el motor elige una víctima y
   * la deshace —PG `40P01`, MySQL `1213`—) salen como **409
   * `E_AUTHZ_WRITE_CONFLICT`** —«envenena tu transacción: haz rollback y
   * reintenta»—; un deadline vencido sigue siendo el 503
   * `E_AUTHZ_BACKEND_TIMEOUT` que ya clasificó `#sql`, y cualquier otro fallo,
   * su 503. Nunca una segunda sentencia sobre una transacción que puede estar
   * abortada. (Medido por motor en `tests/relations_database.spec.ts`.)
   */
  #poisoned(operation: string, error: unknown): never {
    if (isUniqueViolation(error)) {
      throw new WriteConflictError(
        `database-relations.${operation}: la tupla la escribió otra transacción mientras la tuya estaba abierta ` +
          '(choque del UNIQUE dentro de tu transacción). No se puede absorber ahí dentro: la transacción queda ' +
          'envenenada (en PostgreSQL, abortada). Haz rollback y reintenta.',
        { cause: error }
      )
    }
    if (isDeadlock(error)) {
      throw new WriteConflictError(
        `database-relations.${operation}: el motor detectó un DEADLOCK con otra transacción y eligió la tuya ` +
          'como víctima (dos transacciones escribiendo las mismas tuplas en orden cruzado). La transacción queda ' +
          'envenenada (PostgreSQL la aborta; MySQL la deshace entera). Haz rollback y reintenta.',
        { cause: error }
      )
    }
    throw error
  }

  /* ── Validación de identidad (defensa en profundidad) ─────────────────── */

  /** El objeto es `{ type, id }` bien formado (F-05 —tipo/relación declarados— la aplica `assertRelationDeclared` en `relate`/`unrelate`, L-0). */
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

  /**
   * Valida el sujeto (holder o userset) y devuelve sus columnas. L-4b: el
   * holder lleva `relation: ''` (NUNCA NULL): es lo que hace que el UNIQUE
   * `authz_rel_tuple_uq` lo defienda (`'' = ''`, mientras que NULL ≠ NULL).
   */
  #subjectColumns(subject: RelSubject, partitionKey: string): {
    type: string
    uuid: string
    relation: string
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
    return { type: subject.type, uuid: subject.uuid, relation: HOLDER_RELATION, partition: null }
  }

  /**
   * El WHERE por `subject_relation`. Para un userset, su relación exacta. Para
   * un HOLDER (`''`), **tolerante a NULL**: una fila vieja con NULL (alpha.1
   * sin el backfill de L-4b) sigue siendo el mismo hecho, y si `unrelate`/
   * `purgeSubject` no la vieran seguiría concediendo tras retirarla
   * (fail-open); el «¿ya existe?» de `relate` también la encuentra, así que
   * renovar su caducidad la sustituye por una fila con `''`.
   */
  #whereSubjectRelation(b: any, relation: string): void {
    if (relation === HOLDER_RELATION) b.where('subject_relation', HOLDER_RELATION).orWhereNull('subject_relation')
    else b.where('subject_relation', relation)
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
    options?: RelationWriteOptions
  ): Promise<void> {
    // L-0 · F-05 en el DRIVER (la MISMA función que el manager): la red para
    // quien entra por `manager.driver()` o por `reconcileRelations`. Corta
    // ANTES de pedir la conexión. En `database` la tabla es propia (inocuo),
    // pero el 422 es el MISMO que en `openfga`, donde el store es compartido.
    assertRelationDeclared(this.#config, object, relation)
    assertScope(partition)
    this.#assertObject(object)
    this.#assertId(`la relación de '${object.type}'`, relation, RELATION_ID_MAX)
    // R-15 (defensa en profundidad; el manager ya lo validó): los tres estados.
    assertExpiresAt(options?.expiresAt)
    const requested = options?.expiresAt
    const partitionKey = scopeKey(partition)
    const s = this.#subjectColumns(subject, partitionKey)
    const codec = this.#expiry
    const now = this.#now()
    // L-4: por la transacción del llamante si llegó (`#writer`, juzgada AQUÍ,
    // después de F-05 y la gramática y antes de la primera sentencia).
    const { client, external } = this.#writer('relate', options)
    // El check-then-delete-insert idempotente. Con transacción EXTERNA corre
    // tal cual sobre ella (el trigger de partición dispara en ESE INSERT,
    // dentro de la trx del consumidor; NUNCA se abre una interna: la fila
    // confirmaría sola y sobreviviría al rollback del llamante). Sin ella, en
    // una transacción INTERNA de la conexión del driver (la atomicidad
    // trigger+insert de 4-3). Cada sentencia lleva su deadline (`#sql`).
    const write = async (trx: any) => {
      const existing: Array<{ uuid: string; expires_at: unknown }> = await this.#sql('relate.select', () =>
        trx
          .from(RELATIONS_TABLE)
          .where('partition_key', partitionKey)
          .where('object_type', object.type)
          .where('object_uuid', object.id)
          .where('relation', relation)
          .where('subject_type', s.type)
          .where('subject_uuid', s.uuid)
          .where((b: any) => this.#whereSubjectRelation(b, s.relation))
          .select('uuid', codec.select('expires_at'))
          .limit(1)
      )
      const current = existing[0]
      const previous = current ? codec.fromDb(current.expires_at) : null
      // Los tres estados (invariante 10): omitido preserva la VIGENTE (una
      // caducada revive sin caducidad), null la quita, Date la fija.
      const expiresAt = resolveGrantExpiry(previous, requested, now)
      if (current) {
        // Idempotente (invariante 6): la misma caducidad no reescribe nada.
        if (sameInstant(previous, expiresAt)) return
        // **INSERT/DELETE-ONLY (decisión (c))**: cambiar la caducidad es
        // BORRAR la fila e INSERTAR otra —nunca un UPDATE—; la fila nueva
        // tiene otro `uuid`, que es lo que lo hace observable. Dentro de la
        // trx del llamante, el rollback devuelve la fila (y la caducidad) VIEJA.
        await this.#sql('relate.delete', () => trx.from(RELATIONS_TABLE).where('uuid', current.uuid).delete())
      }
      await this.#sql('relate.insert', () =>
        trx.table(RELATIONS_TABLE).insert({
          uuid: uuidv7(),
          partition_key: partitionKey,
          object_type: object.type,
          object_uuid: object.id,
          relation,
          subject_type: s.type,
          subject_uuid: s.uuid,
          subject_relation: s.relation,
          subject_partition: s.partition,
          expires_at: codec.toDb(expiresAt),
          // Sello de auditoría, no decisión (2.5-B · K5): reloj del SISTEMA
          // (con el reloj inyectado en 2099 un TIMESTAMP de MySQL reventaría).
          created_at: systemClock(),
        } satisfies RelationRow)
      )
    }
    if (external) {
      try {
        await write(client)
      } catch (error) {
        this.#poisoned('relate', error)
      }
      return
    }
    await this.#sql('relate', () => client.transaction(write))
  }

  async unrelate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    options?: RelationWriteOptions
  ): Promise<void> {
    // L-0 · F-05 también al RETIRAR (paridad con `openfga`).
    assertRelationDeclared(this.#config, object, relation)
    assertScope(partition)
    this.#assertObject(object)
    this.#assertId(`la relación de '${object.type}'`, relation, RELATION_ID_MAX)
    const partitionKey = scopeKey(partition)
    const s = this.#subjectColumns(subject, partitionKey)
    const { client, external } = this.#writer('unrelate', options)
    try {
      await this.#sql('unrelate', () =>
        client
          .from(RELATIONS_TABLE)
          .where('partition_key', partitionKey)
          .where('object_type', object.type)
          .where('object_uuid', object.id)
          .where('relation', relation)
          .where('subject_type', s.type)
          .where('subject_uuid', s.uuid)
          .where((b: any) => this.#whereSubjectRelation(b, s.relation))
          .delete()
      )
    } catch (error) {
      if (external) this.#poisoned('unrelate', error)
      throw error
    }
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

    const at = this.#expiry.bind(this.#now())
    const { cte, bindings: cteBindings } = this.#principalCte(meta, q, s, partitionKey, at)
    const relPlaceholders = relations.map(() => '?').join(', ')
    const sql =
      cte +
      ` SELECT ${meta.hint}1 FROM ${q(RELATIONS_TABLE)} r ` +
      `JOIN principal p ON r.${q('subject_type')} = p.p_type AND r.${q('subject_uuid')} = p.p_uuid ` +
      `AND COALESCE(r.${q('subject_relation')}, '') = p.p_rel ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = ? AND r.${q('object_uuid')} = ? ` +
      `AND r.${q('relation')} IN (${relPlaceholders}) AND ${this.#activeSql(q, 'r')} LIMIT 1`
    const bindings = [...cteBindings, partitionKey, object.type, object.id, ...relations, at]
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

    const at = this.#expiry.bind(this.#now())
    const { cte, bindings: cteBindings } = this.#principalCte(meta, q, s, partitionKey, at)
    const relPlaceholders = relations.map(() => '?').join(', ')
    const sql =
      cte +
      ` SELECT ${meta.hint}DISTINCT r.${q('object_uuid')} AS ${q('object_uuid')} FROM ${q(RELATIONS_TABLE)} r ` +
      `JOIN principal p ON r.${q('subject_type')} = p.p_type AND r.${q('subject_uuid')} = p.p_uuid ` +
      `AND COALESCE(r.${q('subject_relation')}, '') = p.p_rel ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = ? ` +
      `AND r.${q('relation')} IN (${relPlaceholders}) AND ${this.#activeSql(q, 'r')}`
    const bindings = [...cteBindings, partitionKey, objectType, ...relations, at]
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
    // usersets (`group#member`) salen junto con los holders. Solo VIGENTES (R-15).
    const now = this.#now()
    const rows: any[] = await this.#sql('listSubjects', () =>
      this.#whereActive(
        this.#connection()
          .from(RELATIONS_TABLE)
          .where('partition_key', partitionKey)
          .where('object_type', object.type)
          .where('object_uuid', object.id)
          .where('relation', relation),
        now
      ).select('subject_type', 'subject_uuid', 'subject_relation')
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
    const at = this.#expiry.bind(this.#now())
    const active = this.#activeSql(q, 'r')

    // `grp`: los grupos alcanzables por usersets desde (object, RS) —directos y
    // anidados—. Ancla de UN solo SELECT (MySQL no mezcla UNION ALL con la
    // recursión): los usersets directos del objeto para cualquier rel de RS.
    // Solo hechos VIGENTES en los cuatro tramos (R-15): una membresía caducada
    // no lleva a nadie dentro.
    const sql =
      `WITH RECURSIVE grp(g_uuid) AS ( ` +
      `SELECT r.${q('subject_uuid')} FROM ${q(RELATIONS_TABLE)} r ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = ? AND r.${q('object_uuid')} = ? ` +
      `AND r.${q('relation')} IN (${relPlaceholders}) AND r.${q('subject_type')} = '${GROUP_TYPE}' ` +
      `AND r.${q('subject_relation')} = '${GROUP_MEMBER}' AND ${active} ` +
      `UNION ` +
      `SELECT r.${q('subject_uuid')} FROM ${q(RELATIONS_TABLE)} r ` +
      `JOIN grp ON r.${q('object_uuid')} = grp.g_uuid ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = '${GROUP_TYPE}' ` +
      `AND r.${q('relation')} = '${GROUP_MEMBER}' AND r.${q('subject_type')} = '${GROUP_TYPE}' ` +
      `AND r.${q('subject_relation')} = '${GROUP_MEMBER}' AND ${active} ` +
      `) ` +
      // Holders directos del objeto para RS, UNION holders directos de cualquier grupo de `grp`.
      `SELECT ${meta.hint}${q('subject_type')} AS ${q('subject_type')}, ${q('subject_uuid')} AS ${q('subject_uuid')} ` +
      `FROM ${q(RELATIONS_TABLE)} r ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = ? AND r.${q('object_uuid')} = ? ` +
      `AND r.${q('relation')} IN (${relPlaceholders}) AND COALESCE(r.${q('subject_relation')}, '') = '' AND ${active} ` +
      `UNION ` +
      `SELECT r.${q('subject_type')}, r.${q('subject_uuid')} FROM ${q(RELATIONS_TABLE)} r ` +
      `JOIN grp ON r.${q('object_uuid')} = grp.g_uuid ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = '${GROUP_TYPE}' ` +
      `AND r.${q('relation')} = '${GROUP_MEMBER}' AND COALESCE(r.${q('subject_relation')}, '') = '' AND ${active}`
    const bindings = [
      // grp ancla
      partitionKey, object.type, object.id, ...relations, at,
      // grp recursiva
      partitionKey, at,
      // holders directos del objeto
      partitionKey, object.type, object.id, ...relations, at,
      // holders de los grupos
      partitionKey, at,
    ]
    const rows = rowsOf(await this.#raw('membersOf', sql, bindings))
    const subjects: RelSubject[] = rows.map(
      (row: any): SubjectRef => ({ type: String(row.subject_type), uuid: String(row.subject_uuid) })
    )
    return { subjects }
  }

  /* ── Purga (invariante 11): el DELETE demuestra el cero ───────────────── */

  async purgeObject(object: RelObject, partition: ScopeRef, options?: RelationTransactionOptions): Promise<void> {
    assertScope(partition)
    this.#assertObject(object)
    const partitionKeys = this.#partitionSpellings(partition)
    // L-4: por la transacción del llamante si llegó — la purga borra y
    // REVIERTE con ella (tras un rollback todo lo purgado está de vuelta).
    const { client, external } = this.#writer('purgeObject', options)
    try {
      await this.#sql('purgeObject', () =>
        client
          .from(RELATIONS_TABLE)
          .whereIn('partition_key', partitionKeys)
          .where('object_type', object.type)
          .where('object_uuid', object.id)
          .delete()
      )
    } catch (error) {
      if (external) this.#poisoned('purgeObject', error)
      throw error
    }
  }

  async purgeSubject(subject: RelSubject, partition: ScopeRef, options?: RelationTransactionOptions): Promise<void> {
    assertScope(partition)
    const partitionKeys = this.#partitionSpellings(partition)
    const s = this.#subjectColumns(subject, scopeKey(partition))
    const { client, external } = this.#writer('purgeSubject', options)
    try {
      await this.#sql('purgeSubject', () =>
        client
          .from(RELATIONS_TABLE)
          .whereIn('partition_key', partitionKeys)
          .where('subject_type', s.type)
          .where('subject_uuid', s.uuid)
          .where((b: any) => this.#whereSubjectRelation(b, s.relation))
          .delete()
      )
    } catch (error) {
      if (external) this.#poisoned('purgeSubject', error)
      throw error
    }
  }

  /* ── ORIGEN de reconcile (4-5): enumera los hechos directos ───────────── */

  /**
   * **`enumerateRelations` — el ORIGEN de `authz:reconcile` de relaciones**
   * (4-5). Devuelve los hechos DIRECTOS de la partición (`authz_relations`),
   * paginados por la PK (`uuid`, cursor que AVANZA), sin derivar por
   * includes/usersets (el modelo del destino lo recompone): el destino recibe
   * los hechos tal cual y decide qué escribe (invariante 7 + la higiene de
   * reconcile — **la caducada LLEGA con su `expiresAt`**, R-15, para contarse
   * en `skipped`; filtrarla aquí la haría desaparecer sin rastro). Barre las
   * DOS ortografías del uuid de partición (🟡2,
   * coherente con `purge*`): un origen que las funde no puede dejar hechos del
   * alias sin migrar.
   *
   * **Filtra por TIPOS DECLARADOS** (⚪3, paridad con `openfga`): el driver
   * `openfga` descarta de su enumeración todo `object_type` que no sea `group`
   * ni un tipo de `defineRelationsConfig`; el de `database` NO lo hacía y
   * devolvía TODA fila. Como `reconcileRelations` escribe `to.relate(...)`
   * DIRECTO (salta el manager/F-05), una fila `object_type='role_binding'`
   * sembrada a mano habría migrado al store compartido y reabierto la escalada.
   * Con el filtro ambos drivers censan lo mismo y el chokepoint no deja residuo
   * por el camino de reconcile.
   */
  async enumerateRelations(partition: ScopeRef, page?: RelationPage): Promise<RelationTuplePage> {
    assertScope(partition)
    const partitionKeys = this.#partitionSpellings(partition)
    const declaredTypes = [GROUP_TYPE, ...this.#config.objectTypes.map((t) => t.type)]
    const limit = Math.max(1, Math.min(page?.limit ?? DEFAULT_ENUMERATE_LIMIT, MAX_ENUMERATE_LIMIT))
    const after = page?.after
    const rows: RelationRow[] = await this.#sql('enumerateRelations', () => {
      let q = this.#connection()
        .from(RELATIONS_TABLE)
        .whereIn('partition_key', partitionKeys)
        .whereIn('object_type', declaredTypes)
        .orderBy('uuid', 'asc')
        .limit(limit + 1)
      if (after) q = q.where('uuid', '>', after)
      return q.select(
        'uuid',
        'object_type',
        'object_uuid',
        'relation',
        'subject_type',
        'subject_uuid',
        'subject_relation',
        this.#expiry.select('expires_at')
      )
    })
    const hasMore = rows.length > limit
    const pageRows = hasMore ? rows.slice(0, limit) : rows
    const tuples: RelationTuple[] = pageRows.map((row) => ({
      subject: this.#rowToSubject(row),
      relation: String(row.relation),
      object: { type: String(row.object_type), id: String(row.object_uuid) },
      // La partición canónica pedida: el barrido de ortografías ya la unificó.
      partition,
      expiresAt: this.#expiry.fromDb(row.expires_at),
    }))
    const cursor = hasMore ? String(pageRows[pageRows.length - 1].uuid) : undefined
    return cursor ? { tuples, cursor } : { tuples }
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
    s: { type: string; uuid: string; relation: string },
    partitionKey: string,
    at: unknown
  ): { cte: string; bindings: unknown[] } {
    // L-4b: el holder ya viene con `''`; el `COALESCE(subject_relation, '')`
    // del JOIN es la tolerancia a una fila vieja con NULL.
    const baseRel = s.relation
    // Solo membresías VIGENTES suben por la recursión (R-15): una `member`
    // caducada no convierte al sujeto en miembro de nada.
    const cte =
      `WITH RECURSIVE principal(p_type, p_uuid, p_rel) AS ( ` +
      `SELECT ${meta.text('?')}, ${meta.text('?')}, ${meta.text('?')} ` +
      `UNION ` +
      `SELECT ${meta.text(`'${GROUP_TYPE}'`)}, r.${q('object_uuid')}, ${meta.text(`'${GROUP_MEMBER}'`)} ` +
      `FROM ${q(RELATIONS_TABLE)} r ` +
      `JOIN principal p ON r.${q('subject_type')} = p.p_type AND r.${q('subject_uuid')} = p.p_uuid ` +
      `AND COALESCE(r.${q('subject_relation')}, '') = p.p_rel ` +
      `WHERE r.${q('partition_key')} = ? AND r.${q('object_type')} = '${GROUP_TYPE}' ` +
      `AND r.${q('relation')} = '${GROUP_MEMBER}' AND ${this.#activeSql(q, 'r')} )`
    return { cte, bindings: [s.type, s.uuid, baseRel, partitionKey, at] }
  }

  /** `''` (L-4b) o NULL (fila vieja sin backfill) ⇒ holder; con valor ⇒ userset. */
  #rowToSubject(row: any): RelSubject {
    if (row.subject_relation === null || row.subject_relation === undefined || row.subject_relation === HOLDER_RELATION) {
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
