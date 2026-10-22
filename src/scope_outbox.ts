/**
 * **La outbox del árbol sobre Lucid** (3b-2d; panel 2, cruce 4 · S5).
 *
 * El puerto es `ScopeOutbox` (`src/types.ts`) y el paquete NO impone tabla:
 * cualquier implementación vale. Esta es la que se publica para quien no
 * quiera escribir la suya, junto con su migración
 * (`stubs/scopes_outbox_migration.stub`, que hay que COPIAR al proyecto:
 * `configure` no la publica sola porque la outbox es opt-in).
 *
 *   import { sqlScopeOutbox } from '@jantstack/adonis-authz'
 *
 *   const outbox = sqlScopeOutbox()
 *   export default defineConfig({
 *     scopes: { resolveChain, outbox },
 *     ...
 *   })
 *
 *   // y en el sitio donde mueves tu árbol:
 *   await db.transaction(async (trx) => {
 *     await authorization.scopes.moved(unit, nuevaOrg, { within, actor, transaction: trx })
 *     await unit.useTransaction(trx).merge({ organizationId: nuevaOrg.uuid }).save()
 *   })
 *
 * Lo único que tiene que cumplir una implementación del puerto es que
 * `enqueue` escriba DENTRO de la transacción que le pasan: es lo que hace
 * que el cambio del árbol y su propagación al backend confirmen —o se vayan—
 * juntos. Todo lo demás (nombres de columna, si las filas aplicadas se
 * borran o se marcan, si hay reintento con backoff) es del consumidor.
 *
 * Aquí las filas aplicadas se MARCAN (`applied_at`), no se borran: la cola
 * es también el registro de lo que se propagó y cuándo, y `authz:scopes:relay`
 * no puede ser silencioso.
 */

import { createHash } from 'node:crypto'
import db from '@adonisjs/lucid/services/db'
import { AuthorizationConfigError } from './errors.js'
import { systemClock } from './clock.js'
import type { Clock } from './clock.js'
import { assertScope, assertSubject } from './identity.js'
import { guardSql } from './shared/backend_guard.js'
import { assertCallerTransaction } from './shared/transaction_guard.js'
import { dialectOf, isSqliteDialect } from './shared/sql_expiry.js'
import { APP_SCOPE, APP_SCOPE_TYPE } from './types.js'
import type {
  PendingScopeTreeChange,
  ScopeOutbox,
  ScopeOutboxContext,
  ScopeOutboxFailure,
  ScopeOutboxLease,
  ScopeOutboxPendingFilter,
  ScopeRef,
  ScopeTreeChange,
} from './types.js'

export interface SqlScopeOutboxOptions {
  /** Tabla de la cola (default `authz_scope_outbox`, la del stub). */
  table?: string
  /** Nombre de la conexión Lucid (default: la primaria). */
  connection?: string
  /** Deadline de cada consulta en ms (default 5000): vencido ⇒ 503. */
  timeoutMs?: number
  /**
   * Reloj de pared con el que se sellan `created_at` y `applied_at`
   * (2.5 · J1). Default `() => new Date()`; inyectable para fijar el
   * instante en tests.
   */
  now?: Clock
  /**
   * **Cuántas veces se reintenta una entrada antes de APARCARLA** (3b-2h ·
   * 🔴 2; default 5). Alcanzado el tope, `pending()` deja de ofrecerla y sale
   * por `dead()`: hay entradas que no se pueden aplicar NUNCA —el scope padre
   * del `attached` encolado lo borró el tenant antes del relevo y no va a
   * volver— y sin tope esa fila se reintenta en todas las pasadas para
   * siempre. Aparcar no es olvidar: el relay la reporta en cada pasada y el
   * comando sale ≠ 0 mientras haya alguna, porque el árbol del backend queda
   * permanentemente divergente en ese nodo (lo reconcilia `authz:reconcile`,
   * 3b-3, o un `scopes.detached`/`attached` nuevo del consumidor).
   */
  maxAttempts?: number
  /**
   * **Encolar sin `{ transaction }` es 500** (2.4.0-alpha.8; panel relay 2,
   * cuestión 6; P13 del tester). Con `true`, `enqueue` sin la transacción
   * ABIERTA del llamante es 500 `E_AUTHZ_CONFIG` ANTES del INSERT: la fila
   * confirmaría sola, fuera de tu unidad de trabajo, y si tu transacción
   * revierte después el relay aplica al store un cambio que en TU base no
   * ocurrió — la fuga S5 por el camino de uso «correcto» (SQL dice un padre y
   * el PDP otro, sin que tu base pueda enseñártelo). Default **`true` desde
   * 2.5.0** (plan 2.5 · lote B · B6, decisión del dueño; en 2.4.0-alpha.8 era
   * `false` porque el contrato PUBLICADO encolaba sin transacción en `ctx()` —
   * desde B6 el contrato pasa la transacción del harness en TODO encolado,
   * directo y por el manager, y lo juzga el par `requiresTransaction`).
   * `requireTransaction: false` es el opt-out EXPLÍCITO: la firma de quien
   * encola fuera de su unidad de trabajo a sabiendas (un harness, un seeder).
   * `{ transaction }` por el manager exige pool ≥ 2 (la barrera del freeze lee
   * por OTRA conexión).
   */
  requireTransaction?: boolean
}

const DEFAULT_TABLE = 'authz_scope_outbox'
const DEFAULT_TIMEOUT_MS = 5_000
/** Intentos antes de aparcar una entrada (3b-2h · 🔴 2). */
const DEFAULT_MAX_ATTEMPTS = 5
/**
 * Leases tomados por ESTE proceso (SQLite y cualquier dialecto sin cerrojo de
 * sesión): la exclusión es entonces de proceso, no de despliegue, y va escrita
 * en el README. Con PostgreSQL y MySQL el cerrojo es del servidor.
 */
const localLeases = new Set<string>()
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/
/** Las tres operaciones del árbol, tal como se guardan en la columna `op`. */
const OPS = ['attached', 'moved', 'detached'] as const

/** Lo que se necesita del `db` de Lucid; inyectable para probar sin servidor. */
interface DatabaseLike {
  from(table: string): any
  table(table: string): any
}

/** El scope que va a la fila: la raíz se guarda como `app` con uuid nulo. */
function columnsOf(scope: ScopeRef): { type: string; uuid: string | null } {
  return { type: scope.type, uuid: scope.type === APP_SCOPE_TYPE ? null : scope.uuid }
}

/** La vuelta: `app` sin uuid es `APP_SCOPE`; el resto, la fila tal cual. */
function scopeOf(type: string, uuid: string | null): ScopeRef {
  return type === APP_SCOPE_TYPE ? APP_SCOPE : { type, uuid: uuid === null ? null : String(uuid) }
}

/**
 * Valida el cambio ANTES del INSERT (422): una cola es un diferido, y un
 * `ScopeRef` mal formado que entrara aquí explotaría días después dentro del
 * relay, lejos del call-site que lo escribió.
 */
function assertChange(change: ScopeTreeChange): void {
  if (!change || !OPS.includes(change.op as any)) {
    throw new AuthorizationConfigError(
      `sqlScopeOutbox: 'op' debe ser uno de ${OPS.join(', ')} (llegó ${String((change as any)?.op)})`
    )
  }
  assertScope(change.child)
  if (change.op !== 'detached') assertScope(change.parent)
}

/** Namespace de los advisory locks del paquete en PostgreSQL. */
const ADVISORY_LOCK_NAMESPACE = 0x617a

/** Tope de MySQL para el nombre de un `GET_LOCK` (más largo es un error 3158). */
const MYSQL_LOCK_NAME_MAX = 64

/**
 * **Los nombres del lease de una cola** (2.4.0-alpha.5 · R6; tester del panel
 * relay). Hasta alpha.4 el nombre era `authz_scope_outbox:<conexión>:<tabla>`
 * recortado a 64 caracteres para MySQL: dos despliegues cuya conexión+tabla
 * coincidieran en los primeros 64 COMPARTÍAN lease y se excluían para siempre
 * — y el modo de fallo era `busy: true`, que no lanza: el relay de uno de los
 * dos no corría nunca, en silencio. Desde alpha.5 el nombre es un hash
 * ESTABLE del nombre completo (`current`, 59 caracteres), que no colisiona entre
 * TABLAS — entre BASES del mismo servidor sí: el «nombre completo» no llevaba la
 * base (rotación 2 · R2-01, abajo).
 *
 * **Transición**: `sqlScopeOutbox.acquire()` toma el lock viejo (`legacy`, el
 * recortado) Y el nuevo durante alpha.5, porque en un rolling deploy un
 * proceso con alpha.4 y otro con alpha.5 tienen que seguir excluyéndose
 * (+0,56 ms medidos por `acquire`). El viejo se retira en 2.5 (CHANGELOG):
 * mientras dure la transición, dos tablas con los mismos 64 primeros
 * caracteres siguen compartiendo el `legacy` — la colisión solo se cierra
 * del todo al retirarlo. Exportado para que el caso lo fije sin MySQL.
 */
/**
 * **Retirada del lock viejo, atada a la versión (cierre alpha.6).** `acquire()` toma
 * el nombre `legacy` SOLO mientras `SCOPE_OUTBOX_TAKES_LEGACY_LOCK` sea `true`, y
 * `tests/scope_outbox.spec.ts` exige que ese flag valga exactamente
 * «`package.json` ≤ `SCOPE_OUTBOX_LEGACY_LOCK_UNTIL`»: en cuanto alguien suba la
 * versión por encima de la última que necesita la transición, la suite se pone en
 * ROJO hasta que el flag pase a `false` (y el caso MySQL de R6 se ajuste). Nadie
 * tiene que acordarse: el propio bump lo exige. Por qué no se retira en la misma
 * versión que estrena el nombre nuevo: durante un despliegue rodante los procesos
 * de alpha.4 sostienen el viejo y los nuevos el nuevo, y ninguno ve al otro —
 * dos escritores justo entonces.
 */
export const SCOPE_OUTBOX_LEGACY_LOCK_UNTIL = '2.4.0-alpha.6'
/**
 * `false` desde `2.4.0-alpha.7`: la transición terminó (decisión del dueño 2026-09-10: sin
 * consumidores en MySQL desplegando desde alpha.4, la transición no protegía a nadie). Subir
 * desde ≤ alpha.4 en MySQL exige parada completa del relay, no despliegue rodante.
 */
export const SCOPE_OUTBOX_TAKES_LEGACY_LOCK = false

/**
 * **La identidad de la BASE en el nombre del lease** (rotación 2 de M4 · R2-01, decisión del dueño 2026-10-22 (1)).
 * `GET_LOCK` es un cerrojo de SERVIDOR, y hasta 2.5.0-alpha.4 el nombre era `<conexión>:<tabla>`: dos despliegues en
 * BASES distintas del mismo MySQL con la conexión por defecto de Adonis y la tabla del stub calculaban el MISMO nombre y
 * se excluían (`busy`, exit 0) — el síntoma que R6 de alpha.5 daba por cerrado nunca lo estuvo, porque el «nombre
 * completo» no llevaba la base. Desde este cierre `current` lleva la base que la PROPIA conexión que sostiene el lease
 * lee con `DATABASE()` (no la del config: es la base contra la que esa sesión resuelve la tabla sin cualificar, o sea la
 * identidad real de la cola; un alias de host o una URL distinta que apunte a la misma base dan el mismo nombre).
 *
 * En MINÚSCULAS a propósito: los dos errores posibles no cuestan lo mismo. Fundir `App` y `app` (dos bases distintas en
 * un servidor sensible a mayúsculas) solo hace que esos dos despliegues compartan lease —vivacidad, `busy`—; separar la
 * misma base escrita de dos formas por dos procesos del MISMO despliegue serían dos escritores —seguridad—. Se elige el
 * error barato. `DATABASE()` `NULL` (sesión sin base por defecto: la tabla tiene que ir cualificada) entra como cadena
 * vacía: los procesos de ese despliegue siguen calculando el mismo nombre.
 *
 * Los tres nombres: `legacy` (el recortado a 64 de ≤ alpha.4, retirado en alpha.7, se conserva para el caso que lo
 * fija), `unscoped` (el sha1 sin base de 2.4.0-alpha.5..2.5.0-alpha.4) y `current` (el sha1 con base). Sin `database`
 * —quien no ha abierto conexión: los casos de identidad pura— `current` es `unscoped`.
 */
export function scopeOutboxLockNames(
  connection: string | undefined,
  table: string,
  database?: string | null
): { legacy: string; unscoped: string; current: string } {
  const full = `authz_scope_outbox:${connection ?? 'default'}:${table}`
  const sha = (value: string) => `authz_scope_outbox:${createHash('sha1').update(value).digest('hex')}`
  const unscoped = sha(full)
  return {
    legacy: full.slice(0, MYSQL_LOCK_NAME_MAX),
    unscoped,
    current: database === undefined ? unscoped : sha(`${full}@db:${String(database ?? '').toLowerCase()}`),
  }
}

/**
 * **La transición del nombre sin base** (rotación 2 · R2-01, firmada: «como alpha.5»). En 2.5.x `acquire()` toma el
 * nombre VIEJO (`unscoped`, el de 2.4.0-alpha.5..2.5.0-alpha.4) y DESPUÉS el nuevo (`current`, con la base), y suelta
 * los dos: en un despliegue rodante un proceso de alpha.4 solo conoce el viejo, y los dos tienen que seguir
 * excluyéndose. **El precio, declarado**: mientras se tome el viejo, dos despliegues en bases distintas del mismo
 * servidor SIGUEN compartiéndolo — R2-01 queda abierto en 2.5.x y se cierra al retirarlo en 2.6 (README «Limits»,
 * `relay.mysql-unscoped-lease`; backlog 2.6). Atado a la versión como en alpha.6: `tests/rotacion2_cierre.spec.ts` exige
 * que valga exactamente «`package.json` < `SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN`» (`2.6.0-alpha.0`: toda 2.6, sus
 * prereleases incluidas), así que el bump a 2.6 pone la suite en rojo hasta retirarlo.
 */
export const SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN = '2.6.0-alpha.0'
export const SCOPE_OUTBOX_TAKES_UNSCOPED_LOCK = true

/** Hash de 32 bits con signo (lo que acepta `pg_try_advisory_xact_lock`). */
function hash32(value: string): number {
  let hash = 0
  for (let i = 0; i < value.length; i++) hash = (Math.imul(hash, 31) + value.charCodeAt(i)) | 0
  return hash
}

/** El primer valor de un `rawQuery`, sea cual sea la forma del dialecto. */
function firstValue(result: any, column: string): unknown {
  const rows = Array.isArray(result) ? result[0] : (result?.rows ?? result)
  const row = Array.isArray(rows) ? rows[0] : rows
  return row?.[column]
}

/**
 * El cliente con el que se toma el lease: la conexión con nombre, la primaria
 * del `db` de Lucid, o `null` si lo que se inyectó no es un cliente de Lucid
 * (los dobles de test) — entonces el lease es de proceso.
 */
function lockClientOf(database: DatabaseLike, connection: string | undefined): any {
  if (connection) return (db as any).connection(connection)
  const client: any = database
  if (typeof client?.transaction === 'function' && client?.dialect) return client
  if (typeof client?.connection === 'function') {
    const primary = client.connection()
    return typeof primary?.transaction === 'function' ? primary : null
  }
  return null
}

/**
 * El sello `created_at` como `Date`, venga como venga del dialecto (medido:
 * `Date` en PostgreSQL y MySQL, milisegundos como `number` en SQLite). Parsear
 * un valor NO es leer el reloj (`tests/clock.spec.ts`). Ilegible ⇒ ausente.
 */
function stampOf(value: unknown): Date | undefined {
  if (value === null || value === undefined) return undefined
  const date = value instanceof Date ? value : new Date(value as any)
  return Number.isNaN(date.getTime()) ? undefined : date
}

/** Una fila de la cola, tal como la ve el puerto. */
function rowToPending(row: any): PendingScopeTreeChange {
  const child = scopeOf(String(row.child_type), row.child_uuid)
  const change: ScopeTreeChange =
    row.op === 'detached'
      ? { op: 'detached', child }
      : { op: row.op, child, parent: scopeOf(String(row.parent_type), row.parent_uuid) }
  const actor =
    row.actor_type === null || row.actor_type === undefined
      ? undefined
      : { type: String(row.actor_type), uuid: String(row.actor_uuid) }
  const createdAt = stampOf(row.created_at)
  return {
    id: row.id,
    change,
    attempts: Number(row.attempts ?? 0),
    actor,
    ...(row.last_error === null || row.last_error === undefined ? {} : { lastError: String(row.last_error) }),
    // La EDAD de la cola (2.4.0-alpha.8): el sello de quien encoló, tal cual.
    ...(createdAt === undefined ? {} : { createdAt }),
  }
}

/**
 * El id de la fila que acaba de insertar Lucid, sea cual sea la forma del
 * dialecto (medido, 2.4.0-alpha.5): `[id]` en SQLite y MySQL, `[{ id }]` en
 * PostgreSQL con `returning('id')`.
 */
function insertedId(result: any): string | number {
  const first = Array.isArray(result) ? result[0] : result
  const id = first !== null && typeof first === 'object' ? first.id : first
  if (typeof id !== 'number' && typeof id !== 'string') {
    throw new AuthorizationConfigError(
      `sqlScopeOutbox.enqueue: el motor no devolvió el id de la fila insertada (llegó ${JSON.stringify(first)}); ` +
        'sin recibo no hay `only`.'
    )
  }
  return id
}

/** Los ids de `only`: una lista NO vacía de números o cadenas (500 si no). */
function assertIds(ids: unknown): Array<string | number> {
  if (!Array.isArray(ids) || ids.length === 0 || ids.some((id) => typeof id !== 'number' && typeof id !== 'string')) {
    throw new AuthorizationConfigError(
      `sqlScopeOutbox: filter.ids debe ser una lista NO vacía de ids (llegó ${JSON.stringify(ids)})`
    )
  }
  return ids
}

/** La cota de `pending`/`dead`: entera y positiva o 500 (config rota). */
function assertLimit(limit: number): void {
  if (!(Number.isInteger(limit) && limit >= 1)) {
    throw new AuthorizationConfigError(`sqlScopeOutbox: limit debe ser un entero >= 1 (llegó ${String(limit)})`)
  }
}

export function sqlScopeOutbox(
  options: SqlScopeOutboxOptions = {},
  database: DatabaseLike = db as unknown as DatabaseLike
): ScopeOutbox {
  const table = options.table ?? DEFAULT_TABLE
  if (!IDENTIFIER.test(table)) {
    throw new AuthorizationConfigError(
      `sqlScopeOutbox: table '${table}' no es un identificador SQL simple (letras, dígitos y _).`
    )
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const connection = options.connection
  const now = options.now ?? systemClock
  const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS
  if (!(Number.isInteger(maxAttempts) && maxAttempts >= 1)) {
    throw new AuthorizationConfigError(
      `sqlScopeOutbox: maxAttempts debe ser un entero >= 1 (llegó ${String(options.maxAttempts)})`
    )
  }
  const requireTransaction = options.requireTransaction === undefined ? true : options.requireTransaction
  if (typeof requireTransaction !== 'boolean') {
    throw new AuthorizationConfigError(
      `sqlScopeOutbox: requireTransaction debe ser un booleano (llegó ${String(options.requireTransaction)}); ` +
        'true = encolar sin { transaction } es 500 antes del INSERT (default true desde 2.5.0; false es el opt-out explícito).'
    )
  }

  /**
   * La conexión de ESTA cola: la declarada, o la primaria del `db` de Lucid
   * (un doble sin `primaryConnectionName` deja `undefined`: entonces se exige
   * una transacción, pero no se juzga su conexión).
   */
  const ownConnection: string | undefined =
    connection ??
    (typeof (database as any).primaryConnectionName === 'string' ? (database as any).primaryConnectionName : undefined)

  /**
   * El cliente del encolado: la transacción del consumidor si la hay — y
   * SOLO si es una transacción abierta de la conexión de la cola (L-1 · 🟠 9,
   * `assertCallerTransaction`): un `trx` de otra conexión encolaba en la base
   * equivocada y `db` entero escribía fuera de toda transacción, en silencio.
   */
  const clientOf = (context: ScopeOutboxContext | undefined): any => {
    const trx = assertCallerTransaction('sqlScopeOutbox.enqueue', context?.transaction, { connection: ownConnection })
    if (trx === undefined && requireTransaction) {
      // La fuga S5, nombrada (2.4.0-alpha.8): sin tu transacción la fila
      // confirma sola y un rollback tuyo no se la lleva.
      throw new AuthorizationConfigError(
        'sqlScopeOutbox.enqueue: no llegó { transaction } y esta outbox tiene requireTransaction: true (el default desde 2.5.0). Encolar fuera ' +
          'de tu unidad de trabajo es la fuga que la outbox existe para cerrar: la fila confirmaría sola, y si tu ' +
          'transacción hace rollback después el cambio se queda en la cola y el relay lo aplica al store — tu base ' +
          'diría un padre y el PDP otro. Pasa el `trx` de db.transaction() en scopes.attached/moved/detached ' +
          '({ transaction: trx }); si de verdad encolas fuera de toda transacción, dilo: sqlScopeOutbox({ requireTransaction: false }). ' +
          'OJO: { transaction } por el manager exige un pool >= 2 (la barrera del freeze lee por OTRA conexión y con una sola ' +
          'es 503 E_AUTHZ_BACKEND_TIMEOUT a freezeTimeoutMs); con pool max 1 —el default de knex en TODO SQLite, fichero o ' +
          ':memory:— usa requireTransaction: false. No se ha escrito nada.'
      )
    }
    return trx ?? on(database)
  }

  const query = <T>(operation: string, run: () => Promise<T>): Promise<T> =>
    guardSql('sqlScopeOutbox', operation, timeoutMs, run)

  /** Igual que el resto del paquete: la conexión con nombre si se declaró. */
  const on = (client: any) => (connection && client === database ? (db.connection(connection) as any) : client)

  return {
    async enqueue(change: ScopeTreeChange, context: ScopeOutboxContext): Promise<{ id: string | number }> {
      assertChange(change)
      if (context?.actor !== undefined) assertSubject(context.actor)
      const child = columnsOf(change.child)
      const parent = change.op === 'detached' ? { type: null, uuid: null } : columnsOf(change.parent)
      const client = clientOf(context)
      // El RECIBO (alpha.5 · R1): el id de la fila, que es el mismo que
      // devolverá `pending()`. `returning` solo lo aplica Lucid donde el
      // dialecto lo soporta; en los demás el insert ya devuelve `[id]`.
      const inserted = await query('enqueue', () =>
        client.table(table).returning('id').insert({
          op: change.op,
          child_type: child.type,
          child_uuid: child.uuid,
          parent_type: parent.type,
          parent_uuid: parent.uuid,
          actor_type: context?.actor?.type ?? null,
          actor_uuid: context?.actor?.uuid ?? null,
          attempts: 0,
          last_error: null,
          created_at: now(),
          applied_at: null,
        })
      )
      return { id: insertedId(inserted) }
    },

    async pending(
      limit: number,
      after?: string | number,
      filter?: ScopeOutboxPendingFilter
    ): Promise<PendingScopeTreeChange[]> {
      assertLimit(limit)
      const ids = filter === undefined ? undefined : assertIds(filter.ids)
      const client = on(database)
      const rows: any[] = await query('pending', () => {
        // Lo APARCADO (`attempts >= maxAttempts`) sale por `dead()`, no por
        // aquí: si volviera, la pasada la reintentaría eternamente.
        let q = client
          .from(table)
          .whereNull('applied_at')
          .where('attempts', '<', maxAttempts)
          .orderBy('id', 'asc')
          .limit(limit)
        // `after` es el último id que el relay ya vio EN ESTA PASADA: lo que
        // dejó sin aplicar sigue pendiente y sin esto volvería a salir el
        // primero para siempre (3b-2h · 🔴 2).
        if (after !== undefined) q = q.where('id', '>', after)
        // `only` (alpha.5 · R1) se filtra AQUÍ, en SQL: es la PK, 0,20 ms
        // sobre un backlog de 501; en memoria habría que leer la cola entera.
        if (ids !== undefined) q = q.whereIn('id', ids)
        return q
      })
      return rows.map(rowToPending)
    },

    /**
     * **La sonda de dependencia de `only`** (alpha.5 · R1): la pendiente más
     * antigua ANTERIOR a `id` —sin aplicar, no aparcada— que nombre alguno de
     * `scopes` como hijo o como padre. Una consulta de existencia con el
     * índice `(applied_at, id)`: 0,69 ms medidos sobre 501 pendientes.
     */
    async earlierPending(id: string | number, scopes: ScopeRef[]): Promise<PendingScopeTreeChange | null> {
      const targets = scopes.map((scope) => {
        assertScope(scope)
        return columnsOf(scope)
      })
      if (targets.length === 0) return null
      const client = on(database)
      const rows: any[] = await query('earlierPending', () =>
        client
          .from(table)
          .whereNull('applied_at')
          .where('attempts', '<', maxAttempts)
          .where('id', '<', id)
          .where((names: any) => {
            for (const target of targets) {
              // La raíz se guarda como `app` con uuid NULO (solo puede ser padre).
              names.orWhere((one: any) => {
                one.where('child_type', target.type)
                target.uuid === null ? one.whereNull('child_uuid') : one.where('child_uuid', target.uuid)
              })
              names.orWhere((one: any) => {
                one.where('parent_type', target.type)
                target.uuid === null ? one.whereNull('parent_uuid') : one.where('parent_uuid', target.uuid)
              })
            }
          })
          .orderBy('id', 'asc')
          .limit(1)
      )
      return rows.length === 0 ? null : rowToPending(rows[0])
    },

    /**
     * Las entradas APARCADAS: pendientes que agotaron sus intentos. No se
     * reintentan, se MIRAN (3b-2h · 🔴 2).
     */
    async dead(limit: number): Promise<PendingScopeTreeChange[]> {
      assertLimit(limit)
      const client = on(database)
      const rows: any[] = await query('dead', () =>
        client
          .from(table)
          .whereNull('applied_at')
          .where('attempts', '>=', maxAttempts)
          .orderBy('id', 'asc')
          .limit(limit)
      )
      return rows.map(rowToPending)
    },

    /**
     * **El lease del escritor ÚNICO** (3b-2h · 🟠 4). Cerrojo del SERVIDOR en
     * PostgreSQL (`pg_try_advisory_xact_lock`, que se suelta con la
     * transacción) y en MySQL (`GET_LOCK(name, 0)`); en SQLite —y en
     * cualquier dialecto sin cerrojo de sesión— es un cerrojo de PROCESO, y
     * eso está escrito: SQLite ya serializa sus escrituras y no es el motor
     * de un despliegue con dos réplicas del relay.
     *
     * La transacción se abre SOLO para sostener el cerrojo (no escribe nada)
     * y se revierte al soltarlo: es una conexión ocupada mientras dura la
     * pasada, que es el precio de que dos pasadas no se pisen.
     */
    async acquire(): Promise<ScopeOutboxLease | null> {
      /** El nombre del cerrojo de PROCESO y del advisory de PG: el completo (allí no hay recorte). */
      const name = `authz_scope_outbox:${connection ?? 'default'}:${table}`
      const client = lockClientOf(database, connection)
      if (client === null || isSqliteDialect(client)) {
        if (localLeases.has(name)) return null
        localLeases.add(name)
        return { release: async () => void localLeases.delete(name) }
      }
      const dialect = dialectOf(client)
      const trx: any = await query('acquire', () => client.transaction())
      try {
        if (dialect.startsWith('postgres')) {
          const result: any = await query('acquire', () =>
            trx.rawQuery('select pg_try_advisory_xact_lock(?, ?) as taken', [ADVISORY_LOCK_NAMESPACE, hash32(name)])
          )
          if (!firstValue(result, 'taken')) {
            await trx.rollback()
            return null
          }
          // El cerrojo es de la TRANSACCIÓN: revertirla lo suelta.
          return { release: async () => void (await trx.rollback()) }
        }
        if (dialect.startsWith('mysql')) {
          // **La base en el nombre** (rotación 2 · R2-01): la lee la MISMA sesión que va a sostener el cerrojo.
          const database = firstValue(await query('acquire', () => trx.rawQuery('select database() as db')), 'db')
          const names = scopeOutboxLockNames(connection, table, database === null || database === undefined ? null : String(database))
          // **Transición** (2.5.x): el VIEJO (sin base) primero y el NUEVO después; si cualquiera falla se sueltan los
          // ya tomados y es `busy`. Un proceso de alpha.4 solo toma el viejo: los dos siguen excluyéndose.
          // (El recortado de ≤ alpha.4 sigue retirado: `SCOPE_OUTBOX_TAKES_LEGACY_LOCK` es `false` desde alpha.7.)
          const order = [
            ...(SCOPE_OUTBOX_TAKES_UNSCOPED_LOCK ? [names.unscoped] : []),
            names.current,
            ...(SCOPE_OUTBOX_TAKES_LEGACY_LOCK ? [names.legacy] : []),
          ]
          const taken: string[] = []
          const take = async (lockName: string): Promise<boolean> => {
            const result: any = await query('acquire', () => trx.rawQuery('select get_lock(?, 0) as taken', [lockName]))
            const ok = Number(firstValue(result, 'taken') ?? 0) === 1
            if (ok) taken.push(lockName)
            return ok
          }
          // `GET_LOCK` es de SESIÓN, no de la transacción: revertir no lo suelta, y una conexión que vuelve al pool
          // con el cerrojo puesto deja la cola `busy` para siempre. Se sueltan TODOS los tomados (en orden inverso)
          // aunque uno falle, y la transacción se revierte al final pase lo que pase.
          let released = false
          const releaseAll = async () => {
            if (released) return
            released = true
            let failure: unknown
            for (const lockName of [...taken].reverse()) {
              try {
                await trx.rawQuery('select release_lock(?)', [lockName])
              } catch (error) {
                failure ??= error
              }
            }
            await trx.rollback()
            if (failure !== undefined) throw failure
          }
          try {
            for (const lockName of order) {
              if (!(await take(lockName))) {
                await releaseAll()
                return null
              }
            }
          } catch (error) {
            await releaseAll().catch(() => {})
            throw error
          }
          return { release: releaseAll }
        }
        // Un dialecto que no sabemos cerrar: se cierra en el proceso y se
        // suelta la transacción (nunca se devuelve un lease de mentira).
        await trx.rollback()
        if (localLeases.has(name)) return null
        localLeases.add(name)
        return { release: async () => void localLeases.delete(name) }
      } catch (error) {
        await trx.rollback().catch(() => {})
        throw error
      }
    },

    /**
     * **La sonda anti-reversión de `requeue`** (alpha.5 · R2b), espejo de
     * `earlierPending`: las entradas APLICADAS posteriores a `id` que nombren
     * alguno de `scopes` como hijo o como padre, en orden de id. Una consulta
     * acotada por `limit`; es lo que el manager mira antes de devolver una
     * aparcada a la cola.
     */
    async laterApplied(id: string | number, scopes: ScopeRef[], limit: number): Promise<PendingScopeTreeChange[]> {
      assertLimit(limit)
      const targets = scopes.map((scope) => {
        assertScope(scope)
        return columnsOf(scope)
      })
      if (targets.length === 0) return []
      const client = on(database)
      const rows: any[] = await query('laterApplied', () =>
        client
          .from(table)
          .whereNotNull('applied_at')
          .where('id', '>', id)
          .where((names: any) => {
            for (const target of targets) {
              names.orWhere((one: any) => {
                one.where('child_type', target.type)
                target.uuid === null ? one.whereNull('child_uuid') : one.where('child_uuid', target.uuid)
              })
              names.orWhere((one: any) => {
                one.where('parent_type', target.type)
                target.uuid === null ? one.whereNull('parent_uuid') : one.where('parent_uuid', target.uuid)
              })
            }
          })
          .orderBy('id', 'asc')
          .limit(limit)
      )
      return rows.map(rowToPending)
    },

    /**
     * **Reencola entradas APARCADAS** (alpha.5 · R2b): todo o nada, y
     * `attempts = maxAttempts − 1` (decisión del dueño: vuelve a `dead()` en
     * UNA pasada si la causa sigue rota, entra a la primera si se arregló;
     * sin columna nueva). Cada id tiene que existir, no estar aplicado y
     * tener los intentos agotados; si alguno no cumple se lanza nombrándolo
     * ANTES de tocar nada — una fila aplicada no revive jamás (reencolar un
     * `detached` aplicado volvería a purgar). `last_error` se conserva: la
     * causa es historia, y la siguiente pasada la sobreescribe si vuelve a
     * fallar. La política (qué se puede reencolar sin revertir el árbol) es
     * del manager, no de aquí.
     */
    async requeue(ids: Array<string | number>): Promise<void> {
      const wanted = assertIds(ids)
      const client = on(database)
      const rows: any[] = await query('requeue', () =>
        client.from(table).whereIn('id', wanted).select('id', 'applied_at', 'attempts')
      )
      const found = new Map<string, any>(rows.map((row) => [String(row.id), row]))
      const rejectedIds = wanted.filter((id) => {
        const row = found.get(String(id))
        return !row || (row.applied_at !== null && row.applied_at !== undefined) || Number(row.attempts) < maxAttempts
      })
      if (rejectedIds.length > 0) {
        throw new AuthorizationConfigError(
          `sqlScopeOutbox.requeue: ${rejectedIds.map(String).join(', ')} no existe(n) o no está(n) aparcada(s) ` +
            `(ya aplicada, o todavía pendiente con intentos por gastar): no se ha tocado NINGUNA fila. ` +
            'Solo se reencola lo que sale por dead().'
        )
      }
      await query('requeue', () =>
        client
          .from(table)
          .whereIn('id', wanted)
          .whereNull('applied_at')
          .where('attempts', '>=', maxAttempts)
          .update({ attempts: maxAttempts - 1 })
      )
      // La comprobación y la escritura no van en una transacción (el cliente
      // puede ser un doble): se relee, y si la cola cambió entre medias se dice.
      const after: any[] = await query('requeue', () =>
        client.from(table).whereIn('id', wanted).whereNull('applied_at').where('attempts', maxAttempts - 1).select('id')
      )
      if (after.length !== wanted.length) {
        throw new AuthorizationConfigError(
          `sqlScopeOutbox.requeue: se pidió reencolar ${wanted.length} fila(s) y quedaron ${after.length} en la cola: ` +
            'la outbox cambió entre la comprobación y la escritura. Mira dead() y repite.'
        )
      }
    },

    async markApplied(id: string | number): Promise<void> {
      const client = on(database)
      await query('markApplied', () =>
        client.from(table).where('id', id).update({ applied_at: now(), last_error: null })
      )
    },

    async markFailed(id: string | number, error: string, options?: ScopeOutboxFailure): Promise<void> {
      const client = on(database)
      // El intento se cuenta aunque el mensaje sea larguísimo: se recorta el
      // texto, nunca el hecho de que falló. Salvo que la causa sea el BACKEND
      // (`transient`, alpha.5 · R2a): entonces se escribe la causa —nada se
      // vuelve silencioso— y NO se cuenta, porque `maxAttempts` converge
      // sobre lo irreparable y una caída del store no dice nada de la fila.
      await query('markFailed', () => {
        const q = client.from(table).where('id', id).update({ last_error: String(error).slice(0, 2000) })
        return options?.transient === true ? q : q.increment('attempts', 1)
      })
    },
  }
}
