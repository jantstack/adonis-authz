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
  ScopeOutboxLease,
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
  return {
    id: row.id,
    change,
    attempts: Number(row.attempts ?? 0),
    actor,
    ...(row.last_error === null || row.last_error === undefined ? {} : { lastError: String(row.last_error) }),
  }
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
    return trx ?? on(database)
  }

  const query = <T>(operation: string, run: () => Promise<T>): Promise<T> =>
    guardSql('sqlScopeOutbox', operation, timeoutMs, run)

  /** Igual que el resto del paquete: la conexión con nombre si se declaró. */
  const on = (client: any) => (connection && client === database ? (db.connection(connection) as any) : client)

  return {
    async enqueue(change: ScopeTreeChange, context: ScopeOutboxContext): Promise<void> {
      assertChange(change)
      if (context?.actor !== undefined) assertSubject(context.actor)
      const child = columnsOf(change.child)
      const parent = change.op === 'detached' ? { type: null, uuid: null } : columnsOf(change.parent)
      const client = clientOf(context)
      await query('enqueue', () =>
        client.table(table).insert({
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
    },

    async pending(limit: number, after?: string | number): Promise<PendingScopeTreeChange[]> {
      assertLimit(limit)
      const client = on(database)
      const rows: any[] = await query('pending', () => {
        // Lo APARCADO (`attempts >= maxAttempts`) sale por `dead()`, no por
        // aquí: si volviera, la pasada la reintentaría eternamente.
        const q = client
          .from(table)
          .whereNull('applied_at')
          .where('attempts', '<', maxAttempts)
          .orderBy('id', 'asc')
          .limit(limit)
        // `after` es el último id que el relay ya vio EN ESTA PASADA: lo que
        // dejó sin aplicar sigue pendiente y sin esto volvería a salir el
        // primero para siempre (3b-2h · 🔴 2).
        return after === undefined ? q : q.where('id', '>', after)
      })
      return rows.map(rowToPending)
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
          const result: any = await query('acquire', () =>
            trx.rawQuery('select get_lock(?, 0) as taken', [name.slice(0, 64)])
          )
          if (Number(firstValue(result, 'taken') ?? 0) !== 1) {
            await trx.rollback()
            return null
          }
          return {
            release: async () => {
              try {
                await trx.rawQuery('select release_lock(?)', [name.slice(0, 64)])
              } finally {
                await trx.rollback()
              }
            },
          }
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

    async markApplied(id: string | number): Promise<void> {
      const client = on(database)
      await query('markApplied', () =>
        client.from(table).where('id', id).update({ applied_at: now(), last_error: null })
      )
    },

    async markFailed(id: string | number, error: string): Promise<void> {
      const client = on(database)
      // El intento se cuenta aunque el mensaje sea larguísimo: se recorta el
      // texto, nunca el hecho de que falló.
      await query('markFailed', () =>
        client
          .from(table)
          .where('id', id)
          .update({ last_error: String(error).slice(0, 2000) })
          .increment('attempts', 1)
      )
    },
  }
}
