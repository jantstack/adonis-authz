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
import { guardSql } from './drivers/backend_guard.js'
import { APP_SCOPE, APP_SCOPE_TYPE } from './types.js'
import type {
  PendingScopeTreeChange,
  ScopeOutbox,
  ScopeOutboxContext,
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
}

const DEFAULT_TABLE = 'authz_scope_outbox'
const DEFAULT_TIMEOUT_MS = 5_000
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

  /** El cliente de la consulta: la transacción del consumidor si la hay. */
  const clientOf = (context: ScopeOutboxContext | undefined): any => {
    const trx: any = context?.transaction
    if (trx === undefined || trx === null) return database
    if (typeof trx.from !== 'function' || typeof trx.table !== 'function') {
      throw new AuthorizationConfigError(
        "sqlScopeOutbox: 'transaction' no parece un cliente de Lucid (le faltan .from()/.table()). " +
          'Pasa el `trx` de db.transaction(); si tu outbox usa otra cosa, implementa el puerto a mano.'
      )
    }
    return trx
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
      const client = on(clientOf(context))
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

    async pending(limit: number): Promise<PendingScopeTreeChange[]> {
      if (!(Number.isInteger(limit) && limit >= 1)) {
        throw new AuthorizationConfigError(`sqlScopeOutbox: limit debe ser un entero >= 1 (llegó ${String(limit)})`)
      }
      const client = on(database)
      const rows: any[] = await query('pending', () =>
        client.from(table).whereNull('applied_at').orderBy('id', 'asc').limit(limit)
      )
      return rows.map((row) => {
        const child = scopeOf(String(row.child_type), row.child_uuid)
        const change: ScopeTreeChange =
          row.op === 'detached'
            ? { op: 'detached', child }
            : { op: row.op, child, parent: scopeOf(String(row.parent_type), row.parent_uuid) }
        const actor =
          row.actor_type === null || row.actor_type === undefined
            ? undefined
            : { type: String(row.actor_type), uuid: String(row.actor_uuid) }
        return { id: row.id, change, attempts: Number(row.attempts ?? 0), actor }
      })
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
