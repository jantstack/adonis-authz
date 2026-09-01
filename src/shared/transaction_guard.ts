/**
 * **¿De quién es esta transacción?** (L-1 · 🟠 9, auditor del panel `{trx}`;
 * ascendido por el juez a REGLA del puerto `{trx}` de L-3/L-4.)
 *
 * Una escritura que se inscribe en la transacción del llamante solo cumple
 * «los dos o ninguno» si esa transacción es de la MISMA conexión que usa
 * quien escribe. `sqlScopeOutbox` lo daba por hecho: con un `trx` devolvía el
 * `trx` tal cual e ignoraba `connection` en silencio, así que el encolado
 * caía en la base del llamante — donde, si existe la tabla, ningún relay
 * lee y la fila ni siquiera sale en `dead()`. Y `db` entero pasaba el
 * duck-check (`.from`/`.table`) y escribía FUERA de toda transacción, sin un
 * solo aviso: la mitigación entera apagada.
 *
 * Esta es la ÚNICA comprobación, para que la outbox de hoy y el
 * `{ transaction }` de `grant`/`relate` de mañana no puedan desincronizarse:
 *
 *  1. tiene que ser un cliente de Lucid (`.from()`/`.table()`);
 *  2. tiene que ser una TRANSACCIÓN ABIERTA (`isTransaction === true`): el
 *     `db` de Lucid y un `QueryClient` (`db.connection()`) no lo son;
 *  3. tiene que pertenecer a la conexión de quien escribe (`connectionName`),
 *     cuando se conoce cuál es.
 *
 * Cualquiera de las tres ⇒ 500 `E_AUTHZ_CONFIG` nombrando la operación y las
 * dos conexiones. Es un error de cableado del consumidor, no del backend ni de
 * la petición; y va ANTES de tocar la base (cero sentencias por la
 * transacción ajena).
 */

import { AuthorizationConfigError } from '../errors.js'

/** Lo mínimo que se exige de la transacción del llamante (un `TransactionClientContract` de Lucid). */
export interface CallerTransaction {
  from(table: string): any
  table(table: string): any
  readonly isTransaction: true
  readonly connectionName: string
}

export interface CallerTransactionOwner {
  /**
   * La conexión de quien ESCRIBE: la declarada (`connection` de la outbox o
   * del driver) o la primaria del `db` de Lucid. `undefined` solo cuando no
   * se puede saber (un `db` doble sin `primaryConnectionName`): entonces se
   * exige que sea una transacción, pero no se juzga su conexión.
   */
  connection: string | undefined
}

/**
 * Valida que `transaction` sea la transacción ABIERTA del llamante sobre la
 * conexión de `owner`, y la devuelve tipada. `undefined`/`null` ⇒ `undefined`
 * (no llegó ninguna; el llamante decide qué hacer).
 */
export function assertCallerTransaction(
  operation: string,
  transaction: unknown,
  owner: CallerTransactionOwner
): CallerTransaction | undefined {
  if (transaction === undefined || transaction === null) return undefined
  const trx: any = transaction
  if (typeof trx.from !== 'function' || typeof trx.table !== 'function') {
    throw new AuthorizationConfigError(
      `${operation}: 'transaction' no parece un cliente de Lucid (le faltan .from()/.table()). ` +
        'Pasa el `trx` de db.transaction(); si usas otra cosa, implementa el puerto a mano.'
    )
  }
  // El `db` de Lucid entero (`connection()`/`manager`/`primaryConnectionName`)
  // tiene `.from()`/`.table()` y pasaba: escribía fuera de toda transacción.
  if (typeof trx.connection === 'function' || typeof trx.primaryConnectionName === 'string') {
    throw new AuthorizationConfigError(
      `${operation}: 'transaction' es el servicio \`db\` entero, no una transacción abierta: la escritura se ` +
        'confirmaría sola, FUERA de tu transacción, y la mitigación no existiría. Pasa el `trx` de db.transaction().'
    )
  }
  if (trx.isTransaction !== true) {
    throw new AuthorizationConfigError(
      `${operation}: 'transaction' no es una transacción ABIERTA de Lucid (isTransaction !== true` +
        `${typeof trx.connectionName === 'string' ? `, conexión '${trx.connectionName}'` : ''}): ` +
        'un cliente de consulta confirma cada sentencia por su cuenta. Pasa el `trx` de db.transaction().'
    )
  }
  if (owner.connection !== undefined && trx.connectionName !== owner.connection) {
    throw new AuthorizationConfigError(
      `${operation}: la transacción es de la conexión '${String(trx.connectionName)}' y la escritura va por la ` +
        `conexión '${owner.connection}': no puede inscribirse en ella («los dos o ninguno» sería falso). ` +
        `Abre la transacción con db.connection('${owner.connection}').transaction(), o declara esa conexión aquí.`
    )
  }
  return trx as CallerTransaction
}
