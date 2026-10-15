/**
 * **El contrato del puerto `ScopeOutbox`** (2.4.0-alpha.5 · R5) corrido contra
 * la implementación REAL del paquete —`sqlScopeOutbox`, en el motor que pida
 * `TEST_DB` (los cuatro)— y contra el doble en memoria en sus DOS formas
 * (todas las capacidades / ninguna), para ejercer LAS DOS CARAS de cada par
 * en `npm test` (patrón `relations_contract.spec.ts`).
 */
import db from '@adonisjs/lucid/services/db'
import { sqlScopeOutbox } from '../src/scope_outbox.js'
import { makeScopeOutbox, runScopeOutboxContract } from '../src/testing/scope_outbox_contract.js'
import type { ScopeOutboxCapabilities } from '../src/testing/scope_outbox_contract.js'
import { cleanScopeOutbox } from './helpers/schema.js'
import { testEngine } from './helpers/app.js'

/**
 * Plan 2.5 · lote B · B6: `sqlScopeOutbox` exige `{ transaction }` por defecto y el juez encola con la transacción
 * del harness en cada caso (par `requiresTransaction`). **Medido**: `{ transaction }` por el MANAGER exige pool ≥ 2
 * (la barrera del freeze lee la fila `id = 2` por OTRA conexión y con la única conexión en manos del llamante es 503
 * a `freezeTimeoutMs`), así que en `:memory:` (pool 1) la outbox SQL se construye con el opt-out explícito y declara
 * `requiresTransaction: false`; en `sqlite-file`/pg/mysql corre con el DEFAULT y declara `true`. La cara `true` corre
 * en `:memory:` sobre el doble FULL (abajo).
 */
const POOL_OF_ONE = testEngine() === 'sqlite'

const SQL: ScopeOutboxCapabilities = {
  transactionalEnqueue: true,
  filter: true,
  transient: true,
  dead: true,
  acquire: true,
  earlierPending: true,
  requeue: true,
  createdAt: true,
  requiresTransaction: !POOL_OF_ONE,
}

runScopeOutboxContract({
  name: `sqlScopeOutbox (${process.env.TEST_DB ?? 'sqlite'}${POOL_OF_ONE ? ', requireTransaction: false por pool 1' : ', default requireTransaction'})`,
  capabilities: SQL,
  limits: { maxAttempts: 3 },
  makeOutbox: () => (POOL_OF_ONE ? sqlScopeOutbox({ maxAttempts: 3, requireTransaction: false }) : sqlScopeOutbox({ maxAttempts: 3 })),
  cleanup: () => cleanScopeOutbox(db),
  transactions: {
    async begin() {
      const trx = await db.transaction()
      return { client: trx, commit: () => trx.commit(), rollback: () => trx.rollback() }
    },
  },
})

// El doble FULL declara `requiresTransaction: true` (exige la clave y la ignora: es memoria) con una «transacción»
// de mentira del harness, para que la cara `true` del par corra también en `:memory:`.
const FULL: ScopeOutboxCapabilities = { ...SQL, transactionalEnqueue: false, requiresTransaction: true }
const MINIMAL: ScopeOutboxCapabilities = {
  transactionalEnqueue: false,
  filter: false,
  transient: false,
  dead: false,
  acquire: false,
  earlierPending: false,
  requeue: false,
  createdAt: false,
  requiresTransaction: false,
}

runScopeOutboxContract({
  name: 'doble en memoria (full)',
  capabilities: FULL,
  limits: { maxAttempts: 3 },
  makeOutbox: () => makeScopeOutbox({ capabilities: FULL, maxAttempts: 3 }),
  transactions: {
    async begin() {
      return { client: { fake: 'transaction' }, commit: async () => {}, rollback: async () => {} }
    },
  },
})

runScopeOutboxContract({
  name: 'doble en memoria (mínimo)',
  capabilities: MINIMAL,
  makeOutbox: () => makeScopeOutbox({ capabilities: MINIMAL }),
})
