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

const SQL: ScopeOutboxCapabilities = {
  transactionalEnqueue: true,
  filter: true,
  transient: true,
  dead: true,
  acquire: true,
  earlierPending: true,
  requeue: true,
}

runScopeOutboxContract({
  name: `sqlScopeOutbox (${process.env.TEST_DB ?? 'sqlite'})`,
  capabilities: SQL,
  limits: { maxAttempts: 3 },
  makeOutbox: () => sqlScopeOutbox({ maxAttempts: 3 }),
  cleanup: () => cleanScopeOutbox(db),
  transactions: {
    async begin() {
      const trx = await db.transaction()
      return { client: trx, commit: () => trx.commit(), rollback: () => trx.rollback() }
    },
  },
})

const FULL: ScopeOutboxCapabilities = { ...SQL, transactionalEnqueue: false }
const MINIMAL: ScopeOutboxCapabilities = {
  transactionalEnqueue: false,
  filter: false,
  transient: false,
  dead: false,
  acquire: false,
  earlierPending: false,
  requeue: false,
}

runScopeOutboxContract({
  name: 'doble en memoria (full)',
  capabilities: FULL,
  limits: { maxAttempts: 3 },
  makeOutbox: () => makeScopeOutbox({ capabilities: FULL, maxAttempts: 3 }),
})

runScopeOutboxContract({
  name: 'doble en memoria (mínimo)',
  capabilities: MINIMAL,
  makeOutbox: () => makeScopeOutbox({ capabilities: MINIMAL }),
})
