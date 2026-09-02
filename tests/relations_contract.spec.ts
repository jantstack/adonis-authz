/**
 * El contrato del puerto `RelationsDriver` (Fase 4, lote 4-2) corrido contra
 * DOS dobles en memoria — uno con todas las capacidades, otro mínimo — para
 * ejercer LAS DOS CARAS de cada capacidad en `npm test` (patrón «database» +
 * «database (sin listDenies)» del runner de roles). El doble prueba el
 * CONTRATO (F-05, config, capacidades); el MODELO fusionado y la paridad con
 * `database` son del `:8101` en 4-4.
 */
import { runRelationsDriverContract, makeRelationsDriver } from '../src/testing/relations_contract.js'
import type { RelationsDriverCapabilities } from '../src/types.js'

const FULL: RelationsDriverCapabilities = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: true,
  injectableClock: true,
  // Doble en memoria (L-2/L-4): no escribe en ninguna transacción, así que declara `false` y se le juzga esa cara; la `true` la juzga el driver `database` REAL en pool ≥ 2 (`relations_database.spec.ts`).
  transactionalWrites: false,
}

const MINIMAL: RelationsDriverCapabilities = {
  singleCheckRelations: false,
  listObjectsInherited: false,
  usersetSubjects: false,
  membersOfNative: false,
  enumerateRelations: false,
  listObjectsTruncation: false,
  injectableClock: false,
  // Doble en memoria (L-2/L-4): no escribe en ninguna transacción, así que declara `false` y se le juzga esa cara; la `true` la juzga el driver `database` REAL en pool ≥ 2 (`relations_database.spec.ts`).
  transactionalWrites: false,
}

runRelationsDriverContract({
  name: 'doble en memoria (full)',
  capabilities: FULL,
  limits: { listMaxResults: 3 },
  makeDriver: (config) => makeRelationsDriver({ config, capabilities: FULL, limits: { listMaxResults: 3 } }),
})

runRelationsDriverContract({
  name: 'doble en memoria (mínimo)',
  capabilities: MINIMAL,
  makeDriver: (config) => makeRelationsDriver({ config, capabilities: MINIMAL }),
})
