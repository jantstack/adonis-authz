/**
 * **`authz:reconcile` de relaciones (Fase 4-5)** — el contrato con CENSO.
 *
 *  1. Doble ↔ doble en memoria (sin servidor, corre en todos los modos): la
 *     lógica del reconcile, la idempotencia, `--prune`, `--dry-run` y el CENSO.
 *  2. database ↔ openfga contra el `:8101` (con `OPENFGA_TEST_URL`): la
 *     migración REAL cross-driver, bidireccional, con el censo hecho a hecho.
 *
 * El CENSO es lo que ve la pérdida SILENCIOSA (lección M1/M3/T4): un tramo
 * omisivo o una pérdida de `subject_relation`/partición se ve ROJA buscando
 * cada hecho sembrado en el destino uno a uno, no cruzando `report.skipped`.
 */
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { runRelationsReconcileContract } from '../src/testing/relations_reconcile_contract.js'
import { reconcileRelations } from '../src/relations/reconcile.js'
import { makeRelationsDriver } from '../src/testing/relations_contract.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { openFgaFactsModel } from '../src/drivers/openfga_facts.js'
import { OpenFgaRelationsDriver } from '../src/drivers/openfga_relations_driver.js'
import type { RelationsConfig } from '../src/relations/define_relations_config.js'
import type { RelObject, RelSubject, RelationsDriver, RelationsDriverCapabilities, ScopeRef } from '../src/types.js'

const HOLDER_MAP = { user: 'user', admin: 'admin', integration: 'integration' } as const

function reconcileConfig(): RelationsConfig {
  return defineRelationsConfig({
    objectTypes: [
      { type: 'document', relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }] },
    ],
    holderTypes: ['user', 'admin', 'integration'],
    database: { membersOf: true },
  })
}

const FULL_CAPS: RelationsDriverCapabilities = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: false,
}

/* ── 1 · Doble ↔ doble en memoria (sin servidor) ─────────────────────────── */

runRelationsReconcileContract({
  name: 'doble en memoria',
  config: reconcileConfig(),
  makeA: (config) => makeRelationsDriver({ config, capabilities: FULL_CAPS }),
  makeB: (config) => makeRelationsDriver({ config, capabilities: FULL_CAPS }),
})

/* ── 2 · El CENSO ve la pérdida que los contadores NO (M1/M3/T4) ─────────── */

test.group('relaciones · reconcile — el censo ve la pérdida silenciosa', () => {
  test('un origen que TIRA los usersets migra con `written` limpio pero el censo lo caza', async ({ assert }) => {
    const config = reconcileConfig()
    const source = makeRelationsDriver({ config, capabilities: FULL_CAPS })
    const dest = makeRelationsDriver({ config, capabilities: FULL_CAPS })
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const u: RelSubject = { type: 'user', uuid: uuidv7() }
    const g1: RelObject = { type: 'group', id: uuidv7() }
    const g2: RelObject = { type: 'group', id: uuidv7() }
    await source.relate(u, 'member', g1, p)
    await source.relate({ object: g1, relation: 'member' }, 'member', g2, p)

    // Un origen OMISIVO: enumera solo los holders, se salta los usersets.
    const omissive: RelationsDriver = {
      capabilities: FULL_CAPS,
      relate: source.relate.bind(source),
      unrelate: source.unrelate.bind(source),
      check: source.check.bind(source),
      listObjects: source.listObjects.bind(source),
      listSubjects: source.listSubjects.bind(source),
      purgeObject: source.purgeObject.bind(source),
      purgeSubject: source.purgeSubject.bind(source),
      enumerateRelations: async (part) => {
        const page = await source.enumerateRelations!(part)
        return { tuples: page.tuples.filter((t) => !('object' in t.subject)) }
      },
    }
    const report = await reconcileRelations({ from: omissive, to: dest, partition: p })
    // El contador NO delata la pérdida: escribió lo que enumeró.
    assert.equal(report.written, 1)
    // El CENSO sí: el userset g1#member de g2 no está en el destino.
    const direct = await dest.listSubjects('member', g2, p)
    assert.isFalse(
      direct.subjects.some((s) => 'object' in s && (s as any).object.id === g1.id),
      'CENSO: el userset anidado se perdió y el destino no lo tiene'
    )
  })
})

/* ── 3 · database ↔ openfga contra el `:8101` (migración REAL) ────────────── */

const openFgaStores: string[] = []
const openFgaTestUrl = process.env.OPENFGA_TEST_URL

if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl
  const config = reconcileConfig()

  runRelationsReconcileContract({
    name: 'database ↔ openfga',
    config,
    clean: async () => {
      await db.from('authz_relations').delete()
    },
    makeA: () => new DatabaseRelationsDriver(config),
    makeB: async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `reconcile-${Date.now()}-${uuidv7().slice(0, 8)}` })
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDER_MAP, [], { objectTypes: config.objectTypes })
      )
      openFgaStores.push(store.id!)
      return new OpenFgaRelationsDriver(config, {
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id,
        holderTypes: HOLDER_MAP,
        logger: { warn: () => {} },
      })
    },
  })
}

// Los stores creados se borran al cerrar la suite (guard de bin/test.ts barre
// lo que quede; aquí se cierran explícitamente para no gotear en corridas largas).
test.group('relaciones · reconcile — limpieza de stores', (group) => {
  group.teardown(async () => {
    if (!openFgaTestUrl) return
    const { OpenFgaClient } = await import('@openfga/sdk')
    while (openFgaStores.length) {
      try {
        await new OpenFgaClient({ apiUrl: openFgaTestUrl, storeId: openFgaStores.pop()! }).deleteStore()
      } catch {
        /* barrido best-effort */
      }
    }
  })
  test('marcador de limpieza', ({ assert }) => assert.isTrue(true))
})
