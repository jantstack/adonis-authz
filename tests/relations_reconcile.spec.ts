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

/* ── R-17 · el seguro de borrado masivo de reconcileRelations ────────────── */

/**
 * El hallazgo del auditor (🟡2): `reconcileRelations --prune` con un ORIGEN
 * vacío/equivocado VACIABA el destino y el reporte salía limpio. Se porta el
 * seguro de `authz:reconcile` de roles: origen sin una sola tupla utilizable +
 * `--prune` con tuplas que borrar ⇒ 500 `E_AUTHZ_MASS_RECONCILE_REFUSED` antes
 * de tocar nada, salvo `allowMassDelete`; `--dry-run` no lanza, lo marca.
 */
test.group('relaciones · reconcile — R-17 · seguro de borrado masivo', () => {
  const config = reconcileConfig()
  const p: ScopeRef = { type: 'unit', uuid: uuidv7() }

  async function seed(driver: RelationsDriver): Promise<void> {
    await driver.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, p)
    await driver.relate({ type: 'admin', uuid: uuidv7() }, 'owner', { type: 'document', id: uuidv7() }, p)
  }
  async function count(driver: RelationsDriver): Promise<number> {
    return (await driver.enumerateRelations!(p)).tuples.length
  }

  test('--prune con ORIGEN VACÍO y destino lleno ⇒ 500 E_AUTHZ_MASS_RECONCILE_REFUSED, destino INTACTO', async ({
    assert,
  }) => {
    const empty = makeRelationsDriver({ config, capabilities: FULL_CAPS })
    const full = makeRelationsDriver({ config, capabilities: FULL_CAPS })
    await seed(full)
    assert.equal(await count(full), 2)

    let caught: any
    try {
      await reconcileRelations({ from: empty, to: full, partition: p, prune: true, toConfig: config })
    } catch (e) {
      caught = e
    }
    assert.equal(caught?.status, 500)
    assert.equal(caught?.code, 'E_AUTHZ_MASS_RECONCILE_REFUSED')
    assert.equal(await count(full), 2, 'no borró nada antes de rechazar')
  })

  test('un origen que lee N tuplas pero TODAS de tipo que el destino no declara también se niega', async ({
    assert,
  }) => {
    // El seguro cuenta hechos UTILIZABLES, no el conteo crudo (paridad 3b-8·B1):
    // un origen con tuplas de un tipo `folder` que el destino (`document`) no
    // declara no respalda NADA de lo que --prune borraría.
    const sourceConfig = defineRelationsConfig({
      objectTypes: [{ type: 'folder', relations: [{ name: 'viewer' }] }],
      holderTypes: ['user', 'admin', 'integration'],
    })
    const source = makeRelationsDriver({ config: sourceConfig, capabilities: FULL_CAPS })
    const full = makeRelationsDriver({ config, capabilities: FULL_CAPS })
    await source.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'folder', id: uuidv7() }, p)
    await seed(full)
    let caught: any
    try {
      await reconcileRelations({ from: source, to: full, partition: p, prune: true, toConfig: config })
    } catch (e) {
      caught = e
    }
    assert.equal(caught?.code, 'E_AUTHZ_MASS_RECONCILE_REFUSED')
    assert.equal(await count(full), 2, 'destino intacto')
  })

  test('con allowMassDelete el destino SÍ se vacía y lo reporta', async ({ assert }) => {
    const empty = makeRelationsDriver({ config, capabilities: FULL_CAPS })
    const full = makeRelationsDriver({ config, capabilities: FULL_CAPS })
    await seed(full)
    const report = await reconcileRelations({
      from: empty,
      to: full,
      partition: p,
      prune: true,
      allowMassDelete: true,
      toConfig: config,
    })
    assert.equal(report.deleted, 2)
    assert.equal(await count(full), 0)
  })

  test('--dry-run NO lanza y marca massDelete; el destino queda intacto', async ({ assert }) => {
    const empty = makeRelationsDriver({ config, capabilities: FULL_CAPS })
    const full = makeRelationsDriver({ config, capabilities: FULL_CAPS })
    await seed(full)
    const report = await reconcileRelations({
      from: empty,
      to: full,
      partition: p,
      prune: true,
      dryRun: true,
      toConfig: config,
    })
    assert.isTrue(report.massDelete)
    assert.equal(await count(full), 2, 'dry-run no escribe')
  })

  test('un origen con tuplas UTILIZABLES no dispara el seguro (poda solo lo que sobra)', async ({ assert }) => {
    const source = makeRelationsDriver({ config, capabilities: FULL_CAPS })
    const dest = makeRelationsDriver({ config, capabilities: FULL_CAPS })
    const keep: RelObject = { type: 'document', id: uuidv7() }
    const alice = { type: 'user', uuid: uuidv7() }
    await source.relate(alice, 'viewer', keep, p)
    await dest.relate(alice, 'viewer', keep, p)
    await dest.relate({ type: 'user', uuid: uuidv7() }, 'owner', { type: 'document', id: uuidv7() }, p)
    const report = await reconcileRelations({ from: source, to: dest, partition: p, prune: true, toConfig: config })
    assert.isFalse(report.massDelete)
    assert.equal(report.deleted, 1)
    assert.equal(await count(dest), 1)
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
