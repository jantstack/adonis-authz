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
  injectableClock: true,
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

/* ── L-0 · reconcile EMBUDA por F-05: lo no declarado en el destino NO se escribe y se CUENTA ── */

/**
 * Panel `{trx}`, 🔴 2 del auditor: `reconcileRelations` escribe con
 * `to.relate(...)` —por el DRIVER, no por el manager—, así que una tupla del
 * origen de un tipo (o relación) que el destino no declara se ESCRIBÍA igual:
 * `modelDrift` la reportaba y `written` la contaba como migrada. Con L-0 el
 * driver del destino la rechaza 422 (F-05) y el reconcile la CUENTA en
 * `skipped.undeclared` con motivo declarado — por las dos puertas: con
 * `toConfig` se descarta ANTES de llamar al driver (dry-run y pasada real dan
 * los MISMOS números, cero llamadas para ella: espía), y sin `toConfig` es el
 * propio 422 del driver el que la embuda (misma función, mismo `code`).
 */
test.group('relaciones · reconcile — L-0 · F-05 embuda el reconcile (lo no declarado no se escribe y se cuenta)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  /** El ORIGEN declara `folder` y `document#publisher`; el DESTINO (`reconcileConfig`) ninguno de los dos. */
  const sourceConfig = defineRelationsConfig({
    objectTypes: [
      { type: 'document', relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }, { name: 'publisher' }] },
      { type: 'folder', relations: [{ name: 'viewer' }] },
    ],
    holderTypes: ['user', 'admin', 'integration'],
  })

  async function seededSource(p: ScopeRef): Promise<{ source: RelationsDriver; keep: RelObject; alice: RelSubject }> {
    const source = makeRelationsDriver({ config: sourceConfig, capabilities: FULL_CAPS })
    const alice: RelSubject = { type: 'user', uuid: uuidv7() }
    const keep: RelObject = { type: 'document', id: uuidv7() }
    await source.relate(alice, 'viewer', keep, p) // declarada en el destino: SÍ migra
    await source.relate(alice, 'viewer', { type: 'folder', id: uuidv7() }, p) // tipo no declarado
    await source.relate(alice, 'publisher', { type: 'document', id: uuidv7() }, p) // relación no declarada
    return { source, keep, alice }
  }

  /** El destino REAL (`database`) con su `relate` contado: qué llegó a pedirle el reconcile. */
  function countedDestination(): { dest: RelationsDriver; relates: () => string[] } {
    const real = new DatabaseRelationsDriver(reconcileConfig())
    const asked: string[] = []
    const dest: RelationsDriver = {
      capabilities: real.capabilities,
      relate: (s, r, o, p, opts) => {
        asked.push(`${o.type}#${r}`)
        return real.relate(s, r, o, p, opts)
      },
      unrelate: real.unrelate.bind(real),
      check: real.check.bind(real),
      listObjects: real.listObjects.bind(real),
      listSubjects: real.listSubjects.bind(real),
      purgeObject: real.purgeObject.bind(real),
      purgeSubject: real.purgeSubject.bind(real),
      enumerateRelations: real.enumerateRelations!.bind(real),
    }
    return { dest, relates: () => asked }
  }

  test('SIN toConfig: el 422 del DRIVER del destino embuda — la no declarada no se escribe, se cuenta en skipped.undeclared, y lo declarado sí migra', async ({
    assert,
  }) => {
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const { source, keep, alice } = await seededSource(p)
    const { dest, relates } = countedDestination()
    const report = await reconcileRelations({ from: source, to: dest, partition: p })
    assert.equal(report.written, 1, 'solo la declarada (document#viewer) cuenta como escrita')
    assert.equal(report.skipped.undeclared, 2, 'folder#viewer y document#publisher se cuentan, no se escriben')
    assert.deepEqual(report.modelDrift, [], 'sin toConfig no hay modelDrift: fue el driver el que las rechazó')
    // El reconcile SÍ se las pidió al driver (sin config no puede saberlo antes) y el driver dijo 422.
    assert.sameMembers(relates(), ['document#viewer', 'folder#viewer', 'document#publisher'])
    // El CENSO en la tabla: ni una fila de folder ni de publisher; la declarada sí.
    const rows = await db.from('authz_relations').select('object_type', 'relation')
    assert.deepEqual(rows.map((r: any) => `${r.object_type}#${r.relation}`), ['document#viewer'])
    assert.isTrue(await dest.check(alice, 'viewer', keep, p))
  })

  test('CON toConfig: se descarta ANTES del driver (cero relate para ella), MISMOS números en dry-run y en real', async ({
    assert,
  }) => {
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const { source } = await seededSource(p)
    const toConfig = reconcileConfig()
    const { dest: dryDest, relates: dryRelates } = countedDestination()
    const dry = await reconcileRelations({ from: source, to: dryDest, partition: p, dryRun: true, toConfig })
    assert.equal(dry.written, 1)
    assert.equal(dry.skipped.undeclared, 2)
    assert.deepEqual(dry.modelDrift, ['folder'], 'el TIPO no declarado sigue saliendo como deriva del modelo')
    assert.deepEqual(dryRelates(), [], 'dry-run: cero escrituras')
    assert.lengthOf(await db.from('authz_relations'), 0)

    const { dest, relates } = countedDestination()
    const real = await reconcileRelations({ from: source, to: dest, partition: p, toConfig })
    assert.equal(real.written, dry.written, 'dry-run y pasada real: los MISMOS números')
    assert.equal(real.skipped.undeclared, dry.skipped.undeclared)
    assert.deepEqual(relates(), ['document#viewer'], 'con toConfig el driver NO llega a ver la no declarada')
    const rows = await db.from('authz_relations').select('object_type', 'relation')
    assert.deepEqual(rows.map((r: any) => `${r.object_type}#${r.relation}`), ['document#viewer'])

    // Idempotente: la segunda pasada sigue contándolas (no desaparecen sin rastro) y no escribe.
    const again = await reconcileRelations({ from: source, to: dest, partition: p, toConfig })
    assert.equal(again.written, 0)
    assert.equal(again.unchanged, 1)
    assert.equal(again.skipped.undeclared, 2)
  })

  test('una tupla no declarada que ya estuviera en el destino NO cuenta como respaldada: es `extra` (y `deleted` con --prune)', async ({
    assert,
  }) => {
    // El destino es un DOBLE aquí (un driver real ya no deja escribirla), para
    // fijar la regla del reconcile: lo que el destino no declara no lo respalda
    // el origen aunque lo tenga, así que --prune lo barre.
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const { source, keep, alice } = await seededSource(p)
    const toConfig = reconcileConfig()
    const dest = makeRelationsDriver({ config: toConfig, capabilities: FULL_CAPS })
    const stray: RelObject = { type: 'folder', id: uuidv7() }
    // La MISMA tupla en origen y destino: sin el embudo contaría como `unchanged` (respaldada).
    await source.relate(alice, 'viewer', stray, p)
    await dest.relate(alice, 'viewer', keep, p)
    await dest.relate(alice, 'viewer', stray, p)
    const dry = await reconcileRelations({ from: source, to: dest, partition: p, dryRun: true, toConfig })
    assert.equal(dry.unchanged, 1)
    assert.equal(dry.extra, 1, 'la folder del destino no la respalda el origen (no cabe en el destino)')
    const pruned = await reconcileRelations({ from: source, to: dest, partition: p, prune: true, toConfig })
    assert.equal(pruned.deleted, 1)
    assert.equal(pruned.skipped.undeclared, 3)
    assert.isFalse(await dest.check(alice, 'viewer', stray, p))
    assert.isTrue(await dest.check(alice, 'viewer', keep, p))
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
