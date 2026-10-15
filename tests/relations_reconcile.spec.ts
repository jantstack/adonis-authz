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
import { RelationsManager } from '../src/relations/manager.js'
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
  // Doble en memoria (L-2/L-4): no escribe en ninguna transacción, así que declara `false` y se le juzga esa cara; la `true` la juzga el driver `database` REAL en pool ≥ 2 (`relations_database.spec.ts`).
  transactionalWrites: false,
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
    // El destino es un DOBLE aquí, para fijar la regla del PLANIFICADOR: lo que
    // `toConfig` no declara no lo respalda el origen aunque el destino lo tenga.
    // Lo que modela el caso (cierre del auditor del lote 0, ⚪ 10): un destino
    // cuyo DRIVER sigue construido con la config VIEJA (`sourceConfig`, que
    // declara `folder`) mientras el reconcile ya corre con la ACTUAL (`toConfig`,
    // sin `folder`) — la ventana en que un despliegue rota la config antes que el
    // store. En ESA ventana la tupla `folder` sale en la enumeración del destino
    // (su lista blanca aún la incluye), el planificador la cuenta como `extra` y
    // `--prune` la borra. NO es el «residuo declarado» de CLAUDE.md: ése es el
    // caso del destino YA bajo la config nueva, cuya lista blanca la OCULTA en
    // `enumerateRelations`, así que ni sale como `extra` ni `--prune` la toca
    // («no las barre nadie», README «Limits»; `--prune-undeclared`, D7, es el
    // lote D). Desde el lote 0 del plan 2.5 (D13) el doble aplica F-05 como los
    // drivers reales, así que sembrar `folder` con la config actual ya no entra —
    // exactamente lo que un store real tampoco deja hacer.
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const { source, keep, alice } = await seededSource(p)
    const toConfig = reconcileConfig()
    const dest = makeRelationsDriver({ config: sourceConfig, capabilities: FULL_CAPS })
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

/* ── ⚪ R2 (cierre-2 del lote A) · lo ENUMERADO fuera de la gramática se clasifica, nunca es un 422 del llamante ── */

/**
 * **⚪ R2 del re-ataque al cierre del lote A** (decisión del dueño 2026-10-15 (2)):
 * `relationTupleKey` valida cada componente (⚪ A9) y `planPartition` la aplicaba
 * a las tuplas ENUMERADAS del destino. Una tupla escrita a mano fuera de la
 * gramática (`document:<key>|ABC` con el SDK; una fila con `object_uuid` en
 * mayúsculas) hacía 422 `E_AUTHZ_INVALID_IDENTITY` TODA la pasada, también con
 * `--dry-run --prune`: un dato del BACKEND vendido como pregunta inválida del
 * llamante (invariante 5), y nadie la barría. Ahora es `extra` con motivo
 * (`invalid-identity`), listada con su línea; `--prune` se la pide al driver,
 * y si el driver la rechaza por el puerto se dice (`pruned: false`) sin tumbar
 * la pasada. El repro del auditor (`loteA-cierre-reataque.spec.ts` R2) está
 * invertido aquí.
 */
test.group('relaciones · reconcile — ⚪ R2 · una tupla ENUMERADA fuera de la gramática es `extra` con motivo invalid-identity, nunca un 422', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  const partitionOf = (): ScopeRef => ({ type: 'unit', uuid: uuidv7() })
  const goodTuple = (partition: ScopeRef) => ({
    subject: { type: 'user', uuid: uuidv7() } as RelSubject,
    relation: 'viewer',
    object: { type: 'document', id: uuidv7() } as RelObject,
    partition,
    expiresAt: null,
  })
  /** Un driver falso que enumera lo que se le da y APUNTA lo que se le pide borrar (sin gramática: borra lo que enumeró). */
  function fake(tuples: any[]): { driver: RelationsDriver; unrelated: string[] } {
    const unrelated: string[] = []
    const driver: any = {
      capabilities: { enumerateRelations: true },
      enumerateRelations: async () => ({ tuples }),
      relate: async () => {},
      unrelate: async (_s: any, _r: string, o: any) => void unrelated.push(o.id),
    }
    return { driver, unrelated }
  }

  test('el repro del auditor, invertido: fake([good, garbage]) como destino ⇒ --dry-run --prune NO lanza, unchanged 1, la basura listada como destino con pruned: true; sin --prune es extra con motivo; --prune la borra (deleted 1) y la buena queda', async ({
    assert,
  }) => {
    const partition = partitionOf()
    const good = goodTuple(partition)
    const garbage = { ...good, object: { type: 'document', id: 'ABC' } }
    const from = fake([good]).driver
    const dry = await reconcileRelations({ from, to: fake([good, garbage]).driver, partition, dryRun: true, prune: true })
    assert.equal(dry.unchanged, 1)
    assert.equal(dry.deleted, 1, 'dry-run: se pedirá borrar')
    assert.equal(dry.extra, 0)
    assert.lengthOf(dry.details ?? [], 1, 'ROJO (R2): la basura del backend salía como 422 del llamante')
    assert.deepInclude(dry.details![0], { side: 'destino', reason: 'invalid-identity', pruned: true })
    assert.include(dry.details![0].tuple, 'document:ABC#viewer@user:')
    assert.include(dry.details![0].tuple, `unit|${partition.uuid}`)
    assert.match(dry.details![0].message, /ABC/)

    const noPrune = await reconcileRelations({ from, to: fake([good, garbage]).driver, partition })
    assert.equal(noPrune.extra, 1, 'sin --prune: sobra, con motivo')
    assert.equal(noPrune.deleted, 0)
    assert.isUndefined(noPrune.details![0].pruned)

    const to = fake([good, garbage])
    const pruned = await reconcileRelations({ from, to: to.driver, partition, prune: true })
    assert.equal(pruned.deleted, 1, '--prune la borra')
    assert.equal(pruned.extra, 0)
    assert.equal(pruned.unchanged, 1)
    assert.deepEqual(to.unrelated, ['ABC'], 'se le pidió al driver EXACTAMENTE la que enumeró, y no la buena')
    assert.deepInclude(pruned.details![0], { side: 'destino', pruned: true })
  })

  test('destino REAL (`database`) con una fila ESCRITA A MANO (object_uuid en mayúsculas): --dry-run la lista sin lanzar; --prune se la pide al driver, que la rechaza por el puerto (R-16 en unrelate) ⇒ pruned: false, cuenta como extra, SIN throw, la fila sigue y la buena intacta', async ({
    assert,
  }) => {
    const partition = partitionOf()
    const good = goodTuple(partition)
    const dest = new DatabaseRelationsDriver(reconcileConfig())
    await dest.relate(good.subject, good.relation, good.object, partition, { expiresAt: null })
    await db.table('authz_relations').insert({
      uuid: uuidv7(),
      partition_key: `unit|${partition.uuid}`,
      object_type: 'document',
      object_uuid: 'ABC',
      relation: 'viewer',
      subject_type: 'user',
      subject_uuid: (good.subject as any).uuid,
      subject_relation: '',
      subject_partition: null,
      expires_at: null,
      created_at: new Date(),
    })
    const from = fake([good]).driver

    const dry = await reconcileRelations({ from, to: dest, partition, dryRun: true, prune: true })
    assert.equal(dry.unchanged, 1)
    assert.lengthOf(dry.details ?? [], 1, 'ROJO (R2): el dry-run lanzaba 422 por la fila a mano')
    assert.deepInclude(dry.details![0], { side: 'destino', reason: 'invalid-identity', pruned: true })

    const real = await reconcileRelations({ from, to: dest, partition, prune: true })
    assert.deepInclude(real.details![0], { side: 'destino', reason: 'invalid-identity', pruned: false }, 'el driver la rechazó por el puerto: se dice, no se lanza')
    assert.equal(real.deleted, 0)
    assert.equal(real.extra, 1, 'sigue sobrando')
    assert.equal(real.unchanged, 1)
    const rows: any[] = await db.from('authz_relations').select('object_uuid').orderBy('object_uuid')
    assert.deepEqual(rows.map((r) => String(r.object_uuid)).sort(), ['ABC', good.object.id].sort(), 'la fila a mano sigue (a mano se borra) y la buena intacta')
    assert.isTrue(await dest.check(good.subject, 'viewer', good.object, partition))
  })

  test('ORIGEN con una tupla fuera de la gramática: no se migra (la API no puede escribirla), skipped.invalid = 1, listada como origen, el resto migra; nunca un 422', async ({
    assert,
  }) => {
    const partition = partitionOf()
    const good = goodTuple(partition)
    const garbage = { ...good, subject: { type: 'user', uuid: 'Mallory' } }
    const dest = makeRelationsDriver({ config: reconcileConfig(), capabilities: FULL_CAPS })
    const report = await reconcileRelations({ from: fake([good, garbage]).driver, to: dest, partition })
    assert.equal(report.written, 1)
    assert.equal(report.skipped.invalid, 1, 'ROJO (R2): el origen con basura lanzaba 422')
    assert.lengthOf(report.details ?? [], 1)
    assert.deepInclude(report.details![0], { side: 'origen', reason: 'invalid-identity' })
    assert.include(report.details![0].tuple, '@user:Mallory')
    assert.isUndefined(report.details![0].pruned)
    assert.isTrue(await dest.check(good.subject, 'viewer', good.object, partition))
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

/* ── alpha.8 · C2 · el RESPALDO de `enumerateRelationsMany` no puede perder tuplas ── */

/**
 * **alpha.8 · C2** (panel relay 2, analista §8 / juez 7.1, 🟠). El respaldo de
 * `RelationsManager.enumerateRelationsMany` (driver SIN el método) acumulaba las
 * K llamadas a `enumerateRelations` y devolvía **el cursor de la última partición
 * que tenía más**: reanudar con él aplicaba `uuid > after` a TODAS las
 * particiones y perdía tuplas en silencio (medido: 6 en el store, 5 vistas,
 * `a9` perdida). En el ORIGEN de una migración eso es «esa tupla no existía».
 * Doctrina del barrido único (decisión del dueño 2026-09-10 (3)): si no puede
 * enumerar exhaustivamente, falla RUIDOSO. El respaldo no emite cursores que
 * no sabe reanudar (500 en cuanto una partición devuelve uno) y no acepta un
 * cursor ajeno (`after` ⇒ 500 con cero llamadas al driver).
 */
test.group('alpha.8 · C2 — el respaldo de `RelationsManager.enumerateRelationsMany` no pierde tuplas: exhaustivo o RUIDOSO (500)', () => {
  // D4 (lote A): la partición va CON guiones (la ortografía de 32 hex es 422).
  const uuid = (n: number) => {
    const hex = String(n).padStart(32, '0')
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
  }
  const pA: ScopeRef = { type: 'organization', uuid: uuid(1) }
  const pB: ScopeRef = { type: 'organization', uuid: uuid(2) }
  const tuple = (id: string, partition: ScopeRef) => ({
    subject: { type: 'user', uuid: uuid(9) },
    relation: 'viewer',
    object: { type: 'document', id },
    partition,
    expiresAt: null,
  })

  /** Un driver de terceros que pagina por partición (2 por página) y NO trae `enumerateRelationsMany`. */
  function pagingDriver(rows: Record<string, string[]>, perPage: number) {
    const calls: string[] = []
    const driver: any = {
      capabilities: { enumerateRelations: true },
      async enumerateRelations(partition: ScopeRef, page?: { after?: string; limit?: number }) {
        const after = page?.after
        calls.push(`${String(partition.uuid).slice(-1)} after=${after ?? '-'}`)
        const all = rows[String(partition.uuid)].filter((u) => (after === undefined ? true : u > after))
        const slice = all.slice(0, perPage)
        const cursor = all.length > perPage ? slice[slice.length - 1] : undefined
        const tuples = slice.map((u) => tuple(u, partition))
        return cursor ? { tuples, cursor } : { tuples }
      },
    }
    return { driver, calls }
  }

  test('EL CASO (analista m6): con particiones que PAGINAN, el respaldo NO devuelve un cursor que no sabe reanudar — 500 E_AUTHZ_CONFIG nombrando `enumerateRelationsMany`; y reanudar con un cursor ajeno (`after`) es 500 con CERO llamadas al driver', async ({
    assert,
  }) => {
    const { driver, calls } = pagingDriver({ [uuid(1)]: ['a1', 'a5', 'a9'], [uuid(2)]: ['b2', 'b3', 'b4'] }, 2)
    const manager = new RelationsManager(driver, reconcileConfig())

    // Hasta alpha.7: página 1 = a1,a5,b2,b3 · cursor=b3; página 2 (after b3) = b4 — a9 PERDIDA.
    let caught: any
    try {
      await manager.enumerateRelationsMany([pA, pB])
    } catch (error) {
      caught = error
    }
    assert.equal(caught?.code, 'E_AUTHZ_CONFIG', 'una partición devolvió cursor: el respaldo no puede mentir con uno que no sabe reanudar')
    assert.equal(caught?.status, 500)
    assert.include(caught?.message, 'enumerateRelationsMany')
    assert.include(caught?.message, 'enumerateRelations', 'la salida: implementar el método en el driver o paginar partición a partición')

    calls.length = 0
    caught = undefined
    try {
      await manager.enumerateRelationsMany([pA, pB], { after: 'b3' })
    } catch (error) {
      caught = error
    }
    assert.equal(caught?.code, 'E_AUTHZ_CONFIG', 'un cursor que el respaldo no emitió no se reanuda: ruidoso')
    assert.deepEqual(calls, [], 'y sin tocar el driver: no hay «medio barrido»')
  })

  test('control: cuando NINGUNA partición pagina, el respaldo devuelve la unión de las K llamadas, sin cursor (alpha.6, intacto)', async ({
    assert,
  }) => {
    const { driver, calls } = pagingDriver({ [uuid(1)]: ['a1', 'a5'], [uuid(2)]: ['b2', 'b3'] }, 10)
    const manager = new RelationsManager(driver, reconcileConfig())
    const page = await manager.enumerateRelationsMany([pA, pB])
    assert.isUndefined(page.cursor)
    assert.deepEqual(page.tuples.map((t) => t.object.id), ['a1', 'a5', 'b2', 'b3'])
    assert.deepEqual(calls, ['1 after=-', '2 after=-'], 'K llamadas, una por partición')
  })
})
