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
import { relationsReconcileLines } from '../commands/authz_relations_reconcile.js'
import { RelationsManager } from '../src/relations/manager.js'
import { contractDenyRelationsConfig, makeRelationsDriver } from '../src/testing/relations_contract.js'
import { assertRelationDeclared, assertSupportedUserset, defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { relationTupleKey } from '../src/relations/tuple_key.js'
import { AuthorizationBackendError, InvalidIdentityError, InvalidSlugError, RelationTypeUnknownError, RelationUnknownError, RelationUsersetUnsupportedError } from '../src/errors.js'
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

/* ── 1b · La cara del DENY del runner (lote D · D2), doble ↔ doble ─────────── */

runRelationsReconcileContract({
  name: 'doble en memoria · deny',
  config: contractDenyRelationsConfig(),
  denies: true,
  makeA: (config) => makeRelationsDriver({ config, capabilities: { ...FULL_CAPS, relationDenies: true } }),
  makeB: (config) => makeRelationsDriver({ config, capabilities: { ...FULL_CAPS, relationDenies: true } }),
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

  /** El residuo pre-2.5 de B3, sembrado por SQL tal como lo dejó alpha.x: una fila con un sujeto userset ≠ `group#member`. */
  async function seedUsersetResidue(p: ScopeRef, objectId: string, subjectObjectId: string, relation = 'viewer'): Promise<string> {
    const uuid = uuidv7()
    await db.table('authz_relations').insert({
      uuid,
      partition_key: `unit|${p.uuid}`,
      object_type: 'document',
      object_uuid: objectId,
      relation: 'viewer',
      subject_type: 'document',
      subject_uuid: subjectObjectId,
      subject_relation: relation,
      subject_partition: `unit|${p.uuid}`,
      expires_at: null,
      created_at: new Date(),
    })
    return uuid
  }
  const residueRows = async (p: ScopeRef) =>
    db.from('authz_relations').where('partition_key', `unit|${p.uuid}`).where('subject_type', 'document').select('uuid')

  /**
   * **Cierre 1 del lote B · 🟠 2 (decisión 4 RECHAZADA)**: una tupla del ORIGEN cuyo sujeto es un userset
   * DECLARADO que no es `group#member` —la fila inerte de `database` anterior a 2.5.0, enumerada tal cual— se
   * clasifica en el PLAN, antes del driver: `skipped.usersetUnsupported`, entrada en `details` con lado y receta,
   * y los MISMOS números en `--dry-run`, en la pasada real y en el `--dry-run` siguiente; el driver NO recibe
   * ese `relate`. Hasta el cierre `RelationUsersetUnsupportedError` heredaba de F-05 y `relateOrSkip` la tragaba
   * como `undeclared` (consejo falso «decláralo en el destino»), `--dry-run` decía «haría 1 escritura» y `details`
   * salía vacío (repro del auditor, `audb_b3.spec.ts` segundo caso).
   */
  test('🟠 2 · ORIGEN `database` REAL con el residuo de B3 sembrado por SQL ⇒ dry-run, real y dry-run siguiente dan los MISMOS números (skipped.usersetUnsupported 1, details origen/userset-unsupported), el driver del destino NO recibe ese relate, lo bueno migra; con toConfig igual', async ({
    assert,
  }) => {
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const alice: RelSubject = { type: 'user', uuid: uuidv7() }
    const keep: RelObject = { type: 'document', id: uuidv7() }
    const source = new DatabaseRelationsDriver(reconcileConfig())
    await source.relate(alice, 'viewer', keep, p)
    const staleObject = uuidv7()
    await seedUsersetResidue(p, staleObject, uuidv7())
    for (const toConfig of [undefined, reconcileConfig()]) {
      const label = toConfig ? 'con toConfig' : 'sin toConfig'
      const relates: string[] = []
      const double = makeRelationsDriver({ config: reconcileConfig(), capabilities: FULL_CAPS })
      const dest: RelationsDriver = { ...double, relate: (s, r, o, pp, opts) => { relates.push(`${o.type}:${o.id}#${r}`); return double.relate(s, r, o, pp, opts) } } as RelationsDriver
      const dry1 = await reconcileRelations({ from: source, to: dest, partition: p, dryRun: true, toConfig })
      const real = await reconcileRelations({ from: source, to: dest, partition: p, toConfig })
      const dry2 = await reconcileRelations({ from: source, to: dest, partition: p, dryRun: true, toConfig })
      assert.equal(dry1.written, 1, `${label} · dry1: ROJO (🟠 2) si dice 2 — el residuo se vendía como escritura pendiente`)
      assert.equal(real.written, 1, `${label} · real`)
      assert.equal(dry2.written, 0, `${label} · dry2: nada pendiente`)
      assert.equal(dry2.unchanged, 1, `${label} · dry2`)
      for (const [name, report] of [['dry1', dry1], ['real', real], ['dry2', dry2]] as const) {
        assert.equal(report.skipped.undeclared, 0, `${label} · ${name}: NO es «no declarado» (el consejo era falso)`)
        assert.equal(report.skipped.usersetUnsupported, 1, `${label} · ${name}: ROJO (🟠 2) — el residuo se cuenta con SU motivo, en los tres`)
        assert.lengthOf(report.details ?? [], 1, `${label} · ${name}: listado`)
        assert.deepInclude(report.details![0], { side: 'origen', reason: 'userset-unsupported' }, `${label} · ${name}`)
        assert.isUndefined(report.details![0].pruned, `${label} · ${name}: en el origen no hay poda`)
        assert.include(report.details![0].tuple, `document:${staleObject}#viewer@document:`, `${label} · ${name}: la tupla legible`)
        assert.match(report.details![0].message, /group#member/, `${label} · ${name}: el porqué`)
      }
      assert.deepEqual(relates, [`document:${keep.id}#viewer`], `${label}: el driver del destino recibió SOLO lo bueno, una vez (el residuo nunca llegó a relate)`)
      assert.isTrue(await dest.check(alice, 'viewer', keep, p), label)
      // La letra: el verificador queda rojo, pero DICE qué, de qué lado y cómo se arregla.
      const { lines, clean } = relationsReconcileLines(dry2)
      assert.isFalse(clean, `${label}: hay algo que hacer a mano ⇒ no limpia`)
      const line = lines.find((l) => /\(userset-unsupported\) origen/.test(l.message))
      assert.equal(line?.level, 'error', `${label}: la línea del residuo`)
      assert.match(line!.message, /residuo pre-2\.5 \(B3\)/, label)
      assert.match(line!.message, /DELETE FROM authz_relations WHERE subject_relation <> ''/, `${label}: la receta en la línea`)
      assert.isTrue(lines.every((l) => !/decláralos en el destino/.test(l.message)), `${label}: el consejo falso de undeclared no sale`)
    }
    assert.lengthOf(await residueRows(p), 1, 'el residuo del origen sigue ahí: solo lo quita la receta')
  })

  /**
   * **Cierre 2 del lote B · 🟡 N2** (el 🟠 2 sobrevivía en un subconjunto; decisión 3 del cierre 1 RECHAZADA): un
   * residuo del ORIGEN cuyo userset tiene un tipo o una relación que `toConfig` NO declara
   * (`document#viewer@folder:F#viewer`, `document#viewer@document:E#reader`) volvía a `skipped.undeclared` —sin
   * `details`, sin receta y con el consejo FALSO «decláralos en el destino» (que no arregla nada: declarado, la
   * pasada siguiente lo reclasifica como residuo)— porque `classifySubject` juzgaba F-05 ANTES que la forma. B3
   * hace la fila inadmisible con CUALQUIER config, así que la FORMA domina: `assertSupportedUserset` primero, con o
   * sin `toConfig`. El bucket ya no depende de si hay config persistida (repro del auditor, `audb2_residue` C).
   */
  test('🟡 N2 · ORIGEN `database` con residuos cuyo userset NO está declarado en toConfig (tipo `folder`, relación `reader`) ⇒ skipped.usersetUnsupported 2 + 2 details con receta, undeclared 0, modelDrift [], MISMOS números con toConfig que lo declara y sin toConfig, dry = real; el consejo falso de undeclared no sale', async ({
    assert,
  }) => {
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const alice: RelSubject = { type: 'user', uuid: uuidv7() }
    const keep: RelObject = { type: 'document', id: uuidv7() }
    const sourceConfig = defineRelationsConfig({
      objectTypes: [
        { type: 'document', relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }] },
        { type: 'folder', relations: [{ name: 'viewer' }] },
      ],
      holderTypes: ['user', 'admin', 'integration'],
      database: { membersOf: true },
    })
    const source = new DatabaseRelationsDriver(sourceConfig)
    await source.relate(alice, 'viewer', keep, p)
    const folderResidue = uuidv7()
    const readerResidue = uuidv7()
    await db.table('authz_relations').insert({ uuid: uuidv7(), partition_key: `unit|${p.uuid}`, object_type: 'document', object_uuid: folderResidue, relation: 'viewer', subject_type: 'folder', subject_uuid: uuidv7(), subject_relation: 'viewer', subject_partition: `unit|${p.uuid}`, expires_at: null, created_at: new Date() })
    await db.table('authz_relations').insert({ uuid: uuidv7(), partition_key: `unit|${p.uuid}`, object_type: 'document', object_uuid: readerResidue, relation: 'viewer', subject_type: 'document', subject_uuid: uuidv7(), subject_relation: 'reader', subject_partition: `unit|${p.uuid}`, expires_at: null, created_at: new Date() })
    for (const [label, toConfig] of [['toConfig SIN folder ni reader', reconcileConfig()], ['toConfig CON folder', sourceConfig], ['sin toConfig', undefined]] as const) {
      const dest = makeRelationsDriver({ config: reconcileConfig(), capabilities: FULL_CAPS })
      const dry = await reconcileRelations({ from: source, to: dest, partition: p, dryRun: true, toConfig })
      const real = await reconcileRelations({ from: source, to: dest, partition: p, toConfig })
      for (const [name, report] of [['dry', dry], ['real', real]] as const) {
        assert.equal(report.skipped.usersetUnsupported, 2, `${label} · ${name}: ROJO (N2) — la forma del userset domina sobre F-05 del par: ${JSON.stringify(report.skipped)}`)
        assert.equal(report.skipped.undeclared, 0, `${label} · ${name}: NUNCA undeclared (el consejo «decláralos» no arregla un residuo B3)`)
        assert.deepEqual(report.modelDrift, [], `${label} · ${name}: el userset no es deriva del modelo`)
        assert.equal(report.written, name === 'dry' ? 1 : 1, `${label} · ${name}`)
        assert.lengthOf(report.details ?? [], 2, `${label} · ${name}: los dos residuos listados`)
        for (const detail of report.details!) {
          assert.deepInclude(detail, { side: 'origen', reason: 'userset-unsupported' }, `${label} · ${name}`)
          assert.match(detail.message, /group#member/, `${label} · ${name}: el porqué (B3)`)
        }
        const { lines, clean } = relationsReconcileLines(report)
        assert.isFalse(clean, `${label} · ${name}`)
        assert.lengthOf(lines.filter((l) => /\(userset-unsupported\) origen/.test(l.message)), 2, `${label} · ${name}: dos líneas con receta`)
        assert.isTrue(lines.every((l) => !/decláralos en el destino/.test(l.message)), `${label} · ${name}: el consejo falso no sale`)
        assert.isTrue(lines.every((l) => !/skipped\.undeclared/.test(l.message)), `${label} · ${name}`)
      }
      assert.isTrue(await dest.check(alice, 'viewer', keep, p), `${label}: lo bueno migró`)
    }
  })

  /**
   * **Cierre 2 del lote B · ⚪ N8**: la letra del seguro R-17 cuando el origen solo aporta residuo. Con `toConfig`
   * decía «(1 leídas, todas de tipos que el destino no declara)» —falso: es residuo B3, no un tipo sin declarar— y
   * sin `toConfig` «(1 leídas)» sin nombrar nada. Ahora el desglose cuenta cada motivo POR SU NOMBRE y solo los que
   * son > 0; «todas de tipos que el destino no declara» solo cuando es verdad.
   */
  test('⚪ N8 · R-17 con un ORIGEN que solo aporta residuo B3 (+ una caducada) ⇒ 500 E_AUTHZ_MASS_RECONCILE_REFUSED cuyo desglose nombra «userset no admitido (B3)» y «caducada», con y sin toConfig, y NUNCA «todas de tipos que el destino no declara»; con un origen que solo aporta un tipo no declarado SÍ lo dice', async ({
    assert,
  }) => {
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const source = new DatabaseRelationsDriver(reconcileConfig())
    await seedUsersetResidue(p, uuidv7(), uuidv7())
    await db.table('authz_relations').insert({ uuid: uuidv7(), partition_key: `unit|${p.uuid}`, object_type: 'document', object_uuid: uuidv7(), relation: 'viewer', subject_type: 'user', subject_uuid: uuidv7(), subject_relation: '', subject_partition: null, expires_at: new Date(Date.now() - 86_400_000), created_at: new Date() })
    for (const [label, toConfig] of [['con toConfig', reconcileConfig()], ['sin toConfig', undefined]] as const) {
      const dest = makeRelationsDriver({ config: reconcileConfig(), capabilities: FULL_CAPS })
      await dest.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, p)
      const caught = await reconcileRelations({ from: source, to: dest, partition: p, prune: true, toConfig }).then(() => null, (e) => e)
      assert.equal(caught?.code, 'E_AUTHZ_MASS_RECONCILE_REFUSED', `${label}: el seguro se niega`)
      assert.include(caught.message, '2 leídas', label)
      assert.include(caught.message, '1 con sujeto userset no admitido (B3, skipped.usersetUnsupported)', `ROJO (N8) ${label}: el residuo no se nombra`)
      assert.include(caught.message, '1 caducada(s)', label)
      assert.notInclude(caught.message, 'todas de tipos que el destino no declara', `ROJO (N8) ${label}: la letra falsa`)
      assert.notInclude(caught.message, 'undeclared', label)
    }
    // Control: un origen cuyo ÚNICO aporte es un tipo que el destino no declara sí lo dice, y por su nombre.
    const p2: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const folderConfig = defineRelationsConfig({ objectTypes: [{ type: 'document', relations: [{ name: 'viewer' }] }, { type: 'folder', relations: [{ name: 'viewer' }] }], holderTypes: ['user'] })
    const src2 = new DatabaseRelationsDriver(folderConfig)
    await src2.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'folder', id: uuidv7() }, p2)
    const dest2 = makeRelationsDriver({ config: reconcileConfig(), capabilities: FULL_CAPS })
    await dest2.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, p2)
    const control = await reconcileRelations({ from: src2, to: dest2, partition: p2, prune: true, toConfig: reconcileConfig() }).then(() => null, (e) => e)
    assert.equal(control?.code, 'E_AUTHZ_MASS_RECONCILE_REFUSED')
    assert.include(control.message, '1 de tipo o relación que el destino no declara (skipped.undeclared)')
    assert.notInclude(control.message, 'userset')
  })

  /**
   * **Cierre 1 del lote B · 🟠 1**: el residuo de B3 en el DESTINO `database` con `--prune`. Hasta el cierre
   * el plan lo metía en `toDelete`, los `toWrite` se escribían, `to.unrelate(residuo)` daba 422 y el bucle de
   * poda RELANZABA: pasada abortada a mitad, escritura parcial, el sobrante sin borrar, y cada `--prune`
   * siguiente moría igual (repro del auditor, `audb_b3.spec.ts` primer caso). Ahora: `extra` + `details`
   * (`destino`, `userset-unsupported`, `pruned: false`, receta), cero throw, cero DELETE por vía de plataforma,
   * la pasada hace TODO lo demás (escribe W, borra X) y el verificador lo dice con exit ≠ 0. Corre en los
   * CUATRO modos del harness (`:memory:`, sqlite-file, pg, mysql): los tres motores.
   */
  test('🟠 1 · DESTINO `database` REAL con el residuo de B3 sembrado por SQL + --prune ⇒ sin throw, W escrita, X borrada, el residuo sigue (nunca un DELETE de plataforma), extra 1, details destino/userset-unsupported/pruned:false con receta, exit ≠ 0; --dry-run --prune da los MISMOS números; sin --prune también lo lista', async ({
    assert,
  }) => {
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const dest = new DatabaseRelationsDriver(reconcileConfig())
    const d1 = uuidv7()
    const residueUuid = await seedUsersetResidue(p, d1, uuidv7())
    const x: RelObject = { type: 'document', id: uuidv7() }
    await dest.relate({ type: 'user', uuid: uuidv7() }, 'viewer', x, p) // sobra en el destino: --prune la borra
    const source = makeRelationsDriver({ config: reconcileConfig(), capabilities: FULL_CAPS })
    const w: RelObject = { type: 'document', id: uuidv7() }
    const alice: RelSubject = { type: 'user', uuid: uuidv7() }
    await source.relate(alice, 'viewer', w, p)

    const dry = await reconcileRelations({ from: source, to: dest, partition: p, prune: true, dryRun: true })
    assert.equal(dry.written, 1)
    assert.equal(dry.deleted, 1, 'dry-run: X se pedirá borrar')
    assert.equal(dry.extra, 1, 'dry-run: el residuo SOBRA y no se pedirá borrar')
    assert.deepInclude(dry.details![0], { side: 'destino', reason: 'userset-unsupported', pruned: false }, 'dry-run: pruned: false desde el plan')
    assert.lengthOf(await db.from('authz_relations').where('partition_key', `unit|${p.uuid}`), 2, 'dry-run: cero escrituras')

    const real = await reconcileRelations({ from: source, to: dest, partition: p, prune: true }).then((r) => r, (e) => e)
    assert.isFalse(real instanceof Error, `ROJO (🟠 1): la pasada --prune REVENTÓ a mitad por el residuo: ${real?.code} ${real?.message}`)
    assert.equal(real.written, dry.written, 'dry-run y real: los MISMOS números (written)')
    assert.equal(real.deleted, dry.deleted, 'deleted')
    assert.equal(real.extra, dry.extra, 'extra')
    assert.deepEqual(real.skipped, dry.skipped, 'skipped')
    assert.deepInclude(real.details![0], { side: 'destino', reason: 'userset-unsupported', pruned: false })
    assert.include(real.details![0].tuple, `document:${d1}#viewer@document:`)
    assert.isTrue(await dest.check(alice, 'viewer', w, p), 'W escrita (y no a medias: la pasada terminó)')
    const rows: any[] = await db.from('authz_relations').where('partition_key', `unit|${p.uuid}`).select('uuid', 'object_uuid', 'subject_type')
    assert.sameDeepMembers(
      rows.map((r) => `${r.object_uuid}@${r.subject_type}`),
      [`${w.id}@user`, `${d1}@document`],
      'X borrada por --prune, W escrita, el residuo sigue (la plataforma no lo borra)'
    )
    assert.equal(String(rows.find((r) => r.subject_type === 'document').uuid), residueUuid)
    const { lines, clean } = relationsReconcileLines(real)
    assert.isFalse(clean, 'exit ≠ 0: hay un residuo que solo se borra a mano')
    const line = lines.find((l) => /\(userset-unsupported\) destino/.test(l.message))
    assert.equal(line?.level, 'error')
    assert.match(line!.message, /--prune NO lo borra/)
    assert.match(line!.message, /DELETE FROM authz_relations WHERE subject_relation <> ''/, 'la receta en la línea')
    // Idempotente: la pasada siguiente no revienta, no escribe y sigue listando el residuo.
    const again = await reconcileRelations({ from: source, to: dest, partition: p, prune: true })
    assert.equal(again.written, 0)
    assert.equal(again.deleted, 0)
    assert.equal(again.extra, 1)
    assert.equal(again.unchanged, 1)
    // Sin --prune: el residuo también se lista (sin `pruned`), cuenta en extra, y la pasada tampoco es limpia.
    const noPrune = await reconcileRelations({ from: source, to: dest, partition: p })
    assert.equal(noPrune.extra, 1)
    assert.deepInclude(noPrune.details![0], { side: 'destino', reason: 'userset-unsupported' })
    assert.isUndefined(noPrune.details![0].pruned)
    const noPruneLines = relationsReconcileLines(noPrune)
    assert.isFalse(noPruneLines.clean)
    assert.match(noPruneLines.lines.find((l) => /\(userset-unsupported\) destino/.test(l.message))!.message, /--prune tampoco lo borraría/)
    // Y la receta del README (⚪ 12) es lo ÚNICO que lo quita: después, la pasada es limpia.
    const { RELATION_USERSET_RESIDUE_DELETE } = await import('../src/relations/define_relations_config.js')
    await db.rawQuery(RELATION_USERSET_RESIDUE_DELETE.replace(/;$/, ''))
    const cleanPass = await reconcileRelations({ from: source, to: dest, partition: p, prune: true })
    assert.equal(cleanPass.extra, 0)
    assert.lengthOf(cleanPass.details ?? [], 0)
    assert.isTrue(relationsReconcileLines(cleanPass).clean, 'tras la receta: limpia')
  })

  /**
   * **`relateOrSkip` NO traga `E_AUTHZ_RELATION_USERSET_UNSUPPORTED`** (cierre 1 del lote B, decisión 4
   * rechazada; R2-5: el plan clasifica, el driver no absorbe): un driver que lo lanzara por una tupla que el plan
   * dio por BUENA (un holder) está diciendo otra cosa, y eso se PROPAGA — nunca `skipped.undeclared`.
   */
  test('🟠 2 · relateOrSkip no traga E_AUTHZ_RELATION_USERSET_UNSUPPORTED: un destino que lo lanza por un HOLDER propaga el 422 (no lo cuenta como undeclared)', async ({ assert }) => {
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const { RelationUsersetUnsupportedError } = await import('../src/errors.js')
    const source = makeRelationsDriver({ config: reconcileConfig(), capabilities: FULL_CAPS })
    await source.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, p)
    const odd: RelationsDriver = {
      capabilities: FULL_CAPS,
      enumerateRelations: async () => ({ tuples: [] }),
      relate: async () => {
        throw new RelationUsersetUnsupportedError('un driver raro')
      },
    } as any
    const caught = await reconcileRelations({ from: source, to: odd, partition: p }).then(() => null, (e) => e)
    assert.isNotNull(caught, 'ROJO: el 422 del driver se tragó como skipped')
    assert.equal(caught.code, 'E_AUTHZ_RELATION_USERSET_UNSUPPORTED')
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

  test('una tupla no declarada que ya estuviera en el destino NO cuenta como respaldada: es `extra` con motivo `undeclared` (cierre 3 · 🟠 N9) y --prune NO la borra; re-declarada en toConfig vuelve a ser una tupla normal', async ({
    assert,
  }) => {
    // El destino es un DOBLE aquí, para fijar la regla del PLANIFICADOR: lo que
    // `toConfig` no declara no lo respalda el origen aunque el destino lo tenga.
    // Lo que modela el caso (cierre del auditor del lote 0, ⚪ 10): un destino
    // cuyo DRIVER sigue construido con la config VIEJA (`sourceConfig`, que
    // declara `folder`) mientras el reconcile ya corre con la ACTUAL (`toConfig`,
    // sin `folder`) — la ventana en que un despliegue rota la config antes que el
    // store. En ESA ventana la tupla `folder` sale en la enumeración del destino
    // (su lista blanca aún la incluye). **Hasta el cierre 3 del lote B el plan la
    // contaba como `extra` y `--prune` la borraba por el driver viejo** — la misma
    // fila que con el driver YA bajo la config nueva hacía 422 a mitad de pasada
    // (🟠 N9). Desde el cierre 3 la regla es por la FILA, no por el driver (N3,
    // «una regla, no dos»): `toConfig` dice que el destino no declara `folder`, así
    // que es residuo `undeclared` —`extra` + `details`, `pruned: false`, nunca en
    // `toDelete`— con la receta «retírala a mano o vuelve a declararla». Y el
    // «residuo declarado» de CLAUDE.md (el destino YA bajo la config nueva, cuya
    // lista blanca la OCULTA en `enumerateRelations`) sigue sin verse: ni sale
    // como `extra` ni `--prune` la toca («no las barre nadie», README «Limits»;
    // `--prune-undeclared`, D7, es el lote D). Desde el lote 0 del plan 2.5 (D13)
    // el doble aplica F-05 como los drivers reales, así que sembrar `folder` con
    // la config actual ya no entra — exactamente lo que un store real tampoco deja hacer.
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
    assert.deepInclude(dry.details![0], { side: 'destino', reason: 'undeclared' }, 'N9: y se LISTA con su motivo')
    const pruned = await reconcileRelations({ from: source, to: dest, partition: p, prune: true, toConfig })
    assert.equal(pruned.deleted, 0, 'N9: --prune NO la borra (la regla es por la fila: el destino no la declara)')
    assert.equal(pruned.extra, 1)
    assert.deepInclude(pruned.details![0], { side: 'destino', reason: 'undeclared', pruned: false })
    assert.equal(pruned.skipped.undeclared, 3)
    assert.isTrue(await dest.check(alice, 'viewer', stray, p), 'sigue ahí: a mano o re-declarar')
    assert.isTrue(await dest.check(alice, 'viewer', keep, p))
    // Re-declarada en toConfig (la receta): vuelve a ser una tupla normal — respaldada por el origen, `unchanged`.
    const redeclared = await reconcileRelations({ from: source, to: dest, partition: p, prune: true, toConfig: sourceConfig })
    assert.equal(redeclared.unchanged, 2)
    assert.deepEqual(redeclared.details, [])
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

  /**
   * **Cierre 2 del lote B · 🟡 N3 (unificación, condición del auditor a la decisión 1 del cierre 1)**: un residuo
   * del DESTINO que ningún driver del paquete borra —`invalid-identity` igual que `userset-unsupported`— tiene UNA
   * semántica: `extra` + `details` con `pruned: false` bajo `--prune` (también en `--dry-run`), NUNCA en `toDelete`
   * (la pasada no se lo pide a nadie: ni `unrelate` por el puerto —los dos drivers del paquete lo rechazan por su
   * gramática, R-16— ni un DELETE de plataforma), exit ≠ 0 en los cuatro modos y receta en la línea. Hasta el
   * cierre 2 (regla del cierre-2 del lote A) la pasada se lo PEDÍA al driver: un driver sin gramática lo borraba
   * (`pruned: true`), los del paquete lo rechazaban (`pruned: false`), y sin `--prune` era un warning con el consejo
   * falso «repite con --prune». «Una regla, no dos» (coordinador, 2026-10-15). El reporte lleva `prune`.
   */
  test('🟡 N3 · fake([good, garbage]) como destino ⇒ en los CUATRO modos la basura es extra 1 con details destino/invalid-identity, NUNCA se le pide al driver (unrelated = []), pruned: false bajo --prune (dry y real), ausente sin --prune, deleted 0; el reporte lleva prune', async ({
    assert,
  }) => {
    const partition = partitionOf()
    const good = goodTuple(partition)
    const garbage = { ...good, object: { type: 'document', id: 'ABC' } }
    const from = fake([good]).driver
    for (const prune of [true, false]) {
      for (const dryRun of [true, false]) {
        const to = fake([good, garbage])
        const report = await reconcileRelations({ from, to: to.driver, partition, dryRun, prune })
        const label = `prune=${prune} dryRun=${dryRun}`
        assert.equal(report.prune, prune, `${label}: el reporte lleva prune`)
        assert.equal(report.dryRun, dryRun, label)
        assert.equal(report.unchanged, 1, label)
        assert.equal(report.deleted, 0, `ROJO (N3) ${label}: la basura se vendía como borrada/por borrar`)
        assert.equal(report.extra, 1, `${label}: sobra, con motivo, en los cuatro modos`)
        assert.lengthOf(report.details ?? [], 1, label)
        assert.deepInclude(report.details![0], { side: 'destino', reason: 'invalid-identity' }, label)
        if (prune) assert.strictEqual(report.details![0].pruned, false, `ROJO (N3) ${label}: pruned: false desde el plan (nadie la borra)`)
        else assert.isUndefined(report.details![0].pruned, label)
        assert.include(report.details![0].tuple, 'document:ABC#viewer@user:', label)
        assert.include(report.details![0].tuple, `unit|${partition.uuid}`, label)
        assert.match(report.details![0].message, /ABC/, label)
        assert.deepEqual(to.unrelated, [], `ROJO (N3) ${label}: se le pidió al driver que la borrara`)
        const { lines, clean } = relationsReconcileLines(report)
        assert.isFalse(clean, `${label}: deriva en los cuatro modos`)
        const line = lines.find((l) => /\(invalid-identity\) destino/.test(l.message))
        assert.equal(line?.level, 'error', label)
        assert.match(line!.message, /^sobra \(invalid-identity\) destino: /, `${label}: prefijo estable de la rama`)
        assert.match(line!.message, /a mano \(SQL\/SDK\)/, label)
        assert.isTrue(lines.every((l) => !/no pasaste --prune|repite con --prune/.test(l.message)), `${label}: jamás «repite con --prune»`)
      }
    }
  })

  test('destino REAL (`database`) con una fila ESCRITA A MANO (object_uuid en mayúsculas): --dry-run la lista sin lanzar; --prune NO se la pide al driver (cierre 2 · N3: lo rechazaría por el puerto, R-16) ⇒ pruned: false en dry y real, cuenta como extra, SIN throw, la fila sigue y la buena intacta', async ({
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
    // Cierre 2 · N3: `pruned: false` ya desde el plan, también en --dry-run (nadie la borra: ni se le pide al driver).
    assert.deepInclude(dry.details![0], { side: 'destino', reason: 'invalid-identity', pruned: false })
    assert.equal(dry.extra, 1, 'dry-run: sobra (no «se borraría»)')
    assert.equal(dry.deleted, 0)

    const unrelates: string[] = []
    // Proxy y no spread: `DatabaseRelationsDriver` es una clase (el spread perdería `enumerateRelations`).
    const spied = new Proxy(dest, {
      get(target, prop, receiver) {
        if (prop === 'unrelate') return async (s: any, r: string, o: any, pp: any, opts?: any) => { unrelates.push(o.id); return target.unrelate(s, r, o, pp, opts) }
        const value = Reflect.get(target, prop, receiver)
        return typeof value === 'function' ? value.bind(target) : value
      },
    }) as RelationsDriver
    const real = await reconcileRelations({ from, to: spied, partition, prune: true })
    assert.deepInclude(real.details![0], { side: 'destino', reason: 'invalid-identity', pruned: false }, 'nadie la borra: se dice, no se lanza')
    assert.deepEqual(unrelates, [], 'N3: la pasada no se la pide al driver (hasta el cierre 2 se la pedía y él la rechazaba)')
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

/* ── 🟠 N9 (cierre 3 del lote B) · la fila del DESTINO cuya relación (o tipo) el destino YA NO declara ───────────── */

/**
 * **🟠 N9 del repaso final del auditor (`loteB-auditor-cierre2.md`), preexistente desde L-0/lote A**: una config de la
 * que se RETIRÓ una relación (`document#publisher`) mientras quedan filas suyas en el destino. `#enumerateRows` filtra
 * por TIPO (no por relación), el plan solo juzgaba gramática y forma del userset, así que la fila entraba en `toDelete`;
 * `unrelate` corre F-05 en su primera línea ⇒ 422 `E_AUTHZ_RELATION_UNKNOWN` DESPUÉS de escribir W y borrar X; el
 * cierre 2 había quitado el catch («todo lo de `toDelete` pasó la gramática») ⇒ stack crudo, destino a medias, dry ≠
 * real y `--prune` inutilizable para esa partición para siempre. Decisión del coordinador (2026-10-15, cierre 3): **la
 * poda NUNCA lanza por un 422 de la familia de relaciones**, en DOS capas — (1) con `toConfig` el plan aplica F-05 del
 * destino a la fila (`classifyDestinationRow`) ⇒ `extra` + `details` (`reason: 'undeclared'`, `pruned: false`), jamás
 * `toDelete`; (2) sin `toConfig` (API directa) o si el driver contradice al plan, el bucle de poda captura SOLO los 422
 * de la familia (tipo/relación no declarados, userset no admitido, identidad inválida), los clasifica por `code`, sigue
 * con las demás filas y los lista con el MISMO prefijo «sobra (<motivo>) destino:». Cualquier otro error se propaga.
 * NO se filtra por relación en `#enumerateRows`: una fila que nadie lista es peor (L8). Repro del auditor
 * (`audb3_repro` A) invertido aquí, con y sin `toConfig`, en `database` (3 motores) y en el doble.
 */
test.group('relaciones · reconcile — 🟠 N9 · relación RETIRADA del destino: la poda nunca lanza por un 422 de la familia', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  const partitionOf = (): ScopeRef => ({ type: 'unit', uuid: uuidv7() })
  const tupleOf = (partition: ScopeRef, over: Partial<{ relation: string; object: RelObject; subject: RelSubject }> = {}) => ({
    subject: { type: 'user', uuid: uuidv7() } as RelSubject,
    relation: 'viewer',
    object: { type: 'document', id: uuidv7() } as RelObject,
    partition,
    expiresAt: null,
    ...over,
  })
  /** Fila sembrada por SQL tal como la deja una relación retirada: `publisher` sigue en la tabla, la config ya no la declara. */
  async function seedRow(partition: ScopeRef, over: Record<string, unknown>): Promise<string> {
    const uuid = uuidv7()
    await db.table('authz_relations').insert({
      uuid,
      partition_key: `unit|${partition.uuid}`,
      object_type: 'document',
      object_uuid: uuidv7(),
      relation: 'viewer',
      subject_type: 'user',
      subject_uuid: uuidv7(),
      subject_relation: '',
      subject_partition: null,
      expires_at: null,
      created_at: new Date(),
      ...over,
    })
    return uuid
  }
  const rowsOf = async (partition: ScopeRef): Promise<Array<{ object_uuid: string; relation: string }>> =>
    (await db.from('authz_relations').where('partition_key', `unit|${partition.uuid}`).select('object_uuid', 'relation')).map((r: any) => ({ object_uuid: String(r.object_uuid), relation: String(r.relation) }))
  /** Un origen falso que enumera lo que se le da. */
  const sourceOf = (tuples: any[]): RelationsDriver => ({ capabilities: { enumerateRelations: true }, enumerateRelations: async () => ({ tuples }), relate: async () => {}, unrelate: async () => {} } as any)
  /** Espía de `unrelate` sobre el driver REAL (Proxy: `DatabaseRelationsDriver` es una clase). */
  function spied(dest: DatabaseRelationsDriver): { driver: RelationsDriver; asked: string[] } {
    const asked: string[] = []
    const driver = new Proxy(dest, {
      get(target, prop, receiver) {
        if (prop === 'unrelate') return async (s: any, r: string, o: any, pp: any, opts?: any) => { asked.push(`${o.type}:${o.id}#${r}`); return target.unrelate(s, r, o, pp, opts) }
        const value = Reflect.get(target, prop, receiver)
        return typeof value === 'function' ? value.bind(target) : value
      },
    }) as RelationsDriver
    return { driver, asked }
  }
  /** El escenario del auditor: destino `database` con X (sobra) y `publisher` (retirada); origen con W (nueva). */
  async function scenario() {
    const p = partitionOf()
    const dest = new DatabaseRelationsDriver(reconcileConfig())
    const x = tupleOf(p)
    await dest.relate(x.subject, 'viewer', x.object, p, { expiresAt: null })
    await seedRow(p, { relation: 'publisher' })
    const w = tupleOf(p)
    return { p, dest, x, w, source: sourceOf([w]) }
  }

  test('🟠 N9 · CON toConfig (capa 1, el plan): dry/real/dry2 con --prune ⇒ la fila `publisher` es extra 1 + details destino/undeclared con pruned: false, NUNCA se le pide al driver, W se escribe, X se borra, `publisher` sigue, SIN throw; dry = real = dry2; sin --prune también se lista (pruned ausente)', async ({ assert }) => {
    const { p, dest, x, w, source } = await scenario()
    const toConfig = reconcileConfig()
    const { driver, asked } = spied(dest)
    const dry = await reconcileRelations({ from: source, to: driver, partition: p, prune: true, dryRun: true, toConfig })
    assert.deepInclude(dry, { written: 1, deleted: 1, extra: 1, unchanged: 0 }, `ROJO (N9) dry: ${JSON.stringify(dry)}`)
    assert.lengthOf(dry.details ?? [], 1, 'ROJO (N9) dry: la fila de la relación retirada no se lista')
    assert.deepInclude(dry.details![0], { side: 'destino', reason: 'undeclared', pruned: false })
    assert.match(dry.details![0].message, /'publisher' no está declarada/, 'el porqué es el de F-05 (la misma función que el driver)')
    assert.include(dry.details![0].tuple, '#publisher@user:')
    const real = await reconcileRelations({ from: source, to: driver, partition: p, prune: true, toConfig }).then((r) => r, (e) => e)
    assert.notInstanceOf(real, Error, `ROJO (N9): la pasada real LANZÓ ${real?.code} ${real?.message}`)
    assert.deepInclude(real, { written: 1, deleted: 1, extra: 1 }, `real: ${JSON.stringify(real)}`)
    assert.deepInclude(real.details![0], { side: 'destino', reason: 'undeclared', pruned: false })
    assert.deepEqual(asked.filter((a) => a.endsWith('#publisher')), [], 'ROJO (N9): se le pidió al driver la fila que su F-05 rechaza')
    assert.lengthOf(asked, 1, 'solo X se le pidió')
    const rows = await rowsOf(p)
    assert.sameDeepMembers(rows, [{ object_uuid: w.object.id, relation: 'viewer' }, ...rows.filter((r) => r.relation === 'publisher')], 'W escrita, X borrada')
    assert.lengthOf(rows.filter((r) => r.relation === 'publisher'), 1, 'la retirada sigue (a mano o re-declarar)')
    assert.isTrue(await dest.check(w.subject, 'viewer', w.object, p))
    assert.isFalse(await dest.check(x.subject, 'viewer', x.object, p))
    const dry2 = await reconcileRelations({ from: source, to: driver, partition: p, prune: true, dryRun: true, toConfig })
    assert.deepInclude(dry2, { written: 0, deleted: 0, extra: 1, unchanged: 1 }, `dry2: ${JSON.stringify(dry2)}`)
    assert.deepInclude(dry2.details![0], { side: 'destino', reason: 'undeclared', pruned: false })
    for (const [label, report] of [['dry', dry], ['real', real], ['dry2', dry2]] as const) {
      const { lines, clean } = relationsReconcileLines(report)
      assert.isFalse(clean, `${label}: deriva (exit ≠ 0)`)
      const line = lines.find((l) => /\(undeclared\) destino/.test(l.message))
      assert.equal(line?.level, 'error', `${label}: la línea`)
      assert.match(line!.message, /^sobra \(undeclared\) destino: .*#publisher@/, `${label}: prefijo estable`)
      assert.match(line!.message, /--prune NO la borra/, label)
      assert.match(line!.message, /vuelve a declarar/, `${label}: la receta`)
      assert.isTrue(lines.every((l) => !/repite con --prune/.test(l.message)), label)
    }
    // Sin --prune: se lista igual (deriva en los cuatro modos), `pruned` ausente, «tampoco la borraría».
    const noPrune = await reconcileRelations({ from: source, to: driver, partition: p, dryRun: true, toConfig })
    assert.deepInclude(noPrune, { extra: 1, deleted: 0 })
    assert.deepInclude(noPrune.details![0], { side: 'destino', reason: 'undeclared' })
    assert.isUndefined(noPrune.details![0].pruned)
    assert.match(relationsReconcileLines(noPrune).lines.find((l) => /\(undeclared\) destino/.test(l.message))!.message, /tampoco la borraría/)
  })

  test('🟠 N9 · SIN toConfig (capa 2, la captura por código): --dry-run no puede anticiparla (límite declarado, como L-0 con `written`) y la cuenta en deleted; la pasada REAL captura el 422 del driver, la clasifica (destino/undeclared, pruned: false), sigue con las demás filas (W escrita, X borrada), NO lanza y es repetible', async ({ assert }) => {
    const { p, dest, x, w, source } = await scenario()
    const { driver, asked } = spied(dest)
    const dry = await reconcileRelations({ from: source, to: driver, partition: p, prune: true, dryRun: true })
    assert.deepInclude(dry, { written: 1, deleted: 2, extra: 0 }, `dry sin toConfig (límite): ${JSON.stringify(dry)}`)
    assert.deepEqual(dry.details, [])
    const real = await reconcileRelations({ from: source, to: driver, partition: p, prune: true }).then((r) => r, (e) => e)
    assert.notInstanceOf(real, Error, `ROJO (N9): la pasada real LANZÓ ${real?.code} ${real?.message} (destino a medias)`)
    assert.deepInclude(real, { written: 1, deleted: 1, extra: 1 }, `real: ${JSON.stringify(real)}`)
    assert.lengthOf(real.details ?? [], 1)
    assert.deepInclude(real.details![0], { side: 'destino', reason: 'undeclared', pruned: false })
    assert.match(real.details![0].message, /'publisher' no está declarada/, 'el porqué: el mensaje del 422 del driver')
    assert.include(real.details![0].tuple, '#publisher@user:')
    assert.lengthOf(asked, 2, 'se le pidieron X y publisher; el driver dijo 422 de la segunda y la pasada siguió')
    const rows = await rowsOf(p)
    assert.isTrue(rows.some((r) => r.object_uuid === w.object.id), 'W escrita')
    assert.isFalse(rows.some((r) => r.object_uuid === x.object.id), 'X borrada (la poda siguió tras el 422)')
    assert.lengthOf(rows.filter((r) => r.relation === 'publisher'), 1, 'la retirada sigue')
    const { lines, clean } = relationsReconcileLines(real)
    assert.isFalse(clean)
    const line = lines.find((l) => /\(undeclared\) destino/.test(l.message))
    assert.match(line!.message, /^sobra \(undeclared\) destino: .*#publisher@.*--prune NO la borra/, 'prefijo estable, misma rama que con toConfig')
    assert.isTrue(lines.every((l) => !/repite con --prune/.test(l.message)))
    // Repetible: la pasada siguiente clasifica igual y no lanza (hasta el cierre: el mismo throw para siempre).
    const again = await reconcileRelations({ from: source, to: driver, partition: p, prune: true }).then((r) => r, (e) => e)
    assert.notInstanceOf(again, Error, 'ROJO (N9): --prune inutilizable para esa partición')
    assert.deepInclude(again, { written: 0, deleted: 0, extra: 1, unchanged: 1 })
    assert.deepInclude(again.details![0], { side: 'destino', reason: 'undeclared', pruned: false })
  })

  /**
   * El doble (un driver de TERCEROS con la forma del paquete): enumera filas que su `unrelate` rechaza con los cuatro
   * 422 de la familia. Capa 2 los clasifica por `code` (`reason` derivado del código) y sigue; y los que NO son de la
   * familia —otro 422 (`E_AUTHZ_INVALID_SLUG`), un 503, un `Error` a secas— se PROPAGAN: eso sí es el driver
   * contradiciendo al plan por una causa que la pasada no sabe contar.
   */
  function refusingDestination(tuples: any[], refuse: (tuple: { relation: string; object: RelObject; subject: RelSubject }) => Error | null) {
    const deleted: string[] = []
    const driver: any = {
      capabilities: { enumerateRelations: true },
      enumerateRelations: async () => ({ tuples }),
      relate: async () => {},
      unrelate: async (subject: any, relation: string, object: any) => {
        const error = refuse({ subject, relation, object })
        if (error) throw error
        deleted.push(`${object.type}:${object.id}#${relation}`)
      },
    }
    return { driver: driver as RelationsDriver, deleted }
  }

  test('🟠 N9 · doble de terceros SIN toConfig: los CUATRO 422 de la familia (tipo, relación, userset, identidad) se capturan y clasifican por code, la poda sigue (la buena sobrante se borra), cada uno con su línea; otro 422 (E_AUTHZ_INVALID_SLUG), un 503 y un Error a secas se PROPAGAN', async ({ assert }) => {
    const p = partitionOf()
    const good = tupleOf(p)
    const stray = tupleOf(p)
    const retiredRelation = tupleOf(p, { relation: 'publisher' })
    const retiredType = tupleOf(p, { object: { type: 'folder', id: uuidv7() } })
    // El driver dice «userset no admitido» / «identidad inválida» de filas que el plan dio por buenas (contradice al plan): se clasifican igual.
    const saysUserset = tupleOf(p)
    const saysIdentity = tupleOf(p)
    const family: Record<string, () => Error> = {
      [`${retiredRelation.object.id}`]: () => new RelationUnknownError("La relación 'publisher' no está declarada para el tipo 'document' en defineRelationsConfig (F-05)."),
      [`${retiredType.object.id}`]: () => new RelationTypeUnknownError("El tipo de objeto 'folder' no está declarado en defineRelationsConfig (F-05)."),
      [`${saysUserset.object.id}`]: () => new RelationUsersetUnsupportedError('El userset no vale como SUJETO (B3)'),
      [`${saysIdentity.object.id}`]: () => new InvalidIdentityError('identidad inválida según el driver'),
    }
    const to = refusingDestination([good, stray, retiredRelation, retiredType, saysUserset, saysIdentity], (t) => family[t.object.id]?.() ?? null)
    const report = await reconcileRelations({ from: sourceOf([good]), to: to.driver, partition: p, prune: true }).then((r) => r, (e) => e)
    assert.notInstanceOf(report, Error, `ROJO (N9): lanzó ${report?.code}`)
    assert.deepInclude(report, { unchanged: 1, deleted: 1, extra: 4 }, JSON.stringify(report))
    assert.deepEqual(to.deleted, [`document:${stray.object.id}#viewer`], 'la poda siguió: la sobrante buena se borró')
    const byTuple = new Map<string, any>((report.details ?? []).map((d: any) => [d.tuple, d]))
    const expect = (t: any, reason: string, message: RegExp) => {
      const d = byTuple.get(`unit|${p.uuid} ${t.object.type}:${t.object.id}#${t.relation}@user:${t.subject.uuid}`)
      assert.isDefined(d, `${reason}: listada`)
      assert.deepInclude(d!, { side: 'destino', reason, pruned: false })
      assert.match(d!.message, message, reason)
    }
    expect(retiredRelation, 'undeclared', /'publisher' no está declarada/)
    expect(retiredType, 'undeclared', /'folder' no está declarado/)
    expect(saysUserset, 'userset-unsupported', /B3/)
    expect(saysIdentity, 'invalid-identity', /identidad inválida/)
    const { lines, clean } = relationsReconcileLines(report)
    assert.isFalse(clean)
    for (const reason of ['undeclared', 'userset-unsupported', 'invalid-identity']) {
      assert.isTrue(lines.some((l) => l.level === 'error' && new RegExp(`^sobra \\(${reason}\\) destino: `).test(l.message)), `${reason}: la línea con el prefijo estable`)
    }
    assert.lengthOf(lines.filter((l) => /^sobra \(undeclared\) destino: /.test(l.message)), 2)
    assert.isTrue(lines.every((l) => !/repite con --prune/.test(l.message)))
    // Lo que NO es de la familia se propaga (el plan no sabe contarlo): otro 422, un 503, un Error.
    for (const [label, make] of [
      ['otro 422 (E_AUTHZ_INVALID_SLUG)', () => new InvalidSlugError('slug')],
      ['503', () => new AuthorizationBackendError('fake', 'unrelate', new Error('boom'))],
      ['Error a secas', () => new Error('boom')],
      // ⚪ N13 (repaso del cierre 3): un 422 cuyo `code` es una clave del PROTOTIPO de la tabla no es de la familia.
      ['422 con code `constructor` (prototipo)', () => Object.assign(new Error('proto-constructor'), { status: 422, code: 'constructor' })],
      ['422 con code `__proto__` (prototipo)', () => Object.assign(new Error('proto-proto'), { status: 422, code: '__proto__' })],
      // ⚪ N15: la mitad `status` de la captura — un code de la familia con status 500 NO se absorbe.
      ['status 500 con code de la familia', () => Object.assign(new Error('familia-500'), { status: 500, code: RelationUnknownError.code })],
    ] as const) {
      const other = refusingDestination([good, stray], () => make())
      const caught = await reconcileRelations({ from: sourceOf([good]), to: other.driver, partition: p, prune: true }).then(() => null, (e) => e)
      assert.isNotNull(caught, `ROJO (N9): ${label} se TRAGÓ — solo la familia de relaciones se clasifica`)
      assert.equal(caught.message, make().message, label)
    }
  })

  /**
   * **Tabla de verdad de N9** (punto 5 (b)): {motivo} × {toConfig sí/no} × {dry, real} ⇒ bucket, details, línea, exit —
   * ejecutada, no transcrita. El destino es un doble con la gramática del paquete (identidad por `relationTupleKey`,
   * forma del userset, F-05 del driver con la config SIN `publisher` ni `folder`) y enumera una fila buena + la del
   * motivo. `invalid-identity` y `userset-unsupported` se clasifican en el plan con o sin `toConfig` (N3/N2);
   * `undeclared` (tipo o relación) lo clasifica el plan CON `toConfig` (capa 1) y, SIN ella, la captura del 422 en la
   * pasada real (capa 2) — en `--dry-run` sin `toConfig` cuenta en `deleted` (límite declarado: sin config el plan no
   * puede anticipar F-05, igual que L-0 con `written`). Las filas de la tabla del informe son ESTAS.
   */
  test('🟠 N9 · tabla de verdad {invalid-identity, userset-unsupported, undeclared(type), undeclared(relation)} × {toConfig sí/no} × {dry, real} ⇒ bucket, details, línea, exit', async ({ assert }) => {
    const p = partitionOf()
    const driverConfig = reconcileConfig()
    const rowsOfReason: Record<string, any> = {
      'invalid-identity': tupleOf(p, { object: { type: 'document', id: 'ABC' } }),
      'userset-unsupported': tupleOf(p, { subject: { object: { type: 'document', id: uuidv7() }, relation: 'viewer' } as any }),
      'undeclared(type)': tupleOf(p, { object: { type: 'folder', id: uuidv7() } }),
      'undeclared(relation)': tupleOf(p, { relation: 'publisher' }),
      // La FORMA antes que F-05 también en el destino (N2 extendido): un userset ≠ group#member sobre una relación
      // retirada es `userset-unsupported` (con receta), nunca `undeclared`. Mutante «F-05 del destino antes que la forma» ⇒ rojo.
      'userset-unsupported+undeclared(relation)': tupleOf(p, { relation: 'publisher', subject: { object: { type: 'document', id: uuidv7() }, relation: 'viewer' } as any }),
    }
    /** El `unrelate` del paquete, en miniatura: identidad, forma del userset y F-05 — los tres 422 de la familia. */
    const packageLikeUnrelate = (subject: any, relation: string, object: RelObject) => {
      relationTupleKey({ subject, relation, object, partition: p, kind: 'allow' })
      if (subject && 'object' in subject) assertSupportedUserset(subject)
      assertRelationDeclared(driverConfig, object, relation)
    }
    const expected: Record<string, { bucketDry: string; bucketReal: string; details: string; line: string; exit: number }> = {
      // motivo|toConfig ⇒ lo mismo en dry y real salvo `undeclared` sin toConfig.
      'invalid-identity|sí': { bucketDry: 'extra', bucketReal: 'extra', details: 'destino/invalid-identity/pruned:false', line: 'sobra (invalid-identity) destino:', exit: 1 },
      'invalid-identity|no': { bucketDry: 'extra', bucketReal: 'extra', details: 'destino/invalid-identity/pruned:false', line: 'sobra (invalid-identity) destino:', exit: 1 },
      'userset-unsupported|sí': { bucketDry: 'extra', bucketReal: 'extra', details: 'destino/userset-unsupported/pruned:false', line: 'sobra (userset-unsupported) destino:', exit: 1 },
      'userset-unsupported|no': { bucketDry: 'extra', bucketReal: 'extra', details: 'destino/userset-unsupported/pruned:false', line: 'sobra (userset-unsupported) destino:', exit: 1 },
      'undeclared(type)|sí': { bucketDry: 'extra', bucketReal: 'extra', details: 'destino/undeclared/pruned:false', line: 'sobra (undeclared) destino:', exit: 1 },
      'undeclared(type)|no': { bucketDry: 'deleted', bucketReal: 'extra', details: 'destino/undeclared/pruned:false', line: 'sobra (undeclared) destino:', exit: 1 },
      'undeclared(relation)|sí': { bucketDry: 'extra', bucketReal: 'extra', details: 'destino/undeclared/pruned:false', line: 'sobra (undeclared) destino:', exit: 1 },
      'undeclared(relation)|no': { bucketDry: 'deleted', bucketReal: 'extra', details: 'destino/undeclared/pruned:false', line: 'sobra (undeclared) destino:', exit: 1 },
      'userset-unsupported+undeclared(relation)|sí': { bucketDry: 'extra', bucketReal: 'extra', details: 'destino/userset-unsupported/pruned:false', line: 'sobra (userset-unsupported) destino:', exit: 1 },
      'userset-unsupported+undeclared(relation)|no': { bucketDry: 'extra', bucketReal: 'extra', details: 'destino/userset-unsupported/pruned:false', line: 'sobra (userset-unsupported) destino:', exit: 1 },
    }
    const table: string[] = []
    for (const [reason, row] of Object.entries(rowsOfReason)) {
      for (const [withConfig, toConfig] of [['sí', driverConfig], ['no', undefined]] as const) {
        for (const dryRun of [true, false]) {
          const good = tupleOf(p)
          const to = refusingDestination([good, row], (t) => { try { packageLikeUnrelate(t.subject, t.relation, t.object); return null } catch (e) { return e as Error } })
          const report = await reconcileRelations({ from: sourceOf([good]), to: to.driver, partition: p, prune: true, dryRun, toConfig }).then((r) => r, (e) => e)
          const key = `${reason}|${withConfig}`
          const label = `${key} ${dryRun ? 'dry' : 'real'}`
          assert.notInstanceOf(report, Error, `ROJO (N9) ${label}: lanzó ${report?.code} ${report?.message}`)
          const want = expected[key]
          const bucket = report.extra === 1 && report.deleted === 0 ? 'extra' : report.deleted === 1 && report.extra === 0 ? 'deleted' : `?(extra ${report.extra}, deleted ${report.deleted})`
          const detail = report.details?.[0]
          const details = detail ? `${detail.side}/${detail.reason}/pruned:${detail.pruned}` : '—'
          const { lines, clean } = relationsReconcileLines(report)
          const line = lines.find((l) => /^sobra \(/.test(l.message))?.message.match(/^sobra \([a-z-]+\) destino:/)?.[0] ?? '—'
          const exit = clean ? 0 : 1
          table.push(`| ${reason} | ${withConfig} | ${dryRun ? 'dry' : 'real'} | ${bucket} | ${details} | ${line} | ${exit} |`)
          assert.equal(bucket, dryRun ? want.bucketDry : want.bucketReal, `${label}: bucket`)
          assert.equal(details, dryRun && want.bucketDry === 'deleted' ? '—' : want.details, `${label}: details`)
          assert.equal(line, dryRun && want.bucketDry === 'deleted' ? '—' : want.line, `${label}: línea`)
          assert.equal(exit, want.exit, `${label}: exit (dry con algo que haría es deriva; real con residuo es deriva)`)
          assert.deepEqual(to.deleted, [], `${label}: la fila del motivo nunca se borró`)
          assert.equal(report.unchanged, 1, label)
        }
      }
    }
    // La tabla ejecutada, para el informe (scratchpad): `AUTHZ_N9_TABLE` la vuelca.
    if (process.env.AUTHZ_N9_TABLE) console.log(['| motivo | toConfig | pasada | bucket | details | línea | exit |', '|---|---|---|---|---|---|---|', ...table].join('\n'))
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

if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl
  const denyConfig = contractDenyRelationsConfig()
  const newStore = async (objectTypes: RelationsConfig['objectTypes']) => {
    const { OpenFgaClient } = await import('@openfga/sdk')
    const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `reconcile-deny-${Date.now()}-${uuidv7().slice(0, 8)}` })
    const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(openFgaFactsModel(HOLDER_MAP, [], { objectTypes }))
    openFgaStores.push(store.id!)
    return { storeId: store.id!, modelId: model.authorization_model_id! }
  }

  // Lote D · D2 · T3 contra el servidor real, en las DOS direcciones, con el censo por listDenies.
  runRelationsReconcileContract({
    name: 'database ↔ openfga · deny',
    config: denyConfig,
    denies: true,
    clean: async () => {
      await db.from('authz_relations').delete()
    },
    makeA: () => new DatabaseRelationsDriver(denyConfig),
    makeB: async () => {
      const { storeId, modelId } = await newStore(denyConfig.objectTypes)
      return new OpenFgaRelationsDriver(denyConfig, { apiUrl, storeId, modelId, holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
    },
  })

  test.group('relaciones · reconcile — D2 · la puerta del deny contra el modelo FIJADO del destino (D-31, R2-5)', (group) => {
    group.each.setup(async () => {
      await db.from('authz_relations').delete()
    })
    test("destino openfga con el tipo en 'write' pero pineado a un modelo SIN denied_* ⇒ 500 motivo model con CERO escrituras; --dry-run lo marca", async ({ assert }) => {
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const u: RelSubject = { type: 'user', uuid: uuidv7() }
      const d: RelObject = { type: 'document', id: uuidv7() }
      const from = new DatabaseRelationsDriver(denyConfig)
      await from.relate(u, 'viewer', d, p)
      await from.deny(u, 'viewer', d, p)
      // El modelo publicado SIN deny (la config vieja), el pod con la config NUEVA (S11/D-31).
      const { storeId, modelId } = await newStore(reconcileConfig().objectTypes)
      const to = new OpenFgaRelationsDriver(denyConfig, { apiUrl, storeId, modelId, holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
      const error = await reconcileRelations({ from, to, partition: p }).then(
        () => null,
        (e) => e
      )
      assert.equal(error?.code, 'E_AUTHZ_DENY_MIGRATION_REFUSED', String(error?.message))
      assert.deepEqual(error?.refusals?.map((r: any) => r.reason), ['model'])
      assert.include(String(error?.message), 'denied_viewer')
      const { OpenFgaClient } = await import('@openfga/sdk')
      const tuples = await new OpenFgaClient({ apiUrl, storeId }).read({})
      assert.lengthOf(tuples.tuples, 0, 'CERO escrituras en el store: ni el deny ni el allow')
      const dry = await reconcileRelations({ from, to, partition: p, dryRun: true })
      assert.deepEqual(dry.denyRefused?.map((r) => r.reason), ['model'])
      assert.isFalse(relationsReconcileLines(dry).clean)
    })
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
