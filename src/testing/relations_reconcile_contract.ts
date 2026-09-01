/**
 * **El contrato de `authz:reconcile` de relaciones** (Fase 4, lote 4-5),
 * publicado en `@jantstack/adonis-authz/testing` — un driver de TERCEROS que
 * quiera migrar sus tuplas tiene que poder correrlo.
 *
 *   import { runRelationsReconcileContract } from '@jantstack/adonis-authz/testing'
 *
 * Corta por donde el 3b-4·C1 enseñó que hay que cortar: **el CENSO**. No basta
 * cruzar `report.skipped` ni los contadores; el contrato busca CADA hecho
 * sembrado en el destino UNO A UNO por el camino DIRECTO (`listSubjects`), no
 * le pregunta al origen lleno. Así un tramo omisivo (un driver que no migra los
 * usersets), una pérdida de `subject_relation` (un userset migrado como holder)
 * o una pérdida de partición se ven ROJAS —la lección M1/M3/T4—.
 *
 * La siembra FIJA cubre las cuatro formas que la migración puede perder:
 *  - holders directos (`viewer`, `owner`),
 *  - includes (`editor` ⊆ `viewer`) — el hecho DIRECTO es `editor`, no `viewer`,
 *  - un userset directo (`group#member` como `viewer`),
 *  - un userset ANIDADO (`g1#member` como `member` de `g2`) — el que pierde su
 *    `subject_relation` un driver descuidado,
 *  - y, desde R-15, **la caducidad**: un hecho VIGENTE con `expiresAt` tiene
 *    que llegar al destino con el MISMO instante (perderla es fail-OPEN: una
 *    compartición temporal se vuelve permanente), y un hecho CADUCADO tiene que
 *    LLEGAR enumerado del origen para contarse en `skipped.expired` — no
 *    desaparecer sin rastro (la lección de la 3b).
 */
import { v7 as uuidv7 } from 'uuid'
import { test as japaTest } from '@japa/runner'
import type { Assert } from '@japa/assert'
import { reconcileRelations } from '../relations/reconcile.js'
import { sameInstant } from '../expiry.js'
import { isRelUserset } from '../types.js'
import type { RelObject, RelSubject, RelationsDriver, ScopeRef } from '../types.js'
import type { RelationsConfig } from '../relations/define_relations_config.js'
import type { ContractTestApi } from './contract.js'

export interface RelationsReconcileHarness {
  name: string
  /** La config del contrato (un `document` con owner ⊆ editor ⊆ viewer). */
  config: RelationsConfig
  /** Construye el driver A (backend PROPIO, limpio). */
  makeA(config: RelationsConfig): RelationsDriver | Promise<RelationsDriver>
  /** Construye el driver B (backend PROPIO, distinto de A, limpio). */
  makeB(config: RelationsConfig): RelationsDriver | Promise<RelationsDriver>
  /** Limpia ambos backends antes de cada caso. */
  clean?(): Promise<void>
}

function subjectKey(subject: RelSubject): string {
  if (isRelUserset(subject)) return `${subject.object.type}:${subject.object.id}#${subject.relation}`
  return `${subject.type}:${subject.uuid}`
}

interface Seed {
  partition: ScopeRef
  u1: RelSubject
  u2: RelSubject
  u3: RelSubject
  u4: RelSubject
  g1: RelObject
  g2: RelObject
  doc1: RelObject
  doc2: RelObject
  /** Los hechos DIRECTOS sembrados, con los que se hace el censo. */
  facts: Array<{ relation: string; object: RelObject; subject: RelSubject; label: string }>
  /** R-15: un hecho VIGENTE con caducidad (dentro de un año) y uno CADUCADO (hace una hora). */
  timeBoxed: { relation: string; object: RelObject; subject: RelSubject; expiresAt: Date }
  expired: { relation: string; object: RelObject; subject: RelSubject; expiresAt: Date }
}

function makeSeed(): Seed {
  const u1: RelSubject = { type: 'user', uuid: uuidv7() }
  const u2: RelSubject = { type: 'user', uuid: uuidv7() }
  const u3: RelSubject = { type: 'user', uuid: uuidv7() }
  const u4: RelSubject = { type: 'admin', uuid: uuidv7() }
  const g1: RelObject = { type: 'group', id: uuidv7() }
  const g2: RelObject = { type: 'group', id: uuidv7() }
  const doc1: RelObject = { type: 'document', id: uuidv7() }
  const doc2: RelObject = { type: 'document', id: uuidv7() }
  return {
    partition: { type: 'unit', uuid: uuidv7() },
    u1, u2, u3, u4, g1, g2, doc1, doc2,
    facts: [
      { relation: 'viewer', object: doc1, subject: u1, label: 'holder viewer directo' },
      { relation: 'editor', object: doc1, subject: u2, label: 'holder editor (includes viewer)' },
      { relation: 'member', object: g1, subject: u3, label: 'holder member de g1' },
      { relation: 'member', object: g2, subject: { object: g1, relation: 'member' }, label: 'userset ANIDADO g1#member de g2' },
      { relation: 'viewer', object: doc2, subject: { object: g2, relation: 'member' }, label: 'userset g2#member como viewer' },
      { relation: 'owner', object: doc2, subject: u4, label: 'holder owner (admin)' },
    ],
    // Instantes relativos a hoy (2.5-B · K7): el juez no adelanta ningún reloj.
    timeBoxed: {
      relation: 'viewer',
      object: doc2,
      subject: u2,
      expiresAt: new Date(Date.now() + 365 * 24 * 3_600_000 + 789),
    },
    expired: { relation: 'editor', object: doc2, subject: u3, expiresAt: new Date(Date.now() - 3_600_000) },
  }
}

/** Siembra los hechos FIJOS en un driver. */
async function plant(driver: RelationsDriver, seed: Seed): Promise<void> {
  for (const fact of seed.facts) {
    await driver.relate(fact.subject, fact.relation, fact.object, seed.partition)
  }
}

/**
 * **El CENSO**: cada hecho sembrado tiene que estar en el destino, buscado UNO
 * A UNO por `listSubjects` DIRECTO (invariante 7). Un hecho ausente o con el
 * sujeto cambiado (userset → holder) falla aquí, no en los contadores.
 */
async function census(assert: Assert, driver: RelationsDriver, seed: Seed): Promise<void> {
  for (const fact of seed.facts) {
    const page = await driver.listSubjects(fact.relation, fact.object, seed.partition)
    const wanted = subjectKey(fact.subject)
    const found = page.subjects.some((s) => subjectKey(s) === wanted)
    assert.isTrue(
      found,
      `CENSO: falta el hecho '${fact.label}' en el destino ` +
        `(${fact.object.type}:${fact.object.id}#${fact.relation}@${wanted}); ` +
        `listSubjects devolvió [${page.subjects.map(subjectKey).join(', ') || 'vacío'}]`
    )
  }
}

export function runRelationsReconcileContract(harness: RelationsReconcileHarness) {
  return registerRelationsReconcileContract(harness, {
    group: (title, define) => japaTest.group(title, define as any),
    test: (title, fn) => japaTest(title, fn as any),
  })
}

export function registerRelationsReconcileContract(
  harness: RelationsReconcileHarness,
  api: { group: ContractTestApi['group']; test: ContractTestApi['test'] }
): { registered: number } {
  let registered = 0

  // Las dos direcciones (A→B y B→A): la migración es BIDIRECCIONAL, y el censo
  // vale igual en las dos (el origen se siembra, el destino se censa).
  const directions: Array<{ label: string; source: 'A' | 'B' }> = [
    { label: 'A→B', source: 'A' },
    { label: 'B→A', source: 'B' },
  ]

  api.group(`relations reconcile [${harness.name}]`, (group) => {
    let a: RelationsDriver
    let b: RelationsDriver
    group.each.setup(async () => {
      if (harness.clean) await harness.clean()
      a = await harness.makeA(harness.config)
      b = await harness.makeB(harness.config)
    })

    const test = (title: string, fn: (ctx: { assert: Assert }) => Promise<void>) => {
      registered++
      api.test(title, fn)
    }

    for (const dir of directions) {
      const from = () => (dir.source === 'A' ? a : b)
      const to = () => (dir.source === 'A' ? b : a)

      test(`${dir.label} · migra los 6 hechos y el CENSO los ve todos en el destino`, async ({ assert }) => {
        const seed = makeSeed()
        await plant(from(), seed)
        const report = await reconcileRelations({ from: from(), to: to(), partition: seed.partition, toConfig: harness.config })
        assert.equal(report.written, seed.facts.length, `escribe los ${seed.facts.length} hechos`)
        assert.equal(report.unchanged, 0)
        assert.equal(report.extra, 0)
        await census(assert, to(), seed)
      })

      test(`${dir.label} · idempotente: una segunda pasada no escribe nada`, async ({ assert }) => {
        const seed = makeSeed()
        await plant(from(), seed)
        await reconcileRelations({ from: from(), to: to(), partition: seed.partition })
        const again = await reconcileRelations({ from: from(), to: to(), partition: seed.partition })
        assert.equal(again.written, 0, 'la segunda pasada no reescribe')
        assert.equal(again.unchanged, seed.facts.length)
        await census(assert, to(), seed)
      })

      test(`${dir.label} · --prune borra del destino lo que el origen ya no respalda`, async ({ assert }) => {
        const seed = makeSeed()
        await plant(from(), seed)
        // Una tupla EXTRA en el destino que el origen no tiene.
        const orphan: RelObject = { type: 'document', id: uuidv7() }
        await to().relate(seed.u1, 'viewer', orphan, seed.partition)
        const pruned = await reconcileRelations({ from: from(), to: to(), partition: seed.partition, prune: true })
        assert.equal(pruned.deleted, 1, 'borra la tupla huérfana')
        assert.isFalse(await to().check(seed.u1, 'viewer', orphan, seed.partition), 'la huérfana ya no está')
        await census(assert, to(), seed) // y no se llevó ninguno de los buenos
      })

      test(`${dir.label} · R-15 · la caducidad VIAJA: la vigente llega con su instante (y una distinta en el destino se reescribe, updated); la caducada LLEGA enumerada y se cuenta en skipped.expired, no se escribe`, async ({
        assert,
      }) => {
        const seed = makeSeed()
        await plant(from(), seed)
        const { timeBoxed, expired } = seed
        await from().relate(timeBoxed.subject, timeBoxed.relation, timeBoxed.object, seed.partition, { expiresAt: timeBoxed.expiresAt })
        await from().relate(expired.subject, expired.relation, expired.object, seed.partition, { expiresAt: expired.expiresAt })
        // El destino ya tiene el hecho temporal, pero SIN caducidad: si la
        // migración lo dejara así, una compartición temporal sería permanente.
        await to().relate(timeBoxed.subject, timeBoxed.relation, timeBoxed.object, seed.partition)

        // 1 · La caducada LLEGA del origen (enumerada con su expiresAt): no se
        // filtra en el origen, o desaparecería sin rastro.
        const enumerated = (await from().enumerateRelations!(seed.partition)).tuples
        const arrived = enumerated.find(
          (t) => t.relation === expired.relation && t.object.id === expired.object.id && subjectKey(t.subject) === subjectKey(expired.subject)
        )
        assert.isDefined(arrived, 'la tupla CADUCADA tiene que llegar enumerada del origen')
        assert.isTrue(sameInstant(arrived!.expiresAt ?? null, expired.expiresAt), 'con su expiresAt')

        const report = await reconcileRelations({ from: from(), to: to(), partition: seed.partition, toConfig: harness.config })
        // 2 · Se cuenta, no se escribe: los 6 fijos se escriben, la temporal se
        // ACTUALIZA (misma clave, otra caducidad) y la caducada va a skipped.
        assert.equal(report.skipped.expired, 1, 'la caducada se cuenta en skipped.expired')
        assert.equal(report.written, seed.facts.length)
        assert.equal(report.updated, 1, 'la temporal estaba sin caducidad en el destino: se reescribe')
        assert.isFalse(
          await to().check(expired.subject, expired.relation, expired.object, seed.partition),
          'la caducada no concede en el destino'
        )
        const destExpired = (await to().enumerateRelations!(seed.partition)).tuples.some(
          (t) => t.relation === expired.relation && t.object.id === expired.object.id && subjectKey(t.subject) === subjectKey(expired.subject)
        )
        assert.isFalse(destExpired, 'la caducada NO se escribió en el destino')
        // 3 · La vigente llegó con el MISMO instante (censo de la caducidad).
        const landed = (await to().enumerateRelations!(seed.partition)).tuples.find(
          (t) => t.relation === timeBoxed.relation && t.object.id === timeBoxed.object.id && subjectKey(t.subject) === subjectKey(timeBoxed.subject)
        )
        assert.isDefined(landed, 'la temporal está en el destino')
        assert.isTrue(
          sameInstant(landed!.expiresAt ?? null, timeBoxed.expiresAt),
          `la caducidad viajó al milisegundo (destino ${landed!.expiresAt?.toISOString()}, origen ${timeBoxed.expiresAt.toISOString()})`
        )
        await census(assert, to(), seed)
        // 4 · Idempotente también con caducidades: la segunda pasada no toca nada.
        const again = await reconcileRelations({ from: from(), to: to(), partition: seed.partition })
        assert.equal(again.written + again.updated, 0)
        assert.equal(again.skipped.expired, 1)
      })

    test(`${dir.label} · --dry-run no escribe: reporta lo que HARÍA y el destino queda intacto`, async ({ assert }) => {
        const seed = makeSeed()
        await plant(from(), seed)
        const dry = await reconcileRelations({ from: from(), to: to(), partition: seed.partition, dryRun: true, toConfig: harness.config })
        assert.isTrue(dry.dryRun)
        assert.equal(dry.written, seed.facts.length, 'reporta que escribiría los 6')
        assert.deepEqual(dry.modelDrift, [], 'ningún tipo del origen falta en la config del destino')
        // Cero escrituras: el censo del destino falla (nada llegó).
        const first = await to().listSubjects(seed.facts[0].relation, seed.facts[0].object, seed.partition)
        assert.lengthOf(first.subjects, 0, 'dry-run no tocó el destino')
      })
    }

    // El puerto exige `enumerateRelations` en ambos: un driver que no lo trae
    // no puede ser origen ni destino (500, jamás una migración a ciegas).
    test('un driver sin `enumerateRelations` ⇒ 500 E_AUTHZ_UNSUPPORTED como origen', async ({ assert }) => {
      const blind: RelationsDriver = {
        capabilities: { ...(a.capabilities as any), enumerateRelations: false },
        relate: a.relate.bind(a),
        unrelate: a.unrelate.bind(a),
        check: a.check.bind(a),
        listObjects: a.listObjects.bind(a),
        listSubjects: a.listSubjects.bind(a),
        purgeObject: a.purgeObject.bind(a),
        purgeSubject: a.purgeSubject.bind(a),
      }
      let caught: any
      try {
        await reconcileRelations({ from: blind, to: b, partition: { type: 'unit', uuid: uuidv7() } })
        assert.fail('debería haber lanzado')
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 500)
      assert.equal(caught.code, 'E_AUTHZ_UNSUPPORTED')
    })
  })

  return { registered }
}
