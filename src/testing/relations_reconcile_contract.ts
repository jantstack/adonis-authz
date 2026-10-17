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
  /**
   * **La cara del DENY** (plan 2.5 · lote D · D2; tester T3 / D-27): los dos drivers declaran `relationDenies: true` y
   * `config` tiene al menos un tipo en `deny: 'write'`. Registra, por dirección, (a) «el deny viaja como deny» —con
   * `kind`, ANTES que los allows, y el CENSO lo busca por `listDenies`; `check` del destino niega— y (b) «la poda de un
   * deny sobrante es `removeDeny`, después de los allows», más un negativo global (S6: destino sin `relationDenies` ⇒
   * 500 `E_AUTHZ_DENY_MIGRATION_REFUSED` con CERO escrituras). Un driver de terceros que declare `relationDenies` y no
   * marque `kind` en `enumerateRelations` NO pasa (a): la pasada se niega con el motivo `unmarked`.
   */
  denies?: boolean
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

    if (harness.denies === true) {
      const denyType = harness.config.objectTypes.find((t) => t.deny === 'write')?.type
      if (!denyType) throw new Error(`runRelationsReconcileContract [${harness.name}]: denies: true exige un tipo con deny: 'write' en config`)
      const writesOf = (driver: RelationsDriver) => {
        const log: string[] = []
        const proxy = new Proxy(driver as any, {
          get(target, prop) {
            const value = Reflect.get(target, prop, target)
            if (typeof prop === 'string' && ['relate', 'unrelate', 'deny', 'removeDeny'].includes(prop) && typeof value === 'function') {
              return async (...args: any[]) => {
                log.push(`${prop} ${args[1]}`)
                return value.apply(target, args)
              }
            }
            return typeof value === 'function' ? value.bind(target) : value
          },
        })
        return { driver: proxy as RelationsDriver, log }
      }
      /**
       * Cierre 3 de D2 (🟠 C2-1 / 🟡 C2-2): un espía que pregunta `check(probe)` tras CADA escritura del destino — los
       * prefijos de la pasada, tal como los ve el PDP del destino.
       */
      const prefixSpy = (driver: RelationsDriver, probe: (d: RelationsDriver) => Promise<boolean>) => {
        const prefixes: string[] = []
        const proxy = new Proxy(driver as any, {
          get(target, prop) {
            const value = Reflect.get(target, prop, target)
            if (typeof prop === 'string' && ['relate', 'unrelate', 'deny', 'removeDeny'].includes(prop) && typeof value === 'function') {
              return async (...args: any[]) => {
                const out = await value.apply(target, args)
                const s = args[0]
                const who = isRelUserset(s) ? `${s.object.id.slice(-4)}#${s.relation}` : `${(s as any).uuid.slice(-4)}`
                prefixes.push(`${prop}(${who} ${args[1]} ${args[2]?.type}:${String(args[2]?.id).slice(-4)}) ⇒ ${await probe(driver)}`)
                return out
              }
            }
            return typeof value === 'function' ? value.bind(target) : value
          },
        })
        return { driver: proxy as RelationsDriver, prefixes }
      }
      const past = () => new Date(Date.now() - 3_600_000)
      for (const dir of directions) {
        const from = () => (dir.source === 'A' ? a : b)
        const to = () => (dir.source === 'A' ? b : a)
        test(`${dir.label} · vigencia · C2-1 · una membresía PORTADORA VENCIDA en el destino y viva en el origen es una escritura normal (jamás renewal-unsafe): ningún prefijo concede, el destino niega o concede según el ORIGEN y la 2.ª pasada tiene el plan vacío`, async ({ assert }) => {
          const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
          const u: RelSubject = { type: 'user', uuid: uuidv7() }
          const h: RelObject = { type: 'group', id: uuidv7() }
          const x: RelObject = { type: denyType, id: uuidv7() }
          const y: RelObject = { type: denyType, id: uuidv7() }
          for (const side of [from(), to()]) {
            await side.deny!({ object: h, relation: 'member' }, 'viewer', x, p)
            await side.relate({ object: h, relation: 'member' }, 'viewer', y, p)
          }
          await from().relate(u, 'member', h, p)
          await from().relate(u, 'viewer', x, p)
          await to().relate(u, 'member', h, p, { expiresAt: past() })
          assert.isFalse(await from().check(u, 'viewer', x, p), 'el origen niega X')
          assert.isTrue(await from().check(u, 'viewer', y, p), 'el origen concede Y')
          assert.isFalse(await to().check(u, 'viewer', x, p), 'el destino niega X al empezar')
          assert.isFalse(await to().check(u, 'viewer', y, p), 'el destino niega Y al empezar (la membresía venció)')
          const dry = await reconcileRelations({ from: from(), to: to(), partition: p, toConfig: harness.config, dryRun: true })
          const spy = prefixSpy(to(), (d) => d.check(u, 'viewer', x, p))
          const report = await reconcileRelations({ from: from(), to: spy.driver, partition: p, toConfig: harness.config })
          for (const r of [dry, report]) {
            assert.deepEqual((r.details ?? []).map((d) => d.reason), [], 'ni renewal-unsafe ni residuo: la vencida es AUSENTE')
            assert.deepEqual({ written: r.written, updated: r.updated }, { written: 2, updated: 0 }, 'la membresía y el allow son ESCRITURAS')
            assert.deepEqual(r.orderResidue, [])
          }
          assert.notInclude(spy.prefixes.join(' | '), '⇒ true', `ningún prefijo concede X: ${spy.prefixes.join(' | ')}`)
          assert.isFalse(await to().check(u, 'viewer', x, p), 'el destino niega X, como el origen')
          assert.isTrue(await to().check(u, 'viewer', y, p), 'el destino concede Y, como el origen')
          const again = await reconcileRelations({ from: from(), to: to(), partition: p, toConfig: harness.config })
          assert.equal(again.written + again.updated + again.deleted, 0, 'converge: la 2.ª pasada no escribe nada')
          assert.deepEqual(again.details ?? [], [])
        })
        test(`${dir.label} · vigencia · C2-2 · una arista de anidación VENCIDA solo en el destino no cuenta para el auto-corte del orden: la membresía que entra en el grupo que DENIEGA va antes que la del grupo que concede, y ningún prefijo concede (sin residuo)`, async ({ assert }) => {
          const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
          const u: RelSubject = { type: 'user', uuid: uuidv7() }
          // Ids ordenados: sin la precedencia «h antes que g», el desempate estable pondría g primero.
          const [gId, hId, kId] = [uuidv7(), uuidv7(), uuidv7()].sort()
          const g: RelObject = { type: 'group', id: gId }
          const h: RelObject = { type: 'group', id: hId }
          const k: RelObject = { type: 'group', id: kId }
          const x: RelObject = { type: denyType, id: uuidv7() }
          for (const side of [from(), to()]) {
            await side.relate({ object: g, relation: 'member' }, 'viewer', x, p)
            await side.deny!({ object: k, relation: 'member' }, 'viewer', x, p)
            await side.deny!({ object: h, relation: 'member' }, 'viewer', x, p)
          }
          await to().relate({ object: g, relation: 'member' }, 'member', k, p, { expiresAt: past() })
          await from().relate(u, 'member', g, p)
          await from().relate(u, 'member', h, p)
          assert.isFalse(await to().check(u, 'viewer', x, p))
          const spy = prefixSpy(to(), (d) => d.check(u, 'viewer', x, p))
          const report = await reconcileRelations({ from: from(), to: spy.driver, partition: p, toConfig: harness.config })
          assert.deepEqual(report.orderResidue, [])
          assert.lengthOf(spy.prefixes, 2, spy.prefixes.join(' | '))
          assert.notInclude(spy.prefixes.join(' | '), '⇒ true', `ningún prefijo concede: ${spy.prefixes.join(' | ')}`)
          assert.isFalse(await to().check(u, 'viewer', x, p), 'final: niega, como el origen')
        })
        test(`${dir.label} · vigencia · C3-1 · una membresía PORTADORA VIVA en el destino con una caducidad MÁS CORTA que la del origen: en un destino sin atomicRenewal no se renueva (renewal-unsafe) y su PARTICIÓN se niega —cero escrituras, partitionsRefused— (cierre 5 de D2, opción A); con atomicRenewal se renueva; en los dos, el destino NIEGA en now y TRAS la caducidad vieja (reloj inyectado), como el origen`, async ({ assert }) => {
          const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
          const u: RelSubject = { type: 'user', uuid: uuidv7() }
          const h: RelObject = { type: 'group', id: uuidv7() }
          const x: RelObject = { type: denyType, id: uuidv7() }
          const old = new Date(Date.now() + 3_600_000)
          for (const side of [from(), to()]) await side.deny!({ object: h, relation: 'member' }, 'viewer', x, p)
          await from().relate(u, 'member', h, p, { expiresAt: new Date(Date.now() + 86_400_000) })
          await from().relate(u, 'viewer', x, p)
          await to().relate(u, 'member', h, p, { expiresAt: old })
          assert.isFalse(await from().check(u, 'viewer', x, p), 'el origen niega X')
          const atomic = to().capabilities?.atomicRenewal === true
          const dry = await reconcileRelations({ from: from(), to: to(), partition: p, toConfig: harness.config, dryRun: true })
          const spy = writesOf(to())
          const report = await reconcileRelations({ from: from(), to: spy.driver, partition: p, toConfig: harness.config })
          for (const r of [dry, report]) {
            assert.deepEqual(
              {
                written: r.written,
                updated: r.updated,
                details: (r.details ?? []).map((d) => `${d.side}:${d.reason}`),
                refused: (r.partitionsRefused ?? []).map((x) => x.causes.map((c) => c.reason).join(',')),
              },
              atomic
                ? { written: 1, updated: 1, details: [], refused: [] }
                : { written: 0, updated: 0, details: ['destino:renewal-unsafe'], refused: ['renewal-unsafe'] },
              `atomicRenewal=${atomic}`
            )
          }
          if (!atomic) assert.deepEqual(spy.log, [], `ni la renovación ni el allow llegan al driver: ${spy.log.join(' | ')}`)
          assert.isFalse(await to().check(u, 'viewer', x, p), 'el destino niega X en now')
          // El HORIZONTE: tras la caducidad vieja del destino, con el reloj del destino adelantado (sin sleeps).
          const later = typeof to().withClock === 'function' ? to().withClock!(() => new Date(old.getTime() + 1_000)) : null
          if (later) assert.isFalse(await later.check(u, 'viewer', x, p), `ROJO (C3-1): tras la caducidad vieja el destino concede lo que el origen niega`)
        })
        test(`${dir.label} · D2 · el deny viaja como DENY (kind), ANTES que los allows; el CENSO lo busca por listDenies y check niega en el destino`, async ({ assert }) => {
          const seed = makeSeed()
          await plant(from(), seed)
          const object: RelObject = { type: denyType, id: uuidv7() }
          const viaGroup: RelObject = { type: denyType, id: uuidv7() }
          // Corte de camino (owner con deny en editor), y un deny transportado por g1#member (u3 es miembro).
          await from().relate(seed.u1, 'owner', object, seed.partition)
          await from().deny!(seed.u1, 'editor', object, seed.partition)
          await from().relate(seed.u3, 'viewer', viaGroup, seed.partition)
          await from().deny!({ object: seed.g1, relation: 'member' }, 'viewer', viaGroup, seed.partition)
          const spy = writesOf(to())
          const report = await reconcileRelations({ from: from(), to: spy.driver, partition: seed.partition })
          assert.equal(report.denies?.written, 2, 'los dos denies, contados aparte')
          assert.equal(report.written, seed.facts.length + 4)
          assert.equal(report.skipped.undeclared, 0, 'un deny NUNCA es undeclared')
          const firstAllow = spy.log.findIndex((l) => l.startsWith('relate'))
          const lastDeny = spy.log.map((l) => l.startsWith('deny')).lastIndexOf(true)
          assert.isBelow(lastDeny, firstAllow, `fase 1 (denies) antes que fase 2 (allows): ${spy.log.join(' | ')}`)
          assert.isFalse(spy.log.some((l) => l.includes('denied_')), 'jamás relate/unrelate de una relación denied_*')
          await census(assert, to(), seed)
          const denied = await to().listDenies!('editor', object, seed.partition)
          assert.isTrue(denied.subjects.some((s) => subjectKey(s) === subjectKey(seed.u1)), 'CENSO del deny directo')
          const deniedGroup = await to().listDenies!('viewer', viaGroup, seed.partition)
          assert.isTrue(deniedGroup.subjects.some((s) => subjectKey(s) === `${seed.g1.type}:${seed.g1.id}#member`), 'CENSO del deny a g1#member')
          assert.isFalse(await to().check(seed.u1, 'owner', object, seed.partition), 'corte de camino en el destino')
          assert.isFalse(await to().check(seed.u3, 'viewer', viaGroup, seed.partition), 'el deny del grupo llega a su miembro')
          const again = await reconcileRelations({ from: from(), to: to(), partition: seed.partition })
          assert.equal(again.written + again.updated + again.deleted, 0, 'idempotente con denies')
          assert.equal(again.denies?.unchanged, 2)
        })
        test(`${dir.label} · D2 · --prune: el deny SOBRANTE se borra con removeDeny (jamás unrelate), DESPUÉS de los allows sobrantes`, async ({ assert }) => {
          const seed = makeSeed()
          await plant(from(), seed)
          const gone: RelObject = { type: denyType, id: uuidv7() }
          await to().relate(seed.u2, 'viewer', gone, seed.partition)
          await to().deny!(seed.u2, 'viewer', gone, seed.partition)
          const spy = writesOf(to())
          const report = await reconcileRelations({ from: from(), to: spy.driver, partition: seed.partition, prune: true })
          assert.equal(report.denies?.deleted, 1)
          const prunes = spy.log.filter((l) => l.startsWith('unrelate') || l.startsWith('removeDeny'))
          assert.deepEqual(prunes, ['unrelate viewer', 'removeDeny viewer'], 'allows antes que denies; el deny con removeDeny')
          assert.lengthOf((await to().listDenies!('viewer', gone, seed.partition)).subjects, 0)
          await census(assert, to(), seed)
        })
      }
      test('D2 · S6 · un destino SIN relationDenies con un deny en el origen ⇒ 500 E_AUTHZ_DENY_MIGRATION_REFUSED con CERO escrituras (jamás skipped)', async ({ assert }) => {
        const seed = makeSeed()
        await plant(a, seed)
        await a.deny!(seed.u1, 'viewer', { type: denyType, id: uuidv7() }, seed.partition)
        const blind = writesOf(b)
        const target = new Proxy(blind.driver as any, {
          get(t, prop) {
            if (prop === 'capabilities') return { ...(b.capabilities as any), relationDenies: false }
            return Reflect.get(t, prop, t)
          },
        }) as RelationsDriver
        let caught: any = null
        try {
          await reconcileRelations({ from: a, to: target, partition: seed.partition })
        } catch (error) {
          caught = error
        }
        assert.equal(caught?.status, 500, String(caught?.message))
        assert.equal(caught?.code, 'E_AUTHZ_DENY_MIGRATION_REFUSED')
        assert.deepEqual(blind.log, [], 'CERO escrituras: tampoco los allows')
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
