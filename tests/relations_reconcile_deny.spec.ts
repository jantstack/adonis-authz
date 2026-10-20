/**
 * **Plan 2.5 · lote D · D2 — `reconcileRelations` con `kind` y denies** (tester §3 «Lote D» T3 / D-27, §5 S4, S5, S6;
 * auditor R2-3, R2-5; juez ronda 2 fila D; analista §4.7).
 *
 * Sin servidor (dobles en memoria, corre en los cuatro modos): la lógica del plan y de las cuatro fases de escritura.
 * Las filas contra `database` ↔ `openfga` reales viven en el runner publicado (`runRelationsReconcileContract` con
 * `denies: true`, `tests/relations_reconcile.spec.ts`) y el efecto por el kernel (D-27) en
 * `tests/relations_reconcile_deny_cli.spec.ts`.
 *
 * Las cuatro fases (por partición), en el orden del punto de paso ÚNICO `src/relations/tuple_order.ts` (cierre 1 de D2 ·
 * 🟠 1, compartido con las purgas de `openfga`): (1) denies nuevos/actualizados (`to.deny`), (2) membresías —las que
 * transportan un deny primero— y luego allows (`to.relate`), (3) con `--prune` allows y luego membresías sobrantes
 * (`to.unrelate`), (4) con `--prune` denies sobrantes (`to.removeDeny`), los ÚLTIMOS. Una pasada cortada en cualquier
 * punto no concede lo que no concedían ni el estado inicial ni el final (S4/S5; residuo declarado en `tuple_order.ts`).
 */
import { test } from '@japa/runner'
import { readFileSync } from 'node:fs'
import { v7 as uuidv7 } from 'uuid'
import { partitionRefusalRecipe, reconcileRelations } from '../src/relations/reconcile.js'
import { partialReportLines, relationsReconcileLines } from '../commands/authz_relations_reconcile.js'
import { contractDenyRelationsConfig, makeRelationsDriver, RELATIONS_HOLDER_TYPES } from '../src/testing/relations_contract.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { AuthorizationBackendError, AuthorizationConfigError, isPartialWrite, markPartialWrite } from '../src/errors.js'
import type { RelationsConfig } from '../src/relations/define_relations_config.js'
import type { RelObject, RelSubject, RelationTuple, RelationsDriver, RelationsDriverCapabilities, ScopeRef } from '../src/types.js'

const FULL: RelationsDriverCapabilities = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: false,
  injectableClock: true,
  transactionalWrites: false,
  relationDenies: true,
}
const NO_DENY: RelationsDriverCapabilities = { ...FULL, relationDenies: false }

const RELS = [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }]
/** El ORIGEN escribe denies en los TRES tipos (fase 'write'); el destino es la config del contrato (document 'write', workspace 'read', note sin opt-in). */
function allWriteConfig(): RelationsConfig {
  return defineRelationsConfig({
    objectTypes: ['document', 'workspace', 'note'].map((type) => ({ type, relations: RELS, deny: 'write' as const })),
    holderTypes: [...RELATIONS_HOLDER_TYPES],
    database: { membersOf: true },
  })
}

const double = (config: RelationsConfig = contractDenyRelationsConfig(), capabilities = FULL) => makeRelationsDriver({ config, capabilities })
const user = (): RelSubject => ({ type: 'user', uuid: uuidv7() })
const doc = (type = 'document'): RelObject => ({ type, id: uuidv7() })
const part = (): ScopeRef => ({ type: 'unit', uuid: uuidv7() })

const WRITES = ['relate', 'unrelate', 'deny', 'removeDeny'] as const

/**
 * Un espía sobre el DESTINO: anota cada escritura (`op relación tipo:id`) y, con `failAfter`, hace fallar la escritura
 * número `failAfter + 1` con un 503 no-timeout (el «corte» de S4/S5). Las lecturas pasan tal cual.
 */
function spied(driver: RelationsDriver, failAfter?: number) {
  const log: string[] = []
  let writes = 0
  const proxy = new Proxy(driver as any, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target)
      if (typeof prop === 'string' && (WRITES as readonly string[]).includes(prop) && typeof value === 'function') {
        return async (...args: any[]) => {
          if (failAfter !== undefined && writes >= failAfter) throw new AuthorizationBackendError('doble', 'reconcile', new Error('corte inyectado (S4/S5)'))
          writes++
          log.push(`${prop} ${args[1]} ${args[2].type}:${args[2].id}`)
          return value.apply(target, args)
        }
      }
      return typeof value === 'function' ? value.bind(target) : value
    },
  })
  return { driver: proxy as RelationsDriver, log, writes: () => writes }
}

/** Un ORIGEN de terceros que enumera EXACTAMENTE estas tuplas (para las formas que la API no escribe: deny caducado, deny sin `kind`). */
function fakeSource(tuples: RelationTuple[]): RelationsDriver {
  const unused = async () => {
    throw new Error('fakeSource: solo enumera')
  }
  return {
    capabilities: FULL,
    relate: unused,
    unrelate: unused,
    check: unused as any,
    listObjects: unused as any,
    listSubjects: unused as any,
    purgeObject: unused,
    purgeSubject: unused,
    enumerateRelations: async (partition: ScopeRef) => ({ tuples: tuples.map((t) => ({ ...t, partition })) }),
  }
}

async function caught(run: () => Promise<unknown>): Promise<any> {
  return run().then(
    () => null,
    (e) => e
  )
}

test.group('D2 · reconcile con kind — T3 (D-27) sobre dobles: el deny viaja como deny', () => {
  test('T3 · deny vivo + allow del MISMO hecho ⇒ dos escrituras (la clave lleva kind), el deny ANTES que el allow, report.denies.written, censo por listDenies y check F en el destino', async ({ assert }) => {
    const from = double()
    const { driver: to, log } = spied(double())
    const p = part()
    const u = user()
    const d = doc()
    await from.relate(u, 'viewer', d, p)
    await from.deny!(u, 'viewer', d, p)
    const enumerated = (await from.enumerateRelations!(p)).tuples
    assert.deepEqual(
      enumerated.map((t) => `${t.kind}:${t.relation}`).sort(),
      ['allow:viewer', 'deny:viewer'],
      'enumerateRelations marca kind y da la relación PÚBLICA (nunca denied_viewer)'
    )

    const report = await reconcileRelations({ from, to, partition: p, toConfig: contractDenyRelationsConfig() })
    assert.equal(report.written, 2, 'allow y deny: dos escrituras')
    assert.deepEqual(report.denies, { written: 1, updated: 0, deleted: 0, unchanged: 0, extra: 0 })
    assert.deepEqual(report.skipped, { expired: 0, undeclared: 0, invalid: 0, usersetUnsupported: 0 }, 'el deny NO es undeclared (R2-3)')
    assert.deepEqual(log, [`deny viewer document:${d.id}`, `relate viewer document:${d.id}`], 'fase 1 (denies) antes que fase 2 (allows); jamás relate(denied_viewer)')
    assert.deepEqual((await to.listDenies!('viewer', d, p)).subjects, [u], 'CENSO: el deny está en el destino')
    assert.isFalse(await to.check(u, 'viewer', d, p), 'el destino niega lo que el origen niega')

    const again = await reconcileRelations({ from, to, partition: p, toConfig: contractDenyRelationsConfig() })
    assert.equal(again.written + again.updated + again.deleted, 0, 'idempotente')
    assert.equal(again.unchanged, 2)
    assert.equal(again.denies?.unchanged, 1)
  })

  test('T3 · deny CADUCADO en el origen (escrito a mano) ⇒ skipped.expired, no se escribe', async ({ assert }) => {
    const u = user()
    const d = doc()
    const from = fakeSource([{ subject: u, relation: 'viewer', object: d, partition: part(), kind: 'deny', expiresAt: new Date(Date.now() - 60_000) }])
    const { driver: to, log } = spied(double())
    const report = await reconcileRelations({ from, to, partition: part() })
    assert.equal(report.skipped.expired, 1)
    assert.equal(report.written, 0)
    assert.deepEqual(log, [])
  })

  test('T3 · S6 · origen con un deny y destino SIN relationDenies ⇒ 500 E_AUTHZ_DENY_MIGRATION_REFUSED con CERO escrituras (tampoco los allows); jamás skipped', async ({ assert }) => {
    const from = double()
    const { driver: to, log } = spied(double(contractDenyRelationsConfig(), NO_DENY))
    const p = part()
    const u = user()
    await from.relate(u, 'viewer', doc(), p)
    await from.deny!(u, 'viewer', doc(), p)
    const error = await caught(() => reconcileRelations({ from, to, partition: p }))
    assert.equal(error?.status, 500, String(error?.message))
    assert.equal(error?.code, 'E_AUTHZ_DENY_MIGRATION_REFUSED')
    assert.include(String(error?.message), 'relationDenies')
    assert.deepEqual(error?.refusals?.map((r: any) => r.reason), ['no-capability'])
    assert.deepEqual(log, [], 'CERO escrituras: ni el deny ni el allow (escribir el allow sin su deny concedería)')

    const dry = await reconcileRelations({ from, to, partition: p, dryRun: true })
    assert.deepEqual(dry.denyRefused?.map((r) => r.reason), ['no-capability'], '--dry-run no lanza: lo marca')
    assert.equal(dry.written, 2, 'el dry-run dice lo que HARÍA si pudiera; la línea dice que la real se niega')
    const { lines, clean } = relationsReconcileLines(dry)
    assert.isFalse(clean, 'una negativa de deny es DERIVA')
    assert.isTrue(lines.some((l) => l.level === 'error' && l.message.startsWith('deny NO migrable')), JSON.stringify(lines))
  })

  test("T3 · S6 · R2-5 · el tipo del deny NO está en 'write' EN EL DESTINO (fase 'read' o sin opt-in) ⇒ 500 con CERO escrituras, POR TIPO; la spec persistida no decide (toConfig ausente)", async ({ assert }) => {
    for (const [type, phase] of [
      ['workspace', 'read'],
      ['note', 'none'],
    ] as const) {
      const from = double(allWriteConfig())
      const { driver: to, log } = spied(double())
      const p = part()
      const u = user()
      const d = doc(type)
      await from.relate(u, 'viewer', d, p)
      await from.deny!(u, 'viewer', d, p)
      const error = await caught(() => reconcileRelations({ from, to, partition: p }))
      assert.equal(error?.code, 'E_AUTHZ_DENY_MIGRATION_REFUSED', `${type}: ${error?.message}`)
      assert.deepEqual(error?.refusals?.map((r: any) => `${r.objectType}:${r.reason}`), [`${type}:phase`], `${type} (${phase})`)
      assert.include(String(error?.message), type)
      assert.deepEqual(log, [], `${type}: CERO escrituras`)
    }
  })

  test('T3 · un destino con relationDenies pero SIN denyPhase no puede responder por el tipo ⇒ 500 (motivo no-deny-phase), cero escrituras', async ({ assert }) => {
    const from = double()
    const base = double()
    const { denyPhase: _omit, ...rest } = base as any
    const blind = Object.assign(Object.create(Object.getPrototypeOf(base)), rest, { capabilities: base.capabilities }) as RelationsDriver
    delete (blind as any).denyPhase
    const { driver: to, log } = spied(blind)
    const p = part()
    await from.deny!(user(), 'viewer', doc(), p)
    const error = await caught(() => reconcileRelations({ from, to, partition: p }))
    assert.equal(error?.code, 'E_AUTHZ_DENY_MIGRATION_REFUSED', String(error?.message))
    assert.deepEqual(error?.refusals?.map((r: any) => r.reason), ['no-deny-phase'])
    assert.deepEqual(log, [])
  })

  test('T3 · un ORIGEN que enumera un deny SIN marcar kind (relación denied_viewer) ⇒ 500 motivo unmarked, jamás undeclared ni un allow «denied_viewer»', async ({ assert }) => {
    const u = user()
    const d = doc()
    const from = fakeSource([
      { subject: u, relation: 'viewer', object: d, partition: part() },
      { subject: u, relation: 'denied_viewer', object: d, partition: part() },
    ])
    const { driver: to, log } = spied(double())
    const error = await caught(() => reconcileRelations({ from, to, partition: part(), toConfig: contractDenyRelationsConfig() }))
    assert.equal(error?.code, 'E_AUTHZ_DENY_MIGRATION_REFUSED', String(error?.message))
    assert.deepEqual(error?.refusals?.map((r: any) => r.reason), ['unmarked'])
    assert.deepEqual(log, [])
  })

  test('⚪ 8 (cierre 1 de D2) · un DESTINO (de terceros) que enumera un deny SIN kind ⇒ negativa unmarked en el PLAN (500 con cero escrituras; --dry-run --prune lo marca), jamás planificado como allow ni podado con unrelate(denied_*)', async ({ assert }) => {
    const p = part()
    const u = user()
    const d = doc()
    const from = double()
    await from.relate(u, 'viewer', doc(), p)
    const base = double()
    // El destino de terceros: enumera además una tupla `denied_viewer` SIN `kind` (lo que un driver que no marca haría).
    const unmarked = new Proxy(base as any, {
      get(target, prop) {
        const value = Reflect.get(target, prop, target)
        if (prop === 'enumerateRelations') {
          return async (partition: ScopeRef, page?: any) => {
            const out = await value.call(target, partition, page)
            return { ...out, tuples: [...out.tuples, { subject: u, relation: 'denied_viewer', object: d, partition }] }
          }
        }
        return typeof value === 'function' ? value.bind(target) : value
      },
    }) as RelationsDriver
    const dry = await reconcileRelations({ from, to: unmarked, partition: p, prune: true, dryRun: true })
    assert.deepEqual(dry.denyRefused?.map((r) => `${r.reason} ${r.objectType}#${r.relation}`), ['unmarked document#denied_viewer'])
    assert.include(dry.denyRefused?.[0].message, 'DESTINO')
    assert.equal(dry.deleted, 0, 'nunca se planifica como allow sobrante (no se poda con unrelate)')
    const { driver: to, log } = spied(unmarked)
    const error = await caught(() => reconcileRelations({ from, to, partition: p, prune: true }))
    assert.equal(error?.code, 'E_AUTHZ_DENY_MIGRATION_REFUSED', String(error?.message))
    assert.deepEqual(error?.refusals?.map((r: any) => r.reason), ['unmarked'])
    assert.deepEqual(log, [], 'cero escrituras')
  })

  test('T3 · un deny cuyo par tipo/relación el destino NO declara ⇒ 500 motivo undeclared (nunca skipped.undeclared: perder un deny no se declara)', async ({ assert }) => {
    const u = user()
    const from = fakeSource([{ subject: u, relation: 'approver', object: doc(), partition: part(), kind: 'deny' }])
    const { driver: to, log } = spied(double())
    const error = await caught(() => reconcileRelations({ from, to, partition: part() }))
    assert.equal(error?.code, 'E_AUTHZ_DENY_MIGRATION_REFUSED', String(error?.message))
    assert.deepEqual(error?.refusals?.map((r: any) => r.reason), ['undeclared'])
    assert.deepEqual(log, [])
  })

  test('🟡 6 (cierre 1 de D2) · relación RETIRADA con denies vivos en el ORIGEN database: la negativa undeclared trae SU receta, y la receta FUNCIONA por la API (re-declarar la relación temporalmente → removeDeny → retirarla ⇒ la pasada entra); la receta vieja («retira esos denies del origen») daba 422', async ({ assert }) => {
    const p = part()
    const u = user()
    const d = doc()
    const spec = (relations: Array<{ name: string; includes?: string[] }>, deny?: 'write') =>
      defineRelationsConfig({
        objectTypes: [{ type: 'document', relations, ...(deny ? { deny } : {}) }],
        holderTypes: [...RELATIONS_HOLDER_TYPES],
        database: { membersOf: true },
      })
    const withApprover = spec([...RELS, { name: 'approver' }], 'write')
    const retired = spec(RELS, 'write')
    await new DatabaseRelationsDriver(withApprover).deny!(u, 'approver', d, p)
    await new DatabaseRelationsDriver(withApprover).relate(u, 'viewer', d, p)
    // La relación se retira de la config (de los dos lados) con el deny vivo en la tabla.
    const origin = new DatabaseRelationsDriver(retired)
    const dest = double(retired)
    const refused = await caught(() => reconcileRelations({ from: origin, to: dest, partition: p }))
    assert.equal(refused?.code, 'E_AUTHZ_DENY_MIGRATION_REFUSED', String(refused?.message))
    const refusal = refused.refusals[0]
    assert.equal(refusal.reason, 'undeclared')
    assert.include(refusal.recipe, 'vuelve a declarar', 'la receta de undeclared es la de re-declarar, no la genérica')
    assert.include(refusal.recipe, 'removeDeny')
    assert.include(String(refused.message), refusal.recipe, 'la letra del 500 lleva la receta de SU motivo')
    // La receta genérica de D2 («retira esos denies del origen») NO funciona por la API: F-05 en removeDeny.
    const naive = await caught(() => origin.removeDeny!(u, 'approver', d, p))
    assert.equal(naive?.status, 422, String(naive?.message))
    // La receta, EJECUTADA: re-declarar la relación (sin opt-in: removeDeny no exige fase) → removeDeny → retirarla.
    await new DatabaseRelationsDriver(spec([...RELS, { name: 'approver' }])).removeDeny!(u, 'approver', d, p)
    const report = await reconcileRelations({ from: origin, to: dest, partition: p })
    assert.equal(report.written, 1, 'la pasada entra: el allow se migra')
    assert.isTrue(await dest.check(u, 'viewer', d, p))
  })

  test('🟡 6 / ⚪ 11 (cierre 1 de D2) · una receta POR MOTIVO: cada negativa lleva la suya y ninguna repite la genérica de D2', async ({ assert }) => {
    const u = user()
    const p = part()
    const recipes = new Map<string, string>()
    const collect = async (from: RelationsDriver, to: RelationsDriver, toConfig?: RelationsConfig) => {
      const report = await reconcileRelations({ from, to, partition: p, dryRun: true, ...(toConfig ? { toConfig } : {}) })
      for (const r of report.denyRefused ?? []) recipes.set(r.reason, r.recipe)
    }
    const deniedSource = async (type = 'document') => {
      const from = double(allWriteConfig())
      await from.deny!(u, 'viewer', doc(type), p)
      return from
    }
    await collect(await deniedSource(), double(contractDenyRelationsConfig(), NO_DENY)) // no-capability
    const noPhase = double()
    delete (noPhase as any).denyPhase
    await collect(await deniedSource(), noPhase) // no-deny-phase
    await collect(await deniedSource('workspace'), double()) // phase (escribir exige 'write')
    await collect(fakeSource([{ subject: u, relation: 'denied_viewer', object: doc(), partition: p }]), double()) // unmarked
    await collect(fakeSource([{ subject: u, relation: 'approver', object: doc(), partition: p, kind: 'deny' }]), double()) // undeclared
    await collect(fakeSource([{ subject: { type: 'user', uuid: '*' } as any, relation: 'viewer', object: doc(), partition: p, kind: 'deny' }]), double()) // invalid
    // ⚪ 11: un deny que YA está en un destino sin opt-in (note): se mantiene la negativa, con el porqué de D8.
    const present = await deniedSource('note')
    const target = double(allWriteConfig())
    const note = (await present.enumerateRelations!(p)).tuples[0]
    await target.deny!(note.subject, note.relation, note.object, p)
    const honored = await reconcileRelations({ from: present, to: new Proxy(target as any, { get: (t, k) => (k === 'denyPhase' ? async () => null : typeof t[k] === 'function' ? t[k].bind(t) : t[k]) }) as RelationsDriver, partition: p, dryRun: true })
    const phaseHonor = honored.denyRefused?.find((r) => r.reason === 'phase')
    assert.include(phaseHonor?.message, 'D8', '⚪ 11: la letra explica por qué se niega aunque database honre la fila')
    assert.sameMembers([...recipes.keys()], ['no-capability', 'no-deny-phase', 'phase', 'unmarked', 'undeclared', 'invalid'])
    const distinct = new Set(recipes.values())
    assert.equal(distinct.size, recipes.size, `una receta DISTINTA por motivo: ${[...recipes.entries()].map(([k, v]) => `${k}: ${v}`).join(' | ')}`)
    for (const [reason, recipe] of recipes) assert.notInclude(recipe, 'o retira esos denies del origen, y repite la pasada', `${reason}: la genérica de D2`)
    assert.include(recipes.get('invalid'), 'a mano', 'invalid: removeDeny lo rechazaría')
    assert.include(recipes.get('unmarked'), 'kind', 'unmarked: actualizar el driver que no marca')
    assert.include(recipes.get('phase'), "deny: 'write'")
  })

  test('🟡 4 (cierre 1 de D2) → 🟡 C3-2 (cierre 4) → cierre 5 (opción A) · un destino SIN atomicRenewal con un deny CONDICIONAL que el origen tiene ⇒ el PLAN lo decide: residuo deny-conditional con su receta y la PARTICIÓN NEGADA (cero escrituras: el allow que ese deny corta tampoco), mismos números en --dry-run y real, deriva (exit ≠ 0); y si un driver que declara atomicRenewal lo rechaza igual, se PROPAGA', async ({ assert }) => {
    const p = part()
    const u = user()
    const d = doc()
    const from = double()
    await from.relate(u, 'viewer', d, p)
    await from.deny!(u, 'viewer', d, p)
    const target = double()
    // El destino ya tiene el deny CON caducidad (escrito a mano) y, como openfga, no puede reemplazar la clave (M5).
    await target.deny!(u, 'viewer', d, p)
    let denyCalls = 0
    const conditional = (atomicRenewal: boolean) =>
      new Proxy(target as any, {
        get(t, prop) {
          const value = Reflect.get(t, prop, t)
          if (prop === 'capabilities') return { ...value, atomicRenewal }
          if (prop === 'enumerateRelations') {
            return async (...args: any[]) => {
              const page = await value.apply(t, args)
              return { ...page, tuples: page.tuples.map((x: RelationTuple) => (x.kind === 'deny' ? { ...x, expiresAt: new Date(Date.now() + 3_600_000) } : x)) }
            }
          }
          if (prop === 'deny') return async () => { denyCalls++; throw AuthorizationConfigError.conditionalDeny('deny', 'document:…#denied_viewer@user:…') }
          return typeof value === 'function' ? value.bind(t) : value
        },
      }) as RelationsDriver
    const to = conditional(false)
    for (const dryRun of [true, false, false]) {
      const report = await reconcileRelations({ from, to, partition: p, dryRun })
      assert.deepEqual((report.details ?? []).map((x) => `${x.side}:${x.reason}`), ['destino:deny-conditional'], `dryRun=${dryRun}`)
      assert.deepEqual((report.partitionsRefused ?? []).map((x) => x.causes.map((c) => c.reason)), [['deny-conditional']], `dryRun=${dryRun}`)
      assert.equal(report.written, 0, `dryRun=${dryRun}: la partición NEGADA no escribe nada (el allow que ese deny corta concedería al caducar el deny)`)
      assert.equal(report.denies?.updated, 0)
      assert.equal(report.denies?.extra, 1)
      assert.isFalse(await target.check(u, 'viewer', d, p))
      const { lines, clean } = relationsReconcileLines(report)
      assert.isFalse(clean, 'deriva: exit ≠ 0')
      assert.isTrue(lines.some((l) => l.message.startsWith('sobra (deny-conditional) destino:') && l.message.includes('removeDeny')), JSON.stringify(lines))
      assert.isTrue(lines.some((l) => l.level === 'error' && l.message.startsWith('partición NEGADA ')), JSON.stringify(lines))
    }
    assert.equal(denyCalls, 0, 'el plan no le pide al driver lo que ya sabe que no puede')
    // Un driver que DECLARA atomicRenewal y aun así lo rechaza contradice su capacidad: se propaga (nunca «sigue»).
    const caught = await reconcileRelations({ from, to: conditional(true), partition: p }).then(() => null, (e) => e)
    assert.equal(caught?.status, 500, String(caught?.message))
    assert.isTrue(caught?.denyConditional)
    assert.equal(caught?.report?.written, 0, 'los allows van DESPUÉS de los denies: no se escribió ninguno')
  })

  test('T3 · --prune: un deny SOBRANTE se borra con removeDeny (jamás unrelate) y los allows sobrantes se podan ANTES que los denies', async ({ assert }) => {
    const from = double()
    const { driver: to, log } = spied(double())
    const p = part()
    const u = user()
    const keep = doc()
    const gone = doc()
    await from.relate(u, 'viewer', keep, p)
    await to.relate(u, 'viewer', keep, p)
    await to.relate(u, 'editor', gone, p)
    await to.deny!(u, 'editor', gone, p)
    log.length = 0
    const report = await reconcileRelations({ from, to, partition: p, prune: true })
    assert.equal(report.deleted, 2)
    assert.deepEqual(report.denies, { written: 0, updated: 0, deleted: 1, unchanged: 0, extra: 0 })
    assert.deepEqual(log, [`unrelate editor document:${gone.id}`, `removeDeny editor document:${gone.id}`], 'fase 3 (allows) antes que fase 4 (denies)')
    assert.lengthOf((await to.listDenies!('editor', gone, p)).subjects, 0)

    // Sin --prune, el deny sobrante cuenta en extra (y en denies.extra).
    const from2 = double()
    const to2 = double()
    const p2 = part()
    await from2.relate(u, 'viewer', keep, p2)
    await to2.deny!(u, 'editor', gone, p2)
    const noPrune = await reconcileRelations({ from: from2, to: to2, partition: p2 })
    assert.equal(noPrune.extra, 1)
    assert.equal(noPrune.denies?.extra, 1)
  })

  test('T3 · --dry-run: los MISMOS números que la pasada real (denies incluidos) y CERO escrituras; deriva', async ({ assert }) => {
    const build = async () => {
      const from = double()
      const p = part()
      const u = user()
      const d = doc()
      await from.relate(u, 'owner', d, p)
      await from.deny!(u, 'editor', d, p)
      return { from, p }
    }
    const a = await build()
    const { driver: dryTo, log } = spied(double())
    const dry = await reconcileRelations({ from: a.from, to: dryTo, partition: a.p, dryRun: true })
    assert.deepEqual(log, [], '--dry-run es read-only')
    const real = await reconcileRelations({ from: a.from, to: double(), partition: a.p })
    for (const k of ['written', 'updated', 'deleted', 'unchanged', 'extra'] as const) assert.equal(dry[k], real[k], k)
    assert.deepEqual(dry.denies, real.denies)
    assert.isFalse(relationsReconcileLines(dry).clean, 'un deny por escribir es deriva en el verificador')
  })

  test('T3 · massDelete: un deny VIVO del origen cuenta como utilizable (un origen con solo denies no dispara el seguro)', async ({ assert }) => {
    const from = double()
    const to = double()
    const p = part()
    const u = user()
    await from.deny!(u, 'viewer', doc(), p)
    await to.relate(u, 'viewer', doc(), p)
    const report = await reconcileRelations({ from, to, partition: p, prune: true })
    assert.isFalse(report.massDelete)
    assert.equal(report.deleted, 1)
    assert.equal(report.denies?.written, 1)
  })
})

test.group('D2 · S4/S5 — la pasada cortada nunca deja un allow sin su deny en el destino', () => {
  test('S4 · cortada al ESCRIBIR tras k escrituras (k = 0…n): ningún estado intermedio concede lo que el origen niega; el error va marcado parcial si ya escribió', async ({ assert }) => {
    const from = double()
    const p = part()
    const u = user()
    const w = user()
    const d1 = doc()
    const d2 = doc()
    // Corte de camino (D5): owner con deny en editor ⇒ F; y allow+deny del mismo hecho ⇒ F.
    await from.relate(u, 'owner', d1, p)
    await from.deny!(u, 'editor', d1, p)
    await from.relate(w, 'viewer', d2, p)
    await from.deny!(w, 'viewer', d2, p)
    const total = 4
    for (let k = 0; k <= total; k++) {
      const target = double()
      const { driver: to } = spied(target, k < total ? k : undefined)
      const error = await caught(() => reconcileRelations({ from, to, partition: p }))
      if (k < total) {
        assert.equal(error?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', `k=${k}: ${error?.message}`)
        assert.equal(isPartialWrite(error), k > 0, `k=${k}: parcial ⇔ ya escribió`)
      } else assert.isNull(error)
      assert.isFalse(await target.check(u, 'owner', d1, p), `ROJO (S4) k=${k}: owner sin el deny de editor`)
      assert.isFalse(await target.check(u, 'viewer', d1, p), `ROJO (S4) k=${k}`)
      assert.isFalse(await target.check(w, 'viewer', d2, p), `ROJO (S4) k=${k}: un allow sin su deny`)
    }
  })

  test('🟠 1 (cierre 1 de D2) · ORIGEN database REAL: allow directo creado ANTES de entrar al grupo denegado (uuid v7 = orden de creación) ⇒ cortada tras k escrituras, el destino nunca concede; la membresía que transporta el deny va antes que el allow', async ({ assert }) => {
    const p = part()
    const u = user()
    const d = doc()
    const g = { type: 'group', id: uuidv7() }
    const from = new DatabaseRelationsDriver(contractDenyRelationsConfig())
    await from.relate(u, 'viewer', d, p) // lunes: se le comparte el documento
    await from.relate(u, 'member', g, p) // martes: entra en «contratistas suspendidos»
    await from.deny!({ object: g, relation: 'member' }, 'viewer', d, p) // el grupo está denegado
    assert.isFalse(await from.check(u, 'viewer', d, p), 'el origen niega')
    const enumerated = (await from.enumerateRelations!(p)).tuples.map((t) => `${t.kind ?? 'allow'} ${t.object.type}#${t.relation}`)
    assert.deepEqual(enumerated, ['allow document#viewer', 'allow group#member', 'deny document#viewer'], 'database enumera por uuid v7: el allow ANTES que la membresía')
    const full = spied(double())
    await reconcileRelations({ from, to: full.driver, partition: p })
    assert.deepEqual(full.log.map((l) => l.split(' ').slice(0, 2).join(' ')), ['deny viewer', 'relate member', 'relate viewer'], 'orden de ESCRITURA: deny → membresía → allow')
    for (let k = 0; k <= 3; k++) {
      const target = double()
      const { driver: to } = spied(target, k < 3 ? k : undefined)
      await caught(() => reconcileRelations({ from, to, partition: p }))
      assert.isFalse(await target.check(u, 'viewer', d, p), `ROJO (🟠 1) k=${k}: el allow directo llegó antes que la membresía que transporta el deny`)
    }
  })

  test('S5 · --prune cortado tras k borrados: allows podados ANTES que denies ⇒ ningún estado intermedio concede', async ({ assert }) => {
    const from = double()
    const p = part()
    const u = user()
    const keep = doc()
    await from.relate(u, 'viewer', keep, p)
    const victims = [doc(), doc()]
    for (let k = 0; k <= 4; k++) {
      const target = double()
      await target.relate(u, 'viewer', keep, p)
      for (const v of victims) {
        await target.relate(u, 'viewer', v, p)
        await target.deny!(u, 'viewer', v, p)
      }
      const { driver: to } = spied(target, k < 4 ? k : undefined)
      await caught(() => reconcileRelations({ from, to, partition: p, prune: true }))
      for (const v of victims) assert.isFalse(await target.check(u, 'viewer', v, p), `ROJO (S5) k=${k}: el deny se podó antes que su allow`)
    }
  })
})

test.group('D2 · reporte parcial por partición (roadmap 2.5, 🟡 3 del auditor de alpha.6)', () => {
  test('K particiones: si revienta la 2.ª, el error lleva el reporte con la 1.ª done, la 2.ª failed y la 3.ª pending, y la marca de escritura parcial', async ({ assert }) => {
    const from = double()
    const parts = [part(), part(), part()]
    const u = user()
    for (const p of parts) await from.relate(u, 'viewer', doc(), p)
    const { driver: to } = spied(double(), 1)
    const error = await caught(() => reconcileRelations({ from, to, partitions: parts }))
    assert.equal(error?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    assert.isTrue(isPartialWrite(error))
    const partial = error?.report
    assert.isTrue(partial?.partial, 'el reporte del error dice partial: true')
    assert.deepEqual(
      partial?.partitions?.map((r: any) => r.status),
      ['done', 'failed', 'pending']
    )
    assert.equal(partial?.partitions?.[0]?.written, 1)
    assert.equal(partial?.written, 1, 'lo escrito hasta el fallo')

    const ok = await reconcileRelations({ from, to: double(), partitions: parts })
    assert.deepEqual(ok.partitions?.map((r) => r.status), ['done', 'done', 'done'])
    assert.deepEqual(ok.partitions?.map((r) => r.written), [1, 1, 1])
    assert.notExists(ok.partial)
  })
})

test.group('D2 · letra con dientes: el README dice lo que el código imprime', () => {
  test('§Upgrading nombra el orden «provision → pin modelId → deploy», y los prefijos ESTABLES de las ramas nuevas son los del código', ({ assert }) => {
    const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
    const section = readme.slice(readme.indexOf('### Upgrading to 2.5.0-alpha.3'), readme.indexOf('## Compatibility'))
    assert.include(section, '**Turning the deny on is two deployments, in this order: provision → pin `modelId` → deploy.**')
    assert.include(section, '**Rolling back below 2.5 with live denies is not supported (D12 · S17, declared row).**')
    for (const prefix of ['provision NEGADO:', 'deny NO migrable', 'pasada PARCIAL:', '`denies:`', 'E_AUTHZ_DENY_MIGRATION_REFUSED']) {
      assert.include(readme, prefix, `el README nombra ${prefix}`)
    }
    const command = readFileSync(new URL('../commands/authz_relations_reconcile.ts', import.meta.url), 'utf8')
    const provision = readFileSync(new URL('../commands/openfga_provision.ts', import.meta.url), 'utf8')
    for (const prefix of ['deny NO migrable (', 'pasada PARCIAL: ', '`denies: escritos ']) assert.include(command, prefix)
    assert.include(provision, '`provision NEGADO: ')
    assert.include(readme, '| `E_AUTHZ_DENY_MIGRATION_REFUSED` | 500 |', 'la fila de la tabla de códigos')
    // Cierre 1 de D2: el paso 0 del rollback (🟠 2), la rama sin escrituras (⚪ 10), el recuento (🟠 2), el residuo
    // declarado del orden (🟠 1) y los totales con denies (⚪ 12) — la letra del README es la del código.
    assert.include(section, "0. **Move the whole fleet to `deny: 'read'`**")
    assert.include(section, '4. **Count again: it must still be 0.**')
    assert.include(readme, '`pasada FALLIDA sin escribir nada:`')
    assert.include(command, 'pasada FALLIDA sin escribir nada: ')
    assert.include(section, '`provision NEGADO: el RECUENTO …`')
    assert.include(provision, '`provision NEGADO: el RECUENTO justo antes de publicar')
    // Cierre 2 de D2 · 🟡 N3/🟡 N2: la garantía es la DEMOSTRADA (sin ciclo ⇒ ningún prefijo concede) y el residuo es el
    // ciclo (la frase del residuo de «grupos mixtos» del cierre 1 desaparece); los prefijos estables de la línea, los del código.
    assert.include(readme, '`relations.reconcile.order` and `openfga.purge.order`, the last two judged with the source enumerated in both orders')
    assert.include(readme, '**if the precedence graph has\nno cycle, no state of a pass cut after any write grants something neither the initial nor the final state granted')
    assert.include(readme, 'The **residue is the cycle**')
    assert.notInclude(readme, 'declared residue**: a group that carries both an allow and a deny')
    assert.include(readme, '`orden SIN garantía`')
    assert.include(command, 'orden SIN garantía: ')
    assert.include(readme, '`sin renovar (renewal-unsafe) destino:`')
    assert.include(command, '`sin renovar ${what}.`')
    assert.include(readme, '**The totals `written`/`unchanged`/`extra` include the\ndenies**')
  })

  test('cierre 5 de D2 (opción A) · el README dice el LÍMITE de openfga (409, sin forma sin ventana, #2151, patrón recomendado, TOCTOU de N1, atomicRenewal → true con upsert), el prefijo «partición NEGADA» es el del código, y la retención del cierre 4 ya no se promete', ({ assert }) => {
    const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
    const command = readFileSync(new URL('../commands/authz_relations_reconcile.ts', import.meta.url), 'utf8')
    assert.include(readme, '**The limit: changing the expiry of a deny-carrying membership on `openfga`.**')
    assert.include(readme, 'https://github.com/openfga/openfga/issues/2151')
    assert.include(readme, '**There is no window-free way to do it.**')
    assert.include(readme, 'memberships\n**without expiry** in groups that carry a deny')
    assert.include(readme, '**Declared window (TOCTOU of N1):**')
    // Lote «antes de RC» · F4 (decisión (6a), fila 10 del barrido del analista): un upsert de la misma clave no se ha medido
    // contra un lector concurrente: «candidato», no «será `true`».
    assert.include(readme, '**When OpenFGA offers an upsert, the renewal will be one `Write` and a candidate for `atomicRenewal: true`**')
    assert.include(readme, '`partición NEGADA <partition>:`')
    assert.include(command, '`partición NEGADA ${refusal.partition}: ')
    assert.notInclude(readme, 'Withholding only restricts', 'la frase universal del cierre 4 (falsa: D4-1, D4-2)')
    assert.notInclude(readme, 'retire the deny first (`removeDeny`), renew', 'la receta que reabría la ventana, presentada como salida')
    assert.notInclude(readme, '`retenida (withheld-by-unsafe-deny) destino:`')
  })

  test('cierre 6 de D2 · ⚪ D5-3 · el README dice que «as it was» NO es estático y las salidas reales de la partición negada; «the reconcile refuses that partition» ya no es absoluto (D5-1); el comentario rancio de applyPartition («con los allows que corta retenidos») no vuelve', ({ assert }) => {
    const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
    const source = readFileSync(new URL('../src/relations/reconcile.ts', import.meta.url), 'utf8')
    assert.include(readme, '**And "as it was" is not static**')
    assert.include(readme, '`partitionsRefused[].evolves`')
    assert.include(readme, 'Making the membership expiry-less in the SOURCE does NOT unlock')
    assert.include(readme, 'the reconcile refuses that partition when its plan counts that deny')
    assert.notInclude(readme, 'the reconcile refuses that partition. ')
    assert.notInclude(source, 'con los allows que corta retenidos')
  })
})

/* ── Cierre 2 de D2 · 🟠 N1 (renovación de una membresía PORTADORA) y 🟡 N3 (el residuo del orden, avisado) ─────────── */

test.group('reconcile · cierre 2 de D2 · 🟠 N1 · renovar una membresía que TRANSPORTA un deny', () => {
  /** Origen: U ∈ g PERMANENTE; destino: U ∈ g con caducidad; en los dos, allow directo de U y deny de g#member. */
  async function carrierRenewal(destinationCaps: RelationsDriverCapabilities) {
    const p = part()
    const u = user()
    const d = doc()
    const g: RelObject = { type: 'group', id: uuidv7() }
    const from = double()
    const to = double(contractDenyRelationsConfig(), destinationCaps)
    for (const side of [from, to]) {
      await side.relate(u, 'viewer', d, p)
      await side.deny!({ object: g, relation: 'member' }, 'viewer', d, p)
    }
    await from.relate(u, 'member', g, p)
    await to.relate(u, 'member', g, p, { expiresAt: new Date(Date.now() + 3_600_000) })
    return { p, u, d, g, from, to }
  }

  test('destino SIN atomicRenewal (renueva con dos escrituras): el PLAN clasifica renewal-unsafe con su receta — mismos números en --dry-run y real, ni un relate de esa membresía, el deny sigue negando, deriva con «sin renovar (renewal-unsafe) destino:»', async ({ assert }) => {
    for (const dryRun of [true, false]) {
      const { p, u, d, from, to } = await carrierRenewal(FULL)
      const spy = spied(to)
      const report = await reconcileRelations({ from, to: spy.driver, partition: p, dryRun, toConfig: contractDenyRelationsConfig() })
      assert.equal(report.updated, 0, `dryRun=${dryRun}`)
      assert.deepEqual((report.details ?? []).map((x) => `${x.side}:${x.reason}`), ['destino:renewal-unsafe'])
      assert.include(report.details![0].message, 'unrelate + relate')
      assert.deepEqual(spy.log, [], 'CERO escrituras')
      assert.isFalse(await to.check(u, 'viewer', d, p))
      const { lines, clean } = relationsReconcileLines(report)
      assert.isFalse(clean)
      assert.isTrue(lines.some((l) => l.level === 'error' && l.message.startsWith('sin renovar (renewal-unsafe) destino:')))
    }
  })

  test('destino CON atomicRenewal (database: una transacción): la misma membresía se RENUEVA (updated 1, sin residuo) y el deny sigue negando', async ({ assert }) => {
    const { p, u, d, from, to } = await carrierRenewal({ ...FULL, atomicRenewal: true })
    const report = await reconcileRelations({ from, to, partition: p, toConfig: contractDenyRelationsConfig() })
    assert.equal(report.updated, 1)
    assert.deepEqual(report.details, [])
    assert.isFalse(await to.check(u, 'viewer', d, p))
    assert.isTrue(relationsReconcileLines(report).clean)
  })

  test('cierre 4 de D2 · 🟡 horizonte · una renovación que ACORTA un allow va con los borrados (fase 2), ANTES de que salga la membresía que transporta su deny: cortada en cualquier punto, ningún prefijo concede cuando vence la caducidad NUEVA (reloj inyectado), donde ni el inicial ni el origen conceden', async ({ assert }) => {
    const shorter = new Date(Date.now() + 1_800_000)
    const horizon = new Date(shorter.getTime() + 1_000)
    const setup = async () => {
      const p = part()
      const u = user()
      const d = doc()
      const h: RelObject = { type: 'group', id: uuidv7() }
      const from = double()
      const to = double(contractDenyRelationsConfig(), { ...FULL, atomicRenewal: true })
      for (const side of [from, to]) await side.deny!({ object: h, relation: 'member' }, 'viewer', d, p)
      await from.relate(u, 'viewer', d, p, { expiresAt: shorter })
      await to.relate(u, 'viewer', d, p, { expiresAt: new Date(Date.now() + 3_600_000) })
      await to.relate(u, 'member', h, p, { expiresAt: new Date(Date.now() + 3_600_000) })
      return { p, u, d, h, from, to }
    }
    const full = await setup()
    const spy = spied(full.to)
    await reconcileRelations({ from: full.from, to: spy.driver, partition: full.p, prune: true, toConfig: contractDenyRelationsConfig() })
    const renew = spy.log.findIndex((l) => l.startsWith('relate viewer'))
    const leave = spy.log.findIndex((l) => l.startsWith('unrelate member'))
    assert.isAbove(leave, renew, `ROJO (horizonte): la membresía portadora sale antes de acortar el allow: ${spy.log.join(' | ')}`)
    for (let k = 0; k <= spy.log.length; k++) {
      const { p, u, d, from, to } = await setup()
      await reconcileRelations({ from, to: spied(to, k).driver, partition: p, prune: true, toConfig: contractDenyRelationsConfig() }).catch(() => {})
      // En `now` el final (el origen) SÍ concede: lo que se vigila es el instante en que vence la caducidad NUEVA, donde
      // ni el inicial (la membresía lo deniega) ni el origen (el allow ya venció) conceden.
      assert.isFalse(await to.withClock!(() => horizon).check(u, 'viewer', d, p), `ROJO (horizonte) tras ${k} escrituras: concede cuando vence la caducidad nueva`)
    }
  })

  test('la pasada que revienta en una escritura que el DRIVER marca parcial (una renovación de openfga: delete hecho, write no) ⇒ report.partial true aunque no completara ninguna, y la línea lo dice (jamás «sin escribir nada»)', async ({ assert }) => {
    const p = part()
    const u = user()
    const k: RelObject = { type: 'group', id: uuidv7() }
    const from = double()
    const base = double()
    await from.relate(u, 'member', k, p)
    await base.relate(u, 'member', k, p, { expiresAt: new Date(Date.now() + 3_600_000) })
    const to = new Proxy(base as any, {
      get(target, prop) {
        if (prop === 'relate') return async () => {
          throw markPartialWrite(new AuthorizationBackendError('doble', 'relate', new Error('2.º Write de la renovación')))
        }
        const value = Reflect.get(target, prop, target)
        return typeof value === 'function' ? value.bind(target) : value
      },
    }) as RelationsDriver
    const caught = await reconcileRelations({ from, to, partition: p }).then(() => null, (e) => e)
    assert.equal(caught?.status, 503)
    assert.isTrue(isPartialWrite(caught))
    assert.isTrue(caught.report.partial, 'partial: el driver ya había borrado')
    assert.isTrue(partialReportLines(caught.report).some((l) => l.includes('YA había aplicado parte')))
  })
})

test.group('reconcile · cierre 2 de D2 · 🟡 N3 · el RESIDUO del orden se AVISA (orderResidue)', () => {
  test('dos membresías del mismo sujeto que se cortan entre sí (g concede X y deniega Y; h al revés): report.orderResidue las nombra en --dry-run y en la real, y el comando avisa «orden SIN garantía» (warning: el estado final es el correcto)', async ({ assert }) => {
    for (const dryRun of [true, false]) {
      const p = part()
      const u = user()
      const x = doc()
      const y = doc()
      const g: RelObject = { type: 'group', id: uuidv7() }
      const h: RelObject = { type: 'group', id: uuidv7() }
      const from = double()
      const to = double()
      for (const side of [from, to]) {
        await side.relate({ object: g, relation: 'member' }, 'viewer', x, p)
        await side.deny!({ object: g, relation: 'member' }, 'viewer', y, p)
        await side.relate({ object: h, relation: 'member' }, 'viewer', y, p)
        await side.deny!({ object: h, relation: 'member' }, 'viewer', x, p)
      }
      await from.relate(u, 'member', g, p)
      await from.relate(u, 'member', h, p)
      const report = await reconcileRelations({ from, to, partition: p, dryRun, toConfig: contractDenyRelationsConfig() })
      assert.lengthOf(report.orderResidue ?? [], 2, `dryRun=${dryRun}: ${JSON.stringify(report.orderResidue)}`)
      const { lines } = relationsReconcileLines(report)
      assert.isTrue(lines.some((l) => l.level === 'warning' && l.message.startsWith('orden SIN garantía:')))
      if (!dryRun) assert.isTrue(relationsReconcileLines(report).clean, 'el aviso no es deriva: el estado final es el correcto')
    }
  })

  test('el AUTO-CORTE sale de la config del destino (toConfig): g concede y deniega X (y deniega Y), h concede Y y deniega X — con toConfig la membresía de g no trae ningún allow efectivo y no hay ciclo; sin ella el orden no da nada por cortado y DECLARA el residuo (más conservador, nunca menos garantía)', async ({ assert }) => {
    const build = async () => {
      const p = part()
      const u = user()
      const x = doc()
      const y = doc()
      const g: RelObject = { type: 'group', id: uuidv7() }
      const h: RelObject = { type: 'group', id: uuidv7() }
      const from = double()
      const to = double()
      for (const side of [from, to]) {
        await side.relate({ object: g, relation: 'member' }, 'viewer', x, p)
        await side.deny!({ object: g, relation: 'member' }, 'viewer', x, p)
        await side.deny!({ object: g, relation: 'member' }, 'viewer', y, p)
        await side.relate({ object: h, relation: 'member' }, 'viewer', y, p)
        await side.deny!({ object: h, relation: 'member' }, 'viewer', x, p)
      }
      await from.relate(u, 'member', g, p)
      await from.relate(u, 'member', h, p)
      return { from, to, p }
    }
    const withConfig = await build()
    const a = await reconcileRelations({ from: withConfig.from, to: withConfig.to, partition: withConfig.p, dryRun: true, toConfig: contractDenyRelationsConfig() })
    assert.deepEqual(a.orderResidue, [])
    const withoutConfig = await build()
    const b = await reconcileRelations({ from: withoutConfig.from, to: withoutConfig.to, partition: withoutConfig.p, dryRun: true })
    assert.lengthOf(b.orderResidue ?? [], 2)
  })

  test('sin ciclo no hay residuo: el 🟡 N2 (el otro grupo solo DENIEGA) se ordena entero', async ({ assert }) => {
    const p = part()
    const u = user()
    const x = doc()
    const y = doc()
    const g: RelObject = { type: 'group', id: uuidv7() }
    const h: RelObject = { type: 'group', id: uuidv7() }
    const from = double()
    const to = double()
    for (const side of [from, to]) {
      await side.relate({ object: g, relation: 'member' }, 'viewer', x, p)
      await side.deny!({ object: g, relation: 'member' }, 'viewer', y, p)
      await side.deny!({ object: h, relation: 'member' }, 'viewer', x, p)
    }
    await from.relate(u, 'member', g, p)
    await from.relate(u, 'member', h, p)
    const spy = spied(to)
    const report = await reconcileRelations({ from, to: spy.driver, partition: p, toConfig: contractDenyRelationsConfig() })
    assert.deepEqual(report.orderResidue, [])
    assert.deepEqual(spy.log, [`relate member group:${h.id}`, `relate member group:${g.id}`], 'la de h (solo deny) ANTES que la de g')
  })
})

/**
 * **Cierre 5 de D2 — opción A** (decisión del dueño §2026-10-16 (10)): la PARTICIÓN con ≥ 1 `renewal-unsafe` o
 * `deny-conditional` recibe CERO escrituras y CERO borrados (también con `--prune` y las vencidas); el resto migra. Fuera
 * la retención del cierre 4 (`withheld-by-unsafe-deny`, `carrier-conflict`). Reproducciones del auditor del cierre 4: D4-1
 * (la retención en cascada dejaba al destino concediendo YA) y D4-3 (`carrier-conflict` global, forzable desde el origen).
 */
test.group('reconcile · cierre 5 de D2 · opción A · la partición NEGADA', () => {
  const hour = () => new Date(Date.now() + 3_600_000)
  const day = () => new Date(Date.now() + 86_400_000)
  const g = (): RelObject => ({ type: 'group', id: uuidv7() })
  const member = (x: RelObject) => ({ object: x, relation: 'member' })

  test('D4-3 · un tenant que fuerza un renewal-unsafe en SU partición (extiende una portadora y quita otra membresía) ya no bloquea a los demás: con --prune su partición recibe CERO escrituras y CERO borrados (ni las vencidas), la del otro tenant MIGRA; --dry-run y la real dan los mismos números; exit ≠ 0 con la línea «partición NEGADA» que nombra la partición, dice que su destino queda COMO ESTABA y la deriva pendiente', async ({ assert }) => {
    const setup = async () => {
      const P = part()
      const P2 = part()
      const U = user()
      const V = user()
      const X = doc()
      const Z = doc()
      const W = doc()
      const W2 = doc()
      const H = g()
      const K = g()
      const from = double()
      const to = double()
      for (const side of [from, to]) {
        await side.deny!(member(H), 'viewer', X, P)
        await side.deny!(member(K), 'viewer', X, P)
        await side.relate(member(K), 'viewer', Z, P)
      }
      // Origen (tras la pasada N): U ∈ H EXTENDIDA y U ∈ K quitada; un allow nuevo; y la partición del otro tenant.
      await from.relate(U, 'member', H, P, { expiresAt: day() })
      await from.relate(U, 'viewer', W, P)
      await from.relate(V, 'viewer', W2, P2)
      // Destino (lo que copió la pasada N): U ∈ H corta, U ∈ K; y una sobrante VENCIDA (también se queda).
      await to.relate(U, 'member', H, P, { expiresAt: hour() })
      await to.relate(U, 'member', K, P)
      return { P, P2, U, V, W, W2, from, to }
    }
    const counts: Array<Record<string, unknown>> = []
    for (const dryRun of [true, false]) {
      const { P, P2, U, V, W, W2, from, to } = await setup()
      const before = (await to.enumerateRelations!(P)).tuples.length
      const spy = spied(to)
      const report = await reconcileRelations({ from, to: spy.driver, partitions: [P, P2], prune: true, dryRun, toConfig: contractDenyRelationsConfig() })
      const refused = report.partitionsRefused ?? []
      assert.lengthOf(refused, 1, JSON.stringify(refused))
      assert.equal(refused[0].partition, `unit|${P.uuid}`)
      assert.deepEqual(refused[0].causes.map((c) => c.reason), ['renewal-unsafe'])
      assert.deepEqual(refused[0].pending, { write: 1, update: 1, delete: 1 }, 'la deriva que queda a la vista: el allow nuevo, la portadora y la sobrante')
      assert.deepEqual(report.partitions!.map((r) => r.status), ['refused', 'done'])
      assert.deepEqual(report.partitions!.map((r) => r.written + r.updated + r.deleted), [0, 1], 'P: cero escrituras y cero borrados; P2: migra')
      counts.push({ written: report.written, updated: report.updated, deleted: report.deleted, extra: report.extra })
      if (!dryRun) {
        assert.deepEqual(spy.log, [`relate viewer document:${W2.id}`], `solo la partición del otro tenant: ${spy.log.join(' | ')}`)
        assert.equal((await to.enumerateRelations!(P)).tuples.length, before, 'el destino de P queda COMO ESTABA')
        assert.isTrue(await to.check(V, 'viewer', W2, P2), 'P2 migró')
        assert.isFalse(await to.check(U, 'viewer', W, P), 'P no recibió el allow nuevo')
      }
      const { lines, clean } = relationsReconcileLines(report)
      assert.isFalse(clean, 'deriva: exit ≠ 0 mientras la partición siga negada')
      const line = lines.find((l) => l.level === 'error' && l.message.startsWith('partición NEGADA '))
      assert.isDefined(line, JSON.stringify(lines))
      assert.include(line!.message, `unit|${P.uuid}`)
      assert.include(line!.message, 'COMO ESTABA')
      assert.include(line!.message, 'Cero escrituras y cero borrados')
      assert.include(line!.message, 'por escribir 1, por renovar 1, por borrar 1')
      assert.include(line!.message, 'openfga/openfga#2151')
      assert.include(line!.message, 'SIN caducidad')
      assert.isFalse(lines.some((l) => l.message.includes('withheld') || l.message.includes('carrier-conflict')), 'la retención del cierre 4 no existe')
    }
    assert.deepEqual(counts[0], counts[1], '--dry-run y la real dan los MISMOS números')
  })

  test('D4-1 · la portadora que no se puede renovar y una membresía nueva que transporta OTRO deny: la partición NEGADA no escribe ni la membresía nueva (antes «retenida») — el destino queda exactamente como estaba, la línea lo dice, y NINGUNA línea afirma que dejarlo así lo hace más restrictivo', async ({ assert }) => {
    const P = part()
    const U = user()
    const X = doc()
    const Y = doc()
    const H = g()
    const K = g()
    const from = double()
    const to = double()
    for (const side of [from, to]) {
      await side.deny!(member(H), 'viewer', X, P)
      await side.deny!(member(K), 'viewer', Y, P)
      await side.relate(member(K), 'viewer', X, P)
      await side.relate(U, 'viewer', Y, P)
    }
    await from.relate(U, 'member', H, P, { expiresAt: day() })
    await from.relate(U, 'member', K, P)
    await to.relate(U, 'member', H, P, { expiresAt: hour() })
    const before = JSON.stringify((await to.enumerateRelations!(P)).tuples)
    const report = await reconcileRelations({ from, to, partition: P, toConfig: contractDenyRelationsConfig() })
    assert.equal(report.written + report.updated + report.deleted, 0)
    assert.equal(JSON.stringify((await to.enumerateRelations!(P)).tuples), before, 'el destino queda EXACTAMENTE como estaba')
    assert.isFalse(await from.check(U, 'viewer', Y, P), 'el origen niega Y (por K)')
    assert.isTrue(await to.check(U, 'viewer', Y, P), 'el destino lo concedía ANTES y lo sigue concediendo: es la deriva previa, a la vista')
    const { lines } = relationsReconcileLines(report)
    const line = lines.find((l) => l.message.startsWith('partición NEGADA '))!
    assert.include(line.message, 'por escribir 1')
    assert.isFalse(lines.some((l) => /más restrictivo|igual o más restrictivo/.test(l.message)), 'ninguna frase universal falsa')
  })

  test('la RECETA es honesta: sin atomicRenewal no hay forma sin ventana (#2151); el patrón recomendado son membresías SIN caducidad en grupos con deny; unrelate + relate se ofrece DICHO como ventana; jamás «retira antes el deny» como salida segura — en la partición negada y en el 409 de relate', async ({ assert }) => {
    const { partitionRefusalRecipe } = await import('../src/relations/reconcile.js')
    const { RenewalUnsafeError } = await import('../src/errors.js')
    const renewal = partitionRefusalRecipe(['renewal-unsafe'])
    const conditional = partitionRefusalRecipe(['deny-conditional'])
    const relate = RenewalUnsafeError.carrier('group:g#member@user:u', 'document:x#denied_viewer@group:g#member').message
    for (const text of [renewal, relate]) {
      assert.include(text, 'openfga/openfga#2151')
      assert.include(text, 'SIN caducidad')
      assert.include(text, 'unrelate + relate')
      assert.match(text, /ACEPTANDO la ventana|aceptando la ventana/)
      assert.notInclude(text, 'retira antes el deny')
      assert.include(text, 'NO hay forma sin ventana')
    }
    assert.include(conditional, 'removeDeny')
    assert.match(conditional, /aceptando la ventana/)
    assert.include(partitionRefusalRecipe(['renewal-unsafe', 'deny-conditional']), 'deny-conditional:')
  })

  test('⚪ D5-3 (cierre 6 de D2) · E3: «COMO ESTABA» NO es estático — la portadora que el origen ALARGA deja de transportar el deny en su caducidad vieja y el destino CONCEDE lo que ese deny corta: el reporte (partitionsRefused[].evolves) y las dos líneas lo dicen con FECHA y QUÉ, y el reloj inyectado lo confirma', async ({ assert }) => {
    const P = part()
    const U = user() as { type: string; uuid: string }
    const X = doc()
    const H = g()
    const from = double()
    const to = double()
    for (const side of [from, to]) {
      await side.deny!(member(H), 'viewer', X, P)
      await side.relate(U, 'viewer', X, P)
    }
    const old = hour()
    await from.relate(U, 'member', H, P, { expiresAt: day() })
    await to.relate(U, 'member', H, P, { expiresAt: old })
    const report = await reconcileRelations({ from, to, partition: P, toConfig: contractDenyRelationsConfig() })
    assert.lengthOf(report.partitionsRefused ?? [], 1)
    assert.deepEqual(report.partitionsRefused![0].evolves, [
      { at: old.toISOString(), member: `user:${U.uuid}`, cut: [`viewer sobre document:${X.id}`] },
    ])
    assert.include(report.details![0].message, `A partir de ${old.toISOString()} el destino CONCEDERÁ a user:${U.uuid}`)
    const line = relationsReconcileLines(report).lines.find((l) => l.message.startsWith('partición NEGADA '))!
    assert.include(line.message, 'ese estado EVOLUCIONA')
    assert.include(line.message, `a partir de ${old.toISOString()} el destino concederá a user:${U.uuid} lo que cortan viewer sobre document:${X.id}`)
    // Lo que la línea promete, medido: en `now` el destino niega; pasada la caducidad vieja concede, y el origen niega.
    const later = new Date(old.getTime() + 60_000)
    assert.isFalse(await to.check(U, 'viewer', X, P))
    assert.isTrue(await (to as any).withClock(() => later).check(U, 'viewer', X, P), 'a partir de la fecha de la línea el destino CONCEDE')
    assert.isFalse(await (from as any).withClock(() => later).check(U, 'viewer', X, P), 'y el origen lo sigue negando')
    // Una portadora que ACORTA (el destino la conserva más) no evoluciona así: sin `evolves`.
    const P2 = part()
    const from2 = double()
    const to2 = double()
    for (const side of [from2, to2]) await side.deny!(member(H), 'viewer', X, P2)
    await from2.relate(U, 'member', H, P2, { expiresAt: hour() })
    await to2.relate(U, 'member', H, P2, { expiresAt: day() })
    const shortening = await reconcileRelations({ from: from2, to: to2, partition: P2, toConfig: contractDenyRelationsConfig() })
    assert.lengthOf(shortening.partitionsRefused ?? [], 1)
    assert.isUndefined(shortening.partitionsRefused![0].evolves)
  })

  test('⚪ D5-3 (cierre 6 de D2) · E4: la receta de la partición negada NO ofrece «SIN caducidad en el ORIGEN» como salida (medido: la 2.ª pasada sigue NEGADA) y nombra las salidas reales — unrelate en el ORIGEN (medido: la partición migra), unrelate + relate en el DESTINO aceptando la ventana, o esperar a la caducidad vieja', async ({ assert }) => {
    const setup = async () => {
      const P = part()
      const U = user()
      const X = doc()
      const H = g()
      const to = double()
      // El ORIGEN renueva en una escritura (atomicRenewal, como database): aplicar la receta en él no es un 409.
      const from = double(contractDenyRelationsConfig(), { ...FULL, atomicRenewal: true })
      for (const side of [from, to]) await side.deny!(member(H), 'viewer', X, P)
      await from.relate(U, 'member', H, P, { expiresAt: day() })
      await to.relate(U, 'member', H, P, { expiresAt: hour() })
      return { P, U, H, from, to }
    }
    const recipe = partitionRefusalRecipe(['renewal-unsafe'])
    assert.include(recipe, 'NO desbloquea la partición')
    assert.include(recipe, 'unrelate de esa membresía en el ORIGEN')
    assert.include(recipe, 'unrelate + relate de esa membresía en el DESTINO')
    assert.include(recipe, 'Esperar a que venza la caducidad vieja del DESTINO')
    assert.include(recipe, 'Para el FUTURO, el patrón recomendado')
    {
      const { P, U, H, from, to } = await setup()
      assert.lengthOf((await reconcileRelations({ from, to, partition: P, toConfig: contractDenyRelationsConfig() })).partitionsRefused ?? [], 1)
      await from.relate(U, 'member', H, P, { expiresAt: null })
      const second = await reconcileRelations({ from, to, partition: P, toConfig: contractDenyRelationsConfig() })
      assert.lengthOf(second.partitionsRefused ?? [], 1, 'SIN caducidad en el ORIGEN no desbloquea (1 h frente a null sigue siendo un cambio)')
    }
    {
      const { P, U, H, from, to } = await setup()
      await from.unrelate(U, 'member', H, P)
      const after = await reconcileRelations({ from, to, partition: P, toConfig: contractDenyRelationsConfig() })
      assert.lengthOf(after.partitionsRefused ?? [], 0, 'unrelate en el ORIGEN: la partición ya no se niega')
    }
  })

  test('⚪ D4-4 · la letra de «orden SIN garantía» cubre las RENOVACIONES y el instante POSTERIOR', ({ assert }) => {
    const { lines } = relationsReconcileLines({
      dryRun: false, written: 2, deleted: 0, updated: 0, unchanged: 0, extra: 0, modelDrift: [], massDelete: false,
      skipped: { expired: 0, undeclared: 0 }, orderResidue: ['unit|x group:g#member@user:u', 'unit|x group:h#member@user:u'],
    } as any)
    const warning = lines.find((l) => l.message.startsWith('orden SIN garantía:'))!
    assert.include(warning.message, 'RENOVACIÓN')
    assert.include(warning.message, 'instante posterior')
    assert.notInclude(warning.message, 'entra o sale a la vez')
  })
})
