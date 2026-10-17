/**
 * **Guardia del linaje L9 — «clasificación en el punto equivocado»** (plan 2.5 · lote D · D2; decisión del dueño
 * 2026-10-15 (7); `linajes.md`: R2-5 → lote B decisión 4 → cierre 3 N9). Propiedad universal: *el PLAN clasifica toda
 * tupla por su motivo antes del driver; el driver solo rechaza; ningún catch convierte un 422 en otro bucket*.
 *
 *  1. POR REFLEXIÓN: toda clase de `src/errors.ts` con `status === 422` que nombra un fichero del puerto de relaciones
 *     (`src/relations/` salvo el propio registro, `src/shared/` entero —⚪ 7 del cierre 1 de D2—, los dos drivers de
 *     relaciones, el doble publicado y `src/identity.ts`)
 *     tiene UNA entrada en `RELATION_REJECTIONS` — una clase nueva sin clasificar nace ROJA con su nombre; una entrada
 *     sin clase es rancia —, y `RELATION_422_REASONS` (la capa 2 del cierre 3 del lote B) es EXACTAMENTE lo derivado.
 *  2. Cada entrada `classified`/`refused` tiene un caso EJECUTABLE aquí que la provoca: el plan la clasifica (o niega la
 *     pasada) sin pedirle al driver la tupla, con los MISMOS números en `--dry-run` y en la pasada real.
 *  3. Un 422 que NO es de la familia nunca se absorbe en la poda (se propaga).
 */
import { test } from '@japa/runner'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { v7 as uuidv7 } from 'uuid'
import * as errors from '../src/errors.js'
import { RELATION_422_REASONS, RELATION_REJECTIONS, RELATION_RESIDUES, RELATIONS_RECONCILE_DETAIL_REASONS, reconcileRelations } from '../src/relations/reconcile.js'
import { contractDenyRelationsConfig, makeRelationsDriver, RELATIONS_HOLDER_TYPES } from '../src/testing/relations_contract.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import type { RelationsConfig } from '../src/relations/define_relations_config.js'
import type { RelationTuple, RelationsDriver, RelationsDriverCapabilities, ScopeRef } from '../src/types.js'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
/** Los ficheros del PUERTO de relaciones (fuente), menos el registro mismo (que importa todas las clases que clasifica). */
function portSources(): Array<{ file: string; text: string }> {
  const relations = readdirSync(path.join(ROOT, 'src/relations'))
    .filter((f) => f.endsWith('.ts') && f !== 'reconcile.ts')
    .map((f) => `src/relations/${f}`)
  // ⚪ 7 (cierre 1 de D2): `src/shared/` ENTERO — lo importan los dos drivers de relaciones (`withDeadline`, `guardSql`,
  // `isServerWriteLimit`…), así que un 422 que naciera ahí llegaría al puerto sin pasar por los ficheros de arriba (el
  // auditor lo midió: una clase nombrada SOLO en `backend_guard.ts` dejaba la guardia en verde).
  const shared = readdirSync(path.join(ROOT, 'src/shared'))
    .filter((f) => f.endsWith('.ts'))
    .map((f) => `src/shared/${f}`)
  const files = [
    ...relations,
    ...shared,
    'src/relations_reconcile.ts',
    'src/drivers/database_relations_driver.ts',
    'src/drivers/openfga_relations_driver.ts',
    'src/testing/relations_contract.ts',
    'src/identity.ts',
  ]
  return files.map((file) => ({ file, text: readFileSync(path.join(ROOT, file), 'utf8') }))
}

/** Las clases 422 de `src/errors.ts`, POR REFLEXIÓN sobre el módulo (no una lista a mano). */
function classes422(): Array<{ name: string; code: string }> {
  return Object.entries(errors)
    .filter(([, value]) => typeof value === 'function' && (value as any).status === 422 && typeof (value as any).code === 'string')
    .map(([name, value]) => ({ name, code: (value as any).code }))
}

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
const RELS = [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }]
const holderTypes = [...RELATIONS_HOLDER_TYPES]
const P = (): ScopeRef => ({ type: 'unit', uuid: uuidv7() })
const U = () => ({ type: 'user', uuid: uuidv7() })

function spiedWrites(driver: RelationsDriver) {
  const log: string[] = []
  const proxy = new Proxy(driver as any, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target)
      if (typeof prop === 'string' && ['relate', 'unrelate', 'deny', 'removeDeny'].includes(prop) && typeof value === 'function') {
        return async (...args: any[]) => {
          log.push(`${prop} ${args[2].type}#${args[1]}`)
          return value.apply(target, args)
        }
      }
      return typeof value === 'function' ? value.bind(target) : value
    },
  })
  return { driver: proxy as RelationsDriver, log }
}

function fakeSource(tuples: RelationTuple[]): RelationsDriver {
  const no = async () => {
    throw new Error('solo enumera')
  }
  return {
    capabilities: FULL,
    relate: no,
    unrelate: no,
    check: no as any,
    listObjects: no as any,
    listSubjects: no as any,
    purgeObject: no,
    purgeSubject: no,
    enumerateRelations: async (partition: ScopeRef) => ({ tuples: tuples.map((t) => ({ ...t, partition })) }),
  }
}

/** Corre la MISMA pasada en `--dry-run` y real (con `prune`); devuelve los dos reportes (o errores) y lo que se escribió. */
async function both(make: () => Promise<{ from: RelationsDriver; to: RelationsDriver; partition: ScopeRef; toConfig?: RelationsConfig }>) {
  const run = async (dryRun: boolean) => {
    const { from, to, partition, toConfig } = await make()
    const spy = spiedWrites(to)
    const outcome = await reconcileRelations({ from, to: spy.driver, partition, toConfig, prune: true, dryRun }).then(
      (report) => ({ report, error: null as any }),
      (error) => ({ report: null as any, error })
    )
    return { ...outcome, log: spy.log }
  }
  return { dry: await run(true), real: await run(false) }
}

/**
 * **Un caso EJECUTABLE por entrada `classified`/`refused`** (punto 2). Cada uno provoca el 422 de su clase en el
 * DRIVER (si se le pidiera la tupla) y afirma que el plan la clasificó antes: el `log` del destino no tiene la escritura
 * de esa tupla, y el bucket/motivo es el del registro, con los mismos números en `--dry-run` y real.
 */
const FIXTURES: Record<string, (assert: any) => Promise<void>> = {
  [errors.RelationTypeUnknownError.code]: async (assert) => {
    // El destino es un driver con `note` declarado; `toConfig` (lo que el destino declara de verdad) ya no lo tiene.
    const toConfig = defineRelationsConfig({ objectTypes: [{ type: 'document', relations: RELS }], holderTypes })
    const wide = defineRelationsConfig({ objectTypes: ['document', 'note'].map((type) => ({ type, relations: RELS })), holderTypes })
    const { dry, real } = await both(async () => {
      const partition = P()
      const from = makeRelationsDriver({ config: wide, capabilities: FULL })
      const to = makeRelationsDriver({ config: wide, capabilities: FULL })
      await from.relate(U(), 'viewer', { type: 'document', id: uuidv7() }, partition)
      await from.relate(U(), 'viewer', { type: 'note', id: uuidv7() }, partition)
      await to.relate(U(), 'viewer', { type: 'note', id: uuidv7() }, partition)
      return { from, to, partition, toConfig }
    })
    for (const { report, log } of [dry, real]) {
      assert.equal(report.skipped.undeclared, 1, 'origen: skipped.undeclared')
      assert.deepEqual(report.details.map((d: any) => `${d.side}:${d.reason}`), ['destino:undeclared'])
      assert.isFalse(log.some((l) => l.includes('note#')), `el driver nunca recibió la tupla de note: ${log}`)
    }
  },
  [errors.RelationUnknownError.code]: async (assert) => {
    const toConfig = defineRelationsConfig({ objectTypes: [{ type: 'document', relations: RELS }], holderTypes })
    const wide = defineRelationsConfig({ objectTypes: [{ type: 'document', relations: [...RELS, { name: 'approver' }] }], holderTypes })
    const { dry, real } = await both(async () => {
      const partition = P()
      const from = makeRelationsDriver({ config: wide, capabilities: FULL })
      const to = makeRelationsDriver({ config: wide, capabilities: FULL })
      await from.relate(U(), 'viewer', { type: 'document', id: uuidv7() }, partition)
      await from.relate(U(), 'approver', { type: 'document', id: uuidv7() }, partition)
      await to.relate(U(), 'approver', { type: 'document', id: uuidv7() }, partition)
      return { from, to, partition, toConfig }
    })
    for (const { report, log } of [dry, real]) {
      assert.equal(report.skipped.undeclared, 1)
      assert.deepEqual(report.details.map((d: any) => `${d.side}:${d.reason}`), ['destino:undeclared'])
      assert.isFalse(log.some((l) => l.includes('#approver')), `el driver nunca recibió approver: ${log}`)
    }
  },
  [errors.RelationUsersetUnsupportedError.code]: async (assert) => {
    const config = contractDenyRelationsConfig()
    const { dry, real } = await both(async () => {
      const partition = P()
      const from = fakeSource([
        { subject: U(), relation: 'viewer', object: { type: 'document', id: uuidv7() }, partition },
        { subject: { object: { type: 'document', id: uuidv7() }, relation: 'viewer' }, relation: 'viewer', object: { type: 'document', id: uuidv7() }, partition },
      ])
      return { from, to: makeRelationsDriver({ config, capabilities: FULL }), partition }
    })
    for (const { report, log } of [dry, real]) {
      assert.equal(report.skipped.usersetUnsupported, 1)
      assert.deepEqual(report.details.map((d: any) => `${d.side}:${d.reason}`), ['origen:userset-unsupported'])
      assert.lengthOf(log.filter((l) => l.startsWith('relate')), report.dryRun ? 0 : 1, 'solo la buena llega al driver')
    }
  },
  [errors.InvalidIdentityError.code]: async (assert) => {
    const config = contractDenyRelationsConfig()
    const { dry, real } = await both(async () => {
      const partition = P()
      const from = fakeSource([
        { subject: U(), relation: 'viewer', object: { type: 'document', id: uuidv7() }, partition },
        { subject: U(), relation: 'viewer', object: { type: 'document', id: 'A#B' }, partition },
      ])
      return { from, to: makeRelationsDriver({ config, capabilities: FULL }), partition }
    })
    for (const { report } of [dry, real]) {
      assert.equal(report.skipped.invalid, 1)
      assert.deepEqual(report.details.map((d: any) => `${d.side}:${d.reason}`), ['origen:invalid-identity'])
    }
    assert.lengthOf(real.log, 1)
  },
  [errors.RelationNotDenyableError.code]: async (assert) => {
    // El origen deniega en `workspace` (fase 'write' en SU config); el destino lo tiene en 'read' ⇒ su `deny` lanzaría
    // NOT_DENYABLE: el plan lo pregunta antes (`denyPhase`) y NIEGA la pasada con cero escrituras.
    const source = defineRelationsConfig({
      objectTypes: ['document', 'workspace', 'note'].map((type) => ({ type, relations: RELS, deny: 'write' as const })),
      holderTypes,
    })
    const { dry, real } = await both(async () => {
      const partition = P()
      const from = makeRelationsDriver({ config: source, capabilities: FULL })
      const u = U()
      const ws = { type: 'workspace', id: uuidv7() }
      await from.relate(u, 'viewer', ws, partition)
      await from.deny!(u, 'viewer', ws, partition)
      return { from, to: makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: FULL }), partition }
    })
    assert.deepEqual(dry.report.denyRefused.map((r: any) => r.reason), [RELATION_REJECTIONS[errors.RelationNotDenyableError.code].kind === 'refused' ? 'phase' : '?'])
    assert.equal(real.error?.code, 'E_AUTHZ_DENY_MIGRATION_REFUSED')
    assert.deepEqual(real.error?.refusals?.map((r: any) => r.reason), ['phase'])
    assert.deepEqual(real.log, [], 'CERO escrituras')
  },
}

test.group('L9 · guardia de clasificación por reflexión sobre las clases 422 del puerto de relaciones', () => {
  test('toda clase 422 que nombra el puerto de relaciones está clasificada en RELATION_REJECTIONS (y ninguna entrada es rancia)', ({ assert }) => {
    const sources = portSources()
    const referenced = classes422().filter(({ name }) => sources.some(({ text }) => new RegExp(`\\b${name}\\b`).test(text)))
    assert.isAbove(referenced.length, 5, 'la reflexión encuentra las clases (si no, el escáner está roto)')
    const missing = referenced.filter(({ code }) => !Object.hasOwn(RELATION_REJECTIONS, code)).map(({ name, code }) => `${name} (${code})`)
    assert.deepEqual(missing, [], `ROJO (L9): 422 del puerto de relaciones SIN clasificar en RELATION_REJECTIONS (src/relations/reconcile.ts): ${missing.join(', ')} — decide su bucket + details en el plan, o por qué es inalcanzable`)
    const codes = new Set(referenced.map(({ code }) => code))
    const stale = Object.keys(RELATION_REJECTIONS).filter((code) => !codes.has(code))
    assert.deepEqual(stale, [], `ROJO (L9): entradas rancias en RELATION_REJECTIONS (ninguna clase 422 del puerto las lanza): ${stale.join(', ')}`)
    for (const [code, entry] of Object.entries(RELATION_REJECTIONS)) {
      if (entry.kind === 'unreachable') assert.isAbove(entry.why.length, 20, `${code}: «inalcanzable» con su porqué`)
      else assert.isAbove(entry.where.length, 10, `${code}: dónde lo clasifica el plan`)
    }
  })

  test('RELATION_422_REASONS (capa 2 de la poda) es EXACTAMENTE lo derivado de las entradas classified del registro', ({ assert }) => {
    const derived = Object.fromEntries(Object.entries(RELATION_REJECTIONS).flatMap(([code, e]) => (e.kind === 'classified' ? [[code, e.reason]] : [])))
    assert.deepEqual({ ...RELATION_422_REASONS }, derived)
  })

  test('cada entrada classified/refused del registro tiene su caso EJECUTABLE aquí (FIXTURES), y ninguno sobra', ({ assert }) => {
    const wanted = Object.entries(RELATION_REJECTIONS).filter(([, e]) => e.kind !== 'unreachable').map(([code]) => code)
    assert.deepEqual(
      wanted.filter((code) => !FIXTURES[code]),
      [],
      'ROJO (L9): entradas del registro sin caso que las ejecute en FIXTURES'
    )
    assert.deepEqual(Object.keys(FIXTURES).filter((code) => !wanted.includes(code)), [], 'FIXTURES de códigos que el registro no clasifica')
  })

  for (const [code, entry] of Object.entries(RELATION_REJECTIONS)) {
    if (entry.kind === 'unreachable') continue
    test(`L9 · ${code} ⇒ ${entry.kind === 'classified' ? `bucket '${entry.reason}'` : `negativa '${entry.refusal}'`} en el PLAN, sin pedirle la tupla al driver, mismos números en --dry-run y real`, async ({ assert }) => {
      const fixture = FIXTURES[code]
      assert.isFunction(fixture, `ROJO (L9): ${code} sin caso`)
      await fixture(assert)
    })
  }

  test('L9 · la poda NO absorbe un 422 de fuera de la familia (RelationNotDenyable en unrelate ⇒ se propaga)', async ({ assert }) => {
    const config = contractDenyRelationsConfig()
    const from = makeRelationsDriver({ config, capabilities: FULL })
    const base = makeRelationsDriver({ config, capabilities: FULL })
    const partition = P()
    await from.relate(U(), 'viewer', { type: 'document', id: uuidv7() }, partition)
    await base.relate(U(), 'viewer', { type: 'document', id: uuidv7() }, partition)
    const to = new Proxy(base as any, {
      get(target, prop) {
        if (prop === 'unrelate') return async () => {
          throw new errors.RelationNotDenyableError('un 422 que no es de la familia de la poda')
        }
        const value = Reflect.get(target, prop, target)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const error = await reconcileRelations({ from, to, partition, prune: true }).then(
      () => null,
      (e) => e
    )
    assert.equal(error?.code, 'E_AUTHZ_RELATION_NOT_DENYABLE', 'se propaga: ningún catch lo convierte en residuo')
  })
})

/**
 * **Cierre 2 de D2 · ⚪ N6: los RESIDUOS que no son 422** (`deny-conditional`, que se clasifica por un `catch` en la
 * PASADA, y `renewal-unsafe`, en el PLAN): la guardia L9 recorre `RELATIONS_RECONCILE_DETAIL_REASONS` (los motivos en
 * runtime) y exige su entrada en `RELATION_RESIDUES` con DÓNDE se clasifica y, si es en la pasada, la excepción al punto
 * 2 escrita. Un caso EJECUTABLE por cada motivo que no tiene ya el suyo en la parte de los 422.
 */
const RESIDUE_FIXTURES: Partial<Record<string, (assert: any) => Promise<void>>> = {
  'renewal-unsafe': async (assert) => {
    const config = contractDenyRelationsConfig()
    const { dry, real } = await both(async () => {
      const partition = P()
      const u = U()
      const d = { type: 'document', id: uuidv7() }
      const g = { type: 'group', id: uuidv7() }
      const from = makeRelationsDriver({ config, capabilities: FULL })
      const to = makeRelationsDriver({ config, capabilities: FULL })
      for (const side of [from, to]) {
        await side.relate(u, 'viewer', d, partition)
        await side.deny!({ object: g, relation: 'member' }, 'viewer', d, partition)
      }
      await from.relate(u, 'member', g, partition)
      await to.relate(u, 'member', g, partition, { expiresAt: new Date(Date.now() + 3_600_000) })
      return { from, to, partition, toConfig: config }
    })
    for (const { report, log } of [dry, real]) {
      assert.equal(report.updated, 0)
      assert.deepEqual(report.details.map((d: any) => `${d.side}:${d.reason}`), ['destino:renewal-unsafe'])
      // Cierre 5 de D2 (opción A): y su PARTICIÓN queda negada (cero escrituras en ella), decidido en el PLAN.
      assert.deepEqual((report.partitionsRefused ?? []).map((x: any) => x.causes.map((c: any) => c.reason)), [['renewal-unsafe']])
      assert.isFalse(log.some((l) => l.startsWith('relate group#member')), `el driver nunca recibió la renovación: ${log}`)
    }
  },
  'deny-conditional': async (assert) => {
    // El destino es un doble que NO sabe rehacer un deny condicional (como openfga, M5): su `deny` lanza el 500 marcado.
    const config = contractDenyRelationsConfig()
    const { dry, real } = await both(async () => {
      const partition = P()
      const u = U()
      const d = { type: 'document', id: uuidv7() }
      const from = makeRelationsDriver({ config, capabilities: FULL })
      const base = makeRelationsDriver({ config, capabilities: FULL })
      await from.deny!(u, 'viewer', d, partition)
      await base.deny!(u, 'viewer', d, partition)
      const to = new Proxy(base as any, {
        get(target, prop) {
          if (prop === 'enumerateRelations') {
            return async (...args: any[]) => {
              const page = await target.enumerateRelations(...args)
              return { ...page, tuples: page.tuples.map((t: any) => (t.kind === 'deny' ? { ...t, expiresAt: new Date(Date.now() + 3_600_000) } : t)) }
            }
          }
          if (prop === 'deny') return async () => {
            throw Object.assign(errors.AuthorizationConfigError.conditionalDeny('deny', 'document#denied_viewer'), {})
          }
          const value = Reflect.get(target, prop, target)
          return typeof value === 'function' ? value.bind(target) : value
        },
      }) as RelationsDriver
      return { from, to, partition, toConfig: config }
    })
    // Cierre 4 de D2 · 🟡 C3-2: ya no es la EXCEPCIÓN al punto 2 — lo decide el PLAN (sin atomicRenewal): mismos números.
    for (const { report, log } of [dry, real]) {
      assert.equal(report.denies.updated, 0)
      assert.deepEqual(report.details.map((d: any) => `${d.side}:${d.reason}`), ['destino:deny-conditional'])
      assert.deepEqual((report.partitionsRefused ?? []).map((x: any) => x.causes.map((c: any) => c.reason)), [['deny-conditional']])
      assert.isFalse(log.some((l) => l.startsWith('deny')), `el driver nunca recibió el deny: ${log}`)
    }
  },
}

test.group('L9 · cierre 2 de D2 · ⚪ N6 · los residuos que no son 422 (deny-conditional, renewal-unsafe) también están en la guardia', () => {
  test('RELATION_RESIDUES tiene EXACTAMENTE una entrada por motivo de RelationsReconcileDetail (por reflexión sobre RELATIONS_RECONCILE_DETAIL_REASONS); las de la PASADA declaran su porqué; las que el registro de 422 clasifica son del PLAN', ({ assert }) => {
    assert.sameMembers(Object.keys(RELATION_RESIDUES), [...RELATIONS_RECONCILE_DETAIL_REASONS], 'ROJO (L9 · N6): un motivo sin entrada (o una entrada rancia)')
    for (const [reason, entry] of Object.entries(RELATION_RESIDUES)) {
      assert.isAbove(entry.how.length, 10, `${reason}: dónde`)
      if (entry.where === 'pass') assert.isAbove((entry as any).why.length, 20, `${reason}: la excepción al punto 2, escrita`)
    }
    for (const entry of Object.values(RELATION_REJECTIONS)) {
      if (entry.kind === 'classified') assert.equal(RELATION_RESIDUES[entry.reason].where, 'plan', `${entry.reason}: clasificado por el registro de 422 ⇒ en el PLAN`)
    }
    // Cierre 4 de D2 · 🟡 C3-2: `deny-conditional` pasó al PLAN — ya no queda ninguna excepción al punto 2.
    assert.deepEqual(Object.entries(RELATION_RESIDUES).filter(([, e]) => e.where === 'pass').map(([r]) => r), [], 'ninguna excepción declarada')
  })

  test('cada motivo tiene su caso EJECUTABLE: los de 422 en FIXTURES (arriba) y los demás en RESIDUE_FIXTURES', ({ assert }) => {
    const covered422 = new Set(Object.values(RELATION_REJECTIONS).flatMap((e) => (e.kind === 'classified' ? [e.reason] : [])))
    const missing = RELATIONS_RECONCILE_DETAIL_REASONS.filter((r) => !covered422.has(r) && !RESIDUE_FIXTURES[r])
    assert.deepEqual(missing, [], 'ROJO (L9 · N6): motivos sin caso')
  })

  for (const reason of Object.keys(RESIDUE_FIXTURES)) {
    test(`L9 · N6 · ${reason} ⇒ ${RELATION_RESIDUES[reason as keyof typeof RELATION_RESIDUES]?.where === 'plan' ? 'en el PLAN, mismos números en --dry-run y real' : 'en la PASADA (excepción declarada: --dry-run no lo ve)'}`, async ({ assert }) => {
      await RESIDUE_FIXTURES[reason]!(assert)
    })
  }
})
