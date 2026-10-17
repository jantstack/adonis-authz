/**
 * **Plan 2.5 · lote D · D2 — banderas y ramas con EFECTO, por el KERNEL de ace** (CLAUDE.md puntos 6, 7 y 9; entra en
 * `scripts/check_flag_mutants.mjs` por el nombre `command_flags*`).
 *
 *  1. `openfga:provision --store-id … [--allow-drop-deny]` — la guarda contra la MUTILACIÓN del modelo (analista §4.6,
 *     juez ronda 2 · R2-4 c / H3). La bandera era `pending` en el manifiesto de mutantes de banderas: aquí tiene su caso
 *     de EFECTO (con la bandera y un store sin denies vivos se publica; sin ella, exit 1 y CERO escrituras), SIN servidor
 *     (un OpenFGA de mentira en memoria que sirve los tres endpoints que el comando toca), para que el job sin OpenFGA lo
 *     juzgue.
 *  2. D-27 · T3 del tester por el kernel con la bandera de verdad: `authz:relations:reconcile` con denies (línea y exit
 *     propios por rama, prefijos estables «denies:», «deny NO migrable», «pasada PARCIAL:»).
 */
import { test } from '@japa/runner'
import http from 'node:http'
import { v7 as uuidv7 } from 'uuid'
import { aceFor } from './helpers/ace.js'
import authorization from '../services/main.js'
import { AuthorizationManager } from '../src/manager.js'
import { openFgaFactsModel } from '../src/drivers/openfga_facts.js'
import { contractDenyRelationsConfig, makeRelationsDriver } from '../src/testing/relations_contract.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { countLiveDenies, droppedDenyRelations } from '../commands/openfga_provision.js'
import { readFileSync } from 'node:fs'
import OpenFgaProvision from '../commands/openfga_provision.js'
import AuthzRelationsReconcile from '../commands/authz_relations_reconcile.js'
import type { RelationsDriver, RelationsDriverCapabilities } from '../src/types.js'

/* ── Un OpenFGA de MENTIRA en memoria (los tres endpoints de provision --store-id) ─────────────────────────── */

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
let ulidSeq = 0
const ulid = () => `01J${String(++ulidSeq).padStart(23, '0').split('').map((c) => CROCKFORD[Number(c)]).join('')}`

interface FakeFga {
  url: string
  storeId: string
  models: any[]
  tuples: Array<{ user: string; relation: string; object: string }>
  seen: string[]
  /** Cierre 1 de D2 · 🟠 2: se llama al servir la ÚLTIMA página de cada barrido completo (n = 1, 2, …) — la carrera. */
  onSweepEnd?: (n: number) => void
  /** Cierre 1 de D2 · ⚪ 10 c: desde el `read` número N (1-based) todo `read` responde 500 (el barrido falla a medias). */
  failReadAt?: number
  close(): Promise<void>
}

async function fakeFga(): Promise<FakeFga> {
  const state: FakeFga = { url: '', storeId: ulid(), models: [], tuples: [], seen: [], close: async () => {} }
  let sweeps = 0
  let reads = 0
  const server = http.createServer((req, res) => {
    let body = ''
    req.on('data', (c) => (body += c))
    req.on('end', () => {
      state.seen.push(`${req.method} ${req.url?.split('?')[0]}`)
      const send = (code: number, json: unknown) => {
        res.statusCode = code
        res.setHeader('content-type', 'application/json')
        res.end(JSON.stringify(json))
      }
      const base = `/stores/${state.storeId}`
      const path = req.url?.split('?')[0]
      if (req.method === 'GET' && path === `${base}/authorization-models`) {
        // Como el servidor: del más RECIENTE al más antiguo, paginado (`page_size`, `continuation_token`).
        const query = new URLSearchParams(req.url?.split('?')[1] ?? '')
        const size = Number(query.get('page_size') ?? 50)
        const from = Number(query.get('continuation_token') || 0)
        const all = [...state.models].reverse()
        const next = from + size < all.length ? String(from + size) : ''
        return send(200, { authorization_models: all.slice(from, from + size), continuation_token: next })
      }
      if (req.method === 'POST' && path === `${base}/authorization-models`) {
        const id = ulid()
        state.models.push({ id, ...JSON.parse(body || '{}') })
        return send(201, { authorization_model_id: id })
      }
      if (req.method === 'POST' && path === `${base}/read`) {
        const { page_size = 50, continuation_token } = JSON.parse(body || '{}')
        const from = continuation_token ? Number(continuation_token) : 0
        if (state.failReadAt !== undefined && ++reads >= state.failReadAt) return send(500, { code: 'internal_error', message: 'fake: el barrido muere a medias' })
        const slice = state.tuples.slice(from, from + page_size)
        const next = from + page_size < state.tuples.length ? String(from + page_size) : ''
        send(200, { tuples: slice.map((key) => ({ key, timestamp: new Date().toISOString() })), continuation_token: next })
        if (!next) state.onSweepEnd?.(++sweeps)
        return
      }
      return send(400, { code: 'validation_error', message: `fake: ${req.method} ${path} no está servido` })
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  state.url = `http://127.0.0.1:${(server.address() as any).port}`
  state.close = () => new Promise((resolve) => server.close(() => resolve()))
  return state
}

const HOLDERS = { users: 'user' }
const PERMISSIONS = ['posts.read']
const RELS = [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }]
const withDeny = () => defineRelationsConfig({ objectTypes: [{ type: 'document', relations: RELS, deny: 'write' }], holderTypes: ['user'] })
const withoutDeny = () => defineRelationsConfig({ objectTypes: [{ type: 'document', relations: RELS }], holderTypes: ['user'] })
const provisionConfig = (url: string, relations: any) => ({
  holderTypes: HOLDERS,
  catalogs: [async () => ({ permissions: PERMISSIONS.map((slug) => ({ slug })) })],
  openfga: { url },
  relations: { config: relations },
})

test.group('D2 · `openfga:provision --store-id [--allow-drop-deny]` — la guarda contra la mutilación del modelo (por el kernel, sin servidor)', (group) => {
  let fga: FakeFga
  group.each.setup(async () => {
    fga = await fakeFga()
    // El store ya sirve el modelo CON el deny de document (fase ≥ 1).
    fga.models.push({ id: ulid(), ...openFgaFactsModel(HOLDERS, PERMISSIONS, { objectTypes: withDeny().objectTypes }) })
    return () => fga.close()
  })

  test('droppedDenyRelations (pura): quitar el opt-in quita document#denied_*; los denied_<P> de scope (roles) no cuentan', ({ assert }) => {
    const current = openFgaFactsModel(HOLDERS, PERMISSIONS, { objectTypes: withDeny().objectTypes })
    assert.deepEqual(droppedDenyRelations(current, openFgaFactsModel(HOLDERS, PERMISSIONS, { objectTypes: withoutDeny().objectTypes })), [
      'document#denied_editor',
      'document#denied_owner',
      'document#denied_viewer',
    ])
    assert.deepEqual(droppedDenyRelations(current, current), [])
    assert.deepEqual(droppedDenyRelations(current, openFgaFactsModel(HOLDERS, [], { objectTypes: withDeny().objectTypes })), [], 'retirar un permiso no es retirar un opt-in de relaciones')
  })

  test('SIN --allow-drop-deny: un modelo que quita denied_* ⇒ exit 1, «provision NEGADO:», CERO escrituras (ningún POST de modelo)', async ({ assert }) => {
    const run = await (await aceFor(OpenFgaProvision, { authorization: provisionConfig(fga.url, withoutDeny()) })).exec([`--store-id=${fga.storeId}`])
    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(run.exitCode, 1, JSON.stringify(run.logs))
    const text = run.logs.join('\n')
    assert.include(text, 'provision NEGADO: el modelo nuevo QUITA document#denied_editor, document#denied_owner, document#denied_viewer')
    assert.include(text, '--allow-drop-deny')
    assert.lengthOf(fga.models, 1, 'no se escribió ningún modelo')
    assert.notInclude(fga.seen.join(' '), `POST /stores/${fga.storeId}/authorization-models`)
  })

  test('CON --allow-drop-deny y el store SIN denies vivos de esas relaciones ⇒ barre, publica (exit 0) y lo dice — el EFECTO de la bandera', async ({ assert }) => {
    fga.tuples.push({ user: 'user:u1', relation: 'viewer', object: 'document:app|d1' })
    const run = await (await aceFor(OpenFgaProvision, { authorization: provisionConfig(fga.url, withoutDeny()) })).exec([
      `--store-id=${fga.storeId}`,
      '--allow-drop-deny',
    ])
    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(run.exitCode ?? 0, 0, JSON.stringify(run.logs))
    assert.lengthOf(fga.models, 2, 'el modelo nuevo se publicó')
    assert.isTrue(run.logs.some((l) => l.includes('--allow-drop-deny: el modelo nuevo quita') && l.includes('0 denies vivos')), JSON.stringify(run.logs))
    assert.include(fga.seen.join(' '), `POST /stores/${fga.storeId}/read`, 'barrió el store antes de publicar')
  })

  test('CON --allow-drop-deny y un deny VIVO de esas relaciones ⇒ exit 1 que los cuenta, CERO escrituras (la bandera nunca apaga denies vivos)', async ({ assert }) => {
    fga.tuples.push({ user: 'user:u1', relation: 'viewer', object: 'document:app|d1' })
    fga.tuples.push({ user: 'user:u1', relation: 'denied_viewer', object: 'document:app|d1' })
    const run = await (await aceFor(OpenFgaProvision, { authorization: provisionConfig(fga.url, withoutDeny()) })).exec([
      `--store-id=${fga.storeId}`,
      '--allow-drop-deny',
    ])
    assert.isUndefined(run.error, run.error?.message)
    assert.equal(run.exitCode, 1)
    assert.isTrue(run.logs.some((l) => l.includes('provision NEGADO: --allow-drop-deny no apaga denies VIVOS: el store tiene 1 deny(s)')), JSON.stringify(run.logs))
    assert.lengthOf(fga.models, 1)
  })

  test('un modelo que NO quita ningún denied_* publica sin la bandera (la guarda no estorba): exit 0, sin barrido', async ({ assert }) => {
    const run = await (await aceFor(OpenFgaProvision, { authorization: provisionConfig(fga.url, withDeny()) })).exec([`--store-id=${fga.storeId}`])
    assert.isUndefined(run.error, run.error?.message)
    assert.equal(run.exitCode ?? 0, 0, JSON.stringify(run.logs))
    assert.lengthOf(fga.models, 2)
    assert.notInclude(fga.seen.join(' '), '/read')
  })

  test('🟡 3 (cierre 1 de D2) · la guarda juzga el ESTADO del store, no el último modelo: con un modelo INTERMEDIO sin denied_* (un alpha.10 publicado entre medias) y un deny VIVO, publicar sin el opt-in ⇒ exit 1 y CERO modelos; sin denies vivos publica (no hace falta la bandera: el opt-in ya se había retirado)', async ({ assert }) => {
    // El historial: el modelo con el deny (beforeEach) y, ENCIMA, uno publicado por un binario alpha.10 sin denied_*.
    fga.models.push({ id: ulid(), ...openFgaFactsModel(HOLDERS, PERMISSIONS, { objectTypes: withoutDeny().objectTypes }) })
    fga.tuples.push({ user: 'user:u1', relation: 'denied_viewer', object: 'document:app|d1' })
    const ace = await aceFor(OpenFgaProvision, { authorization: provisionConfig(fga.url, withoutDeny()) })
    const refused = await ace.exec([`--store-id=${fga.storeId}`])
    assert.isUndefined(refused.error, refused.error?.message)
    assert.equal(refused.exitCode, 1, JSON.stringify(refused.logs))
    assert.isTrue(refused.logs.some((l) => l.includes('provision NEGADO:') && l.includes('1 deny(s) VIVOS') && l.includes('document#denied_viewer')), JSON.stringify(refused.logs))
    assert.lengthOf(fga.models, 2, 'ningún modelo nuevo')
    fga.tuples.length = 0
    const allowed = await ace.exec([`--store-id=${fga.storeId}`])
    assert.equal(allowed.exitCode ?? 0, 0, JSON.stringify(allowed.logs))
    assert.lengthOf(fga.models, 3, 'sin denies vivos se publica')
  })

  test('🟠 2 (cierre 1 de D2) · TOCTOU: --allow-drop-deny vuelve a contar JUSTO antes de writeAuthorizationModel — un deny que llega tras el barrido (la flota aún en deny: «write») ⇒ exit 1 que lo dice y CERO modelos', async ({ assert }) => {
    fga.tuples.push({ user: 'user:u1', relation: 'viewer', object: 'document:app|d1' })
    // Un pod que sigue en 'write' escribe un deny en cuanto termina el PRIMER barrido.
    fga.onSweepEnd = (n) => {
      if (n === 1) fga.tuples.push({ user: 'user:u2', relation: 'denied_viewer', object: 'document:app|d1' })
    }
    const run = await (await aceFor(OpenFgaProvision, { authorization: provisionConfig(fga.url, withoutDeny()) })).exec([
      `--store-id=${fga.storeId}`,
      '--allow-drop-deny',
    ])
    assert.isUndefined(run.error, run.error?.message)
    assert.equal(run.exitCode, 1, JSON.stringify(run.logs))
    assert.isTrue(run.logs.some((l) => l.includes('provision NEGADO:') && l.includes('RECUENTO') && l.includes("deny: 'read'")), JSON.stringify(run.logs))
    assert.lengthOf(fga.models, 1, 'CERO modelos: no se publica con un deny vivo')
  })

  test('⚪ 10 c (cierre 1 de D2) · el barrido de --allow-drop-deny que FALLA a medias ⇒ exit 1 con el prefijo «provision NEGADO:» (nunca el error crudo del SDK), CERO modelos', async ({ assert }) => {
    for (let i = 0; i < 120; i++) fga.tuples.push({ user: `user:u${i}`, relation: 'viewer', object: 'document:app|d1' })
    fga.failReadAt = 2
    const run = await (await aceFor(OpenFgaProvision, { authorization: provisionConfig(fga.url, withoutDeny()) })).exec([
      `--store-id=${fga.storeId}`,
      '--allow-drop-deny',
    ])
    assert.isUndefined(run.error, `error crudo: ${run.error?.message}`)
    assert.equal(run.exitCode, 1)
    assert.isTrue(run.logs.some((l) => l.includes('provision NEGADO: el barrido del store')), JSON.stringify(run.logs))
    assert.lengthOf(fga.models, 1)
  }).timeout(30_000) // el SDK reintenta un 5xx con espera exponencial antes de rendirse

  test('el modelo ACTUAL ilegible ⇒ exit 1 «provision NEGADO: no se pudo leer», CERO escrituras (no se publica a ciegas)', async ({ assert }) => {
    const run = await (await aceFor(OpenFgaProvision, { authorization: provisionConfig(fga.url, withoutDeny()) })).exec([`--store-id=${ulid()}`])
    assert.isUndefined(run.error, run.error?.message)
    assert.equal(run.exitCode, 1)
    assert.isTrue(run.logs.some((l) => l.includes('provision NEGADO: no se pudo leer el modelo ACTUAL')), JSON.stringify(run.logs))
    assert.lengthOf(fga.models, 1)
  })
})

/* ── D-27 · T3 por el kernel: `authz:relations:reconcile` con denies ───────────────────────────────────────── */

function patchManager(method: string, impl: (...args: any[]) => any): () => void {
  const target: any = authorization
  const had = Object.prototype.hasOwnProperty.call(target, method)
  const previous = had ? Object.getOwnPropertyDescriptor(target, method) : undefined
  Object.defineProperty(target, method, { value: impl, writable: true, configurable: true, enumerable: false })
  return () => {
    if (previous) Object.defineProperty(target, method, previous)
    else delete target[method]
  }
}

/** Como `relationsAce` de `command_flags.spec`: los tres lectores de relaciones del manager de servicio, cableados a un config fixture. */
async function relationsAce(relations: any) {
  const fixture = new AuthorizationManager({ default: 'origen', drivers: {}, relations, warnOnOptInSecurity: false } as any)
  const ace = await aceFor(AuthzRelationsReconcile, {})
  return {
    async exec(argv: string[]) {
      const undo = ['relationsDriverKey', 'relationsDriverKeys', 'relationsDriverFactory'].map((m) => patchManager(m, (...a: any[]) => (fixture as any)[m](...a)))
      try {
        const run = await ace.exec(argv)
        return { ...run, text: run.logs.join('\n') }
      } finally {
        undo.reverse().forEach((r) => r())
      }
    },
  }
}

const CAPS: RelationsDriverCapabilities = {
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
const APP = { type: 'app', uuid: null } as const

function writesOf(driver: RelationsDriver, failAfter?: number) {
  const log: string[] = []
  const proxy = new Proxy(driver as any, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target)
      if (typeof prop === 'string' && ['relate', 'unrelate', 'deny', 'removeDeny'].includes(prop) && typeof value === 'function') {
        return async (...args: any[]) => {
          if (failAfter !== undefined && log.length >= failAfter) {
            const { AuthorizationBackendError } = await import('../src/errors.js')
            throw new AuthorizationBackendError('doble', 'reconcile', new Error('corte inyectado'))
          }
          log.push(`${prop} ${args[1]}`)
          return value.apply(target, args)
        }
      }
      return typeof value === 'function' ? value.bind(target) : value
    },
  })
  return { driver: proxy as RelationsDriver, log }
}

test.group('D2 · D-27 · T3 por el kernel: `authz:relations:reconcile` con denies (línea y exit propios por rama)', () => {
  test('deny vivo ⇒ exit 0, la línea «denies: escritos 1», el deny ANTES del allow y en el destino', async ({ assert }) => {
    const origen = makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: CAPS })
    const target = makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: CAPS })
    const destino = writesOf(target)
    const u = { type: 'user', uuid: uuidv7() }
    const d = { type: 'document', id: uuidv7() }
    await origen.relate(u, 'viewer', d, APP)
    await origen.deny!(u, 'viewer', d, APP)
    const run = await (await relationsAce({ drivers: { origen: () => origen, destino: () => destino.driver } })).exec(['--to=destino', '--from=origen'])
    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(run.exitCode ?? 0, 0, run.text)
    assert.include(run.text, 'denies: escritos 1, rehechos 0, borrados 0, iguales 0, sobran 0')
    assert.deepEqual(destino.log, ['deny viewer', 'relate viewer'])
    assert.isFalse(await target.check(u, 'viewer', d, APP))
  })

  test('S6 · destino SIN relationDenies ⇒ exit 1, la letra «deny NO migrable:», CERO escrituras; con --dry-run también exit 1 y la misma rama por línea', async ({ assert }) => {
    const origen = makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: CAPS })
    const target = makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: { ...CAPS, relationDenies: false } })
    const destino = writesOf(target)
    const u = { type: 'user', uuid: uuidv7() }
    await origen.relate(u, 'viewer', { type: 'document', id: uuidv7() }, APP)
    await origen.deny!(u, 'viewer', { type: 'document', id: uuidv7() }, APP)
    const ace = await relationsAce({ drivers: { origen: () => origen, destino: () => destino.driver } })
    const real = await ace.exec(['--to=destino', '--from=origen'])
    assert.isUndefined(real.error, `stack crudo: ${real.error?.message}`)
    assert.equal(real.exitCode, 1)
    assert.isTrue(real.logs.some((l: string) => l.includes('deny NO migrable: authz:relations:reconcile se NIEGA')), real.text)
    assert.deepEqual(destino.log, [], 'CERO escrituras (tampoco el allow)')
    const dry = await ace.exec(['--to=destino', '--from=origen', '--dry-run'])
    assert.equal(dry.exitCode, 1)
    assert.isTrue(dry.logs.some((l: string) => l.includes('deny NO migrable (no-capability) document#viewer')), dry.text)
    assert.include(dry.text, 'DERIVA')
  })

  test('--prune con un deny SOBRANTE ⇒ removeDeny (jamás unrelate), exit 0, «denies: … borrados 1»', async ({ assert }) => {
    const origen = makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: CAPS })
    const target = makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: CAPS })
    const u = { type: 'user', uuid: uuidv7() }
    await origen.relate(u, 'viewer', { type: 'document', id: uuidv7() }, APP)
    await target.deny!(u, 'editor', { type: 'document', id: uuidv7() }, APP)
    const destino = writesOf(target)
    const run = await (await relationsAce({ drivers: { origen: () => origen, destino: () => destino.driver } })).exec(['--to=destino', '--from=origen', '--prune'])
    assert.isUndefined(run.error, run.error?.message)
    assert.equal(run.exitCode ?? 0, 0, run.text)
    assert.include(run.text, 'borrados 1, iguales 0, sobran 0')
    assert.deepEqual(destino.log, ['relate viewer', 'removeDeny editor'])
  })

  test('--dry-run con un deny por escribir ⇒ exit 1 «DERIVA», CERO escrituras; sin la bandera escribe (efecto de --dry-run con denies)', async ({ assert }) => {
    for (const [argv, writes] of [
      [['--to=destino', '--from=origen', '--dry-run'], 0],
      [['--to=destino', '--from=origen'], 1],
    ] as const) {
      const origen = makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: CAPS })
      const destino = writesOf(makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: CAPS }))
      await origen.deny!({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, APP)
      const run = await (await relationsAce({ drivers: { origen: () => origen, destino: () => destino.driver } })).exec([...argv])
      assert.lengthOf(destino.log, writes, `${argv.join(' ')}: ${run.text}`)
      if (writes === 0) {
        assert.equal(run.exitCode, 1)
        assert.include(run.text, 'denies: escritos 1')
      }
    }
  })

  test('pasada CORTADA a mitad ⇒ exit 1, las líneas «pasada PARCIAL:» por partición y sin stack crudo', async ({ assert }) => {
    const origen = makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: CAPS })
    const destino = writesOf(makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: CAPS }), 1)
    const u = { type: 'user', uuid: uuidv7() }
    const d = { type: 'document', id: uuidv7() }
    await origen.relate(u, 'viewer', d, APP)
    await origen.deny!(u, 'viewer', d, APP)
    const run = await (await relationsAce({ drivers: { origen: () => origen, destino: () => destino.driver } })).exec(['--to=destino', '--from=origen'])
    assert.isUndefined(run.error, `stack crudo: ${run.error?.message}`)
    assert.equal(run.exitCode, 1)
    assert.isTrue(run.logs.some((l: string) => l.includes('pasada PARCIAL: partición app · REVENTÓ aquí') && l.includes('denies escritos 1')), run.text)
    assert.deepEqual(destino.log, ['deny viewer'], 'el deny entró, el allow no: denies de MÁS, nunca un allow sin su deny')
  })

  test('⚪ 10 (cierre 1 de D2) · pasada que revienta ANTES de escribir nada ⇒ exit 1 con la línea del error y SIN «PARCIAL» (ni en la letra ni en el reporte: partial solo con ≥ 1 escrita), sin stack crudo', async ({ assert }) => {
    const origen = makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: CAPS })
    const destino = writesOf(makeRelationsDriver({ config: contractDenyRelationsConfig(), capabilities: CAPS }), 0)
    const u = { type: 'user', uuid: uuidv7() }
    const d = { type: 'document', id: uuidv7() }
    await origen.relate(u, 'viewer', d, APP)
    await origen.deny!(u, 'viewer', d, APP)
    const run = await (await relationsAce({ drivers: { origen: () => origen, destino: () => destino.driver } })).exec(['--to=destino', '--from=origen'])
    assert.isUndefined(run.error, `stack crudo: ${run.error?.message}`)
    assert.equal(run.exitCode, 1)
    assert.notInclude(run.text, 'PARCIAL', run.text)
    assert.isTrue(run.logs.some((l: string) => l.includes('pasada FALLIDA sin escribir nada:')), run.text)
    assert.deepEqual(destino.log, [])
  })
})

test.group('openfga:provision · cierre 2 de D2 · 🟡 N4 (el barrido en STREAMING, sin cota) y ⚪ N5 (la letra del recuento)', () => {
  /** Un cliente FGA falso que pagina `pages` páginas de 100 tuplas (generadas al vuelo: nada se guarda) y deja UN deny vivo en la última. */
  function streamingClient(pages: number, opts: { repeatAt?: number; cycleFrom?: number } = {}) {
    let served = 0
    return {
      served: () => served,
      read: async (_filter: unknown, options: { continuationToken?: string }) => {
        const page = options.continuationToken ? Number(options.continuationToken.slice(1)) : 0
        served++
        // Un barrido que no detecta el token repetido no terminaría nunca: el doble corta a las pages + 10 lecturas.
        if (served > pages + 10) throw new Error('el doble cortó un barrido que no se detenía')
        const tuples = Array.from({ length: 100 }, (_, i) => ({ key: { object: `document:p|${page}-${i}`, relation: 'viewer', user: `user:${i}` } }))
        if (page === pages - 1) tuples[99] = { key: { object: 'document:p|x', relation: 'denied_viewer', user: 'user:victim' } }
        // `cycleFrom`: a partir de esa página el servidor vuelve a la página 1 (un ciclo de tokens, no un token inmediato repetido).
        const cycled = opts.cycleFrom !== undefined && page >= opts.cycleFrom ? 1 : undefined
        const next = page + 1 < pages ? `t${cycled ?? (opts.repeatAt !== undefined && page >= opts.repeatAt ? opts.repeatAt : page + 1)}` : undefined
        return { tuples, continuation_token: next }
      },
    }
  }

  test('N4 · un store de MÁS de 1 M tuplas (10 001 páginas de 100) se barre ENTERO: el deny vivo de la última página se cuenta (hasta el cierre 2: «el barrido no termina», exit 1 para siempre)', async ({ assert }) => {
    const client = streamingClient(10_001)
    const sweep = await countLiveDenies(client, ['document#denied_viewer'])
    assert.equal(sweep.read, 1_000_100)
    assert.equal(sweep.count, 1)
    assert.deepEqual(sweep.live, ['document:p|x#denied_viewer@user:victim'])
    assert.equal(client.served(), 10_001)
  }).timeout(60_000)

  test('N4 · exhaustivo o ruidoso: un continuation_token que se repite LANZA (el comando lo dice como «el barrido falló a medias»), jamás «cero» sin terminar', async ({ assert }) => {
    const caught = await countLiveDenies(streamingClient(50, { repeatAt: 3 }), ['document#denied_viewer']).then(() => null, (e) => e)
    assert.match(String(caught?.message), /se repite/, 'lo para la guarda del token, no el corte del doble')
  })

  test('N4 · un CICLO de continuation_tokens (t1 → … → t5 → t1, nunca el inmediato repetido) también LANZA: sin la cota de tuplas, esta guarda es lo único que impide un barrido infinito', async ({ assert }) => {
    const caught = await countLiveDenies(streamingClient(50, { cycleFrom: 5 }), ['document#denied_viewer']).then(() => null, (e) => e)
    assert.match(String(caught?.message), /se repite/, 'lo para la guarda del token (no el corte del doble a las pages + 10 lecturas)')
  })

  test('N5 · la letra: el recuento ESTRECHA la ventana y no la cierra; la cierra el paso 0 (flota a deny: \'read\') — en el bloque del provision y en el paso 3 del procedimiento', ({ assert }) => {
    const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, '**The recount narrows the window, it does not close it**')
    assert.include(readme, '**step 0 (the whole fleet on\n`deny: \'read\'` before counting) is what closes it**')
    assert.include(readme, 're-counts right before writing the model — the recount narrows the window, it does not close it: step 0 does)')
  })
})
