/**
 * El driver `openfga` de relaciones (Fase 4, lote 4-4) contra el contrato del
 * puerto (`runRelationsDriverContract`) EN EL STORE COMPARTIDO, más los casos
 * que un doble no puede probar:
 *  - `check` es UN solo `Check` (espía sobre el cliente),
 *  - el parseo CANÓNICO del id con partición no-raíz (⚪5),
 *  - el TRUNCADO de `listObjects` MEDIDO contra el tope del servidor (:8103).
 *
 * Corre solo con `OPENFGA_TEST_URL`. Detecta el tope de `ListObjects` del
 * servidor al arrancar (⚠️ top-level await): con un servidor de tope bajo
 * (:8103, tope 3) la cara `whenTrue` de `listObjectsTruncation` se MIDE; con el
 * :8101 (tope 1000) se mide la cara `whenFalse` (exhaustiva, sin señal falsa).
 */
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import {
  runRelationsDriverContract,
  contractRelationsConfig,
  contractDenyRelationsConfig,
  makeRelationsDriver,
} from '../src/testing/relations_contract.js'
import { reconcileRelations } from '../src/relations/reconcile.js'
import { relationsReconcileLines } from '../commands/authz_relations_reconcile.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { RelationsManager } from '../src/relations/manager.js'
import {
  openFgaFactsModel,
  factsRootTuples,
  factsParentTuple,
  factsBindingTuples,
  factsBindingObject,
  factsScopeObject,
} from '../src/drivers/openfga_facts.js'
import { MONOTONIC_CLOCK, OpenFgaRelationsDriver } from '../src/drivers/openfga_relations_driver.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import db from '@adonisjs/lucid/services/db'
import { buildRelationsManager } from '../providers/authz_provider.js'
import { spyFgaClient } from './helpers/fga_spy.js'
import { isPartialWrite, RenewalRacedError } from '../src/errors.js'
import type { RelationsConfig } from '../src/relations/define_relations_config.js'
import { APP_SCOPE } from '../src/types.js'
import type { RelationTuple, RelationsDriverCapabilities, ScopeRef } from '../src/types.js'
import { TEST_MODEL_ID, serveGeneratedModel } from './helpers/fga_model.js'

const HOLDER_MAP = { user: 'user', admin: 'admin', integration: 'integration' } as const

const openFgaTestUrl = process.env.OPENFGA_TEST_URL
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  /** Publica el modelo FUSIONADO de una config de relaciones y devuelve el store. */
  async function provisionFusedStore(config: RelationsConfig): Promise<{ storeId: string; modelId: string }> {
    const { OpenFgaClient } = await import('@openfga/sdk')
    const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `rel-${Date.now()}-${Math.random().toString(36).slice(2, 8)}` })
    const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
      openFgaFactsModel(HOLDER_MAP, [], { objectTypes: config.objectTypes })
    )
    return { storeId: store.id!, modelId: model.authorization_model_id! }
  }

  async function deleteStore(storeId: string): Promise<void> {
    const { OpenFgaClient } = await import('@openfga/sdk')
    await new OpenFgaClient({ apiUrl, storeId }).deleteStore()
  }

  /**
   * **Detecta el tope de `ListObjects` del servidor** (`OPENFGA_LIST_OBJECTS_MAX_RESULTS`):
   * relate N a un user fresco y cuenta cuántos devuelve `ListObjects`. Si el
   * servidor corta por debajo de N, ése es el tope; si no, el tope es > N y se
   * trata como «alto» (el :8101 por defecto, tope 1000). Store efímero, borrado.
   */
  async function detectListObjectsCap(): Promise<number> {
    const { OpenFgaClient } = await import('@openfga/sdk')
    const config = contractRelationsConfig()
    const { storeId, modelId } = await provisionFusedStore(config)
    try {
      const client = new OpenFgaClient({ apiUrl, storeId, authorizationModelId: modelId })
      const user = `user:${uuidv7()}`
      const part = `unit|${uuidv7()}`
      const PROBE = 8
      for (let i = 0; i < PROBE; i++) {
        await client.write({ writes: [{ user, relation: 'viewer', object: `document:${part}|${uuidv7()}` }] })
      }
      const response = await client.listObjects({ user, relation: 'viewer', type: 'document' })
      const got = (response.objects ?? []).length
      // Cortó por debajo de la sonda ⇒ ése es el tope; si no, es > PROBE (alto).
      return got < PROBE ? got : 1_000
    } finally {
      await deleteStore(storeId)
    }
  }

  const serverListObjectsCap = await detectListObjectsCap()
  // «Bajo» = el tope se puede desbordar con las cifras pequeñas del contrato
  // (:8103, tope 3). Con el :8101 (tope 1000) la cara observable es la
  // exhaustiva. Las DOS son medidas reales contra el servidor, ninguna un skip.
  const capsLow = serverListObjectsCap <= 16

  const createdStores: string[] = []

  /* ── El contrato del puerto contra el driver REAL, en el store compartido ── */

  runRelationsDriverContract({
    name: `openfga (tope ListObjects ${capsLow ? serverListObjectsCap : '1000+'})`,
    capabilities: {
      singleCheckRelations: true,
      listObjectsInherited: false,
      usersetSubjects: true,
      membersOfNative: false,
      enumerateRelations: true,
      // whenTrue MEDIDO solo donde el tope es bajo (:8103); si no, whenFalse.
      listObjectsTruncation: capsLow,
      injectableClock: true,
      // L-2: `openfga` no puede ser otra cosa (una tupla no entra en una transacción SQL, no hay 2PC); `false` EXPLÍCITO, y el rechazo con dientes contra el :8101 es L-5.
      transactionalWrites: false,
      // Lote D · D1: el modelo fusionado publica `denied_<rel>` para los tipos con opt-in (cara `true` del par).
      relationDenies: true,
      // Cierre 2 de D2 · 🟠 N1: `false` EXPLÍCITO — renueva con dos Write (M5): NIEGA la renovación de una portadora.
      atomicRenewal: false,
    },
    limits: { listMaxResults: serverListObjectsCap },
    makeDriver: async (config) => {
      const { storeId, modelId } = await provisionFusedStore(config)
      createdStores.push(storeId)
      return new OpenFgaRelationsDriver(config, {
        apiUrl,
        storeId,
        modelId,
        holderTypes: HOLDER_MAP,
        listObjectsMaxResults: serverListObjectsCap,
        logger: { warn: () => {} },
      })
    },
  })

  /* ── `check` = UN solo `Check` (espía) ────────────────────────────────────── */

  test.group('openfga relaciones — check es UN solo Check (espía)', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    test('un check con includes + userset anidado dispara EXACTAMENTE un Check al servidor', async ({ assert }) => {
      const config = contractRelationsConfig()
      const { storeId, modelId } = await provisionFusedStore(config)
      stores.push(storeId)
      const driver = new OpenFgaRelationsDriver(config, {
        apiUrl,
        storeId,
        modelId,
        holderTypes: HOLDER_MAP,
        logger: { warn: () => {} },
      })
      const client = (driver as any).client
      const original = client.check.bind(client)
      let checks = 0
      client.check = (...args: any[]) => {
        checks += 1
        return original(...args)
      }
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const g = { type: 'group', id: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      // u miembro de g; g#member es editor del doc; check(viewer) resuelve
      // includes (editor⊆viewer) + userset EN EL SERVIDOR.
      await driver.relate(u, 'member', g, p)
      await driver.relate({ object: g, relation: 'member' }, 'editor', doc, p)
      checks = 0
      assert.isTrue(await driver.check(u, 'viewer', doc, p))
      assert.equal(checks, 1, 'la derivación (includes + userset) la resuelve el modelo en UN Check')
    })
  })

  /* ── Plan 2.5 · lote A · checkMany en openfga: UN batchCheck, alineado por correlationId (A-16, A-17, A-19) ── */

  test.group('openfga relaciones — checkMany es UN batchCheck por cada 50 objetos distintos, alineado por correlationId (espía)', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    async function spiedDriver() {
      const config = contractRelationsConfig()
      const { storeId, modelId } = await provisionFusedStore(config)
      stores.push(storeId)
      const driver = new OpenFgaRelationsDriver(config, { apiUrl, storeId, modelId, holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
      return { driver, client: (driver as any).client as any }
    }

    test('A-17 · 45 objetos distintos en 50 posiciones (5 duplicados) ⇒ EXACTAMENTE un batchCheck con 45 ítems; la respuesta BARAJADA se alinea por correlationId, nunca por posición (includes + userset anidado + caducada + nada, por posición)', async ({
      assert,
    }) => {
      const { driver, client } = await spiedDriver()
      const u = { type: 'user', uuid: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const g1 = { type: 'group', id: uuidv7() }
      const g2 = { type: 'group', id: uuidv7() }
      const objects = Array.from({ length: 45 }, () => ({ type: 'document', id: uuidv7() }))
      const expected: boolean[] = new Array(45).fill(false)
      // Posiciones 0 (directo), 7 (includes: editor), 23 (userset ANIDADO), 44 (caducada) y el resto nada.
      await driver.relate(u, 'viewer', objects[0], p)
      await driver.relate(u, 'editor', objects[7], p)
      await driver.relate(u, 'member', g1, p)
      await driver.relate({ object: g1, relation: 'member' }, 'member', g2, p)
      await driver.relate({ object: g2, relation: 'member' }, 'viewer', objects[23], p)
      await driver.relate(u, 'viewer', objects[44], p, { expiresAt: new Date(Date.now() - 60_000) })
      expected[0] = expected[7] = expected[23] = true
      const original = client.batchCheck.bind(client)
      let calls = 0
      let items = 0
      client.batchCheck = async (request: any, options: any) => {
        calls += 1
        items += request.checks.length
        const response = await original(request, options)
        // Respuesta BARAJADA (el SDK ya concatena sub-lotes según llegan): el driver tiene que alinear por id.
        return { ...response, result: [...response.result].reverse() }
      }
      const request = [...objects, ...objects.slice(0, 5)]
      const answers = await driver.checkMany(u, 'viewer', request, p)
      assert.deepEqual(answers, [...expected, ...expected.slice(0, 5)], 'por posición, con la respuesta al revés')
      assert.equal(calls, 1, 'UN batchCheck para 45 objetos distintos (50 posiciones)')
      assert.equal(items, 45, 'un ítem por objeto DISTINTO')
      // Control: coincide con N check.
      const one: boolean[] = []
      for (const object of request.slice(0, 25)) one.push(await driver.check(u, 'viewer', object, p))
      assert.deepEqual(answers.slice(0, 25), one)
    })

    test('A-19 · el current_time viaja en CADA ítem del batchCheck y es el MISMO instante para todo el lote (un now, el del reloj inyectado)', async ({ assert }) => {
      const { driver, client } = await spiedDriver()
      const T = new Date('2030-06-15T12:34:56.789Z')
      const clocked = driver.withClock(() => new Date(T)) as OpenFgaRelationsDriver
      const u = { type: 'user', uuid: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const docs = [uuidv7(), uuidv7(), uuidv7()].map((id) => ({ type: 'document', id }))
      await clocked.relate(u, 'viewer', docs[0], p, { expiresAt: new Date(T.getTime() + 1) })
      await clocked.relate(u, 'viewer', docs[1], p, { expiresAt: T })
      let seen: any[] = []
      const original = client.batchCheck.bind(client)
      client.batchCheck = async (request: any, options: any) => {
        seen = request.checks
        return original(request, options)
      }
      assert.deepEqual(await clocked.checkMany(u, 'viewer', docs, p), [true, false, false], 'T+1 concede, T (estricta) no, nada no')
      assert.lengthOf(seen, 3)
      for (const item of seen) assert.deepEqual(item.context, { current_time: T.toISOString() }, 'cada ítem lleva el MISMO current_time')
      assert.sameMembers(seen.map((i) => i.correlationId), ['0', '1', '2'])
    })

    test('A-16 · un `error` en UN ítem de la respuesta del batchCheck ⇒ la clase de R3 para TODO el lote (internal_error ⇒ 503 E_AUTHZ_BACKEND_UNAVAILABLE, validation_error ⇒ 500 E_AUTHZ_CONFIG), nunca false; un resultado de más o de menos ⇒ 500 E_AUTHZ_INTERNAL', async ({ assert }) => {
      const { driver, client } = await spiedDriver()
      const u = { type: 'user', uuid: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const docs = [uuidv7(), uuidv7(), uuidv7()].map((id) => ({ type: 'document', id }))
      await driver.relate(u, 'viewer', docs[0], p)
      const original = client.batchCheck.bind(client)
      client.batchCheck = async (request: any, options: any) => {
        const response = await original(request, options)
        // R3: el ítem pasa por el clasificador; el transitorio (`internal_error`, forma de 3b-8) sigue siendo 503.
        const result = response.result.map((r: any) => (r.correlationId === '1' ? { ...r, allowed: false, error: itemError } : r))
        return { ...response, result }
      }
      let itemError: object = { internal_error: 'deadline_exceeded', message: 'simulado' }
      const caught = await driver.checkMany(u, 'viewer', docs, p).then(() => null, (e) => e)
      assert.isNotNull(caught, 'ROJO (A-16): un error por ítem salió como booleano')
      assert.equal(caught.status, 503, String(caught.message))
      assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
      // R3: un ítem `validation_error` es despliegue ⇒ 500 E_AUTHZ_CONFIG para TODO el lote (hasta R3, 503), nunca false.
      itemError = { input_error: 'validation_error', message: 'simulado' }
      const config = await driver.checkMany(u, 'viewer', docs, p).then(() => null, (e) => e)
      assert.equal(config?.status, 500, String(config?.message))
      assert.equal(config?.code, 'E_AUTHZ_CONFIG')
      client.batchCheck = async (request: any, options: any) => {
        const response = await original(request, options)
        return { ...response, result: response.result.slice(1) }
      }
      const short = await driver.checkMany(u, 'viewer', docs, p).then(() => null, (e) => e)
      assert.equal(short?.code, 'E_AUTHZ_INTERNAL', String(short?.message))
      client.batchCheck = original
      assert.deepEqual(await driver.checkMany(u, 'viewer', docs, p), [true, false, false], 'control: sin el espía, por posición')
    })
  })

  /* ── D4 · la receta de canonización en openfga: reconcile desde database + delete con el SDK (plan 2.5 · lote A) ── */

  test.group('openfga relaciones — D4 · receta (el equivalente de --rekey, opt-in; en openfga el default es LISTAR con el SDK y --delete es el delete del SDK, cierre-2 · 🟡 R3): las tuplas sin guiones del store se re-escriben por reconcile desde database y se borran con el SDK (write canónica ANTES de delete)', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    test('una tupla escrita antes de 2.5.0 bajo `unit|<32 hex>` no se puede direccionar (422) ni concede por la canónica; `reconcileRelations` desde database escribe la canónica (check true), y el delete del SDK de la vieja deja el store limpio sin perder la concesión', async ({
      assert,
    }) => {
      const config = contractRelationsConfig()
      const { storeId, modelId } = await provisionFusedStore(config)
      stores.push(storeId)
      const { OpenFgaClient } = await import('@openfga/sdk')
      const client = new OpenFgaClient({ apiUrl, storeId, authorizationModelId: modelId })
      const fga = new OpenFgaRelationsDriver(config, { apiUrl, storeId, modelId, holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
      const dashed = uuidv7()
      const dashless = dashed.replace(/-/g, '')
      const canonical: ScopeRef = { type: 'unit', uuid: dashed }
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      // La tupla vieja, tal como la escribía 2.4 con la ortografía sin guiones.
      const legacy = { user: `user:${u.uuid}`, relation: 'viewer', object: `document:unit|${dashless}|${doc.id}` }
      await client.write({ writes: [legacy] })
      assert.equal((await fga.check(u, 'viewer', doc, { type: 'unit', uuid: dashless }).then(() => null, (e) => e))?.code, 'E_AUTHZ_INVALID_IDENTITY', 'inalcanzable por la API')
      assert.isFalse(await fga.check(u, 'viewer', doc, canonical), 'y la canónica no la ve (H5)')
      // Paso 1 · la copia en database YA está canonizada (receta SQL) y se reconcilia la partición canónica.
      await db.from('authz_relations').delete()
      const database = new DatabaseRelationsDriver(config)
      await database.relate(u, 'viewer', doc, canonical)
      const report = await reconcileRelations({ from: database, to: fga, partition: canonical, toConfig: config })
      assert.equal(report.written, 1)
      assert.isTrue(await fga.check(u, 'viewer', doc, canonical), 'la canónica concede tras el reconcile (write ANTES de delete: fail-closed en todo momento)')
      // Paso 2 · la tupla vieja no la gobierna ningún comando: se borra con el SDK.
      await client.write({ deletes: [legacy] })
      const dump: string[] = []
      let token: string | undefined
      do {
        const page = await client.read({}, { pageSize: 100, continuationToken: token })
        for (const t of page.tuples ?? []) dump.push(t.key.object)
        token = page.continuation_token || undefined
      } while (token)
      assert.isFalse(dump.some((o) => o.includes(`unit|${dashless}|`)), 'sin rastro de la ortografía vieja')
      assert.isTrue(dump.some((o) => o === `document:unit|${dashed}|${doc.id}`))
      assert.isTrue(await fga.check(u, 'viewer', doc, canonical), 'la concesión sobrevive al borrado de la vieja')
      await db.from('authz_relations').delete()
    })
  })

  /* ── 🟠 N9 (cierre 3 del lote B) · relación RETIRADA de la config en `openfga`: `#sweep` filtra por tipo, `unrelate` hace F-05 ── */

  /**
   * El «❓ en `openfga`» del auditor, medido: el modelo del store SÍ declara `publisher` (lo publicó la config vieja) y
   * el `Read` la devuelve; el driver con la config NUEVA (sin `publisher`) la enumera (`#sweep` filtra solo por tipo,
   * `:847-854`) y su `unrelate` la rechaza por F-05 (`:564`) — la misma forma que en `database`. Con `toConfig` la
   * clasifica el plan (capa 1); sin ella, la captura por código (capa 2). En ningún caso un throw a mitad de pasada.
   */
  test.group('openfga relaciones — 🟠 N9 · relación RETIRADA (document#publisher) con filas vivas en el store: --prune no lanza, clasifica y sigue (con y sin toConfig)', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    test('driver con la config nueva sobre el store del modelo viejo: dry/real/dry2 con toConfig ⇒ extra 1 + details destino/undeclared/pruned:false y cero `write` de la retirada; sin toConfig la pasada real captura el 422, sigue (W escrita, X borrada) y lista igual; la tupla retirada sigue en el store', async ({ assert }) => {
      const oldConfig = defineRelationsConfig({
        objectTypes: [{ type: 'document', relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }, { name: 'publisher' }] }],
        holderTypes: ['user', 'admin', 'integration'],
      })
      const newConfig = contractRelationsConfig()
      const { storeId, modelId } = await provisionFusedStore(oldConfig)
      stores.push(storeId)
      const make = (config: RelationsConfig, pinned = modelId) =>
        new OpenFgaRelationsDriver(config, { apiUrl, storeId, modelId: pinned, holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
      const old = make(oldConfig)
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const u = { type: 'user', uuid: uuidv7() }
      const retired = { type: 'document', id: uuidv7() }
      const x = { type: 'document', id: uuidv7() }
      const w = { type: 'document', id: uuidv7() }
      await old.relate(u, 'publisher', retired, p)
      await old.relate(u, 'viewer', x, p)
      // L11: el pod con la config NUEVA se fija al modelo que publica ESA config (con el modelo viejo fijado, la puerta da
      // 500 —relación de más `document#publisher`— antes de tocar nada: es justo lo que L11 exige). Las filas de la
      // relación retirada siguen en el store: `Read` no depende del modelo.
      const { OpenFgaClient } = await import('@openfga/sdk')
      const republished = await new OpenFgaClient({ apiUrl, storeId }).writeAuthorizationModel(
        openFgaFactsModel(HOLDER_MAP, [], { objectTypes: newConfig.objectTypes })
      )
      const stale = await make(newConfig).check(u, 'viewer', x, p).then(() => null, (e) => e)
      assert.equal(stale?.code, 'E_AUTHZ_CONFIG', 'L11: la config nueva con el modelo viejo fijado ⇒ 500')
      assert.include(String(stale?.message), 'document#publisher (relación de más)')
      const source: any = { capabilities: { enumerateRelations: true }, enumerateRelations: async () => ({ tuples: [{ subject: u, relation: 'viewer', object: w, partition: p, expiresAt: null }] }), relate: async () => {}, unrelate: async () => {} }
      for (const [label, toConfig] of [['con toConfig', newConfig], ['sin toConfig', undefined]] as const) {
        const fresh = make(newConfig, republished.authorization_model_id!)
        const dry = await reconcileRelations({ from: source, to: fresh, partition: p, prune: true, dryRun: true, toConfig }).then((r) => r, (e) => e)
        assert.notInstanceOf(dry, Error, `${label} dry: ${dry?.message}`)
        const real = await reconcileRelations({ from: source, to: fresh, partition: p, prune: true, toConfig }).then((r) => r, (e) => e)
        assert.notInstanceOf(real, Error, `ROJO (N9) ${label}: la pasada real LANZÓ ${real?.code} ${real?.message}`)
        assert.lengthOf(real.details ?? [], 1, `${label}: la retirada listada`)
        assert.deepInclude(real.details![0], { side: 'destino', reason: 'undeclared', pruned: false }, label)
        assert.include(real.details![0].tuple, `#publisher@user:${u.uuid}`, label)
        assert.equal(real.extra, 1, label)
        if (toConfig) {
          assert.deepInclude(dry, { written: 1, deleted: 1, extra: 1 }, `${label} dry: ${JSON.stringify(dry)}`)
          assert.deepInclude(dry.details![0], { side: 'destino', reason: 'undeclared', pruned: false }, `${label} dry = real`)
          assert.deepInclude(real, { written: 1, deleted: 1 }, `${label} real: ${JSON.stringify(real)}`)
        } else {
          assert.deepInclude(dry, { written: 1, deleted: 2, extra: 0 }, `${label} dry (límite declarado): ${JSON.stringify(dry)}`)
          assert.deepInclude(real, { written: 1, deleted: 1 }, `${label} real: ${JSON.stringify(real)}`)
        }
        assert.isTrue(await fresh.check(u, 'viewer', w, p), `${label}: W escrita`)
        assert.isFalse(await fresh.check(u, 'viewer', x, p), `${label}: X borrada (la poda siguió)`)
        assert.isTrue(await old.check(u, 'publisher', retired, p), `${label}: la retirada sigue en el store (a mano / re-declarar)`)
        const dry2 = await reconcileRelations({ from: source, to: fresh, partition: p, prune: true, dryRun: true, toConfig })
        assert.deepInclude(dry2, { written: 0, unchanged: 1, extra: toConfig ? 1 : 0, deleted: toConfig ? 0 : 1 }, `${label} dry2: ${JSON.stringify(dry2)}`)
        // Restaura el escenario para la segunda vuelta del bucle (X vuelve, W se va).
        await old.relate(u, 'viewer', x, p)
        await old.unrelate(u, 'viewer', w, p)
      }
    })
  })

  /* ── ⚪5 · parseo CANÓNICO del id con partición NO-raíz ────────────────────── */

  test.group('openfga relaciones — ⚪5 · parseo canónico del id (partición no-raíz)', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    test('listObjects/listSubjects devuelven el uuid del objeto (último segmento), no la partición', async ({
      assert,
    }) => {
      const config = contractRelationsConfig()
      const { storeId, modelId } = await provisionFusedStore(config)
      stores.push(storeId)
      const driver = new OpenFgaRelationsDriver(config, {
        apiUrl,
        storeId,
        modelId,
        holderTypes: HOLDER_MAP,
        logger: { warn: () => {} },
      })
      const u = { type: 'user', uuid: uuidv7() }
      const docUuid = uuidv7()
      const doc = { type: 'document', id: docUuid }
      // Partición NON-raíz: scopeKey = `unit|<partUuid>`, así que el id del
      // store lleva DOS `|` (`document:unit|<partUuid>|<docUuid>`).
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      await driver.relate(u, 'viewer', doc, p)
      // listObjects: el id es SOLO el uuid del objeto (último segmento), nunca
      // `unit|<partUuid>|<docUuid>` ni un pedazo de la partición.
      const objects = await driver.listObjects(u, 'viewer', 'document', p)
      assert.deepEqual(objects.objects, [{ type: 'document', id: docUuid }])
      // listSubjects: el holder vuelve como {type:'user', uuid}, no como un id compuesto.
      const subjects = await driver.listSubjects('viewer', doc, p)
      assert.deepEqual(subjects.subjects, [{ type: 'user', uuid: u.uuid }])
      // Y no cruza a la raíz: la MISMA pregunta en `app` no ve nada.
      const rootObjects = await driver.listObjects(u, 'viewer', 'document', { type: 'app', uuid: null })
      assert.lengthOf(rootObjects.objects, 0)
    })
  })

  /* ── R-16 · el driver openfga valida object.id (paridad con database) ────── */

  /**
   * El hallazgo del auditor (🟡1): el driver `openfga` solo medía la LONGITUD
   * del `object.id` (`assertFgaObjectId`). Un `object.id` con un `|` (`'a|b'`)
   * se ESCRIBÍA, `check` lo honraba, pero `listObjects`/`enumerateRelations` lo
   * PERDÍAN al parsear por el último `|` —invisibilidad y pérdida silenciosa en
   * `reconcile`—, y los caracteres estructurales salían como 503, no 422. Con la
   * gramática de relaciones aplicada por defensa en profundidad, el driver
   * rechaza con 422 (paridad con `database`) y nada llega al store.
   */
  test.group('openfga relaciones — R-16 · object.id inválido ⇒ 422 (defensa en profundidad)', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    test('relate EN DIRECTO con object.id "a|b" ⇒ 422 y el store NO lo tiene', async ({ assert }) => {
      const config = contractRelationsConfig()
      const { storeId, modelId } = await provisionFusedStore(config)
      stores.push(storeId)
      const driver = new OpenFgaRelationsDriver(config, {
        apiUrl,
        storeId,
        modelId,
        holderTypes: HOLDER_MAP,
        logger: { warn: () => {} },
      })
      const u = { type: 'user', uuid: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      for (const bad of ['a|b', 'a:b', 'a#viewer', 'a b', '*']) {
        let caught: any
        try {
          await driver.relate(u, 'viewer', { type: 'document', id: bad }, p)
        } catch (e) {
          caught = e
        }
        assert.equal(caught?.status, 422, `${bad}: 422 y no 503`)
        assert.equal(caught?.code, 'E_AUTHZ_INVALID_IDENTITY', bad)
      }
      // Un id válido: escribe, y `listObjects` lo ENUMERA (no se pierde).
      const good = { type: 'document', id: uuidv7() }
      await driver.relate(u, 'viewer', good, p)
      const objects = await driver.listObjects(u, 'viewer', 'document', p)
      assert.deepEqual(objects.objects, [good])
    })
  })

  /* ── L-0 · F-05 vive TAMBIÉN en el driver: 422 con cero llamadas al store ── */

  /**
   * Panel `{trx}`, 🔴 2 del auditor: el driver `openfga` de relaciones no
   * comprobaba `hasType`/`isDeclared` (solo `assertRelationId`), así que
   * `manager.driver()` y `reconcileRelations` —que escribe con `to.relate`—
   * saltaban F-05 y componían el id de un `role_binding` REAL en el store
   * COMPARTIDO (la escalada la mide `relations_bridge.spec.ts`). Aquí: el 422
   * sale ANTES del `Read` de la tupla y del `Write` (espía sobre el cliente),
   * con la MISMA clase y `code` que el manager (una sola función, F-05).
   */
  test.group('openfga relaciones — L-0 · F-05 en el driver: 422 ANTES de tocar el store (espía)', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    async function spiedDriver(): Promise<{ driver: OpenFgaRelationsDriver; calls: { read: number; write: number } }> {
      const config = contractRelationsConfig()
      const { storeId, modelId } = await provisionFusedStore(config)
      stores.push(storeId)
      const driver = new OpenFgaRelationsDriver(config, {
        apiUrl,
        storeId,
        modelId,
        holderTypes: HOLDER_MAP,
        logger: { warn: () => {} },
      })
      const client = (driver as any).client
      const calls = { read: 0, write: 0 }
      const originalRead = client.read.bind(client)
      const originalWrite = client.write.bind(client)
      client.read = (...args: any[]) => {
        calls.read += 1
        return originalRead(...args)
      }
      client.write = (...args: any[]) => {
        calls.write += 1
        return originalWrite(...args)
      }
      return { driver, calls }
    }

    test('relate/unrelate con object.type NO declarado ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN y cero Read/Write', async ({
      assert,
    }) => {
      const { driver, calls } = await spiedDriver()
      const u = { type: 'user', uuid: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      for (const object of [
        { type: 'role_binding', id: uuidv7() },
        { type: 'scope', id: uuidv7() },
        { type: 'role', id: uuidv7() },
        { type: 'folder', id: uuidv7() },
      ]) {
        for (const op of ['relate', 'unrelate'] as const) {
          let caught: any
          try {
            await driver[op](u, 'assignee', object, p)
            assert.fail(`${op} aceptó el tipo no declarado '${object.type}'`)
          } catch (e) {
            caught = e
          }
          assert.equal(caught?.status, 422, `${op} · ${object.type}: ${caught?.message}`)
          assert.equal(caught?.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN', `${op} · ${object.type}`)
        }
      }
      assert.deepEqual(calls, { read: 0, write: 0 }, 'la guarda corta ANTES del Read de la tupla y del Write')
    })

    test('relate/unrelate con una relación NO declarada del tipo ⇒ 422 E_AUTHZ_RELATION_UNKNOWN y cero Read/Write', async ({
      assert,
    }) => {
      const { driver, calls } = await spiedDriver()
      const u = { type: 'user', uuid: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      for (const [relation, object] of [
        ['assignee', { type: 'document', id: uuidv7() }],
        ['can_p0', { type: 'document', id: uuidv7() }],
        ['viewer', { type: 'group', id: uuidv7() }],
      ] as const) {
        for (const op of ['relate', 'unrelate'] as const) {
          let caught: any
          try {
            await driver[op](u, relation, object, p)
            assert.fail(`${op} aceptó la relación no declarada '${object.type}#${relation}'`)
          } catch (e) {
            caught = e
          }
          assert.equal(caught?.status, 422, `${op} · ${object.type}#${relation}`)
          assert.equal(caught?.code, 'E_AUTHZ_RELATION_UNKNOWN', `${op} · ${object.type}#${relation}`)
        }
      }
      assert.deepEqual(calls, { read: 0, write: 0 })
      // CONTROL: lo declarado sigue escribiendo (y `check` lo ve).
      const doc = { type: 'document', id: uuidv7() }
      await driver.relate(u, 'viewer', doc, p)
      assert.isAbove(calls.write, 0)
      assert.isTrue(await driver.check(u, 'viewer', doc, p))
    })
  })

  /* ── CIERRE alpha.3 · 🔴 1 / 🟠 2 · F-05 en purgas y lecturas, en el store COMPARTIDO ── */

  /**
   * **El exploit del auditor de alpha.3, contra el `:8101`** (`alpha3-f05-purge.ts`):
   * driver de roles `facts` y driver de relaciones en el MISMO store; `user:U`
   * tiene el rol `R` en `organization:S` y `can_read` es `true`. Hasta el
   * cierre, `purgeObject({ type: 'role_binding', id: R }, S)` por el manager
   * componía `role_binding:organization|S|R` —byte a byte el binding real— y
   * lo borraba con demostración de cero: `authorize` pasaba a `false`, 0
   * tuplas, y un `RelationWriteEvent` limpio (`operation: 'purgeObject'`).
   * `listSubjects('assignee', role_binding)` devolvía sus asignados. Ahora:
   * 422 `E_AUTHZ_RELATION_TYPE_UNKNOWN`, `authorize` SIGUE en `true`, tuplas
   * intactas, CERO llamadas al cliente FGA (espía) y CERO eventos — por el
   * manager Y por el driver en directo. **Mutantes**: quitar F-05 de
   * `purgeObject` en el manager ⇒ el caso «por el MANAGER» rojo con la
   * destrucción literal; quitarlo del driver ⇒ el caso «por el DRIVER» rojo.
   */
  test.group('cierre alpha.3 · 🔴 1 / 🟠 2 · F-05 en purgeObject/purgeSubject/check/listObjects/listSubjects contra el store COMPARTIDO (:8101): el puerto de relaciones no borra ni enumera un role_binding REAL', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    /** Roles `facts` + relaciones en el MISMO store: `user:U` tiene el rol `R` (permits_read) en `organization:S`. */
    async function sharedRoleStore() {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const config = contractRelationsConfig()
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `cierre-f05-${Date.now()}` })
      const storeId = store.id!
      stores.push(storeId)
      const model = await new OpenFgaClient({ apiUrl, storeId }).writeAuthorizationModel(
        openFgaFactsModel(HOLDER_MAP, ['read'], { objectTypes: config.objectTypes })
      )
      const modelId = model.authorization_model_id!
      const client = new OpenFgaClient({ apiUrl, storeId, authorizationModelId: modelId })
      const S = uuidv7()
      const R = uuidv7()
      const U = uuidv7()
      const scopeKeyValue = `organization|${S}`
      await client.write({
        writes: [
          ...factsRootTuples(HOLDER_MAP),
          factsParentTuple(scopeKeyValue, 'app'),
          ...factsBindingTuples(scopeKeyValue, R),
          { user: 'user:*', relation: 'permits_read', object: `role:${R}` },
          { user: `user:${U}`, relation: 'assignee', object: factsBindingObject(scopeKeyValue, R) },
        ] as any,
      })
      const can = async () =>
        (
          await client.check({
            user: `user:${U}`,
            relation: 'can_read',
            object: factsScopeObject(scopeKeyValue),
            context: { current_time: new Date().toISOString() },
          })
        ).allowed === true
      const bindingTuples = async () => ((await client.read({ object: factsBindingObject(scopeKeyValue, R) })).tuples ?? []).length
      const driver = new OpenFgaRelationsDriver(config, { apiUrl, storeId, modelId, holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
      const partition: ScopeRef = { type: 'organization', uuid: S }
      const binding = { type: 'role_binding', id: R }
      const user = { type: 'user', uuid: U }
      return { config, driver, can, bindingTuples, partition, binding, user }
    }

    async function expect422(assert: any, label: string, run: () => Promise<unknown>) {
      const caught = await run().then(() => null, (e) => e)
      assert.isNotNull(caught, `ROJO (${label}): ENTRÓ contra el role_binding real del store compartido`)
      assert.equal(caught.status, 422, `${label}: ${caught.message}`)
      assert.equal(caught.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN', label)
    }

    test('por el MANAGER: purgeObject(role_binding:R) ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN, authorize(U, read, S) SIGUE true, las tuplas del binding intactas, CERO llamadas al cliente FGA y CERO eventos; listSubjects(assignee, role_binding:R) ⇒ 422 sin fuga; check/listObjects/purgeSubject(userset) ⇒ 422', async ({
      assert,
    }) => {
      const { config, driver, can, bindingTuples, partition, binding, user } = await sharedRoleStore()
      assert.isTrue(await can(), 'CONTROL: U concede read en S por su rol')
      const before = await bindingTuples()
      assert.isAbove(before, 0, 'CONTROL: el binding tiene tuplas')
      const spy = spyFgaClient(driver)
      const events: unknown[] = []
      const manager = new RelationsManager(driver, config, {
        requireActor: true,
        assertWrite: () => {
          throw new Error('assertWrite: el gate del consumidor RECHAZA TODO (y las purgas no pasan por él)')
        },
        onRelationWrite: (e) => void events.push(e),
      })
      await expect422(assert, 'purgeObject', () => manager.purgeObject(binding, partition, { actor: user }))
      // La condición dura, MEDIDA contra el `:8101`: sin la guarda ESTA línea es la destrucción literal.
      assert.isTrue(await can(), 'ROJO: el puerto de relaciones DESTRUYÓ una asignación de rol real (authorize pasó a false)')
      assert.equal(await bindingTuples(), before, 'las tuplas del binding están intactas')
      await expect422(assert, 'listSubjects', () => manager.listSubjects('assignee', binding, partition))
      await expect422(assert, 'check', () => manager.check(user, 'assignee', binding, partition))
      await expect422(assert, 'listObjects', () => manager.listObjects(user, 'assignee', 'role_binding', partition))
      await expect422(assert, 'purgeSubject(userset)', () =>
        manager.purgeSubject({ object: binding, relation: 'role' }, partition, { actor: user })
      )
      assert.deepEqual(spy.calls, [], 'CERO llamadas al cliente FGA: ni un Read, ni un Write, ni un Check')
      assert.deepEqual(events, [], 'CERO eventos: no hay purga rutinaria que un SOC pueda leer')
      // CONTROL: lo declarado sigue funcionando en el mismo store (con un
      // manager cuyo gate no rechaza: el de arriba rechazaba TODO a propósito).
      spy.reset()
      const doc = { type: 'document', id: uuidv7() }
      const permissive = new RelationsManager(driver, config, { requireActor: true, onRelationWrite: (e) => void events.push(e) })
      await permissive.relate(user, 'viewer', doc, partition, { actor: user })
      assert.isTrue(await permissive.check(user, 'viewer', doc, partition))
      assert.isAbove(spy.total(), 0)
      assert.lengthOf(events, 1)
    })

    test('por el DRIVER en directo (manager.driver()): las MISMAS cinco con role_binding ⇒ el MISMO 422 con CERO llamadas al cliente FGA; authorize sigue true y el binding intacto (defensa en profundidad)', async ({
      assert,
    }) => {
      const { driver, can, bindingTuples, partition, binding, user } = await sharedRoleStore()
      const before = await bindingTuples()
      const spy = spyFgaClient(driver)
      await expect422(assert, 'driver.purgeObject', () => driver.purgeObject(binding, partition))
      assert.isTrue(await can(), 'ROJO: el driver EN DIRECTO destruyó la asignación de rol real')
      assert.equal(await bindingTuples(), before)
      await expect422(assert, 'driver.purgeSubject(userset)', () => driver.purgeSubject({ object: binding, relation: 'role' }, partition))
      await expect422(assert, 'driver.listSubjects', () => driver.listSubjects('assignee', binding, partition))
      await expect422(assert, 'driver.check', () => driver.check(user, 'assignee', binding, partition))
      await expect422(assert, 'driver.listObjects', () => driver.listObjects(user, 'assignee', 'role_binding', partition))
      await expect422(assert, 'driver.check(userset)', () => driver.check({ object: binding, relation: 'assignee' }, 'viewer', { type: 'document', id: uuidv7() }, partition))
      assert.deepEqual(spy.calls, [], 'CERO llamadas al cliente FGA por el camino del driver')
    })

    /**
     * **Cierre-2 · 🟠 1 / 🟡 2 (re-ataque del auditor, O1a–O1d)**: con la
     * `relation?` opcional del primer cierre, `relate(u, undefined, doc, p)`
     * llegaba al servidor y volvía como 503 `E_AUTHZ_BACKEND_UNAVAILABLE`
     * (una pregunta inválida convertida en caída del backend, invariante 5),
     * y `listSubjects(undefined, doc, p)` devolvía la UNIÓN de los holders de
     * todas las relaciones (un `Read` sin filtro). Ahora: 422
     * `E_AUTHZ_RELATION_UNKNOWN` con CERO llamadas al cliente, por el manager
     * y por el driver (la misma clase y el mismo `code` que `database`).
     */
    test('cierre-2 · relate/unrelate/check/listSubjects/listObjects con relation: undefined ⇒ 422 E_AUTHZ_RELATION_UNKNOWN con CERO llamadas al cliente FGA (antes: 503 del servidor) y cero eventos, por el MANAGER y por el DRIVER; listSubjects(undefined) ya no es la UNIÓN de relaciones', async ({
      assert,
    }) => {
      const config = contractRelationsConfig()
      const { storeId, modelId } = await provisionFusedStore(config)
      stores.push(storeId)
      const driver = new OpenFgaRelationsDriver(config, { apiUrl, storeId, modelId, holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
      const events: unknown[] = []
      const manager = new RelationsManager(driver, config, { onRelationWrite: (e) => void events.push(e) })
      const u = { type: 'user', uuid: uuidv7() }
      const v = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const p: ScopeRef = { type: 'organization', uuid: uuidv7() }
      await manager.relate(u, 'viewer', doc, p)
      await manager.relate(v, 'owner', doc, p)
      events.length = 0
      const spy = spyFgaClient(driver)
      const missing = undefined as any
      for (const [label, run] of [
        ['manager.relate', () => manager.relate(u, missing, doc, p)],
        ['manager.unrelate', () => manager.unrelate(u, missing, doc, p)],
        ['manager.check', () => manager.check(u, missing, doc, p)],
        ['manager.listSubjects', () => manager.listSubjects(missing, doc, p)],
        ['manager.listObjects', () => manager.listObjects(u, missing, 'document', p)],
        ['driver.relate', () => driver.relate(u, missing, doc, p)],
        ['driver.unrelate', () => driver.unrelate(u, missing, doc, p)],
        ['driver.check', () => driver.check(u, missing, doc, p)],
        ['driver.listSubjects', () => driver.listSubjects(missing, doc, p)],
        ['driver.listObjects', () => driver.listObjects(u, missing, 'document', p)],
      ] as Array<[string, () => Promise<unknown>]>) {
        const caught = await run().then(() => null, (e) => e)
        assert.isNotNull(caught, `ROJO (${label}): sin relación ENTRÓ (O1b: la unión) o llegó al servidor`)
        assert.equal(caught.status, 422, `${label}: ${caught.message} (O1a: antes 503 del servidor)`)
        assert.equal(caught.code, 'E_AUTHZ_RELATION_UNKNOWN', label)
      }
      assert.deepEqual(spy.calls, [], 'CERO llamadas al cliente FGA: la pregunta inválida no llega al servidor')
      assert.deepEqual(events, [])
      // CONTROL: con la relación, `listSubjects` da SOLO esa (no la unión).
      spy.reset()
      assert.deepEqual((await manager.listSubjects('owner', doc, p)).subjects, [v])
      assert.deepEqual((await manager.listSubjects('viewer', doc, p)).subjects, [u])
      assert.isAbove(spy.total(), 0)
    })
  })

  /* ── CIERRE alpha.3 · 🟡 6 · la purga que muere a MEDIAS es indeterminada ── */

  /**
   * **F del auditor contra el `:8101`**: la purga de `openfga` es N requests
   * (`Read` + `deleteTuples` + `Read` de demostración de cero, por ortografía
   * y por tipo). Un espía sobre el cliente REAL hace fallar la request
   * SIGUIENTE a un `deleteTuples` (la demostración de cero) con un error que
   * no es timeout: el driver YA borró, el error sale como 503
   * `E_AUTHZ_BACKEND_UNAVAILABLE` marcado parcial y el manager notifica
   * `indeterminate: true` ANTES de propagarlo. Si la request que falla es la
   * PRIMERA (antes de borrar nada), nada se marca y no hay evento: ahí «esa
   * escritura no ocurrió» sigue siendo verdad. **Mutante**: quitar
   * `#partialIfDeleted` del driver (o `isPartialWrite` de `#write`) ⇒ rojo
   * («borró ≥ 1 y EVENTOS=0»).
   */
  test.group('cierre alpha.3 · 🟡 6 · una purga de openfga que muere a MEDIAS contra el :8101 ⇒ borró ≥ 1, onRelationWrite con indeterminate: true y 503 propagado; una que muere ANTES de borrar ⇒ cero eventos', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    /**
     * Espía con FALLO sobre el cliente FGA real: `failOn(method, seen)` decide,
     * request a request, si esa llamada estalla (sin llegar al servidor).
     */
    function faultyClient(driver: object, failOn: (method: string, seen: string[]) => boolean) {
      const holder = driver as { client: any }
      const original = holder.client
      const seen: string[] = []
      let fired = 0
      holder.client = new Proxy(original, {
        get(target, prop, receiver) {
          const value = Reflect.get(target, prop, receiver)
          if (typeof value !== 'function' || typeof prop !== 'string') return value
          return (...args: unknown[]) => {
            if (failOn(prop, seen)) {
              fired += 1
              seen.push(`${prop}!`)
              const e: any = new Error(`backend caído a mitad de la purga (${prop})`)
              e.code = 'ECONNRESET'
              throw e
            }
            seen.push(prop)
            return value.apply(target, args)
          }
        },
      })
      return { seen, fired: () => fired, restore: () => void (holder.client = original) }
    }

    async function realDriver() {
      const config = contractRelationsConfig()
      const { storeId, modelId } = await provisionFusedStore(config)
      stores.push(storeId)
      const driver = new OpenFgaRelationsDriver(config, { apiUrl, storeId, modelId, holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
      return { config, driver }
    }

    /** Falla la request que sigue a un `deleteTuples` (la demostración de cero): ya se borró. */
    const afterFirstDelete = (method: string, seen: string[]) => seen.includes('deleteTuples') && !seen.some((s) => s.endsWith('!')) && method === 'read'

    test('purgeObject: la demostración de cero falla tras el deleteTuples ⇒ las tuplas YA no están (borró ≥ 1), el error es 503 E_AUTHZ_BACKEND_UNAVAILABLE (no timeout) y onRelationWrite recibió { operation: purgeObject, indeterminate: true } ANTES', async ({
      assert,
    }) => {
      const { config, driver } = await realDriver()
      const u = { type: 'user', uuid: uuidv7() }
      const v = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const actor = { type: 'admin', uuid: uuidv7() }
      await driver.relate(u, 'viewer', doc, p)
      await driver.relate(v, 'editor', doc, p)
      assert.lengthOf((await driver.listSubjects('viewer', doc, p)).subjects, 1)
      const events: any[] = []
      const sequence: string[] = []
      const manager = new RelationsManager(driver, config, {
        onRelationWrite: (e) => {
          events.push(e)
          sequence.push(`hook:${e.operation}:${e.indeterminate}`)
        },
      })
      const fault = faultyClient(driver, afterFirstDelete)
      const caught = await manager.purgeObject(doc, p, { actor }).then(() => null, (e) => e)
      sequence.push('catch')
      fault.restore()
      assert.equal(fault.fired(), 1, `el espía hizo fallar UNA request: ${fault.seen.join(' → ')}`)
      assert.isTrue(fault.seen.includes('deleteTuples'), 'el driver YA había borrado cuando falló')
      assert.equal(caught?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', `un 503 que NO es timeout: ${caught?.message}`)
      assert.equal(caught?.status, 503)
      // borró ≥ 1: las tuplas ya no están.
      assert.lengthOf((await driver.listSubjects('viewer', doc, p)).subjects, 0, 'las tuplas se borraron antes del fallo')
      assert.lengthOf((await driver.listSubjects('editor', doc, p)).subjects, 0)
      assert.deepEqual(
        events.map((e) => [e.operation, e.indeterminate]),
        [['purgeObject', true]],
        'ROJO (F del auditor): borró ≥ 1 y EVENTOS=0 — el paquete publicaba «esa escritura no ocurrió»'
      )
      assert.deepEqual(sequence, ['hook:purgeObject:true', 'catch'], 'el evento sale ANTES de propagar el 503')
      assert.deepEqual(events[0].object, doc)
      assert.deepEqual(events[0].actor, actor)
      assert.notProperty(events[0], 'transactional')
    })

    test('purgeSubject: el mismo fallo tras el deleteTuples del tipo document ⇒ borró ≥ 1, 503 y { operation: purgeSubject, indeterminate: true }', async ({ assert }) => {
      const { config, driver } = await realDriver()
      const u = { type: 'user', uuid: uuidv7() }
      const doc1 = { type: 'document', id: uuidv7() }
      const doc2 = { type: 'document', id: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      await driver.relate(u, 'viewer', doc1, p)
      await driver.relate(u, 'owner', doc2, p)
      const events: any[] = []
      const manager = new RelationsManager(driver, config, { onRelationWrite: (e) => void events.push(e) })
      const fault = faultyClient(driver, afterFirstDelete)
      const caught = await manager.purgeSubject(u, p).then(() => null, (e) => e)
      fault.restore()
      assert.equal(fault.fired(), 1, fault.seen.join(' → '))
      assert.equal(caught?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', caught?.message)
      assert.isFalse(await driver.check(u, 'viewer', doc1, p), 'borró ≥ 1')
      assert.deepEqual(events.map((e) => [e.operation, e.indeterminate, e.subject]), [['purgeSubject', true, u]])
    })

    test('CONTROL: si la PRIMERA request (el Read, antes de borrar nada) falla ⇒ 503 sin marca, CERO eventos y las tuplas intactas — ahí «esa escritura no ocurrió» es verdad', async ({ assert }) => {
      const { config, driver } = await realDriver()
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      await driver.relate(u, 'viewer', doc, p)
      const events: any[] = []
      const manager = new RelationsManager(driver, config, { onRelationWrite: (e) => void events.push(e) })
      // Falla TODO Read mientras no se haya borrado nada: las dos purgas mueren en su primera request.
      const fault = faultyClient(driver, (method, seen) => method === 'read' && !seen.includes('deleteTuples'))
      const caughtObject = await manager.purgeObject(doc, p).then(() => null, (e) => e)
      const caughtSubject = await manager.purgeSubject(u, p).then(() => null, (e) => e)
      fault.restore()
      assert.equal(caughtObject?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
      assert.equal(caughtSubject?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
      assert.deepEqual(events, [], 'nada se borró: nada que auditar como indeterminado')
      assert.isTrue(await driver.check(u, 'viewer', doc, p), 'la tupla sigue')
    })

    /**
     * **Cierre-2 · ⚪ 5**: el driver de relaciones clasificaba el timeout por
     * SUBSTRING del mensaje (`/timeout/i`), así que un error que decía «NO es
     * timeout» salía como 503 `E_AUTHZ_BACKEND_TIMEOUT` con `indeterminate:
     * true` sin haber borrado nada (B del auditor). Ahora usa el
     * `isTimeoutLike` de `backend_guard.ts`, el mismo que el driver de roles:
     * solo `ECONNABORTED`/`ETIMEDOUT`/`.timeout` numérico/`KnexTimeoutError`.
     */
    test('cierre-2 · ⚪ 5 · un error cuyo MENSAJE dice «timeout» pero no lo es (antes de borrar) ⇒ 503 E_AUTHZ_BACKEND_UNAVAILABLE y CERO eventos; uno con code ETIMEDOUT ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT e indeterminate: true (el mismo criterio que roles)', async ({
      assert,
    }) => {
      const { config, driver } = await realDriver()
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      await driver.relate(u, 'viewer', doc, p)
      const events: any[] = []
      const manager = new RelationsManager(driver, config, { onRelationWrite: (e) => void events.push(e) })
      const holder = driver as unknown as { client: any }
      const original = holder.client
      const failFirstReadWith = (make: () => Error) => {
        let fired = false
        holder.client = new Proxy(original, {
          get(target, prop, receiver) {
            const value = Reflect.get(target, prop, receiver)
            if (prop !== 'read' || typeof value !== 'function') return value
            return (...args: unknown[]) => {
              if (!fired) {
                fired = true
                throw make()
              }
              return value.apply(target, args)
            }
          },
        })
      }
      failFirstReadWith(() => new Error('socket reset (503, NO es timeout)'))
      const notTimeout = await manager.purgeObject(doc, p).then(() => null, (e) => e)
      holder.client = original
      assert.equal(notTimeout?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', `ROJO (B del auditor): la palabra «timeout» en el mensaje lo clasificó como timeout: ${notTimeout?.message}`)
      assert.deepEqual(events, [], 'no se borró nada y no es timeout: cero eventos')
      failFirstReadWith(() => Object.assign(new Error('read ETIMEDOUT'), { code: 'ETIMEDOUT' }))
      const timeout = await manager.purgeObject(doc, p).then(() => null, (e) => e)
      holder.client = original
      assert.equal(timeout?.code, 'E_AUTHZ_BACKEND_TIMEOUT', timeout?.message)
      assert.deepEqual(events.map((e) => [e.operation, e.indeterminate]), [['purgeObject', true]], 'un timeout de verdad sigue siendo indeterminado')
      assert.isTrue(await driver.check(u, 'viewer', doc, p), 'la tupla sigue en los dos casos')
    })
  })

  /* ── R-10 · el TRUNCADO de listObjects, MEDIDO contra el tope del servidor ── */

  test.group('openfga relaciones — listObjectsTruncation MEDIDO contra el servidor', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    test(`listObjects señala truncado cuando el servidor corta (tope real ${capsLow ? serverListObjectsCap : '1000+'})`, async ({
      assert,
    }) => {
      const config = contractRelationsConfig()
      const { storeId, modelId } = await provisionFusedStore(config)
      stores.push(storeId)
      const { OpenFgaClient } = await import('@openfga/sdk')
      const driver = new OpenFgaRelationsDriver(config, {
        apiUrl,
        storeId,
        modelId,
        holderTypes: HOLDER_MAP,
        listObjectsMaxResults: serverListObjectsCap,
        logger: { warn: () => {} },
      })
      const u = { type: 'user', uuid: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const TOTAL = capsLow ? serverListObjectsCap + 3 : 5
      for (let i = 0; i < TOTAL; i++) {
        await driver.relate(u, 'viewer', { type: 'document', id: uuidv7() }, p)
      }
      const page = await driver.listObjects(u, 'viewer', 'document', p)

      if (capsLow) {
        // El SERVIDOR corta a su tope; el driver lo SEÑALA y no calla la lista parcial.
        assert.equal(page.objects.length, serverListObjectsCap, 'ListObjects devuelve el tope del servidor')
        assert.isTrue(page.truncated, 'con el servidor cortando, truncated: true')
        // Y es el SERVIDOR quien corta, no el driver: un `Read` crudo (sin tope)
        // demuestra que las TOTAL tuplas existen de verdad.
        const raw = new OpenFgaClient({ apiUrl, storeId, authorizationModelId: modelId })
        const read = await raw.read({ user: `user:${u.uuid}`, object: 'document:' })
        assert.equal((read.tuples ?? []).length, TOTAL, 'las tuplas existen; el truncado es del servidor')
      } else {
        // Con el tope alto y pocas tuplas NO hay corte: exhaustiva, sin señal FALSA.
        assert.equal(page.objects.length, TOTAL)
        assert.isUndefined(page.truncated, 'sin corte del servidor no se inventa un truncado')
      }
    })
  })

  /* ── L-5 · `openfga` rechaza `{ transaction }` CON DIENTES (puerto de relaciones), contra el `:8101` ── */

  /**
   * L-5 (panel `{trx}`, veredicto (C); `panel-trx-juez.md` §7 · L-5). **Una
   * tupla de OpenFGA no puede entrar en una transacción SQL** (otro servicio,
   * sin 2PC): `transactionalWrites` es «los dos o ninguno» y este driver lo
   * declara `false`. Se hace cumplir por DOS puertas: el `RelationsManager`
   * (L-2) y, desde L-5, el DRIVER mismo (`manager.driver()` y
   * `reconcileRelations` entran por el driver; sin la guarda, un
   * `{ transaction }` por ahí escribiría la tupla IGNORANDO la transacción —
   * la misma lección que F-05 en L-0).
   *
   * El espía va sobre el cliente FGA REAL contra el `:8101` (ni un `Write`,
   * ni un `Read`, ni un `Check`); el arranque se prueba por el PROVIDER con el
   * driver real. **Mutante M2** (quitar `#assertTransactional` del
   * `RelationsManager`): el caso «por el manager» sigue VERDE porque el
   * driver re-valida; sin la guarda del driver, ROJO con un `Write` real.
   */
  test.group('L-5 · openfga (relations) rechaza { transaction } con dientes: 500 E_AUTHZ_UNSUPPORTED con CERO llamadas al cliente FGA (espía sobre el cliente real), por el manager Y por el driver; y el arranque por el provider', (group) => {
    const stores: string[] = []
    group.tap((t) => t.tags(['@l5']))
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    /** El driver de relaciones REAL sobre un store recién provisionado con el modelo fusionado. */
    async function realDriver(): Promise<{ config: RelationsConfig; driver: OpenFgaRelationsDriver }> {
      const config = contractRelationsConfig()
      const { storeId, modelId } = await provisionFusedStore(config)
      stores.push(storeId)
      const driver = new OpenFgaRelationsDriver(config, {
        apiUrl,
        storeId,
        modelId,
        holderTypes: HOLDER_MAP,
        logger: { warn: () => {} },
      })
      return { config, driver }
    }

    async function rejects(assert: any, run: () => Promise<unknown>, label: string): Promise<any> {
      try {
        await run()
      } catch (error: any) {
        assert.equal(error?.status, 500, `${label}: status de ${error?.message ?? error}`)
        assert.equal(error?.code, 'E_AUTHZ_UNSUPPORTED', `${label}: code de ${error?.message ?? error}`)
        return error
      }
      assert.fail(`ROJO: ${label} con { transaction } NO lanzó sobre openfga (¿escribió una tupla fingiendo ir en la transacción?)`)
    }

    const trx = { from() {}, table() {}, isTransaction: true, connectionName: 'primary' }

    test('por el MANAGER: relate/unrelate/purgeObject/purgeSubject con { transaction } ⇒ 500 nombrando openfga y la operación, CERO llamadas al cliente FGA, sin onRelationWrite; sin transaction la misma llamada entra (y el cliente sí se llama)', async ({
      assert,
    }) => {
      const { config, driver } = await realDriver()
      assert.strictEqual(driver.capabilities.transactionalWrites, false, 'openfga declara false EXPLÍCITO')
      const spy = spyFgaClient(driver)
      const events: unknown[] = []
      const manager = new RelationsManager(driver, config, { driverName: 'openfga', onRelationWrite: (e) => void events.push(e) })
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const writes: Array<[string, () => Promise<unknown>]> = [
        ['relate', () => manager.relate(u, 'viewer', doc, p, { transaction: trx })],
        ['unrelate', () => manager.unrelate(u, 'viewer', doc, p, { transaction: trx })],
        ['purgeObject', () => manager.purgeObject(doc, p, { transaction: trx })],
        ['purgeSubject', () => manager.purgeSubject(u, p, { transaction: trx })],
      ]
      for (const [operation, run] of writes) {
        const error = await rejects(assert, run, `manager.${operation}`)
        assert.include(error.message, `'openfga'`, `${operation}: nombra el driver`)
        assert.include(error.message, operation, `${operation}: nombra la operación`)
        assert.include(error.message, 'transacción SQL', `${operation}: dice el porqué`)
      }
      assert.deepEqual(spy.calls, [], 'CERO llamadas al cliente FGA: ni un Write, ni un Read, ni un Check')
      assert.deepEqual(events, [], 'nada que auditar: no se llegó al driver')
      await manager.relate(u, 'viewer', doc, p)
      assert.isAbove(spy.total(), 0, 'sin transaction el driver escribe en el store')
      assert.isTrue(await manager.check(u, 'viewer', doc, p))
      assert.lengthOf(events, 1)
    })

    test('por el DRIVER en directo (manager.driver()): las cuatro con { transaction } ⇒ el MISMO 500 con CERO llamadas al cliente FGA (defensa en profundidad: el driver re-valida)', async ({
      assert,
    }) => {
      const { driver } = await realDriver()
      const spy = spyFgaClient(driver)
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const writes: Array<[string, () => Promise<unknown>]> = [
        ['relate', () => driver.relate(u, 'viewer', doc, p, { transaction: trx })],
        ['unrelate', () => driver.unrelate(u, 'viewer', doc, p, { transaction: trx })],
        ['purgeObject', () => driver.purgeObject(doc, p, { transaction: trx })],
        ['purgeSubject', () => driver.purgeSubject(u, p, { transaction: trx })],
      ]
      for (const [operation, run] of writes) {
        const error = await rejects(assert, run, `driver.${operation}`)
        assert.include(error.message, operation, `${operation}: nombra la operación`)
        assert.include(error.message, 'transacción SQL', `${operation}: dice el porqué`)
      }
      assert.deepEqual(spy.calls, [], 'CERO llamadas al cliente FGA por el camino del driver')
      assert.isFalse(await driver.check(u, 'viewer', doc, p), 'el store no tiene la tupla: no se escribió «fuera de la transacción» en silencio')
      spy.reset()
      await driver.relate(u, 'viewer', doc, p)
      assert.isAbove(spy.total(), 0)
      assert.isTrue(await driver.check(u, 'viewer', doc, p))
    })

    test('ARRANQUE por el PROVIDER: relations.default openfga (driver REAL) + requireTransactionalWrites: true (raíz o en relations) ⇒ 500 E_AUTHZ_CONFIG al construir el RelationsManager, cero llamadas al cliente; default database (capaz) + openfga solo REGISTRADO ⇒ construye y la factory de openfga no se invoca', async ({
      assert,
    }) => {
      const { config, driver } = await realDriver()
      const spy = spyFgaClient(driver)
      const baseConfig = (relations: Record<string, unknown>, root: Record<string, unknown> = {}) =>
        ({ default: 'database', drivers: {}, warnOnOptInSecurity: false, ...root, relations: { config, ...relations } }) as any

      for (const [label, cfg] of [
        ['raíz', baseConfig({ default: 'openfga', drivers: { openfga: () => driver } }, { requireTransactionalWrites: true })],
        ['relations', baseConfig({ default: 'openfga', drivers: { openfga: () => driver }, requireTransactionalWrites: true })],
      ] as Array<[string, any]>) {
        let caught: any
        try {
          await buildRelationsManager(cfg)
          assert.fail(`ROJO (${label}): el RelationsManager se construyó sobre openfga con requireTransactionalWrites: true`)
        } catch (error) {
          caught = error
        }
        assert.equal(caught?.status, 500, `${label}: ${caught?.message}`)
        assert.equal(caught?.code, 'E_AUTHZ_CONFIG', label)
        assert.include(caught.message, `'openfga'`, `${label}: nombra el driver`)
        assert.include(caught.message, 'transactionalWrites', `${label}: nombra la capacidad`)
      }
      assert.deepEqual(spy.calls, [], 'no arrancar es no hablar con el store')

      // Un driver solo REGISTRADO no inutiliza el despliegue: con `database`
      // (capaz) activo, arranca y la factory de `openfga` ni se invoca.
      let openFgaFactoryCalls = 0
      const manager = await buildRelationsManager(
        baseConfig(
          {
            drivers: {
              database: () => new DatabaseRelationsDriver(config),
              openfga: () => {
                openFgaFactoryCalls += 1
                return driver
              },
            },
          },
          { requireTransactionalWrites: true }
        )
      )
      assert.strictEqual(manager.driver().capabilities?.transactionalWrites, true, 'database declara true (default)')
      assert.equal(openFgaFactoryCalls, 0, 'un driver solo registrado no se construye ni se juzga')
    })
  })

  /* ── alpha.6 · pieza 1 · el barrido ÚNICO de `enumerateRelations` ───────── */

  /**
   * **alpha.6 · barrido ÚNICO** (panel relay, analista §3; auditor 🔴 3 / 🟡 8;
   * decisión del dueño 2026-09-10 (3)). `enumerateRelations(partition)` es
   * `Read({})` del store ENTERO + filtro en JS: K particiones = K barridos,
   * O(store) cada uno (medido: 3 particiones en 5 000 tuplas ⇒ 150 `Read`,
   * ~0,5 s). `enumerateRelationsMany(partitions)` hace UN `Read({})` y reparte
   * por `partitionKey` — la forma que el analista midió (1,4 s → 0,46 s con 3).
   *
   * Lo que NO puede hacer, con espía sobre el cliente REAL: un `Read` con
   * `object` parcial (prefijo `document:unit|<uuid>|`) responde **200 con
   * cero tuplas** (medido por el panel): «esta partición está vacía» en el
   * ORIGEN de una migración. Por eso el caso mira el FILTRO de cada `read`,
   * no solo cuántos hubo. Y «exhaustivo o ruidoso»: una página vacía con
   * token no es el fin, un token que se repite es 503, una respuesta sin
   * `tuples` es 503 — jamás «vacío = éxito».
   */
  test.group('alpha.6 · barrido ÚNICO de `enumerateRelations`: K particiones = UN `Read({})` paginado, sin prefijo, exhaustivo o ruidoso (espía sobre el cliente REAL)', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    /** 3 particiones × PER + FOREIGN ajenas ⇒ más de una página de `Read` (100). */
    const PER = 40
    const FOREIGN = 60
    const PAGES = Math.ceil((3 * PER + FOREIGN) / 100)

    const keyOf = (p: ScopeRef) => (p.type === 'app' ? 'app' : `${p.type}|${p.uuid}`)
    const sorted = (tuples: RelationTuple[]) =>
      tuples
        .map((t) => ({ ...t, expiresAt: t.expiresAt ?? null }))
        .sort((a, b) => (a.object.id < b.object.id ? -1 : a.object.id > b.object.id ? 1 : 0))

    async function seeded(partitions: ScopeRef[], per: number, foreign: number) {
      const config = contractRelationsConfig()
      const { storeId, modelId } = await provisionFusedStore(config)
      stores.push(storeId)
      const { OpenFgaClient } = await import('@openfga/sdk')
      const client = new OpenFgaClient({ apiUrl, storeId, authorizationModelId: modelId })
      const writes: Array<{ user: string; relation: string; object: string }> = []
      for (const p of partitions) {
        for (let i = 0; i < per; i++) writes.push({ user: `user:${uuidv7()}`, relation: 'viewer', object: `document:${keyOf(p)}|${uuidv7()}` })
      }
      const other: ScopeRef = { type: 'organization', uuid: uuidv7() }
      for (let i = 0; i < foreign; i++) writes.push({ user: `user:${uuidv7()}`, relation: 'viewer', object: `document:${keyOf(other)}|${uuidv7()}` })
      for (let i = 0; i < writes.length; i += 100) await client.write({ writes: writes.slice(i, i + 100) })
      const driver = new OpenFgaRelationsDriver(config, { apiUrl, storeId, modelId, holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
      const spy = spyFgaClient(driver)
      return { driver, spy, config }
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
    }

    test('EL CASO: 3 particiones (`app`, `appliance|…` —prefijo literal de `app`— y `unit|…`) ⇒ `enumerateRelationsMany` hace UN barrido (`read` = páginas del store, cada uno con filtro `{}`: ningún `object`), reparte 40/40/40 y su salida por partición es IDÉNTICA a la de tres `enumerateRelations` (que cuestan 3× lecturas)', async ({
      assert,
    }) => {
      const appliance: ScopeRef = { type: 'appliance', uuid: uuidv7() } // 3-3: `document:app` es prefijo de `document:appliance|…`
      const unit: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const partitions = [APP_SCOPE, appliance, unit]
      const { driver, spy } = await seeded(partitions, PER, FOREIGN)

      // Hoy: tres barridos (la forma del coste, no su magnitud: 3 × páginas).
      const baseline = new Map<string, RelationTuple[]>()
      for (const p of partitions) baseline.set(keyOf(p), sorted((await driver.enumerateRelations(p)).tuples))
      const threeSweeps = spy.calls.filter((c) => c === 'read').length
      assert.equal(threeSweeps, 3 * PAGES, 'tres enumerateRelations = tres barridos del store entero')
      spy.reset()

      const page = await driver.enumerateRelationsMany!(partitions)
      const reads = spy.invocations.filter((i) => i.method === 'read')
      assert.lengthOf(reads, PAGES, 'UN barrido: tantas lecturas como páginas tiene el store, sea cual sea K')
      for (const read of reads) {
        assert.deepEqual(read.args[0], {}, 'ningún Read lleva object/user/relation: el prefijo está PROHIBIDO (200 con cero tuplas)')
      }
      assert.isUndefined(page.cursor, 'exhaustivo: todo en una página, como enumerateRelations')
      for (const p of partitions) {
        const mine = sorted(page.tuples.filter((t) => keyOf(t.partition) === keyOf(p)))
        assert.lengthOf(mine, PER, `partición ${keyOf(p).slice(0, 12)}: sus ${PER}, ni una ajena`)
        assert.deepEqual(mine, baseline.get(keyOf(p))!, 'paridad con la versión de hoy, tupla a tupla')
      }
      assert.lengthOf(page.tuples, 3 * PER, 'las ajenas (otra partición) no vienen')
    })

    test('reconcileRelations({ partitions: [3] }) desde openfga ⇒ UN barrido del origen (`read` = páginas) y el MISMO destino que tres reconciles por partición; el reporte es la SUMA', async ({
      assert,
    }) => {
      const partitions: ScopeRef[] = [APP_SCOPE, { type: 'appliance', uuid: uuidv7() }, { type: 'unit', uuid: uuidv7() }]
      const { driver, spy, config } = await seeded(partitions, PER, FOREIGN)
      const many = makeRelationsDriver({ config, capabilities: CAPS })
      const one = makeRelationsDriver({ config, capabilities: CAPS })

      const report = await reconcileRelations({ from: driver, to: many, partitions, toConfig: config })
      assert.equal(spy.calls.filter((c) => c === 'read').length, PAGES, 'el origen se barre UNA vez para las tres')
      spy.reset()

      const sum = { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 }
      for (const p of partitions) {
        const r = await reconcileRelations({ from: driver, to: one, partition: p, toConfig: config })
        sum.written += r.written
        sum.updated += r.updated
        sum.unchanged += r.unchanged
        sum.extra += r.extra
        sum.deleted += r.deleted
      }
      assert.equal(spy.calls.filter((c) => c === 'read').length, 3 * PAGES, 'por partición: tres barridos')
      assert.deepEqual(
        { written: report.written, updated: report.updated, unchanged: report.unchanged, extra: report.extra, deleted: report.deleted },
        sum
      )
      assert.equal(report.written, 3 * PER)
      for (const p of partitions) {
        assert.deepEqual(
          sorted((await many.enumerateRelations!(p)).tuples),
          sorted((await one.enumerateRelations!(p)).tuples),
          'el destino es el mismo, partición a partición'
        )
        assert.lengthOf((await many.enumerateRelations!(p)).tuples, PER)
      }
      const again = await reconcileRelations({ from: driver, to: many, partitions, toConfig: config })
      assert.equal(again.written + again.updated + again.deleted, 0, 'idempotente')
      assert.equal(again.unchanged, 3 * PER)
    })

    test('particiones que comparten prefijo NO se cruzan: `org|U` vs `organization|U` (3-4) — cada una recibe EXACTAMENTE las suyas, también con un solo `Read({})`; y la ortografía SIN guiones del uuid ya no es «otra partición»: es 422 (D4, plan 2.5 · lote A) con cero lecturas', async ({
      assert,
    }) => {
      const uuid = uuidv7()
      const org: ScopeRef = { type: 'org', uuid }
      const organization: ScopeRef = { type: 'organization', uuid }
      const dashed: ScopeRef = { type: 'unit', uuid }
      const dashless: ScopeRef = { type: 'unit', uuid: uuid.replace(/-/g, '') }
      const partitions = [org, organization, dashed]
      const { driver, spy } = await seeded(partitions, 3, 0)
      const page = await driver.enumerateRelationsMany!(partitions)
      assert.equal(spy.calls.filter((c) => c === 'read').length, 1)
      for (const p of partitions) {
        const mine = page.tuples.filter((t) => keyOf(t.partition) === keyOf(p))
        assert.lengthOf(mine, 3, keyOf(p))
        assert.deepEqual(sorted(mine), sorted((await driver.enumerateRelations(p)).tuples))
      }
      assert.lengthOf(page.tuples, 9)
      // Pedir solo una devuelve solo la suya (no «todo lo que casa por prefijo»).
      const only = await driver.enumerateRelationsMany!([org])
      assert.lengthOf(only.tuples, 3)
      assert.isTrue(only.tuples.every((t) => keyOf(t.partition) === keyOf(org)))
      // D4: hasta 2.5.0 `unit|<32 hex>` era una CUARTA partición (3-6) que nadie canonizaba; ahora es 422 en la
      // puerta —en `enumerateRelationsMany` aunque vaya en la posición 1— y no se lee nada.
      spy.reset()
      for (const [label, run] of [
        ['enumerateRelations', () => driver.enumerateRelations(dashless)],
        ['enumerateRelationsMany', () => driver.enumerateRelationsMany!([org, dashless])],
        ['purgeObject', () => driver.purgeObject({ type: 'document', id: uuidv7() }, dashless)],
        ['checkMany', () => driver.checkMany!({ type: 'user', uuid: uuidv7() }, 'viewer', [{ type: 'document', id: uuidv7() }], dashless)],
      ] as Array<[string, () => Promise<unknown>]>) {
        const caught = await run().then(() => null, (e) => e)
        assert.equal(caught?.code, 'E_AUTHZ_INVALID_IDENTITY', `${label}: ${caught?.message}`)
        assert.include(String(caught?.message), uuid, `${label}: nombra la forma canónica`)
      }
      assert.lengthOf(spy.calls, 0, 'CERO llamadas al cliente con la ortografía sin guiones')
    })

    test('MUTANTE «una página vacía = fin» ⇒ rojo: una página con CERO tuplas y token de continuación no termina el barrido (todas llegan, una lectura más); un token que se REPITE es 503 E_AUTHZ_BACKEND_UNAVAILABLE; una respuesta SIN `tuples` es 503 — nunca una partición vacía en verde', async ({
      assert,
    }) => {
      const partitions: ScopeRef[] = [APP_SCOPE, { type: 'unit', uuid: uuidv7() }, { type: 'unit', uuid: uuidv7() }]
      const { driver, spy } = await seeded(partitions, PER, FOREIGN)
      const client = (driver as any).client
      const realRead = client.read.bind(client)

      // (a) primera página vacía con token sintético ⇒ el driver sigue (y la
      // segunda llamada retoma desde el principio REAL, sin el token falso).
      let served = 0
      ;(driver as any).client = {
        // L11: la puerta (parte `conditions`) lee el modelo con el cliente REAL.
        readAuthorizationModel: client.readAuthorizationModel.bind(client),
        read: (filter: any, options: any) => {
          served += 1
          if (served === 1) return Promise.resolve({ tuples: [], continuation_token: 'alpha6-empty-page' })
          return realRead(filter, options?.continuationToken === 'alpha6-empty-page' ? { ...options, continuationToken: undefined } : options)
        },
      }
      const page = await driver.enumerateRelationsMany!(partitions)
      assert.lengthOf(page.tuples, 3 * PER, 'la página vacía NO fue el fin: llegaron todas')
      assert.equal(served, PAGES + 1)

      // (b) token que se repite ⇒ 503, no una enumeración parcial.
      served = 0
      ;(driver as any).client = {
        // L11: la puerta (parte `conditions`) lee el modelo con el cliente REAL.
        readAuthorizationModel: client.readAuthorizationModel.bind(client),
        read: (filter: any, options: any) => {
          served += 1
          if (served <= 2) return Promise.resolve({ tuples: [], continuation_token: 'alpha6-loop' })
          return realRead(filter, options)
        },
      }
      let caught: any
      try {
        await driver.enumerateRelationsMany!(partitions)
      } catch (error) {
        caught = error
      }
      assert.equal(caught?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
      assert.equal(caught?.status, 503)
      assert.include(String(caught?.cause?.message ?? ''), 'se repite')

      // (c) una respuesta que no se entiende (sin `tuples`) ⇒ 503, jamás «cero tuplas».
      ;(driver as any).client = { read: () => Promise.resolve({ continuation_token: '' }) }
      caught = undefined
      try {
        await driver.enumerateRelationsMany!(partitions)
      } catch (error) {
        caught = error
      }
      assert.equal(caught?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', 'sin `tuples` no hay «vacío»: hay ruido')
      caught = undefined
      try {
        await driver.enumerateRelations(partitions[1])
      } catch (error) {
        caught = error
      }
      assert.equal(caught?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', 'también en enumerateRelations (mismo barrido por debajo)')

      // (d) sin particiones no hay «éxito vacío»: 500 con CERO lecturas.
      ;(driver as any).client = client
      spy.reset()
      caught = undefined
      try {
        await driver.enumerateRelationsMany!([])
      } catch (error) {
        caught = error
      }
      assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
      assert.equal(spy.calls.filter((c) => c === 'read').length, 0)
    })
  })

  /* ── Plan 2.5 · lote D · D1 · el deny contra el servidor REAL (D14, D-31, S11, S12 por camino, S15, D-24, D-26, D8) ── */

  test.group('lote D · D1 · deny en openfga contra el servidor real (D14, D-31, S11, S12 por camino, S15, D-24, D-26/S3, D8)', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })

    async function denyStore(config: RelationsConfig = contractDenyRelationsConfig()) {
      const { storeId, modelId } = await provisionFusedStore(config)
      stores.push(storeId)
      return { storeId, modelId }
    }
    function driverOver(config: RelationsConfig, storeId: string, modelId: string) {
      return new OpenFgaRelationsDriver(config, { apiUrl, storeId, modelId, holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
    }
    const u = () => ({ type: 'user', uuid: uuidv7() })
    const doc = () => ({ type: 'document', id: uuidv7() })
    const part = (): ScopeRef => ({ type: 'unit', uuid: uuidv7() })

    test('🟠 R2 del panel «óptimo» (cierre 5 de D2) · un tipo SIN deny cuya regla la config ESTRECHÓ (viewer sin includes editor) y un pod fijado al modelo VIEJO ⇒ 500 E_AUTHZ_CONFIG nombrando note#viewer, jamás conceder por la regla vieja (database con la misma config niega); con el modelo de la config, responde', async ({ assert }) => {
      const wide = contractDenyRelationsConfig()
      const narrow = defineRelationsConfig({
        objectTypes: wide.objectTypes.map((t: any) => (t.type === 'note' ? { type: 'note', relations: t.relations.map((r: any) => (r.name === 'viewer' ? { name: 'viewer' } : r)) } : t)),
        holderTypes: ['user', 'admin', 'integration'],
        database: { membersOf: true },
      } as any)
      const { storeId, modelId } = await denyStore(wide)
      const p = part()
      const user = u()
      const note = { type: 'note', id: uuidv7() }
      const old = driverOver(wide, storeId, modelId)
      await old.relate(user, 'editor', note, p)
      assert.isTrue(await old.check(user, 'viewer', note, p), 'con el modelo de SU config, editor ⇒ viewer')
      const drifted = driverOver(narrow, storeId, modelId)
      const caught = await drifted.check(user, 'viewer', note, p).then(() => null, (e: any) => e)
      assert.equal(caught?.status, 500, `ROJO (R2): el pod con la config estrecha concede por la regla del modelo viejo (${caught})`)
      assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
      assert.include(String(caught?.message), 'note#viewer')
      const db = new DatabaseRelationsDriver(narrow)
      await db.relate(user, 'editor', note, p)
      assert.isFalse(await db.check(user, 'viewer', note, p), 'database con la config estrecha niega')
    })

    test('🟡 D5-2 (cierre 6 de D2) · la excepción D8 exige la forma CON deny ENTERA: un modelo a mano con `denied_editor = this` (sin el cierre del corte de camino) y un pod SIN opt-in ⇒ 500 E_AUTHZ_CONFIG nombrando note#editor, jamás conceder editor a quien tiene deny en viewer (database niega); el control CON opt-in también da 500 (reproducción del auditor, loteD2-auditor-cierre5-d31.ts)', async ({ assert }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const spec = (deny?: 'write') =>
        defineRelationsConfig({
          objectTypes: [{ type: 'note', relations: [{ name: 'editor' }, { name: 'viewer', includes: ['editor'] }], ...(deny ? { deny } : {}) }],
          holderTypes: ['user', 'admin', 'integration'],
        } as any)
      const model: any = openFgaFactsModel(HOLDER_MAP, [], { objectTypes: spec('write').objectTypes })
      model.type_definitions.find((d: any) => d.type === 'note').relations.denied_editor = { this: {} }
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `rel-d52-${Date.now()}` })
      stores.push(store.id!)
      const written = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(model)
      const modelId = written.authorization_model_id!
      const p = part()
      const user = u()
      const note = { type: 'note', id: uuidv7() }
      // Las filas, como las dejaría otro proceso: editor@U y denied_viewer@U (el pod sin opt-in no puede escribir el deny).
      const raw = new OpenFgaClient({ apiUrl, storeId: store.id, authorizationModelId: modelId })
      const optedIn = driverOver(spec('write'), store.id!, modelId)
      const objectId = `note:unit|${p.uuid}|${note.id}`
      await raw.write({ writes: [{ user: `user:${user.uuid}`, relation: 'editor', object: objectId }, { user: `user:${user.uuid}`, relation: 'denied_viewer', object: objectId }] })
      const noOptIn = driverOver(spec(), store.id!, modelId)
      const caught = await noOptIn.check(user, 'editor', note, p).then((v) => v, (e: any) => e)
      assert.equal(caught?.status, 500, `ROJO (D5-2): el pod SIN opt-in responde ${caught} con un modelo sin el cierre del corte de camino`)
      assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
      assert.include(String(caught?.message), 'note#denied_editor (regla)')
      const control = await optedIn.check(user, 'editor', note, p).then((v) => v, (e: any) => e)
      assert.equal(control?.status, 500, 'control: el pod CON opt-in y el mismo modelo ya daba 500 (D-31 · ⚪ N4)')
      const dbDriver = new DatabaseRelationsDriver(spec('write'))
      await dbDriver.relate(user, 'editor', note, p)
      await dbDriver.deny(user, 'viewer', note, p)
      assert.isFalse(await new DatabaseRelationsDriver(spec()).check(user, 'editor', note, p), 'database honra el deny (corte D5) también sin opt-in')
    })

    // L11 (decisión del dueño 2026-10-17 (2)): D14 AMPLIADO — el pin es obligatorio con o sin deny. Hasta L11 la mitad
    // «sin tipos con deny, sin pin sigue valiendo» era la expectativa; ahora es la misma 500 (caso que se puso rojo, a propósito).
    test('L11 · C14 · el driver de relaciones exige modelId FIJADO SIEMPRE (D14 ampliado): sin él ⇒ 500 E_AUTHZ_CONFIG al construir, con o sin tipos con deny, con la receta (OPENFGA_MODEL_ID, provision)', async ({ assert }) => {
      const { storeId } = await denyStore()
      for (const config of [contractDenyRelationsConfig(), contractRelationsConfig()]) {
        for (const modelId of [undefined, '', '   ']) {
          const caught = (() => {
            try {
              driverOver(config, storeId, modelId as any)
              return null
            } catch (e) {
              return e as any
            }
          })()
          assert.equal(caught?.status, 500, `modelId ${JSON.stringify(modelId)}`)
          assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
          assert.include(String(caught?.message), 'modelId')
          assert.include(String(caught?.message), 'OPENFGA_MODEL_ID')
          assert.include(String(caught?.message), 'openfga:provision')
        }
      }
    })

    test('D-31 · tipo con deny y modelo FIJADO SIN denied_<rel> (publicado desde la config sin deny) ⇒ 500 E_AUTHZ_CONFIG al USARLO (check, checkMany, decideMany, listObjects, relate, deny) con CERO Write/Check: solo la lectura del modelo, UNA por proceso (memo compartido con withClock)', async ({ assert }) => {
      const { storeId, modelId } = await denyStore(contractRelationsConfig())
      const driver = driverOver(contractDenyRelationsConfig(), storeId, modelId)
      const view = driver.withClock(() => new Date()) as OpenFgaRelationsDriver
      const spy = spyFgaClient(driver)
      const p = part()
      const runs: Array<[string, () => Promise<unknown>]> = [
        ['check', () => driver.check(u(), 'viewer', doc(), p)],
        ['checkMany', () => driver.checkMany(u(), 'viewer', [doc()], p)],
        ['decideMany', () => driver.decideMany(u(), 'viewer', [doc()], p)],
        ['listObjects', () => driver.listObjects(u(), 'viewer', 'document', p)],
        ['relate', () => driver.relate(u(), 'viewer', doc(), p)],
        ['deny', () => driver.deny(u(), 'viewer', doc(), p)],
        ['vista withClock · check', () => view.check(u(), 'viewer', doc(), p)],
      ]
      for (const [op, run] of runs) {
        const caught = await run().then(() => null, (e) => e)
        assert.equal(caught?.status, 500, `${op}: ${caught?.message}`)
        assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
        assert.include(String(caught?.message), 'document#denied_viewer')
      }
      assert.deepEqual([...new Set(spy.calls)], ['readAuthorizationModel'], 'ni un Write, Read de tuplas, Check ni ListObjects')
      assert.equal(spy.calls.length, 1, 'UNA lectura del modelo por proceso: el memo se comparte con la vista withClock')
    })

    test('⚪ 7 · D-31 juzga la FORMA: un modelo que declara document#denied_viewer pero deja viewer SIN restarlo (sin but not) ⇒ 500 E_AUTHZ_CONFIG al usarlo, cero Check', async ({ assert }) => {
      const { storeId } = await denyStore()
      const model: any = openFgaFactsModel(HOLDER_MAP, [], { objectTypes: contractDenyRelationsConfig().objectTypes })
      const document = model.type_definitions.find((t: any) => t.type === 'document')
      assert.exists(document.relations.denied_viewer, 'el modelo a mano DECLARA denied_viewer')
      document.relations.viewer = document.relations.viewer.difference.base
      const { OpenFgaClient } = await import('@openfga/sdk')
      const handWritten = await new OpenFgaClient({ apiUrl, storeId }).writeAuthorizationModel(model)
      const driver = driverOver(contractDenyRelationsConfig(), storeId, handWritten.authorization_model_id!)
      const spy = spyFgaClient(driver)
      const caught = await driver.check(u(), 'viewer', doc(), part()).then((answer) => ({ answer }), (e) => e)
      assert.equal(caught?.status, 500, `ROJO (⚪ 7): un modelo con denied_viewer que no resta respondió ${JSON.stringify(caught?.answer)}`)
      assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
      assert.include(String(caught?.message), 'document#viewer (regla)')
      assert.deepEqual(spy.calls, ['readAuthorizationModel'], 'solo la lectura del modelo: ni un Check')
    })

    /**
     * **⚪ N4 del auditor (cierre 2 de D1): D-31 juzga la REGLA, no solo la forma.** Un modelo escrito a mano con
     * `denied_editor: [user]` —sin `or denied_viewer`, el cierre ASCENDENTE del corte de camino (D5)— y `editor` restando
     * bien pasaba ⚪ 7: con U owner y un deny en `viewer`, el servidor CONCEDE `editor` (no hay camino del deny de viewer a
     * `denied_editor`) mientras `database` niega (`up*(owner) ∋ viewer`). La guarda compara ahora `<rel>` y `denied_<rel>`
     * con lo que GENERA el paquete (`factsRelationRewrites`), por igualdad estructural. Las tuplas se escriben con el
     * cliente CRUDO: el driver no llega a escribir con ese modelo. **Mutante** `fga.D31.shape-only` (volver a la forma de
     * ⚪ 7) ⇒ rojo con `true`.
     */
    test('⚪ N4 · D-31 juzga la REGLA: un modelo a mano con denied_editor sin el cierre (`or denied_viewer`) ⇒ 500 E_AUTHZ_CONFIG al usarlo, jamás el true que da el servidor', async ({ assert }) => {
      const { storeId } = await denyStore()
      const model: any = openFgaFactsModel(HOLDER_MAP, [], { objectTypes: contractDenyRelationsConfig().objectTypes })
      const document = model.type_definitions.find((t: any) => t.type === 'document')
      assert.deepEqual(document.relations.denied_editor, { union: { child: [{ this: {} }, { computedUserset: { relation: 'denied_viewer' } }] } }, 'lo que genera el paquete')
      document.relations.denied_editor = { this: {} }
      const { OpenFgaClient } = await import('@openfga/sdk')
      const handWritten = await new OpenFgaClient({ apiUrl, storeId }).writeAuthorizationModel(model)
      const raw = new OpenFgaClient({ apiUrl, storeId, authorizationModelId: handWritten.authorization_model_id! })
      const user = u()
      const d = doc()
      const p = part()
      const object = `document:unit|${p.uuid}|${d.id}`
      await raw.write({ writes: [
        { user: `user:${user.uuid}`, relation: 'owner', object },
        { user: `user:${user.uuid}`, relation: 'denied_viewer', object },
      ] })
      const served = await raw.check({ user: `user:${user.uuid}`, relation: 'editor', object, context: { current_time: new Date().toISOString() } })
      assert.isTrue(served.allowed, 'el modelo mal cerrado CONCEDE editor en el servidor (lo que la guarda tiene que impedir que el driver devuelva)')
      const driver = driverOver(contractDenyRelationsConfig(), storeId, handWritten.authorization_model_id!)
      const spy = spyFgaClient(driver)
      const caught = await driver.check(user, 'editor', d, p).then((answer) => ({ answer }), (e) => e)
      assert.equal(caught?.status, 500, `ROJO (⚪ N4): un modelo con denied_editor sin el cierre respondió ${JSON.stringify(caught?.answer)} donde database niega`)
      assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
      assert.include(String(caught?.message), 'document#denied_editor')
      assert.include(String(caught?.message), 'NO es el que genera la config de este proceso (L11')
      assert.deepEqual(spy.calls, ['readAuthorizationModel'], 'solo la lectura del modelo: ni un Check')
    })

    test('⚪ N4 · la igualdad es ESTRUCTURAL, no textual: un modelo equivalente (hijos de la unión en otro orden; el servidor devuelve `object: ""` y otro orden de claves) entra y el deny corta', async ({ assert }) => {
      const { storeId } = await denyStore()
      const model: any = openFgaFactsModel(HOLDER_MAP, [], { objectTypes: contractDenyRelationsConfig().objectTypes })
      const document = model.type_definitions.find((t: any) => t.type === 'document')
      document.relations.denied_editor.union.child.reverse()
      document.relations.viewer.difference.base.union.child.reverse()
      const { OpenFgaClient } = await import('@openfga/sdk')
      const equivalent = await new OpenFgaClient({ apiUrl, storeId }).writeAuthorizationModel(model)
      const driver = driverOver(contractDenyRelationsConfig(), storeId, equivalent.authorization_model_id!)
      const user = u()
      const d = doc()
      const p = part()
      await driver.relate(user, 'owner', d, p)
      await driver.deny(user, 'viewer', d, p)
      assert.isFalse(await driver.check(user, 'editor', d, p), 'el deny en viewer corta editor del owner (D5)')
      await driver.removeDeny(user, 'viewer', d, p)
      assert.isTrue(await driver.check(user, 'editor', d, p))
    })

    test('S11 · FILA DECLARADA: un pod con el modelId VIEJO (sin denied_*) y la config vieja CONCEDE sobre un objeto denegado por un pod nuevo; el pod nuevo, no (runbook: provision → fijar modelId en TODA la flota → solo entonces deny: write)', async ({ assert }) => {
      const oldModel = await denyStore(contractRelationsConfig())
      const { OpenFgaClient } = await import('@openfga/sdk')
      const newModel = await new OpenFgaClient({ apiUrl, storeId: oldModel.storeId }).writeAuthorizationModel(
        openFgaFactsModel(HOLDER_MAP, [], { objectTypes: contractDenyRelationsConfig().objectTypes })
      )
      const writer = driverOver(contractDenyRelationsConfig(), oldModel.storeId, newModel.authorization_model_id!)
      const oldReader = driverOver(contractRelationsConfig(), oldModel.storeId, oldModel.modelId)
      const user = u()
      const d = doc()
      const p = part()
      await writer.relate(user, 'viewer', d, p)
      await writer.deny(user, 'viewer', d, p)
      assert.isFalse(await writer.check(user, 'viewer', d, p))
      assert.isTrue(await oldReader.check(user, 'viewer', d, p), 'FILA DECLARADA (S11): el pod viejo ignora el deny — ventana del rolling deploy')
    })

    /**
     * **S12 · un espía que QUITA `context` (el `current_time` de la condición `not_expired`) en UN camino** (M6: el
     * servidor responde 400 / error por ítem cuando a una tupla condicional le falta el parámetro, también en la rama
     * RESTADA): el paquete tiene que devolver 503 —jamás T/F/`none`/una lista—. Un mutante por camino («error ⇒
     * false/none/[]») lo pone rojo. Tuplas del caso C de M6: allow fijo + deny transportado por una membresía
     * CONDICIONAL viva.
     */
    test('S12 · sin `context` en check / checkMany / decideMany / listObjects ⇒ 500 E_AUTHZ_CONFIG (R3: validation_error = despliegue; hasta R3, 503) en CADA camino (nunca T, F, none ni una lista); con context, el deny transportado bloquea', async ({ assert }) => {
      const { storeId, modelId } = await denyStore()
      const driver = driverOver(contractDenyRelationsConfig(), storeId, modelId)
      const user = u()
      const g = { type: 'group', id: uuidv7() }
      const d = doc()
      const p = part()
      await driver.relate(user, 'viewer', d, p)
      await driver.relate(user, 'member', g, p, { expiresAt: new Date(Date.now() + 3_600_000) })
      await driver.deny({ object: g, relation: 'member' }, 'viewer', d, p)
      assert.isFalse(await driver.check(user, 'viewer', d, p), 'control: con context, el deny transportado bloquea')
      assert.deepEqual(await driver.decideMany(user, 'viewer', [d], p), ['deny'])
      // El espía: quita `context` de check, de CADA ítem de batchCheck y de listObjects.
      const client = (driver as any).client
      const strip = (method: string, fn: (req: any) => any) => {
        const original = client[method].bind(client)
        client[method] = (req: any, opts: any) => original(fn(req), opts)
      }
      strip('check', ({ context: _c, ...rest }: any) => rest)
      strip('batchCheck', (req: any) => ({ ...req, checks: req.checks.map(({ context: _c, ...rest }: any) => rest) }))
      strip('listObjects', ({ context: _c, ...rest }: any) => rest)
      const paths: Array<[string, () => Promise<unknown>]> = [
        ['check', () => driver.check(user, 'viewer', d, p)],
        ['checkMany', () => driver.checkMany(user, 'viewer', [d], p)],
        ['decideMany', () => driver.decideMany(user, 'viewer', [d], p)],
        ['listObjects', () => driver.listObjects(user, 'viewer', 'document', p)],
      ]
      // R3 (decisión del dueño 2026-10-17 (3); rojo previsto por el juez): el 400 / el ítem `validation_error` de un
      // contexto ausente comparte código con «relación ausente del modelo» y separarlos exigiría leer el mensaje
      // (prohibido): los dos son la clase «despliegue o dato inválido» ⇒ 500 E_AUTHZ_CONFIG, marcado transitorio para el
      // relay. Que falte `current_time` es un defecto del PAQUETE (el driver lo manda siempre): 500 es lo honesto.
      for (const [path, run] of paths) {
        const outcome = await run().then((answer) => ({ answer }), (e) => e)
        assert.equal(outcome?.status, 500, `ROJO (S12 · ${path}): sin context respondió ${JSON.stringify(outcome?.answer ?? outcome?.message)}`)
        assert.equal(outcome?.code, 'E_AUTHZ_CONFIG', path)
        assert.isTrue(outcome?.deploymentFailure === true, `${path}: marcado como fallo de despliegue`)
      }
    })

    /**
     * **R3-3 (lote «antes de RC» · R3, decisión del dueño 2026-10-17 (4))**: una anidación de grupos más profunda que lo
     * que OpenFGA resuelve (la cadena de 26 de F0 · M-d) ⇒ 503 `E_AUTHZ_RESOLUTION_LIMIT` en `check` (la excepción del
     * SDK) Y en `checkMany`/`decideMany` (el error POR ÍTEM del `batchCheck`, que pasa por el MISMO clasificador: H9) —
     * jamás `false`/`none`, y nunca el 503 genérico—. El borde lo fija R1; aquí basta que 26 está fuera.
     */
    test('R3-3 · anidación de 26 grupos ⇒ 503 E_AUTHZ_RESOLUTION_LIMIT en check, checkMany y decideMany (la excepción y el ítem del batchCheck, mismo clasificador); nunca false/none', async ({ assert }) => {
      const { storeId, modelId } = await denyStore()
      const driver = driverOver(contractDenyRelationsConfig(), storeId, modelId)
      const user = u()
      const d = doc()
      const p = part()
      const groups = Array.from({ length: 27 }, () => ({ type: 'group', id: uuidv7() }))
      // R1 (rojo justificado): desde el sublote 4 el gate de escritura rechaza la arista del salto 23 (422
      // E_AUTHZ_GROUP_DEPTH_LIMIT). La cadena de 26 es aquí PREEXISTENTE —escrita antes de 2.5.0-alpha.4, o con el techo
      // apagado de forma explícita (`maxGroupDepth: false`)—, que es justo la cara de LECTURA que este caso juzga.
      const seeder = driverOver({ ...contractDenyRelationsConfig(), maxGroupDepth: false }, storeId, modelId)
      await seeder.relate(user, 'member', groups[0], p)
      for (let i = 1; i < groups.length; i++) await seeder.relate({ object: groups[i - 1], relation: 'member' }, 'member', groups[i], p)
      await seeder.relate({ object: groups[groups.length - 1], relation: 'member' }, 'viewer', d, p)
      const paths: Array<[string, () => Promise<unknown>]> = [
        ['check', () => driver.check(user, 'viewer', d, p)],
        ['checkMany', () => driver.checkMany(user, 'viewer', [d], p)],
        ['decideMany', () => driver.decideMany(user, 'viewer', [d], p)],
      ]
      for (const [path, run] of paths) {
        const outcome: any = await run().then((answer) => ({ answer }), (e) => e)
        assert.equal(outcome?.status, 503, `R3-3 · ${path}: ${JSON.stringify(outcome?.answer ?? outcome?.message)}`)
        assert.equal(outcome?.code, 'E_AUTHZ_RESOLUTION_LIMIT', `R3-3 · ${path}`)
        assert.include(String(outcome?.message), 'Limits', `R3-3 · ${path}: la letra apunta a «Limits»`)
      }
    }).timeout(60_000)

    test('🟡 4 (cierre 1 de D2) · re-deny sobre un deny CONDICIONAL (escrito a mano) ⇒ 500 E_AUTHZ_CONFIG con la letra de M5, nunca un 503 que se repite; el reconcile database → openfga lo lista como residuo deny-conditional (dos pasadas, sin 503) y la receta removeDeny + deny lo deja permanente', async ({ assert }) => {
      const { storeId, modelId } = await denyStore()
      const driver = driverOver(contractDenyRelationsConfig(), storeId, modelId)
      const user = u()
      const d = doc()
      const p = part()
      await driver.relate(user, 'viewer', d, p)
      // El deny CONDICIONAL solo puede venir de fuera del paquete (D3): se escribe con el SDK, con la clave del driver.
      const client = (driver as any).client
      const allow = (await client.read({})).tuples.find((t: any) => t.key.relation === 'viewer').key
      const until = new Date(Date.now() + 3_600_000)
      await client.write({
        writes: [{ user: allow.user, relation: 'denied_viewer', object: allow.object, condition: { name: 'not_expired', context: { valid_until: until.toISOString() } } }],
      })
      assert.isFalse(await driver.check(user, 'viewer', d, p), 'el deny condicional VIVO niega')
      const caught = await driver.deny(user, 'viewer', d, p).then(() => null, (e) => e)
      assert.equal(caught?.status, 500, `${caught?.code}: ${caught?.message}`)
      assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
      assert.include(String(caught?.message), 'CONDICIONAL')
      assert.include(String(caught?.message), 'removeDeny')
      // El reconcile desde un ORIGEN database con el MISMO deny permanente: residuo con motivo propio, nunca 503.
      const origin = new DatabaseRelationsDriver(contractDenyRelationsConfig())
      await origin.relate(user, 'viewer', d, p)
      await origin.deny(user, 'viewer', d, p)
      for (const pass of [1, 2]) {
        const report = await reconcileRelations({ from: origin, to: driver, partition: p })
        const residue = (report.details ?? []).filter((x) => x.reason === 'deny-conditional')
        assert.lengthOf(residue, 1, `pasada ${pass}: ${JSON.stringify(report.details)}`)
        assert.equal(residue[0].side, 'destino')
        assert.equal(report.denies?.updated, 0, `pasada ${pass}: openfga NO lo rehace (la letra «lo rehace permanente» era falsa aquí)`)
        assert.equal(report.denies?.extra, 1)
      }
      // La receta: removeDeny + deny (la ventana entre los dos está DECLARADA) ⇒ permanente; la pasada queda limpia.
      await driver.removeDeny(user, 'viewer', d, p)
      await driver.deny(user, 'viewer', d, p)
      const key = (await client.read({ user: allow.user, relation: 'denied_viewer', object: allow.object })).tuples[0]?.key
      assert.notOk(key?.condition, 'permanente: sin condición')
      const clean = await reconcileRelations({ from: origin, to: driver, partition: p })
      assert.deepEqual(clean.details, [])
      assert.equal(clean.denies?.unchanged, 1)
    })

    test('🟡 C3-2 (cierre 4 de D2) → cierre 5 (opción A) · un deny CONDICIONAL VENCIDO en el destino que el origen tiene: el PLAN lo decide (deny-conditional) y la PARTICIÓN se niega (cero escrituras: tampoco el allow que corta) — --dry-run y real con los MISMOS números, el destino sigue negando (antes del cierre 4: dry «written 2» y real escribía el allow ⇒ concedía)', async ({ assert }) => {
      const { storeId, modelId } = await denyStore()
      const driver = driverOver(contractDenyRelationsConfig(), storeId, modelId)
      const user = u()
      const d = doc()
      const p = part()
      // El deny CONDICIONAL ya VENCIDO, escrito con el SDK y la clave del driver.
      await driver.deny(user, 'viewer', d, p)
      const client = (driver as any).client
      const key = (await client.read({})).tuples.find((t: any) => t.key.relation === 'denied_viewer').key
      await client.write({ deletes: [{ user: key.user, relation: key.relation, object: key.object }] })
      await client.write({
        writes: [{ user: key.user, relation: key.relation, object: key.object, condition: { name: 'not_expired', context: { valid_until: new Date(Date.now() - 60_000).toISOString() } } }],
      })
      const origin = new DatabaseRelationsDriver(contractDenyRelationsConfig())
      await origin.relate(user, 'viewer', d, p)
      await origin.deny(user, 'viewer', d, p)
      const runs = [
        await reconcileRelations({ from: origin, to: driver, partition: p, dryRun: true }),
        await reconcileRelations({ from: origin, to: driver, partition: p }),
      ]
      for (const report of runs) {
        assert.deepEqual(
          { written: report.written, reasons: (report.details ?? []).map((x) => `${x.side}:${x.reason}`), refused: (report.partitionsRefused ?? []).length },
          { written: 0, reasons: ['destino:deny-conditional'], refused: 1 },
          `dryRun=${report.dryRun}`
        )
        assert.include(report.details![0].message, 'YA VENCIDO')
      }
      assert.isFalse(await origin.check(user, 'viewer', d, p))
      assert.isFalse(await driver.check(user, 'viewer', d, p), 'ROJO (C3-2): el destino concede lo que el origen niega')
    })

    test('🟡 D5-1 (cierre 6 de D2) · un deny del DESTINO ya VENCIDO sobre group#member (escrito a mano con condición) que el origen no tiene NO es portador: el plan lo trata como ausente Y el driver también ⇒ la renovación de la membresía entra, --dry-run y real con los MISMOS números, sin 409, y la partición siguiente MIGRA (antes: dry «done», real 409 E_AUTHZ_RENEWAL_UNSAFE «deny vivo» y P2 sin migrar)', async ({ assert }) => {
      const config = contractDenyRelationsConfig()
      const { storeId, modelId } = await denyStore(config)
      const driver = driverOver(config, storeId, modelId)
      const origin = new DatabaseRelationsDriver(config)
      const hour = 3_600_000
      const user = u()
      const x = doc()
      const g = { type: 'group', id: uuidv7() }
      const p = part()
      const other = u()
      const w = doc()
      const p2 = part()
      // El deny VENCIDO del destino, escrito con el SDK y la clave del driver.
      await driver.deny({ object: g, relation: 'member' }, 'viewer', x, p)
      const client = (driver as any).client
      const key = (await client.read({})).tuples.find((t: any) => t.key.relation === 'denied_viewer').key
      await client.write({ deletes: [{ user: key.user, relation: key.relation, object: key.object }] })
      await client.write({
        writes: [{ user: key.user, relation: key.relation, object: key.object, condition: { name: 'not_expired', context: { valid_until: new Date(Date.now() - hour).toISOString() } } }],
      })
      await origin.relate(user, 'member', g, p, { expiresAt: new Date(Date.now() + 24 * hour) })
      await driver.relate(user, 'member', g, p, { expiresAt: new Date(Date.now() + hour) })
      await origin.relate(other, 'viewer', w, p2)
      const opts = { from: origin, to: driver, partitions: [p, p2], toConfig: config }
      const shape = (r: any) => ({
        written: r.written,
        updated: r.updated,
        status: (r.partitions ?? []).map((x: any) => x.status),
        refused: (r.partitionsRefused ?? []).length,
      })
      const dry = shape(await reconcileRelations({ ...opts, dryRun: true }))
      const caught: any[] = []
      const real = await reconcileRelations(opts).then(shape, (e: any) => {
        caught.push(e)
        return null
      })
      assert.deepEqual(dry, { written: 1, updated: 1, status: ['done', 'done'], refused: 0 })
      assert.isEmpty(caught, `ROJO (D5-1): la pasada REAL revienta donde el dry-run dice «done» (${caught[0]?.code}: ${String(caught[0]?.message).slice(0, 160)})`)
      assert.deepEqual(real, dry, 'dry == real')
      assert.isTrue(await driver.check(other, 'viewer', w, p2), 'la partición SIGUIENTE migra')
      assert.isTrue(
        await (driver.withClock(() => new Date(Date.now() + 2 * hour)) as OpenFgaRelationsDriver).check(user, 'member', g, p),
        'la renovación entró: a +2 h U sigue en g (la del origen dura 1 día)'
      )
    })

    test('🟠 N1 (cierre 2 de D2) · renovar (otra caducidad) una membresía que TRANSPORTA un deny —directa, y ANIDADA por un grupo que la contiene— ⇒ 409 E_AUTHZ_RENEWAL_UNSAFE con la receta y CERO Write (espía sobre el cliente REAL); un check concurrente nunca concede porque ya no hay dos Write; la membresía SIN deny se renueva con dos', async ({ assert }) => {
      const { storeId, modelId } = await denyStore()
      const driver = driverOver(contractDenyRelationsConfig(), storeId, modelId)
      // Dos sujetos SIN redundancia (cada uno llega al deny de g por UN solo camino), para que el hueco sea observable:
      // `user` ∈ g DIRECTO; `nested` ∈ h, y h ⊂ g. Con un camino de más el hueco quedaría tapado por el otro.
      const user = u()
      const nested = u()
      const d = doc()
      const p = part()
      const g = { type: 'group', id: uuidv7() }
      const h = { type: 'group', id: uuidv7() }
      const k = { type: 'group', id: uuidv7() }
      const hour = new Date(Date.now() + 3_600_000)
      await driver.relate(user, 'viewer', d, p)
      await driver.relate(nested, 'viewer', d, p)
      await driver.relate(user, 'member', g, p, { expiresAt: hour })
      await driver.relate({ object: h, relation: 'member' }, 'member', g, p)
      await driver.relate(nested, 'member', h, p, { expiresAt: hour })
      await driver.relate(user, 'member', k, p, { expiresAt: hour })
      await driver.deny({ object: g, relation: 'member' }, 'viewer', d, p)
      assert.isFalse(await driver.check(user, 'viewer', d, p), 'antes: el deny de g alcanza a U (directo)')
      assert.isFalse(await driver.check(nested, 'viewer', d, p), 'antes: el deny de g alcanza a N (por h)')
      // ESPÍA-BARRERA (brief del cierre 2): tras cada `Write` que SOLO borra, y antes de devolver el control al driver
      // —es decir, justo ENTRE el delete y el write de una renovación—, un `check` del sujeto. Hasta el cierre daba `true`
      // (medido por el auditor: `gapEntreLosDosWrite: true`); ahora la portadora no llega a borrar, así que la barrera no
      // salta nunca. El control (la membresía SIN deny, abajo) demuestra que la barrera está viva.
      const barrier: boolean[] = []
      let probe = user
      const inner = (driver as any).client
      ;(driver as any).client = new Proxy(inner, {
        get(target, prop, receiver) {
          const value = Reflect.get(target, prop, receiver)
          if (prop !== 'write' || typeof value !== 'function') return value
          return async (req: any, opts: any) => {
            const out = await value.call(target, req, opts)
            if ((req?.deletes?.length ?? 0) > 0 && (req?.writes?.length ?? 0) === 0) barrier.push(await driver.check(probe, 'viewer', d, p))
            return out
          }
        },
      })
      const spy = spyFgaClient(driver)
      for (const [subject, group] of [[user, g], [nested, h]] as const) {
        spy.reset()
        probe = subject
        const [renewal, during] = await Promise.all([
          driver.relate(subject, 'member', group, p, { expiresAt: null }).then(() => null, (e) => e),
          driver.check(subject, 'viewer', d, p),
        ])
        assert.notInclude(barrier, true, 'ROJO (N1): un check ENTRE los dos Write concedió a un denegado')
        assert.deepEqual(barrier, [], 'la barrera ENTRE los dos Write no salta: ya no hay dos Write')
        assert.equal(renewal?.status, 409, `${group === g ? 'directa' : 'ANIDADA'}: ${renewal?.message}`)
        assert.equal(renewal?.code, 'E_AUTHZ_RENEWAL_UNSAFE')
        assert.include(String(renewal?.message), 'unrelate + relate')
        assert.include(String(renewal?.message), 'denied_viewer')
        // Cierre 5 de D2 (opción A): la receta es HONESTA — no hay forma sin ventana (#2151); jamás «retira antes el deny».
        assert.include(String(renewal?.message), 'openfga/openfga#2151')
        assert.include(String(renewal?.message), 'ACEPTANDO la ventana')
        assert.notInclude(String(renewal?.message), 'retira antes el deny')
        assert.deepEqual(spy.calls.filter((c) => c === 'write' || c === 'writeTuples' || c === 'deleteTuples'), [], 'CERO Write')
        // Los filtros de las lecturas de la comprobación: `user` + tipo (lo que FGA admite) o la clave exacta, jamás
        // `object` por prefijo a secas (200 con cero tuplas en silencio).
        for (const { method, args } of spy.invocations) {
          if (method !== 'read') continue
          const filter = args[0] as any
          assert.isTrue(filter.user !== undefined, `read con filtro admitido: ${JSON.stringify(filter)}`)
        }
        assert.isFalse(during, 'el check concurrente no concede')
        assert.isFalse(await driver.check(subject, 'viewer', d, p), 'después: sigue negando')
        const kept = (await driver.enumerateRelations(p)).tuples.find((t: any) => t.object.id === group.id && t.subject.uuid === subject.uuid)
        assert.equal(kept?.expiresAt?.getTime(), hour.getTime(), 'la caducidad no cambió')
      }
      spy.reset()
      probe = user
      await driver.relate(user, 'member', k, p, { expiresAt: null })
      assert.lengthOf(spy.calls.filter((c) => c === 'write'), 2, 'la membresía SIN deny se renueva: delete + write')
      assert.deepEqual(barrier, [false], 'control: con dos Write la barrera SÍ salta (y aquí no concede: U sigue en g, que deniega)')
      const renewed = (await driver.enumerateRelations(p)).tuples.find((t: any) => t.object.id === k.id)
      assert.isNull(renewed?.expiresAt ?? null)
    })

    test('🟠 N1 (b) (cierre 2 de D2) · una renovación PERMITIDA cuyo 2.º Write falla ⇒ error marcado PARCIAL (isPartialWrite) y onRelationWrite con indeterminate: true — la tupla quedó BORRADA (hasta el cierre: 503 «sin escribir», sin evento)', async ({ assert }) => {
      const { storeId, modelId } = await denyStore()
      const config = contractDenyRelationsConfig()
      const driver = driverOver(config, storeId, modelId)
      const events: any[] = []
      const manager = new RelationsManager(driver, config, { onRelationWrite: (e) => void events.push(e) })
      const user = u()
      const k = { type: 'group', id: uuidv7() }
      const p = part()
      await manager.relate(user, 'member', k, p, { expiresAt: new Date(Date.now() + 3_600_000) })
      events.length = 0
      const client = (driver as any).client
      const original = client.write.bind(client)
      let writes = 0
      client.write = async (req: any, opts: any) => {
        writes++
        if (writes === 2) throw Object.assign(new Error('503 inyectado en el 2.º Write'), { statusCode: 503 })
        return original(req, opts)
      }
      const caught = await manager.relate(user, 'member', k, p, { expiresAt: null }).then(() => null, (e) => e)
      client.write = original
      assert.equal(caught?.status, 503, String(caught?.message))
      assert.isTrue(isPartialWrite(caught), 'marcado como escritura PARCIAL: el delete ya entró')
      assert.lengthOf(events, 1)
      assert.isTrue(events[0].indeterminate, 'evento indeterminate: true')
      assert.equal(events[0].operation, 'relate')
      assert.isUndefined((await driver.enumerateRelations(p)).tuples.find((t: any) => t.object.id === k.id), 'la membresía quedó borrada (lo que el evento avisa)')
    })

    test('🟡 C2-3 (cierre 3 de D2) · TOCTOU: un deny que entra en el grupo ENTRE la comprobación de portadora y los dos Write de una renovación (espía-barrera) ⇒ la renovación se aplica pero el error lo NOMBRA (409 E_AUTHZ_RENEWAL_RACED —cierre 4: código propio—, carriedDeny, marcado parcial, evento indeterminate); si además cae el 2.º Write, el 503 parcial nombra el deny y la receta (relate de nuevo) lo repara', async ({ assert }) => {
      const config = contractDenyRelationsConfig()
      for (const failSecond of [false, true]) {
        const { storeId, modelId } = await denyStore()
        const driver = driverOver(config, storeId, modelId)
        const admin = driverOver(config, storeId, modelId) // otra petición / otro proceso sobre el MISMO store
        const events: any[] = []
        const manager = new RelationsManager(driver, config, { onRelationWrite: (e) => void events.push(e) })
        const user = u()
        const d = doc()
        const p = part()
        const g = { type: 'group', id: uuidv7() }
        await driver.relate(user, 'viewer', d, p)
        await driver.relate(user, 'member', g, p, { expiresAt: new Date(Date.now() + 3_600_000) })
        assert.isTrue(await driver.check(user, 'viewer', d, p), 'antes: g no transporta ningún deny')
        events.length = 0
        const inner = (driver as any).client
        let writes = 0
        ;(driver as any).client = new Proxy(inner, {
          get(target, prop, receiver) {
            const value = Reflect.get(target, prop, receiver)
            if (prop !== 'write' || typeof value !== 'function') return value
            return async (req: any, opts: any) => {
              writes++
              // ESPÍA-BARRERA: tras `#carriedDeny` («sin deny») y ANTES del delete, el admin deniega a g y su deny QUEDA
              // CONFIRMADO (un check posterior niega).
              if (writes === 1) {
                await admin.deny({ object: g, relation: 'member' }, 'viewer', d, p)
                assert.isFalse(await admin.check(user, 'viewer', d, p), 'el deny está confirmado')
              }
              if (writes === 2 && failSecond) throw Object.assign(new Error('503 inyectado en el 2.º Write'), { statusCode: 503 })
              return value.call(target, req, opts)
            }
          },
        })
        const caught = await manager.relate(user, 'member', g, p, { expiresAt: null }).then(() => null, (e) => e)
        ;(driver as any).client = inner
        assert.isNotNull(caught, `ROJO (C2-3, failSecond=${failSecond}): la renovación con un deny concurrente es MUDA`)
        assert.isTrue(isPartialWrite(caught), 'marcado parcial: el delete ya entró')
        assert.match(String(caught?.carriedDeny), /denied_viewer/, `nombra el deny afectado: ${caught?.message}`)
        assert.lengthOf(events, 1)
        assert.isTrue(events[0].indeterminate, 'evento indeterminate: true')
        if (!failSecond) {
          assert.equal(caught?.status, 409, String(caught?.message))
          // Cierre 4 de D2 · ⚪ C3-3: código PROPIO — la receta de E_AUTHZ_RENEWAL_UNSAFE (unrelate + relate) reabriría la ventana.
          assert.equal(caught?.code, 'E_AUTHZ_RENEWAL_RACED')
          assert.instanceOf(caught, RenewalRacedError)
          assert.include(String(caught?.message), 'NO hay nada que reescribir')
          assert.isTrue(caught?.renewalApplied)
          assert.include(String(caught?.message), 'SE APLICÓ')
          assert.isFalse(await admin.check(user, 'viewer', d, p), 'estado final correcto: el deny alcanza al sujeto')
        } else {
          assert.equal(caught?.status, 503, String(caught?.message))
          assert.include(String(caught?.message), 'quedó BORRADA')
          assert.include(String(caught?.message), 'vuelve a escribirla')
          assert.isTrue(await admin.check(user, 'viewer', d, p), 'el caso PERSISTENTE: sin la membresía, el deny no alcanza al sujeto')
          await driver.relate(user, 'member', g, p, { expiresAt: null })
          assert.isFalse(await admin.check(user, 'viewer', d, p), 'la receta (relate: UN Write) lo repara')
        }
      }
    })

    test('🟠 N1 (cierre 2 de D2) · reconcile database → openfga que necesita RENOVAR una membresía portadora: el PLAN la clasifica renewal-unsafe (misma cifra en --dry-run y real), no la escribe, el destino sigue negando y la línea dice «sin renovar (renewal-unsafe) destino:»', async ({ assert }) => {
      const { storeId, modelId } = await denyStore()
      const config = contractDenyRelationsConfig()
      const destination = driverOver(config, storeId, modelId)
      const origin = new DatabaseRelationsDriver(config)
      const user = u()
      const d = doc()
      const p = part()
      const g = { type: 'group', id: uuidv7() }
      const hour = new Date(Date.now() + 3_600_000)
      for (const side of [origin, destination]) {
        await side.relate(user, 'viewer', d, p)
        await side.deny!({ object: g, relation: 'member' }, 'viewer', d, p)
      }
      await origin.relate(user, 'member', g, p)
      await destination.relate(user, 'member', g, p, { expiresAt: hour })
      const spy = spyFgaClient(destination)
      for (const dryRun of [true, false]) {
        const report = await reconcileRelations({ from: origin, to: destination, partition: p, dryRun, toConfig: config })
        assert.equal(report.updated, 0, `dryRun=${dryRun}: la portadora NO cuenta como actualizada`)
        assert.deepEqual((report.details ?? []).map((x) => `${x.side}:${x.reason}`), ['destino:renewal-unsafe'])
        const { lines, clean } = relationsReconcileLines(report)
        assert.isFalse(clean)
        assert.isTrue(lines.some((l) => l.level === 'error' && l.message.startsWith('sin renovar (renewal-unsafe) destino:') && l.message.includes('unrelate + relate')))
      }
      assert.deepEqual(spy.calls.filter((c) => c === 'write'), [], 'CERO Write en el destino')
      assert.isFalse(await destination.check(user, 'viewer', d, p))
      const kept = (await destination.enumerateRelations(p)).tuples.find((t: any) => t.object.id === g.id)
      assert.equal(kept?.expiresAt?.getTime(), hour.getTime())
    })

    test('S15 · un `error` en UN ítem del batchCheck de decideMany ⇒ la clase de R3 (transitorio 503, validation_error 500) para TODO el lote (nunca `none` por ítem: dejaría subir la cadena del llamante)', async ({ assert }) => {
      const { storeId, modelId } = await denyStore()
      const driver = driverOver(contractDenyRelationsConfig(), storeId, modelId)
      const user = u()
      const a = doc()
      const b = doc()
      const p = part()
      await driver.relate(user, 'viewer', a, p)
      const client = (driver as any).client
      const original = client.batchCheck.bind(client)
      client.batchCheck = async (req: any, opts: any) => {
        const response = await original(req, opts)
        const victim = req.checks.find((c: any) => c.relation.startsWith('denied_'))
        return {
          ...response,
          result: response.result.map((r: any) =>
            r.correlationId === victim.correlationId ? { ...r, allowed: false, error: itemError } : r
          ),
        }
      }
      // R3: el ítem pasa por el clasificador — transitorio (`internal_error`) ⇒ 503; `validation_error` ⇒ 500 E_AUTHZ_CONFIG
      // (hasta R3, 503). Las dos, para TODO el lote: nunca `none` por ítem.
      let itemError: object = { internal_error: 'deadline_exceeded', message: 'inyectado' }
      const caught = await driver.decideMany(user, 'viewer', [a, b], p).then((answer) => ({ answer }), (e) => e)
      assert.equal(caught?.status, 503, `respondió ${JSON.stringify(caught?.answer)}`)
      assert.equal(caught?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
      itemError = { input_error: 'validation_error', message: 'inyectado' }
      const config = await driver.decideMany(user, 'viewer', [a, b], p).then((answer) => ({ answer }), (e) => e)
      assert.equal(config?.status, 500, `respondió ${JSON.stringify(config?.answer)}`)
      assert.equal(config?.code, 'E_AUTHZ_CONFIG')
    })

    test('D-24 · un check con deny + includes + userset anidado sigue siendo UN Check (el corte lo evalúa el servidor; nada se resta en el cliente)', async ({ assert }) => {
      const { storeId, modelId } = await denyStore()
      const driver = driverOver(contractDenyRelationsConfig(), storeId, modelId)
      const user = u()
      const g1 = { type: 'group', id: uuidv7() }
      const g2 = { type: 'group', id: uuidv7() }
      const d = doc()
      const p = part()
      await driver.relate(user, 'member', g1, p)
      await driver.relate({ object: g1, relation: 'member' }, 'member', g2, p)
      await driver.relate({ object: g2, relation: 'member' }, 'owner', d, p)
      await driver.deny({ object: g1, relation: 'member' }, 'editor', d, p)
      await driver.check(user, 'viewer', d, p) // calienta el memo del modelo (D-31)
      const spy = spyFgaClient(driver)
      assert.isFalse(await driver.check(user, 'viewer', d, p), 'fila 35 por grupos anidados')
      assert.deepEqual(spy.calls, ['check'], 'UN Check y nada más')
    })

    test('D-26 / S3 · purgeObject borra en ORDEN GLOBAL (allows antes que denies) y, cortada tras el 1.er deleteTuples, ningún sujeto denegado concede (quedan denies de MÁS); el error lleva la marca de escritura parcial', async ({ assert }) => {
      const { storeId, modelId } = await denyStore()
      const driver = driverOver(contractDenyRelationsConfig(), storeId, modelId)
      const victim = u()
      const d = doc()
      const p = part()
      // El deny se escribe PRIMERO y el allow de la víctima el ÚLTIMO: en el orden del Read, el deny caería en el
      // primer lote de 100 y su allow en el segundo — que es lo que un borrado en orden de Read dejaría vivo.
      await driver.deny(victim, 'viewer', d, p)
      for (let i = 0; i < 100; i++) await driver.relate(u(), 'viewer', d, p)
      await driver.relate(victim, 'viewer', d, p)
      assert.isFalse(await driver.check(victim, 'viewer', d, p))
      const client = (driver as any).client
      const original = client.deleteTuples.bind(client)
      const batches: string[][] = []
      client.deleteTuples = async (keys: any[], opts: any) => {
        batches.push(keys.map((k) => k.relation))
        if (batches.length === 2) {
          const e: any = new Error('backend caído tras el primer lote')
          e.code = 'ECONNRESET'
          throw e
        }
        return original(keys, opts)
      }
      const caught = await driver.purgeObject(d, p).then(() => null, (e) => e)
      assert.equal(caught?.status, 503)
      assert.isTrue(isPartialWrite(caught), 'borró ≥ 1 lote: escritura PARCIAL (invariante 13)')
      assert.isFalse(batches[0].some((r) => r.startsWith('denied_')), 'el primer lote son solo allows')
      client.deleteTuples = original
      assert.isFalse(await driver.check(victim, 'viewer', d, p), 'ROJO (S3): la purga cortada dejó un allow VIVO sin su deny (fail-open)')
      assert.lengthOf((await driver.listDenies('viewer', d, p)).subjects, 1, 'el deny sigue ahí: denies de MÁS, nunca de menos')
    }).timeout(60_000)

    /**
     * **Cierre 1 de D1 · 🟡 3 del auditor**, SUSTITUIDO por L11: `decideMany` sin pin decidía con un memo rancio del modelo.
     * Desde L11 no hay driver sin pin (500 al construir, C14), así que el caso pasa a fijar que, con el pin, memo y `Check`
     * son del MISMO modelo y un modelo REPUBLICADO por otro pod no cambia lo que este pod evalúa.
     */
    test('🟡 3 (L11) · sin modelId no hay driver de relaciones; con el pin, decideMany y check usan el MISMO modelo aunque otro pod republique', async ({ assert }) => {
      const old = await denyStore(contractRelationsConfig())
      assert.throws(() => driverOver(contractRelationsConfig(), old.storeId, undefined as any), /modelId/)
      const user = u()
      const d = doc()
      const p = part()
      const { OpenFgaClient } = await import('@openfga/sdk')
      const fresh = await new OpenFgaClient({ apiUrl, storeId: old.storeId }).writeAuthorizationModel(
        openFgaFactsModel(HOLDER_MAP, [], { objectTypes: contractDenyRelationsConfig().objectTypes })
      )
      const writer = driverOver(contractDenyRelationsConfig(), old.storeId, fresh.authorization_model_id!)
      await writer.relate(user, 'viewer', d, p)
      await writer.deny(user, 'viewer', d, p)
      const pinnedOld = driverOver(contractRelationsConfig(), old.storeId, old.modelId)
      assert.isTrue(await pinnedOld.check(user, 'viewer', d, p), 'el pod fijado al modelo SIN deny evalúa con ESE modelo (fila S11)')
      assert.deepEqual(await pinnedOld.decideMany(user, 'viewer', [d], p), ['allow'], 'decideMany responde con el MISMO modelo que check')
      const pinned = driverOver(contractRelationsConfig(), old.storeId, fresh.authorization_model_id!)
      // D8 por TIPO ENTERO: la config sin opt-in y el modelo con la forma con deny (completa) es legítimo; los dos responden.
      assert.isFalse(await pinned.check(user, 'viewer', d, p), 'el pod fijado al modelo CON deny: el servidor resta')
      assert.deepEqual(await pinned.decideMany(user, 'viewer', [d], p), ['deny'])
    })

    test('D8 · retirar el opt-in con denies vivos (pod con la config SIN deny y el modelo que aún declara denied_*): check sigue false, listDenies los ve y removeDeny los borra (reversible); deny() ⇒ 422', async ({ assert }) => {
      const { storeId, modelId } = await denyStore()
      const before = driverOver(contractDenyRelationsConfig(), storeId, modelId)
      const user = u()
      const d = doc()
      const p = part()
      await before.relate(user, 'viewer', d, p)
      await before.deny(user, 'viewer', d, p)
      const retired = new RelationsManager(driverOver(contractRelationsConfig(), storeId, modelId), contractRelationsConfig())
      assert.isFalse(await retired.check(user, 'viewer', d, p), 'el servidor sigue restando con ESE modelo')
      assert.lengthOf((await retired.listDenies('viewer', d, p)).subjects, 1)
      assert.deepEqual(await retired.decideMany(user, 'viewer', [d], p), ['deny'], 'decideMany pregunta el deny si el MODELO lo declara (D8)')
      const denied = await retired.deny(user, 'viewer', doc(), p).then(() => null, (e) => e)
      assert.equal(denied?.code, 'E_AUTHZ_RELATION_NOT_DENYABLE')
      await retired.removeDeny(user, 'viewer', d, p)
      assert.isTrue(await retired.check(user, 'viewer', d, p), 'removeDeny sobre un tipo que ya no declara deny: reversible')
    })
  })

  /* ── Lote D · cierre 1 del sublote D1 · 🟠 1: la purga de openfga cortada a medias, con el deny TRANSPORTADO ── */

  /**
   * **🟠 1 del auditor de D1** (`loteD1-auditor.md`, repro `aud_d1_purge.spec.ts` contra `:8090`): `purgeSubject` clasificaba
   * por PREFIJO (`denied_*` al final) y no veía que una MEMBRESÍA (`group:g#member@U`, o la arista anidada
   * `group:h#member@group:g#member`) también TRANSPORTA denies; con 100 grants más, la membresía caía en el lote 1 y el
   * allow directo de la víctima en el 2: cortada tras el lote 1, el sujeto CONCEDÍA (S3 roto). Decisión del coordinador:
   * (a) UN `Write` si la purga cabe en el máximo del servidor (100, MEDIDO en v1.19.0: 101 ⇒ 400 y nada aplicado — el
   * `Write` es transaccional); (b) si no cabe, orden allows (no-`group`) → membresías `group:*#member` en un `Write`
   * PROPIO → `denied_*`; con más de `RELATIONS_PURGE_WRITE_MAX` membresías, residuo DECLARADO (fila con caso abajo).
   * El corte lo hace un espía: el `deleteTuples` número k+1 lanza `ECONNRESET` (k lotes ya aplicados).
   */
  test.group('lote D · cierre 1 de D1 · 🟠 1 · purga de openfga cortada con el deny TRANSPORTADO (tabla de verdad {directo, por grupo, anidado} × {cabe, no cabe} × {corte tras el lote k})', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      while (stores.length) await deleteStore(stores.pop()!)
    })
    let shared: { storeId: string; modelId: string } | undefined
    async function store() {
      if (!shared) {
        shared = await provisionFusedStore(contractDenyRelationsConfig())
        stores.push(shared.storeId)
      }
      return shared
    }
    async function freshDriver() {
      const { storeId, modelId } = await store()
      return new OpenFgaRelationsDriver(contractDenyRelationsConfig(), { apiUrl, storeId, modelId, holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
    }
    const u = () => ({ type: 'user', uuid: uuidv7() })
    const doc = () => ({ type: 'document', id: uuidv7() })
    const grp = () => ({ type: 'group', id: uuidv7() })
    /** En paralelo por tandas: el relleno no tiene que ser lento. */
    async function inBatches(n: number, write: (i: number) => Promise<unknown>) {
      for (let i = 0; i < n; i += 25) await Promise.all(Array.from({ length: Math.min(25, n - i) }, (_, j) => write(i + j)))
    }

    type Transport = 'directo' | 'por grupo' | 'anidado' | 'allow por grupo × deny directo' | 'allow por grupo × deny directo (userset)'
    /**
     * Un escenario de la tabla: la víctima NO concede antes (el deny la corta) y NO concede después (la purga se lleva
     * su allow). Lo que se purga es el sujeto; `filler` grants más del MISMO sujeto hacen que la purga NO quepa en un
     * `Write` (100 + lo del escenario > 100).
     *  - directo (holder U): `doc:V#viewer@U` + `doc:V#denied_viewer@U`;
     *  - por grupo (holder U): `doc:V#viewer@U` + `group:g#member@U`, con `doc:V#denied_viewer@group:g#member`;
     *  - anidado (userset g#member): `doc:V#viewer@g#member` + `group:h#member@g#member`, con el deny en `h#member`;
     *    la víctima es un miembro W de g.
     *  - allow por grupo × deny directo (holder U; cierre 2 de D1, 🟡 N1 — la fila SIMÉTRICA): `group:gA#member@U` +
     *    `doc:V#denied_viewer@U`, con el allow en `doc:V#viewer@group:gA#member`; la membresía transporta el ALLOW y el
     *    deny es DIRECTO, así que la membresía tiene que irse ANTES que el deny;
     *  - su gemela userset (g#member): `group:h#member@group:g#member` + `doc:V#denied_viewer@group:g#member`, con el
     *    allow en `doc:V#viewer@group:h#member`; la víctima es un miembro W de g.
     */
    async function scenario(transport: Transport, filler: number) {
      const driver = await freshDriver()
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const V = doc()
      if (transport === 'directo') {
        const U = u()
        await driver.relate(U, 'viewer', V, p)
        await driver.deny(U, 'viewer', V, p)
        await inBatches(filler, () => driver.relate(U, 'viewer', doc(), p))
        return { driver, purge: () => driver.purgeSubject(U, p), victim: () => driver.check(U, 'viewer', V, p) }
      }
      if (transport === 'por grupo') {
        const U = u()
        const g = grp()
        await driver.relate(U, 'member', g, p)
        await driver.deny({ object: g, relation: 'member' }, 'viewer', V, p)
        await inBatches(filler, () => driver.relate(U, 'viewer', doc(), p))
        // El allow de la víctima se escribe el ÚLTIMO (como en el repro): en el orden del Read cae al final.
        await driver.relate(U, 'viewer', V, p)
        return { driver, purge: () => driver.purgeSubject(U, p), victim: () => driver.check(U, 'viewer', V, p) }
      }
      if (transport === 'allow por grupo × deny directo') {
        const U = u()
        const gA = grp()
        await driver.relate(U, 'member', gA, p)
        await driver.relate({ object: gA, relation: 'member' }, 'viewer', V, p)
        await driver.deny(U, 'viewer', V, p)
        await inBatches(filler, () => driver.relate(U, 'viewer', doc(), p))
        return { driver, purge: () => driver.purgeSubject(U, p), victim: () => driver.check(U, 'viewer', V, p) }
      }
      if (transport === 'allow por grupo × deny directo (userset)') {
        const W = u()
        const g = grp()
        const h = grp()
        const gm = { object: g, relation: 'member' }
        await driver.relate(W, 'member', g, p)
        await driver.relate(gm, 'member', h, p)
        await driver.relate({ object: h, relation: 'member' }, 'viewer', V, p)
        await driver.deny(gm, 'viewer', V, p)
        await inBatches(filler, () => driver.relate(gm, 'viewer', doc(), p))
        return { driver, purge: () => driver.purgeSubject(gm, p), victim: () => driver.check(W, 'viewer', V, p) }
      }
      const W = u()
      const g = grp()
      const h = grp()
      const gm = { object: g, relation: 'member' }
      await driver.relate(W, 'member', g, p)
      await driver.relate(gm, 'member', h, p)
      await driver.deny({ object: h, relation: 'member' }, 'viewer', V, p)
      await inBatches(filler, () => driver.relate(gm, 'viewer', doc(), p))
      await driver.relate(gm, 'viewer', V, p)
      return { driver, purge: () => driver.purgeSubject(gm, p), victim: () => driver.check(W, 'viewer', V, p) }
    }

    /** Corta la purga tras `k` `deleteTuples` aplicados (el k+1 lanza `ECONNRESET`); devuelve el error y los lotes. */
    async function cutAfter(driver: OpenFgaRelationsDriver, k: number, purge: () => Promise<void>) {
      const client = (driver as any).client
      const original = client.deleteTuples.bind(client)
      const batches: string[][] = []
      client.deleteTuples = async (keys: any[], opts: any) => {
        batches.push(keys.map((key: any) => `${key.object}#${key.relation}@${key.user}`))
        if (batches.length === k + 1) {
          const e: any = new Error(`backend caído tras ${k} lote(s)`)
          e.code = 'ECONNRESET'
          throw e
        }
        return original(keys, opts)
      }
      try {
        return { caught: await purge().then(() => null, (e) => e), batches }
      } finally {
        client.deleteTuples = original
      }
    }

    /**
     * Una fila de la tabla: el escenario sin corte cuenta sus `Write` (`writes`) y los recorre todos; luego, para cada
     * k en 0..writes−1, un escenario NUEVO cortado tras k lotes. Ningún corte concede (inicial F, final F).
     */
    async function row(assert: any, transport: Transport, fits: boolean) {
      const filler = fits ? 0 : 100
      const label = `${transport} × ${fits ? 'cabe en un Write' : 'no cabe'}`
      const full = await scenario(transport, filler)
      assert.isFalse(await full.victim(), `${label}: antes de la purga el deny corta`)
      const whole = await cutAfter(full.driver, Number.POSITIVE_INFINITY, full.purge)
      assert.isNull(whole.caught, `${label}: la purga sin corte termina (${whole.caught?.message})`)
      assert.isFalse(await full.victim(), `${label}: después de la purga no concede`)
      if (fits) assert.lengthOf(whole.batches, 1, `${label}: la purga cabe en el máximo del servidor ⇒ UN solo Write (transaccional: no hay estado intermedio)`)
      else assert.isAbove(whole.batches.length, 1, `${label}: no cabe ⇒ varios Write`)
      for (let k = 0; k < whole.batches.length; k++) {
        const s = await scenario(transport, filler)
        const { caught, batches } = await cutAfter(s.driver, k, s.purge)
        assert.equal(caught?.status, 503, `${label} · corte tras el lote ${k}: ${caught?.message}`)
        assert.equal(isPartialWrite(caught), k > 0, `${label} · corte tras el lote ${k}: marca de escritura parcial ⇔ ya borró algo (invariante 13)`)
        assert.isFalse(
          await s.victim(),
          `ROJO (🟠 1 · S3 · ${label} · corte tras el lote ${k} de ${whole.batches.length}): el estado intermedio CONCEDE lo que no concedían ni el ` +
            `inicial ni el final — lotes aplicados: ${batches.slice(0, k).map((b) => `[${b.filter((x) => x.includes('#member@') || x.includes('#denied_')).join(', ') || `${b.length} allows`}]`).join(' ')}`
        )
      }
      return whole.batches.length
    }

    test('purgeSubject cortada, deny DIRECTO (holder): {cabe, no cabe} × cada corte ⇒ la víctima nunca concede', async ({ assert }) => {
      await row(assert, 'directo', true)
      assert.equal(await row(assert, 'directo', false), 3, '101 allows ⇒ 2 Write, 1 deny ⇒ 1 Write')
    }).timeout(180_000)

    test('purgeSubject cortada, deny por grupo (holder): la membresía que transporta el deny se borra DESPUÉS de todos los allows y en su propio Write ⇒ ningún corte concede', async ({ assert }) => {
      await row(assert, 'por grupo', true)
      assert.equal(await row(assert, 'por grupo', false), 3, '101 allows ⇒ 2 Write, 1 membresía ⇒ su Write')
    }).timeout(180_000)

    test('purgeSubject cortada, deny anidado (userset g#member): la arista group:h#member@group:g#member se borra DESPUÉS de los allows de g#member ⇒ ningún corte concede a un miembro de g', async ({ assert }) => {
      await row(assert, 'anidado', true)
      assert.equal(await row(assert, 'anidado', false), 3, '101 allows ⇒ 2 Write, 1 arista anidada ⇒ su Write')
    }).timeout(180_000)

    /**
     * **La fila SIMÉTRICA** (cierre 2 de D1, 🟡 N1 del auditor): la membresía transporta el ALLOW y el deny es DIRECTO.
     * La propiedad tiene dos mitades —membresías DESPUÉS de los allows (las filas de arriba) y ANTES de los denies (ésta)—.
     * El mutante «denies antes que membresías» (`[100 allows][deny][membresía]`) deja, cortado tras el lote 2, la
     * membresía viva sin el deny que la cortaba: `ANTES false … DESPUÉS true` (medido por el auditor en `:8090`).
     */
    test('purgeSubject cortada, allow por grupo × deny DIRECTO (holder): la membresía que transporta el allow se borra ANTES que el deny directo ⇒ ningún corte concede', async ({ assert }) => {
      await row(assert, 'allow por grupo × deny directo', true)
      assert.equal(await row(assert, 'allow por grupo × deny directo', false), 3, '100 allows ⇒ 1 Write, 1 membresía ⇒ su Write, 1 deny ⇒ el último')
    }).timeout(180_000)

    test('purgeSubject cortada, allow por grupo × deny DIRECTO (userset g#member): la arista group:h#member@group:g#member se borra ANTES que el deny de g#member ⇒ ningún corte concede a un miembro de g', async ({ assert }) => {
      await row(assert, 'allow por grupo × deny directo (userset)', true)
      assert.equal(await row(assert, 'allow por grupo × deny directo (userset)', false), 3, '100 allows ⇒ 1 Write, 1 arista ⇒ su Write, 1 deny ⇒ el último')
    }).timeout(180_000)

    /**
     * Allow Y deny transportados los dos por MEMBRESÍA (g_allow lleva el allow, g_deny el deny): con ≤ 100 membresías
     * van en el MISMO `Write`, aunque los allows de antes no completen su último lote. El mutante «troceado contiguo»
     * (allows y membresías en lotes de 100 seguidos) mete g_deny con el último lote de allows y g_allow en el
     * siguiente: cortada entre los dos, concede.
     */
    test('purgeSubject cortada, allow Y deny por grupo: las membresías del sujeto (≤ 100) van en UN Write propio, nunca repartidas con el último lote de allows', async ({ assert }) => {
      const make = async () => {
        const driver = await freshDriver()
        const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
        const V = doc()
        const U = u()
        // g_deny ordena ANTES que g_allow (el driver ordena las membresías por objeto: el caso no depende del Read).
        const [a, b] = [uuidv7(), uuidv7()].sort()
        const gDeny = { type: 'group', id: a }
        const gAllow = { type: 'group', id: b }
        await driver.relate(U, 'member', gDeny, p)
        await driver.relate(U, 'member', gAllow, p)
        await driver.deny({ object: gDeny, relation: 'member' }, 'viewer', V, p)
        await driver.relate({ object: gAllow, relation: 'member' }, 'viewer', V, p)
        await inBatches(99, () => driver.relate(U, 'viewer', doc(), p))
        return { driver, purge: () => driver.purgeSubject(U, p), victim: () => driver.check(U, 'viewer', V, p) }
      }
      const full = await make()
      assert.isFalse(await full.victim())
      const whole = await cutAfter(full.driver, Number.POSITIVE_INFINITY, full.purge)
      assert.isNull(whole.caught)
      assert.deepEqual(whole.batches.map((b) => b.length), [99, 2], '99 allows en su Write; las 2 membresías en el suyo')
      for (let k = 0; k < whole.batches.length; k++) {
        const s = await make()
        const { caught } = await cutAfter(s.driver, k, s.purge)
        assert.equal(caught?.status, 503)
        assert.isFalse(await s.victim(), `ROJO (🟠 1 · corte tras el lote ${k}): g_deny se fue antes que g_allow y U concede`)
      }
    }).timeout(180_000)

    /**
     * **FILA DECLARADA (residuo del 🟠 1, decisión del coordinador (b))**: con MÁS de `RELATIONS_PURGE_WRITE_MAX` (100)
     * membresías de grupo del sujeto, las membresías no caben en un `Write` y una que transporta un deny puede caer en un
     * lote anterior a otra que transporta un allow: cortada entre los dos, el sujeto concede hasta que la purga se repita
     * (sale marcada como parcial: `indeterminate: true`). La purga NO se niega antes de borrar (invariante 11: una purga
     * no espera; un 500 aquí dejaría al sujeto de baja con TODO su acceso). Frase en el README, con este caso.
     */
    test('FILA DECLARADA · purgeSubject con más de 100 membresías de grupo: una que transporta un deny puede caer en un lote anterior a otra que transporta un allow (cortada entre los dos, concede); la purga no se niega antes de borrar', async ({ assert }) => {
      const make = async () => {
        const driver = await freshDriver()
        const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
        const V = doc()
        const U = u()
        const ids = Array.from({ length: 101 }, () => uuidv7()).sort()
        const gDeny = { type: 'group', id: ids[0] }
        const gAllow = { type: 'group', id: ids[100] }
        await inBatches(101, (i) => driver.relate(U, 'member', { type: 'group', id: ids[i] }, p))
        await driver.deny({ object: gDeny, relation: 'member' }, 'viewer', V, p)
        await driver.relate({ object: gAllow, relation: 'member' }, 'viewer', V, p)
        return { driver, purge: () => driver.purgeSubject(U, p), victim: () => driver.check(U, 'viewer', V, p) }
      }
      const full = await make()
      assert.isFalse(await full.victim())
      const whole = await cutAfter(full.driver, Number.POSITIVE_INFINITY, full.purge)
      assert.isNull(whole.caught, 'sin corte la purga termina: no se niega antes de borrar')
      assert.deepEqual(whole.batches.map((b) => b.length), [100, 1])
      assert.isFalse(await full.victim())
      const cut = await make()
      const { caught } = await cutAfter(cut.driver, 1, cut.purge)
      assert.isTrue(isPartialWrite(caught), 'cortada a medias: indeterminada (invariante 13)')
      assert.isTrue(await cut.victim(), 'FILA DECLARADA: g_deny cayó en el lote 1 y g_allow en el 2 ⇒ concede hasta repetir la purga')
      await cut.purge()
      assert.isFalse(await cut.victim(), 'repetida, la purga termina y deja de conceder')
    }).timeout(180_000)
  })

}

/* ── alpha.3 · C4 · el deadline de `openfga` con SERVIDOR MUDO, sin el `:8101` ── */

/**
 * **alpha.3 · C4 (invariante 13 en el driver `openfga` de relaciones).** FUERA
 * de la guarda `if (openFgaTestUrl)`: corre en los 4 modos sin servidor
 * (precedente exacto y ungated: `openfga_driver.spec.ts:362`, el socket que
 * acepta y calla). Responde «¿hay deadline ahí?» → sí: el deadline es
 * `baseOptions.timeout` del SDK con `retryParams.maxRetry: 0` y la clasificación
 * es `isTimeoutLike` ⇒ `AuthorizationBackendTimeoutError` — no usa el
 * `withDeadline` de `backend_guard`, cosa que este caso hace observable por
 * primera vez para RELACIONES. Un `relate` por el manager ⇒ 503
 * `E_AUTHZ_BACKEND_TIMEOUT` en < 1 s Y un evento `indeterminate: true` SIN
 * `transactional` (en `openfga` la puerta 1 hace imposible `{ transaction }`).
 * **Mutante**: `retryParams: { maxRetry: 1 }` ⇒ el caso pasa del presupuesto.
 */
test.group('alpha.3 · C4 · openfga (relations) contra un servidor MUDO: el deadline publica indeterminate: true (sin :8101)', (group) => {
  let server: import('node:net').Server
  let port: number
  const sockets = new Set<import('node:net').Socket>()

  group.setup(async () => {
    const net = await import('node:net')
    server = net.createServer((socket) => {
      // Acepta y calla. El cliente se queda esperando la respuesta HTTP.
      sockets.add(socket)
      socket.on('error', () => {})
      socket.on('close', () => sockets.delete(socket))
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    port = (server.address() as import('node:net').AddressInfo).port
  })

  group.teardown(async () => {
    for (const socket of sockets) socket.destroy()
    await new Promise<void>((resolve) => server.close(() => resolve()))
  })

  test('relate/unrelate contra un servidor mudo ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT en < 1 s cada uno, y onRelationWrite recibe indeterminate: true sin transactional, ANTES del 503', async ({
    assert,
  }) => {
    const config = contractRelationsConfig()
    const driver = new OpenFgaRelationsDriver(config, {
      apiUrl: `http://127.0.0.1:${port}`,
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      modelId: TEST_MODEL_ID,
      holderTypes: HOLDER_MAP,
      timeoutMs: 200,
      // Cierre 3 · ⚪ N10: la señal del deadline tiene que poder saltar antes de que el cliente corte (D ≤ timeoutMs).
      listObjectsDeadlineMs: 200,
      logger: { warn: () => {} },
    })
    assert.strictEqual(driver.capabilities.transactionalWrites, false)
    const events: any[] = []
    const sequence: string[] = []
    const manager = new RelationsManager(driver, config, {
      driverName: 'openfga',
      onRelationWrite: (e) => {
        events.push(e)
        sequence.push(`hook:${e.operation}`)
      },
    })
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const actor = { type: 'user', uuid: uuidv7() }
    for (const [op, run] of [
      ['relate', () => manager.relate(u, 'viewer', doc, p, { actor })],
      ['unrelate', () => manager.unrelate(u, 'viewer', doc, p, { actor })],
    ] as Array<[string, () => Promise<unknown>]>) {
      const started = Date.now()
      let caught: any
      try {
        await run()
        assert.fail(`${op}: debería haber lanzado`)
      } catch (error) {
        caught = error
      }
      sequence.push(`catch:${op}`)
      const elapsed = Date.now() - started
      assert.equal(caught.status, 503, `${op}: ${caught.message}`)
      assert.equal(caught.code, 'E_AUTHZ_BACKEND_TIMEOUT', op)
      assert.isBelow(elapsed, 1_000, `${op}: tardó ${elapsed} ms (¿el SDK reintentó por su cuenta?)`)
    }
    assert.deepEqual(
      events.map((e) => [e.operation, e.indeterminate]),
      [
        ['relate', true],
        ['unrelate', true],
      ],
      'ROJO: el deadline de openfga (relations) no publica indeterminate: true'
    )
    assert.deepEqual(sequence, ['hook:relate', 'catch:relate', 'hook:unrelate', 'catch:unrelate'])
    for (const e of events) {
      assert.notProperty(e, 'transactional', 'en openfga { transaction } es imposible: la marca no aparece')
      assert.deepEqual(e.actor, actor)
      assert.deepEqual(e.partition, p)
    }
  }).timeout(30_000)
})


/* ── alpha.6 · 3-1' · el coste del barrido único SIN servidor (doble de cliente) ── */

/**
 * **alpha.6 · 3-1' (tester del panel relay)**: la forma del coste, sin el
 * `:8101`, para que una regresión («volver a K barridos») no entre en `main`
 * sin que `npm test` a secas la vea. Un doble del cliente FGA que pagina de
 * 100 (el tope del servidor) sobre 3 × 150 + 250 tuplas y cuenta las
 * peticiones: `reconcileRelations({ partitions })` desde `openfga` cuesta
 * `ceil(700/100) = 7` lecturas; por partición, 21. Y cada lectura lleva `{}`.
 */
test.group("alpha.6 · 3-1' · el coste del barrido único SIN servidor (doble de cliente FGA que pagina de 100)", () => {
  const PER = 150
  const FOREIGN = 250
  const PAGES = Math.ceil((3 * PER + FOREIGN) / 100)

  function fakeClient(all: Array<{ user: string; relation: string; object: string }>) {
    const reads: Array<{ filter: any; token: string | undefined }> = []
    const client = {
      read: async (filter: any, options: { pageSize: number; continuationToken?: string }) => {
        reads.push({ filter, token: options.continuationToken })
        const start = options.continuationToken ? Number(options.continuationToken) : 0
        const slice = all.slice(start, start + options.pageSize)
        const next = start + options.pageSize
        return { tuples: slice.map((key) => ({ key })), continuation_token: next < all.length ? String(next) : '' }
      },
    }
    return { client, reads }
  }

  test('reconcileRelations({ partitions: [3] }) ⇒ ceil(total/100) lecturas con filtro `{}`; por partición ⇒ 3×; el destino es el mismo', async ({ assert }) => {
    const config = contractRelationsConfig()
    const partitions: ScopeRef[] = [APP_SCOPE, { type: 'appliance', uuid: uuidv7() }, { type: 'unit', uuid: uuidv7() }]
    const keyOf = (p: ScopeRef) => (p.type === 'app' ? 'app' : `${p.type}|${p.uuid}`)
    const all: Array<{ user: string; relation: string; object: string }> = []
    for (const p of partitions) for (let i = 0; i < PER; i++) all.push({ user: `user:${uuidv7()}`, relation: 'viewer', object: `document:${keyOf(p)}|${uuidv7()}` })
    for (let i = 0; i < FOREIGN; i++) all.push({ user: `user:${uuidv7()}`, relation: 'viewer', object: `document:organization|${uuidv7()}|${uuidv7()}` })
    // El SDK exige ULIDs al construir (sin red): ids con forma, sin servidor detrás.
    const driver = new OpenFgaRelationsDriver(config, { apiUrl: 'http://127.0.0.1:9', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: '01ARZ3NDEKTSV4RRFFQ69G5FAW', holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
    const { client, reads } = fakeClient(all)
    // L11: la puerta (parte `conditions` en enumerate*) lee el modelo una vez; el falso sirve el que genera la config.
    ;(driver as any).client = { ...client, ...servedModel(config) }
    const caps: RelationsDriverCapabilities = {
      singleCheckRelations: true,
      listObjectsInherited: false,
      usersetSubjects: true,
      membersOfNative: true,
      enumerateRelations: true,
      listObjectsTruncation: false,
      injectableClock: true,
      transactionalWrites: false,
    }
    const many = makeRelationsDriver({ config, capabilities: caps })
    const report = await reconcileRelations({ from: driver, to: many, partitions })
    assert.lengthOf(reads, PAGES, 'UN barrido para las tres particiones')
    assert.isTrue(reads.every((r) => Object.keys(r.filter ?? {}).length === 0), 'cada Read con `{}`: sin object, sin prefijo')
    assert.equal(report.written, 3 * PER)

    reads.length = 0
    const one = makeRelationsDriver({ config, capabilities: caps })
    for (const p of partitions) await reconcileRelations({ from: driver, to: one, partition: p })
    assert.lengthOf(reads, 3 * PAGES, 'por partición: K barridos (la forma de hoy, que se queda)')
    for (const p of partitions) {
      const a = (await many.enumerateRelations!(p)).tuples.map((t) => t.object.id).sort()
      const b = (await one.enumerateRelations!(p)).tuples.map((t) => t.object.id).sort()
      assert.deepEqual(a, b)
      assert.lengthOf(a, PER)
    }
  })

  test('sin `enumerateRelationsMany` en el origen, `partitions` cae a K `enumerateRelations` (correcto, K barridos) — y `partition` + `partitions` a la vez, o ninguno, o `partitions: []`, es 500 E_AUTHZ_CONFIG', async ({ assert }) => {
    const config = contractRelationsConfig()
    const caps: RelationsDriverCapabilities = {
      singleCheckRelations: true,
      listObjectsInherited: false,
      usersetSubjects: true,
      membersOfNative: true,
      enumerateRelations: true,
      listObjectsTruncation: false,
      injectableClock: true,
      transactionalWrites: false,
    }
    const source = makeRelationsDriver({ config, capabilities: caps })
    const p1: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const p2: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await source.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, p1)
    await source.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, p2)
    assert.isUndefined((source as any).enumerateRelationsMany, 'el doble del contrato no lo trae: la caída es a K llamadas')
    const dest = makeRelationsDriver({ config, capabilities: caps })
    const report = await reconcileRelations({ from: source, to: dest, partitions: [p1, p2] })
    assert.equal(report.written, 2)
    for (const bad of [{ partition: p1, partitions: [p1] }, {}, { partitions: [] }]) {
      let caught: any
      try {
        await reconcileRelations({ from: source, to: dest, ...(bad as any) })
      } catch (error) {
        caught = error
      }
      assert.equal(caught?.code, 'E_AUTHZ_CONFIG', JSON.stringify(bad))
    }
  })
})

/**
 * Cierre 5 de D2 · R2: la guarda modelo ↔ config lee el modelo FIJADO para TODO tipo (antes, solo los que tienen deny),
 * así que los clientes falsos sin servidor sirven el modelo de la config con la que se construye el driver.
 */
function servedModel(config: RelationsConfig = contractRelationsConfig()) {
  const model = { authorization_model: openFgaFactsModel(HOLDER_MAP, [], { objectTypes: config.objectTypes }) }
  return { readAuthorizationModel: async () => model, readLatestAuthorizationModel: async () => model }
}

/* ══════════════════════════════════════════════════════════════════════════
 * Plan 2.5 · lote B · B4 (analista M4, medido; linaje L8 5.ª iteración ⇒ M8):
 * `ListObjects` tiene DOS formas de devolver una lista parcial con 200 y sin
 * señal: el tope (`OPENFGA_LIST_OBJECTS_MAX_RESULTS`, ya señalado) y el
 * DEADLINE del servidor (`--listObjects-deadline`, 3 s por defecto): pasado,
 * el servidor devuelve lo que llevaba. La letra del README («never a mute
 * partial list») era FALSA para la segunda. Propiedad universal: «toda
 * enumeración que se puede cortar devuelve `truncated` o lanza»; punto de paso
 * ÚNICO: el envoltorio de `ListObjects` del driver (`#listObjectsPage`), con
 * un reloj MONÓTONO inyectable (sin `sleep`). Corre sin servidor.
 * ══════════════════════════════════════════════════════════════════════════ */
test.group('lote B · B4 · listObjects de openfga: truncated por DEADLINE (umbral 0,9 × listObjectsDeadlineMs) con reloj inyectado, sin servidor', () => {
  const STORE = '01ARZ3NDEKTSV4RRFFQ69G5FAV'
  const MODEL = '01ARZ3NDEKTSV4RRFFQ69G5FAW'

  /** Un driver con el reloj monótono inyectado y un `listObjects` falso que tarda lo que se le diga. */
  function driverTakingMs(elapsedMs: number, options: { listObjectsDeadlineMs?: number; listObjectsMaxResults?: number } = {}) {
    let clock = 1_000
    const calls: string[] = []
    const driver = new OpenFgaRelationsDriver(contractRelationsConfig(), {
      apiUrl: 'http://127.0.0.1:9',
      storeId: STORE,
      modelId: MODEL,
      holderTypes: HOLDER_MAP,
      logger: { warn: () => {} },
      // ⚪ 9 (cierre 1 del lote B): el reloj monótono entra SOLO por el símbolo, fuera del tipo publicado.
      [MONOTONIC_CLOCK]: () => clock,
      ...options,
    } as any)
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const objects = [1, 2].map(() => `document:unit|${p.uuid}|${uuidv7()}`)
    ;(driver as any).client = { ...servedModel(),
      listObjects: async () => {
        calls.push('listObjects')
        clock += elapsedMs
        return { objects }
      },
    }
    return { driver, p, calls, objects }
  }

  test('B4 · una llamada que dura ≥ 0,9 × deadline ⇒ truncated: true (la misma señal que el tope); por debajo del umbral y por debajo del tope ⇒ sin señal; y en la vista withClock igual', async ({
    assert,
  }) => {
    const { DEFAULT_LIST_OBJECTS_DEADLINE_MS, LIST_OBJECTS_DEADLINE_RATIO } = await import('../src/drivers/openfga_relations_driver.js')
    assert.equal(DEFAULT_LIST_OBJECTS_DEADLINE_MS, 3_000, 'el default de OpenFGA (--listObjects-deadline 3s)')
    assert.equal(LIST_OBJECTS_DEADLINE_RATIO, 0.9)
    const u = { type: 'user', uuid: uuidv7() }
    // Default (3 000 ms): 2 700 ms es el umbral.
    const slow = driverTakingMs(2_700)
    const cut = await slow.driver.listObjects(u, 'viewer', 'document', slow.p)
    assert.isTrue(cut.truncated, 'ROJO (B4): la llamada rozó el deadline del servidor y la lista salió como completa')
    assert.lengthOf(cut.objects, 2, 'lo que llegó se devuelve igualmente')
    const quick = driverTakingMs(2_699)
    const whole = await quick.driver.listObjects(u, 'viewer', 'document', quick.p)
    assert.isUndefined(whole.truncated, 'por debajo del umbral no se inventa un truncado')
    // Deadline configurado (1 000 ms ⇒ umbral 900) y la vista `withClock` (misma instancia de reloj monótono).
    const tuned = driverTakingMs(900, { listObjectsDeadlineMs: 1_000 })
    const view = tuned.driver.withClock(() => new Date()) as OpenFgaRelationsDriver
    ;(view as any).client = (tuned.driver as any).client
    assert.isTrue((await view.listObjects(u, 'viewer', 'document', tuned.p)).truncated, 'la vista hereda deadline y reloj')
    const under = driverTakingMs(899, { listObjectsDeadlineMs: 1_000 })
    assert.isUndefined((await under.driver.listObjects(u, 'viewer', 'document', under.p)).truncated)
    // Y el tope sigue siendo la otra causa de la MISMA señal.
    const capped = driverTakingMs(1, { listObjectsMaxResults: 2 })
    assert.isTrue((await capped.driver.listObjects(u, 'viewer', 'document', capped.p)).truncated, 'tope alcanzado ⇒ truncated')
  })

  test('B4 · `listObjectsDeadlineMs`/`[MONOTONIC_CLOCK]` inválidos ⇒ 500 E_AUTHZ_CONFIG al construir; ⚪ 9: la clave de texto `monotonic` ya no es opción (500, no inerte) y el README no la documenta', async ({ assert }) => {
    for (const [label, bad] of [['deadline 0', { listObjectsDeadlineMs: 0 }], ['deadline negativo', { listObjectsDeadlineMs: -1 }], ['deadline texto', { listObjectsDeadlineMs: '3000' }], ['deadline NaN', { listObjectsDeadlineMs: Number.NaN }], ['deadline Infinity (N1)', { listObjectsDeadlineMs: Infinity }], ['deadline no entero', { listObjectsDeadlineMs: 1.5 }], ['monotonic no función', { [MONOTONIC_CLOCK]: 5 }], ['monotonic por clave de texto (⚪ 9)', { monotonic: () => 0 }]] as const) {
      let caught: any = null
      try {
        new OpenFgaRelationsDriver(contractRelationsConfig(), { apiUrl: 'http://127.0.0.1:9', storeId: STORE, modelId: MODEL, holderTypes: HOLDER_MAP, ...(bad as any) })
      } catch (e) {
        caught = e
      }
      assert.equal(caught?.code, 'E_AUTHZ_CONFIG', label)
    }
    const { readFile } = await import('node:fs/promises')
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.notInclude(readme, 'monotonic:', '⚪ 9: el README no documenta la opción de tests')
    assert.notInclude(readme, 'MONOTONIC_CLOCK', '⚪ 9: ni el símbolo')
    const subpath: Record<string, unknown> = await import('../src/openfga.js')
    assert.isUndefined(subpath.MONOTONIC_CLOCK, '⚪ 9: el símbolo no sale por /openfga')
  })

  /**
   * 🟠 N1 (cierre 2 del lote B; retira el 🟡 8 del cierre 1): `--listObjects-deadline=0` NO es «sin deadline».
   * MEDIDO por el auditor contra OpenFGA v1.19.0 (dos contenedores, 40 000 tuplas): con `--listObjects-deadline=0`
   * el `--request-timeout` del servidor (default 3 s) sigue cortando `ListObjects` con un **200 MUDO** — con
   * `--request-timeout=30ms`, `200 objects 0 of 40000` en 45-48 ms, tres repeticiones; control con 30 s, 40 000 de
   * 40 000. En la fuente: `list_objects.go` solo pone su propio `WithTimeout` si el deadline ≠ 0 (si no, hereda el
   * ctx del interceptor de `--request-timeout`) y elide `DeadlineExceeded` con lo que llevaba. Por eso
   * `listObjectsDeadlineMs` significa desde el cierre 2 «el corte EFECTIVO del servidor»: `--listObjects-deadline`
   * si ≠ 0 y, si es 0, `--request-timeout`. `Infinity` (la receta del cierre 1) producía la lista parcial muda que
   * B4/M8 prohíben — «estrictamente peor que no hacer nada»— y se RETIRA: `Infinity`/`NaN`/≤ 0/no entero ⇒ 500 al
   * construir, con la letra «el servidor siempre corta en alguno de los dos; declara el menor». Los dos a 0 no se
   * soportan (el gateway HTTP, `--http-upstream-timeout` 5 s, no está medido): límite declarado, sin promesa.
   */
  test('🟠 N1 · `listObjectsDeadlineMs: Infinity` ⇒ 500 E_AUTHZ_CONFIG con la letra «siempre corta en alguno de los dos» (--listObjects-deadline / --request-timeout; declara el menor); un servidor con deadline 0 y request-timeout 30 ms se declara con 30 y una llamada de 27 ms ya señala; 0 sigue siendo 500', async ({ assert }) => {
    const u = { type: 'user', uuid: uuidv7() }
    let caught: any = null
    try {
      driverTakingMs(1, { listObjectsDeadlineMs: Infinity })
    } catch (e) {
      caught = e
    }
    assert.isNotNull(caught, 'ROJO (N1): Infinity entró — la receta que produce el 200 mudo sigue aceptada')
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_CONFIG')
    assert.include(caught.message, 'siempre corta en alguno de los dos', 'la letra dice por qué no hay «sin deadline»')
    assert.include(caught.message, '--request-timeout')
    assert.include(caught.message, '--listObjects-deadline')
    assert.include(caught.message, 'declara el menor')
    assert.notInclude(caught.message, 'Infinity si el servidor corre', 'la receta retirada no se ofrece')
    // El significado nuevo: con `--listObjects-deadline=0` el corte efectivo es `--request-timeout` (30 ms en la
    // medición del auditor): se declara ESE y el umbral 0,9 × 30 = 27 ms señala.
    const effective = driverTakingMs(27, { listObjectsDeadlineMs: 30 })
    assert.isTrue((await effective.driver.listObjects(u, 'viewer', 'document', effective.p)).truncated, 'el corte efectivo del servidor señala')
    const under = driverTakingMs(26, { listObjectsDeadlineMs: 30 })
    assert.isUndefined((await under.driver.listObjects(u, 'viewer', 'document', under.p)).truncated)
    const capped = driverTakingMs(1, { listObjectsDeadlineMs: 30, listObjectsMaxResults: 2 })
    assert.isTrue((await capped.driver.listObjects(u, 'viewer', 'document', capped.p)).truncated, 'el tope sigue siendo la otra causa')
    // Y por FUENTE: el constructor no admite Infinity por ningún camino (la guarda es `Number.isInteger(x) && x > 0`).
    const { readFile } = await import('node:fs/promises')
    const source = await readFile(new URL('../src/drivers/openfga_relations_driver.ts', import.meta.url), 'utf8')
    assert.notMatch(source, /deadline === Infinity/, 'ROJO (N1): la rama que aceptaba Infinity sigue en el driver')
    assert.notInclude(source, 'Infinity si el servidor corre')
  })

  /**
   * ⚪ N10 (cierre 3 del lote B): `Number.isInteger(Number.MAX_SAFE_INTEGER)` es `true`, así que la guarda de N1
   * admitía un «sin deadline» con otro nombre — y, en general, cualquier `listObjectsDeadlineMs` MAYOR que el
   * `timeoutMs` del cliente (5 s por defecto) declara una señal que NUNCA puede saltar: el cliente aborta con 503
   * antes de que el umbral 0,9 × D se alcance, y si el servidor corta ANTES que D, la lista muda pasa como completa.
   * Guarda estructural, sin tope arbitrario: **`listObjectsDeadlineMs ≤ timeoutMs`**, si no 500 con la letra «la
   * señal tiene que poder saltar antes de que el cliente corte». Mutante «quitar la guarda» ⇒ rojo.
   */
  test('⚪ N10 · listObjectsDeadlineMs > timeoutMs del cliente ⇒ 500 E_AUTHZ_CONFIG con la letra «la señal tiene que poder saltar antes de que el cliente corte» (MAX_SAFE_INTEGER incluido); igual que timeoutMs entra; y la letra del tercer corte (--http-upstream-timeout) está en el README', async ({ assert }) => {
    const { DEFAULT_LIST_OBJECTS_DEADLINE_MS } = await import('../src/drivers/openfga_relations_driver.js')
    const build = (options: Record<string, unknown>) => {
      try {
        new OpenFgaRelationsDriver(contractRelationsConfig(), { apiUrl: 'http://127.0.0.1:9', storeId: STORE, modelId: MODEL, holderTypes: HOLDER_MAP, ...options } as any)
        return null
      } catch (e) {
        return e as any
      }
    }
    for (const [label, options] of [
      ['MAX_SAFE_INTEGER con el timeout por defecto', { listObjectsDeadlineMs: Number.MAX_SAFE_INTEGER }],
      ['5 001 con el timeout por defecto (5 000)', { listObjectsDeadlineMs: 5_001 }],
      ['el default (3 000) con timeoutMs 2 999', { timeoutMs: 2_999 }],
      ['3 000 con timeoutMs 2 999', { listObjectsDeadlineMs: 3_000, timeoutMs: 2_999 }],
    ] as const) {
      const caught = build(options)
      assert.isNotNull(caught, `ROJO (N10) ${label}: una señal que el cliente corta antes de que salte se admitió`)
      assert.equal(caught.status, 500, label)
      assert.equal(caught.code, 'E_AUTHZ_CONFIG', label)
      assert.include(caught.message, 'la señal tiene que poder saltar antes de que el cliente corte', `${label}: la letra`)
      assert.include(caught.message, 'timeoutMs', label)
      assert.include(caught.message, 'listObjectsDeadlineMs', label)
    }
    // Igual que el timeout entra (≤, no <); el default (3 000 ≤ 5 000) entra; y un timeout mayor también.
    assert.isNull(build({ listObjectsDeadlineMs: 5_000 }), 'igual que timeoutMs: la señal salta a 4 500 ms, antes del corte')
    assert.isNull(build({ listObjectsDeadlineMs: 3_000, timeoutMs: 3_000 }))
    assert.isNull(build({}), `el default ${DEFAULT_LIST_OBJECTS_DEADLINE_MS} cabe en el timeout por defecto`)
    assert.isNull(build({ listObjectsDeadlineMs: 8_000, timeoutMs: 10_000 }))
    // La letra del tercer corte: el menor de los TRES (--listObjects-deadline si ≠ 0, --request-timeout y, por HTTP,
    // --http-upstream-timeout), en el README (párrafo de relaciones, fila de Limits y Upgrading 7) y en el docblock.
    const { readFile } = await import('node:fs/promises')
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.isAtLeast(readme.split('`--http-upstream-timeout`').length - 1, 3, 'N10: el tercer corte nombrado en las tres letras del README')
    assert.include(readme, 'declare that lowest one', 'N10: «declara ese menor»')
    assert.include(readme, 'cannot be lower than `listObjectsDeadlineMs`', 'N10: la guarda del cliente, escrita')
    const source = await readFile(new URL('../src/drivers/openfga_relations_driver.ts', import.meta.url), 'utf8')
    assert.include(source, '--http-upstream-timeout', 'N10: el docblock nombra el tercer corte')
  })

  /**
   * Cierre 2 del lote B · ⚪ N5: `#readTuple` (la lectura PUNTUAL de `relate`/`unrelate`: «¿ya existe, y con qué
   * caducidad?») hacía `response.tuples ?? []` ⇒ «no existe» sobre un 200 sin `tuples`, y `relate` escribía a
   * ciegas (una caducidad vigente que no se ve no se preserva; `IGNORE_DUPLICATE_WRITES` convierte el no-op en
   * «creado»). Ahora es 503, como `#readAll`: exhaustivo-o-ruidoso también en la lectura de UNA clave.
   */
  test('⚪ N5 · relate con un Read que responde {} (sin tuples) ⇒ 503 E_AUTHZ_BACKEND_UNAVAILABLE y CERO write (unrelate no lee: es un delete ciego con IGNORE_MISSING_DELETES, control)', async ({ assert }) => {
    const { driver, p } = driverTakingMs(1)
    const calls: string[] = []
    ;(driver as any).client = { ...servedModel(),
      read: async () => {
        calls.push('read')
        return {}
      },
      write: async () => void calls.push('write'),
    }
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const caught = await driver.relate(u, 'viewer', doc, p).then(() => null, (e) => e)
    assert.isNotNull(caught, 'ROJO (N5) relate: el 200 sin tuples se tomó por «no existe»')
    assert.equal(caught.status, 503)
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    assert.match(caught.cause?.message ?? '', /tuples/)
    assert.deepEqual(calls, ['read'], 'nada se escribe sobre una lectura que no se puede prometer')
    // Control: `unrelate` no lee nada (un delete ciego con IGNORE_MISSING_DELETES es idempotente por sí mismo).
    calls.length = 0
    await driver.unrelate(u, 'viewer', doc, p)
    assert.deepEqual(calls, ['write'])
  })

  /**
   * 🟡 4 (cierre 1 del lote B): un 200 SIN `objects` no es una lista completa vacía — es la tercera forma de lista
   * parcial muda (M8: «toda enumeración que se puede cortar devuelve `truncated` o lanza») ⇒ 503, como `#readAll`
   * sin `tuples`.
   */
  test('🟡 4 · ListObjects responde 200 sin `objects` ({}) ⇒ 503 E_AUTHZ_BACKEND_UNAVAILABLE, nunca `{ objects: [] }` mudo', async ({ assert }) => {
    const { driver, p } = driverTakingMs(1)
    ;(driver as any).client = { ...servedModel(), listObjects: async () => ({}) }
    const caught = await driver.listObjects({ type: 'user', uuid: uuidv7() }, 'viewer', 'document', p).then(() => null, (e) => e)
    assert.isNotNull(caught, 'ROJO (🟡 4): la respuesta sin objects salió como lista completa vacía')
    assert.equal(caught.status, 503)
    assert.equal(caught.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    assert.match(caught.cause?.message ?? '', /objects/)
  })

  /**
   * ⚪ 10 (cierre 1 del lote B): guardia POR FUENTE del punto de paso único (patrón C5): hay UNA sola llamada a
   * `client.listObjects` en el driver y vive DENTRO de `#listObjectsPage`. Una segunda llamada fuera del envoltorio
   * no pondría rojo ningún mutante de la columna `truncation`; ésta sí.
   */
  test('⚪ 10 · por fuente: `client.listObjects(` aparece UNA vez en el driver, dentro de `#listObjectsPage`', async ({ assert }) => {
    const { readFile } = await import('node:fs/promises')
    const source = await readFile(new URL('../src/drivers/openfga_relations_driver.ts', import.meta.url), 'utf8')
    const calls = [...source.matchAll(/client\.listObjects\(/g)]
    assert.lengthOf(calls, 1, 'ROJO (⚪ 10): más de una llamada a ListObjects: el punto de paso único ya no es único')
    const start = source.indexOf('async #listObjectsPage(')
    assert.isAbove(start, 0)
    const end = source.indexOf('\n  async ', start + 1)
    assert.isAbove(end, start)
    assert.isTrue(calls[0].index! > start && calls[0].index! < end, 'la única llamada vive dentro de #listObjectsPage')
  })
})

/* ── cierre 2 de D1 · ⚪ N3 · un servidor con `--max-tuples-per-write` < 100 (cliente falso, sin servidor) ── */

/**
 * **⚪ N3 del auditor (cierre 2 de D1).** Con un servidor arrancado con `--max-tuples-per-write` < 100, la purga parte
 * en lotes de `RELATIONS_PURGE_WRITE_MAX` (100) y el `Write` que pasa el tope del servidor es un 400
 * `exceeded_entity_limit` — que puede NO ser el primero (`[3 allows][60 membresías][40 denies]` con tope 50: el `Write`
 * de 3 ya se aplicó). Hasta el cierre 2 salía como 503 `E_AUTHZ_BACKEND_UNAVAILABLE` (reintentable) y el docblock decía
 * «sin haber borrado nada»; repetida, la purga pide un `Write` de 100 y no termina nunca. Decisión: **500
 * `E_AUTHZ_CONFIG` con la letra del requisito** (`--max-tuples-per-write ≥ 100`), **marcado parcial si ya borró**
 * (`indeterminate: true` en `onRelationWrite`). FUERA de la guarda del servidor: el error es el `FgaApiValidationError`
 * REAL del SDK con la forma MEDIDA en v1.19.0 (400, `exceeded_entity_limit`, «The number of write operations exceeds the
 * allowed limit of N»). **Mutante** `fga.purge.write-limit-as-503` (quitar la clasificación) ⇒ los dos casos rojos.
 */
test.group('cierre 2 de D1 · ⚪ N3 · purga de openfga contra un servidor con --max-tuples-per-write < 100 ⇒ 500 E_AUTHZ_CONFIG con letra, parcial si ya borró (cliente falso)', () => {
  async function serverLimitError(limit: number) {
    const { FgaApiValidationError } = await import('@openfga/sdk')
    const message = `The number of write operations exceeds the allowed limit of ${limit}`
    return new FgaApiValidationError({
      message: 'Request failed with status code 400',
      response: { status: 400, statusText: 'Bad Request', data: { code: 'exceeded_entity_limit', message }, headers: {} },
      config: { method: 'post', url: '/stores/x/write' },
      request: { path: '/stores/01ARZ3NDEKTSV4RRFFQ69G5FAV/write' },
    } as any)
  }

  /** Un driver con el cliente sustituido: `read` sirve 3 allows + 60 membresías + 40 denies del sujeto; `deleteTuples` falla en la llamada `failAt` (1-based) con el 400 del tope. */
  async function harness(failAt: number) {
    const config = contractDenyRelationsConfig()
    const driver = new OpenFgaRelationsDriver(config, {
      apiUrl: 'http://127.0.0.1:1',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      modelId: '01ARZ3NDEKTSV4RRFFQ69G5FAW',
      holderTypes: HOLDER_MAP,
      logger: { warn: () => {} },
    })
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const U = { type: 'user', uuid: uuidv7() }
    const key = `unit|${p.uuid}`
    const user = `user:${U.uuid}`
    const tuples = [
      ...Array.from({ length: 3 }, () => ({ user, relation: 'viewer', object: `document:${key}|${uuidv7()}` })),
      ...Array.from({ length: 60 }, () => ({ user, relation: 'member', object: `group:${key}|${uuidv7()}` })),
      ...Array.from({ length: 40 }, () => ({ user, relation: 'denied_viewer', object: `document:${key}|${uuidv7()}` })),
    ]
    const limitError = await serverLimitError(50)
    const writes: number[] = []
    ;(driver as any).client = { ...servedModel(config),
      read: async (filter: { user?: string; object?: string }) => ({
        tuples: tuples
          .filter((t) => (!filter.user || t.user === filter.user) && (!filter.object || t.object.startsWith(filter.object)))
          .map((key) => ({ key })),
        continuation_token: '',
      }),
      deleteTuples: async (keys: unknown[]) => {
        writes.push(keys.length)
        if (writes.length === failAt) throw limitError
        return {}
      },
    }
    const events: any[] = []
    const manager = new RelationsManager(driver, config, { driverName: 'openfga', onRelationWrite: (e) => void events.push(e) })
    return { manager, driver, U, p, writes, events }
  }

  test('⚪ N3 · el 400 del tope llega en el 2.º Write (el 1.º ya borró 3 allows) ⇒ 500 E_AUTHZ_CONFIG que nombra --max-tuples-per-write ≥ 100, marcado PARCIAL, evento indeterminate: true', async ({ assert }) => {
    const { manager, U, p, writes, events } = await harness(2)
    const caught: any = await manager.purgeSubject(U, p).then(() => null, (e) => e)
    assert.deepEqual(writes, [3, 60], 'el Write de 3 allows se aplicó y el de 60 membresías dio el 400 del tope; no se intentó el de denies')
    assert.equal(caught?.status, 500, `ROJO (⚪ N3): el 400 del tope del servidor salió como ${caught?.status} ${caught?.code} (parece transitorio y la purga no termina nunca)`)
    assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
    for (const fragment of [
      'purgeSubject',
      'rechazó un Write de 60 tuplas',
      'exceeded_entity_limit: «The number of write operations exceeds the allowed limit of 50»',
      'RELATIONS_PURGE_WRITE_MAX = 100',
      '--max-tuples-per-write ≥ 100',
      'No es transitorio',
      'Ya se habían borrado 3 tuplas en Write anteriores: la purga quedó A MEDIAS (escritura parcial).',
    ]) {
      assert.include(String(caught?.message), fragment)
    }
    assert.isTrue(isPartialWrite(caught), 'ya borró ⇒ escritura parcial (invariante 13)')
    assert.lengthOf(events, 1)
    assert.isTrue(events[0].indeterminate, 'onRelationWrite: indeterminate: true')
  })

  test('⚪ N3 · el 400 del tope en el 1.er Write ⇒ 500 E_AUTHZ_CONFIG «No se borró nada.», SIN marca parcial', async ({ assert }) => {
    const { driver, U, p, writes } = await harness(1)
    const caught: any = await driver.purgeSubject(U, p).then(() => null, (e) => e)
    assert.deepEqual(writes, [3])
    assert.equal(caught?.status, 500, `ROJO (⚪ N3): el 400 del tope del servidor salió como ${caught?.status} ${caught?.code}`)
    assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
    assert.include(String(caught?.message), 'No se borró nada.')
    assert.isFalse(isPartialWrite(caught), 'nada borrado ⇒ «esa escritura no ocurrió»')
    // Cierre de R3 (⚪-6 del tester, su T5): la marca de DESPLIEGUE (la misma que R3 pone a `exceeded_entity_limit` en
    // los dos drivers). Relaciones no tiene relay que la consuma hoy, pero un consumidor que separe «despliegue» de
    // «caída» por `deploymentFailure` lee lo mismo en los dos puertos.
    assert.isTrue((caught as any)?.deploymentFailure === true, 'ROJO (T5): el 500 del tope de Write de la purga va marcado de DESPLIEGUE')
  })
})
