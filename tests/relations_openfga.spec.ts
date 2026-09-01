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
import { runRelationsDriverContract, contractRelationsConfig } from '../src/testing/relations_contract.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { RelationsManager } from '../src/relations/manager.js'
import { openFgaFactsModel } from '../src/drivers/openfga_facts.js'
import { OpenFgaRelationsDriver } from '../src/drivers/openfga_relations_driver.js'
import type { RelationsConfig } from '../src/relations/define_relations_config.js'
import type { ScopeRef } from '../src/types.js'

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
      enumerateRelations: false,
      // whenTrue MEDIDO solo donde el tope es bajo (:8103); si no, whenFalse.
      listObjectsTruncation: capsLow,
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
}
