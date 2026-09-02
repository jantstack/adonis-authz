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
import {
  openFgaFactsModel,
  factsRootTuples,
  factsParentTuple,
  factsBindingTuples,
  factsBindingObject,
  factsScopeObject,
} from '../src/drivers/openfga_facts.js'
import { OpenFgaRelationsDriver } from '../src/drivers/openfga_relations_driver.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { buildRelationsManager } from '../providers/authz_provider.js'
import { spyFgaClient } from './helpers/fga_spy.js'
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
      enumerateRelations: true,
      // whenTrue MEDIDO solo donde el tope es bajo (:8103); si no, whenFalse.
      listObjectsTruncation: capsLow,
      injectableClock: true,
      // L-2: `openfga` no puede ser otra cosa (una tupla no entra en una transacción SQL, no hay 2PC); `false` EXPLÍCITO, y el rechazo con dientes contra el :8101 es L-5.
      transactionalWrites: false,
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
      holderTypes: HOLDER_MAP,
      timeoutMs: 200,
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
