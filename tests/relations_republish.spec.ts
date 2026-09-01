/**
 * **🟡3 (republicación sin config en memoria) + la CARRERA
 * `defineRelationsConfig`↔`syncAuthzCatalog` + el 409** (Fase 4-5).
 *
 *  - **🟡3**: republicar el modelo fusionado desde un proceso que NO tiene
 *    `defineRelationsConfig` en memoria NO deja caer los tipos de relación,
 *    porque `republishFusedModel` los lee de `authz_relations_config`.
 *  - **La carrera**: `syncAuthzCatalog` y un `defineRelationsConfig` que se
 *    guarda republican los DOS el modelo del store compartido. Como ambos leen
 *    las DOS mitades persistidas, el modelo final NUNCA está mutilado
 *    (`can_p0` Y `document` resuelven) y el `model_id` queda consistente.
 *  - **El 409**: una contención que no cede (el CAS del `model_id` no gana
 *    nunca) ⇒ 409 `E_AUTHZ_WRITE_CONFLICT`, jamás un modelo a medias.
 *
 * Las dos primeras contra el `:8101` (store compartido REAL); el 409 con un
 * stub del CAS (sin servidor).
 */
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { syncAuthzCatalog } from '../src/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { saveRelationsConfig, readRelationsConfig, readRelationsModelId, republishFusedModel } from '../src/relations_config_store.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { openFgaFactsModel } from '../src/drivers/openfga_facts.js'
import { OpenFgaRelationsDriver } from '../src/drivers/openfga_relations_driver.js'
import { OpenFgaAuthorizationDriver } from '../src/drivers/openfga_driver.js'
import { WriteConflictError } from '../src/errors.js'
import { APP_SCOPE } from '../src/types.js'
import type { RelObject } from '../src/types.js'
import type { RelationsConfig } from '../src/relations/define_relations_config.js'
import type { FusedModelPublisher } from '../src/relations_config_store.js'

const HOLDER_MAP = { user: 'user', admin: 'admin', integration: 'integration' } as const
const SPEC = {
  objectTypes: [{ type: 'document', relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }] }],
  holderTypes: ['user', 'admin', 'integration'],
  database: { membersOf: true },
} as const

const openFgaTestUrl = process.env.OPENFGA_TEST_URL

/* ── 🟡3 + la CARRERA contra el `:8101` ──────────────────────────────────── */

if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  async function provisionShared(): Promise<{ storeId: string; roles: OpenFgaAuthorizationDriver; roleUuid: string; config: RelationsConfig }> {
    const config = defineRelationsConfig(SPEC as any)
    const { OpenFgaClient } = await import('@openfga/sdk')
    const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `republish-${Date.now()}-${uuidv7().slice(0, 8)}` })
    // Modelo inicial fusionado.
    await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
      openFgaFactsModel(HOLDER_MAP, ['p0'], { objectTypes: config.objectTypes })
    )
    const catalog = { permissions: [{ slug: 'p0' }], roles: [{ slug: 'r0', scopeType: 'app', permissions: ['p0'] }] }
    await syncAuthzCatalog(catalog)
    const roles = new OpenFgaAuthorizationDriver({
      apiUrl, storeId: store.id!, holderTypes: HOLDER_MAP, acceptScopeDriftRisk: true, logger: { warn: () => {} },
    })
    await syncAuthzCatalog(catalog, { projection: roles.catalogProjection() })
    // La config de relaciones PERSISTIDA (la mitad de ReBAC en la base).
    await saveRelationsConfig(SPEC as any)
    const role: any = await db.from('authz_roles').where('slug', 'r0').where('scope_type', 'app').first()
    return { storeId: store.id!, roles, roleUuid: role.uuid, config }
  }

  /** ¿El modelo del store (por `modelId`) declara el tipo `document`? */
  async function modelHasDocument(storeId: string, modelId: string): Promise<boolean> {
    const { OpenFgaClient } = await import('@openfga/sdk')
    const res = await new OpenFgaClient({ apiUrl, storeId }).readAuthorizationModel({ authorizationModelId: modelId } as any)
    return (res.authorization_model?.type_definitions ?? []).some((t: any) => t.type === 'document')
  }

  test.group('relaciones · 4-5 — 🟡3 + la carrera republican el modelo fusionado', (group) => {
    const stores: string[] = []
    group.each.setup(async () => {
      await cleanAuthzTables()
    })
    group.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
    })

    test('🟡3 · republicar SIN defineRelationsConfig en memoria conserva los tipos de relación (los lee de la base)', async ({ assert }) => {
      const { storeId, roles } = await provisionShared()
      stores.push(storeId)
      // El driver de ROLES no tiene NADA de relaciones en memoria. Aun así,
      // republishFusedModel lee la config de la BASE y emite el modelo COMPLETO.
      const { modelId, relationTypes } = await republishFusedModel(roles)
      assert.include(relationTypes, 'document', 'leyó los tipos de la base')
      assert.isTrue(await modelHasDocument(storeId, modelId), 'el modelo republicado DECLARA document')

      // CONTRASTE (la mitad que se caería): republicar SOLO la mitad de roles
      // (facts, sin la config) deja caer document — «modelo de uno, tuplas de
      // otro». Es lo que 🟡3 evita leyendo la base.
      const factsOnly = await roles.republishFusedModel(undefined)
      assert.isFalse(await modelHasDocument(storeId, factsOnly), 'sin leer la base, el modelo pierde document')
    })

    test('carrera · syncAuthzCatalog ∥ defineRelationsConfig: el modelo final resuelve can_p0 Y document (nada se pierde)', async ({ assert }) => {
      const { storeId, roles, config } = await provisionShared()
      stores.push(storeId)
      const alice = { type: 'user', uuid: uuidv7() }
      await roles.grant(alice, 'r0', APP_SCOPE, { expiresAt: null })

      // Las PERSISTENCIAS de las dos operaciones las SERIALIZA el gate de versión
      // (invariante 14: `withAuthzCatalogWrite` bloquea la fila de versión), así
      // que NO se pisan en SQL —ese es justo el propósito del gate—: un sync que
      // cambia el catálogo (añade p1) y un defineRelationsConfig que se re-guarda.
      const catalog2 = { permissions: [{ slug: 'p0' }, { slug: 'p1' }], roles: [{ slug: 'r0', scopeType: 'app', permissions: ['p0'] }] }
      await syncAuthzCatalog(catalog2, { projection: roles.catalogProjection() })
      await saveRelationsConfig(SPEC as any)

      // Lo que SÍ compite por el `modelId` es la REPUBLICACIÓN del modelo (fuera
      // de la transacción SQL: no hay 2PC entre la fila y FGA). Los dos republican
      // a la vez; los dos leen las DOS mitades persistidas ⇒ modelo completo.
      const settled = await Promise.allSettled([republishFusedModel(roles), republishFusedModel(roles)])
      for (const outcome of settled) {
        if (outcome.status === 'rejected') {
          // Una contención que no cede sale como 409, jamás como un modelo a medias.
          assert.equal((outcome.reason as any)?.status, 409, String((outcome.reason as any)?.message))
        }
      }
      assert.isTrue(settled.some((o) => o.status === 'fulfilled'), 'al menos una republicación gana el CAS del modelId')

      // El modelId final PINADO es consistente (uno de los dos ganó el CAS) y su
      // modelo resuelve las DOS mitades: nada mutilado.
      const pinned = await readRelationsModelId()
      assert.isNotNull(pinned)
      assert.isTrue(await modelHasDocument(storeId, pinned!), 'el modelo pinado declara document')

      // Y el store, sobre su modelo, sigue respondiendo las DOS preguntas:
      const rolesOnPinned = new OpenFgaAuthorizationDriver({ apiUrl, storeId, modelId: pinned!, holderTypes: HOLDER_MAP, acceptScopeDriftRisk: true, logger: { warn: () => {} } })
      assert.isTrue(await rolesOnPinned.authorize(alice, 'p0', APP_SCOPE), 'can_p0 sigue resolviendo (la mitad de roles)')
      const rel = new OpenFgaRelationsDriver(config, { apiUrl, storeId, modelId: pinned!, holderTypes: HOLDER_MAP, logger: { warn: () => {} } })
      const doc: RelObject = { type: 'document', id: uuidv7() }
      await rel.relate(alice, 'viewer', doc, APP_SCOPE)
      assert.isTrue(await rel.check(alice, 'viewer', doc, APP_SCOPE), 'document#viewer resuelve (la mitad de ReBAC)')
    })
  })
}

/* ── El 409: contención que no cede (CAS que no gana) ─────────────────────── */

test.group('relaciones · 4-5 — el 409 de la contención que no cede', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations_config').delete()
  })

  test('republishFusedModel con el CAS del modelId sin ceder ⇒ 409 E_AUTHZ_WRITE_CONFLICT', async ({ assert }) => {
    await saveRelationsConfig(SPEC as any)
    let published = 0
    const publisher: FusedModelPublisher = {
      republishFusedModel: async () => {
        published += 1
        return `model-${published}`
      },
    }
    let caught: any
    try {
      // stubCas siempre false = otra republicación cambia el pin sin parar.
      await republishFusedModel(publisher, { stubCas: () => false })
      assert.fail('debería haber lanzado 409')
    } catch (error) {
      caught = error
    }
    assert.instanceOf(caught, WriteConflictError)
    assert.equal(caught.status, 409)
    assert.equal(caught.code, 'E_AUTHZ_WRITE_CONFLICT')
    assert.isAbove(published, 1, 'reintentó y publicó cada vez, pero nunca ganó el CAS')
  })

  test('el CAS que gana a la primera NO reintenta ni lanza', async ({ assert }) => {
    await saveRelationsConfig(SPEC as any)
    let published = 0
    const publisher: FusedModelPublisher = {
      republishFusedModel: async () => {
        published += 1
        return 'model-ok'
      },
    }
    const out = await republishFusedModel(publisher, { stubCas: () => true })
    assert.equal(out.modelId, 'model-ok')
    assert.equal(published, 1, 'una sola publicación')
    assert.include(out.relationTypes, 'document')
  })
})
