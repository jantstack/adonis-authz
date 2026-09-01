/**
 * **`openfga:provision` incluye los tipos de RELACIÓN en el modelo `facts`**
 * (Fase 4, lote 4-8). Hasta 4-8 el comando publicaba un modelo facts-ONLY, así
 * que un store recién aprovisionado NO conocía el tipo `document` y rechazaba
 * toda tupla de relación hasta un `authz:catalog:sync` (que republica el modelo
 * fusionado). Ahora `provisionOpenFgaStore` recibe los tipos de relación
 * (`relationsConfigOf` los saca del CONFIG estático) y el store los acepta de
 * salida.
 *
 * `relationsConfigOf` (la decisión del comando) se juzga en memoria; la
 * ACEPTACIÓN de la tupla se mide contra el `:8101` (un doble no prueba el
 * modelo del store).
 */
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { relationsConfigOf } from '../commands/openfga_provision.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'

const RELATIONS = {
  objectTypes: [
    { type: 'document', relations: [{ name: 'owner' }, { name: 'viewer', includes: ['owner'] }] },
  ],
}

/* ── La decisión del comando (memoria, todos los modos) ───────────────────── */

test.group('relaciones · openfga:provision — relationsConfigOf (4-8)', () => {
  test('sin relations.config ⇒ undefined (modelo facts-only, como hasta 4-8)', ({ assert }) => {
    assert.isUndefined(relationsConfigOf({}))
    assert.isUndefined(relationsConfigOf({ relations: {} }))
    assert.isUndefined(relationsConfigOf({ relations: { config: { objectTypes: [] } } }))
  })

  test('con relations.config ⇒ { objectTypes } (los tipos que van fusionados)', ({ assert }) => {
    const config = { relations: { config: defineRelationsConfig({ ...RELATIONS, holderTypes: ['user'] }) } }
    const out = relationsConfigOf(config)
    assert.isDefined(out)
    assert.deepEqual(out!.objectTypes.map((t: any) => t.type), ['document'])
  })
})

/* ── La ACEPTACIÓN de la tupla contra el `:8101` ──────────────────────────── */

const openFgaTestUrl = process.env.OPENFGA_TEST_URL
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl
  const HOLDERS = { users: 'user' }

  test.group('relaciones · openfga:provision — el store aprovisionado acepta relaciones (4-8)', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
    })

    test('ROJO→VERDE · un store fresco aprovisionado CON tipos de relación acepta document#viewer SIN sync', async ({
      assert,
    }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const { provisionOpenFgaStore } = await import('../src/openfga.js')

      // ROJO (el estado anterior): provisionar SIN tipos de relación (facts-only).
      const red = await provisionOpenFgaStore(apiUrl, `prov-red-${uuidv7().slice(0, 8)}`, HOLDERS, ['p0'])
      stores.push(red.storeId)
      const redClient = new OpenFgaClient({ apiUrl, storeId: red.storeId, authorizationModelId: red.modelId })
      let redError: any
      try {
        await redClient.write({ writes: [{ user: 'user:alice', relation: 'viewer', object: `document:app|${uuidv7()}` }] })
      } catch (e) {
        redError = e
      }
      assert.isDefined(redError, 'sin tipos de relación el store RECHAZA la tupla')
      assert.match(
        String(redError?.apiErrorMessage ?? redError?.message),
        /type 'document' not found|not found/,
        'validation_error del servidor: el tipo document no está en el modelo facts-only'
      )

      // VERDE (4-8): provisionar CON los tipos de relación fusionados.
      const relations = relationsConfigOf({ relations: { config: defineRelationsConfig({ ...RELATIONS, holderTypes: ['user'] }) } })
      const green = await provisionOpenFgaStore(apiUrl, `prov-green-${uuidv7().slice(0, 8)}`, HOLDERS, ['p0'], relations)
      stores.push(green.storeId)
      const greenClient = new OpenFgaClient({ apiUrl, storeId: green.storeId, authorizationModelId: green.modelId })
      const alice = `user:${uuidv7()}`
      const object = `document:app|${uuidv7()}`
      // Acepta la escritura de la relación SIN sync previo…
      await greenClient.write({ writes: [{ user: alice, relation: 'viewer', object }] })
      // …y check la resuelve (viewer directo).
      const res = await greenClient.check({ user: alice, relation: 'viewer', object })
      assert.isTrue(res.allowed === true, 'document#viewer resuelve en el store recién aprovisionado')
    })

    test('y el modelo fusionado SIGUE resolviendo la mitad de roles (can_p0)', async ({ assert }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const { provisionOpenFgaStore } = await import('../src/openfga.js')
      const relations = relationsConfigOf({ relations: { config: defineRelationsConfig({ ...RELATIONS, holderTypes: ['user'] }) } })
      const { storeId, modelId } = await provisionOpenFgaStore(apiUrl, `prov-both-${uuidv7().slice(0, 8)}`, HOLDERS, ['p0'], relations)
      stores.push(storeId)
      const client = new OpenFgaClient({ apiUrl, storeId })
      const model = await client.readAuthorizationModel({ authorizationModelId: modelId } as any)
      const types = (model.authorization_model?.type_definitions ?? []).map((t: any) => t.type)
      // Las DOS mitades en el mismo modelo: la de roles (scope/role/role_binding)
      // y la de ReBAC (document).
      assert.include(types, 'document', 'la mitad de ReBAC')
      assert.include(types, 'role_binding', 'la mitad de roles (c2r) sigue ahí')
      assert.include(types, 'scope', 'el árbol de (c2r) sigue ahí')
    })
  })
}
