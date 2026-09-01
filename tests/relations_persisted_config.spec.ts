/**
 * **La config de relaciones PERSISTIDA (Fase 4-5 · 🟡3)** — SQL puro (todos los
 * motores). Es lo que cierra el «modelo de uno, tuplas de otro»: la config vive
 * en `authz_relations_config`, bajo el gate de versión (invariante 14), y
 * CUALQUIER proceso —también uno SIN `defineRelationsConfig` en memoria— la lee
 * de la base antes de republicar el modelo fusionado.
 */
import { test } from '@japa/runner'
import db from '@adonisjs/lucid/services/db'
import {
  saveRelationsConfig,
  readRelationsConfig,
  readRelationsConfigSpec,
} from '../src/relations_config_store.js'
import { readAuthzCatalogVersion } from '../src/catalog_cache.js'
import { RelationConfigError } from '../src/errors.js'
import type { RelationsConfigSpec } from '../src/relations/define_relations_config.js'

const SPEC: RelationsConfigSpec = {
  objectTypes: [
    { type: 'document', relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }] },
    { type: 'folder', relations: [{ name: 'viewer' }] },
  ],
  holderTypes: ['user', 'admin', 'integration'],
  database: { membersOf: true },
}

test.group('relaciones · config persistida (🟡3)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations_config').delete()
  })

  test('saveRelationsConfig persiste el spec y readRelationsConfig lo recupera VALIDADO', async ({ assert }) => {
    await saveRelationsConfig(SPEC)
    const spec = await readRelationsConfigSpec()
    assert.isNotNull(spec)
    assert.deepEqual(spec!.objectTypes.map((t) => t.type).sort(), ['document', 'folder'])
    // Y validado: `hasType`/`isDeclared` responden (lo que consume F-05).
    const config = await readRelationsConfig()
    assert.isTrue(config!.hasType('document'))
    assert.isTrue(config!.isDeclared('document', 'viewer'))
    assert.isFalse(config!.hasType('role_binding')) // la frontera del 🔴 intacta
  })

  test('🟡3 · un proceso SIN defineRelationsConfig en memoria recupera los tipos de la BASE', async ({ assert }) => {
    await saveRelationsConfig(SPEC)
    // «Otro proceso»: no tiene NADA en memoria; solo lee la base.
    const fromDb = await readRelationsConfig()
    assert.isNotNull(fromDb, 'la config viaja por la base, no por memoria')
    assert.deepEqual(fromDb!.objectTypes.map((t) => t.type).sort(), ['document', 'folder'])
  })

  test('invariante 14 · guardar la config SUBE la versión compartida del catálogo', async ({ assert }) => {
    const before = await readAuthzCatalogVersion()
    await saveRelationsConfig(SPEC)
    const after = await readAuthzCatalogVersion()
    assert.isAbove(after, before, 'la versión sube: un sync en otro proceso ve la config nueva en su siguiente pregunta')
  })

  test('re-guardar ACTUALIZA la fila (una sola fila id=1), no duplica', async ({ assert }) => {
    await saveRelationsConfig(SPEC)
    await saveRelationsConfig({ ...SPEC, objectTypes: [{ type: 'space', relations: [{ name: 'member' }] }] })
    const rows = await db.from('authz_relations_config')
    assert.lengthOf(rows, 1)
    const config = await readRelationsConfig()
    assert.deepEqual(config!.objectTypes.map((t) => t.type), ['space'])
  })

  test('sin fila persistida ⇒ readRelationsConfig es null (relaciones opt-in, no un error)', async ({ assert }) => {
    assert.isNull(await readRelationsConfig())
    assert.isNull(await readRelationsConfigSpec())
  })

  test('una config INVÁLIDA no ensucia la tabla (valida antes de escribir)', async ({ assert }) => {
    let caught: any
    try {
      // `role_binding` es un tipo reservado (⚪4): la frontera del 🔴.
      await saveRelationsConfig({ objectTypes: [{ type: 'role_binding', relations: [{ name: 'x' }] }] })
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.instanceOf(caught, RelationConfigError)
    assert.lengthOf(await db.from('authz_relations_config'), 0)
  })
})
