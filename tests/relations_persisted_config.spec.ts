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
import { readAuthzCatalogVersion } from '../src/catalog/catalog_cache.js'
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

  test('cierre-2 de R1 · P1: maxGroupDepth y database.enforceGroupDepth se VALIDAN pero NO se persisten (claves de despliegue); la fila sigue siendo legible por la lista blanca de alpha.3', async ({ assert }) => {
    // Se validan: un valor malo es el mismo 500 y no toca la tabla.
    const bad = await saveRelationsConfig({ ...SPEC, maxGroupDepth: 0 } as any).then(
      () => null,
      (e) => e
    )
    assert.equal(bad?.status, 500, bad?.message)
    assert.isNull(await db.from('authz_relations_config').where('id', 1).first(), 'una spec inválida no ensucia la tabla')
    // Válidas: se guardan SIN ellas (el resto de la spec, tal cual).
    const config = await saveRelationsConfig({ ...SPEC, maxGroupDepth: 5, database: { membersOf: true, enforceGroupDepth: true } })
    assert.equal(config.maxGroupDepth, 5, 'la config devuelta (la del proceso) sí las lleva')
    assert.isTrue(config.enforceGroupDepth)
    const row: any = await db.from('authz_relations_config').where('id', 1).first()
    const stored = JSON.parse(String(row.spec))
    assert.notProperty(stored, 'maxGroupDepth', 'ROJO (P1): maxGroupDepth se persistió')
    assert.deepEqual(stored.database, { membersOf: true }, 'ROJO (P1): enforceGroupDepth se persistió')
    assert.deepEqual(stored.objectTypes, SPEC.objectTypes)
    // La lista blanca de 2.5.0-alpha.3 (antes de R1): un proceso alpha.2/alpha.3 relee esta fila sin RelationConfigError.
    const ALPHA3_SPEC_KEYS = { root: ['objectTypes', 'holderTypes', 'database'], database: ['membersOf'] }
    assert.includeMembers(ALPHA3_SPEC_KEYS.root, Object.keys(stored), 'claves de raíz fuera de la lista blanca de alpha.3')
    assert.includeMembers(ALPHA3_SPEC_KEYS.database, Object.keys(stored.database ?? {}), 'claves de database fuera de la lista blanca de alpha.3')
    const reread = await readRelationsConfig()
    assert.notProperty(reread!, 'maxGroupDepth', 'releída de la base: sin techo (nadie lo lee de ahí: el plan pregunta al driver)')
    assert.isTrue(reread!.isDeclared('document', 'viewer'))
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

  /** ⚪ 13 (cierre 1 del lote B): `saveRelationsConfig(config.relations.config)` — la config YA definida — dice lo que es. */
  test('⚪ 13 · saveRelationsConfig(<config ya definida>) ⇒ 422 con la pista «parece una config ya definida; pasa la spec» y la tabla intacta', async ({ assert }) => {
    const { defineRelationsConfig } = await import('../src/relations/define_relations_config.js')
    const caught = await saveRelationsConfig(defineRelationsConfig(SPEC) as any).then(() => null, (e) => e)
    assert.instanceOf(caught, RelationConfigError, 'ROJO (⚪ 13): entró, o murió con otra letra')
    assert.include(caught.message, 'parece una config YA DEFINIDA')
    assert.include(caught.message, 'saveRelationsConfig')
    assert.lengthOf(await db.from('authz_relations_config'), 0)
  })

  /**
   * 🟡 7 (cierre 1 del lote B): una fila persistida ANTES de 2.5 (`JSON.stringify(spec)` tal cual, con las claves
   * que 2.4 tiraba en silencio), o un ciclo, o un JSON corrupto, es «la config persistida NO valida» (422,
   * `RelationConfigError`), DISTINTO de «la lectura falló» (503, tabla ausente). El comando los separa en dos ramas.
   */
  test('🟡 7 · fila persistida pre-2.5 con `deny: true` ⇒ readRelationsConfig lanza 422 E_AUTHZ_RELATION_CONFIG_UNKNOWN_KEY; JSON corrupto ⇒ 422 RelationConfigError; tabla ausente ⇒ 503 (la lectura falló): tres cosas distintas', async ({ assert }) => {
    const seed = (spec: string) => db.table('authz_relations_config').insert({ id: 1, spec, model_id: null, updated_at: new Date() })
    await seed(JSON.stringify({ ...SPEC, deny: true }))
    const stale = await readRelationsConfig().then(() => null, (e) => e)
    assert.instanceOf(stale, RelationConfigError, 'ROJO (🟡 7): la fila vieja se leyó como válida o murió como 503')
    assert.equal(stale.status, 422)
    assert.equal(stale.code, 'E_AUTHZ_RELATION_CONFIG_UNKNOWN_KEY')
    assert.include(stale.message, "'deny'")
    await db.from('authz_relations_config').delete()
    await seed('{not json')
    const corrupt = await readRelationsConfig().then(() => null, (e) => e)
    assert.instanceOf(corrupt, RelationConfigError, 'un JSON corrupto es «no valida», no «la lectura falló»')
    assert.equal(corrupt.status, 422)
    assert.include(corrupt.message, 'no es JSON')
    await db.from('authz_relations_config').delete()
    const { withTableMissing } = await import('./helpers/table_missing.js')
    const gone = await withTableMissing('authz_relations_config', () => readRelationsConfig().then(() => null, (e) => e))
    assert.equal(gone?.status, 503, 'la tabla ausente sí es «la lectura falló»')
    assert.notInstanceOf(gone, RelationConfigError)
  })

  /**
   * Cierre 2 del lote B · ⚪ N6: una fila persistida cuyo JSON es válido pero NO es un objeto (`null`, `0`, `false`,
   * `""`, `[]`) se leía como «ninguna persistida» (`null`) y APAGABA la vigilancia de la deriva del modelo en
   * silencio (`!row?.spec` para `""`; `JSON.parse('null')` ⇒ `null` ⇒ `spec ? … : null`). Solo la AUSENCIA de fila
   * es `null`; cualquier otra cosa que no sea un objeto es la rama «NO valida» (422), igual que un JSON corrupto.
   */
  test('⚪ N6 · fila persistida con JSON válido que NO es objeto (null/0/false/""/[]) ⇒ 422 RelationConfigError «no es un objeto» en readRelationsConfigSpec y readRelationsConfig, NUNCA null; solo la fila ausente es null', async ({ assert }) => {
    for (const spec of ['null', '0', 'false', '""', '[]']) {
      await db.from('authz_relations_config').delete()
      await db.table('authz_relations_config').insert({ id: 1, spec, model_id: null, updated_at: new Date() })
      for (const [label, read] of [['readRelationsConfigSpec', readRelationsConfigSpec], ['readRelationsConfig', readRelationsConfig]] as const) {
        const outcome = await read().then((c) => ({ value: c }), (e) => ({ error: e }))
        assert.isTrue('error' in outcome, `ROJO (N6) ${label} con ${spec}: se leyó como ${JSON.stringify((outcome as any).value)} («ninguna persistida», la vigilancia se apaga)`)
        const error = (outcome as { error: any }).error
        assert.instanceOf(error, RelationConfigError, `${label} con ${spec}`)
        assert.equal(error.status, 422, `${label} con ${spec}`)
        assert.include(error.message, 'no es un objeto', `${label} con ${spec}: la rama «NO valida»`)
      }
    }
    await db.from('authz_relations_config').delete()
    assert.isNull(await readRelationsConfigSpec(), 'la fila AUSENTE sigue siendo null')
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
