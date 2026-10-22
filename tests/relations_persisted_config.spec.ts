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
  checkRelationsConfigDenyReach,
} from '../src/relations_config_store.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { APP_SCOPE } from '../src/types.js'
import type { ScopeRef } from '../src/types.js'
import { v7 as uuidv7 } from 'uuid'
import { readAuthzCatalogVersion } from '../src/catalog/catalog_cache.js'
import { RelationConfigError } from '../src/errors.js'
import type { RelationsConfigSpec } from '../src/relations/define_relations_config.js'
import { readFileSync } from 'node:fs'

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

/**
 * **Lote RC · sublote (8) · la letra de la guarda de `database`** (punto 7, «docs con dientes» y R6 del analista del panel):
 * la fila de Limits, el párrafo de la config persistida y la entrada del CHANGELOG dicen el código, las dos salidas con
 * nombre (sin `true` global), los prefijos, el orden del pipeline, que persistir es OBLIGATORIO si usas deny, que el
 * `--dry-run` necesita dos drivers (en solo-`database` el detector es la función), la `connection`, la adopción en una
 * release que no cambia la config, y los tres amarillos declarados con su caso. El comportamiento lo juzga la guardia.
 */
test.group('relaciones · config persistida · sublote (8): la letra de la guarda del alcance de los denies', () => {
  const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8')
  test('README (filas de Limits + sección de la config persistida) y CHANGELOG (sección no sellada) dicen la guarda, sus salidas con nombre, los detectores, el pipeline y lo declarado', ({ assert }) => {
    const readme = read('README.md')
    const rowOf = (start: string) => readme.split('\n').find((line) => line.startsWith(start))
    const row = rowOf('| **A relations config that shrinks the reach of a live deny**')
    assert.exists(row, 'la fila de la mitad database en Limits')
    for (const phrase of [
      '500 `E_AUTHZ_DENY_REACH_REFUSED`', '«deny con alcance ENCOGIDO»', '«deny HUÉRFANO»', '«deny SIN línea base»', 'all-or-nothing, never filtered',
      "`{ establishBaseline: true }` lifts only «deny SIN línea base»", 'inert otherwise; orphans are still judged', 'in a release that does not change `relations.config`',
      "`{ allowDenyReachShrink: ['note#editor'] }` exempts only the findings it names", '`true` included, is 500 `E_AUTHZ_CONFIG`',
      '**a name that exempts no `shrunk`/orphan finding of that very save is also 500 `E_AUTHZ_CONFIG`**', 'the list switches itself off',
      '**Persisting the config is a mandatory release step if you use deny**', 'save (the guard) → `checkRelationsConfigDenyReach(served)`', 'never a hard failure in `ready`',
      'which needs two relations drivers: it cannot run in a `database`-only deploy', 'same `connection` as the `database` relations driver', 'A withdrawn TYPE is not enumerated by `--dry-run`',
    ]) {
      assert.include(row!, phrase, `la fila no dice «${phrase}»`)
    }
    for (const gone of ['only `allowDenyReachShrink: true` lifts it', 'only orphans are judged', '`authz:relations:reconcile --dry-run` catches it', 'the detector sees it on its next run']) {
      assert.notInclude(row!, gone, `la fila sigue diciendo «${gone}» (letra anterior al panel (8))`)
    }
    assert.notInclude(row!, 'declared limit `', 'la mitad database NO es un límite declarado del manifiesto openfga (es una guarda)')
    const section = readme.slice(readme.indexOf('**Since 2.5.0-alpha.4 a save is also a guard (decision (8)):**'), readme.indexOf('**Migrating tuples between drivers**'))
    for (const phrase of ['**If you use deny, persisting the config is a mandatory release step**', 'save the config the release\nserves (the guard) → `checkRelationsConfigDenyReach(served)`', '→ serve', 'never as a hard failure in `ready`', 'release that does **not** change `relations.config`', '**same `connection`**', 'needs **two** relations drivers']) {
      assert.include(section, phrase, `el párrafo de la config persistida no dice «${phrase}»`)
    }
    // Los tres amarillos declarados: fila con «declared yellow of `database`», receta, detector, cierre 2.6 y SU caso (que existe aquí).
    const here = read('tests/relations_persisted_config.spec.ts')
    for (const [start, label] of [['| **A stale baseline hides a narrowing (S-B)**', 'S-B'], ['| **The rolling-deploy window (S-C)**', 'S-C'], ['| **Forcing a withdrawal, then declaring it again, resurrects grants (S-E)**', 'S-E']] as const) {
      const declared = rowOf(start)
      assert.exists(declared, `la fila de ${label}`)
      for (const phrase of ['declared yellow of `database`', '**Recipe**', '**Detector**', '**Closes in 2.6**', 'Case: «límite declarado database (8) · ' + label]) assert.include(declared!, phrase, `${label}: la fila no dice «${phrase}»`)
      const title = declared!.match(/Case: «([^»]+)»/)![1]
      assert.include(here, `test('${title}'`, `${label}: el caso que nombra la fila no existe`)
    }
    assert.include(rowOf('| **A stale baseline hides a narrowing (S-B)**')!, '«línea base RANCIA»')
    // Cierre 1 · ronda (🟡 2 del auditor): en el orden del caso S-B el paso de CI no la ve; la ve un cron mientras N sirve.
    for (const phrase of ['**In the order of this case, the CI step does not see it**', '**what sees it is a cron that runs while release N serves, after the deny is written**', 'the cron must run more often than a release lives']) {
      assert.include(rowOf('| **A stale baseline hides a narrowing (S-B)**')!, phrase, `S-B: la fila no dice «${phrase}»`)
    }
    // Cierre 1 · ronda (🟡 4 del tester): W NO cierra S-E; solo el alcance grabado en el deny.
    const rowSE = rowOf('| **Forcing a withdrawal, then declaring it again, resurrects grants (S-E)**')!
    assert.include(rowSE, '**Closes in 2.6** only by recording the reach in the deny: checking at deny write (W) does NOT close it')
    assert.notInclude(rowSE, 'checking at deny write (W) or recording the reach in the deny', 'S-E: la fila sigue prometiendo que W la cierra')
    const guardSection = readme.slice(readme.indexOf('**Since 2.5.0-alpha.4 a save is also a guard (decision (8)):**'), readme.indexOf('**Migrating tuples between drivers**'))
    assert.include(guardSection, 'a name that exempts nothing in\nthat save is 500 `E_AUTHZ_CONFIG`', 'el párrafo no dice que un nombre sin hallazgo es 500')
    assert.include(rowOf('| **The rolling-deploy window (S-C)**')!, 'from the save of the narrowed config to the end of the deploy (the last old pod)')
    assert.include(rowOf('| **The rolling-deploy window (S-C)**')!, '`shrunk` is not detected afterwards')
    const changelog = read('CHANGELOG.md')
    const unreleased = changelog.slice(0, changelog.indexOf('## [2.5.0-alpha.3]'))
    const entry = unreleased.slice(unreleased.indexOf('### Sub-lot 7 · decision (8)'))
    assert.isAbove(unreleased.indexOf('### Sub-lot 7 · decision (8)'), 0, 'la entrada del sublote (8) en la sección no sellada')
    for (const phrase of ['*Problem.*', '*Decision*', '*Not done, and why.*', '`E_AUTHZ_DENY_REACH_REFUSED`', '**`no-baseline`**', '**all-or-nothing**', '{ establishBaseline: true }', "{ allowDenyReachShrink: ['note#editor'] }", 'There is no global `true`', '`checkRelationsConfigDenyReach(served, options?)`', '«línea base RANCIA»', '**distinct tuple keys**', '**mandatory\n  release step if you use deny**', '`database.deny-reach.baseline`', '`database.deny-reach.check`', '`openfga.deny-reach.detector`', "plan B", 'a name that exempts no `shrunk`/`orphan` finding of\n  that very save', 'only recording the reach in the deny\n  closes it, W does not', 'with 31 mutants']) {
      assert.include(entry, phrase, `el CHANGELOG no dice «${phrase}»`)
    }
  })
})

test.group('relaciones · config persistida · alpha.4: el bloque «release steps» del README (petición de COGNITIV)', () => {
  const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8')
  test('README reúne en UN bloque los pasos del release con deny (guardar → comprobar → servir, la adopción una vez, la lista con nombre, el chequeo periódico) y el CHANGELOG lo anuncia', ({ assert }) => {
    const readme = read('README.md')
    const start = readme.indexOf('### Upgrading to 2.5.0-alpha.4: the release steps if you use the deny (`database`)')
    assert.isAbove(start, 0, 'falta la sección del bloque de release')
    const block = readme.slice(start, readme.indexOf('\n## ', start))
    const save = block.indexOf('const served = await saveRelationsConfig(spec)')
    const check = block.indexOf('await checkRelationsConfigDenyReach(served)')
    const serve = block.indexOf('// 3 · Serve.')
    assert.isAbove(save, 0, 'el bloque no guarda la config')
    assert.isAbove(check, save, 'el bloque no comprueba DESPUÉS de guardar')
    assert.isAbove(serve, check, 'el bloque no sirve DESPUÉS de comprobar')
    for (const phrase of ['if (!check.ok) throw', '500 E_AUTHZ_DENY_REACH_REFUSED and writes nothing', '{ establishBaseline:\n  true }', 'does **not** change `relations.config`', "{ allowDenyReachShrink: ['note#editor'] }", 'A name that exempts nothing in that save is 500 `E_AUTHZ_CONFIG`', 'on a schedule', 'Never as a hard failure in `ready`', 'it needs two relations drivers', 'same `connection` as the `database` relations driver']) {
      assert.include(block, phrase, `el bloque no dice «${phrase}»`)
    }
    const changelog = read('CHANGELOG.md')
    const unsealed = changelog.slice(0, changelog.indexOf('## [2.5.0-alpha.3]'))
    assert.include(unsealed, '### Docs · the release steps if you use the deny, in one block')
  })
})

/**
 * **Lote RC · sublote (8) · los tres AMARILLOS DECLARADOS de `database`** (firmas (8 · rancia) y (8 · 2.6); juez del panel,
 * «Cierre concreto» 10): casos de CARACTERIZACIÓN que fijan el comportamiento de HOY tal cual —la guarda de
 * `saveRelationsConfig` NO los ve—, cada uno con su fila en Limits del README. Se VOLTEAN (el día que W —comprobar al
 * escribir el deny— o el alcance grabado en el deny entren, 2.6) y entonces cambian con su fila. Sin OpenFGA.
 */
test.group('relaciones · config persistida · sublote (8): límites declarados de database (caracterización)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
    await db.from('authz_relations_config').delete()
    return async () => {
      await db.from('authz_relations').delete()
      await db.from('authz_relations_config').delete()
    }
  })
  const spec = (editor: string[] | null, owner = true) => ({
    objectTypes: [
      {
        type: 'note',
        deny: 'write' as const,
        relations: [...(owner ? [{ name: 'owner' }] : []), ...(editor === null ? [] : [{ name: 'editor', includes: editor }]), { name: 'viewer', includes: editor === null ? ['owner'] : ['editor'] }],
      },
    ],
    holderTypes: ['user'],
  })
  const driverFor = (s: any) => new DatabaseRelationsDriver(defineRelationsConfig(s), { transactionalWrites: false })
  const P = APP_SCOPE as ScopeRef

  test('límite declarado database (8) · S-B línea base RANCIA: la guarda no la ve y la delata checkRelationsConfigDenyReach; se voltea en 2.6', async ({ assert }) => {
    const u = { type: 'user', uuid: uuidv7() }
    const n = { type: 'note', id: uuidv7() }
    // Release N-1 guardó la config ESTRECHA (sin denies todavía). La N sirve la ANCHA sin guardarla y se escribe el deny.
    await saveRelationsConfig(spec([]))
    const wide = driverFor(spec(['owner']))
    await wide.relate(u, 'owner', n, P)
    await wide.deny!(u, 'editor', n, P)
    assert.isFalse(await wide.check(u, 'owner', n, P), 'con la ancha, el deny en editor corta al owner directo')
    // El detector de un driver, con lo que SIRVE la N, lo DELATA (dirección inversa: «línea base RANCIA»).
    const before = await checkRelationsConfigDenyReach(defineRelationsConfig(spec(['owner'])))
    assert.deepEqual(before.staleBaseline.map((f) => [f.relation, f.reason, f.lost]), [['editor', 'stale', ['owner']]], 'el detector delata la fila rancia')
    assert.isFalse(before.ok)
    // La N+1 vuelve a estrechar y guarda (la receta): la fila ya es la estrecha ⇒ «sin cambio» ⇒ GUARDADA (el límite).
    await saveRelationsConfig(spec([]))
    assert.isTrue(await driverFor(spec([])).check(u, 'owner', n, P), 'HOY: el owner vuelve a conceder (S-B, amarillo declarado)')
    // Y después de servir la estrecha, nadie lo ve ya: la comprobación hay que correrla ANTES (CI tras guardar y en un cron).
    assert.isTrue((await checkRelationsConfigDenyReach(defineRelationsConfig(spec([])))).ok, 'tras servir la estrecha, el detector ya no tiene qué ver')
  })

  test('límite declarado database (8) · S-C ventana del despliegue: un deny que escribe un pod viejo tras el guardado no se ve como encogido; se voltea en 2.6', async ({ assert }) => {
    const u = { type: 'user', uuid: uuidv7() }
    const n = { type: 'note', id: uuidv7() }
    // Se guarda la ESTRECHA (sin denies vivos: la guarda no tiene nada que juzgar). Un pod VIEJO aún sirve la ancha.
    await saveRelationsConfig(spec(['owner']))
    await saveRelationsConfig(spec([]))
    const oldPod = driverFor(spec(['owner']))
    await oldPod.relate(u, 'owner', n, P)
    await oldPod.deny!(u, 'editor', n, P)
    assert.isFalse(await oldPod.check(u, 'owner', n, P), 'el pod viejo cree que el deny corta al owner')
    assert.isTrue(await driverFor(spec([])).check(u, 'owner', n, P), 'HOY: con la estrecha, el owner concede (S-C, amarillo declarado)')
    // Ni la guarda (re-guardar la estrecha) ni el detector con lo servido (la estrecha) lo ven: no hay transición que juzgar.
    await saveRelationsConfig(spec([]))
    assert.isTrue((await checkRelationsConfigDenyReach(defineRelationsConfig(spec([])))).ok, 'el encogimiento de un deny escrito en la ventana no se detecta después')
  })

  test('límite declarado database (8) · S-E forzar la retirada y re-declarar resucita los grants que el deny cortaba; se voltea en 2.6', async ({ assert }) => {
    const u = { type: 'user', uuid: uuidv7() }
    const n = { type: 'note', id: uuidv7() }
    await saveRelationsConfig(spec(['owner']))
    const wide = driverFor(spec(['owner']))
    await wide.relate(u, 'owner', n, P)
    await wide.deny!(u, 'editor', n, P)
    assert.isFalse(await wide.check(u, 'owner', n, P))
    // Retirar `owner` encoge el deny de `editor`: se fuerza CON SU NOMBRE (la salida acotada).
    await saveRelationsConfig({ objectTypes: [{ type: 'note', deny: 'write' as const, relations: [{ name: 'editor' }, { name: 'viewer', includes: ['editor'] }] }], holderTypes: ['user'] }, { allowDenyReachShrink: ['note#editor'] })
    // Re-declarar `owner` SIN que `editor` lo incluya: frente a la fila (editor ⊇ ∅) nada encoge ⇒ GUARDADA (el límite). Con
    // la lista del forzado PEGADA es 500 E_AUTHZ_CONFIG (el nombre no exime nada ahí: cierre 1 · ronda); sin ella, entra.
    const stuck: any = await saveRelationsConfig(spec([]), { allowDenyReachShrink: ['note#editor'] }).then(() => null, (e) => e)
    assert.equal(stuck?.code, 'E_AUTHZ_CONFIG', 'la lista pegada en la re-declaración no es 500 E_AUTHZ_CONFIG')
    await saveRelationsConfig(spec([]))
    assert.isTrue(await driverFor(spec([])).check(u, 'owner', n, P), 'HOY: el grant de owner que el deny cortaba vuelve a conceder (S-E, amarillo declarado)')
  })
})
