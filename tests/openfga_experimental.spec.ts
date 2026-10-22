/**
 * **`openfga` es EXPERIMENTAL en 2.5.x** (estrategia 2.5.0, «(b) con candado»; firmas 1, 2 y 4 del dueño 2026-10-21;
 * requisitos E1–E7 de `panel-estrategia-tester.md`). Lo que fija este spec —el resto vive donde está su punto de paso—:
 *
 *  - **E1/E1′ por las rutas del paquete**: `manager.driver()` (roles) y `buildRelationsManager` (relaciones, lo que sirve
 *    el provider y usa `authz:relations:reconcile`) sobre una factory `openfga` SIN la marca ⇒ el 500 del opt-in. La
 *    puerta misma —todo valor que no es el token, primera línea, cero peticiones, por reflexión sobre `./openfga`— es la
 *    propiedad `openfga.experimental.gate` de `guard_surface.spec.ts`, con sus nueve mutantes en el corredor.
 *  - **E3**: un config solo-`database` que REGISTRA la factory `openfga` (sin la marca) arranca y `authorize`/`check`
 *    responden; la factory `openfga` no se llama nunca (la puerta va en la construcción y las factories son perezosas).
 *  - **E5 (letra)**: el README lo dice en la presentación del driver, en «OpenFGA tooling», en la tabla de capacidades y
 *    en «Upgrading to 2.5.0-alpha.4»; cada límite declarado del manifiesto `tests/fixtures/openfga_declared_limits.json`
 *    tiene su fila en «Limits» con su cifra, su receta, su detector y «closes in 2.6»; el CHANGELOG lo cuenta; CLAUDE.md
 *    lleva los textos firmados (1) y (2).
 *  - **E7 (meta)**: ids del manifiesto == casos «límite declarado <id>: se voltea en 2.6» (uno por id, en el fichero que
 *    declara) == filas «declared limit `<id>`» de Limits; los ids SIN caso son una lista cerrada que espera al dueño.
 */
import { test } from '@japa/runner'
import { readFileSync, readdirSync } from 'node:fs'
import { v7 as uuidv7 } from 'uuid'
import { AuthorizationManager } from '../src/manager.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { OpenFgaAuthorizationDriver, OpenFgaRelationsDriver } from '../src/openfga.js'
import { buildRelationsManager } from '../providers/authz_provider.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { contractRelationsConfig } from '../src/testing/relations_contract.js'
import { APP_SCOPE } from '../src/types.js'
import { TEST_MODEL_ID } from './helpers/fga_model.js'
import { cleanAuthzTables } from './helpers/schema.js'

const ROOT = new URL('../', import.meta.url)
const read = (path: string) => readFileSync(new URL(path, ROOT), 'utf8')
const STORE = '01ARZ3NDEKTSV4RRFFQ69G5FAV'

interface DeclaredLimit {
  id: string
  severity: string
  title: string
  figure: string
  where: string
  effect: string
  recipe: string
  detector: string
  closure: string
  origin: string
  case?: null
  noCase?: string
  caseFile?: string
}
const MANIFEST: { closesIn: string; caseTitle: string; limits: DeclaredLimit[] } = JSON.parse(read('tests/fixtures/openfga_declared_limits.json'))
const caseTitle = (id: string) => MANIFEST.caseTitle.replace('<id>', id)
/**
 * Los ids declarados SIN caso de caracterización. Lista CERRADA y hoy VACÍA: la firma (candado · preguntas) 1 del dueño
 * (2026-10-21) dio caso a `openfga.tree.outbox` (apunta al control existente) y no firmó ninguna excepción a «cada una con
 * su caso». Un id sin caso es rojo hasta que el dueño lo firme aquí.
 */
const NO_CASE_PENDING_OWNER: string[] = []
/**
 * Los ids declarados cuyo detector es «none» (sin detector automático). Lista CERRADA y hoy VACÍA (backlog del candado ⚪ 4):
 * el único que lo tenía, `openfga.provision.deny-reach`, tiene detector desde el sublote (8)
 * (`authz:relations:reconcile --dry-run`). Un detector «none» nuevo es rojo hasta que el dueño lo firme aquí.
 */
const NO_DETECTOR_SIGNED: string[] = []

/** El 500 del opt-in (la letra entera la fija la propiedad de la guardia). */
async function rejectsWithOptIn(assert: any, run: () => Promise<unknown>, driver: string, label: string) {
  let caught: any = null
  try {
    await run()
  } catch (error) {
    caught = error
  }
  assert.isNotNull(caught, `${label}: se resolvió un driver openfga sin el opt-in`)
  assert.equal(caught?.status, 500, `${label}: ${caught?.message}`)
  assert.equal(caught?.code, 'E_AUTHZ_CONFIG', `${label}: ${caught?.message}`)
  assert.include(caught.message, `${driver}: el driver openfga es EXPERIMENTAL en 2.5.x`, label)
}

test.group('estrategia 2.5.0 · firma 4 · E1/E3 — la puerta por las rutas del paquete, y un config solo-database que la registra', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({ permissions: [{ slug: 'docs:read' }], roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }] })
  })

  test("E3 (roles) · `default: 'database'` con la factory `openfga` registrada SIN la marca: arranca, grant/authorize responden y la factory openfga no se llama; con `default: 'openfga'`, `driver()`/`authorize` son el 500 del opt-in", async ({ assert }) => {
    let openfgaBuilt = 0
    const drivers = {
      database: () => new DatabaseAuthorizationDriver({}),
      openfga: () => {
        openfgaBuilt++
        // El stub publicado: todo lo demás bien, la marca comentada.
        return new OpenFgaAuthorizationDriver({ apiUrl: 'http://127.0.0.1:9', storeId: STORE, modelId: TEST_MODEL_ID, holderTypes: { users: 'user' }, acceptScopeDriftRisk: true })
      },
    }
    const config = { drivers, holderTypes: { users: 'user' }, scopes: { acceptScopeDriftRisk: true }, warnOnOptInSecurity: false }
    const alice = { type: 'users', uuid: uuidv7() }
    const database = new AuthorizationManager({ ...config, default: 'database' } as any)
    await database.grant(alice, 'editor', APP_SCOPE)
    assert.isTrue(await database.authorize(alice, 'docs:read', APP_SCOPE), 'el despliegue database funciona con la factory openfga registrada')
    assert.equal(openfgaBuilt, 0, 'registrar no construye: la factory openfga no se llamó')

    const openfga = new AuthorizationManager({ ...config, default: 'openfga' } as any)
    await rejectsWithOptIn(assert, () => openfga.driver(), 'OpenFgaAuthorizationDriver', "default: 'openfga' · driver()")
    await rejectsWithOptIn(assert, () => openfga.authorize(alice, 'docs:read', APP_SCOPE), 'OpenFgaAuthorizationDriver', "default: 'openfga' · authorize")
    await rejectsWithOptIn(assert, () => openfga.capabilities(), 'OpenFgaAuthorizationDriver', "default: 'openfga' · capabilities()")
  })

  test("E3 (relaciones) · `relations.default: 'database'` con la factory `openfga` registrada SIN la marca: el servicio se construye y `check` responde; con `'openfga'`, el 500 del opt-in al construir el servicio (lo que hace el provider y authz:relations:reconcile)", async ({ assert }) => {
    const config = contractRelationsConfig()
    let openfgaBuilt = 0
    const relations = (active: string) => ({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver({}) },
      holderTypes: { user: 'user' },
      warnOnOptInSecurity: false,
      relations: {
        config,
        default: active,
        drivers: {
          database: () => new DatabaseRelationsDriver(config, { transactionalWrites: false }),
          openfga: () => {
            openfgaBuilt++
            return new OpenFgaRelationsDriver(config, { apiUrl: 'http://127.0.0.1:9', storeId: STORE, modelId: TEST_MODEL_ID, holderTypes: { user: 'user' } })
          },
        },
      },
    })
    const service = await buildRelationsManager(relations('database') as any)
    const doc = { type: 'document', id: uuidv7() }
    assert.isFalse(await service.check({ type: 'user', uuid: uuidv7() }, 'viewer', doc, APP_SCOPE), 'el servicio database responde')
    assert.equal(openfgaBuilt, 0, 'la factory openfga de relaciones no se llamó')
    await rejectsWithOptIn(assert, () => buildRelationsManager(relations('openfga') as any), 'OpenFgaRelationsDriver', "relations.default: 'openfga'")
  })
})

/** La sección «Limits» del README, y sus filas. */
function limitsRows(): string[] {
  const readme = read('README.md')
  const limits = readme.slice(readme.indexOf('### Limits'), readme.indexOf('### Operational notes for the SQL engines'))
  return limits.split('\n').filter((line) => line.startsWith('| '))
}

test.group('estrategia 2.5.0 · firmas 1, 2 y 4 · E5/E7 — la letra de «experimental» y los límites declarados', () => {
  test('E5 · README: la presentación, «OpenFGA tooling», la tabla de capacidades y «Upgrading to 2.5.0-alpha.4» dicen experimental en 2.5.x, no apto para producción, la marca, el 500 y el cierre en 2.6; el subpath no cambia', ({ assert }) => {
    const readme = read('README.md')
    const intro = readme.slice(0, readme.indexOf('## Install'))
    for (const phrase of ['Experimental in 2.5.x — not production-ready, and outside the semver guarantee', "experimental: 'openfga@2.5'", '500 `E_AUTHZ_CONFIG`', '**2.6**', 'In production, use `database`']) {
      assert.include(intro, phrase, `la presentación del driver openfga no dice «${phrase}»`)
    }
    const tooling = readme.slice(readme.indexOf('## OpenFGA tooling'), readme.indexOf('### Migrating and verifying'))
    assert.match(tooling, /^## OpenFGA tooling\n\n> \*\*Experimental in 2\.5\.x — not production-ready, outside the semver guarantee, closes in 2\.6\.\*\*/, 'la sección de OpenFGA EMPIEZA con el aviso')
    for (const phrase of ["**`experimental: 'openfga@2.5'`**", '**500 `E_AUTHZ_CONFIG`**', 'no client is created', '`manager.driver()`', '`authz:reconcile --to=openfga`', '`openfga:provision`', '`authz:relations:reconcile`', 'registers', '`capabilities.experimental: true`', 'declared limit', 'The subpath\n> keeps its name']) {
      assert.include(tooling, phrase, `«OpenFGA tooling» no dice «${phrase}»`)
    }
    assert.match(readme, /^\| `experimental` \(2\.5\.0-alpha\.4; optional, normalised to `false`\) \| `false` \| \*\*`true`\*\* in 2\.5\.x \|/m, 'la fila de la capacidad en la tabla')
    const upgrading = readme.slice(readme.indexOf("### Upgrading to 2.5.0-alpha.4: `openfga` is experimental — opt in with `experimental: 'openfga@2.5'`"))
    assert.isAbove(readme.indexOf("### Upgrading to 2.5.0-alpha.4: `openfga` is experimental"), 0, 'la sección de la ruptura')
    for (const phrase of ['**Breaking for every `openfga` user, by design.**', '**500 `E_AUTHZ_CONFIG`**', '**Not production-ready in 2.5.x.**', 'They close in **2.6**', '`// experimental: \'openfga@2.5\',`', 'fails closed', '.experimental', 'The subpath keeps its name']) {
      assert.include(upgrading.slice(0, 3000), phrase, `«Upgrading» no dice «${phrase}»`)
    }
    // Ningún ejemplo del README construye un driver openfga sin NOMBRAR la marca; el quick-start la deja COMENTADA (como el
    // stub: quien copia el ejemplo no opta sin escribirla él — 🟡 4 del auditor del candado) y «Upgrading» la muestra viva.
    const constructs = readme.split('\n').filter((line) => /new OpenFga(Authorization|Relations)Driver\(\{/.test(line))
    assert.deepEqual(constructs.filter((line) => !line.includes("experimental: 'openfga@2.5'")), [], 'un ejemplo construye openfga sin nombrar la marca')
    const quickStart = readme.slice(readme.indexOf('## Your domain stays yours'), readme.indexOf('### The scope tree'))
    const quick = quickStart.split('\n').filter((line) => /new OpenFgaAuthorizationDriver\(\{/.test(line))
    assert.lengthOf(quick, 1, 'el quick-start construye openfga una vez')
    assert.include(quick[0], "/* experimental: 'openfga@2.5', */", 'el quick-start trae la marca COMENTADA')
    assert.match(upgrading.slice(0, 3000), /new OpenFgaAuthorizationDriver\(\{ experimental: 'openfga@2\.5',/, '«Upgrading» la trae viva')
    // Firma 2 (candado · preguntas): «outside the semver guarantee» ACOTADA — solo el token y el comportamiento experimental.
    for (const where of [intro, tooling]) {
      assert.match(where.replace(/\n> /g, ' '), /the opt-in token and the drivers' behaviour — may change in 2\.6, a minor(?: release)?, without a major/, 'la frase de semver dice qué queda fuera y nada más')
    }
    assert.include(tooling.replace(/\n> /g, ' '), 'the subpath, its exports and the rest of the package keep semver')
    // ⚪ 7: migrar FUERA de openfga también pasa por la puerta (el origen se construye), dicho sin circularidad.
    assert.include(upgrading.slice(0, 4000), '**Migrating off `openfga` needs the token too.**')
  })

  test('E5 · Limits: cada límite declarado del manifiesto tiene SU fila con id, cifra, dónde, receta, detector y «closes in 2.6»; la fila PROVISIONAL ya no existe y el lector rasgado no se duplica', ({ assert }) => {
    const rows = limitsRows()
    for (const limit of MANIFEST.limits) {
      const row = rows.filter((line) => line.includes(`declared limit \`${limit.id}\``))
      assert.lengthOf(row, 1, `una fila (y solo una) para ${limit.id}`)
      for (const [field, phrase] of [['title', limit.title], ['figure', limit.figure], ['where', limit.where], ['recipe', limit.recipe], ['detector', limit.detector], ['closure', limit.closure]] as const) {
        assert.include(row[0], phrase, `${limit.id}: la fila no lleva su ${field} tal como lo declara el manifiesto`)
      }
      assert.include(row[0], 'closes in 2.6', limit.id)
      assert.include(row[0], 'experimental `openfga`', limit.id)
      assert.include(row[0], limit.case === null ? 'No characterisation case' : `Case: «${caseTitle(limit.id)}»`, limit.id)
    }
    assert.isFalse(rows.some((line) => line.includes('PROVISIONAL')), 'ninguna fila provisional')
    assert.lengthOf(rows.filter((line) => line.startsWith('| **Torn read**')), 1, 'el lector rasgado sigue con SU fila, una')
    assert.isFalse(rows.some((line) => line.startsWith('| **Torn read**') && line.includes('declared limit `')), 'y no se duplica como límite del manifiesto')
  })

  test('E7 · meta: ids del manifiesto (únicos, con severidad 🟠/🟡, cierre 2.6) == casos «límite declarado <id>: se voltea en 2.6» (uno por id, en su fichero) == filas «declared limit» de Limits; los sin caso son la lista cerrada que espera al dueño', ({ assert }) => {
    const ids = MANIFEST.limits.map((l) => l.id)
    assert.equal(new Set(ids).size, ids.length, 'ids únicos')
    assert.equal(MANIFEST.closesIn, '2.6')
    for (const limit of MANIFEST.limits) {
      assert.include(['🟠', '🟡'], limit.severity, `${limit.id}: solo se declaran 🟠/🟡 (un 🔴 de openfga sigue bloqueando la RC, firma 5)`)
      assert.match(limit.id, /^openfga\.[a-z]+\.[a-z-]+$/, limit.id)
      for (const field of ['title', 'figure', 'where', 'effect', 'recipe', 'detector', 'closure', 'origin'] as const) {
        assert.isAbove(String(limit[field] ?? '').trim().length, 0, `${limit.id}: ${field} vacío`)
      }
    }
    // Los casos: se buscan en el TEXTO de los specs (cualquier fichero), con el título canónico.
    const titleRe = /'límite declarado ([a-z0-9.-]+): se voltea en 2\.6'/g
    const found = new Map<string, string[]>()
    for (const file of readdirSync(new URL('tests/', ROOT))) {
      if (!file.endsWith('.spec.ts')) continue
      for (const match of read(`tests/${file}`).matchAll(titleRe)) found.set(match[1], [...(found.get(match[1]) ?? []), `tests/${file}`])
    }
    const withCase = MANIFEST.limits.filter((l) => l.case !== null)
    const withoutCase = MANIFEST.limits.filter((l) => l.case === null)
    assert.sameMembers([...found.keys()], withCase.map((l) => l.id), 'casos == ids con caso (ni uno de más, ni uno de menos)')
    for (const limit of withCase) {
      assert.deepEqual(found.get(limit.id), [limit.caseFile], `${limit.id}: un solo caso, en ${limit.caseFile}`)
    }
    assert.sameMembers(withoutCase.map((l) => l.id), NO_CASE_PENDING_OWNER, 'un id sin caso es una decisión del dueño, no un olvido')
    // ⚪ 4 del candado (sublote (8)): «cada una con su detector» — un detector «none» es la lista cerrada firmada (hoy vacía).
    assert.sameMembers(
      MANIFEST.limits.filter((l) => /^\s*none\b/i.test(l.detector)).map((l) => l.id),
      NO_DETECTOR_SIGNED,
      'un límite sin detector automático es una decisión del dueño, no un olvido'
    )
    for (const limit of withoutCase) assert.isAbove(String(limit.noCase ?? '').length, 40, `${limit.id}: sin caso, con su porqué`)
    // Las filas: «declared limit `<id>`» en Limits == ids.
    const rowIds = limitsRows().flatMap((line) => [...line.matchAll(/declared limit `([a-z0-9.-]+)`/g)].map((m) => m[1]))
    assert.sameMembers(rowIds, ids, 'filas de Limits == ids del manifiesto')
  })

  /**
   * **Límite declarado `openfga.provision.deny-reach`** (decisión (8) del dueño; firma (candado · preguntas) 5: la mitad
   * `openfga` se declara ya). Sin servidor: el modelo GENERADO y el intérprete. `editor: { includes: ['owner'] }`, deny de
   * escritura y un `denied_editor` vivo sobre un owner DIRECTO ⇒ `owner` deniega (el corte D5 sube por `includes`). La
   * config estrecha `editor` a `includes: []`: la guarda de `provision` (`droppedDenyRelations`) no ve nada que negar —
   * ningún `denied_*` desaparece— y con el modelo nuevo las MISMAS tuplas conceden `owner`. Se voltea cuando la guarda de
   * (8) mire el ALCANCE («alcance nuevo ⊇ alcance viejo») y no la presencia.
   */
  test('límite declarado openfga.provision.deny-reach: se voltea en 2.6', async ({ assert }) => {
    const { defineRelationsConfig } = await import('../src/relations/define_relations_config.js')
    const { openFgaFactsModel } = await import('../src/drivers/openfga_facts.js')
    const { compileModel, checkTuples, TupleStore } = await import('./helpers/fga_interpreter.js')
    const { droppedDenyRelations } = await import('../commands/openfga_provision.js')
    const { denyReachFindings } = await import('../src/relations/deny_reach.js')
    const relationsConfig = (editorIncludes: string[]) =>
      defineRelationsConfig({
        objectTypes: [{ type: 'note', relations: [{ name: 'owner' }, { name: 'editor', includes: editorIncludes }, { name: 'viewer', includes: ['editor'] }], deny: 'write' }],
        holderTypes: ['user'],
      })
    const model = (editorIncludes: string[]) =>
      openFgaFactsModel({ users: 'user' }, ['docs:read'], { objectTypes: relationsConfig(editorIncludes).objectTypes })
    const before = model(['owner'])
    const narrowed = model([])
    const tuples = [
      { user: 'user:u', relation: 'owner', object: 'note:n' },
      { user: 'user:u', relation: 'denied_editor', object: 'note:n' },
    ]
    const owner = (m: any) => checkTuples(compileModel(m), new TupleStore(tuples as any), { user: 'user:u', relation: 'owner', object: 'note:n', context: { current_time: new Date(0).toISOString() } }).verdict
    assert.equal(owner(before), 'F', 'antes: el deny en editor corta al owner directo')
    assert.deepEqual(droppedDenyRelations(before, narrowed), [], 'la guarda de provision no ve nada que negar: ningún denied_* desaparece')
    assert.equal(owner(narrowed), 'T', 'con el modelo estrechado las MISMAS tuplas conceden owner: el deny vivo dejó de cortar')
    // Sublote (8) · backlog ⚪ 2/⚪ 4 y firma (8 · openfga): el DETECTOR de `authz:relations:reconcile --dry-run` SÍ lo ve —la
    // guarda de provision no—, y aquí se le pasa por el camino real: el `OpenFgaRelationsDriver` como DESTINO, con un
    // cliente falso que sirve esas mismas tuplas (sin servidor), enumera `denied_editor` como `{ relation: 'editor', kind:
    // 'deny' }` y `reconcileRelations({ dryRun, denyReach })` lo juzga. Con su PRECONDICIÓN: solo con la línea base
    // persistida (`baseline`, la config guardada en cada provision); sin ella, el estrechamiento no se ve (solo «sin
    // juzgar»). El límite sigue declarado hasta 2.6.
    const { reconcileRelations } = await import('../src/relations/reconcile.js')
    const { makeRelationsDriver } = await import('../src/testing/relations_contract.js')
    const { OPENFGA_OPT_IN } = await import('./helpers/openfga_opt_in.js')
    const partition = { type: 'unit', uuid: uuidv7() } as any
    const n = uuidv7()
    const u = uuidv7()
    const detect = async (baseline: any) => {
      const to = new OpenFgaRelationsDriver(relationsConfig(['owner']), {
        ...OPENFGA_OPT_IN,
        apiUrl: 'http://127.0.0.1:9',
        storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
        modelId: '01ARZ3NDEKTSV4RRFFQ69G5FAW',
        holderTypes: { users: 'user' },
        timeoutMs: 1000,
        listObjectsDeadlineMs: 1000,
        logger: { warn: () => {} },
      })
      const written: string[] = []
      const served = { authorization_model: openFgaFactsModel({ users: 'user' }, [], { objectTypes: relationsConfig(['owner']).objectTypes }) }
      const store = [
        { key: { user: `user:${u}`, relation: 'owner', object: `note:unit|${partition.uuid}|${n}` } },
        { key: { user: `user:${u}`, relation: 'denied_editor', object: `note:unit|${partition.uuid}|${n}` } },
      ]
      ;(to as any).client = new Proxy(
        {},
        {
          get: (_target, method) => async () => {
            if (['write', 'writeTuples', 'deleteTuples'].includes(String(method))) written.push(String(method))
            if (method === 'readAuthorizationModel' || method === 'readLatestAuthorizationModel') return served
            if (method === 'read') return { tuples: store, continuation_token: '' }
            return {}
          },
        }
      )
      const report = await reconcileRelations({
        from: makeRelationsDriver({
          config: relationsConfig(['owner']),
          capabilities: {
            singleCheckRelations: true, listObjectsInherited: false, usersetSubjects: true, membersOfNative: true, enumerateRelations: true,
            listObjectsTruncation: false, injectableClock: true, transactionalWrites: false, relationDenies: true, atomicRenewal: false, experimental: false,
          },
        }),
        to,
        partition,
        dryRun: true,
        toConfig: relationsConfig(['owner']),
        denyReach: { baseline, current: relationsConfig([]) },
      })
      assert.deepEqual(written, [], 'el detector no escribe en el store')
      return report.denyReach!
    }
    const detected = await detect(relationsConfig(['owner']))
    assert.deepEqual(
      detected.findings.map((f) => [f.objectType, f.relation, f.reason, f.lost, f.sides]),
      [['note', 'editor', 'shrunk', ['owner'], ['destino']]],
      'el detector de (8), por el driver openfga real, lista el deny encogido con lo que deja de cortar'
    )
    const withoutBaseline = await detect(null)
    assert.deepEqual([withoutBaseline.findings, withoutBaseline.unjudged], [[], 1], 'la precondición: sin línea base persistida el estrechamiento NO se ve (solo «sin juzgar»)')
    assert.equal(owner(model(['owner'])), 'F', 'control: sin estrechar, sigue negando')
  })

  test('E5 · CHANGELOG: el sub-lote 6 cuenta la ruptura (problema → decisión → qué no se hace), la capacidad y los límites declarados', ({ assert }) => {
    const changelog = read('CHANGELOG.md')
    const unreleased = changelog.slice(0, changelog.indexOf('## [2.5.0-alpha.3]'))
    const section = unreleased.slice(unreleased.indexOf('### Sub-lot 6 · `openfga` is EXPERIMENTAL in 2.5.x'))
    assert.isAbove(unreleased.indexOf('### Sub-lot 6 · `openfga` is EXPERIMENTAL in 2.5.x'), 0)
    for (const phrase of ["**🔴 BREAKING (`openfga`) — both `openfga` drivers refuse to be built without `experimental: 'openfga@2.5'`.**", '*Problem*', '*Decision*', '*Not done*', '`assertExperimentalOptIn`', 'FIRST line', '**`experimental`**', 'rule D15', '`openfga.experimental.gate`', 'commented out', 'the subpath is not\nrenamed', 'tests/fixtures/openfga_declared_limits.json', 'límite declarado <id>: se voltea en 2.6', 'PROVISIONAL']) {
      assert.include(section, phrase, `el CHANGELOG no dice «${phrase}»`)
    }
  })

  test('firmas 1 y 2 · CLAUDE.md: el punto 10 con el criterio nuevo, la cabecera de invariantes con la excepción EXPERIMENTAL y la nota en los invariantes 2 y 18', ({ assert }) => {
    const claude = read('CLAUDE.md').replace(/\s+/g, ' ')
    // Lote RC · B2/B3 (firma del dueño, `35f1b50`) intercaló «juzgado por el gate solo-database…» entre las dos mitades del
    // texto de la firma 1; se fijan las dos mitades y el inciso (sublote (8): el caso seguía con la letra anterior y era rojo).
    assert.include(claude, 'rotación de auditoría de sistema sobre la RC con 0 🔴 en todo el paquete y 0 🟠 en `database` y en el código compartido (manager, relay/outbox, reconcile, catálogo, relaciones compartidas), juzgado por el **gate solo-database** de la RC')
    assert.include(claude, '; en los drivers marcados experimental, cada 🟠/🟡 está declarado en Limits con cifra (o "sin medir"), receta, detector y un caso de caracterización, y la versión de cierre')
    assert.notInclude(claude, 'con 0 🔴/🟠 abiertos')
    assert.include(claude, 'Todo driver debe cumplirlos, salvo un driver marcado EXPERIMENTAL (`openfga` en 2.5.x), donde valen salvo las excepciones declaradas en Limits, cada una con su caso. La suite sigue corriendo contra los dos')
    const inv2 = claude.slice(claude.indexOf('2. **Deny explícito gana.**'), claude.indexOf('3. **Expiración observable sin scheduler.**'))
    const inv18 = claude.slice(claude.indexOf('18. **Un rol local solo existe dentro de su owner**'), claude.indexOf('16. **`authorizedScopes` es coherente'))
    const note = '**2.5.x:** en `openfga` (experimental) las carreras declaradas en Limits son excepción a este invariante; se cierran en 2.6.'
    assert.include(inv2, note)
    assert.include(inv18, note)
  })
})
