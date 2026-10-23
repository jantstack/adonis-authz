/**
 * **Juez · clave D15 OMITIDA ⇒ la declaración del driver** (ensayo rc.1 de COGNITIV, día 1, hallazgo 1; firma del dueño
 * 2026-10-23, punto 1).
 *
 * COGNITIV registra NUESTRO `database` en `runAuthorizationDriverContract` (`level: '2.2'`) con un objeto de capacidades
 * escrito en alpha.4, sin `snapshotDecisions`. Hasta este cambio la clave omitida se normalizaba a `false`, la cara
 * `false` exige que el driver NO declare `true`, y `database` la declara ⇒ rojo: un harness verde en alpha.4 pasaba a rojo
 * sin aviso (lo que la regla D15 prohíbe). La regla nueva, en los DOS jueces: una clave OPCIONAL que el harness omite se
 * juzga con la declaración NORMALIZADA del driver; si el harness la declara, manda el harness (y contradecir al driver
 * sigue siendo rojo).
 *
 * Japa no deja registrar grupos desde un test en marcha: el juez se registra contra una API que guarda los casos, los
 * `setup` y los `teardown`, y `run(prefijo)` ejecuta, con un estado fresco cada uno, los casos cuyo título empieza por
 * `<clave>:` (las caras de antes y el caso de la declaración del driver de ahora empiezan así).
 */
import { test } from '@japa/runner'
import db from '@adonisjs/lucid/services/db'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { resolveChainFrom } from '../src/testing/main.js'
import type { DriverCapabilities } from '../src/testing/main.js'
import { registerAuthorizationDriverContract } from '../src/testing/contract.js'
import { makeRelationsDriver, registerRelationsDriverContract } from '../src/testing/relations_contract.js'
import type { RelationsDriver, RelationsDriverCapabilities } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'

type Case = { title: string; fn: (ctx: { assert: any }) => Promise<void> }
type Outcome = { title: string; error?: Error }

/** Una API de Japa que GUARDA: casos, `setup` por caso y `teardown` del grupo. */
function capturingApi() {
  const cases: Case[] = []
  const setups: Array<() => unknown> = []
  const teardowns: Array<() => unknown> = []
  const api = {
    group: (_title: string, define: any) =>
      define({ each: { setup: (fn: () => unknown) => void setups.push(fn) }, teardown: (fn: () => unknown) => void teardowns.push(fn) }),
    test: (title: string, fn: any) => {
      cases.push({ title, fn })
      return { timeout: () => {} }
    },
  }
  /** Corre los casos cuyo título empieza por `prefix`, cada uno tras los `setup`, con el `assert` del caso que llama. */
  async function run(prefix: string, assert: any): Promise<Outcome[]> {
    const found = cases.filter((c) => c.title.startsWith(prefix))
    assert.isAbove(found.length, 0, `el juez registró algún caso que empieza por «${prefix}» (registrados: ${cases.length})`)
    const outcomes: Outcome[] = []
    for (const c of found) {
      for (const setup of setups) await setup()
      try {
        await c.fn({ assert })
        outcomes.push({ title: c.title })
      } catch (error) {
        outcomes.push({ title: c.title, error: error as Error })
      }
    }
    return outcomes
  }
  async function teardown() {
    for (const fn of teardowns) await fn()
  }
  return { api, cases, run, teardown }
}

const red = (outcomes: Outcome[]) => outcomes.filter((o) => o.error).map((o) => `${o.title}\n  → ${o.error!.message}`)

/* ── Roles ───────────────────────────────────────────────────────────────── */

/**
 * Las capacidades del harness de COGNITIV para NUESTRO `database`, tal como se escribían en alpha.4: sin las claves D15
 * (`experimental`, `snapshotDecisions`). `:memory:` ⇒ `transactionalWrites: false` y `serializedCatalogWrites: false`,
 * como el harness del paquete.
 */
const ALPHA4_DATABASE: DriverCapabilities = {
  hierarchyFacts: false,
  transactionalWrites: false,
  truncationSignal: false,
  singleCheckAuthorize: false,
  injectableClock: true,
  exhaustiveLists: true,
  listDenies: true,
  purgeRole: true,
  countRoleAssignments: true,
  serializedCatalogWrites: false,
  canonicalScopeReads: true,
  roleInheritanceNative: false,
  listObjectsInherited: false,
  enumerateFacts: false,
}

function rolesJudge(capabilities: DriverCapabilities, makeDriver: (tree: any) => unknown) {
  const captured = capturingApi()
  registerAuthorizationDriverContract(
    {
      name: 'database (harness alpha.4)',
      level: '2.2',
      capabilities,
      makeDriver: makeDriver as any,
      seedCatalog: (catalog) => syncAuthzCatalog(catalog),
      cleanup: cleanAuthzTables,
    },
    captured.api as any
  )
  return captured
}

/** `database` con `readSnapshot` contado (y, si se pide, otra declaración): la cara `true` lo llama; la `false`, nunca. */
function countedDatabase(
  counter: { readSnapshot: number; drivers?: number; granted?: string[] },
  declare: Record<string, unknown> = {},
  hide: string[] = []
) {
  return (tree: any) => {
    counter.drivers = (counter.drivers ?? 0) + 1
    const base = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree), transactionalWrites: false })
    const view = Object.create(base)
    Object.defineProperty(view, 'grant', {
      value: function (this: any, ...args: any[]) {
        ;(counter.granted ??= []).push(String(args[1]))
        return (base as any).grant.apply(this, args)
      },
      enumerable: false,
      configurable: true,
    })
    Object.defineProperty(view, 'readSnapshot', {
      value: async function (this: any, ...args: any[]) {
        counter.readSnapshot++
        return (base as any).readSnapshot.apply(this, args)
      },
      enumerable: false,
      configurable: true,
    })
    for (const name of hide) Object.defineProperty(view, name, { value: undefined, enumerable: false, configurable: true })
    Object.defineProperty(view, 'capabilities', { value: Object.freeze({ ...base.capabilities, ...declare }), enumerable: false })
    return view
  }
}

test.group('juez D15 · clave omitida ⇒ la declaración del driver (roles)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    return cleanAuthzTables
  })

  test('C1 · el harness «alpha.4» de NUESTRO database (2.2, sin snapshotDecisions) pasa el juez de la clave y se le juzga la cara TRUE (la que el driver declara)', async ({
    assert,
  }) => {
    const counter: { readSnapshot: number; drivers?: number; granted?: string[] } = { readSnapshot: 0 }
    const judge = rolesJudge(ALPHA4_DATABASE, countedDatabase(counter))
    const outcomes = await judge.run('snapshotDecisions:', assert)
    assert.deepEqual(red(outcomes), [], 'el harness alpha.4 tiene que seguir verde')
    assert.isAbove(counter.readSnapshot, 0, 'la cara juzgada es la TRUE: el juez y el manager leyeron por readSnapshot')
    // La cara true ENTERA (sus dos casos), cada uno sobre un estado fresco: el `org-admin` solo lo concede la parte de
    // delegación del SEGUNDO caso, y hay un driver por caso interno (el setup + uno más entre los dos).
    assert.include(counter.granted ?? [], 'org-admin', 'el segundo caso de la cara true corrió (delegación incluida)')
    assert.equal(counter.drivers, 2, 'un estado fresco por caso interno')
  }).timeout(60_000)

  test('C2 · experimental omitido en el harness y declarado TRUE por el driver ⇒ se juzga la cara true (la copia publicada dice true) y pasa', async ({
    assert,
  }) => {
    const counter = { readSnapshot: 0 }
    const judge = rolesJudge({ ...ALPHA4_DATABASE, snapshotDecisions: true }, countedDatabase(counter, { experimental: true }))
    const outcomes = await judge.run('experimental:', assert)
    assert.deepEqual(red(outcomes), [])
  }).timeout(60_000)

  test('C3 · el harness que declara EXPLÍCITO snapshotDecisions: false contra un driver que declara true sigue ROJO, con el mensaje de siempre (manda el harness; nada se relaja)', async ({
    assert,
  }) => {
    const counter = { readSnapshot: 0 }
    const judge = rolesJudge({ ...ALPHA4_DATABASE, snapshotDecisions: false }, countedDatabase(counter))
    const outcomes = await judge.run('snapshotDecisions:', assert)
    const failures = red(outcomes)
    assert.lengthOf(failures, outcomes.length, 'todas las caras false registradas salen rojas')
    for (const failure of failures) assert.include(failure, 'el harness declara snapshotDecisions: false y el driver declara true')
  }).timeout(60_000)

  test('C4 · un tercero sin la clave NI el método (sin readSnapshot, capabilities sin snapshotDecisions) sigue en la cara FALSE y pasa', async ({
    assert,
  }) => {
    const counter = { readSnapshot: 0 }
    const { snapshotDecisions: _omit, ...withoutKey } = new DatabaseAuthorizationDriver().capabilities as any
    const judge = rolesJudge(ALPHA4_DATABASE, (tree: any) => {
      const base = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree), transactionalWrites: false })
      const view = Object.create(base)
      Object.defineProperty(view, 'readSnapshot', { value: undefined, enumerable: false, configurable: true })
      Object.defineProperty(view, 'capabilities', { value: Object.freeze({ ...withoutKey }), enumerable: false })
      return view
    })
    const outcomes = await judge.run('snapshotDecisions:', assert)
    assert.deepEqual(red(outcomes), [], 'la cara false pasa contra un driver sin la capacidad')
    assert.equal(counter.readSnapshot, 0)
  }).timeout(60_000)

  test('C5 · la cara del driver no relaja la otra mitad del par: un driver que declara snapshotDecisions: true SIN readSnapshot, con el harness omitiéndola, sale ROJO («exige readSnapshot»)', async ({
    assert,
  }) => {
    const counter = { readSnapshot: 0 }
    const judge = rolesJudge(ALPHA4_DATABASE, countedDatabase(counter, {}, ['readSnapshot']))
    const outcomes = await judge.run('snapshotDecisions:', assert)
    const failures = red(outcomes)
    assert.isAbove(failures.length, 0, 'declarar true sin el método es rojo también cuando la cara la elige el driver')
    assert.isTrue(failures.some((f) => f.includes('snapshotDecisions: true exige readSnapshot en el puerto')), failures.join('\n'))
  }).timeout(60_000)
})

/* ── Relaciones (los gemelos) ─────────────────────────────────────────────── */

/** Las capacidades de NUESTRO `database` de relaciones en `:memory:` SIN las claves D15 (un harness anterior a ellas). */
const PRE_D15_DATABASE_RELATIONS: RelationsDriverCapabilities = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: false,
  injectableClock: true,
  transactionalWrites: false,
}

function relationsJudge(
  capabilities: RelationsDriverCapabilities,
  makeDriver: (config: any) => RelationsDriver | Promise<RelationsDriver>,
  limits?: { listMaxResults?: number }
) {
  const captured = capturingApi()
  registerRelationsDriverContract({ name: 'relaciones (harness anterior a D15)', capabilities, makeDriver, ...(limits ? { limits } : {}) }, captured.api as any)
  return captured
}

/** `database` de relaciones con `deny` contado: la cara `true` de `relationDenies` deniega; la `false` exige CERO llamadas. */
function countedRelations(counter: { deny: number; fresh?: number }) {
  return async (config: any) => {
    // El estado fresco de cada caso construye el driver sobre la config SIN deny (la de `denyManager` declara `note`).
    if (!JSON.stringify(config).includes('"note"')) counter.fresh = (counter.fresh ?? 0) + 1
    await db.from('authz_relations').delete()
    const driver = new DatabaseRelationsDriver(config, { transactionalWrites: false })
    const deny = driver.deny!.bind(driver)
    ;(driver as any).deny = async (...args: any[]) => {
      counter.deny++
      return (deny as any)(...args)
    }
    return driver
  }
}

test.group('juez D15 · clave omitida ⇒ la declaración del driver (relaciones)', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  test('C6 · relationDenies omitido y NUESTRO database lo declara true ⇒ se juzga la cara TRUE (T1, D9, M6…) y pasa', async ({ assert }) => {
    const counter: { deny: number; fresh?: number } = { deny: 0 }
    const judge = relationsJudge(PRE_D15_DATABASE_RELATIONS, countedRelations(counter))
    const outcomes = await judge.run('relationDenies:', assert)
    assert.deepEqual(red(outcomes), [])
    assert.isAbove(counter.deny, 0, 'la cara juzgada es la TRUE: el juez denegó por el driver')
    const trueCases = judge.cases.find((c) => c.title.startsWith('relationDenies:'))!.title.match(/true: (\d+) caso/)![1]
    assert.equal(counter.fresh, Number(trueCases), 'la cara true ENTERA, un estado fresco por caso interno')
    await judge.teardown()
  }).timeout(300_000)

  test('C7 · atomicRenewal omitido y NUESTRO database lo declara true ⇒ se juzga la cara TRUE (renovar una portadora entra) y pasa', async ({ assert }) => {
    const judge = relationsJudge({ ...PRE_D15_DATABASE_RELATIONS, relationDenies: true }, countedRelations({ deny: 0 }))
    const outcomes = await judge.run('atomicRenewal:', assert)
    assert.deepEqual(red(outcomes), [])
    await judge.teardown()
  }).timeout(60_000)

  test('C8 · experimental omitido y el driver lo declara true ⇒ se juzga la cara true y pasa', async ({ assert }) => {
    const caps: RelationsDriverCapabilities = { ...PRE_D15_DATABASE_RELATIONS, relationDenies: true, atomicRenewal: true }
    const judge = relationsJudge(caps, async (config) => {
      const driver = await countedRelations({ deny: 0 })(config)
      Object.defineProperty(driver, 'capabilities', { value: Object.freeze({ ...driver.capabilities, experimental: true }), configurable: true })
      return driver
    })
    const outcomes = await judge.run('experimental:', assert)
    assert.deepEqual(red(outcomes), [])
    await judge.teardown()
  }).timeout(60_000)

  test('C9 · el harness que declara EXPLÍCITO atomicRenewal: false contra NUESTRO database (true) sigue ROJO (manda el harness)', async ({ assert }) => {
    const judge = relationsJudge({ ...PRE_D15_DATABASE_RELATIONS, relationDenies: true, atomicRenewal: false }, countedRelations({ deny: 0 }))
    const outcomes = await judge.run('atomicRenewal:', assert)
    assert.lengthOf(red(outcomes), 1, 'la cara false explícita contra un driver que renueva atómicamente es roja')
  }).timeout(60_000)

  test('C10 · el harness que declara EXPLÍCITO relationDenies: false contra NUESTRO database (true) sigue ROJO (manda el harness)', async ({ assert }) => {
    const judge = relationsJudge({ ...PRE_D15_DATABASE_RELATIONS, relationDenies: false }, countedRelations({ deny: 0 }))
    const outcomes = await judge.run('relationDenies:', assert)
    assert.lengthOf(red(outcomes), 1)
  }).timeout(60_000)

  test('C11 · un tercero sin las claves NI los métodos (el doble mínimo) sigue en las caras FALSE de relationDenies, atomicRenewal y experimental y pasa', async ({ assert }) => {
    const minimal: RelationsDriverCapabilities = {
      singleCheckRelations: false,
      listObjectsInherited: false,
      usersetSubjects: false,
      membersOfNative: false,
      enumerateRelations: false,
      listObjectsTruncation: false,
      injectableClock: false,
      transactionalWrites: false,
    }
    const judge = relationsJudge(minimal, (config) => makeRelationsDriver({ config, capabilities: minimal }))
    for (const key of ['relationDenies:', 'atomicRenewal:', 'experimental:']) {
      const outcomes = await judge.run(key, assert)
      assert.deepEqual(red(outcomes), [], key)
    }
    await judge.teardown()
  }).timeout(60_000)
})
