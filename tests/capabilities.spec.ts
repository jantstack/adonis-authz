/**
 * **`authorization.capabilities()` / `relations.capabilities()`** (2.4.0-alpha.4;
 * pregunta 1 de COGNITIV, panel alpha.4). Una lectura de solo lectura de lo
 * que el driver ACTIVO declara, para que el código de tenant pueda ramificar
 * (`transactionalWrites` ⇒ `{ transaction }` o no) sin llamar a `driver()`,
 * que sigue siendo API de PLATAFORMA (README: «a code review can grep for it»).
 *
 * Lo que fija esta spec, en el orden en que importa:
 *
 *  - **D-5 PRIMERO (🔴 del auditor)**: `capabilities()` en roles es
 *    `(await this.driver()).capabilities` y NADA más — pasa las dos puertas a
 *    propósito y JAMÁS resuelve el driver por otro camino ni toca `#driver`.
 *    Una implementación que «lea sin lanzar» saltándose las puertas y cachee
 *    deja `driver()` sirviendo un driver que nunca pasó por el gate de
 *    deriva: bypass permanente. Por eso: `capabilities()` primero ⇒ el mismo
 *    500 que `driver()`, y `driver()` DESPUÉS sigue lanzando.
 *  - copia CONGELADA y NORMALIZADA: todas las claves conocidas presentes,
 *    `undefined` → `false`, nunca `undefined` (repetiría el bug de
 *    `stillGranting`); mutar la copia no toca la puerta 1.
 *  - el mismo contenido que `driver().capabilities` en los dos drivers de cada
 *    puerto (una copia a mano en el manager es exactamente el bug que esta API
 *    puede introducir — precedente: `countRoleAssignments`).
 *  - relaciones ídem, SÍNCRONO (el driver es eager), y devuelve las claves de
 *    RELACIONES, no las de roles.
 *  - el README lo bendice con su letra (patrón `trx_docs.spec.ts`).
 */
import { test } from '@japa/runner'
import { readFile } from 'node:fs/promises'
import { v7 as uuidv7 } from 'uuid'
import { AuthorizationManager } from '../src/manager.js'
import { RelationsManager } from '../src/relations/manager.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { OpenFgaAuthorizationDriver, OpenFgaRelationsDriver } from '../src/openfga.js'
import { APP_SCOPE } from '../src/types.js'
import type { AuthorizationDriverCapabilities, RelationsDriverCapabilities } from '../index.js'
import { makeRelationsDriver, contractRelationsConfig } from '../src/testing/relations_contract.js'
import { TEST_MODEL_ID, serveGeneratedModel } from './helpers/fga_model.js'

const HOLDERS = { users: 'user' }
const ULID = '01ARZ3NDEKTSV4RRFFQ69G5FAV'

/** Las claves del puerto de ROLES (`AuthorizationDriverCapabilities`), literales: una nueva sin normalizar es rojo. */
const ROLE_KEYS: Array<keyof AuthorizationDriverCapabilities> = [
  'hierarchyFacts',
  'singleCheckAuthorize',
  'roleInheritanceNative',
  'listObjectsInherited',
  'purgeRole',
  'countRoleAssignments',
  'canonicalScopeReads',
  'enumerateFacts',
  'transactionalWrites',
]
/** Las del puerto de RELACIONES (`RelationsDriverCapabilities`). */
const RELATION_KEYS: Array<keyof RelationsDriverCapabilities> = [
  'singleCheckRelations',
  'listObjectsInherited',
  'usersetSubjects',
  'membersOfNative',
  'enumerateRelations',
  'listObjectsTruncation',
  'injectableClock',
  'transactionalWrites',
  // Lote D · D1 (regla D15): opcional en el tipo, normalizada a `false` en la copia; los dos drivers declaran `true`.
  'relationDenies',
  // Cierre 2 de D2 · 🟠 N1 (regla D15): opcional, normalizada a `false`; `database` declara `true`, `openfga` `false`.
  'atomicRenewal',
]

const fakeTrx = () => ({ from() {}, table() {}, isTransaction: true as const, connectionName: 'sqlite' })

/** Un driver de terceros: `capabilities` a elección (o ausente) y NO congeladas. */
function thirdParty(capabilities?: Record<string, unknown>) {
  const driver: any = capabilities === undefined ? {} : { capabilities: { ...capabilities } }
  for (const method of ['authorize', 'grant', 'revoke', 'hasRole', 'deny', 'removeDeny', 'listRoles', 'purgeScope']) {
    driver[method] = async () => (method === 'grant' ? { existed: false, expiresAt: null } : method === 'listRoles' ? [] : false)
  }
  return driver
}

function labOpenFga(options: Record<string, unknown> = {}) {
  return serveGeneratedModel(new OpenFgaAuthorizationDriver({
    apiUrl: 'http://127.0.0.1:9',
    storeId: ULID,
    modelId: TEST_MODEL_ID,
    holderTypes: HOLDERS,
    logger: { warn: () => {} },
    ...options,
  } as any), HOLDERS)
}

function managerOver(factory: () => unknown, extra: Record<string, unknown> = {}) {
  let factoryCalls = 0
  const manager = new AuthorizationManager({
    default: 'x',
    drivers: {
      x: () => {
        factoryCalls += 1
        return factory()
      },
    },
    holderTypes: HOLDERS,
    warnOnOptInSecurity: false,
    ...extra,
  } as any)
  return { manager, calls: () => factoryCalls }
}

async function rejects(assert: any, run: () => Promise<unknown>, code: string, label: string): Promise<any> {
  let caught: any
  try {
    await run()
  } catch (error) {
    caught = error
  }
  assert.isDefined(caught, `ROJO: ${label} no lanzó`)
  assert.equal(caught?.status, 500, `${label}: ${caught?.message}`)
  assert.equal(caught?.code, code, `${label}: ${caught?.message}`)
  return caught
}

test.group('alpha.4 · D · authorization.capabilities() — D-5 primero: pasa las DOS puertas y no envenena la caché de driver()', () => {
  test('D-5a · gate de deriva: driver hierarchyFacts sin outbox ni firma ⇒ capabilities() lanza 500 E_AUTHZ_SCOPE_DRIFT_UNGUARDED, y un driver() POSTERIOR sigue lanzando (la factory se llamó dos veces: nada quedó cacheado)', async ({
    assert,
  }) => {
    const { manager, calls } = managerOver(() => thirdParty({ hierarchyFacts: true }))
    await rejects(assert, () => manager.capabilities(), 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED', 'capabilities()')
    await rejects(assert, () => manager.driver(), 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED', 'driver() después de capabilities()')
    await rejects(assert, () => manager.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', APP_SCOPE), 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED', 'authorize después')
    assert.equal(calls(), 3, 'cada intento re-resuelve: NADA se cacheó saltándose la puerta')
  })

  test('D-5b · puerta 2: requireTransactionalWrites: true + openfga ⇒ capabilities() lanza 500 E_AUTHZ_CONFIG (la misma letra que driver()), y driver() después sigue lanzando; y en el orden inverso, igual', async ({
    assert,
  }) => {
    const strict = managerOver(() => labOpenFga({ acceptScopeDriftRisk: true }), {
      requireTransactionalWrites: true,
      scopes: { acceptScopeDriftRisk: true },
    })
    const fromCaps = await rejects(assert, () => strict.manager.capabilities(), 'E_AUTHZ_CONFIG', 'capabilities()')
    const fromDriver = await rejects(assert, () => strict.manager.driver(), 'E_AUTHZ_CONFIG', 'driver() después')
    assert.equal(fromCaps.message, fromDriver.message, 'la MISMA puerta, la misma letra')
    assert.include(fromCaps.message, "'x'")
    assert.include(fromCaps.message, 'transactionalWrites')

    const inverse = managerOver(() => labOpenFga({ acceptScopeDriftRisk: true }), {
      requireTransactionalWrites: true,
      scopes: { acceptScopeDriftRisk: true },
    })
    await rejects(assert, () => inverse.manager.driver(), 'E_AUTHZ_CONFIG', 'driver() primero')
    await rejects(assert, () => inverse.manager.capabilities(), 'E_AUTHZ_CONFIG', 'capabilities() después')
  })

  test('D-1 · el mismo contenido que driver().capabilities en los DOS drivers del paquete (y una sola resolución)', async ({ assert }) => {
    const database = managerOver(() => new DatabaseAuthorizationDriver({}))
    const caps = await database.manager.capabilities()
    assert.deepEqual({ ...caps }, { ...(await database.manager.driver()).capabilities! })
    assert.strictEqual(caps.transactionalWrites, true)
    assert.strictEqual(caps.hierarchyFacts, false)
    assert.equal(database.calls(), 1, 'capabilities() resolvió por driver(): UNA factory, cacheada')

    const openfga = managerOver(() => labOpenFga({ acceptScopeDriftRisk: true }), { scopes: { acceptScopeDriftRisk: true } })
    const fga = await openfga.manager.capabilities()
    assert.deepEqual({ ...fga }, { ...(await openfga.manager.driver()).capabilities! })
    assert.strictEqual(fga.transactionalWrites, false)
    assert.strictEqual(fga.hierarchyFacts, true)
    assert.equal(openfga.calls(), 1)
  })

  test('D-2 · copia CONGELADA, no la referencia: mutarla lanza, driver().capabilities no cambia y la puerta 1 sigue siendo 500 para { transaction } sobre un driver false', async ({
    assert,
  }) => {
    // Un driver de terceros con `capabilities` MUTABLES (los del paquete ya
    // congelan): lo que el consumidor recibe no puede ser ese objeto vivo.
    const driver = thirdParty({ transactionalWrites: false, purgeRole: true })
    const { manager } = managerOver(() => driver)
    const caps: any = await manager.capabilities()
    assert.isTrue(Object.isFrozen(caps))
    assert.notStrictEqual(caps, driver.capabilities, 'una copia, no un alias')
    assert.throws(() => {
      caps.transactionalWrites = true
    }, TypeError)
    assert.strictEqual(caps.transactionalWrites, false)
    assert.strictEqual(driver.capabilities.transactionalWrites, false, 'el objeto del driver no se tocó')
    assert.strictEqual((await manager.capabilities()).transactionalWrites, false, 'la segunda lectura dice lo mismo')
    // La puerta 1 lee el driver cacheado, no la copia: `{ transaction }` sigue siendo 500.
    const alice = { type: 'users', uuid: uuidv7() }
    await rejects(assert, () => manager.grant(alice, 'editor', APP_SCOPE, { transaction: fakeTrx() } as any), 'E_AUTHZ_UNSUPPORTED', 'grant { transaction }')
  })

  test('D-3 · un driver SIN capabilities ⇒ todas las claves conocidas en false, ninguna undefined; con capabilities PARCIALES, lo no declarado es false', async ({
    assert,
  }) => {
    const none = await managerOver(() => thirdParty()).manager.capabilities()
    assert.deepEqual(Object.keys(none).sort(), [...ROLE_KEYS].sort(), 'todas las claves conocidas, y solo esas')
    for (const key of ROLE_KEYS) assert.strictEqual(none[key], false, `${key} es false (no undefined)`)
    assert.isTrue(Object.isFrozen(none))

    const partial = await managerOver(() => thirdParty({ purgeRole: true, enumerateFacts: undefined, canonicalScopeReads: 'yes' as any })).manager.capabilities()
    assert.strictEqual(partial.purgeRole, true)
    assert.strictEqual(partial.enumerateFacts, false, 'undefined → false')
    assert.strictEqual(partial.canonicalScopeReads, false, 'solo `true` es true: la MISMA lectura que aplica la puerta 1 (=== true)')
    assert.strictEqual(partial.transactionalWrites, false)
    assert.isFalse(Object.values(partial).includes(undefined as any), 'ninguna clave es undefined')
  })

  test('D-6 · la vista de forRequest() delega en el padre: la misma copia, UNA resolución', async ({ assert }) => {
    const { manager, calls } = managerOver(() => new DatabaseAuthorizationDriver({}))
    const view = manager.forRequest()
    const fromView = await view.capabilities()
    const fromParent = await manager.capabilities()
    assert.deepEqual({ ...fromView }, { ...fromParent })
    assert.equal(calls(), 1, 'la vista no resuelve una segunda instancia (saltándose caché y puertas)')
  })
})

test.group('alpha.4 · D-4 · relations.capabilities() — síncrono, el mismo trío, y las claves de RELACIONES', () => {
  const config = contractRelationsConfig()

  test('el mismo contenido que driver().capabilities en los dos drivers de relaciones del paquete (database membersOfNative: true, openfga: false)', ({ assert }) => {
    const database = new RelationsManager(new DatabaseRelationsDriver(config, { transactionalWrites: false }), config)
    const dbCaps = database.capabilities()
    assert.deepEqual({ ...dbCaps }, { ...database.driver().capabilities! })
    assert.strictEqual(dbCaps.membersOfNative, true)
    assert.strictEqual(dbCaps.transactionalWrites, false)

    const openfga = new RelationsManager(
      new OpenFgaRelationsDriver(config, { apiUrl: 'http://127.0.0.1:9', storeId: ULID, modelId: TEST_MODEL_ID, holderTypes: { user: 'user' }, logger: { warn: () => {} } } as any),
      config
    )
    const fgaCaps = openfga.capabilities()
    assert.deepEqual({ ...fgaCaps }, { ...openfga.driver().capabilities! })
    assert.strictEqual(fgaCaps.membersOfNative, false)
    assert.strictEqual(fgaCaps.transactionalWrites, false)
    // Lote D · D1: los dos drivers del paquete declaran el deny.
    assert.strictEqual(dbCaps.relationDenies, true)
    assert.strictEqual(fgaCaps.relationDenies, true)
    // Cierre 2 de D2 · 🟠 N1: `database` renueva en UNA transacción; `openfga` con dos Write (y niega la portadora).
    assert.strictEqual(dbCaps.atomicRenewal, true)
    assert.strictEqual(fgaCaps.atomicRenewal, false)
    // Devuelve las claves de RELACIONES, no las de roles.
    assert.deepEqual(Object.keys(fgaCaps).sort(), [...RELATION_KEYS].sort())
    assert.notProperty(fgaCaps, 'hierarchyFacts')
  })

  test('copia congelada y normalizada: un driver sin capabilities ⇒ todo false; mutar la copia lanza y no apaga la puerta 1 (relate { transaction } sigue siendo 500)', async ({
    assert,
  }) => {
    const bare = new RelationsManager({} as any, config)
    const none = bare.capabilities()
    assert.deepEqual(Object.keys(none).sort(), [...RELATION_KEYS].sort())
    for (const key of RELATION_KEYS) assert.strictEqual(none[key], false, key)
    assert.isTrue(Object.isFrozen(none))

    const double = makeRelationsDriver({
      config,
      capabilities: {
        singleCheckRelations: true,
        listObjectsInherited: false,
        usersetSubjects: true,
        membersOfNative: true,
        enumerateRelations: true,
        listObjectsTruncation: false,
        injectableClock: false,
        transactionalWrites: false,
      },
    })
    const manager = new RelationsManager(double, config)
    const caps: any = manager.capabilities()
    assert.notStrictEqual(caps, double.capabilities)
    assert.throws(() => {
      caps.transactionalWrites = true
    }, TypeError)
    assert.strictEqual(manager.capabilities().transactionalWrites, false)
    await rejects(
      assert,
      () =>
        manager.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, APP_SCOPE, {
          transaction: fakeTrx(),
        } as any),
      'E_AUTHZ_UNSUPPORTED',
      'relate { transaction }'
    )
  })
})

test.group('alpha.4 · D-7 · el README bendice capabilities() con su letra (y no ablanda driver())', () => {
  const HEADING = '### Reading capabilities at runtime'

  function section(text: string, heading: string): string {
    const start = text.indexOf(heading)
    if (start < 0) return ''
    const rest = text.slice(start + heading.length)
    const next = rest.search(/\n#{2,4} /)
    return heading + (next < 0 ? rest : rest.slice(0, next))
  }

  test('la sección existe, enseña el ejemplo del consumidor, dice que es de solo lectura y normalizada, que hereda las puertas, y que driver() sigue siendo API de plataforma', async ({
    assert,
  }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    const text = section(readme, HEADING)
    assert.isNotEmpty(text, `falta la sección «${HEADING}»`)
    assert.include(text, 'await authorization.capabilities()')
    assert.include(text, 'relations.capabilities()')
    assert.include(text, 'transactionalWrites')
    assert.include(text, '{ transaction: trx }')
    assert.include(text, 'read-only')
    assert.include(text, 'frozen')
    assert.include(text, 'never `undefined`')
    assert.include(text, 'E_AUTHZ_UNSUPPORTED')
    assert.include(text, 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED')
    assert.include(text, 'E_AUTHZ_CONFIG')
    assert.include(text, '`driver()` is still platform API')
    assert.include(text, 'AuthorizationDriverCapabilities')
  })
})
