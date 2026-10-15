/**
 * **El singleton `RelationsManager` de servicio** (Fase 4, lote 4-8) — el
 * cableado que el 4-6 dejó pendiente. `buildRelationsManager(config)` es la
 * función PURA que el provider usa para resolver `authz.relations` (análogo a
 * cómo el provider resuelve `authz.manager`): tiene su caso sin montar la app.
 *
 * Antes de 4-8 no existía: el consumidor construía el `RelationsManager` a mano
 * con `defineRelationsConfig`. Ahora sale de `relations.config` +
 * `relations.drivers[relations.default ?? default]`.
 *
 * Corre sin servidor ni base: config + doble en memoria.
 */
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { buildRelationsManager } from '../providers/authz_provider.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { RelationsManager } from '../src/relations/manager.js'
import { makeRelationsDriver } from '../src/testing/relations_contract.js'
import { createTestClock } from '../src/testing/test_clock.js'
import { systemClock } from '../src/clock.js'
import { APP_SCOPE } from '../src/types.js'
import type { RelationsConfig } from '../src/relations/define_relations_config.js'
import type { RelationsDriver, RelationsDriverCapabilities } from '../src/types.js'
import type { AuthorizationConfig } from '../src/define_config.js'

const CAPS: RelationsDriverCapabilities = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: false,
  injectableClock: true,
  // Doble en memoria (L-2/L-4): no escribe en ninguna transacción, así que declara `false` y se le juzga esa cara; la `true` la juzga el driver `database` REAL en pool ≥ 2 (`relations_database.spec.ts`).
  transactionalWrites: false,
}

function relationsConfig(): RelationsConfig {
  return defineRelationsConfig({
    objectTypes: [{ type: 'document', relations: [{ name: 'owner' }, { name: 'viewer', includes: ['owner'] }] }],
    holderTypes: ['user'],
  })
}

/** Un config de roles mínimo (el manager de relaciones NO lo usa para roles). */
function baseConfig(relations: NonNullable<AuthorizationConfig['relations']>, extra?: Partial<AuthorizationConfig>): AuthorizationConfig {
  return {
    default: 'database',
    drivers: {},
    warnOnOptInSecurity: false,
    ...extra,
    relations,
  } as AuthorizationConfig
}

test.group('relaciones · singleton de servicio (4-8)', () => {
  test('buildRelationsManager cablea el manager desde relations.config + el driver activo', async ({ assert }) => {
    const config = relationsConfig()
    const dbDriver = makeRelationsDriver({ config, capabilities: CAPS })
    const manager = await buildRelationsManager(
      baseConfig({ config, drivers: { database: () => dbDriver } })
    )

    assert.instanceOf(manager, RelationsManager)
    // El driver activo (default = 'database') es el que se construyó.
    assert.strictEqual(manager.driver(), dbDriver, 'resuelve relations.drivers[default]')

    // F-05 vive en el manager: un tipo no declarado ⇒ 422 ANTES del driver.
    const user = { type: 'user', uuid: uuidv7() }
    let caught: any
    try {
      await manager.relate(user, 'assignee', { type: 'role_binding', id: uuidv7() }, APP_SCOPE)
      assert.fail('un tipo no declarado tenía que ser 422')
    } catch (e) {
      caught = e
    }
    assert.equal(caught.status, 422, String(caught?.message))

    // Y un tipo declarado sí pasa (llega al driver doble, que lo acepta).
    const doc = { type: 'document', id: uuidv7() }
    await manager.relate(user, 'viewer', doc, APP_SCOPE)
    assert.isTrue(await manager.check(user, 'viewer', doc, APP_SCOPE), 'la relación declarada resuelve en el driver')
  })

  test('relations.default elige el driver; sin él, cae al `default` de roles', async ({ assert }) => {
    const config = relationsConfig()
    const dbDriver = makeRelationsDriver({ config, capabilities: CAPS })
    const fgaDriver = makeRelationsDriver({ config, capabilities: CAPS })

    // Sin relations.default: usa config.default ('database').
    const m1 = await buildRelationsManager(
      baseConfig({ config, drivers: { database: () => dbDriver, openfga: () => fgaDriver } })
    )
    assert.strictEqual(m1.driver(), dbDriver, 'sin relations.default, cae al default de roles')

    // Con relations.default = 'openfga': gana ése.
    const m2 = await buildRelationsManager(
      baseConfig({ config, default: 'openfga', drivers: { database: () => dbDriver, openfga: () => fgaDriver } })
    )
    assert.strictEqual(m2.driver(), fgaDriver, 'relations.default elige el driver activo')
  })

  test('sin relations.config ⇒ lanza con la receta (ReBAC es opt-in)', async ({ assert }) => {
    let caught: any
    try {
      await buildRelationsManager({ default: 'database', drivers: {} } as AuthorizationConfig)
      assert.fail('sin relations.config tenía que lanzar')
    } catch (e) {
      caught = e
    }
    assert.match(String(caught.message), /relations\.config/)
  })

  test('relations.config presente pero sin el driver activo ⇒ lanza nombrando la clave', async ({ assert }) => {
    const config = relationsConfig()
    let caught: any
    try {
      await buildRelationsManager(baseConfig({ config, default: 'openfga', drivers: {} }))
      assert.fail('sin el driver activo tenía que lanzar')
    } catch (e) {
      caught = e
    }
    assert.match(String(caught.message), /openfga/)
  })

  test('requireActor se hereda del config de roles (una sola política de auditoría)', async ({ assert }) => {
    const config = relationsConfig()
    const driver = makeRelationsDriver({ config, capabilities: CAPS })
    const manager = await buildRelationsManager(
      baseConfig({ config, drivers: { database: () => driver } }, { requireActor: true })
    )
    const user = { type: 'user', uuid: uuidv7() }
    let caught: any
    try {
      // Sin actor y requireActor: true ⇒ 422 antes del driver.
      await manager.relate(user, 'viewer', { type: 'document', id: uuidv7() }, APP_SCOPE)
      assert.fail('requireActor: true exigía actor')
    } catch (e) {
      caught = e
    }
    assert.equal(caught.status, 422, String(caught?.message))
    assert.equal(caught.code, 'E_AUTHZ_ACTOR_REQUIRED')
  })
})

/* ── alpha.3 · bloque A · el cableado de `relations.assertWrite` / `relations.onRelationWrite` / `relations.requireActor` ── */

/**
 * **2.4.0-alpha.3 · A (criterio (a) de COGNITIV).** Hasta alpha.2 el provider
 * pasaba al `RelationsManager` exactamente `requireActor`, `clock`,
 * `freezeTimeoutMs`, `requireTransactionalWrites` y `driverName`
 * (`authz_provider.ts:47-56`), y `defineConfig` no admitía ni `assertWrite` ni
 * `onRelationWrite` en `relations`: por `authz.relations` NO había auditoría
 * posible ni gate de policy del consumidor. Un solo home (D-4): `relations.*`.
 * `relations.requireActor ?? config.requireActor` (D-5), los tres sentidos.
 */
/* ── Plan 2.5 · lote A · P5: el reloj del config llega a `authz.relations` (P5-1/P5-2/A-4) ── */

/**
 * **P5-1 (A-1)**: `config.clock` llega al `RelationsManager` que construye el
 * provider. Medido por el tester (ronda 2, §0): borrar `clock: config.clock`
 * en `providers/authz_provider.ts` dejaba la suite VERDE —entrada inerte,
 * linaje L5—. Aquí: reloj fijado en T (2030) y una tupla con `expiresAt = T`;
 * con el reloj inyectado la caducidad ESTRICTA la deja fuera (`false`); con
 * el reloj de pared (hoy ≪ 2030) concedería ⇒ el mutante se pone rojo.
 */
test.group('lote A · P5 · el reloj del config gobierna el singleton de relaciones (createTestClock)', () => {
  test('P5-1 · config.clock llega a authz.relations: con el reloj en T, una tupla con expiresAt = T no concede (estricta) y en T−1 sí; sin reloj (pared) concedería', async ({ assert }) => {
    const config = relationsConfig()
    const T = new Date('2030-06-15T12:34:56.789Z')
    const clock = createTestClock(T)
    const driver = makeRelationsDriver({ config, capabilities: CAPS })
    const manager = await buildRelationsManager(baseConfig({ config, drivers: { database: () => driver } }, { clock }))
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    await manager.relate(u, 'viewer', doc, APP_SCOPE, { expiresAt: T })
    assert.isFalse(await manager.check(u, 'viewer', doc, APP_SCOPE), 'ROJO (P5-1): el reloj del config NO llegó al manager de relaciones (con la hora de pared, 2030 es futuro y concede)')
    clock.advance(-1)
    assert.isTrue(await manager.check(u, 'viewer', doc, APP_SCOPE), 'T−1 ms concede')
    clock.set(T.getTime() + 60_000)
    assert.isFalse(await manager.check(u, 'viewer', doc, APP_SCOPE))
    // Control: el MISMO config sin `clock` decide con la hora de pared y concede.
    const wall = await buildRelationsManager(baseConfig({ config, drivers: { database: () => driver } }))
    assert.isTrue(await wall.check(u, 'viewer', doc, APP_SCOPE), 'sin clock: la hora de pared (hoy) está antes de 2030')
  })

  test('P5-2 · createTestClock es una función ESTABLE sobre un valor mutable (set/advance/now/at), no muta systemClock ni el config, y valida sus entradas', ({ assert }) => {
    const clock = createTestClock('2030-01-01T00:00:00.000Z')
    const sameRef = clock
    assert.equal(clock().toISOString(), '2030-01-01T00:00:00.000Z')
    assert.notStrictEqual(clock(), clock(), 'cada lectura es una copia nueva')
    clock.advance(1_500)
    assert.equal(sameRef().toISOString(), '2030-01-01T00:00:01.500Z', 'la MISMA referencia ve el avance')
    assert.equal(clock.now().getTime(), clock().getTime())
    assert.equal(clock.at(500).toISOString(), '2030-01-01T00:00:02.000Z')
    clock.set(new Date('2031-01-01T00:00:00.000Z'))
    assert.equal(clock().getUTCFullYear(), 2031)
    clock.set(Date.parse('2032-01-01T00:00:00.000Z'))
    assert.equal(clock().getUTCFullYear(), 2032)
    // Y la hora de pared NO se ha tocado (el helper no muta nada global).
    assert.isBelow(Math.abs(systemClock().getTime() - Date.now()), 5_000, 'systemClock sigue siendo la hora de pared')
    assert.throws(() => clock.set('no es una fecha'), /no es un instante válido/)
    assert.throws(() => clock.advance(Number.NaN), /advance\(ms\)/)
    assert.throws(() => createTestClock('tampoco'), /start/)
  })

  /**
   * **A-4**: el MISMO reloj decide la BARRERA del freeze (`#assertNotFrozen`
   * lee `nowMs` del `clock` del manager, `relations/manager.ts`). Una fila de
   * freeze con lease hasta T+15 s: con el reloj en T las escrituras de
   * relaciones son 503; adelantado 16 s, la barrera ve el lease VENCIDO y la
   * escritura entra — mientras un manager sin reloj (hora de pared, ≪ T)
   * sigue viendo la ventana viva. Mutante: `systemClock()` en la barrera ⇒
   * tras avanzar sigue 503 ⇒ rojo. Y va escrito en el README («Testing expiry
   * from your app»).
   */
  test('A-4 · el reloj de test gobierna también la barrera del freeze: con el lease hasta T+15 s, en T es 503 E_AUTHZ_FROZEN; avanzado 16 s la escritura entra; un manager con la hora de pared sigue congelado', async ({ assert }) => {
    const { acquireFreeze, releaseFreeze } = await import('../src/freeze.js')
    const T = Date.UTC(2030, 5, 15, 12, 0, 0)
    const token = await acquireFreeze({ reason: 'A-4 lease', holder: 'reconcile:a4', untilMs: T + 15_000, nowMs: T })
    assert.isNotNull(token, 'precondición: la fila de freeze estaba libre')
    try {
      const config = relationsConfig()
      const driver = makeRelationsDriver({ config, capabilities: CAPS })
      const clock = createTestClock(T)
      const clocked = await buildRelationsManager(baseConfig({ config, drivers: { database: () => driver } }, { clock }))
      const wall = await buildRelationsManager(baseConfig({ config, drivers: { database: () => driver } }))
      const u = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: uuidv7() }
      const frozen = await clocked.relate(u, 'viewer', doc, APP_SCOPE).then(() => null, (e) => e)
      assert.equal(frozen?.code, 'E_AUTHZ_FROZEN', `en T la ventana está viva: ${frozen?.message}`)
      clock.advance(16_000)
      await clocked.relate(u, 'viewer', doc, APP_SCOPE)
      assert.isTrue(await clocked.check(u, 'viewer', doc, APP_SCOPE), 'ROJO (A-4): con el reloj 16 s por delante el lease está vencido y la escritura tenía que entrar')
      const stillFrozen = await wall.relate(u, 'editor', doc, APP_SCOPE).then(() => null, (e) => e)
      assert.equal(stillFrozen?.code, 'E_AUTHZ_FROZEN', 'la hora de pared (hoy) está antes de 2030: para ese manager la ventana sigue viva')
    } finally {
      await releaseFreeze(token!, { nowMs: T })
    }
  })
})

test.group('alpha.3 · A · el cableado de relations.assertWrite / onRelationWrite / requireActor por el singleton', () => {
  /** El doble envuelto en un espía que cuenta las CUATRO escrituras. */
  function spied(config: RelationsConfig) {
    const base = makeRelationsDriver({ config, capabilities: CAPS })
    const calls: string[] = []
    const driver = new Proxy(base, {
      get(target, prop, receiver) {
        if (prop === 'relate' || prop === 'unrelate' || prop === 'purgeObject' || prop === 'purgeSubject') {
          return async (...args: unknown[]) => {
            calls.push(prop)
            return (target as any)[prop](...args)
          }
        }
        const value = Reflect.get(target, prop, receiver)
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    return { driver, calls }
  }

  async function rejects(assert: any, fn: () => Promise<unknown>, expected: { status: number; code: string }, label: string): Promise<any> {
    try {
      await fn()
    } catch (error: any) {
      assert.equal(error.status, expected.status, `${label}: ${error.message}`)
      assert.equal(error.code, expected.code, `${label}: ${error.message}`)
      return error
    }
    assert.fail(`ROJO: ${label} no lanzó`)
  }

  test('A1 · relations.onRelationWrite declarado en el config ⇒ un relate por el singleton lo dispara con su actor (exactamente un evento, con la forma entera)', async ({
    assert,
  }) => {
    const config = relationsConfig()
    const { driver } = spied(config)
    const events: any[] = []
    const manager = await buildRelationsManager(
      baseConfig({ config, drivers: { database: () => driver }, onRelationWrite: (e: any) => void events.push(e) } as any)
    )
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    const actor = { type: 'user', uuid: uuidv7() }
    await manager.relate(u, 'viewer', doc, p, { actor })
    assert.lengthOf(events, 1, 'ROJO: el provider no cablea relations.onRelationWrite (cero eventos por el singleton)')
    assert.equal(events[0].operation, 'relate')
    assert.deepEqual(events[0].subject, u)
    assert.equal(events[0].relation, 'viewer')
    assert.deepEqual(events[0].object, doc)
    assert.deepEqual(events[0].partition, p)
    assert.deepEqual(events[0].actor, actor)
  })

  test('A2 · relations.assertWrite declarado ⇒ rechaza ⇒ CERO llamadas al driver y CERO eventos; la relación permitida sí entra y notifica 1', async ({
    assert,
  }) => {
    const config = relationsConfig()
    const { driver, calls } = spied(config)
    const events: any[] = []
    const manager = await buildRelationsManager(
      baseConfig({
        config,
        drivers: { database: () => driver },
        assertWrite: (ref: any) => {
          if (ref.relation === 'owner') throw new Error('prohibido owner por policy del consumidor')
        },
        onRelationWrite: (e: any) => void events.push(e),
      } as any)
    )
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    let threw = false
    try {
      await manager.relate(u, 'owner', doc, p)
    } catch {
      threw = true
    }
    assert.isTrue(threw, 'ROJO: relations.assertWrite no llega al manager: el owner ENTRÓ por el singleton (el gate de policy es inerte)')
    assert.deepEqual(calls, [], 'assertWrite cortó ANTES del driver')
    assert.lengthOf(events, 0)
    await manager.relate(u, 'viewer', doc, p)
    assert.deepEqual(calls, ['relate'])
    assert.lengthOf(events, 1)
  })

  test('A3 · relations.requireActor anula el raíz por PUERTO, en los tres sentidos: (i) heredar, (ii) raíz false + relations true ⇒ 422 antes del driver, (iii) raíz true + relations false ⇒ entra', async ({
    assert,
  }) => {
    const config = relationsConfig()
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }

    // (i) sin nada declarado en relations: se hereda el raíz (el caso 4-8 de arriba lo fija con true; aquí con false entra).
    const inherit = spied(config)
    const m1 = await buildRelationsManager(baseConfig({ config, drivers: { database: () => inherit.driver } }, { requireActor: false }))
    await m1.relate(u, 'viewer', doc, p)
    assert.deepEqual(inherit.calls, ['relate'], '(i) raíz false heredado: entra sin actor')

    // (ii) raíz false + relations.requireActor: true ⇒ 422 E_AUTHZ_ACTOR_REQUIRED, cero escrituras.
    const raise = spied(config)
    const m2 = await buildRelationsManager(
      baseConfig({ config, drivers: { database: () => raise.driver }, requireActor: true } as any, { requireActor: false })
    )
    await rejects(assert, () => m2.relate(u, 'viewer', doc, p), { status: 422, code: 'E_AUTHZ_ACTOR_REQUIRED' }, '(ii) relations.requireActor: true')
    assert.deepEqual(raise.calls, [], '(ii) cero escrituras')
    await m2.relate(u, 'viewer', doc, p, { actor: { type: 'user', uuid: uuidv7() } })
    assert.deepEqual(raise.calls, ['relate'], '(ii) con actor entra')

    // (iii) raíz true + relations.requireActor: false ⇒ el opt-out explícito por puerto: el mismo relate ENTRA.
    const lower = spied(config)
    const m3 = await buildRelationsManager(
      baseConfig({ config, drivers: { database: () => lower.driver }, requireActor: false } as any, { requireActor: true })
    )
    await m3.relate(u, 'viewer', doc, p)
    assert.deepEqual(lower.calls, ['relate'], 'ROJO (iii): relations.requireActor: false no anula el raíz (el false explícito se pierde: `||` o `??` al revés)')
  })

  test('A4 · inverso · sin los hooks declarados el singleton no inventa nada: relate entra, no lanza, ningún hook que llamar', async ({ assert }) => {
    const config = relationsConfig()
    const { driver, calls } = spied(config)
    const manager = await buildRelationsManager(baseConfig({ config, drivers: { database: () => driver } }))
    const u = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    await manager.relate(u, 'viewer', doc, APP_SCOPE)
    await manager.relate(u, 'owner', doc, APP_SCOPE)
    assert.deepEqual(calls, ['relate', 'relate'])
    assert.isTrue(await manager.check(u, 'owner', doc, APP_SCOPE))
  })

  test('A6 · el ORDEN por el singleton: F-05 primero (assertWrite NO se llamó), assertWrite después (SÍ se llamó una vez con una relación declarada), driver al final', async ({
    assert,
  }) => {
    const config = relationsConfig()
    const { driver, calls } = spied(config)
    const events: any[] = []
    let assertWriteCalls = 0
    const manager = await buildRelationsManager(
      baseConfig({
        config,
        drivers: { database: () => driver },
        assertWrite: () => void (assertWriteCalls += 1),
        onRelationWrite: (e: any) => void events.push(e),
      } as any)
    )
    const u = { type: 'user', uuid: uuidv7() }
    const p = { type: 'unit', uuid: uuidv7() }
    await rejects(
      assert,
      () => manager.relate(u, 'assignee', { type: 'role_binding', id: uuidv7() }, p),
      { status: 422, code: 'E_AUTHZ_RELATION_TYPE_UNKNOWN' },
      'F-05 por el singleton'
    )
    assert.equal(assertWriteCalls, 0, 'F-05 va ANTES de assertWrite')
    assert.deepEqual(calls, [])
    assert.lengthOf(events, 0)
    // La aserción POSITIVA (regla del lote: todo «no se llamó» va con su «sí se llamó»).
    await manager.relate(u, 'viewer', { type: 'document', id: uuidv7() }, p)
    assert.equal(assertWriteCalls, 1, 'ROJO: assertWrite no está cableado (el 0 de arriba era por el motivo equivocado)')
    assert.deepEqual(calls, ['relate'])
    assert.lengthOf(events, 1)
  })
})

/* ── L-2 · la puerta 2 en `config.relations` (al RESOLVER el driver de relaciones) ── */

test.group('L-2 · requireTransactionalWrites en config.relations (puerta 2 del puerto de relaciones, al resolver)', () => {
  async function rejects(assert: any, fn: () => Promise<unknown>, label: string): Promise<any> {
    try {
      await fn()
    } catch (error: any) {
      assert.equal(error.status, 500, `${label}: ${error.message}`)
      assert.equal(error.code, 'E_AUTHZ_CONFIG', `${label}: ${error.message}`)
      return error
    }
    assert.fail(`ROJO: ${label} resolvió un driver de relaciones sin transactionalWrites con requireTransactionalWrites: true`)
  }

  test('relations.requireTransactionalWrites: true + el driver activo declara false ⇒ 500 E_AUTHZ_CONFIG nombrando la clave del driver; el raíz se hereda (una sola política) y relations.* lo anula; con un driver capaz resuelve', async ({
    assert,
  }) => {
    const config = relationsConfig()
    const incapable = makeRelationsDriver({ config, capabilities: { ...CAPS, transactionalWrites: false } as any })
    const capable = makeRelationsDriver({ config, capabilities: { ...CAPS, transactionalWrites: true } as any })
    const drivers = { database: () => incapable, openfga: () => capable }

    // En `relations`:
    const e1 = await rejects(
      assert,
      () => buildRelationsManager(baseConfig({ config, drivers, requireTransactionalWrites: true } as any)),
      'relations.requireTransactionalWrites'
    )
    assert.include(e1.message, `'database'`)
    assert.include(e1.message, 'transactionalWrites')
    // Heredado del raíz, como `requireActor`:
    const e2 = await rejects(
      assert,
      () => buildRelationsManager(baseConfig({ config, drivers }, { requireTransactionalWrites: true } as any)),
      'requireTransactionalWrites raíz'
    )
    assert.include(e2.message, `'database'`)
    // `relations.requireTransactionalWrites: false` anula el raíz (cada puerto decide):
    const m1 = await buildRelationsManager(
      baseConfig({ config, drivers, requireTransactionalWrites: false } as any, { requireTransactionalWrites: true } as any)
    )
    assert.strictEqual(m1.driver(), incapable)
    // Con el driver capaz (misma bandera) resuelve:
    const m2 = await buildRelationsManager(
      baseConfig({ config, default: 'openfga', drivers, requireTransactionalWrites: true } as any)
    )
    assert.strictEqual(m2.driver(), capable)
    // Y sin bandera, el incapaz resuelve (opt-in).
    assert.strictEqual((await buildRelationsManager(baseConfig({ config, drivers }))).driver(), incapable)
  })
})
