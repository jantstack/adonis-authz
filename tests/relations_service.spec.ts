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
  // L-2: `false` hasta L-4 (la escritura real en la transacción del llamante); la cara `whenFalse` es la que se juzga hoy.
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
