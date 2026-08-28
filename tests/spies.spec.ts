/**
 * Coste observable de las operaciones: cuántas veces tocan el árbol del
 * consumidor y el backend. No es semántica (eso lo juzga el contrato); es la
 * factura actual, fijada para que cambie a propósito.
 *
 * `authorize` con una cadena de 3 (unit → org → app) resuelve ancestros UNA
 * vez en ambos drivers. En Fase 2 el memo por request bajará este número en
 * llamadas repetidas y en Fase 3b el modo facts lo dejará en 0: cada cambio
 * reescribe este test conscientemente.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { memoryScopeTree, resolveAncestorsFrom } from '../src/testing/main.js'
import type { ContractScopeTree } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import type { AuthorizationDriver, ScopeRef, ScopeAncestorsResolver } from '../src/types.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import {
  OpenFgaAuthorizationDriver,
  provisionOpenFgaStore,
} from '../src/openfga.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { countCalls, countQueries, withFailing } from './helpers/spies.js'

const CATALOG = {
  permissions: [{ slug: 'docs:write' }],
  roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:write'] }],
}

/**
 * El driver recibe una función que delega en `holder.resolveAncestors` en
 * cada llamada: así el contador puede sustituir el método DESPUÉS de
 * construir el driver y seguir viendo las llamadas.
 */
function makeResolverHolder(tree: ContractScopeTree) {
  const holder = { resolveAncestors: resolveAncestorsFrom(tree) }
  const resolver: ScopeAncestorsResolver = (scope) => holder.resolveAncestors(scope)
  return { holder, resolver }
}

async function threeLevelTree(): Promise<{ tree: ContractScopeTree; unit: ScopeRef }> {
  const tree = memoryScopeTree()
  const org: ScopeRef = { type: 'organization', uuid: uuidv7() }
  const unit: ScopeRef = { type: 'unit', uuid: uuidv7() }
  await tree.attach(org, APP_SCOPE)
  await tree.attach(unit, org)
  return { tree, unit }
}

interface SpiedDriver {
  name: string
  make(resolver: ScopeAncestorsResolver): Promise<AuthorizationDriver>
  teardown(): Promise<void>
  /** Llamadas al backend de HECHOS durante `fn` (SQL en database, cliente FGA en openfga). */
  backendCalls(driver: AuthorizationDriver, fn: () => Promise<void>): Promise<number>
}

const FGA_CLIENT_METHODS = ['check', 'batchCheck', 'read', 'write', 'writeTuples', 'deleteTuples', 'listObjects', 'listUsers']

const drivers: SpiedDriver[] = [
  {
    name: 'database',
    make: async (resolveAncestors) => new DatabaseAuthorizationDriver({ resolveAncestors }),
    teardown: async () => {},
    backendCalls: async (_driver, fn) => (await countQueries(fn)).queries.length,
  },
]

const openFgaTestUrl = process.env.OPENFGA_TEST_URL
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl
  const holderTypes = { users: 'user' }
  const stores: string[] = []
  drivers.push({
    name: 'openfga',
    make: async (resolveAncestors) => {
      const { storeId, modelId } = await provisionOpenFgaStore(apiUrl, `spies-${uuidv7()}`, holderTypes)
      stores.push(storeId)
      return new OpenFgaAuthorizationDriver({ apiUrl, storeId, modelId, holderTypes, resolveAncestors })
    },
    teardown: async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) {
        await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
      }
    },
    backendCalls: async (driver, fn) => {
      // El catálogo sigue en SQL también con openfga: se cuentan ambos.
      const counter = countCalls((driver as any).client, FGA_CLIENT_METHODS)
      try {
        const sql = (await countQueries(fn)).queries.length
        return sql + Object.values(counter.counts).reduce((a, b) => a + b, 0)
      } finally {
        counter.restore()
      }
    },
  })
}

for (const spied of drivers) {
  test.group(`espías [${spied.name}]`, (group) => {
    group.each.setup(async () => {
      await cleanAuthzTables()
      await syncAuthzCatalog(CATALOG)
    })
    group.teardown(() => spied.teardown())

    test('authorize con cadena de 3 resuelve ancestros exactamente 1 vez', async ({ assert }) => {
      const { tree, unit } = await threeLevelTree()
      const { holder, resolver } = makeResolverHolder(tree)
      const driver = await spied.make(resolver)
      const alice = { type: 'users', uuid: uuidv7() }
      await driver.grant(alice, 'editor', APP_SCOPE)

      const counter = countCalls(holder, ['resolveAncestors'])
      try {
        assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
        assert.equal(counter.counts.resolveAncestors, 1)
      } finally {
        counter.restore()
      }
    })

    test('si el resolutor falla, authorize no cae a un false silencioso', async ({ assert }) => {
      // El árbol del consumidor es una dependencia más: su caída se nota,
      // igual que la del backend (invariante 5).
      const { tree, unit } = await threeLevelTree()
      const { holder, resolver } = makeResolverHolder(tree)
      const driver = await spied.make(resolver)
      const alice = { type: 'users', uuid: uuidv7() }
      await driver.grant(alice, 'editor', APP_SCOPE)

      let caught: any
      try {
        await withFailing(holder, 'resolveAncestors', () => driver.authorize(alice, 'docs:write', unit))
        assert.fail('debería haber rechazado')
      } catch (error) {
        caught = error
      }
      // Clasificado como caída de una dependencia (503, código propio), con
      // el error del consumidor como causa: ni crudo ni disfrazado de bug.
      assert.equal(caught.status, 503)
      assert.equal(caught.code, 'E_AUTHZ_RESOLVER_FAILED')
      assert.equal(caught.cause?.message, 'resolveAncestors caído')
      // Y al restaurarlo, vuelve a responder.
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
    })

    test('un ancestro inválido devuelto por el resolutor es 503 E_AUTHZ_RESOLVER_FAILED, no un 422', async ({
      assert,
    }) => {
      // D13 (auditor H11). La pregunta era válida; lo inválido es la RESPUESTA
      // del árbol (`{app, 'X'}`, `{organization, 'a|b'}`, un no-array): es un
      // fallo de la dependencia, no del llamante, y se clasifica como tal.
      const { tree, unit } = await threeLevelTree()
      const { holder, resolver } = makeResolverHolder(tree)
      const driver = await spied.make(resolver)
      const alice = { type: 'users', uuid: uuidv7() }
      await driver.grant(alice, 'editor', APP_SCOPE)

      const original = holder.resolveAncestors
      for (const bad of [
        [{ type: 'app', uuid: 'X' }],
        [{ type: 'organization', uuid: 'a|b' }, APP_SCOPE],
        [{ type: 'organization' }],
        'no-es-un-array',
      ]) {
        holder.resolveAncestors = async () => bad as any
        let caught: any
        try {
          await driver.authorize(alice, 'docs:write', unit)
          assert.fail(`${JSON.stringify(bad)}: debería haber rechazado`)
        } catch (error) {
          caught = error
        } finally {
          holder.resolveAncestors = original
        }
        assert.equal(caught.status, 503, JSON.stringify(bad))
        assert.equal(caught.code, 'E_AUTHZ_RESOLVER_FAILED', JSON.stringify(bad))
      }
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
    })

    test('una identidad inválida se rechaza con 0 llamadas al backend', async ({ assert }) => {
      // L0.5/L0.10/L0.15: la validación va ANTES de catálogo, árbol y hechos.
      // No es solo coste: una escritura a medias (`user:undefined` en FGA)
      // era el defecto. Cero consultas es la prueba de que no hay rastro.
      const { tree } = await threeLevelTree()
      const { resolver } = makeResolverHolder(tree)
      const driver = await spied.make(resolver)
      const bad: Array<() => Promise<unknown>> = [
        () => driver.grant({ type: 'users', uuid: undefined as any }, 'editor', APP_SCOPE),
        () => driver.grant({ type: 'users', uuid: 'x#y' }, 'editor', APP_SCOPE),
        () => driver.authorize({ type: 'users', uuid: "x' OR '1'='1" }, 'docs:write', APP_SCOPE),
        () => driver.grant({ type: 'users', uuid: uuidv7() }, 'editor', { type: 'app', uuid: 'X' }),
        () =>
          driver.deny({ type: 'users', uuid: uuidv7() }, 'docs:write', {
            type: 'organization',
            uuid: '00000000-0000-0000-0000-000000000000',
          }),
      ]
      for (const call of bad) {
        const calls = await spied.backendCalls(driver, async () => {
          try {
            await call()
            assert.fail('debería haber rechazado')
          } catch (error: any) {
            assert.equal(error.status, 422)
            assert.equal(error.code, 'E_AUTHZ_INVALID_IDENTITY')
          }
        })
        assert.equal(calls, 0)
      }
    })
  })
}
