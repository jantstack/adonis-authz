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
} from '../src/drivers/openfga_driver.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { countCalls, withFailing } from './helpers/spies.js'

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
}

const drivers: SpiedDriver[] = [
  {
    name: 'database',
    make: async (resolveAncestors) => new DatabaseAuthorizationDriver({ resolveAncestors }),
    teardown: async () => {},
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

      await assert.rejects(() =>
        withFailing(holder, 'resolveAncestors', () => driver.authorize(alice, 'docs:write', unit))
      )
      // Y al restaurarlo, vuelve a responder.
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
    })
  })
}
