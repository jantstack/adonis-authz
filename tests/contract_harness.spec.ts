/**
 * La regla de capacidades del juez, ejecutable: una capacidad declarada
 * `true` sin par registrado, o `exhaustiveLists: false` sin tope conocido, se
 * rechazan al registrar el contrato — un `skip` con otro nombre no pasa.
 * Y `level` hace lo que dice: sin él solo se registran los casos core.
 *
 * Japa no deja registrar grupos desde un test en marcha, así que el juez se
 * registra contra una API falsa que solo anota títulos.
 */

import { test } from '@japa/runner'
import { registerAuthorizationDriverContract } from '../src/testing/contract.js'
import type { ContractTestApi } from '../src/testing/contract.js'
import type { ContractLevel, DriverCapabilities } from '../src/testing/main.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'

const NONE: DriverCapabilities = {
  hierarchyFacts: false,
  transactions: false,
  truncationSignal: false,
  singleCheckAuthorize: false,
  injectableClock: false,
  exhaustiveLists: true,
}

function fakeApi(): { api: ContractTestApi; titles: string[] } {
  const titles: string[] = []
  return {
    titles,
    api: {
      group: (_title, define) => define({ each: { setup: () => {} }, teardown: () => {} }),
      test: (title) => {
        titles.push(title)
        return { timeout: () => {} }
      },
    },
  }
}

function register(
  capabilities: DriverCapabilities,
  options: { level?: ContractLevel; limits?: { listMaxResults?: number } } = {}
): string[] {
  const { api, titles } = fakeApi()
  registerAuthorizationDriverContract(
    {
      name: 'harness-de-prueba',
      level: options.level,
      capabilities,
      limits: options.limits,
      makeDriver: () => new DatabaseAuthorizationDriver(),
      seedCatalog: async () => {},
      cleanup: async () => {},
    },
    api
  )
  return titles
}

test.group('juez — regla de capacidades y niveles', () => {
  test('declarar true una capacidad sin par registrado se rechaza al registrar', ({ assert }) => {
    // El par `whenTrue` de truncationSignal llega en Fase 1 (L0.7).
    assert.throws(
      () => register({ ...NONE, truncationSignal: true }, { level: '2.0' }),
      /'truncationSignal: true'/
    )
  })

  test('exhaustiveLists:false sin limits.listMaxResults se rechaza al registrar', ({ assert }) => {
    assert.throws(() => register({ ...NONE, exhaustiveLists: false }, { level: '2.0' }), /listMaxResults/)
  })

  test('exhaustiveLists:false con tope registra el caso de frontera con ese número', ({ assert }) => {
    const titles = register({ ...NONE, exhaustiveLists: false }, { level: '2.0', limits: { listMaxResults: 3 } })
    assert.include(titles, 'frontera del tope: 3 asignaciones directas se devuelven enteras')
  })

  test('sin level se registran solo los casos core; con 2.0 se añaden los nuevos', ({ assert }) => {
    const core = register(NONE)
    const full = register(NONE, { level: '2.0' })
    assert.lengthOf(core, 28)
    assert.lengthOf(full, 35)
    // Todo caso core está también en 2.0: un harness de 1.x no pierde nada.
    for (const title of core) assert.include(full, title)
    // El par de capacidad se juzga en TODOS los niveles (H1): declarar
    // `exhaustiveLists: true` en un harness core no es un skip.
    assert.include(core, 'listas exhaustivas: 1.200 asignaciones directas se devuelven enteras')
  })
})
