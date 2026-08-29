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
  listDenies: false,
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

  test('sin level se registran solo los casos core; con 2.0 y 2.1 se añaden los nuevos, anidados', ({ assert }) => {
    const core = register(NONE)
    const full = register(NONE, { level: '2.0' })
    const primitives = register({ ...NONE, listDenies: true }, { level: '2.1' })
    assert.lengthOf(core, 36)
    assert.lengthOf(full, 49)
    assert.lengthOf(primitives, 61)
    // Todo caso core está también en 2.0, y todo 2.0 en 2.1: un harness de
    // un nivel anterior no pierde nada, y uno de 2.1 no puede saltarse nada.
    for (const title of core) assert.include(full, title)
    for (const title of full) assert.include(primitives, title)
    // El par de capacidad se juzga en TODOS los niveles (H1): declarar
    // `exhaustiveLists: true` en un harness core no es un skip.
    assert.include(core, 'listas exhaustivas: 1.200 asignaciones directas se devuelven enteras')
  })

  test("listDenies es un par de capacidad de '2.1' (I5): true ⇒ los casos que restan denies; false ⇒ el caso «lo dice con 500 UNSUPPORTED»; true en core/2.0 se rechaza (no hay caso que lo observe)", ({
    assert,
  }) => {
    const withIt = register({ ...NONE, listDenies: true }, { level: '2.1' })
    const without = register({ ...NONE, listDenies: false }, { level: '2.1' })
    const needIt = withIt.filter((t) => /^(listDenies|effectivePermissions|authorizedScopes|el catálogo que decide)/.test(t))
    assert.lengthOf(needIt, 7)
    for (const title of needIt) assert.notInclude(without, title)
    const says = 'sin listDenies en el puerto: listDenies, effectivePermissions y authorizedScopes son 500 E_AUTHZ_UNSUPPORTED nombrándolo (nunca un [] simulado); el puerto 2.0 sigue respondiendo'
    assert.include(without, says)
    assert.notInclude(withIt, says)
    // Todo lo demás de 2.1 se juzga igual con y sin la capacidad.
    for (const title of withIt) if (!needIt.includes(title)) assert.include(without, title)
    assert.lengthOf(without, withIt.length - needIt.length + 1)
    // Sin nivel 2.1 no hay caso que observe `listDenies: true`: se rechaza, como cualquier promesa sin juez.
    assert.throws(() => register({ ...NONE, listDenies: true }), /'listDenies: true'/)
    assert.throws(() => register({ ...NONE, listDenies: true }, { level: '2.0' }), /'listDenies: true'/)
  })
})
