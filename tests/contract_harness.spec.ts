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
  purgeRole: false,
  serializedCatalogWrites: false,
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
    assert.lengthOf(primitives, 66)
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
    // Y el literal, para que el número documentado no pueda deslizarse en silencio.
    assert.lengthOf(without, 60)
    // Sin nivel 2.1 no hay caso que observe `listDenies: true`: se rechaza, como cualquier promesa sin juez.
    assert.throws(() => register({ ...NONE, listDenies: true }), /'listDenies: true'/)
    assert.throws(() => register({ ...NONE, listDenies: true }, { level: '2.0' }), /'listDenies: true'/)
  })

  test("3B: '2.2' añade los casos de roles locales anidados sobre '2.1'; purgeRole es un par de capacidad solo en '2.2' (true ⇒ la purga; false ⇒ «lo dice con 500»; true por debajo se rechaza); listDenies tiene cara 2.2 (defineScopedRole ⇒ 500 sin él)", ({
    assert,
  }) => {
    const base = { ...NONE, listDenies: true }
    const primitives = register(base, { level: '2.1' })
    const scoped = register(base, { level: '2.2' })
    const withPurge = register({ ...base, purgeRole: true }, { level: '2.2' })
    const withoutDenies = register(NONE, { level: '2.2' })
    for (const title of primitives) assert.include(scoped, title)
    // 7 casos de driver (B2, uno de ellos «por nivel, no por conjunto», otro
    // la ambigüedad de 3D · M1 y otro la paridad de nivel de 3D · N1) +
    // assignableAt (B5) + par purgeRole (B4).
    //
    // Desde 3E · P4 la API de DELEGACIÓN entera —`defineScopedRole` (B3/B7),
    // `effectivePermissions` por uuid y la carrera de dos define (3D ·
    // M1/M2)— cuelga del par `purgeRole`: un driver que no sabe purgar no
    // puede tener roles locales (el 500 llega ANTES de escribir), así que su
    // policy no se le juzga. El par es asimétrico: la cara `true` suma esos
    // 3 casos MÁS el de `scopes.detached` que purga los roles del owner (3D ·
    // M4); la `false`, uno solo (el 500 antes de escribir y su salida).
    assert.lengthOf(scoped, primitives.length + 9)
    assert.lengthOf(scoped, 75)
    assert.lengthOf(scoped.filter((t) => /^sin purgeRole: el puerto NO lo trae/.test(t)), 1)
    assert.isEmpty(withPurge.filter((t) => /^sin purgeRole: el puerto NO lo trae/.test(t)))
    assert.lengthOf(withPurge.filter((t) => /^purgeRole\(uuid\) revoca/.test(t)), 1)
    assert.lengthOf(withPurge.filter((t) => /^scopes\.detached purga también/.test(t)), 1)
    // 3G · W4: cuatro casos de COMPOSICIÓN más (los que habrían cazado las
    // tres regresiones seguidas de 3E/3F/3G): tres de `scopes.detached`
    // —ancestro desconocido con descendientes vivos, cota superada con rango
    // insuficiente, `descendantsOf` que falla— y uno de `defineScopedRole`
    // (ensombrecer con el subárbol sin enumerar), este último bajo el par
    // `listDenies` como el resto de la delegación.
    assert.lengthOf(withPurge, scoped.length + 8)
    assert.lengthOf(withPurge.filter((t) => /^composición \(3G · W4/.test(t)), 4)
    // Sin listDenies en 2.2: la cara «defineScopedRole lo dice con 500» sustituye a la de la delegación.
    assert.lengthOf(withoutDenies, 70)
    assert.lengthOf(withoutDenies.filter((t) => /^sin listDenies en el puerto: defineScopedRole/.test(t)), 1)
    assert.isEmpty(withoutDenies.filter((t) => /^defineScopedRole:/.test(t)))
    assert.isEmpty(scoped.filter((t) => /^defineScopedRole:/.test(t)))
    assert.lengthOf(withPurge.filter((t) => /^defineScopedRole:/.test(t)), 1)
    // Sin nivel 2.2 no hay caso que observe `purgeRole: true`.
    assert.throws(() => register({ ...base, purgeRole: true }, { level: '2.1' }), /'purgeRole: true'/)
    assert.throws(() => register({ ...NONE, purgeRole: true }), /'purgeRole: true'/)
    // Y con el reloj, los 4 de J1 se suman igual.
    assert.lengthOf(register({ ...base, injectableClock: true }, { level: '2.2' }), 79)
  })

  test("3E · R2: serializedCatalogWrites es un par de capacidad de '2.2': true ⇒ la carrera de dos define exige EXACTAMENTE un ganador y 422 para el perdedor; false ⇒ la forma laxa (nunca dos, el perdedor no escribe); true sin caso que lo observe se rechaza", ({
    assert,
  }) => {
    const base = { ...NONE, listDenies: true, purgeRole: true }
    const estricto = register({ ...base, serializedCatalogWrites: true }, { level: '2.2' })
    const laxo = register(base, { level: '2.2' })
    const strictTitle = (t: string) => /^dos defineScopedRole del MISMO \(slug, nivel\).*EXACTAMENTE uno gana y el perdedor es 422/.test(t)
    const laxTitle = (t: string) => /^dos defineScopedRole del MISMO \(slug, nivel\).*nunca dos ganadores/.test(t)
    assert.lengthOf(estricto.filter(strictTitle), 1)
    assert.isEmpty(estricto.filter(laxTitle))
    assert.lengthOf(laxo.filter(laxTitle), 1)
    assert.isEmpty(laxo.filter(strictTitle))
    // Es un par exacto: la misma cuenta de casos con una cara o con la otra.
    assert.lengthOf(estricto, laxo.length)
    // Sin nivel 2.2, o sin la API de delegación (listDenies/purgeRole), no hay
    // caso que lo observe: declararlo `true` se rechaza, como cualquier
    // promesa sin juez.
    assert.throws(() => register({ ...base, serializedCatalogWrites: true }, { level: '2.1' }), /'serializedCatalogWrites: true'/)
    assert.throws(() => register({ ...NONE, serializedCatalogWrites: true }, { level: '2.2' }), /'serializedCatalogWrites: true'/)
  })

  test('injectableClock es un par en todos los niveles (2.5 · J1): false ⇒ los tres estados en tiempo real; true ⇒ los tres estados con reloj y, en 2.1, la caducidad exacta y el clock del manager', ({
    assert,
  }) => {
    const realTime = 'expiresAt en tres estados: omitido preserva la caducidad vigente, null la quita, expirada revive (observado en tiempo real: sin reloj inyectable)'
    const clocked = 'expiresAt en tres estados con el reloj inyectado: omitido preserva la caducidad vigente, null la quita, expirada revive; el instante que vence es exacto'
    const exact = (t: string) => /^caducidad exacta con el reloj inyectado/.test(t)
    const managerClock = (t: string) => /^el manager expone el reloj \(config\.clock\)/.test(t)

    const coreWithout = register(NONE)
    const coreWith = register({ ...NONE, injectableClock: true })
    assert.include(coreWithout, realTime)
    assert.notInclude(coreWithout, clocked)
    assert.include(coreWith, clocked)
    assert.notInclude(coreWith, realTime)
    // Un caso por cara en core: el mismo tamaño, sin skip.
    assert.lengthOf(coreWith, coreWithout.length)
    assert.isEmpty(coreWith.filter(exact))

    const fullWithout = register({ ...NONE, listDenies: true }, { level: '2.1' })
    const fullWith = register({ ...NONE, listDenies: true, injectableClock: true }, { level: '2.1' })
    assert.lengthOf(fullWith.filter(exact), 1)
    assert.lengthOf(fullWith.filter(managerClock), 1)
    assert.isEmpty(fullWithout.filter(exact))
    assert.isEmpty(fullWithout.filter(managerClock))
    assert.lengthOf(fullWith, fullWithout.length + 4)
    assert.lengthOf(fullWith, 70)
  })
})
