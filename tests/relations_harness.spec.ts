/**
 * El conteo del runner de relaciones, ejecutable (análogo a
 * `contract_harness.spec.ts`, pero SEPARADO — no toca los conteos de roles).
 * Registra el contrato contra una API falsa que solo cuenta, y afirma:
 *  - el nº LITERAL de casos por harness (núcleo + una cara por capacidad);
 *  - que TODA capacidad quedó cubierta (ninguna cara ausente = ningún skip);
 *  - que un harness `true` y uno `false` eligen caras DISTINTAS (mismo total).
 */
import { test } from '@japa/runner'
import { registerRelationsDriverContract, makeRelationsDriver } from '../src/testing/relations_contract.js'
import type { RelationsDriverCapabilities } from '../src/types.js'

const FULL: RelationsDriverCapabilities = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: true,
}
const MINIMAL: RelationsDriverCapabilities = {
  singleCheckRelations: false,
  listObjectsInherited: false,
  usersetSubjects: false,
  membersOfNative: false,
  enumerateRelations: false,
  listObjectsTruncation: false,
}

function fakeApi() {
  const titles: string[] = []
  return {
    titles,
    api: {
      group: (_t: string, define: any) => define({ each: { setup: () => {} }, teardown: () => {} }),
      test: (title: string) => {
        titles.push(title)
        return { timeout: () => {} }
      },
    },
  }
}

function register(capabilities: RelationsDriverCapabilities) {
  const { api, titles } = fakeApi()
  const result = registerRelationsDriverContract(
    {
      name: 'harness-de-conteo',
      capabilities,
      limits: { listMaxResults: 3 },
      makeDriver: (config) => makeRelationsDriver({ config, capabilities, limits: { listMaxResults: 3 } }),
    },
    api as any
  )
  return { titles, ...result }
}

// 11 núcleo (R-01, R-02, R-03/04, R-05, R-06, R-07/08, R-09, R-12, F-05 tipo,
// F-05 relación, R-13) + 1 cara por cada una de las 6 capacidades = 17.
const EXPECTED_CASES = 17
const CAPABILITY_KEYS = 6

test.group('runner de relaciones — conteo y cobertura de capacidades', () => {
  test('un harness FULL registra el nº literal de casos y cubre las 6 capacidades', ({ assert }) => {
    const { registered, covered, titles } = register(FULL)
    assert.equal(registered, EXPECTED_CASES)
    assert.equal(titles.length, EXPECTED_CASES)
    assert.equal(covered.size, CAPABILITY_KEYS)
  })

  test('un harness MÍNIMO registra el MISMO total y también cubre las 6', ({ assert }) => {
    const { registered, covered } = register(MINIMAL)
    assert.equal(registered, EXPECTED_CASES)
    assert.equal(covered.size, CAPABILITY_KEYS)
  })

  test('true y false eligen caras DISTINTAS de membersOfNative (no un skip)', ({ assert }) => {
    const full = register(FULL).titles.find((t) => t.startsWith('membersOfNative'))
    const min = register(MINIMAL).titles.find((t) => t.startsWith('membersOfNative'))
    assert.include(full, 'TRANSITIVA')
    assert.include(min, 'E_AUTHZ_UNSUPPORTED')
    assert.notEqual(full, min)
  })
})
