/**
 * El conteo del runner de la outbox, ejecutable (análogo a
 * `relations_harness.spec.ts`). Registra el contrato contra una API falsa
 * que solo cuenta, y afirma:
 *  - el nº LITERAL de casos por harness (núcleo + una cara por capacidad);
 *  - que TODA capacidad quedó cubierta (ninguna cara ausente = ningún skip);
 *  - que un harness `true` y uno `false` eligen caras DISTINTAS (mismo total);
 *  - que una capacidad `true` sin su soporte se RECHAZA al registrar.
 */
import { test } from '@japa/runner'
import {
  makeScopeOutbox,
  registerScopeOutboxContract,
  SCOPE_OUTBOX_CAPABILITY_KEYS,
} from '../src/testing/scope_outbox_contract.js'
import type { ScopeOutboxCapabilities, ScopeOutboxContractHarness } from '../src/testing/scope_outbox_contract.js'

const FULL: ScopeOutboxCapabilities = {
  transactionalEnqueue: false, // el doble no escribe por ninguna transacción
  filter: true,
  transient: true,
  dead: true,
  acquire: true,
  earlierPending: true,
  requeue: true,
  createdAt: true,
}
const MINIMAL: ScopeOutboxCapabilities = {
  transactionalEnqueue: false,
  filter: false,
  transient: false,
  dead: false,
  acquire: false,
  earlierPending: false,
  requeue: false,
  createdAt: false,
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

function register(capabilities: ScopeOutboxCapabilities, over: Partial<ScopeOutboxContractHarness> = {}) {
  const { api, titles } = fakeApi()
  const result = registerScopeOutboxContract(
    {
      name: 'harness-de-conteo',
      capabilities,
      limits: capabilities.dead ? { maxAttempts: 3 } : undefined,
      makeOutbox: () => makeScopeOutbox({ capabilities, maxAttempts: 3 }),
      ...over,
    },
    api as any
  )
  return { titles, ...result }
}

// 9 núcleo (O-01 recibo, O-02 orden/identidad/actor, O-03 after, O-04 markApplied,
// O-05 markFailed, O-06 el manager drena, O-07 aplaza por clave, O-07b la raíz
// `app` NO es clave —2.4.0-alpha.8—, O-08 `pending()` no esconde filas —cierre
// alpha.5, 🟡 3 del auditor—) + 1 cara por cada una de las 8 capacidades
// (`createdAt` desde 2.4.0-alpha.8: la edad de la cola) = 17.
const EXPECTED_CASES = 17
const CAPABILITY_KEYS = 8

test.group('runner de la outbox — conteo y cobertura de capacidades', () => {
  test('un harness FULL registra el nº literal de casos y cubre las 8 capacidades', ({ assert }) => {
    const { registered, covered, titles } = register(FULL)
    assert.equal(registered, EXPECTED_CASES)
    assert.equal(titles.length, EXPECTED_CASES)
    assert.equal(covered.size, CAPABILITY_KEYS)
    assert.lengthOf(SCOPE_OUTBOX_CAPABILITY_KEYS, CAPABILITY_KEYS)
  })

  test('un harness MÍNIMO registra el MISMO total y también cubre las 8', ({ assert }) => {
    const { registered, covered } = register(MINIMAL)
    assert.equal(registered, EXPECTED_CASES)
    assert.equal(covered.size, CAPABILITY_KEYS)
  })

  test('true y false eligen caras DISTINTAS de cada capacidad (no un skip)', ({ assert }) => {
    const full = register(FULL).titles
    const min = register(MINIMAL).titles
    for (const key of SCOPE_OUTBOX_CAPABILITY_KEYS.filter((k) => k !== 'transactionalEnqueue')) {
      const a = full.find((t) => t.startsWith(`${key}:true`))
      const b = min.find((t) => t.startsWith(`${key}:false`))
      assert.isDefined(a, `${key}: cara true`)
      assert.isDefined(b, `${key}: cara false`)
      assert.notEqual(a, b)
    }
    assert.isDefined(min.find((t) => t.startsWith('transactionalEnqueue:false')))
  })

  test('una capacidad `true` sin su soporte se RECHAZA al registrar (dead sin maxAttempts, requeue sin dead, transactionalEnqueue sin transactions, un valor no booleano)', ({
    assert,
  }) => {
    assert.throws(() => register(FULL, { limits: undefined }), /maxAttempts/)
    assert.throws(() => register({ ...MINIMAL, requeue: true }), /requeue: true/)
    assert.throws(() => register({ ...MINIMAL, transactionalEnqueue: true }), /transactions/)
    assert.throws(() => register({ ...MINIMAL, filter: 'sí' as any }), /booleano/)
    assert.throws(() => makeScopeOutbox({ capabilities: { ...MINIMAL, transactionalEnqueue: true } }), /transactionalEnqueue: false/)
  })
})
