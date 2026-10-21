/**
 * **El doble FIEL del cliente OpenFGA y su planificador** (lote C · sublote «asentar», paso 1): cada punto de fidelidad
 * que promete `tests/helpers/fga_memory_client.ts` tiene aquí su caso, para que la propiedad
 * `openfga.roles.visibility.settle` (y la de `openfga.roles.moved.order`, migrada a este doble) no se apoye en un doble
 * que miente. Sin servidor.
 */
import { classifyFgaFailure } from '../src/shared/backend_guard.js'
import { test } from '@japa/runner'
import { OpenFgaAuthorizationDriver, isDuplicateWrite } from '../src/drivers/openfga_driver.js'
import { factsParentTuple } from '../src/drivers/openfga_facts.js'
import { AuthorizationBackendError } from '../src/errors.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { checkTuples, TupleStore } from './helpers/fga_interpreter.js'
import {
  FgaMemoryStore,
  installMemoryClient,
  pctPolicy,
  preemptPolicy,
  runScheduled,
  sdkError,
  seededRandom,
  type IoEvent,
} from './helpers/fga_memory_client.js'
import { generatedModel, TEST_MODEL_ID } from './helpers/fga_model.js'

const HOLDERS = { users: 'user' }
const model = () => generatedModel(HOLDERS, ['docs:read'])
const t = (object: string, relation: string, user: string) => ({ object, relation, user })
/** Cadena `n0 ⊂ n1 ⊂ … ⊂ n<depth> ⊂ app`: `n0` está a `depth + 1` saltos de `app`. */
const chainTuples = (depth: number) => [
  ...Array.from({ length: depth }, (_, i) => factsParentTuple(`unit|n${i}`, `unit|n${i + 1}`)),
  factsParentTuple(`unit|n${depth}`, 'app'),
]
const ids = (store: FgaMemoryStore) => store.tuples().map((x) => `${x.object}#${x.relation}@${x.user}`).sort()

test.group('fga_memory_client · (a) conflictos con la forma del SDK', () => {
  test('duplicado y borrado ausente lanzan la forma MEDIDA y rechazan el Write ENTERO', async ({ assert }) => {
    const store = new FgaMemoryStore({ model: model(), initial: [t('scope:unit|a', 'parent', 'scope:app')] })
    const client = store.client('x')
    const before = ids(store)
    const dup: any = await client.write({ writes: [t('scope:unit|b', 'parent', 'scope:app'), t('scope:unit|a', 'parent', 'scope:app')], deletes: [] }).catch((e) => e)
    assert.equal(dup.statusCode, 400)
    assert.equal(dup.apiErrorCode, 'write_failed_due_to_invalid_input')
    assert.isTrue(isDuplicateWrite(dup), 'el driver lo reconoce como carrera')
    assert.deepEqual(ids(store), before, 'nada se aplica (la tupla nueva del mismo Write tampoco)')
    const missing: any = await client.write({ writes: [], deletes: [t('scope:unit|z', 'parent', 'scope:app')] }).catch((e) => e)
    assert.equal(missing.apiErrorCode, 'write_failed_due_to_invalid_input')
    assert.match(String(missing.apiErrorMessage), /does not exist/)
    assert.deepEqual(ids(store), before)
  })

  test('onDuplicateWrites y onMissingDeletes se honran POR SEPARADO (el doble de F4 los juntaba)', async ({ assert }) => {
    const store = new FgaMemoryStore({ model: model(), initial: [t('scope:unit|a', 'parent', 'scope:app')] })
    const client = store.client('x')
    const body = { writes: [t('scope:unit|a', 'parent', 'scope:app')], deletes: [t('scope:unit|z', 'parent', 'scope:app')] }
    const onlyDup: any = await client.write(body, { conflict: { onDuplicateWrites: 'ignore' } }).catch((e) => e)
    assert.match(String(onlyDup?.apiErrorMessage), /does not exist/, 'ignorar duplicados NO ignora borrados ausentes')
    const onlyMissing: any = await client.write(body, { conflict: { onMissingDeletes: 'ignore' } }).catch((e) => e)
    assert.match(String(onlyMissing?.apiErrorMessage), /already exists/, 'ignorar ausentes NO ignora duplicados')
    await client.write(body, { conflict: { onDuplicateWrites: 'ignore', onMissingDeletes: 'ignore' } })
    assert.deepEqual(ids(store), ['scope:unit|a#parent@scope:app'])
  })

  test('más de 100 tuplas en un Write ⇒ el 400 del servidor, sin aplicar nada', async ({ assert }) => {
    const store = new FgaMemoryStore({ model: model() })
    const writes = Array.from({ length: 101 }, (_, i) => t(`scope:unit|k${i}`, 'parent', 'scope:app'))
    const error: any = await store.client('x').write({ writes, deletes: [] }).catch((e) => e)
    assert.equal(error.statusCode, 400)
    assert.equal(error.apiErrorCode, (sdkError('real-write-exceeded-entity-limit') as any).apiErrorCode)
    assert.lengthOf(store.tuples(), 0)
  })
})

test.group('fga_memory_client · (b)(c) Check por el intérprete, ancestor salto a salto, cota de profundidad', () => {
  test('check y batchCheck de ancestor = el intérprete, a 1/4/20/26/27/30 saltos y con dos padres', async ({ assert }) => {
    const store = new FgaMemoryStore({ model: model(), initial: [...chainTuples(30), factsParentTuple('unit|n3', 'unit|side'), factsParentTuple('unit|side', 'app')] })
    const client = store.client('x')
    const state = new TupleStore(store.tuples())
    for (const d of [1, 4, 20, 26, 27, 30]) {
      for (const [user, object] of [[`scope:unit|n${d}`, 'scope:unit|n0'], ['scope:app', `scope:unit|n${d}`], ['scope:unit|zz', `scope:unit|n${d}`], ['scope:unit|side', 'scope:unit|n0']]) {
        const expected = checkTuples(store.model, state, { user, relation: 'ancestor', object }).verdict === 'T'
        assert.equal((await client.check({ user, relation: 'ancestor', object })).allowed, expected, `${object} ancestor ${user}`)
        const batch = await client.batchCheck({ checks: [{ user, relation: 'ancestor', object, correlationId: '1' }] })
        assert.equal(batch.result[0].allowed, expected)
      }
    }
  })

  test('ancestor CEDE en cada salto (d − 1 puntos tras el del Check) y ve un movimiento ENTRE saltos (Check rasgado)', async ({ assert }) => {
    const store = new FgaMemoryStore({ model: model(), initial: chainTuples(6) })
    const hops: IoEvent[] = []
    const client = store.client('x', { onIo: (e) => void (e.kind === 'check-hop' && hops.push(e)) })
    assert.isTrue((await client.check({ user: 'scope:unit|n6', relation: 'ancestor', object: 'scope:unit|n0' })).allowed)
    assert.lengthOf(hops, 5, 'n6 está a 6 saltos: 1 del Check + 5 cedidos')
    // Otro escritor desengancha n4 de n5 mientras el Check va por n2: el paseo lo ve (un Check real no es una foto).
    const mover = store.client('y')
    const torn = store.client('x', {
      onIo: async (e) => {
        if (e.kind === 'check-hop' && e.k === 3) await mover.write({ writes: [factsParentTuple('unit|n4', 'app')], deletes: [factsParentTuple('unit|n4', 'unit|n5')] })
      },
    })
    assert.isFalse((await torn.check({ user: 'scope:unit|n6', relation: 'ancestor', object: 'scope:unit|n0' })).allowed)
  })

  test('depthLimits (lo medido en M2): la cara verdadera a la cota resuelve y un salto más es el 400 resolution_too_complex (también por ítem de batchCheck); la falsa resuelve', async ({ assert }) => {
    const store = new FgaMemoryStore({ model: model(), initial: chainTuples(30), depthLimits: { ancestor: 26 } })
    const client = store.client('x')
    assert.isTrue((await client.check({ user: 'scope:unit|n26', relation: 'ancestor', object: 'scope:unit|n0' })).allowed)
    const error: any = await client.check({ user: 'scope:unit|n27', relation: 'ancestor', object: 'scope:unit|n0' }).catch((e) => e)
    assert.equal(error.statusCode, 400)
    assert.equal(error.apiErrorCode, 'authorization_model_resolution_too_complex')
    const batch = await client.batchCheck({ checks: [{ user: 'scope:unit|n27', relation: 'ancestor', object: 'scope:unit|n0', correlationId: 'a' }] })
    assert.exists(batch.result[0].error)
    // Asentar · cierre 1: la FORMA del servidor (snake_case, fixture `real-batchcheck-mixed-items`), y el clasificador de
    // producción la lee como límite de resolución — con el camelCase de antes era un 503 y la caída a `storeChain` del
    // settle nunca se ejercía sin servidor.
    assert.equal(batch.result[0].error.input_error, 'authorization_model_resolution_too_complex')
    assert.equal(classifyFgaFailure(batch.result[0].error).kind, 'resolution-limit')
    // M2: la cara FALSA (owner ausente, pasea los 30 saltos hasta la raíz) resuelve; solo la verdadera pasada la cota falla.
    assert.isFalse((await client.check({ user: 'scope:unit|ausente', relation: 'ancestor', object: 'scope:unit|n0' })).allowed)
  })
})

test.group('fga_memory_client · (d) caché, (e) fallos, (f) traza', () => {
  test('staleBy: sin HIGHER se lee el pasado; con HIGHER, lo último (read, check y batchCheck)', async ({ assert }) => {
    const store = new FgaMemoryStore({ model: model(), initial: chainTuples(2), staleBy: 1 })
    const client = store.client('x')
    await client.write({ writes: [factsParentTuple('unit|n1', 'unit|zz')], deletes: [factsParentTuple('unit|n1', 'unit|n2')] })
    const higher = { consistency: 'HIGHER_CONSISTENCY' }
    const minimize = { consistency: 'MINIMIZE_LATENCY' }
    const read = async (o: any) => (await client.read({ object: 'scope:unit|n1', relation: 'parent' }, o)).tuples.map((x: any) => x.key.user)
    assert.deepEqual(await read(minimize), ['scope:unit|n2'])
    assert.deepEqual(await read(higher), ['scope:unit|zz'])
    const q = { user: 'scope:unit|n2', relation: 'ancestor', object: 'scope:unit|n0' }
    assert.isTrue((await client.check(q, minimize)).allowed)
    assert.isFalse((await client.check(q, higher)).allowed)
    assert.isTrue((await client.batchCheck({ checks: [{ ...q, correlationId: '1' }] }, minimize)).result[0].allowed)
  })

  test('fault before: el servidor no lo vio; fault after: aplicado y DESPUÉS el error (deadline vencido)', async ({ assert }) => {
    const store = new FgaMemoryStore({ model: model() })
    const before = store.client('x', { fault: (e) => (e.kind === 'write' && e.k === 1 ? { error: sdkError('fake-503-unavailable') } : undefined) })
    await assert.rejects(() => before.write({ writes: [t('scope:unit|a', 'parent', 'scope:app')], deletes: [] }))
    assert.lengthOf(store.tuples(), 0)
    const after = store.client('y', { fault: (e) => (e.kind === 'write' ? { error: sdkError('fake-504-deadline-exceeded'), when: 'after' } : undefined) })
    await assert.rejects(() => after.write({ writes: [t('scope:unit|a', 'parent', 'scope:app')], deletes: [] }))
    assert.lengthOf(store.tuples(), 1)
    const entry = store.trace.find((e) => e.actor === 'y' && e.kind === 'write')!
    assert.deepEqual(entry.writes, [t('scope:unit|a', 'parent', 'scope:app')], 'la traza lleva las tuplas EFECTIVAS')
    assert.equal(store.trace.find((e) => e.actor === 'x')!.result.startsWith('error:'), true)
  })

  test('installMemoryClient deja el clasificador del driver en medio (503 clasificado; el duplicado sigue siendo carrera)', async ({ assert }) => {
    const store = new FgaMemoryStore({ model: model(), initial: [t('scope:unit|a', 'parent', 'scope:app')] })
    const driver: any = new OpenFgaAuthorizationDriver({
      apiUrl: 'http://127.0.0.1:1',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      modelId: TEST_MODEL_ID,
      holderTypes: HOLDERS,
      resolveChain: resolveChainFrom(memoryScopeTree()),
      acceptScopeDriftRisk: true,
      logger: { warn: () => {} },
    } as any)
    installMemoryClient(driver, store.client('x', { fault: (e) => (e.kind === 'read' ? { error: sdkError('fake-503-unavailable') } : undefined) }))
    const unavailable: any = await driver.client.read({ object: 'scope:unit|a' }).catch((e: unknown) => e)
    assert.instanceOf(unavailable, AuthorizationBackendError)
    assert.equal(unavailable.status, 503)
    const dup: any = await driver.client.write({ writes: [t('scope:unit|a', 'parent', 'scope:app')], deletes: [] }).catch((e: unknown) => e)
    assert.isTrue(isDuplicateWrite(dup), 'tras el guard, la cadena de causas sigue diciendo «ya existe»')
  })
})

test.group('fga_memory_client · planificador cooperativo sembrado', () => {
  const scenario = async (seed: number) => {
    const store = new FgaMemoryStore({ model: model() })
    const actors = ['a', 'b', 'c'].map((id) => ({
      id,
      run: async (onIo: (e: IoEvent) => Promise<void>) => {
        const client = store.client(id, { onIo })
        for (let i = 0; i < 4; i++) await client.write({ writes: [t(`scope:unit|${id}${i}`, 'parent', 'scope:app')], deletes: [] })
      },
    }))
    const result = await runScheduled(actors, pctPolicy(seededRandom(seed), ['a', 'b', 'c'], 2, 12))
    return { order: store.trace.map((e) => e.actor).join(''), switches: result.switches }
  }

  test('misma semilla ⇒ mismo entrelazado; semillas distintas ⇒ entrelazados distintos', async ({ assert }) => {
    const one = await scenario(7)
    assert.deepEqual(await scenario(7), one)
    const orders = new Set<string>()
    for (let seed = 1; seed <= 30; seed++) orders.add((await scenario(seed)).order)
    assert.isAbove(orders.size, 3, 'PCT explora más de un orden')
  })

  test('preempt: el actor 2 corre ENTERO en el I/O k del actor 1; si el 1 acaba antes, no dispara', async ({ assert }) => {
    for (const k of [1, 2, 3]) {
      const store = new FgaMemoryStore({ model: model() })
      const policy = preemptPolicy('a', 'b', k)
      const mk = (id: string, n: number) => ({
        id,
        run: async (onIo: (e: IoEvent) => Promise<void>) => {
          const client = store.client(id, { onIo })
          for (let i = 0; i < n; i++) await client.write({ writes: [t(`scope:unit|${id}${i}`, 'parent', 'scope:app')], deletes: [] })
        },
      })
      await runScheduled([mk('a', 3), mk('b', 2)], policy)
      assert.equal(store.trace.map((e) => e.actor).join(''), 'a'.repeat(k - 1) + 'bb' + 'a'.repeat(3 - k + 1))
      assert.isTrue(policy.fired())
    }
    const store = new FgaMemoryStore({ model: model() })
    const late = preemptPolicy('a', 'b', 9)
    await runScheduled(
      ['a', 'b'].map((id) => ({
        id,
        run: async (onIo: (e: IoEvent) => Promise<void>) => {
          await store.client(id, { onIo }).write({ writes: [t(`scope:unit|${id}`, 'parent', 'scope:app')], deletes: [] })
        },
      })),
      late
    )
    assert.isFalse(late.fired())
  })
})
