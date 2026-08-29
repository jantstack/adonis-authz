/**
 * `memoizeAncestors` (Fase 2, lote 2A · A3): memo de UNA instancia sobre el
 * resolutor del consumidor. Sin reloj: vive lo que viva el objeto.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { memoizeAncestors } from '../src/memoize_ancestors.js'
import { APP_SCOPE } from '../src/types.js'
import type { ScopeChainResolver, ScopeRef } from '../src/types.js'

function countingResolver(answer: (scope: ScopeRef) => Promise<ScopeRef[] | null>) {
  const calls: ScopeRef[] = []
  const resolver: ScopeChainResolver = (scope) => {
    calls.push(scope)
    return answer(scope)
  }
  return { calls, resolver }
}

test.group('memoizeAncestors (2A · A3)', () => {
  test('el mismo scope se resuelve una vez; scopes distintos, una vez cada uno', async ({ assert }) => {
    const { calls, resolver } = countingResolver(async () => [APP_SCOPE])
    const memo = memoizeAncestors(resolver)
    const org = { type: 'organization', uuid: uuidv7() }
    const other = { type: 'organization', uuid: uuidv7() }

    for (let i = 0; i < 10; i++) assert.deepEqual(await memo(org), [APP_SCOPE])
    assert.lengthOf(calls, 1)
    assert.deepEqual(await memo(other), [APP_SCOPE])
    assert.lengthOf(calls, 2)
    // Mismo uuid con otro tipo es OTRO scope.
    await memo({ type: 'unit', uuid: org.uuid })
    assert.lengthOf(calls, 3)
  })

  test('`null` (scope desconocido) también se memoiza', async ({ assert }) => {
    const { calls, resolver } = countingResolver(async () => null)
    const memo = memoizeAncestors(resolver)
    const org = { type: 'organization', uuid: uuidv7() }
    assert.isNull(await memo(org))
    assert.isNull(await memo(org))
    assert.lengthOf(calls, 1)
  })

  test('un resolutor que lanza no deja nada memoizado: la siguiente pregunta reintenta', async ({
    assert,
  }) => {
    let fail = true
    const { calls, resolver } = countingResolver(async () => {
      if (fail) throw new Error('árbol caído')
      return [APP_SCOPE]
    })
    const memo = memoizeAncestors(resolver)
    const org = { type: 'organization', uuid: uuidv7() }
    await assert.rejects(() => memo(org), /árbol caído/)
    fail = false
    assert.deepEqual(await memo(org), [APP_SCOPE])
    assert.deepEqual(await memo(org), [APP_SCOPE])
    assert.lengthOf(calls, 2)
  })

  test('dos memos sobre el mismo resolutor son independientes', async ({ assert }) => {
    const { calls, resolver } = countingResolver(async () => [APP_SCOPE])
    const a = memoizeAncestors(resolver)
    const b = memoizeAncestors(resolver)
    const org = { type: 'organization', uuid: uuidv7() }
    await a(org)
    await a(org)
    await b(org)
    assert.lengthOf(calls, 2)
  })

  test('las preguntas concurrentes por el mismo scope comparten una llamada', async ({ assert }) => {
    const { calls, resolver } = countingResolver(async () => [APP_SCOPE])
    const memo = memoizeAncestors(resolver)
    const org = { type: 'organization', uuid: uuidv7() }
    await Promise.all(Array.from({ length: 5 }, () => memo(org)))
    assert.lengthOf(calls, 1)
  })
})
