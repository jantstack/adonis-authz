/**
 * `hierarchicalScopeResolver` (2.1, B4): un `ScopeAncestorsResolver` a partir
 * de un `parentOf` del consumidor. Lo que se fija aquí es lo que NO puede
 * hacer: truncar una cadena (perdería el deny de la raíz: fail-open), cerrar
 * un ciclo en silencio, o convertir un fallo del consumidor en `[]`.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { hierarchicalScopeResolver } from '../src/hierarchical_resolver.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { APP_SCOPE } from '../src/types.js'
import type { ScopeRef } from '../src/types.js'

const key = (s: ScopeRef) => `${s.type}:${s.uuid ?? ''}`

async function rejectsWith(assert: any, fn: () => Promise<unknown>, expected: { status: number; code: string }) {
  try {
    await fn()
  } catch (error: any) {
    assert.equal(error?.status, expected.status, `status de ${error?.message ?? error}`)
    assert.equal(error?.code, expected.code, `code de ${error?.message ?? error}`)
    return
  }
  assert.fail('debería haber rechazado')
}

test.group('hierarchicalScopeResolver (2B · B4)', () => {
  const org: ScopeRef = { type: 'organization', uuid: uuidv7() }
  const unit: ScopeRef = { type: 'unit', uuid: uuidv7() }
  const team: ScopeRef = { type: 'team', uuid: uuidv7() }

  /** team → unit → org → (null = raíz). Lo demás es desconocido. */
  const parents = new Map<string, ScopeRef | null>([
    [key(org), null],
    [key(unit), org],
    [key(team), unit],
  ])
  const parentOf = async (scope: ScopeRef) => parents.get(key(scope))

  test('cadena de 3 niveles, ordenada del más cercano a la raíz, terminada en app', async ({ assert }) => {
    const resolve = hierarchicalScopeResolver({ parentOf })
    assert.deepEqual(await resolve(team), [unit, org, APP_SCOPE])
    assert.deepEqual(await resolve(unit), [org, APP_SCOPE])
    assert.deepEqual(await resolve(org), [APP_SCOPE])
    // La raíz nunca se pregunta: sus ancestros son [] por definición.
    let asked = 0
    const counting = hierarchicalScopeResolver({
      parentOf: async (s) => {
        asked += 1
        return parentOf(s)
      },
    })
    assert.deepEqual(await counting(APP_SCOPE), [])
    assert.equal(asked, 0)
  })

  test('parentOf → undefined es scope desconocido ⇒ null (también a mitad de cadena); un padre `app` explícito termina', async ({
    assert,
  }) => {
    const resolve = hierarchicalScopeResolver({ parentOf })
    assert.isNull(await resolve({ type: 'organization', uuid: uuidv7() }))
    // Un hijo cuyo padre el consumidor ya no conoce: el árbol está roto ahí
    // y se deniega (fail-closed), no se "cuelga de app".
    const orphan: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const broken = hierarchicalScopeResolver({
      parentOf: async (s) => (key(s) === key(orphan) ? { type: 'organization', uuid: uuidv7() } : undefined),
    })
    assert.isNull(await broken(orphan))
    // `parentOf → APP_SCOPE` equivale a `null`.
    const explicit = hierarchicalScopeResolver({ parentOf: async (s) => (key(s) === key(org) ? APP_SCOPE : parentOf(s)) })
    assert.deepEqual(await explicit(unit), [org, APP_SCOPE])
  })

  test('un ciclo A→B→A lanza 422 E_AUTHZ_SCOPE_CYCLE, nunca una cadena', async ({ assert }) => {
    const a: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const b: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const cyclic = new Map([[key(a), b], [key(b), a]])
    const resolve = hierarchicalScopeResolver({ parentOf: async (s) => cyclic.get(key(s)) })
    await rejectsWith(assert, () => resolve(a), { status: 422, code: 'E_AUTHZ_SCOPE_CYCLE' })
    // Un scope que es su propio padre también.
    const self = hierarchicalScopeResolver({ parentOf: async (s) => s })
    await rejectsWith(assert, () => self(a), { status: 422, code: 'E_AUTHZ_SCOPE_CYCLE' })
  })

  test('maxDepth (default 64) superado ⇒ lanza E_AUTHZ_SCOPE_TOO_DEEP; exactamente 64 se resuelve entera', async ({
    assert,
  }) => {
    // Truncar devolvería una cadena sin la raíz: un deny en `app` dejaría de
    // verse (fail-open). Se lanza, y el caso afirma que NO hay cadena corta.
    function chainOf(length: number): { leaf: ScopeRef; parentOf: (s: ScopeRef) => Promise<ScopeRef | null | undefined> } {
      const nodes: ScopeRef[] = Array.from({ length }, (_, i) => ({ type: 'level', uuid: `${i}`.padStart(8, '0') }))
      const map = new Map<string, ScopeRef | null>()
      nodes.forEach((n, i) => map.set(key(n), i === 0 ? null : nodes[i - 1]))
      return { leaf: nodes[length - 1], parentOf: async (s) => map.get(key(s)) }
    }
    const exact = chainOf(64)
    const okChain = await hierarchicalScopeResolver({ parentOf: exact.parentOf })(exact.leaf)
    assert.lengthOf(okChain!, 64) // 63 ancestros + app
    assert.deepEqual(okChain!.at(-1), APP_SCOPE)

    const deep = chainOf(65)
    await rejectsWith(assert, () => hierarchicalScopeResolver({ parentOf: deep.parentOf })(deep.leaf), {
      status: 500,
      code: 'E_AUTHZ_SCOPE_TOO_DEEP',
    })
    // Con una cota más corta, lo mismo; y con una más larga, resuelve.
    await rejectsWith(assert, () => hierarchicalScopeResolver({ parentOf: exact.parentOf, maxDepth: 10 })(exact.leaf), {
      status: 500,
      code: 'E_AUTHZ_SCOPE_TOO_DEEP',
    })
    assert.lengthOf((await hierarchicalScopeResolver({ parentOf: deep.parentOf, maxDepth: 65 })(deep.leaf))!, 65)
    assert.throws(() => hierarchicalScopeResolver({ parentOf, maxDepth: 0 }))
  })

  test('parentOf que lanza propaga tal cual; a través de un driver es 503 E_AUTHZ_RESOLVER_FAILED, nunca false ni []', async ({
    assert,
  }) => {
    const boom = new Error('el árbol del consumidor está caído')
    const resolve = hierarchicalScopeResolver({
      parentOf: async (s) => {
        if (key(s) === key(unit)) throw boom
        return parentOf(s)
      },
    })
    let caught: unknown
    try {
      await resolve(team)
    } catch (error) {
      caught = error
    }
    assert.strictEqual(caught, boom)

    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
    const driver = new DatabaseAuthorizationDriver({ resolveAncestors: resolve })
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    await rejectsWith(assert, () => driver.authorize(alice, 'docs:read', team), { status: 503, code: 'E_AUTHZ_RESOLVER_FAILED' })
    // Y con el árbol sano, la cadena de 3 hereda de app.
    assert.isTrue(await new DatabaseAuthorizationDriver({ resolveAncestors: hierarchicalScopeResolver({ parentOf }) }).authorize(alice, 'docs:read', team))
  })
})
