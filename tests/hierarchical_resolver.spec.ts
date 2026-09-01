/**
 * `hierarchicalScopeResolver` (2.1, B4; 2.5-B · K1): un `ScopeChainResolver`
 * a partir de un `nodeOf` del consumidor (la fila: el nodo canónico y su
 * padre). Lo que se fija aquí es lo que NO puede hacer: truncar una cadena
 * (perdería el deny de la raíz: fail-open), cerrar un ciclo en silencio,
 * convertir un fallo del consumidor en `[]`, o devolver como elemento 0 algo
 * que no sea la fila del scope pedido.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { hierarchicalScopeResolver } from '../src/hierarchical_resolver.js'
import type { NodeOf } from '../src/hierarchical_resolver.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
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

/** Un `nodeOf` a partir de un mapa hijo → padre (`null` = primer nivel); lo que no está es desconocido. */
function nodeOfMap(parents: Map<string, ScopeRef | null>, nodes: ScopeRef[]): NodeOf {
  const byKey = new Map(nodes.map((n) => [key(n), n]))
  return async (scope) => {
    const self = byKey.get(key(scope))
    if (!self || !parents.has(key(scope))) return undefined
    return { self, parent: parents.get(key(scope))! }
  }
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
  const nodeOf = nodeOfMap(parents, [org, unit, team])

  test('cadena de 3 niveles: el propio scope, los ancestros del más cercano a la raíz y app al final', async ({ assert }) => {
    const resolve = hierarchicalScopeResolver({ nodeOf })
    assert.deepEqual(await resolve(team), [team, unit, org, APP_SCOPE])
    assert.deepEqual(await resolve(unit), [unit, org, APP_SCOPE])
    assert.deepEqual(await resolve(org), [org, APP_SCOPE])
    // La raíz nunca se pregunta: su cadena es [app] por definición.
    let asked = 0
    const counting = hierarchicalScopeResolver({
      nodeOf: async (s) => {
        asked += 1
        return nodeOf(s)
      },
    })
    assert.deepEqual(await counting(APP_SCOPE), [APP_SCOPE])
    assert.equal(asked, 0)
  })

  test('nodeOf → undefined es scope desconocido ⇒ null (también a mitad de cadena); un padre `app` explícito termina', async ({
    assert,
  }) => {
    const resolve = hierarchicalScopeResolver({ nodeOf })
    assert.isNull(await resolve({ type: 'organization', uuid: uuidv7() }))
    // Un hijo cuyo padre el consumidor ya no conoce: el árbol está roto ahí
    // y se deniega (fail-closed), no se "cuelga de app".
    const orphan: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const broken = hierarchicalScopeResolver({
      nodeOf: async (s) => (key(s) === key(orphan) ? { self: orphan, parent: { type: 'organization', uuid: uuidv7() } } : undefined),
    })
    assert.isNull(await broken(orphan))
    // `parent: APP_SCOPE` equivale a `null`.
    const explicit = hierarchicalScopeResolver({
      nodeOf: async (s) => (key(s) === key(org) ? { self: org, parent: APP_SCOPE } : nodeOf(s)),
    })
    assert.deepEqual(await explicit(unit), [unit, org, APP_SCOPE])
  })

  test('K1: el elemento 0 es la FILA (canónica), no lo que llegó: un alias del uuid (mayúsculas/guiones que el motor del consumidor funde) resuelve a la identidad real', async ({
    assert,
  }) => {
    // 2.5-B · K1 (auditor 🔴 1). Un `SELECT … WHERE uuid = ?` sobre una
    // columna `uuid` de PG encuentra la fila para `BBBB…` o para el id sin
    // guiones; antes el resolutor solo devolvía el padre y la cadena se
    // construía con el alias del llamante, así que los hechos —guardados
    // canónicos— no casaban. Aquí el "motor" es un mapa que canoniza.
    const canonical: ScopeRef = { type: 'unit', uuid: 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb' }
    const fold = (uuid: string) => uuid.toLowerCase().replaceAll('-', '')
    const folding = hierarchicalScopeResolver({
      nodeOf: async (s) => {
        if (s.type === 'unit' && fold(s.uuid!) === fold(canonical.uuid!)) return { self: canonical, parent: org }
        return nodeOf(s)
      },
    })
    for (const alias of [canonical.uuid!, canonical.uuid!.toUpperCase(), canonical.uuid!.replaceAll('-', ''), canonical.uuid!.replaceAll('-', '').toUpperCase()]) {
      assert.deepEqual(await folding({ type: 'unit', uuid: alias }), [canonical, org, APP_SCOPE], alias)
    }
    // Y un `self` que NO es el scope pedido (otro tipo, otro id) es un fallo
    // del resolutor: 503, nunca una cadena con otra identidad.
    const expected = { status: 503, code: 'E_AUTHZ_RESOLVER_FAILED' }
    const otherId = hierarchicalScopeResolver({ nodeOf: async () => ({ self: { type: 'unit', uuid: uuidv7() }, parent: org }) })
    await rejectsWith(assert, () => otherId(unit), expected)
    const otherType = hierarchicalScopeResolver({ nodeOf: async (s) => ({ self: { type: 'organization', uuid: s.uuid }, parent: null }) })
    await rejectsWith(assert, () => otherType(unit), expected)
    // También a mitad de cadena: el padre devuelto tiene que ser la fila del padre pedido.
    const badParentRow = hierarchicalScopeResolver({
      nodeOf: async (s) => (key(s) === key(unit) ? { self: unit, parent: org } : { self: team, parent: null }),
    })
    await rejectsWith(assert, () => badParentRow(unit), expected)
  })

  test('F6: la clave de visitados lleva separador: `org`+`a-1` y `o`+`rga-1` son scopes distintos, no un ciclo', async ({
    assert,
  }) => {
    // CR4 / auditor 10: `${type}${uuid}` colisionaba y un árbol legítimo
    // era un 422 falso de ciclo.
    const nodeOfSeparated: NodeOf = async (s) => {
      if (s.type === 'org' && s.uuid === 'a-1') return { self: s, parent: { type: 'o', uuid: 'rga-1' } }
      if (s.type === 'o' && s.uuid === 'rga-1') return { self: s, parent: null }
      return undefined
    }
    const resolve = hierarchicalScopeResolver({ nodeOf: nodeOfSeparated })
    assert.deepEqual(await resolve({ type: 'org', uuid: 'a-1' }), [{ type: 'org', uuid: 'a-1' }, { type: 'o', uuid: 'rga-1' }, APP_SCOPE])
  })

  test('F6: un padre o un self mal formado devuelto por nodeOf ({app, uuid}, tipo en mayúsculas, uuid con separador, un no-nodo) es 503 E_AUTHZ_RESOLVER_FAILED, nunca se normaliza en silencio', async ({
    assert,
  }) => {
    // Antes `{ type: 'app', uuid: 'X' }` se tomaba por la raíz y la cadena
    // terminaba ahí: una identidad ilegal en el resto del motor se aceptaba
    // como padre. La RESPUESTA del árbol se valida como la de
    // `resolveChain` (D13): fallo de la dependencia ⇒ 503.
    const expected = { status: 503, code: 'E_AUTHZ_RESOLVER_FAILED' }
    for (const bad of [{ type: 'app', uuid: 'X' }, { type: 'Organization', uuid: uuidv7() }, { type: 'organization', uuid: 'a|b' }, { type: 'organization' }, 'app']) {
      const asParent = hierarchicalScopeResolver({ nodeOf: async (s) => ({ self: s, parent: bad as any }) })
      await rejectsWith(assert, () => asParent(unit), expected)
      const asSelf = hierarchicalScopeResolver({ nodeOf: async () => ({ self: bad as any, parent: null }) })
      await rejectsWith(assert, () => asSelf(unit), expected)
    }
    for (const notNode of [null, 'unit', 42, { parent: null }, { self: unit }]) {
      const broken = hierarchicalScopeResolver({ nodeOf: async () => notNode as any })
      await rejectsWith(assert, () => broken(unit), expected)
    }
    // Y a través de un driver sigue siendo 503, nunca false.
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
    const driver = new DatabaseAuthorizationDriver({
      resolveChain: hierarchicalScopeResolver({ nodeOf: async (s) => ({ self: s, parent: { type: 'app', uuid: 'X' } }) }),
    })
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    await rejectsWith(assert, () => driver.authorize(alice, 'docs:read', unit), expected)
  })

  test('un ciclo A→B→A lanza 422 E_AUTHZ_SCOPE_CYCLE, nunca una cadena', async ({ assert }) => {
    const a: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const b: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const cyclic = new Map([[key(a), b], [key(b), a]])
    const resolve = hierarchicalScopeResolver({ nodeOf: async (s) => ({ self: s, parent: cyclic.get(key(s))! }) })
    await rejectsWith(assert, () => resolve(a), { status: 422, code: 'E_AUTHZ_SCOPE_CYCLE' })
    // Un scope que es su propio padre también.
    const self = hierarchicalScopeResolver({ nodeOf: async (s) => ({ self: s, parent: s }) })
    await rejectsWith(assert, () => self(a), { status: 422, code: 'E_AUTHZ_SCOPE_CYCLE' })
  })

  test('maxDepth (default 64) superado ⇒ lanza E_AUTHZ_SCOPE_TOO_DEEP; exactamente 64 ancestros se resuelven enteros', async ({
    assert,
  }) => {
    // Truncar devolvería una cadena sin la raíz: un deny en `app` dejaría de
    // verse (fail-open). Se lanza, y el caso afirma que NO hay cadena corta.
    function chainOf(length: number): { leaf: ScopeRef; nodeOf: NodeOf } {
      const nodes: ScopeRef[] = Array.from({ length }, (_, i) => ({ type: 'level', uuid: `${i}`.padStart(8, '0') }))
      const map = new Map<string, ScopeRef | null>()
      nodes.forEach((n, i) => map.set(key(n), i === 0 ? null : nodes[i - 1]))
      return { leaf: nodes[length - 1], nodeOf: nodeOfMap(map, nodes) }
    }
    const exact = chainOf(64)
    const okChain = await hierarchicalScopeResolver({ nodeOf: exact.nodeOf })(exact.leaf)
    assert.lengthOf(okChain!, 65) // el propio scope + 63 ancestros + app
    assert.deepEqual(okChain![0], exact.leaf)
    assert.deepEqual(okChain!.at(-1), APP_SCOPE)

    const deep = chainOf(65)
    await rejectsWith(assert, () => hierarchicalScopeResolver({ nodeOf: deep.nodeOf })(deep.leaf), {
      status: 500,
      code: 'E_AUTHZ_SCOPE_TOO_DEEP',
    })
    // Con una cota más corta, lo mismo; y con una más larga, resuelve.
    await rejectsWith(assert, () => hierarchicalScopeResolver({ nodeOf: exact.nodeOf, maxDepth: 10 })(exact.leaf), {
      status: 500,
      code: 'E_AUTHZ_SCOPE_TOO_DEEP',
    })
    assert.lengthOf((await hierarchicalScopeResolver({ nodeOf: deep.nodeOf, maxDepth: 65 })(deep.leaf))!, 66)
    assert.throws(() => hierarchicalScopeResolver({ nodeOf, maxDepth: 0 }))
  })

  test('nodeOf que lanza propaga tal cual; a través de un driver es 503 E_AUTHZ_RESOLVER_FAILED, nunca false ni []', async ({
    assert,
  }) => {
    const boom = new Error('el árbol del consumidor está caído')
    const resolve = hierarchicalScopeResolver({
      nodeOf: async (s) => {
        if (key(s) === key(unit)) throw boom
        return nodeOf(s)
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
    const driver = new DatabaseAuthorizationDriver({ resolveChain: resolve })
    const alice = { type: 'users', uuid: uuidv7() }
    await driver.grant(alice, 'editor', APP_SCOPE)
    await rejectsWith(assert, () => driver.authorize(alice, 'docs:read', team), { status: 503, code: 'E_AUTHZ_RESOLVER_FAILED' })
    // Y con el árbol sano, la cadena de 3 hereda de app.
    assert.isTrue(await new DatabaseAuthorizationDriver({ resolveChain: hierarchicalScopeResolver({ nodeOf }) }).authorize(alice, 'docs:read', team))
  })
})
