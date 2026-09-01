/**
 * `memoryScopeTree` es la pieza sobre la que el juez prueba el invariante 1.
 * Si el árbol de test dejara pasar un ciclo o resolviera mal los ancestros,
 * los casos de herencia pasarían (o fallarían) por la razón equivocada.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { descendantsFrom, memoryScopeTree } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import type { ScopeRef } from '../src/types.js'

const org = (): ScopeRef => ({ type: 'organization', uuid: uuidv7() })
const unit = (): ScopeRef => ({ type: 'unit', uuid: uuidv7() })

test.group('memoryScopeTree', () => {
  test('la clave interna no confunde scopes cuyo tipo y uuid concatenan igual', async ({ assert }) => {
    // `a:b`+`c` y `a`+`b:c` serían la misma cadena con un separador ingenuo;
    // el árbol tiene que verlos como dos nodos distintos.
    const tree = memoryScopeTree()
    const left: ScopeRef = { type: 'a:b', uuid: 'c' }
    const right: ScopeRef = { type: 'a', uuid: 'b:c' }
    await tree.attach(left, APP_SCOPE)
    assert.deepEqual(await tree.chainOf(left), [left, APP_SCOPE])
    assert.isNull(await tree.chainOf(right))
  })

  test('chainOf empieza por el propio nodo y sube hasta app, del más cercano a la raíz', async ({ assert }) => {
    const tree = memoryScopeTree()
    const o = org()
    const u = unit()
    await tree.attach(o, APP_SCOPE)
    await tree.attach(u, o)

    assert.deepEqual(await tree.chainOf(u), [u, o, APP_SCOPE])
    assert.deepEqual(await tree.chainOf(o), [o, APP_SCOPE])
    assert.deepEqual(await tree.chainOf(APP_SCOPE), [APP_SCOPE])
  })

  test('un scope que nunca se colgó es desconocido (null), no huérfano de app', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    assert.isNull(await tree.chainOf(org()))
  })

  test('attach de un hijo ya existente equivale a move', async ({ assert }) => {
    const tree = memoryScopeTree()
    const a = org()
    const b = org()
    const u = unit()
    await tree.attach(a, APP_SCOPE)
    await tree.attach(b, APP_SCOPE)
    await tree.attach(u, a)
    await tree.attach(u, b)

    assert.deepEqual(await tree.chainOf(u), [u, b, APP_SCOPE])
    const edges = []
    for await (const edge of tree.edges()) edges.push(edge)
    assert.lengthOf(edges, 3)
  })

  test('detach borra el nodo y sus descendientes', async ({ assert }) => {
    const tree = memoryScopeTree()
    const a = org()
    const u = unit()
    await tree.attach(a, APP_SCOPE)
    await tree.attach(u, a)
    await tree.detach(a)

    assert.isNull(await tree.chainOf(a))
    assert.isNull(await tree.chainOf(u))
    await assert.rejects(() => tree.move(u, APP_SCOPE))
  })

  test('anti-ciclo: colgar un ancestro de su descendiente lanza y no escribe la arista', async ({
    assert,
  }) => {
    const tree = memoryScopeTree()
    const a = org()
    const u = unit()
    await tree.attach(a, APP_SCOPE)
    await tree.attach(u, a)

    await assert.rejects(() => tree.attach(a, u), /ciclo/)
    await assert.rejects(() => tree.move(a, u), /ciclo/)
    await assert.rejects(() => tree.attach(a, a), /ciclo/)
    assert.deepEqual(await tree.chainOf(a), [a, APP_SCOPE])
  })

  test('la raíz app no cuelga de nada y un padre desconocido se rechaza', async ({ assert }) => {
    const tree = memoryScopeTree()
    await assert.rejects(() => tree.attach(APP_SCOPE, org()), /raíz/)
    await assert.rejects(() => tree.attach(unit(), org()), /no existe/)
  })

  test('3b-1 · M14: descendantsFrom cumple el contrato del puerto — null para un scope que el árbol NO conoce, lista para uno que sí (vacía si es hoja), y lanza en vez de truncar al pasar maxNodes', async ({
    assert,
  }) => {
    // El contrato `null` del helper PUBLICADO (`@jantstack/adonis-authz/testing`)
    // se quedó sin oráculo al borrarse W2 en 3b-0: es la distinción que separa
    // «no hay descendientes» de «no sé», y de ella cuelga la degradación de
    // `#descendantsOrDegrade` (3F · S2). Un driver de terceros lo copia.
    const tree = memoryScopeTree()
    const a = org()
    const u1 = unit()
    const u2 = unit()
    await tree.attach(a, APP_SCOPE)
    await tree.attach(u1, a)
    await tree.attach(u2, a)
    const descendants = descendantsFrom(tree)

    assert.isNull(await descendants(org(), { maxNodes: 10 }), 'scope desconocido ⇒ null, nunca []')
    assert.isNull(await descendants(unit(), { maxNodes: 10 }), 'y da igual el tipo')
    assert.deepEqual(await descendants(u1, { maxNodes: 10 }), [], 'una hoja CONOCIDA ⇒ [], que no es lo mismo')
    assert.sameDeepMembers((await descendants(a, { maxNodes: 10 })) ?? [], [u1, u2])
    assert.sameDeepMembers((await descendants(APP_SCOPE, { maxNodes: 10 })) ?? [], [a, u1, u2], 'la raíz siempre se conoce')
    // Nunca una lista truncada en silencio (el contrato del puerto).
    assert.deepEqual(await descendants(a, { maxNodes: 2 }), [u1, u2], 'la cota justa cabe')
    await assert.rejects(() => descendants(a, { maxNodes: 1 }), /más de 1 descendientes/)
  })
})
