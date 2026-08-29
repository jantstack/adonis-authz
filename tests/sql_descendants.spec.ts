/**
 * `sqlDescendantsOf` (2.1, B2): la CTE recursiva opt-in sobre una tabla del
 * consumidor con columna padre, probada sobre `demo_scopes` (tabla ficticia
 * del harness). PG y SQLite comparten el SQL (`WITH RECURSIVE`); MySQL se
 * rechaza hasta que haya observación (Fase 2.5).
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { sqlDescendantsOf } from '../src/sql_descendants.js'
import { APP_SCOPE } from '../src/types.js'
import type { ScopeRef } from '../src/types.js'
import { countQueries } from './helpers/spies.js'

const keys = (scopes: ScopeRef[]) => scopes.map((s) => `${s.type}:${s.uuid ?? ''}`).sort()

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

const DEMO = { table: 'demo_scopes', uuidColumn: 'uuid', parentColumn: 'parent_uuid', typeColumn: 'type' }

test.group('sqlDescendantsOf (2B · B2)', (group) => {
  const orgA: ScopeRef = { type: 'organization', uuid: uuidv7() }
  const orgB: ScopeRef = { type: 'organization', uuid: uuidv7() }
  const unitA1: ScopeRef = { type: 'unit', uuid: uuidv7() }
  const unitA2: ScopeRef = { type: 'unit', uuid: uuidv7() }
  const teamA1x: ScopeRef = { type: 'team', uuid: uuidv7() }
  const unitB1: ScopeRef = { type: 'unit', uuid: uuidv7() }

  group.each.setup(async () => {
    await db.from('demo_scopes').delete()
    await db.table('demo_scopes').multiInsert([
      { uuid: orgA.uuid, type: 'organization', parent_uuid: null },
      { uuid: orgB.uuid, type: 'organization', parent_uuid: null },
      { uuid: unitA1.uuid, type: 'unit', parent_uuid: orgA.uuid },
      { uuid: unitA2.uuid, type: 'unit', parent_uuid: orgA.uuid },
      { uuid: teamA1x.uuid, type: 'team', parent_uuid: unitA1.uuid },
      { uuid: unitB1.uuid, type: 'unit', parent_uuid: orgB.uuid },
    ])
  })

  test('devuelve el subárbol entero (todos los tipos, toda la profundidad), sin el propio scope; app ⇒ todo; hoja ⇒ []', async ({
    assert,
  }) => {
    const descendantsOf = sqlDescendantsOf(DEMO)
    assert.deepEqual(keys((await descendantsOf(orgA, { maxNodes: 100 }))!), keys([unitA1, unitA2, teamA1x]))
    assert.deepEqual(keys((await descendantsOf(unitA1, { maxNodes: 100 }))!), keys([teamA1x]))
    assert.deepEqual(await descendantsOf(teamA1x, { maxNodes: 100 }), [])
    assert.deepEqual(keys((await descendantsOf(APP_SCOPE, { maxNodes: 100 }))!), keys([orgA, orgB, unitA1, unitA2, teamA1x, unitB1]))
  })

  test('scope desconocido (uuid ausente, o tipo que no coincide con la fila) ⇒ null', async ({ assert }) => {
    const descendantsOf = sqlDescendantsOf(DEMO)
    assert.isNull(await descendantsOf({ type: 'organization', uuid: uuidv7() }, { maxNodes: 100 }))
    assert.isNull(await descendantsOf({ type: 'unit', uuid: orgA.uuid! }, { maxNodes: 100 }))
  })

  test('maxNodes superado ⇒ 422 E_AUTHZ_TOO_MANY_SCOPES (nunca parcial); exactamente maxNodes ⇒ entero', async ({
    assert,
  }) => {
    const descendantsOf = sqlDescendantsOf(DEMO)
    await rejectsWith(assert, () => descendantsOf(orgA, { maxNodes: 2 }), { status: 422, code: 'E_AUTHZ_TOO_MANY_SCOPES' })
    assert.lengthOf((await descendantsOf(orgA, { maxNodes: 3 }))!, 3)
    // La cota propia del helper acota por debajo de la del llamante.
    await rejectsWith(assert, () => sqlDescendantsOf({ ...DEMO, maxNodes: 2 })(orgA, { maxNodes: 100 }), {
      status: 422,
      code: 'E_AUTHZ_TOO_MANY_SCOPES',
    })
    // Y la consulta lee como mucho maxNodes + 1 filas: nunca el árbol entero.
    const { queries } = await countQueries(() => descendantsOf(APP_SCOPE, { maxNodes: 3 }).catch(() => undefined))
    assert.isTrue(queries.some((q) => /limit/i.test(q.sql)))
  })

  test('un ciclo en la tabla no cuelga la consulta: termina y lanza E_AUTHZ_TOO_MANY_SCOPES', async ({ assert }) => {
    const x = uuidv7()
    const y = uuidv7()
    await db.table('demo_scopes').multiInsert([
      { uuid: x, type: 'organization', parent_uuid: y },
      { uuid: y, type: 'organization', parent_uuid: x },
    ])
    const descendantsOf = sqlDescendantsOf(DEMO)
    await rejectsWith(assert, () => descendantsOf({ type: 'organization', uuid: x }, { maxNodes: 50 }), {
      status: 422,
      code: 'E_AUTHZ_TOO_MANY_SCOPES',
    })
    // G1: el ciclo se reporta como cota superada, y el mensaje lo dice.
    let message = ''
    try {
      await descendantsOf({ type: 'organization', uuid: x }, { maxNodes: 50 })
    } catch (error: any) {
      message = error.message
    }
    assert.match(message, /posible ciclo/)
    // El resto del árbol sigue respondiendo.
    assert.lengthOf((await descendantsOf(orgB, { maxNodes: 50 }))!, 1)
  })

  test('sin typeColumn, scopeType fija el tipo de todos los nodos; ambos a la vez o ninguno es config rota', async ({
    assert,
  }) => {
    const flat = sqlDescendantsOf({ table: 'demo_scopes', uuidColumn: 'uuid', parentColumn: 'parent_uuid', scopeType: 'node' })
    const found = (await flat({ type: 'node', uuid: orgA.uuid! }, { maxNodes: 100 }))!
    assert.deepEqual(new Set(found.map((s) => s.type)), new Set(['node']))
    assert.lengthOf(found, 3)
    assert.throws(() => sqlDescendantsOf({ table: 'demo_scopes', uuidColumn: 'uuid', parentColumn: 'parent_uuid' } as any), /typeColumn|scopeType/)
    assert.throws(() => sqlDescendantsOf({ ...DEMO, scopeType: 'node' }), /typeColumn|scopeType/)
    // G1 (auditor 11): `scopeType` es identidad de scope y pasa por la misma
    // gramática que el resto del motor (minúsculas, ≤ 20, sin separadores).
    for (const bad of ['Node', 'a b', 'x'.repeat(21), 'a:b', '', 'app']) {
      assert.throws(
        () => sqlDescendantsOf({ table: 'demo_scopes', uuidColumn: 'uuid', parentColumn: 'parent_uuid', scopeType: bad }),
        /scopeType|tipo/,
        bad
      )
    }
  })

  test('identificadores que no son un nombre SQL simple se rechazan al construir (nada se interpola)', ({ assert }) => {
    for (const bad of ['demo_scopes; drop table authz_roles', 'demo scopes', '"x"', 'a.b', '']) {
      assert.throws(() => sqlDescendantsOf({ ...DEMO, table: bad }), /identificador/i, bad)
      assert.throws(() => sqlDescendantsOf({ ...DEMO, parentColumn: bad }), /identificador/i, bad)
    }
  })

  test('MySQL ⇒ 500 E_AUTHZ_UNSUPPORTED_DIALECT en la primera llamada (sin observación hasta 2.5); una tabla ausente ⇒ 503', async ({
    assert,
  }) => {
    const fakeMysql: any = { connection: () => ({ dialect: { name: 'mysql' } }) }
    const onMysql = sqlDescendantsOf(DEMO, fakeMysql)
    await rejectsWith(assert, () => onMysql(orgA, { maxNodes: 10 }), { status: 500, code: 'E_AUTHZ_UNSUPPORTED_DIALECT' })
    const fakeMysql2: any = { connection: () => ({ dialect: { name: 'mysql2' } }) }
    await rejectsWith(assert, () => sqlDescendantsOf(DEMO, fakeMysql2)(orgA, { maxNodes: 10 }), { status: 500, code: 'E_AUTHZ_UNSUPPORTED_DIALECT' })

    const missing = sqlDescendantsOf({ ...DEMO, table: 'no_existe' })
    await rejectsWith(assert, () => missing(orgA, { maxNodes: 10 }), { status: 503, code: 'E_AUTHZ_BACKEND_UNAVAILABLE' })
  })

  test('toda consulta sale con el deadline configurado', async ({ assert }) => {
    const descendantsOf = sqlDescendantsOf({ ...DEMO, timeoutMs: 1234 })
    const { queries } = await countQueries(() => descendantsOf(orgA, { maxNodes: 100 }))
    assert.isAtLeast(queries.length, 1)
    assert.isTrue(queries.every((q) => q.timeout === 1234), JSON.stringify(queries.map((q) => q.timeout)))
  })
})
