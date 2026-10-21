/**
 * **Lote «antes de RC» · 7.4 — los listados de relaciones no paginan en 2.5** (opción 4 del juez,
 * `loteRC-74-paginacion-juez.md`; decisión del dueño 2026-10-17 (7.4)). Lo que la guardia de superficie (columna
 * `page`, `tests/guard_surface.spec.ts`) no juzga celda a celda:
 *
 *  - RC74-5 · el ORDEN de las guardas: F-05 y la partición antes que la página (manager y los tres drivers);
 *  - RC74-6 · `enumerate*` de `openfga` rechaza `after` (500, cero llamadas al cliente) y con un `limit` válido devuelve
 *    TODO en una página sin cursor (caso de letra: «Limits»);
 *  - RC74-7 · la guardia de TIPO: `page` fuera de las cuatro firmas y `cursor` fuera de los dos tipos de respuesta
 *    (`@ts-expect-error`: si alguien los devuelve, TS2578 ⇒ `npm run typecheck` en rojo; el corredor de mutantes no lo
 *    ve, lo ve el compilador);
 *  - H2 · `limit` por encima de `RELATIONS_ENUMERATE_MAX_LIMIT` se RECORTA con cursor (sin pérdida), y la cota está en
 *    «Limits» con el número del código;
 *  - H3 (mitad) · un `after` que `database` no emitió es 422 con cero sentencias en los TRES motores (hasta 7.4: 503 en
 *    PG, fin silencioso en MySQL/SQLite); un uuid canónico que no es de la partición sigue entrando (atar el cursor a su
 *    partición es del lote C / 2.6, declarado).
 */
import { test } from '@japa/runner'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { contractRelationsConfig, makeRelationsDriver } from '../src/testing/relations_contract.js'
import { RelationsManager } from '../src/relations/manager.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { OpenFgaRelationsDriver } from '../src/drivers/openfga_relations_driver.js'
import { openFgaFactsModel } from '../src/drivers/openfga_facts.js'
import { RELATIONS_ENUMERATE_DEFAULT_LIMIT, RELATIONS_ENUMERATE_MAX_LIMIT } from '../src/relations/page.js'
import * as root from '../index.js'
import type { RelationObjectsPage, RelationsDriver, RelationsDriverCapabilities, RelationSubjectsPage, ScopeRef, SubjectRef } from '../src/types.js'
import { countQueries } from './helpers/spies.js'

const ROOT = fileURLToPath(new URL('../', import.meta.url))
const HOLDERS = { user: 'user', admin: 'admin', integration: 'integration' } as const
const FULL: RelationsDriverCapabilities = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: false,
  injectableClock: true,
  transactionalWrites: false,
}

const U: SubjectRef = { type: 'user', uuid: uuidv7() }
const DOC = { type: 'document', id: uuidv7() }
const BINDING = { type: 'role_binding', id: uuidv7() }
const DASHLESS: ScopeRef = { type: 'unit', uuid: uuidv7().replace(/-/g, '') }

async function caught(run: () => Promise<unknown>): Promise<any> {
  return run().then(
    () => null,
    (e) => e
  )
}

/** Un cliente de OpenFGA FALSO que cuenta cada método y sirve el modelo de la config y las tuplas dadas (sin servidor). */
function fakeClient(driver: OpenFgaRelationsDriver, tuples: Array<{ user: string; relation: string; object: string }> = []) {
  const calls: string[] = []
  const model = { authorization_model: openFgaFactsModel(HOLDERS, [], { objectTypes: contractRelationsConfig().objectTypes }) }
  const responses: Record<string, unknown> = {
    readAuthorizationModel: model,
    readLatestAuthorizationModel: model,
    read: { tuples: tuples.map((key) => ({ key })), continuation_token: '' },
    listObjects: { objects: [] },
  }
  ;(driver as unknown as { client: unknown }).client = new Proxy(
    {},
    {
      get(_t, prop) {
        if (typeof prop !== 'string') return undefined
        return async () => {
          calls.push(prop)
          return responses[prop] ?? {}
        }
      },
    }
  )
  return calls
}

function fgaDriver(): OpenFgaRelationsDriver {
  return new OpenFgaRelationsDriver(contractRelationsConfig(), {
    apiUrl: 'http://127.0.0.1:9',
    storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    modelId: '01ARZ3NDEKTSV4RRFFQ69G5FAW',
    holderTypes: HOLDERS,
    timeoutMs: 1000,
    listObjectsDeadlineMs: 1000,
    logger: { warn: () => {} },
  })
}

/* ── RC74-7 · la guardia de TIPO (no se ejecuta: la juzga `tsc` sobre tsconfig.test.json) ── */

function rc74TypeGuard(manager: RelationsManager, port: RelationsDriver, database: DatabaseRelationsDriver, p: ScopeRef): void {
  // @ts-expect-error RC74-7: `page` salió de la firma de listObjects (manager)
  void manager.listObjects(U, 'viewer', 'document', p, { limit: 1 })
  // @ts-expect-error RC74-7: … de listSubjects (manager)
  void manager.listSubjects('viewer', DOC, p, { limit: 1 })
  // @ts-expect-error RC74-7: … de listDenies (manager)
  void manager.listDenies('viewer', DOC, p, { limit: 1 })
  // @ts-expect-error RC74-7: … de membersOf (manager)
  void manager.membersOf(DOC, 'member', p, { limit: 1 })
  // @ts-expect-error RC74-7: … del PUERTO (listObjects)
  void port.listObjects(U, 'viewer', 'document', p, { limit: 1 })
  // @ts-expect-error RC74-7: … del PUERTO (listSubjects)
  void port.listSubjects('viewer', DOC, p, { limit: 1 })
  // @ts-expect-error RC74-7: … del PUERTO (listDenies)
  void port.listDenies!('viewer', DOC, p, { limit: 1 })
  // @ts-expect-error RC74-7: … del PUERTO (membersOf)
  void port.membersOf!(DOC, 'member', p, { limit: 1 })
  // @ts-expect-error RC74-7: … del driver database (clase concreta)
  void database.listSubjects('viewer', DOC, p, { limit: 1 })
  // @ts-expect-error RC74-7: `cursor` salió de RelationObjectsPage
  const objects: RelationObjectsPage = { objects: [], cursor: 'x' }
  // @ts-expect-error RC74-7: `cursor` salió de RelationSubjectsPage
  const subjects: RelationSubjectsPage = { subjects: [], cursor: 'x' }
  void objects
  void subjects
  // Control: `enumerate*` SÍ conserva su página y su cursor.
  void port.enumerateRelations!(p, { limit: 10, after: uuidv7() }).then((page) => page.cursor)
}

test.group('7.4 · RC74-7 · la guardia de tipo', () => {
  test('RC74-7 · `page` fuera de las cuatro firmas (manager, puerto, driver) y `cursor` fuera de RelationObjectsPage/RelationSubjectsPage: lo afirma `tsc` (@ts-expect-error ⇒ TS2578 si vuelven)', ({ assert }) => {
    assert.isFunction(rc74TypeGuard, 'la función de la guardia de tipo existe y la compila npm run typecheck')
  })
})

/* ── RC74-5 · el orden de las guardas ── */

test.group('7.4 · RC74-5 · F-05 y la partición ANTES que la página', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  const P: ScopeRef = { type: 'unit', uuid: uuidv7() }
  const targets = (): Array<[string, any]> => {
    const fga = fgaDriver()
    fakeClient(fga)
    const double = makeRelationsDriver({ config: contractRelationsConfig(), capabilities: FULL })
    return [
      ['manager (doble)', new RelationsManager(double, contractRelationsConfig())],
      ['database', new DatabaseRelationsDriver(contractRelationsConfig(), { transactionalWrites: false })],
      ['openfga', fga],
      ['doble', double],
    ]
  }

  test('RC74-5 · role_binding + page ⇒ 422 F-05 (no el 500 de la página); partición sin guiones + page ⇒ 422 D4; los dos en listObjects y listSubjects de las cuatro capas', async ({ assert }) => {
    for (const [label, t] of targets()) {
      const f05Objects = await caught(() => t.listObjects(U, 'assignee', 'role_binding', P, { limit: 1 }))
      assert.equal(f05Objects?.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN', `${label} · listObjects: ${f05Objects?.message}`)
      const f05Subjects = await caught(() => t.listSubjects('assignee', BINDING, P, { limit: 1 }))
      assert.equal(f05Subjects?.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN', `${label} · listSubjects: ${f05Subjects?.message}`)
      const d4 = await caught(() => t.listSubjects('viewer', DOC, DASHLESS, { limit: 1 }))
      assert.equal(d4?.status, 422, `${label} · partición: ${d4?.message}`)
      assert.equal(d4?.code, 'E_AUTHZ_INVALID_IDENTITY', `${label} · partición: ${d4?.message}`)
      // Y con la pregunta bien formada, la página es lo que corta (500).
      const page = await caught(() => t.listSubjects('viewer', DOC, P, { limit: 1 }))
      assert.equal(page?.code, 'E_AUTHZ_UNSUPPORTED', `${label} · página: ${page?.message}`)
    }
  })

  test('RC74-5 · enumerate*: la partición mal formada va antes que la página mal formada (422 de identidad, no de página)', async ({ assert }) => {
    for (const [label, t] of targets()) {
      const bad = await caught(() => t.enumerateRelations(DASHLESS, { limit: Number.NaN }))
      assert.equal(bad?.code, 'E_AUTHZ_INVALID_IDENTITY', `${label}: ${bad?.message}`)
    }
  })
})

/* ── RC74-6 · enumerate de openfga: after ⇒ 500, limit se ignora (una página, sin cursor) ── */

test.group('7.4 · RC74-6 · enumerate* de openfga', () => {
  test('RC74-6 · enumerateRelations/enumerateRelationsMany con after ⇒ 500 E_AUTHZ_UNSUPPORTED con CERO llamadas al cliente (no emite cursor); con { limit: 5 } devuelve las 7 tuplas en UNA página sin cursor (el limit se ignora, «Limits»)', async ({
    assert,
  }) => {
    const P: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const key = `${P.type}|${P.uuid}`
    const stored = Array.from({ length: 7 }, () => ({ user: `user:${uuidv7()}`, relation: 'viewer', object: `document:${key}|${uuidv7()}` }))
    for (const [op, run] of [
      ['enumerateRelations', (d: OpenFgaRelationsDriver, page: any) => d.enumerateRelations(P, page)],
      ['enumerateRelationsMany', (d: OpenFgaRelationsDriver, page: any) => d.enumerateRelationsMany([P], page)],
    ] as const) {
      const driver = fgaDriver()
      const calls = fakeClient(driver, stored)
      const refused = await caught(() => run(driver, { after: uuidv7() }))
      assert.equal(refused?.status, 500, `${op}: ${refused?.message}`)
      assert.equal(refused?.code, 'E_AUTHZ_UNSUPPORTED')
      assert.include(refused.message, op)
      assert.deepEqual(calls, [], `${op} con after: CERO llamadas al cliente`)

      const page = await run(driver, { limit: 5 })
      assert.lengthOf(page.tuples, 7, `${op}: el limit no recorta en openfga (todo en una página)`)
      assert.isUndefined(page.cursor, `${op}: sin cursor`)
    }
  })
})

/* ── H2 / H3 · la página de enumerate* en database ── */

test.group('7.4 · H2/H3 · enumerate* de database', (group) => {
  group.each.setup(async () => {
    await db.from('authz_relations').delete()
  })

  function row(partition: ScopeRef) {
    return {
      uuid: uuidv7(),
      partition_key: `${partition.type}|${partition.uuid}`,
      object_type: 'document',
      object_uuid: uuidv7(),
      relation: 'viewer',
      subject_type: 'user',
      subject_uuid: uuidv7(),
      subject_relation: '',
      subject_partition: null,
      created_at: new Date(),
    }
  }

  test(`H2 · { limit: 5000 } se RECORTA a RELATIONS_ENUMERATE_MAX_LIMIT (${RELATIONS_ENUMERATE_MAX_LIMIT}) con cursor, y la segunda página trae el resto: sin pérdida; sin limit, ${RELATIONS_ENUMERATE_DEFAULT_LIMIT}`, async ({ assert }) => {
    const P: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const rows = Array.from({ length: RELATIONS_ENUMERATE_MAX_LIMIT + 1 }, () => row(P))
    for (let i = 0; i < rows.length; i += 200) await db.table('authz_relations').multiInsert(rows.slice(i, i + 200))
    const driver = new DatabaseRelationsDriver(contractRelationsConfig(), { transactionalWrites: false })
    const first = await driver.enumerateRelations(P, { limit: 5000 })
    assert.lengthOf(first.tuples, RELATIONS_ENUMERATE_MAX_LIMIT, 'recortado al techo, no 5000 ni un error')
    assert.isString(first.cursor, 'con cursor: el recorte no pierde nada')
    const second = await driver.enumerateRelations(P, { limit: 5000, after: first.cursor })
    assert.lengthOf(second.tuples, 1)
    assert.isUndefined(second.cursor)
    const seen = new Set([...first.tuples, ...second.tuples].map((t) => t.object.id))
    assert.equal(seen.size, rows.length, 'cada fila exactamente una vez')
    const byDefault = await driver.enumerateRelations(P)
    assert.lengthOf(byDefault.tuples, RELATIONS_ENUMERATE_DEFAULT_LIMIT)
  })

  test('H3 · un after que database no emitió (no es un uuid canónico) ⇒ 422 E_AUTHZ_INVALID_PAGE con CERO sentencias, en enumerateRelations y en enumerateRelationsMany, también por el manager; un uuid canónico sí entra', async ({ assert }) => {
    const P: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await db.table('authz_relations').multiInsert([row(P), row(P)])
    const driver = new DatabaseRelationsDriver(contractRelationsConfig(), { transactionalWrites: false })
    const manager = new RelationsManager(driver, contractRelationsConfig())
    const id = uuidv7()
    for (const after of ['x', 'b3', id.toUpperCase(), id.replace(/-/g, ''), `${id}'`]) {
      for (const [label, run] of [
        ['driver.enumerateRelations', () => driver.enumerateRelations(P, { after })],
        ['driver.enumerateRelationsMany', () => driver.enumerateRelationsMany([P], { after })],
        ['manager.enumerateRelations', () => manager.enumerateRelations(P, { after })],
      ] as const) {
        const { result: error, queries } = await countQueries(() => caught(run))
        assert.equal(error?.status, 422, `${label} · after ${after}: ${error?.message}`)
        assert.equal(error?.code, 'E_AUTHZ_INVALID_PAGE', `${label} · after ${after}`)
        assert.lengthOf(queries, 0, `${label} · after ${after}: CERO sentencias (hasta 7.4: 503 en PG, fin silencioso en MySQL/SQLite)`)
      }
    }
    // Un uuid canónico ANTERIOR a todo (o de otra partición): entra — atar el cursor a su partición es del lote C / 2.6.
    const all = await driver.enumerateRelations(P, { after: '00000000-0000-0000-0000-000000000000' })
    assert.lengthOf(all.tuples, 2)
  })

  test('⚪ 1 (auditor 7.x) · la página se lee UNA vez: un getter que da 1 al validar y NaN después no saca la consulta sin LIMIT, ni por el driver ni por el manager', async ({ assert }) => {
    const P: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await db.table('authz_relations').multiInsert([row(P), row(P), row(P)])
    const driver = new DatabaseRelationsDriver(contractRelationsConfig(), { transactionalWrites: false })
    const manager = new RelationsManager(driver, contractRelationsConfig())
    const flipping = () => {
      let reads = 0
      return {
        get limit() {
          return reads++ === 0 ? 1 : Number.NaN
        },
      } as { limit: number }
    }
    for (const [label, run] of [
      ['driver.enumerateRelations', () => driver.enumerateRelations(P, flipping())],
      ['driver.enumerateRelationsMany', () => driver.enumerateRelationsMany([P], flipping())],
      ['manager.enumerateRelations', () => manager.enumerateRelations(P, flipping())],
      ['manager.enumerateRelationsMany', () => manager.enumerateRelationsMany([P], flipping())],
    ] as const) {
      const page = await run()
      assert.lengthOf(page.tuples, 1, `${label}: el limit validado (1), no el NaN de la segunda lectura`)
      assert.isString(page.cursor, label)
    }
  })
})

/* ── Letra: la cota en «Limits» con el número del código, y lo que se exporta ── */

test.group('7.4 · letra', () => {
  test('«Limits» lleva RELATIONS_ENUMERATE_MAX_LIMIT y RELATIONS_ENUMERATE_DEFAULT_LIMIT con los números del código, y que los list* de relaciones no paginan; index.ts exporta las dos constantes y InvalidRelationPageError', ({ assert }) => {
    const readme = readFileSync(`${ROOT}README.md`, 'utf8')
    const limits = readme.slice(readme.indexOf('### Limits'), readme.indexOf('### Operational notes for the SQL engines'))
    const row = limits.split('\n').find((line) => line.includes('`RELATIONS_ENUMERATE_MAX_LIMIT`'))
    assert.isString(row, 'la fila de la página de enumerate* está en «Limits»')
    assert.include(row!, RELATIONS_ENUMERATE_MAX_LIMIT.toLocaleString('en-US'))
    assert.include(row!, '`RELATIONS_ENUMERATE_DEFAULT_LIMIT`')
    assert.include(row!, String(RELATIONS_ENUMERATE_DEFAULT_LIMIT))
    assert.include(row!, 'E_AUTHZ_INVALID_PAGE')
    const lists = limits.split('\n').find((line) => line.includes('do not page'))
    assert.isString(lists, '«Limits» dice que los list* de relaciones no paginan')
    assert.equal((root as any).RELATIONS_ENUMERATE_MAX_LIMIT, RELATIONS_ENUMERATE_MAX_LIMIT)
    assert.equal((root as any).RELATIONS_ENUMERATE_DEFAULT_LIMIT, RELATIONS_ENUMERATE_DEFAULT_LIMIT)
    assert.isFunction((root as any).InvalidRelationPageError)
  })
})
