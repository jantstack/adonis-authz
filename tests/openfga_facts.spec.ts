/**
 * Modo `facts` (3b-2a) — el GENERADOR del modelo (c2) y la PROYECCIÓN del
 * catálogo. Pieza pura: aquí no hay `authorize` ni camino caliente.
 *
 * El modelo (c2) es el que fijó el panel 2 (`panel2-2026-08-28-juez.md`,
 * cruce 1) y no se rediseña: se compara con el literal del plan y se escribe
 * contra el servidor REAL (`OPENFGA_TEST_URL`). Si el servidor lo rechaza, el
 * generador está mal, no el servidor.
 */

import { test } from '@japa/runner'
import {
  FGA_MAX_OBJECT_ID,
  FGA_MAX_RELATION_NAME,
  factsCatalogTuples,
  factsModelBytes,
  openFgaFactsModel,
} from '../src/openfga.js'
import { OpenFgaAuthorizationDriver } from '../src/openfga.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'
import db from '@adonisjs/lucid/services/db'
import { readFile } from 'node:fs/promises'
import { APP_SCOPE } from '../src/types.js'

/** Los tres holders y los dos permisos del literal del plan. */
const HOLDERS = { users: 'user', admins: 'admin', integrations: 'integration' }
const PERMISSIONS = ['docs:read', 'docs:write']

/** `[user:*, admin:*, integration:*]` — el catálogo de (c2) por comodín de USUARIO. */
const WILDCARDS = [
  { type: 'user', wildcard: {} },
  { type: 'admin', wildcard: {} },
  { type: 'integration', wildcard: {} },
]
/** `[user, admin, integration]` — los denies, sin condición (no caducan hoy). */
const DIRECT = [{ type: 'user' }, { type: 'admin' }, { type: 'integration' }]
/** `[<holders> with not_expired]` — la asignación, con y sin caducidad. */
const DIRECT_WITH_EXPIRY = [
  ...DIRECT,
  { type: 'user', condition: 'not_expired' },
  { type: 'admin', condition: 'not_expired' },
  { type: 'integration', condition: 'not_expired' },
]

const ttu = (tupleset: string, relation: string) => ({
  tupleToUserset: { tupleset: { relation: tupleset }, computedUserset: { relation } },
})
const computed = (relation: string) => ({ computedUserset: { relation } })

/**
 * El modelo (c2) para `docs:read` y `docs:write` con tres holders, escrito a
 * mano desde el literal del plan. Si el generador se desvía de esto, se
 * desvía del diseño que el juez validó contra el servidor real.
 */
const EXPECTED = {
  schema_version: '1.1',
  type_definitions: [
    { type: 'user', relations: {}, metadata: null },
    { type: 'admin', relations: {}, metadata: null },
    { type: 'integration', relations: {}, metadata: null },
    {
      type: 'role',
      relations: {
        permits_docs_read: { this: {} },
        permits_docs_write: { this: {} },
      },
      metadata: {
        relations: {
          permits_docs_read: { directly_related_user_types: WILDCARDS },
          permits_docs_write: { directly_related_user_types: WILDCARDS },
        },
      },
    },
    {
      type: 'role_binding',
      relations: {
        role: { this: {} },
        assignee: { this: {} },
        docs_read: {
          intersection: { child: [computed('assignee'), ttu('role', 'permits_docs_read')] },
        },
        docs_write: {
          intersection: { child: [computed('assignee'), ttu('role', 'permits_docs_write')] },
        },
      },
      metadata: {
        relations: {
          role: { directly_related_user_types: [{ type: 'role' }] },
          assignee: { directly_related_user_types: DIRECT_WITH_EXPIRY },
          docs_read: { directly_related_user_types: [] },
          docs_write: { directly_related_user_types: [] },
        },
      },
    },
    {
      type: 'scope',
      relations: {
        parent: { this: {} },
        binding: { this: {} },
        docs_read: { union: { child: [ttu('binding', 'docs_read'), ttu('parent', 'docs_read')] } },
        denied_docs_read: { union: { child: [{ this: {} }, ttu('parent', 'denied_docs_read')] } },
        can_docs_read: {
          difference: { base: computed('docs_read'), subtract: computed('denied_docs_read') },
        },
        docs_write: {
          union: { child: [ttu('binding', 'docs_write'), ttu('parent', 'docs_write')] },
        },
        denied_docs_write: { union: { child: [{ this: {} }, ttu('parent', 'denied_docs_write')] } },
        can_docs_write: {
          difference: { base: computed('docs_write'), subtract: computed('denied_docs_write') },
        },
        ancestor: { union: { child: [computed('parent'), ttu('parent', 'ancestor')] } },
      },
      metadata: {
        relations: {
          parent: { directly_related_user_types: [{ type: 'scope' }] },
          binding: { directly_related_user_types: [{ type: 'role_binding' }] },
          docs_read: { directly_related_user_types: [] },
          denied_docs_read: { directly_related_user_types: DIRECT },
          can_docs_read: { directly_related_user_types: [] },
          docs_write: { directly_related_user_types: [] },
          denied_docs_write: { directly_related_user_types: DIRECT },
          can_docs_write: { directly_related_user_types: [] },
          ancestor: { directly_related_user_types: [] },
        },
      },
    },
  ],
  conditions: {
    not_expired: {
      name: 'not_expired',
      expression: 'current_time < valid_until',
      parameters: {
        current_time: { type_name: 'TYPE_NAME_TIMESTAMP' },
        valid_until: { type_name: 'TYPE_NAME_TIMESTAMP' },
      },
    },
  },
}

test.group('facts · A1 — el generador del modelo (c2)', () => {
  test('openFgaFactsModel(holderTypes, permissions) es el literal del plan para 2 permisos y 3 holders', ({
    assert,
  }) => {
    assert.deepEqual(openFgaFactsModel(HOLDERS, PERMISSIONS), EXPECTED)
  })
})

/**
 * A1, segunda mitad: **el modelo se escribe contra el servidor REAL**. Un
 * generador que produce JSON bonito y que OpenFGA rechaza no vale nada, y el
 * literal de arriba no lo demuestra. Además se ejercita la SEMÁNTICA mínima
 * de (c2) —herencia hacia abajo por `parent` y deny explícito que gana—,
 * porque un modelo aceptado que no decide lo que dice el invariante 1 y el 2
 * también sería un generador roto. Esto NO es `authorize`: el driver sigue
 * siendo el de hoy (el lote es aditivo); son tuplas y un `Check` crudos.
 */
const openFgaTestUrl = process.env.OPENFGA_TEST_URL
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('facts · A1 — el servidor real acepta el modelo (c2)', (group) => {
    const stores: string[] = []

    group.each.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) {
        await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
      }
    })

    async function storeWithFactsModel(): Promise<any> {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({
        name: `facts-model-${Date.now()}-${stores.length}`,
      })
      stores.push(store.id!)
      const client = new OpenFgaClient({ apiUrl, storeId: store.id })
      const model = await client.writeAuthorizationModel(openFgaFactsModel(HOLDERS, PERMISSIONS))
      return { client: new OpenFgaClient({ apiUrl, storeId: store.id, authorizationModelId: model.authorization_model_id }), modelId: model.authorization_model_id }
    }

    test('OpenFGA acepta el modelo generado y devuelve un authorization_model_id', async ({
      assert,
    }) => {
      const { modelId } = await storeWithFactsModel()
      assert.isString(modelId)
      assert.isNotEmpty(modelId)
    })

    /**
     * A3 — la medida del techo tiene que ser LA DEL SERVIDOR. OpenFGA cuenta
     * el tamaño protobuf del modelo (`proto.Size`), no el JSON: la razón
     * proto/JSON va de 0,33 a 0,57 según la longitud de los slugs, así que
     * medir el JSON deja pasar lo que el servidor rechaza o rechaza catálogos
     * legales por el doble de margen. Aquí se contrasta con el número que el
     * propio servidor reporta, que es el único oráculo que hay.
     */
    test('factsModelBytes cuenta LOS MISMOS bytes que el servidor (cuatro formas de catálogo)', async ({
      assert,
    }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `facts-size-${Date.now()}` })
      stores.push(store.id!)
      const client = new OpenFgaClient({ apiUrl, storeId: store.id })

      const shapes: Array<[string, Record<string, string>, number, (i: number) => string]> = [
        ['1 holder, slug corto', { users: 'user' }, 1500, (i) => `p${i}`],
        ['3 holders, slug corto', HOLDERS, 800, (i) => `p${i}`],
        ['3 holders, slug de 40', HOLDERS, 500, (i) => `p${i}`.padEnd(40, 'x')],
        [
          '6 holders, slug corto',
          { u: 'user', a: 'admin', i: 'integration', b: 'bot', s: 'service', t: 'team' },
          700,
          (i) => `p${i}`,
        ],
      ]
      for (const [name, holders, count, slug] of shapes) {
        const model = openFgaFactsModel(
          holders,
          Array.from({ length: count }, (_, i) => slug(i))
        )
        let reported: number | null = null
        try {
          await client.writeAuthorizationModel(model)
        } catch (error: any) {
          reported = Number(/limit: (\d+) bytes/.exec(String(error?.message))?.[1] ?? NaN)
        }
        assert.isNotNull(reported, `${name}: el modelo tenía que pasarse del techo para que el servidor diga su cuenta`)
        assert.equal(factsModelBytes(model), reported, name)
      }
    })

    test('la semántica de (c2): el catálogo por tuplas concede, el árbol hereda hacia abajo y el deny gana', async ({
      assert,
    }) => {
      const { client } = await storeWithFactsModel()
      const role = 'role:0192f000-0000-7000-8000-000000000001'
      const binding = 'role_binding:app|0192f000-0000-7000-8000-000000000001'
      const child = 'scope:organization|0192f000-0000-7000-8000-0000000000aa'

      await client.writeTuples([
        // Catálogo proyectado: el rol vincula docs:read para CUALQUIER holder.
        { user: 'user:*', relation: 'permits_docs_read', object: role },
        // Asignación: el binding apunta al rol y tiene a u1 de asignado.
        { user: role, relation: 'role', object: binding },
        { user: 'user:u1', relation: 'assignee', object: binding },
        // Árbol: el binding cuelga de app y la organization cuelga de app.
        { user: binding, relation: 'binding', object: 'scope:app' },
        { user: 'scope:app', relation: 'parent', object: child },
      ])

      const inherited = await client.check({
        user: 'user:u1',
        relation: 'can_docs_read',
        object: child,
        context: { current_time: new Date().toISOString() },
      })
      assert.isTrue(inherited.allowed, 'un grant en app tiene que valer en la organization (invariante 1)')

      // Un permiso que el rol NO vincula no se concede aunque la asignación exista.
      const other = await client.check({
        user: 'user:u1',
        relation: 'can_docs_write',
        object: child,
        context: { current_time: new Date().toISOString() },
      })
      assert.isFalse(other.allowed, 'el catálogo por tuplas tiene que acotar lo que concede el rol')

      // Deny explícito en el hijo: gana aunque el rol conceda (invariante 2).
      await client.writeTuples([{ user: 'user:u1', relation: 'denied_docs_read', object: child }])
      const denied = await client.check({
        user: 'user:u1',
        relation: 'can_docs_read',
        object: child,
        context: { current_time: new Date().toISOString() },
      })
      assert.isFalse(denied.allowed, 'el deny explícito gana (invariante 2)')

      // `ancestor` sin una sola tupla extra: la organization está dentro de app.
      const within = await client.check({
        user: 'scope:app',
        relation: 'ancestor',
        object: child,
        context: { current_time: new Date().toISOString() },
      })
      assert.isTrue(within.allowed, 'ancestor da isWithin/descendantsOf con 0 tuplas')
    })
  })
}

/**
 * A2 — **colisión de familias (S4, bloqueante del juez).** Con CUATRO
 * familias por permiso, dos permisos distintos pueden generar el mismo
 * nombre de relación: `can_docs_read` sale del permiso `can_docs:read` y
 * también del permiso `docs:read`. El generador de antes las colapsaba en
 * silencio y el modelo publicado anulaba un deny (el auditor lo reprodujo
 * con `allowed: true`). Se detecta con un `Map` nombre→origen y se lanza 422
 * ANTES de tocar el servidor.
 */
test.group('facts · A2 — colisión de familias de relación (S4)', () => {
  /** Cliente de mentira: cuenta las escrituras de modelo que llegarían al servidor. */
  function countingClient() {
    const calls: unknown[] = []
    return {
      calls,
      async provision(permissions: string[]) {
        // El orden importa: generar PRIMERO, escribir después. Si el
        // generador no lanza, el modelo ambiguo se publica.
        const model = openFgaFactsModel(HOLDERS, permissions)
        calls.push(model)
        return model
      },
    }
  }

  test("['docs:read', 'can_docs:read'] ⇒ 422 nombrando los DOS permisos y la relación, y 0 escrituras de modelo", async ({
    assert,
  }) => {
    const client = countingClient()
    let caught: any
    try {
      await client.provision(['docs:read', 'can_docs:read'])
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 422)
    assert.equal(caught.code, 'E_AUTHZ_INVALID_SLUG')
    assert.include(caught.message, 'can_docs_read')
    assert.include(caught.message, "'docs:read'")
    assert.include(caught.message, "'can_docs:read'")
    assert.lengthOf(client.calls, 0)
  })

  test('las otras dos familias colisionan igual, y también una relación PROPIA del modelo', ({
    assert,
  }) => {
    const cases: Array<[string[], string]> = [
      [['docs:read', 'denied_docs:read'], 'denied_docs_read'],
      [['docs:read', 'permits_docs:read'], 'permits_docs_read'],
      // `parent` es relación de `scope`: un permiso así invalidaría el modelo entero (S14).
      [['parent'], 'parent'],
    ]
    for (const [permissions, relation] of cases) {
      let caught: any
      try {
        openFgaFactsModel(HOLDERS, permissions)
        assert.fail(`${permissions.join(', ')}: debería haber lanzado`)
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 422, permissions.join(', '))
      assert.equal(caught.code, 'E_AUTHZ_INVALID_SLUG', permissions.join(', '))
      assert.include(caught.message, relation)
    }
  })

  test('dos permisos que se proyectan a la MISMA relación (`docs:write` / `docs_write`) tampoco pasan', ({
    assert,
  }) => {
    let caught: any
    try {
      openFgaFactsModel(HOLDERS, ['docs:write', 'docs_write'])
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 422)
    assert.equal(caught.code, 'E_AUTHZ_INVALID_SLUG')
    assert.include(caught.message, 'docs_write')
  })
})

/**
 * A4 — **cotas de nombre del servidor**: una relación admite 50 caracteres y
 * el id de un objeto 256. Las dos se comprueban donde se COMPONE el nombre,
 * no en runtime: un catálogo que no se puede publicar tiene que morir en el
 * `sync`, no el día que alguien pregunta.
 */
test.group('facts · A4 — cotas de nombre (relación ≤ 50, id de objeto ≤ 256)', (group) => {
  group.each.setup(() => cleanAuthzTables())

  test('un permiso cuyo `permits_<P>` pasa de 50 se rechaza nombrando el permiso y el prefijo que lo desborda', ({
    assert,
  }) => {
    // 43 caracteres: `permits_` + 43 = 51 > 50. El slug es legal en formato.
    const permission = 'a'.repeat(43)
    assert.equal(`permits_${permission}`.length, FGA_MAX_RELATION_NAME + 1)
    let caught: any
    try {
      openFgaFactsModel(HOLDERS, [permission])
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 422)
    assert.equal(caught.code, 'E_AUTHZ_INVALID_SLUG')
    assert.include(caught.message, permission)
    assert.include(caught.message, 'permits_')
    assert.include(caught.message, String(FGA_MAX_RELATION_NAME))
  })

  test('la misma cota se aplica en el SYNC, no en runtime: el catálogo no llega a escribirse', async ({
    assert,
  }) => {
    const permission = 'a'.repeat(43)
    let caught: any
    try {
      await syncAuthzCatalog({ permissions: [{ slug: permission }], roles: [] })
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 422)
    assert.equal(caught.code, 'E_AUTHZ_INVALID_SLUG')
    assert.include(caught.message, 'permits_')
  })

  test('un id de objeto que pasa de 256 no se escribe: 422 E_AUTHZ_INVALID_IDENTITY', ({
    assert,
  }) => {
    // Con la gramática publicada es inalcanzable (`role:<uuid>` son 41): el
    // caso entra por la puerta de la BASE, que es de donde salen las partes.
    const corrupt = 'x'.repeat(FGA_MAX_OBJECT_ID)
    let caught: any
    try {
      factsCatalogTuples([{ uuid: corrupt, permissions: ['docs:read'] }], HOLDERS)
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 422)
    assert.equal(caught.code, 'E_AUTHZ_INVALID_IDENTITY')
    assert.include(caught.message, String(FGA_MAX_OBJECT_ID))
    assert.include(caught.message, 'role')
  })
})

/**
 * Driver `openfga` con el cliente sustituido por un store en memoria: la
 * proyección se puede juzgar (qué lee, qué escribe, cuántas requests) sin
 * servidor. `logger` es el canal por el que sale el aviso del 80 %.
 */
function projectingDriver() {
  const logs: string[] = []
  const driver = new OpenFgaAuthorizationDriver({
    apiUrl: 'http://127.0.0.1:9',
    storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    holderTypes: HOLDERS,
    logger: { warn: (message: string) => void logs.push(message) },
  })
  const tuples = new Map<string, { user: string; relation: string; object: string }>()
  const reads: any[] = []
  const writes: any[] = []
  const other: string[] = []
  const key = (t: any) => `${t.user}#${t.relation}@${t.object}`
  const client: any = (driver as any).client
  client.read = async (filter: any) => {
    reads.push(filter)
    const prefix = filter?.object ?? ''
    return {
      tuples: [...tuples.values()]
        .filter((t) => t.object.startsWith(prefix))
        .map((k) => ({ key: k })),
      continuation_token: '',
    }
  }
  client.write = async (body: any) => {
    writes.push(body)
    for (const t of body.deletes ?? []) tuples.delete(key(t))
    for (const t of body.writes ?? []) tuples.set(key(t), t)
    return {}
  }
  // Cualquier otra escritura sería el patrón prohibido por el panel (cruce 8).
  client.writeTuples = async () => void other.push('writeTuples')
  client.deleteTuples = async () => void other.push('deleteTuples')
  return { driver, logs, reads, writes, other, tuples }
}

/** Un slug de permiso de 40 caracteres (el techo se alcanza con menos permisos). */
const longSlug = (i: number) => `p${i}`.padEnd(40, 'x')
const longPermissions = (n: number) => Array.from({ length: n }, (_, i) => ({ slug: longSlug(i) }))

/**
 * A3 — **techo del modelo: 262.144 bytes.** El servidor mide el tamaño
 * PROTOBUF del `AuthorizationModel` y rechaza por encima de ahí. Se valida en
 * `syncAuthzCatalog` ANTES de escribir: un catálogo que no se puede publicar
 * no puede quedarse en la base dejando el store sin poder regenerarse. Con
 * aviso al 80 %, porque quien declara permisos a ese ritmo tiene que
 * enterarse antes de chocar.
 */
test.group('facts · A3 — techo del modelo (262.144 bytes)', (group) => {
  group.each.setup(() => cleanAuthzTables())

  test('un catálogo que pasa del techo ⇒ 500 E_AUTHZ_MODEL_TOO_LARGE nombrando bytes y nº de permisos, y NADA escrito', async ({
    assert,
  }) => {
    const { driver, writes } = projectingDriver()
    let caught: any
    try {
      await syncAuthzCatalog(
        { permissions: longPermissions(289), roles: [] },
        { projection: driver.catalogProjection() }
      )
      assert.fail('debería haber lanzado')
    } catch (error) {
      caught = error
    }
    assert.equal(caught.status, 500)
    assert.equal(caught.code, 'E_AUTHZ_MODEL_TOO_LARGE')
    assert.include(caught.message, '289')
    assert.include(caught.message, '262144')
    assert.match(caught.message, /\b\d{6} bytes\b/)
    // Ni catálogo ni proyección: se valida antes de escribir.
    const [{ total }] = await db.from('authz_permissions').count('* as total')
    assert.equal(Number(total), 0)
    assert.lengthOf(writes, 0)
  })

  test('al 80 % del techo: escribe Y avisa por el canal de log del driver', async ({ assert }) => {
    const { driver, logs } = projectingDriver()
    await syncAuthzCatalog(
      { permissions: longPermissions(230), roles: [] },
      { projection: driver.catalogProjection() }
    )
    const [{ total }] = await db.from('authz_permissions').count('* as total')
    assert.equal(Number(total), 230)
    assert.lengthOf(logs, 1)
    assert.include(logs[0], '262144')
    assert.include(logs[0], '230 permisos')
  })

  test('un catálogo normal: escribe y NO avisa', async ({ assert }) => {
    const { driver, logs } = projectingDriver()
    await syncAuthzCatalog(
      { permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }], roles: [] },
      { projection: driver.catalogProjection() }
    )
    const [{ total }] = await db.from('authz_permissions').count('* as total')
    assert.equal(Number(total), 2)
    assert.deepEqual(logs, [])
  })
})

/**
 * A5 — **la proyección del catálogo.** `syncAuthzCatalog` escribe las tuplas
 * `role:<uuid>#permits_<P>@<holder>:*` de cada par (rol, permiso) y BORRA las
 * que sobran, en UN `Write` por lote. Con (c2) quitar un permiso de un rol
 * son tantos deletes como holders y ninguna reescritura del modelo — que es
 * justo lo que hacía inviable a (c1) (S10: 30 requests no atómicas sobre
 * 3.000 tenants).
 */
test.group('facts · A5 — la proyección del catálogo (tuplas permits_<P>)', (group) => {
  group.each.setup(() => cleanAuthzTables())

  const roleUuid = '0192f000-0000-7000-8000-0000000000a1'
  const spec = (permissions: string[]) => ({
    permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
    roles: [{ slug: 'editor', scopeType: 'app', uuid: roleUuid, permissions }],
  })

  test('el primer sync escribe una tupla por (rol, permiso, holder), con el comodín de USUARIO', async ({
    assert,
  }) => {
    const { driver, writes, tuples } = projectingDriver()
    const report = await syncAuthzCatalog(spec(['docs:read', 'docs:write']), {
      projection: driver.catalogProjection(),
    })
    assert.deepEqual(report.projection, { written: 6, deleted: 0, unchanged: 0 })
    assert.lengthOf(writes, 1)
    assert.deepEqual(
      [...tuples.values()].map((t) => `${t.user}#${t.relation}@${t.object}`).sort(),
      [
        `admin:*#permits_docs_read@role:${roleUuid}`,
        `admin:*#permits_docs_write@role:${roleUuid}`,
        `integration:*#permits_docs_read@role:${roleUuid}`,
        `integration:*#permits_docs_write@role:${roleUuid}`,
        `user:*#permits_docs_read@role:${roleUuid}`,
        `user:*#permits_docs_write@role:${roleUuid}`,
      ]
    )
  })

  test('quitar 1 permiso de 1 rol con 3 holderTypes ⇒ exactamente 1 Write con 3 deletes y 0 writes', async ({
    assert,
  }) => {
    const { driver, writes, other, tuples } = projectingDriver()
    const projection = driver.catalogProjection()
    await syncAuthzCatalog(spec(['docs:read', 'docs:write']), { projection })
    writes.length = 0

    const report = await syncAuthzCatalog(spec(['docs:read']), { projection })

    assert.deepEqual(report.projection, { written: 0, deleted: 3, unchanged: 3 })
    assert.lengthOf(writes, 1)
    assert.lengthOf(writes[0].deletes, 3)
    assert.isEmpty(writes[0].writes ?? [])
    // El patrón `deleteTuples()` + `writeTuples()` queda prohibido (cruce 8
    // del panel): no es atómico dentro de la request.
    assert.deepEqual(other, [])
    assert.lengthOf([...tuples.values()], 3)
  })

  test('idempotencia: el segundo sync seguido escribe 0 tuplas y no llama al servidor', async ({
    assert,
  }) => {
    const { driver, writes } = projectingDriver()
    const projection = driver.catalogProjection()
    await syncAuthzCatalog(spec(['docs:read', 'docs:write']), { projection })
    writes.length = 0

    const report = await syncAuthzCatalog(spec(['docs:read', 'docs:write']), { projection })

    assert.deepEqual(report.projection, { written: 0, deleted: 0, unchanged: 6 })
    assert.lengthOf(writes, 0)
  })

  test('una tupla que el catálogo ya no respalda se borra aunque nadie la haya pedido (el espejo converge)', async ({
    assert,
  }) => {
    const { driver, tuples } = projectingDriver()
    const projection = driver.catalogProjection()
    await syncAuthzCatalog(spec(['docs:read']), { projection })
    // Alguien escribe a mano un permiso que el catálogo no da: con (c2) una
    // sola tupla concede un permiso a un rol GLOBALMENTE (riesgo 4 del panel).
    tuples.set(`user:*#permits_docs_write@role:${roleUuid}`, {
      user: 'user:*',
      relation: 'permits_docs_write',
      object: `role:${roleUuid}`,
    })

    const report = await syncAuthzCatalog(spec(['docs:read']), { projection })

    assert.deepEqual(report.projection, { written: 0, deleted: 1, unchanged: 3 })
    assert.notInclude(
      [...tuples.keys()],
      `user:*#permits_docs_write@role:${roleUuid}`
    )
  })
})

/**
 * A6 — **la proyección nunca se lee como catálogo.** Es la condición (c) de
 * la regla reescrita (panel 2, cruce 7): un driver puede mantener un espejo
 * derivado si es reconstruible, si `reconcile` lo vigila y si NUNCA se lee
 * como catálogo. Lo tercero es lo que evita que el store se convierta en la
 * fuente de verdad por la puerta de atrás — y con (c2) una sola tupla
 * escrita a mano concede un permiso a un rol globalmente (riesgo 4 del
 * panel), así que leerla sería exactamente la escalada.
 */
test.group('facts · A6 — la proyección no es catálogo', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:read'] }],
    })
  })

  test('listRoles, rolesInChain y authorize (findPermission) hacen 0 lecturas sobre el tipo `role`', async ({
    assert,
  }) => {
    const { driver, reads } = projectingDriver()
    const client: any = (driver as any).client
    const checks: any[] = []
    client.batchCheck = async (body: any) => {
      checks.push(body)
      return {
        result: (body.checks ?? []).map((c: any) => ({ allowed: false, correlationId: c.correlationId })),
      }
    }
    const subject = { type: 'users', uuid: 'u1' }

    await driver.listRoles(subject, APP_SCOPE)
    await driver.rolesInChain(subject, [APP_SCOPE])
    await driver.authorize(subject, 'docs:read', APP_SCOPE)

    // Que hayan preguntado algo: si no leyeran nada, el caso no probaría nada.
    assert.isNotEmpty(reads)
    assert.isNotEmpty(checks)
    for (const filter of reads) {
      assert.notMatch(String(filter?.object ?? ''), /^role:/, JSON.stringify(filter))
      assert.notMatch(String(filter?.relation ?? ''), /^permits_/, JSON.stringify(filter))
    }
    for (const body of checks) {
      for (const check of body.checks ?? []) {
        assert.notMatch(String(check.object), /^role:/, JSON.stringify(check))
        assert.notMatch(String(check.relation), /^permits_/, JSON.stringify(check))
      }
    }
  })

  test('guardia de fuente: el driver solo mira el tipo `role` en la proyección (una vez, y es una escritura)', async ({
    assert,
  }) => {
    const source = await readFile(new URL('../src/drivers/openfga_driver.ts', import.meta.url), 'utf-8')
    const reads = source.match(/FACTS_ROLE_TYPE\}:/g) ?? []
    assert.lengthOf(reads, 1)
    // …y está dentro de `projectCatalog`, no de una lectura de membresía.
    const projection = source.slice(
      source.indexOf('private async projectCatalog('),
      source.indexOf('// `purgeRole` NO existe')
    )
    assert.include(projection, 'FACTS_ROLE_TYPE}:')
  })
})
