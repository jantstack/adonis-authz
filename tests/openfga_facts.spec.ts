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
  FACTS_MAX_RESOLVE_DEPTH,
  FGA_MAX_BATCH_CHECK,
  FGA_MAX_OBJECT_ID,
  FGA_MAX_RELATION_NAME,
  factsCatalogTuples,
  factsModelBytes,
  openFgaFactsModel,
} from '../src/openfga.js'
import { OpenFgaAuthorizationDriver } from '../src/openfga.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { invalidateAuthzCatalog, withAuthzCatalogWrite } from '../src/catalog_cache.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { cleanAuthzTables } from './helpers/schema.js'
import db from '@adonisjs/lucid/services/db'
import { readFile } from 'node:fs/promises'
import { APP_SCOPE } from '../src/types.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { AuthorizationManager } from '../src/manager.js'
import { v7 as uuidv7 } from 'uuid'

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
    // Dos sitios, y ninguno pregunta QUÉ PERMISOS tiene un rol (que es lo que
    // A6 protege): la proyección (una escritura) y el barrido de 3b-2e · E1,
    // que filtra por `user` para enumerar los `role_binding` de un rol.
    // CUATRO sitios, y ninguno pregunta QUÉ PERMISOS tiene un rol (que es lo
    // que A6 protege): `projectCatalog` y `projectCatalogRole` (escrituras del
    // espejo), el barrido de 3b-2e · E1 y `purgeRole` (que enumeran los
    // `role_binding` de un rol filtrando por `user`).
    assert.lengthOf(reads, 4)
    const between = (from: string, to: string) => source.slice(source.indexOf(from), source.indexOf(to))
    const projection = between('private async projectCatalog(', '  /**\n   * **Purga un ROL')
    assert.include(projection, 'FACTS_ROLE_TYPE}:')
    const sweep = between('private async sweepLocalRoleBindings(', 'private async storeChain(')
    assert.include(sweep, `object: \`\${FACTS_BINDING_TYPE}:\``, 'el objeto que enumera es role_binding, no role')
    // Y ningún camino de LECTURA de membresía toca el tipo `role`.
    for (const method of ['async authorize(', 'async hasRole(', 'async listRoles(', 'async rolesInChain(']) {
      const body = source.slice(source.indexOf(method), source.indexOf(method) + 3_000)
      assert.notInclude(body, 'FACTS_ROLE_TYPE}:', `${method}: la proyección no es catálogo`)
    }
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * 3b-2b — EL ÁRBOL COMO HECHOS
 *
 * `hierarchy: 'facts'` en las opciones del driver: `scopes.attached/moved/
 * detached` escriben (y borran) la arista `scope:<hijo>#parent@scope:<padre>`.
 * Por defecto el driver sigue en `'resolver'` (el modo de hoy): este lote es
 * ADITIVO y no cambia una sola respuesta de las suites existentes.
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * **Cruce 3 del panel 2, reproducido aquí: FGA acepta el ciclo.** No se
 * cuelga, no avisa, responde en milisegundos — y la herencia se vuelve
 * BIDIRECCIONAL: un grant en un descendiente concede en el ancestro, que es
 * exactamente lo que el invariante 1 prohíbe. Fail-open mudo.
 *
 * Este caso monta el ciclo A MANO, saltándose la validación del paquete, y
 * enseña el `true` que no debería existir. Es la prueba de que el anti-ciclos
 * tiene que vivir EN EL PAQUETE y no puede delegarse en el backend (y el
 * caso hermano V5 del tester: que nadie confíe en FGA como segunda línea).
 */
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('facts · 3b-2b — el ciclo que FGA acepta (cruce 3)', (group) => {
    const stores: string[] = []
    group.each.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) {
        await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
      }
    })

    test('un ciclo `parent` escrito a mano hace que un grant en el DESCENDIENTE conceda en el ANCESTRO (fail-open del servidor)', async ({
      assert,
    }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({
        name: `facts-cycle-${Date.now()}`,
      })
      stores.push(store.id!)
      const bare = new OpenFgaClient({ apiUrl, storeId: store.id })
      const model = await bare.writeAuthorizationModel(openFgaFactsModel(HOLDERS, PERMISSIONS))
      const client = new OpenFgaClient({
        apiUrl,
        storeId: store.id,
        authorizationModelId: model.authorization_model_id,
      })

      const role = 'role:0192f000-0000-7000-8000-000000000001'
      const org = 'scope:organization|0192f000-0000-7000-8000-0000000000aa'
      const unit = 'scope:unit|0192f000-0000-7000-8000-0000000000bb'
      // El binding cuelga de la UNIT: el grant está abajo del todo.
      const binding = 'role_binding:unit|0192f000-0000-7000-8000-0000000000bb|0192f000-0000-7000-8000-000000000001'

      await client.writeTuples([
        { user: 'user:*', relation: 'permits_docs_read', object: role },
        { user: role, relation: 'role', object: binding },
        { user: 'user:u1', relation: 'assignee', object: binding },
        { user: binding, relation: 'binding', object: unit },
        // El árbol legítimo: unit → org → app.
        { user: org, relation: 'parent', object: unit },
        { user: 'scope:app', relation: 'parent', object: org },
      ])

      const context = { current_time: new Date().toISOString() }
      const before = await client.check({ user: 'user:u1', relation: 'can_docs_read', object: org, context })
      assert.isFalse(before.allowed, 'precondición: sin ciclo, el grant de la unit NO concede en la org')

      // El ciclo: la org pasa a colgar de la unit (su propio descendiente).
      await client.writeTuples([{ user: unit, relation: 'parent', object: org }])

      const started = Date.now()
      const after = await client.check({ user: 'user:u1', relation: 'can_docs_read', object: org, context })
      const elapsed = Date.now() - started

      // Esto es el DEFECTO, no el contrato: se fija para que nadie proponga
      // delegar el anti-ciclos en el servidor.
      assert.isTrue(
        after.allowed,
        'FGA evalúa el ciclo y concede hacia ARRIBA: la herencia deja de ser solo hacia abajo'
      )
      assert.isBelow(elapsed, 2_000, 'y no se cuelga: responde en milisegundos, sin avisar de nada')

      // La RAÍZ todavía se salva, y por una razón que conviene tener escrita:
      // la herencia va padre→hijo, así que un ciclo org↔unit no alcanza a
      // `scope:app` mientras `app` no cuelgue de nadie. Eso es EXACTAMENTE
      // lo que defiende la validación (i) del cruce 3 (`child ≠ app`): en
      // cuanto la raíz cuelga de algo, el grant de la unit concede en la
      // raíz y con él en TODOS los tenants del store.
      const rootBefore = await client.check({ user: 'user:u1', relation: 'can_docs_read', object: 'scope:app', context })
      assert.isFalse(rootBefore.allowed, 'la raíz no cuelga de nadie: el ciclo de abajo no la alcanza')

      await client.writeTuples([{ user: org, relation: 'parent', object: 'scope:app' }])
      const rootAfter = await client.check({ user: 'user:u1', relation: 'can_docs_read', object: 'scope:app', context })
      assert.isTrue(rootAfter.allowed, 'con la raíz colgada, el grant de una unit concede en scope:app')
    })
  })
}

/**
 * El driver `openfga` en modo `facts` con el cliente sustituido por un store
 * en memoria y un árbol de mentira: qué lee, qué escribe y CUÁNTAS requests
 * hace se pueden juzgar sin servidor.
 */
function treeDriver(options: { hierarchy?: 'resolver' | 'facts'; tree?: any; resolveChain?: any } = {}) {
  const tree = options.tree ?? memoryScopeTree()
  const driver = new OpenFgaAuthorizationDriver({
    apiUrl: 'http://127.0.0.1:9',
    storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    holderTypes: HOLDERS,
    resolveChain: options.resolveChain ?? resolveChainFrom(tree),
    hierarchy: options.hierarchy,
    // Estos tests construyen el driver A PELO (sin manager ni transacción del
    // consumidor), así que el gate de 3b-2d no aporta nada aquí: se firma.
    acceptScopeDriftRisk: true,
    logger: { warn: () => {} },
  })
  const tuples = new Map<string, { user: string; relation: string; object: string }>()
  const reads: any[] = []
  const writes: any[] = []
  const other: string[] = []
  const key = (t: any) => `${t.user}#${t.relation}@${t.object}`
  const client: any = (driver as any).client
  client.read = async (filter: any) => {
    reads.push(filter)
    return {
      tuples: [...tuples.values()]
        .filter((t) => (filter?.object ? t.object.startsWith(filter.object) : true))
        .filter((t) => (filter?.relation ? t.relation === filter.relation : true))
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
  client.writeTuples = async () => void other.push('writeTuples')
  client.deleteTuples = async () => void other.push('deleteTuples')
  return { driver, tree, tuples, reads, writes, other }
}

/** Las aristas `#parent` que hay en el store, como `hijo → padre`. */
function edgesOf(tuples: Map<string, { user: string; relation: string; object: string }>): string[] {
  return [...tuples.values()]
    .filter((t) => t.relation === 'parent')
    .map((t) => `${t.object} → ${t.user}`)
    .sort()
}


/** Un caso negativo: la promesa lanza, con el `status` y el `code` esperados. */
async function rejects(
  assert: any,
  run: () => Promise<unknown>,
  expected: { status: number; code: string },
  message?: string
): Promise<any> {
  let caught: any = null
  try {
    await run()
  } catch (error) {
    caught = error
  }
  assert.isNotNull(caught, `${message ?? 'la operación'}: debería haber lanzado`)
  assert.equal(caught.status, expected.status, message)
  assert.equal(caught.code, expected.code, message)
  return caught
}

const orgScope = () => ({ type: 'organization', uuid: uuidv7() })
const unitScope = () => ({ type: 'unit', uuid: uuidv7() })

test.group('facts · 3b-2b — hierarchy: facts escribe el árbol', () => {
  test('`scopes.attached` escribe la arista scope:<hijo>#parent@scope:<padre> en UN solo write', async ({
    assert,
  }) => {
    const { driver, tree, tuples, writes, other } = treeDriver({ hierarchy: 'facts' })
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    await driver.onScopeAttached!(org, APP_SCOPE)

    assert.deepEqual(edgesOf(tuples), [`scope:organization|${org.uuid} → scope:app`])
    assert.lengthOf(writes, 1)
    assert.deepEqual(writes[0].deletes ?? [], [])
    assert.deepEqual(other, [], 'writeTuples/deleteTuples quedan prohibidos (cruce 8)')
  })

  test('por defecto (modo `resolver`, el de hoy) NO se escribe ninguna arista: el lote es aditivo', async ({
    assert,
  }) => {
    const { driver, tree, tuples, writes } = treeDriver()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    await driver.onScopeAttached?.(org, APP_SCOPE)
    await driver.onScopeMoved?.(org, APP_SCOPE)
    await driver.onScopeDetached?.(org)

    assert.deepEqual(edgesOf(tuples), [])
    assert.deepEqual(writes, [])
  })

  test('la arista lleva la identidad CANÓNICA del árbol (invariante 17): un alias del uuid no abre una segunda rama', async ({
    assert,
  }) => {
    // El árbol del consumidor funde el alias sin guiones con su fila (el tipo
    // `uuid` de PostgreSQL lo hace solo) y responde CANÓNICO. Si la arista se
    // escribiera con lo que trajo el llamante, el store tendría dos nodos
    // para el mismo scope y la herencia colgaría del que nadie vuelve a tocar.
    const org = orgScope()
    const unit = unitScope()
    const rows = new Map<string, { self: any; parent: any }>([
      [`organization|${org.uuid.replaceAll('-', '')}`, { self: org, parent: APP_SCOPE }],
      [`unit|${unit.uuid.replaceAll('-', '')}`, { self: unit, parent: org }],
    ])
    const resolveChain = async (scope: any): Promise<any[] | null> => {
      const chain: any[] = []
      let current = scope
      for (let depth = 0; depth < 10; depth++) {
        if (current.type === 'app') return [...chain, APP_SCOPE]
        const row = rows.get(`${current.type}|${String(current.uuid).replaceAll('-', '')}`)
        if (!row) return null
        chain.push(row.self)
        current = row.parent
      }
      return null
    }
    const { driver, tuples } = treeDriver({ hierarchy: 'facts', resolveChain })
    const aliasUnit = { type: 'unit', uuid: unit.uuid.replaceAll('-', '') }
    const aliasOrg = { type: 'organization', uuid: org.uuid.replaceAll('-', '') }

    await driver.onScopeAttached!(aliasUnit as any, aliasOrg as any)

    assert.deepEqual(edgesOf(tuples), [
      `scope:unit|${unit.uuid} → scope:organization|${org.uuid}`,
    ])
  })

  test('idempotencia (invariante 6): re-anexar al MISMO padre no escribe nada', async ({ assert }) => {
    const { driver, tree, tuples, writes } = treeDriver({ hierarchy: 'facts' })
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    await driver.onScopeAttached!(org, APP_SCOPE)
    await driver.onScopeAttached!(org, APP_SCOPE)

    assert.lengthOf(writes, 1, 'la segunda no llega al servidor')
    assert.deepEqual(edgesOf(tuples), [`scope:organization|${org.uuid} → scope:app`])
  })
})

/**
 * **Anti-ciclos EN EL PAQUETE, antes de escribir** (cruce 3, bloqueante S2).
 * El caso de arriba enseña por qué no se puede delegar: el servidor acepta la
 * arista, la evalúa y concede hacia arriba sin decir nada. Las tres
 * validaciones son las del cruce 8 —`child ≠ app`, el padre existe, y el hijo
 * no es ancestro-o-igual del padre— y en los tres casos NO se escribe
 * ninguna arista.
 *
 * Viven en el manager (`#assertEdge`, probado en `tests/manager.spec.ts`) y
 * se repiten aquí por defensa en profundidad: `manager.driver()` es la salida
 * documentada de todas las barreras del paquete, y por ahí se llega al
 * driver sin pasar por el manager.
 */
test.group('facts · 3b-2b — anti-ciclos en el paquete (cruce 3)', () => {
  async function treeWithOrgAndUnit() {
    const t = treeDriver({ hierarchy: 'facts' })
    const org = orgScope()
    const unit = unitScope()
    await t.tree.attach(org, APP_SCOPE)
    await t.tree.attach(unit, org)
    return { ...t, org, unit }
  }

  test('(i) la raíz `app` no puede colgar de nada ⇒ 422 E_AUTHZ_INVALID_IDENTITY sin escribir', async ({
    assert,
  }) => {
    const { driver, org, tuples, writes } = await treeWithOrgAndUnit()
    const expected = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
    await rejects(assert, () => driver.onScopeAttached!(APP_SCOPE, org), expected, 'attached')
    await rejects(assert, () => driver.onScopeMoved!(APP_SCOPE, org), expected, 'moved')
    assert.deepEqual(edgesOf(tuples), [])
    assert.deepEqual(writes, [])
  })

  test('(ii) un padre que el árbol no conoce ⇒ 422 E_AUTHZ_UNKNOWN_SCOPE sin escribir', async ({
    assert,
  }) => {
    const { driver, unit, tuples, writes } = await treeWithOrgAndUnit()
    const ghost = orgScope()
    const expected = { status: 422, code: 'E_AUTHZ_UNKNOWN_SCOPE' }
    await rejects(assert, () => driver.onScopeAttached!(unit, ghost), expected, 'attached')
    await rejects(assert, () => driver.onScopeMoved!(unit, ghost), expected, 'moved')
    assert.deepEqual(edgesOf(tuples), [])
    assert.deepEqual(writes, [])
  })

  test('(iii) colgar un scope de su propio DESCENDIENTE (o de sí mismo) ⇒ 422 E_AUTHZ_SCOPE_CYCLE sin escribir', async ({
    assert,
  }) => {
    const { driver, org, unit, tuples, writes } = await treeWithOrgAndUnit()
    const expected = { status: 422, code: 'E_AUTHZ_SCOPE_CYCLE' }
    await rejects(assert, () => driver.onScopeMoved!(org, unit), expected, 'moved: org bajo su unit')
    await rejects(assert, () => driver.onScopeAttached!(org, unit), expected, 'attached: org bajo su unit')
    await rejects(assert, () => driver.onScopeMoved!(org, org), expected, 'moved: org bajo sí misma')
    assert.deepEqual(edgesOf(tuples), [], 'ninguna arista que cierra un ciclo llega al store')
    assert.deepEqual(writes, [])
  })

  test('el anti-ciclos canoniza: un ALIAS del uuid del hijo tampoco cierra el ciclo, y una arista legítima sí pasa', async ({
    assert,
  }) => {
    const org = orgScope()
    const unit = unitScope()
    const rows = new Map<string, { self: any; parent: any }>([
      [`organization|${org.uuid.replaceAll('-', '')}`, { self: org, parent: APP_SCOPE }],
      [`unit|${unit.uuid.replaceAll('-', '')}`, { self: unit, parent: org }],
    ])
    const resolveChain = async (scope: any): Promise<any[] | null> => {
      const chain: any[] = []
      let current = scope
      for (let depth = 0; depth < 10; depth++) {
        if (current.type === 'app') return [...chain, APP_SCOPE]
        const row = rows.get(`${current.type}|${String(current.uuid).replaceAll('-', '')}`)
        if (!row) return null
        chain.push(row.self)
        current = row.parent
      }
      return null
    }
    const { driver, tuples, writes } = treeDriver({ hierarchy: 'facts', resolveChain })
    const aliasOrg = { type: 'organization', uuid: org.uuid.replaceAll('-', '') }

    await rejects(
      assert,
      () => driver.onScopeMoved!(aliasOrg as any, unit),
      { status: 422, code: 'E_AUTHZ_SCOPE_CYCLE' },
      'el alias del hijo desciende del padre'
    )
    assert.deepEqual(writes, [])

    // El inverso: la arista legítima escrita con el alias sigue pasando.
    await driver.onScopeAttached!({ type: 'unit', uuid: unit.uuid.replaceAll('-', '') } as any, org)
    assert.deepEqual(edgesOf(tuples), [`scope:unit|${unit.uuid} → scope:organization|${org.uuid}`])
  })
})

/**
 * **`moved` atómico** (cruce 8, bloqueante S3). Procedimiento fijado:
 * `Read({object:'scope:<hijo>', relation:'parent'})` —una request, y es
 * OBLIGATORIA porque FGA rechaza borrar una tupla inexistente— y **UN solo
 * `Write`** con el delete del padre viejo y el write del nuevo, que es
 * atómico dentro de la request. Total: 2 requests, 1 mutación.
 *
 * Queda prohibido el patrón `deleteTuples()` + `writeTuples()`: son dos
 * requests y entre ellas el scope se queda sin padre (o con dos).
 */
test.group('facts · 3b-2b — `moved` es un Read y UN Write (cruce 8)', () => {
  test('mover un scope: 1 Read del padre actual + 1 write con deletes Y writes juntos, y 0 writeTuples/deleteTuples', async ({
    assert,
  }) => {
    const { driver, tree, tuples, reads, writes, other } = treeDriver({ hierarchy: 'facts' })
    const orgA = orgScope()
    const orgB = orgScope()
    const unit = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(unit, orgA)
    await driver.onScopeAttached!(unit, orgA)
    reads.length = 0
    writes.length = 0

    await driver.onScopeMoved!(unit, orgB)

    assert.lengthOf(reads, 1, 'un solo Read')
    assert.deepEqual(reads[0], { object: `scope:unit|${unit.uuid}`, relation: 'parent' })
    assert.lengthOf(writes, 1, 'UNA sola mutación: deletes y writes en la misma request')
    assert.deepEqual(writes[0].deletes, [
      { user: `scope:organization|${orgA.uuid}`, relation: 'parent', object: `scope:unit|${unit.uuid}` },
    ])
    assert.deepEqual(writes[0].writes, [
      { user: `scope:organization|${orgB.uuid}`, relation: 'parent', object: `scope:unit|${unit.uuid}` },
    ])
    assert.deepEqual(other, [], 'writeTuples()/deleteTuples() quedan prohibidos')
    assert.deepEqual(
      edgesOf(tuples),
      [`scope:unit|${unit.uuid} → scope:organization|${orgB.uuid}`],
      'queda UNA arista por nodo: la vieja se fue en la misma request'
    )
  })

  test('si el Read devuelve 0 padres (la arista nunca llegó al store) el Write lleva solo writes', async ({
    assert,
  }) => {
    const { driver, tree, tuples, writes } = treeDriver({ hierarchy: 'facts' })
    const orgA = orgScope()
    const unit = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(unit, orgA)

    // Nadie escribió la arista antes (un store recién migrado, un relay con
    // retraso): mover no puede borrar lo que no existe.
    await driver.onScopeMoved!(unit, orgA)

    assert.lengthOf(writes, 1)
    assert.deepEqual(writes[0].deletes, [])
    assert.deepEqual(edgesOf(tuples), [`scope:unit|${unit.uuid} → scope:organization|${orgA.uuid}`])
  })

  test('si el Read devuelve MÁS DE UN padre eso es deriva del store: lanza 500 E_AUTHZ_SCOPE_TREE_DRIFT y no toca nada', async ({
    assert,
  }) => {
    const { driver, tree, tuples, writes } = treeDriver({ hierarchy: 'facts' })
    const orgA = orgScope()
    const orgB = orgScope()
    const unit = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    await tree.attach(unit, orgA)
    // Dos padres a la vez: el paquete no escribe esto nunca (una sola arista
    // por nodo), así que verlo significa que alguien más escribe en el store.
    // "Arreglarlo" en silencio sería adivinar cuál de los dos es el bueno —y
    // con dos padres la herencia YA está trayendo hechos de otra rama—.
    for (const parent of [orgA, orgB]) {
      tuples.set(`scope:organization|${parent.uuid}#parent@scope:unit|${unit.uuid}`, {
        user: `scope:organization|${parent.uuid}`,
        relation: 'parent',
        object: `scope:unit|${unit.uuid}`,
      })
    }
    writes.length = 0

    const error = await rejects(
      assert,
      () => driver.onScopeMoved!(unit, orgB),
      { status: 500, code: 'E_AUTHZ_SCOPE_TREE_DRIFT' },
      'dos padres'
    )
    assert.include(error.message, `scope:unit|${unit.uuid}`)
    assert.deepEqual(writes, [], 'no se arregla: se denuncia')
    assert.lengthOf(edgesOf(tuples), 2, 'las dos aristas siguen ahí, tal cual')
  })
})

/**
 * **S6 — el orden de `detached`** (cruce 9, bloqueante). Primero los HECHOS
 * (el driver los purga y DEMUESTRA cero o lanza), la arista al final. Si se
 * hiciera al revés y la purga muriera a medias, los grants supervivientes se
 * quedarían sin ancestro: los denies que heredaban del padre dejarían de
 * aplicar y esos permisos pasarían a ser **indenegables** (invariante 2).
 *
 * El orden lo fija el manager (`scopes.detached` = `purgeScope` y luego
 * `onScopeDetached`); aquí se demuestra con la purga fallando de verdad.
 */
test.group('facts · 3b-2b — `detached`: hechos primero, arista al final (S6)', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] }],
    })
  })

  test('la arista del scope se borra al final, en un Write de solo deletes', async ({ assert }) => {
    const { driver, tree, tuples, writes } = treeDriver({ hierarchy: 'facts' })
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    await driver.onScopeAttached!(org, APP_SCOPE)
    writes.length = 0

    await driver.onScopeDetached!(org)

    assert.lengthOf(writes, 1)
    assert.deepEqual(writes[0].writes ?? [], [])
    assert.deepEqual(edgesOf(tuples), [])
  })

  test('un scope sin arista en el store no escribe nada (re-detach es un no-op seguro)', async ({
    assert,
  }) => {
    const { driver, tree, writes } = treeDriver({ hierarchy: 'facts' })
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    await driver.onScopeDetached!(org)
    assert.deepEqual(writes, [])
  })

  test('si la purga de hechos NO puede demostrar cero, la arista SIGUE en el store: el subárbol no se queda sin ancestro', async ({
    assert,
  }) => {
    const { driver, tree, tuples } = treeDriver({ hierarchy: 'facts' })
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    await driver.onScopeAttached!(org, APP_SCOPE)
    // Un deny vivo en ese scope que el borrado NO se lleva (el harness deja
    // `deleteTuples` sin efecto): `purgeScope` lo vuelve a leer y lanza. Desde
    // 3b-2c el deny del modo `facts` es `scope:<key>#denied_<P>@<holder>`, no
    // un `deny_binding`: el hecho que la purga tiene que demostrar a cero es
    // este.
    tuples.set(`user:u1#denied_docs_read@scope:organization|${org.uuid}`, {
      user: 'user:u1',
      relation: 'denied_docs_read',
      object: `scope:organization|${org.uuid}`,
    })
    const manager = new AuthorizationManager({
      default: 'openfga',
      drivers: { openfga: () => driver },
      scopes: { resolveChain: resolveChainFrom(tree), acceptScopeDriftRisk: true },
      warnOnOptInSecurity: false,
    } as any)

    await rejects(
      assert,
      () => manager.scopes.detached(org),
      { status: 500, code: 'E_AUTHZ_PURGE_INCOMPLETE' },
      'la purga no demuestra cero'
    )

    assert.deepEqual(
      edgesOf(tuples),
      [`scope:organization|${org.uuid} → scope:app`],
      'la arista se borra DESPUÉS de la purga: si la purga falla, el scope conserva su ancestro y los denies heredados siguen valiendo'
    )
  })

  test('con la purga en verde, `scopes.detached` sí se lleva la arista (mismo camino, orden completo)', async ({
    assert,
  }) => {
    const { driver, tree, tuples } = treeDriver({ hierarchy: 'facts' })
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    await driver.onScopeAttached!(org, APP_SCOPE)
    const manager = new AuthorizationManager({
      default: 'openfga',
      drivers: { openfga: () => driver },
      scopes: { resolveChain: resolveChainFrom(tree), acceptScopeDriftRisk: true },
      warnOnOptInSecurity: false,
    } as any)

    await manager.scopes.detached(org)

    assert.deepEqual(edgesOf(tuples), [])
  })
})

/**
 * De punta a punta por donde entra el consumidor: `manager.scopes.*`. El
 * anti-ciclos del manager (`#assertEdge`) corta ANTES del driver, así que un
 * ciclo no llega ni a intentarse contra el store.
 */
test.group('facts · 3b-2b — `manager.scopes.*` mantiene el árbol del store', () => {
  function managerOver(tree: any, driver: any) {
    return new AuthorizationManager({
      default: 'openfga',
      drivers: { openfga: () => driver },
      scopes: { resolveChain: resolveChainFrom(tree), acceptScopeDriftRisk: true },
      warnOnOptInSecurity: false,
    } as any)
  }

  test('attached y moved mantienen UNA arista por nodo; un ciclo es 422 y no llega al store', async ({
    assert,
  }) => {
    const { driver, tree, tuples, writes } = treeDriver({ hierarchy: 'facts' })
    const manager = managerOver(tree, driver)
    const orgA = orgScope()
    const orgB = orgScope()
    const unit = unitScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)

    await manager.scopes.attached(orgA, APP_SCOPE)
    await manager.scopes.attached(orgB, APP_SCOPE)
    await tree.attach(unit, orgA)
    await manager.scopes.attached(unit, orgA)
    assert.deepEqual(edgesOf(tuples), [
      `scope:organization|${orgA.uuid} → scope:app`,
      `scope:organization|${orgB.uuid} → scope:app`,
      `scope:unit|${unit.uuid} → scope:organization|${orgA.uuid}`,
    ])

    await tree.attach(unit, orgB)
    await manager.scopes.moved(unit, orgB)
    assert.deepEqual(edgesOf(tuples), [
      `scope:organization|${orgA.uuid} → scope:app`,
      `scope:organization|${orgB.uuid} → scope:app`,
      `scope:unit|${unit.uuid} → scope:organization|${orgB.uuid}`,
    ])

    const before = writes.length
    await rejects(
      assert,
      () => manager.scopes.moved(orgB, unit),
      { status: 422, code: 'E_AUTHZ_SCOPE_CYCLE' },
      'la org bajo su propia unit'
    )
    await rejects(
      assert,
      () => manager.scopes.attached(APP_SCOPE, orgA),
      { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' },
      'la raíz colgando de una org'
    )
    await rejects(
      assert,
      () => manager.scopes.moved(unit, orgScope()),
      { status: 422, code: 'E_AUTHZ_UNKNOWN_SCOPE' },
      'un padre fantasma'
    )
    assert.lengthOf(writes, before, 'ninguna de las tres tocó el store')
  })
})

/**
 * Lo de arriba se juzga contra un store en memoria. Esto lo repite contra el
 * servidor REAL con el modelo (c2) publicado: que FGA acepte las aristas que
 * el driver escribe, que la herencia las use, y —la razón por la que el
 * `moved` del cruce 8 necesita un `Read`— que borrar una tupla inexistente
 * sea un error del servidor, no un no-op.
 */
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('facts · 3b-2b — el árbol del driver contra el servidor real', (group) => {
    const stores: string[] = []
    group.each.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) {
        await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
      }
    })

    test('attached/moved/detached mantienen el árbol en un store real y la herencia lo sigue', async ({
      assert,
    }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `facts-tree-${Date.now()}` })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS, PERMISSIONS)
      )
      const tree = memoryScopeTree()
      const orgA = orgScope()
      const orgB = orgScope()
      const unit = unitScope()
      await tree.attach(orgA, APP_SCOPE)
      await tree.attach(orgB, APP_SCOPE)
      await tree.attach(unit, orgA)
      const driver = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id,
        holderTypes: HOLDERS,
        resolveChain: resolveChainFrom(tree),
        hierarchy: 'facts',
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      })
      const client = new OpenFgaClient({
        apiUrl,
        storeId: store.id,
        authorizationModelId: model.authorization_model_id,
      })

      await driver.onScopeAttached(orgA, APP_SCOPE)
      await driver.onScopeAttached(orgB, APP_SCOPE)
      await driver.onScopeAttached(unit, orgA)

      // Un grant en orgA: el rol, el binding y el vínculo del catálogo.
      const roleUuid = '0192f000-0000-7000-8000-000000000001'
      const binding = `role_binding:organization|${orgA.uuid}|${roleUuid}`
      await client.writeTuples([
        { user: 'user:*', relation: 'permits_docs_read', object: `role:${roleUuid}` },
        { user: `role:${roleUuid}`, relation: 'role', object: binding },
        { user: 'user:u1', relation: 'assignee', object: binding },
        { user: binding, relation: 'binding', object: `scope:organization|${orgA.uuid}` },
      ])
      const ask = async (scope: any) =>
        (
          await client.check({
            user: 'user:u1',
            relation: 'can_docs_read',
            object: `scope:${scope}`,
            context: { current_time: new Date().toISOString() },
          })
        ).allowed

      assert.isTrue(await ask(`unit|${unit.uuid}`), 'la unit hereda de su org (invariante 1)')
      assert.isFalse(await ask(`organization|${orgB.uuid}`), 'la otra org no (nunca a hermanos)')
      assert.isFalse(await ask('app'), 'y nunca hacia arriba')

      // Mover la unit a orgB: deja de heredar de A y no hereda de B (que no concede).
      await tree.attach(unit, orgB)
      await driver.onScopeMoved(unit, orgB)
      assert.isFalse(await ask(`unit|${unit.uuid}`), 'movida a orgB, la unit ya no hereda el grant de orgA')

      // Y sacarla del árbol le quita el ancestro por completo.
      await driver.onScopeDetached(unit)
      const left = await client.read({ object: `scope:unit|${unit.uuid}`, relation: 'parent' })
      assert.lengthOf(left.tuples ?? [], 0, 'la arista se fue')
    })

    test('por qué `moved` necesita el `Read`: FGA RECHAZA borrar una tupla que no existe', async ({
      assert,
    }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `facts-del-${Date.now()}` })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS, PERMISSIONS)
      )
      const client = new OpenFgaClient({
        apiUrl,
        storeId: store.id,
        authorizationModelId: model.authorization_model_id,
      })

      let caught: any = null
      try {
        await client.write({
          writes: [{ user: 'scope:app', relation: 'parent', object: 'scope:organization|nada' }],
          deletes: [{ user: 'scope:app', relation: 'parent', object: 'scope:unit|fantasma' }],
        })
      } catch (error) {
        caught = error
      }
      assert.isNotNull(caught, 'el servidor no ignora un delete de una tupla inexistente')
      // …y el write que la acompañaba TAMPOCO aterrizó: el Write es atómico,
      // que es lo que hace legal el `moved` del cruce 8.
      const written = await client.read({ object: 'scope:organization|nada', relation: 'parent' })
      assert.lengthOf(written.tuples ?? [], 0, 'un delete fallido aborta el write que lo acompaña')
    })
  })
}

/* ════════════════════════════════════════════════════════════════════════
 * 3b-2c — `authorize` DE UN SOLO `Check`
 *
 * En modo `facts` la jerarquía, el catálogo y los denies ya están en el
 * store: `authorize` deja de expandir la cadena a un `batchCheck` de N×M
 * items y pasa a ser UN `Check` de `can_<P>` sobre `scope:<key>`. Lo único
 * local que sigue consultando es el MEMO del catálogo, y es obligatorio: un
 * permiso desconocido tiene que ser `false` (invariante 5) y no una relación
 * inexistente que el servidor rechaza con un 400 que saldría como 503.
 *
 * Lo demás de este sub-lote es la forma NUEVA de los objetos que escriben
 * `grant`/`deny`/`revoke`/`removeDeny`: el binding enlazado al scope y al
 * rol, y el deny como `scope:<key>#denied_<P>@<holder>`.
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * El driver en modo `facts` con el cliente sustituido por un store en memoria
 * COMPLETO (`read`/`write`/`writeTuples`/`deleteTuples`) y espías de `check`,
 * `batchCheck` y del resolutor del consumidor: cuántas requests hace cada
 * operación —y de qué forma son las tuplas— se juzga aquí sin servidor; la
 * SEMÁNTICA se juzga contra el `:8101` más abajo.
 */
function factsDriver(
  options: { hierarchy?: 'resolver' | 'facts'; allow?: (check: any) => boolean } = {}
) {
  const tree = memoryScopeTree()
  const base = resolveChainFrom(tree)
  /** Cada llamada al resolutor del consumidor: `authorize` no puede hacer ninguna. */
  const resolved: any[] = []
  const driver = new OpenFgaAuthorizationDriver({
    apiUrl: 'http://127.0.0.1:9',
    storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    holderTypes: HOLDERS,
    resolveChain: async (scope: any) => {
      resolved.push(scope)
      return base(scope)
    },
    hierarchy: options.hierarchy ?? 'facts',
    acceptScopeDriftRisk: true,
    logger: { warn: () => {} },
  })
  const tuples = new Map<string, any>()
  const reads: any[] = []
  const mutations: Array<{ kind: string; writes: any[]; deletes: any[] }> = []
  const checks: any[] = []
  const batches: any[] = []
  const key = (t: any) => `${t.user}#${t.relation}@${t.object}`
  const allow = options.allow ?? (() => false)
  const client: any = (driver as any).client
  client.read = async (filter: any) => {
    reads.push(filter)
    return {
      tuples: [...tuples.values()]
        .filter((t) => (filter?.object ? t.object.startsWith(filter.object) : true))
        .filter((t) => (filter?.relation ? t.relation === filter.relation : true))
        .filter((t) => (filter?.user ? t.user === filter.user : true))
        .map((t) => ({ key: t })),
      continuation_token: '',
    }
  }
  client.write = async (body: any) => {
    mutations.push({ kind: 'write', writes: body.writes ?? [], deletes: body.deletes ?? [] })
    for (const t of body.deletes ?? []) tuples.delete(key(t))
    for (const t of body.writes ?? []) tuples.set(key(t), t)
    return {}
  }
  client.writeTuples = async (list: any[]) => {
    mutations.push({ kind: 'writeTuples', writes: list, deletes: [] })
    for (const t of list) tuples.set(key(t), t)
    return {}
  }
  client.deleteTuples = async (list: any[]) => {
    mutations.push({ kind: 'deleteTuples', writes: [], deletes: list })
    for (const t of list) tuples.delete(key(t))
    return {}
  }
  client.check = async (body: any) => {
    checks.push(body)
    return { allowed: allow(body) }
  }
  client.batchCheck = async (body: any) => {
    batches.push(body)
    return {
      result: (body.checks ?? []).map((c: any) => ({
        allowed: allow(c),
        correlationId: c.correlationId,
        request: c,
      })),
    }
  }
  return { driver, tree, tuples, reads, mutations, checks, batches, resolved }
}

/** Las tuplas del store en memoria, como `user#relation@object`, ordenadas. */
function tupleList(tuples: Map<string, any>): string[] {
  return [...tuples.values()].map((t) => `${t.user}#${t.relation}@${t.object}`).sort()
}

/** El catálogo mínimo de los casos de 2c: un permiso y un rol de organization. */
async function seedCatalog() {
  await cleanAuthzTables()
  await syncAuthzCatalog({
    permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
    roles: [
      { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] },
      { slug: 'app-admin', scopeType: 'app', permissions: ['docs:read', 'docs:write'] },
    ],
  })
}

const roleUuidOf = async (slug: string): Promise<string> =>
  (await db.from('authz_roles').where('slug', slug).select('uuid').first()).uuid

test.group('facts · 3b-2c — `authorize` es UN solo Check', (group) => {
  group.each.setup(seedCatalog)

  test('un `check` de `can_<P>` sobre `scope:<key>`: 0 batchCheck y 0 resolveChain', async ({
    assert,
  }) => {
    const { driver, tree, checks, batches, resolved } = factsDriver({
      allow: (c) => c.relation === 'can_docs_read',
    })
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    const allowed = await driver.authorize({ type: 'users', uuid: 'u1' }, 'docs:read', org)

    assert.isTrue(allowed)
    assert.lengthOf(checks, 1)
    assert.equal(checks[0].user, 'user:u1')
    assert.equal(checks[0].relation, 'can_docs_read')
    assert.equal(checks[0].object, `scope:organization|${org.uuid}`)
    assert.isString(checks[0].context?.current_time, 'el instante de la operación viaja en el check (K9)')
    assert.lengthOf(batches, 0, 'ni un batchCheck: la cadena ya no se expande')
    assert.deepEqual(resolved, [], 'ni una llamada al resolutor del consumidor (cruce 6)')
  })

  test('el `false` del Check es el `false` de la respuesta (denegación por defecto)', async ({
    assert,
  }) => {
    const { driver, tree, checks } = factsDriver({ allow: () => false })
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    assert.isFalse(await driver.authorize({ type: 'users', uuid: 'u1' }, 'docs:read', org))
    assert.lengthOf(checks, 1)
  })

  test('MEMO OBLIGATORIO: un permiso desconocido es `false` y NO llega al servidor (invariante 5)', async ({
    assert,
  }) => {
    const { driver, tree, checks, batches } = factsDriver({ allow: () => true })
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    // Sin la guardia del catálogo esto sería un Check de `can_no_existe`, una
    // relación que el modelo no declara: 400 del servidor ⇒ 503. El invariante
    // 5 exige `false`.
    assert.isFalse(await driver.authorize({ type: 'users', uuid: 'u1' }, 'no:existe', org))
    assert.deepEqual(checks, [])
    assert.deepEqual(batches, [])
  })

  test('un fallo del backend es 503, nunca un `false` silencioso', async ({ assert }) => {
    const { driver, tree } = factsDriver()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    ;(driver as any).client.check = async () => {
      throw new Error('boom')
    }

    await rejects(
      assert,
      () => driver.authorize({ type: 'users', uuid: 'u1' }, 'docs:read', org),
      { status: 503, code: 'E_AUTHZ_BACKEND_UNAVAILABLE' },
      'el Check se cayó'
    )
  })

  test('en modo `resolver` (el default) NADA cambia: sigue siendo el batchCheck de la cadena', async ({
    assert,
  }) => {
    const { driver, tree, checks, batches, resolved } = factsDriver({
      hierarchy: 'resolver',
      allow: () => false,
    })
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    assert.isFalse(await driver.authorize({ type: 'users', uuid: 'u1' }, 'docs:read', org))
    assert.deepEqual(checks, [], 'el modo de hoy no usa `check`')
    assert.lengthOf(batches, 1)
    assert.isNotEmpty(resolved, 'y sí consulta el árbol del consumidor')
  })
})

test.group('facts · 3b-2c — `authorizeMany` es UN batchCheck de N items', (group) => {
  group.each.setup(seedCatalog)

  test('N scopes ⇒ 1 batchCheck con un item por scope (no el N×M de hoy), 0 resolveChain', async ({
    assert,
  }) => {
    const orgA = orgScope()
    const orgB = orgScope()
    const { driver, tree, batches, checks, resolved } = factsDriver({
      allow: (c) => c.object === `scope:organization|${orgA.uuid}`,
    })
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)

    const answers = await driver.authorizeMany({ type: 'users', uuid: 'u1' }, 'docs:read', [
      orgA,
      orgB,
      APP_SCOPE,
    ])

    assert.deepEqual(answers, [true, false, false])
    assert.lengthOf(batches, 1)
    assert.lengthOf(batches[0].checks, 3, 'un item por scope')
    assert.deepEqual(
      batches[0].checks.map((c: any) => `${c.relation} ${c.object}`),
      [
        `can_docs_read scope:organization|${orgA.uuid}`,
        `can_docs_read scope:organization|${orgB.uuid}`,
        'can_docs_read scope:app',
      ]
    )
    assert.deepEqual(checks, [], 'y ni un `check` suelto')
    assert.deepEqual(resolved, [])
  })

  test('un scope repetido COMPARTE item y su respuesta (no duplica el lote)', async ({
    assert,
  }) => {
    const orgA = orgScope()
    const { driver, tree, batches } = factsDriver({
      allow: (c) => c.object === `scope:organization|${orgA.uuid}`,
    })
    const orgB = orgScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)

    const answers = await driver.authorizeMany({ type: 'users', uuid: 'u1' }, 'docs:read', [
      orgA,
      orgB,
      orgA,
    ])

    assert.deepEqual(answers, [true, false, true])
    assert.lengthOf(batches, 1)
    assert.lengthOf(batches[0].checks, 2, 'dos scopes distintos, dos items')
  })

  test('permiso desconocido ⇒ todo `false` sin tocar el servidor; sin scopes, `[]`', async ({
    assert,
  }) => {
    const { driver, tree, batches } = factsDriver({ allow: () => true })
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    assert.deepEqual(
      await driver.authorizeMany({ type: 'users', uuid: 'u1' }, 'no:existe', [org, APP_SCOPE]),
      [false, false]
    )
    assert.deepEqual(await driver.authorizeMany({ type: 'users', uuid: 'u1' }, 'docs:read', []), [])
    assert.deepEqual(batches, [])
  })

  test('un `error` en un check del lote es 503, no un `false` (invariante 5)', async ({ assert }) => {
    const { driver, tree } = factsDriver()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    ;(driver as any).client.batchCheck = async (body: any) => ({
      result: (body.checks ?? []).map((c: any) => ({
        correlationId: c.correlationId,
        error: { message: 'input_error' },
        request: c,
      })),
    })

    await rejects(
      assert,
      () => driver.authorizeMany({ type: 'users', uuid: 'u1' }, 'docs:read', [org]),
      { status: 503, code: 'E_AUTHZ_BACKEND_UNAVAILABLE' },
      'un error por check'
    )
  })
})

test.group('facts · 3b-2c — `grant`/`revoke` escriben el binding ENLAZADO', (group) => {
  group.each.setup(seedCatalog)

  test('`grant` enlaza el binding al scope y al rol, además del asignado', async ({ assert }) => {
    const { driver, tree, tuples } = factsDriver()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const roleUuid = await roleUuidOf('org-editor')
    const binding = `role_binding:organization|${org.uuid}|${roleUuid}`

    await driver.grant({ type: 'users', uuid: 'u1' }, 'org-editor', org, { expiresAt: null })

    assert.deepEqual(tupleList(tuples), [
      `role:${roleUuid}#role@${binding}`,
      `${binding}#binding@scope:organization|${org.uuid}`,
      `user:u1#assignee@${binding}`,
    ])
  })

  test('el enlace es idempotente: un segundo grant no lo duplica ni falla', async ({ assert }) => {
    const { driver, tree, tuples } = factsDriver()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const roleUuid = await roleUuidOf('org-editor')

    await driver.grant({ type: 'users', uuid: 'u1' }, 'org-editor', org, { expiresAt: null })
    await driver.grant({ type: 'users', uuid: 'u2' }, 'org-editor', org, { expiresAt: null })

    assert.deepEqual(tupleList(tuples), [
      `role:${roleUuid}#role@role_binding:organization|${org.uuid}|${roleUuid}`,
      `role_binding:organization|${org.uuid}|${roleUuid}#binding@scope:organization|${org.uuid}`,
      `user:u1#assignee@role_binding:organization|${org.uuid}|${roleUuid}`,
      `user:u2#assignee@role_binding:organization|${org.uuid}|${roleUuid}`,
    ])
  })

  test('`revoke` se lleva la asignación y deja el enlace (inerte sin asignados, y otro holder lo sigue usando)', async ({
    assert,
  }) => {
    const { driver, tree, tuples } = factsDriver()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const roleUuid = await roleUuidOf('org-editor')
    await driver.grant({ type: 'users', uuid: 'u1' }, 'org-editor', org, { expiresAt: null })
    await driver.grant({ type: 'users', uuid: 'u2' }, 'org-editor', org, { expiresAt: null })

    await driver.revoke({ type: 'users', uuid: 'u1' }, 'org-editor', org)

    assert.deepEqual(tupleList(tuples), [
      `role:${roleUuid}#role@role_binding:organization|${org.uuid}|${roleUuid}`,
      `role_binding:organization|${org.uuid}|${roleUuid}#binding@scope:organization|${org.uuid}`,
      `user:u2#assignee@role_binding:organization|${org.uuid}|${roleUuid}`,
    ])
  })

  test('en modo `resolver` el grant escribe SOLO el assignee (el lote es aditivo)', async ({
    assert,
  }) => {
    const { driver, tree, tuples } = factsDriver({ hierarchy: 'resolver' })
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const roleUuid = await roleUuidOf('org-editor')

    await driver.grant({ type: 'users', uuid: 'u1' }, 'org-editor', org, { expiresAt: null })

    assert.deepEqual(tupleList(tuples), [
      `user:u1#assignee@role_binding:organization|${org.uuid}|${roleUuid}`,
    ])
  })
})

test.group('facts · 3b-2c — `deny`/`removeDeny` son `scope#denied_<P>`', (group) => {
  group.each.setup(seedCatalog)

  test('`deny` escribe `scope:<key>#denied_<P>@<holder>` y ningún `deny_binding`', async ({
    assert,
  }) => {
    const { driver, tree, tuples } = factsDriver()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    await driver.deny({ type: 'users', uuid: 'u1' }, 'docs:read', org)

    assert.deepEqual(tupleList(tuples), [`user:u1#denied_docs_read@scope:organization|${org.uuid}`])
  })

  test('`removeDeny` lo quita, y re-denegar/re-quitar son no-ops seguros (invariante 6)', async ({
    assert,
  }) => {
    const { driver, tree, tuples } = factsDriver()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    await driver.deny({ type: 'users', uuid: 'u1' }, 'docs:read', org)
    await driver.deny({ type: 'users', uuid: 'u1' }, 'docs:read', org)
    await driver.removeDeny({ type: 'users', uuid: 'u1' }, 'docs:read', org)
    await driver.removeDeny({ type: 'users', uuid: 'u1' }, 'docs:read', org)

    assert.deepEqual(tupleList(tuples), [])
  })

  test('un permiso fuera del catálogo sigue siendo 422 en las dos escrituras', async ({ assert }) => {
    const { driver, tree, tuples } = factsDriver()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    await rejects(
      assert,
      () => driver.deny({ type: 'users', uuid: 'u1' }, 'no:existe', org),
      { status: 422, code: 'E_AUTHZ_UNKNOWN_PERMISSION' }
    )
    await rejects(
      assert,
      () => driver.removeDeny({ type: 'users', uuid: 'u1' }, 'no:existe', org),
      { status: 422, code: 'E_AUTHZ_UNKNOWN_PERMISSION' }
    )
    assert.deepEqual(tupleList(tuples), [])
  })

  test('`listDenies` lee la forma NUEVA (si no, un deny vivo sería invisible)', async ({
    assert,
  }) => {
    const { driver, tree } = factsDriver()
    const org = orgScope()
    const other = orgScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(other, APP_SCOPE)
    const subject = { type: 'users', uuid: 'u1' }

    await driver.deny(subject, 'docs:read', org)
    await driver.deny(subject, 'docs:write', other)

    assert.deepEqual(await driver.listDenies(subject, org), [{ permission: 'docs:read', scope: org }])
    assert.sameDeepMembers(await driver.listDenies(subject), [
      { permission: 'docs:read', scope: org },
      { permission: 'docs:write', scope: other },
    ])
  })

  test('`listScopes` no lista un scope donde el deny gana (si no lo viera, sería fail-open)', async ({
    assert,
  }) => {
    const { driver, tree } = factsDriver()
    const orgA = orgScope()
    const orgB = orgScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    const subject = { type: 'users', uuid: 'u1' }
    await driver.grant(subject, 'org-editor', orgA, { expiresAt: null })
    await driver.grant(subject, 'org-editor', orgB, { expiresAt: null })

    await driver.deny(subject, 'docs:read', orgB)

    assert.deepEqual(await driver.listScopes(subject, 'docs:read'), [orgA])
  })

  test('`purgeScope` se lleva los denies y el enlace del scope, y NO la arista `parent`', async ({
    assert,
  }) => {
    const { driver, tree, tuples } = factsDriver()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    await driver.onScopeAttached!(org, APP_SCOPE)
    const subject = { type: 'users', uuid: 'u1' }
    await driver.grant(subject, 'org-editor', org, { expiresAt: null })
    await driver.deny(subject, 'docs:read', org)

    await driver.purgeScope(org)

    assert.deepEqual(
      tupleList(tuples),
      [`scope:app#parent@scope:organization|${org.uuid}`],
      'la arista es lo ÚLTIMO y la borra `detached`, no la purga (S6)'
    )
  })
})

/**
 * **3b-2c contra el servidor REAL.** Lo de arriba fija la FORMA (cuántas
 * requests, qué tuplas); esto fija la SEMÁNTICA, que es lo único que
 * demuestra que el Check único responde lo que responde el contrato. Todo el
 * camino es el del paquete: `syncAuthzCatalog` con la proyección del driver,
 * `scopes.attached` para el árbol, `grant`/`deny`/`revoke`/`removeDeny` para
 * los hechos y `authorize`/`authorizeMany` para preguntar. Ni una tupla a
 * mano.
 */
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('facts · 3b-2c — un solo Check contra el servidor real', (group) => {
    const stores: string[] = []
    group.each.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) {
        await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
      }
    })

    /** Store con el modelo (c2), catálogo sincronizado (con proyección) y árbol en el store. */
    async function factsStore() {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({
        name: `facts-authorize-${Date.now()}-${stores.length}`,
      })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS, PERMISSIONS)
      )
      const tree = memoryScopeTree()
      const driver = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id,
        holderTypes: HOLDERS,
        resolveChain: resolveChainFrom(tree),
        hierarchy: 'facts',
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      })
      await cleanAuthzTables()
      await syncAuthzCatalog(
        {
          permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
          roles: [
            { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] },
            { slug: 'unit-lead', scopeType: 'unit', permissions: ['docs:read', 'docs:write'] },
          ],
        },
        { projection: driver.catalogProjection() }
      )
      const orgA = orgScope()
      const orgB = orgScope()
      const unit = unitScope()
      await tree.attach(orgA, APP_SCOPE)
      await tree.attach(orgB, APP_SCOPE)
      await tree.attach(unit, orgA)
      await driver.onScopeAttached(orgA, APP_SCOPE)
      await driver.onScopeAttached(orgB, APP_SCOPE)
      await driver.onScopeAttached(unit, orgA)
      return { driver, tree, orgA, orgB, unit }
    }

    /**
     * **Corrección de 3b-2a encontrada aquí.** La proyección del catálogo
     * (A5) se juzgó contra un doble en memoria, y el doble aceptaba un `Read`
     * cuyo objeto era solo el tipo (`role:`) sin `user`. El servidor REAL lo
     * rechaza con un 400 («the object type field is required and both the
     * object id and user cannot be empty»), así que `syncAuthzCatalog` con
     * proyección era un 503 en cuanto tocaba un store de verdad. Se lee por
     * cada comodín de holder, que es exactamente la forma de las tuplas de
     * (c2), y el espejo sigue convergiendo (incluidas las de un rol que el
     * catálogo ya no lista).
     */
    test('la proyección del catálogo converge contra el servidor real', async ({ assert }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({
        name: `facts-projection-${Date.now()}`,
      })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS, PERMISSIONS)
      )
      const driver = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id,
        holderTypes: HOLDERS,
        logger: { warn: () => {} },
      })
      const client = new OpenFgaClient({ apiUrl, storeId: store.id })
      const permits = async () => {
        const out: string[] = []
        for (const holder of Object.values(HOLDERS)) {
          const page = await client.read({ user: `${holder}:*`, object: 'role:' })
          out.push(...(page.tuples ?? []).map((t: any) => `${t.key.user}#${t.key.relation}@${t.key.object}`))
        }
        return out.sort()
      }
      const sync = (permissions: string[]) =>
        syncAuthzCatalog(
          {
            permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
            roles: [{ slug: 'org-editor', scopeType: 'organization', permissions }],
          },
          { projection: driver.catalogProjection() }
        )

      await cleanAuthzTables()
      await sync(['docs:read', 'docs:write'])
      const roleUuid = await roleUuidOf('org-editor')
      assert.lengthOf(await permits(), 6, '2 permisos × 3 holders')

      // Quitar un permiso del rol son deletes, no una reescritura del modelo.
      await sync(['docs:read'])
      assert.deepEqual(await permits(), [
        `admin:*#permits_docs_read@role:${roleUuid}`,
        `integration:*#permits_docs_read@role:${roleUuid}`,
        `user:*#permits_docs_read@role:${roleUuid}`,
      ])
    })

    test('un grant concede en su scope y HACIA ABAJO, nunca en hermanos ni hacia arriba (invariante 1)', async ({
      assert,
    }) => {
      const { driver, orgA, orgB, unit } = await factsStore()
      const u1 = { type: 'users', uuid: '01a00000-0000-7000-8000-0000000000u1'.replace('u1', '01') }

      assert.isFalse(await driver.authorize(u1, 'docs:read', orgA), 'sin grant, nada')

      await driver.grant(u1, 'org-editor', orgA, { expiresAt: null })

      assert.isTrue(await driver.authorize(u1, 'docs:read', orgA))
      assert.isTrue(await driver.authorize(u1, 'docs:read', unit), 'la unit hereda de su org')
      assert.isFalse(await driver.authorize(u1, 'docs:read', orgB), 'nunca a hermanos')
      assert.isFalse(await driver.authorize(u1, 'docs:read', APP_SCOPE), 'nunca hacia arriba')
      assert.isFalse(
        await driver.authorize(u1, 'docs:write', orgA),
        'el catálogo acota lo que el rol concede'
      )

      // Y la enumeración dice lo mismo que la decisión.
      assert.deepEqual(await driver.listScopes(u1, 'docs:read'), [orgA])

      await driver.revoke(u1, 'org-editor', orgA)
      assert.isFalse(await driver.authorize(u1, 'docs:read', orgA), 'revocar quita, y hacia abajo también')
      assert.isFalse(await driver.authorize(u1, 'docs:read', unit))
    })

    test('el deny explícito gana en la cadena y quitarlo restaura (invariante 2)', async ({
      assert,
    }) => {
      const { driver, orgA, unit } = await factsStore()
      const u1 = { type: 'users', uuid: '01a00000-0000-7000-8000-000000000002' }
      await driver.grant(u1, 'org-editor', orgA, { expiresAt: null })

      await driver.deny(u1, 'docs:read', unit)
      assert.isFalse(await driver.authorize(u1, 'docs:read', unit), 'el deny del hijo gana')
      assert.isTrue(await driver.authorize(u1, 'docs:read', orgA), 'y no sube al padre')
      assert.deepEqual(await driver.listDenies(u1), [{ permission: 'docs:read', scope: unit }])
      assert.deepEqual(await driver.listScopes(u1, 'docs:read'), [orgA])

      // Un deny ARRIBA bloquea abajo (se hereda por `parent` dentro del modelo).
      await driver.deny(u1, 'docs:read', orgA)
      assert.isFalse(await driver.authorize(u1, 'docs:read', orgA))
      assert.deepEqual(await driver.listScopes(u1, 'docs:read'), [])

      await driver.removeDeny(u1, 'docs:read', orgA)
      await driver.removeDeny(u1, 'docs:read', unit)
      assert.isTrue(await driver.authorize(u1, 'docs:read', unit), 'quitar el deny restaura')
      assert.deepEqual(await driver.listDenies(u1), [])
    })

    test('una asignación caducada no concede, sin scheduler (invariante 3)', async ({ assert }) => {
      const { driver, orgA, unit } = await factsStore()
      const u1 = { type: 'users', uuid: '01a00000-0000-7000-8000-000000000003' }

      await driver.grant(u1, 'org-editor', orgA, { expiresAt: new Date(Date.now() - 60_000) })
      assert.isFalse(await driver.authorize(u1, 'docs:read', orgA))
      assert.isFalse(await driver.authorize(u1, 'docs:read', unit))

      await driver.grant(u1, 'org-editor', orgA, { expiresAt: new Date(Date.now() + 600_000) })
      assert.isTrue(await driver.authorize(u1, 'docs:read', orgA), 'vigente sí concede')
    })

    test('holders polimórficos: el mismo uuid con otro type no se cruza (invariante 4)', async ({
      assert,
    }) => {
      const { driver, orgA } = await factsStore()
      const uuid = '01a00000-0000-7000-8000-000000000004'
      await driver.grant({ type: 'users', uuid }, 'org-editor', orgA, { expiresAt: null })

      assert.isTrue(await driver.authorize({ type: 'users', uuid }, 'docs:read', orgA))
      assert.isFalse(await driver.authorize({ type: 'admins', uuid }, 'docs:read', orgA))
    })

    test('`authorizeMany` responde por scope lo mismo que `authorize`, en un solo lote', async ({
      assert,
    }) => {
      const { driver, orgA, orgB, unit } = await factsStore()
      const u1 = { type: 'users', uuid: '01a00000-0000-7000-8000-000000000005' }
      await driver.grant(u1, 'org-editor', orgA, { expiresAt: null })
      await driver.deny(u1, 'docs:read', unit)

      const scopes = [orgA, orgB, unit, orgA, APP_SCOPE]
      const many = await driver.authorizeMany(u1, 'docs:read', scopes)
      const one = []
      for (const scope of scopes) one.push(await driver.authorize(u1, 'docs:read', scope))

      assert.deepEqual(many, [true, false, false, true, false])
      assert.deepEqual(many, one, 'authorizeMany y authorize no pueden discrepar')
    })

    test('un permiso desconocido y un scope que el store no conoce son `false`, no un 503', async ({
      assert,
    }) => {
      const { driver, orgA } = await factsStore()
      const u1 = { type: 'users', uuid: '01a00000-0000-7000-8000-000000000006' }
      await driver.grant(u1, 'org-editor', orgA, { expiresAt: null })

      // Sin el memo esto sería `can_no_existe`: 400 del servidor ⇒ 503.
      assert.isFalse(await driver.authorize(u1, 'no:existe', orgA))
      assert.deepEqual(await driver.authorizeMany(u1, 'no:existe', [orgA]), [false])
      // Un scope que nadie colgó del árbol no tiene tuplas: `false`, y sin
      // preguntarle al resolutor del consumidor.
      assert.isFalse(await driver.authorize(u1, 'docs:read', orgScope()))
    })

    test('`purgeScope` deja el scope a cero en el store (hechos y denies de la forma nueva)', async ({
      assert,
    }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const { driver, orgA, unit } = await factsStore()
      const u1 = { type: 'users', uuid: '01a00000-0000-7000-8000-000000000007' }
      await driver.grant(u1, 'unit-lead', unit, { expiresAt: null })
      await driver.deny(u1, 'docs:write', unit)
      assert.isTrue(await driver.authorize(u1, 'docs:read', unit))

      await driver.purgeScope(unit)

      assert.isFalse(await driver.authorize(u1, 'docs:read', unit), 'purgado, no concede')
      const client = new OpenFgaClient({ apiUrl, storeId: stores[stores.length - 1] })
      const left = await client.read({ object: `scope:unit|${unit.uuid}` })
      assert.deepEqual(
        (left.tuples ?? []).map((t: any) => t.key.relation),
        ['parent'],
        'la arista `parent` es lo único que sobrevive: la borra `detached` al final (S6)'
      )
      // Y el scope de arriba no se ha tocado.
      const u2 = { type: 'users', uuid: '01a00000-0000-7000-8000-000000000008' }
      await driver.grant(u2, 'org-editor', orgA, { expiresAt: null })
      assert.isTrue(await driver.authorize(u2, 'docs:read', orgA))
    })
  })
}

/* ══ 3b-2e · E1 — el barrido del rol local en `moved` ═══════════════════════ */

/**
 * **Decisión del dueño del 2026-08-30, opción (1).** En `facts` el modelo (c2)
 * no tiene `owner`, así que `authorize` no vuelve a decidir con el árbol de
 * HOY si un rol LOCAL sigue siendo visible: un `role_binding` concede mientras
 * su scope alcance al que pregunta. El invariante 18 decía «mover la unit
 * fuera del owner retira lo concedido SIN ESCRIBIR»; en este driver eso deja
 * de ser cierto y es un **fail-open**.
 *
 * La decisión es barrer en `moved`: el paquete borra las aristas
 * `scope#binding` de los roles locales cuyo owner ya no es ancestro del scope
 * donde cuelga la asignación — y **solo** esas. El criterio de aceptación es
 * un caso de **paridad entre drivers**: el mismo `moved` en `database` y en
 * `facts` ⇒ la misma respuesta de `authorize`.
 */
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('facts · 3b-2e · E1 — el barrido del rol local en `moved`', (group) => {
    const stores: string[] = []
    group.each.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) {
        await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
      }
    })

    /**
     * Un rol LOCAL escrito directamente en el catálogo (que es local y de la
     * plataforma), sin pasar por `defineScopedRole`: E1 tiene que estar verde
     * ANTES de que E4 abra esa puerta en este driver.
     */
    async function defineLocalRole(
      slug: string,
      scopeType: string,
      ownerKey: string,
      permissions: string[],
      reproject?: () => Promise<unknown>
    ): Promise<string> {
      const uuid = uuidv7()
      const now = new Date()
      await withAuthzCatalogWrite(async (trx) => {
        await trx.table('authz_roles').insert({
          uuid, slug, name: slug, scope_type: scopeType, rank: 10,
          owner_scope_key: ownerKey, created_at: now, updated_at: now,
        })
        for (const permission of permissions) {
          const row: any = await trx.from('authz_permissions').where('slug', permission).select('uuid').first()
          await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: uuid, permission_uuid: row.uuid, created_at: now })
        }
      })
      invalidateAuthzCatalog()
      // La proyección del catálogo (`role:<uuid>#permits_<P>`) es del store: un
      // rol escrito por fuera del sync no la tiene, y en `facts` un rol sin
      // proyección no concede NADA. Se rehace con un re-sync (el espejo es del
      // catálogo ENTERO, no del spec). Que `defineScopedRole` la mantenga por
      // sí solo es trabajo de E4.
      if (reproject) await reproject()
      return uuid
    }

    /**
     * El MISMO catálogo y el MISMO árbol para los dos drivers: `database` lee
     * el árbol con `resolveChain` y `openfga` lo tiene como hechos en el
     * store. Lo que se compara es la respuesta de `authorize`.
     */
    async function pair() {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({
        name: `facts-sweep-${Date.now()}-${stores.length}`,
      })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS, PERMISSIONS)
      )
      const tree = memoryScopeTree()
      const fga = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id,
        holderTypes: HOLDERS,
        resolveChain: resolveChainFrom(tree),
        hierarchy: 'facts',
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      })
      await cleanAuthzTables()
      const sync = () =>
        syncAuthzCatalog(
          {
            permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
            roles: [
              { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] },
              { slug: 'unit-editor', scopeType: 'unit', permissions: ['docs:write'] },
            ],
          },
          { projection: fga.catalogProjection() }
        )
      await sync()
      const sql = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })

      const orgA = orgScope()
      const orgB = orgScope()
      const unit = unitScope()
      for (const [child, parent] of [[orgA, APP_SCOPE], [orgB, APP_SCOPE], [unit, orgA]] as const) {
        await tree.attach(child, parent)
        await fga.onScopeAttached!(child, parent)
      }
      /** Mueve el subárbol en los DOS drivers, como haría `manager.scopes.moved`. */
      const move = async (child: any, parent: any) => {
        await tree.move(child, parent)
        await fga.onScopeMoved!(child, parent)
      }
      return { fga, sql, tree, orgA, orgB, unit, move, sync }
    }

    test('PARIDAD: sacar la unit del owner del rol local retira lo concedido en los DOS drivers, y devolverla lo restaura', async ({
      assert,
    }) => {
      const { fga, sql, orgA, orgB, unit, move, sync } = await pair()
      const alice = { type: 'users', uuid: uuidv7() }
      await defineLocalRole('lead', 'unit', `organization|${orgA.uuid}`, ['docs:read'], sync)

      // La unit cuelga de orgA, que es el owner: el rol local concede.
      await sql.grant(alice, 'lead', unit, { expiresAt: null })
      await fga.grant(alice, 'lead', unit, { expiresAt: null })
      assert.isTrue(await sql.authorize(alice, 'docs:read', unit), 'database: concede dentro del owner')
      assert.isTrue(await fga.authorize(alice, 'docs:read', unit), 'facts: concede dentro del owner')

      // La unit se va a orgB: el owner deja de estar en su cadena.
      await move(unit, orgB)
      assert.isFalse(await sql.authorize(alice, 'docs:read', unit), 'database: fuera del owner no concede')
      assert.isFalse(
        await fga.authorize(alice, 'docs:read', unit),
        'facts: fuera del owner tampoco (si concede, es el fail-open del hallazgo 2 del 2c)'
      )

      // Y vuelve: el invariante 18 dice que se restaura.
      await move(unit, orgA)
      assert.isTrue(await sql.authorize(alice, 'docs:read', unit), 'database: de vuelta, restaura')
      assert.isTrue(await fga.authorize(alice, 'docs:read', unit), 'facts: de vuelta, restaura')
    })

    test('y SOLO esas: un rol GLOBAL no se toca, y un rol local se conserva en los scopes que NO salieron del owner', async ({
      assert,
    }) => {
      const { fga, sql, tree, orgA, orgB, unit, move, sync } = await pair()
      const alice = { type: 'users', uuid: uuidv7() }
      const otra = unitScope()
      await tree.attach(otra, orgA)
      await fga.onScopeAttached!(otra, orgA)
      await defineLocalRole('lead', 'unit', `organization|${orgA.uuid}`, ['docs:read'], sync)

      for (const driver of [sql, fga] as const) {
        // Un rol GLOBAL de nivel unit y el rol LOCAL, los dos en la unit que se mueve.
        await driver.grant(alice, { slug: 'unit-editor', scopeType: 'unit' }, unit, { expiresAt: null })
        await driver.grant(alice, 'lead', unit, { expiresAt: null })
        // Y el mismo rol local en OTRA unit que se queda donde está.
        await driver.grant(alice, 'lead', otra, { expiresAt: null })
      }
      assert.isTrue(await fga.authorize(alice, 'docs:write', unit), 'precondición: el global concede')
      assert.isTrue(await fga.authorize(alice, 'docs:read', unit), 'precondición: el local concede')

      await move(unit, orgB)

      for (const [name, driver] of [['database', sql], ['facts', fga]] as const) {
        assert.isTrue(await driver.authorize(alice, 'docs:write', unit), `${name}: el rol GLOBAL no se toca`)
        assert.isFalse(await driver.authorize(alice, 'docs:read', unit), `${name}: el local sale con el subárbol`)
        assert.isTrue(
          await driver.authorize(alice, 'docs:read', otra),
          `${name}: el local sigue vivo donde el owner SIGUE en la cadena`
        )
      }
    })

    test('el barrido es por SUBÁRBOL movido, no por nodo: los descendientes del nodo movido también cambian de cadena', async ({
      assert,
    }) => {
      const { fga, sql, tree, orgA, orgB, unit, move, sync } = await pair()
      const alice = { type: 'users', uuid: uuidv7() }
      const sub = unitScope()
      await tree.attach(sub, unit)
      await fga.onScopeAttached!(sub, unit)
      await defineLocalRole('lead', 'unit', `organization|${orgA.uuid}`, ['docs:read'], sync)

      // La asignación cuelga del NIETO, no del nodo que se mueve.
      await sql.grant(alice, 'lead', sub, { expiresAt: null })
      await fga.grant(alice, 'lead', sub, { expiresAt: null })
      assert.isTrue(await sql.authorize(alice, 'docs:read', sub))
      assert.isTrue(await fga.authorize(alice, 'docs:read', sub))

      await move(unit, orgB)

      assert.isFalse(await sql.authorize(alice, 'docs:read', sub), 'database: el nieto también salió del owner')
      assert.isFalse(await fga.authorize(alice, 'docs:read', sub), 'facts: el barrido tiene que bajar el subárbol entero')
    })
  })
}

/* ══ 3b-2e · E4 — `purgeRole` soportado en `openfga` ════════════════════════ */

/**
 * Hasta 3b el driver `openfga` decía «no sé purgar un rol» NO declarando
 * `purgeRole`, y por eso `defineScopedRole` era 500 `E_AUTHZ_UNSUPPORTED`
 * antes de escribir (3E · P4): un rol local que nada puede borrar deja
 * muertos `deleteScopedRole` y `scopes.detached` para siempre.
 *
 * Con (c2) sí se enumera: el binding apunta a su rol (`role_binding#role`), así
 * que los bindings de un rol se leen filtrando por `user: role:<uuid>` — y la
 * arista `scope#binding` dice de qué scope cuelga cada uno.
 */
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('facts · 3b-2e · E4 — `purgeRole` y la API de delegación', (group) => {
    const stores: string[] = []
    group.each.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) {
        await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
      }
    })

    async function world(hierarchy: 'facts' | 'resolver' = 'facts') {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({
        name: `facts-purgerole-${Date.now()}-${stores.length}`,
      })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS, PERMISSIONS)
      )
      const tree = memoryScopeTree()
      const driver = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id,
        holderTypes: HOLDERS,
        resolveChain: resolveChainFrom(tree),
        hierarchy,
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      })
      await cleanAuthzTables()
      await syncAuthzCatalog(
        {
          permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
          roles: [
            { slug: 'org-admin', scopeType: 'organization', rank: 50, permissions: ['docs:read', 'docs:write'] },
          ],
        },
        { projection: driver.catalogProjection() }
      )
      const manager = new AuthorizationManager({
        default: 'openfga',
        drivers: { openfga: () => driver },
        holderTypes: HOLDERS,
        scopes: { resolveChain: resolveChainFrom(tree), acceptScopeDriftRisk: true },
        delegablePermissions: ['docs:read', 'docs:write'],
        warnOnOptInSecurity: false,
      } as any)
      const orgA = orgScope()
      const unit = unitScope()
      const otra = unitScope()
      for (const [child, parent] of [[orgA, APP_SCOPE], [unit, orgA], [otra, orgA]] as const) {
        await tree.attach(child, parent)
        await driver.onScopeAttached!(child, parent)
      }
      const admin = { type: 'users', uuid: uuidv7() }
      await driver.grant(admin, { slug: 'org-admin', scopeType: 'organization' }, orgA, { expiresAt: null })
      return { driver, manager, tree, orgA, unit, otra, admin }
    }

    test('`defineScopedRole` deja de negarse Y el rol CONCEDE de verdad (la proyección se mantiene)', async ({
      assert,
    }) => {
      const { driver, manager, orgA, unit, admin } = await world()
      const alice = { type: 'users', uuid: uuidv7() }

      const lead = await manager.defineScopedRole(admin, orgA, {
        slug: 'lead',
        scopeType: 'unit',
        rank: 10,
        permissions: ['docs:write'],
      })
      assert.equal(lead.owner, `organization|${orgA.uuid}`)

      await driver.grant(alice, { uuid: lead.uuid }, unit, { expiresAt: null })
      assert.isTrue(
        await driver.authorize(alice, 'docs:write', unit),
        'un rol definido por la API tiene que CONCEDER: sin proyección, en `facts` no concede nada'
      )
      assert.isFalse(await driver.authorize(alice, 'docs:read', unit), 'y solo lo que vincula')
    })

    test('`updateScopedRole` que quita un permiso deja de conceder al instante', async ({ assert }) => {
      const { driver, manager, orgA, unit, admin } = await world()
      const alice = { type: 'users', uuid: uuidv7() }
      const lead = await manager.defineScopedRole(admin, orgA, {
        slug: 'lead', scopeType: 'unit', rank: 10, permissions: ['docs:read', 'docs:write'],
      })
      await driver.grant(alice, { uuid: lead.uuid }, unit, { expiresAt: null })
      assert.isTrue(await driver.authorize(alice, 'docs:read', unit))

      await manager.updateScopedRole(admin, lead.uuid, { permissions: ['docs:write'] })

      assert.isFalse(await driver.authorize(alice, 'docs:read', unit), 'el catálogo manda también en `facts`')
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
    })

    test('`purgeRole` se lleva las asignaciones de TODOS los scopes, los vínculos y la fila; recrear el slug no revive nada', async ({
      assert,
    }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const { driver, manager, orgA, unit, otra, admin } = await world()
      const alice = { type: 'users', uuid: uuidv7() }
      const bob = { type: 'users', uuid: uuidv7() }
      const lead = await manager.defineScopedRole(admin, orgA, {
        slug: 'lead', scopeType: 'unit', rank: 10, permissions: ['docs:write'],
      })
      await driver.grant(alice, { uuid: lead.uuid }, unit, { expiresAt: null })
      await driver.grant(bob, { uuid: lead.uuid }, otra, { expiresAt: null })
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
      assert.isTrue(await driver.authorize(bob, 'docs:write', otra))

      assert.typeOf(driver.purgeRole, 'function', 'el driver `facts` sí sabe purgar un rol')
      await driver.purgeRole!(lead.uuid)

      assert.isFalse(await driver.authorize(alice, 'docs:write', unit))
      assert.isFalse(await driver.authorize(bob, 'docs:write', otra))
      assert.lengthOf(await db.from('authz_roles').where('uuid', lead.uuid).select('uuid'), 0, 'la fila del rol')
      assert.lengthOf(
        await db.from('authz_role_permissions').where('role_uuid', lead.uuid).select('uuid'),
        0,
        'y sus vínculos'
      )
      // Cero en el store: ni bindings, ni proyección del rol.
      const client = new OpenFgaClient({ apiUrl, storeId: stores[stores.length - 1] })
      const left = await client.read({ user: `role:${lead.uuid}`, object: 'role_binding:' })
      assert.lengthOf(left.tuples ?? [], 0, 'ningún binding apunta ya al rol')

      // Y el slug vuelve a existir con otro uuid: nada resucita.
      const otroLead = await manager.defineScopedRole(admin, orgA, {
        slug: 'lead', scopeType: 'unit', rank: 10, permissions: ['docs:write'],
      })
      assert.notEqual(otroLead.uuid, lead.uuid)
      assert.isFalse(await driver.authorize(alice, 'docs:write', unit), 'alice no resucita con el slug')
      await driver.grant(bob, { uuid: otroLead.uuid }, otra, { expiresAt: null })
      assert.isTrue(await driver.authorize(bob, 'docs:write', otra))
      assert.isFalse(await driver.authorize(alice, 'docs:write', unit))
    })

    test('uuid desconocido ⇒ 422 E_AUTHZ_UNKNOWN_ROLE; mal formado ⇒ 422 E_AUTHZ_INVALID_IDENTITY', async ({
      assert,
    }) => {
      const { driver } = await world()
      await rejects(assert, () => driver.purgeRole!(uuidv7()), { status: 422, code: 'E_AUTHZ_UNKNOWN_ROLE' })
      await rejects(assert, () => driver.purgeRole!('lead'), { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' })
    })

    test('CASO NEGATIVO: en modo `resolver` el driver sigue diciendo que no sabe purgar, y `defineScopedRole` se niega ANTES de escribir', async ({
      assert,
    }) => {
      const { manager, orgA, admin } = await world('resolver')
      const { driver } = await world('resolver')
      assert.isUndefined(
        driver.purgeRole,
        'sin `scope#binding` los bindings de un rol no se enumeran: el modo `resolver` no lo trae'
      )
      await rejects(
        assert,
        () => manager.defineScopedRole(admin, orgA, { slug: 'lead', scopeType: 'unit', rank: 10, permissions: ['docs:write'] }),
        { status: 500, code: 'E_AUTHZ_UNSUPPORTED' }
      )
      assert.lengthOf(await db.from('authz_roles').where('slug', 'lead').select('uuid'), 0, 'y no escribió nada')
    })
  })
}

/* ══ 3b-2e · E2 — capacidades declaradas y el literal aprobado ══════════════ */

/**
 * El cruce 6 del panel 2 aprobó **un literal exacto** para lo que el README
 * puede prometer del modo `facts`, y PROHIBIÓ el titular «sin SQL en el camino
 * caliente» a secas. Esto lo fija: la promesa es «un solo `Check` en
 * `authorize`», y las cinco lecturas de membresía siguen usando `resolveChain`.
 */
test.group('facts · 3b-2e · E2 — el README promete el literal del cruce 6 y nada más', () => {
  test('el literal aprobado está, con las cinco lecturas nombradas', async ({ assert }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf-8')
    assert.include(readme, 'In `facts` mode, `authorize` is a **single `Check`** against OpenFGA')
    assert.include(readme, 'it does not consult your tree (`resolveChain`)')
    assert.include(
      readme,
      '`hasRole`, `listRoles`, `listRoleScopes`, `listSubjects` and `listScopes` **do** use `resolveChain`'
    )
    assert.include(readme, '`grant` and `deny` use it too, to validate that the scope exists')
  })

  test('el titular PROHIBIDO no se vende: «no SQL in the hot path» solo aparece para desmentirlo', async ({
    assert,
  }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf-8')
    assert.include(readme, '"no SQL in the hot path" is not a claim this package makes')
    // Y no hay ninguna otra aparición del titular suelto.
    const claims = readme.match(/no SQL in the hot path/g) ?? []
    assert.lengthOf(claims, 1)
  })

  test('las capacidades declaradas del driver son las de la tabla del README', async ({ assert }) => {
    const facts = new OpenFgaAuthorizationDriver({
      apiUrl: 'http://127.0.0.1:9',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      holderTypes: HOLDERS,
      hierarchy: 'facts',
      acceptScopeDriftRisk: true,
      logger: { warn: () => {} },
    })
    const resolver = new OpenFgaAuthorizationDriver({
      apiUrl: 'http://127.0.0.1:9',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      holderTypes: HOLDERS,
      logger: { warn: () => {} },
    })
    assert.deepEqual(facts.capabilities, {
      hierarchyFacts: true,
      singleCheckAuthorize: true,
      roleInheritanceNative: false,
      listObjectsInherited: false,
      purgeRole: true,
    })
    assert.deepEqual(resolver.capabilities, {
      hierarchyFacts: false,
      singleCheckAuthorize: false,
      roleInheritanceNative: false,
      listObjectsInherited: false,
      purgeRole: false,
    })
    // Una vista por prototipo declara lo MISMO que su original (si no, el
    // gate del manager dependería de por dónde llegue el driver).
    assert.deepEqual(facts.withClock(() => new Date()).capabilities, facts.capabilities)
    assert.deepEqual(new DatabaseAuthorizationDriver({}).capabilities, {
      hierarchyFacts: false,
      singleCheckAuthorize: false,
      roleInheritanceNative: false,
      listObjectsInherited: false,
      purgeRole: true,
    })
  })
})

/* ══ 3b-2e · E5 — los LÍMITES declarados, cada uno con su caso ══════════════ */

/**
 * El cruce 9 del panel dejó tres cotas declaradas y una **sin medir**: la
 * profundidad. Los ~23 que citaba eran de un modelo MÁS SIMPLE; (c2) añade
 * saltos TTU (`binding`, la resta de `can_<P>`), así que había que medirla
 * aquí. Se mide contra el servidor real y el número vive en
 * `FACTS_MAX_RESOLVE_DEPTH`.
 */
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('facts · 3b-2e · E5 — los límites del modelo (c2), medidos', (group) => {
    const stores: string[] = []
    group.each.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) {
        await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
      }
    })

    /** Una cadena de `hops` saltos con el grant en la RAÍZ y el árbol en el store. */
    async function chainStore(hops: number) {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({
        name: `facts-depth-${Date.now()}-${stores.length}`,
      })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS, PERMISSIONS)
      )
      const tree = memoryScopeTree()
      const driver = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id,
        holderTypes: HOLDERS,
        resolveChain: resolveChainFrom(tree),
        hierarchy: 'facts',
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      })
      await cleanAuthzTables()
      await syncAuthzCatalog(
        {
          permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
          roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] }],
        },
        { projection: driver.catalogProjection() }
      )
      const root = orgScope()
      await tree.attach(root, APP_SCOPE)
      await driver.onScopeAttached!(root, APP_SCOPE)
      let parent: any = root
      const nodes: any[] = [root]
      for (let i = 0; i < hops; i++) {
        const node = unitScope()
        await tree.attach(node, parent)
        await driver.onScopeAttached!(node, parent)
        nodes.push(node)
        parent = node
      }
      const alice = { type: 'users', uuid: uuidv7() }
      await driver.grant(alice, 'org-editor', root, { expiresAt: null })
      return { driver, nodes, alice }
    }

    test(`la cadena de ${FACTS_MAX_RESOLVE_DEPTH} saltos SÍ decide: la cota medida sobre (c2) es esa y no otra`, async ({
      assert,
    }) => {
      const { driver, nodes, alice } = await chainStore(FACTS_MAX_RESOLVE_DEPTH)
      assert.lengthOf(nodes, FACTS_MAX_RESOLVE_DEPTH + 1)
      assert.isTrue(
        await driver.authorize(alice, 'docs:read', nodes[nodes.length - 1]),
        'en el borde exacto la herencia sigue resolviéndose'
      )
    }).timeout(120_000)

    test(`CASO NEGATIVO: a ${FACTS_MAX_RESOLVE_DEPTH + 2} saltos el servidor no puede resolver, y eso es 503 — jamás un \`false\` silencioso`, async ({
      assert,
    }) => {
      // +2 y no +1 a propósito: a `+1` (23 saltos) el borde es
      // PROBABILÍSTICO —medido: 24 de 25 veces resuelve— y un caso apoyado
      // ahí sería flaky en el artefacto publicado. A +2 falla siempre.
      const { driver, nodes, alice } = await chainStore(FACTS_MAX_RESOLVE_DEPTH + 2)
      // Fail-closed, pero RUIDOSO: un `false` aquí sería indistinguible de
      // «no tiene permiso» y mandaría a buscar un rol mal configurado. Es la
      // cara fea de la cota (un DoS al alcance de quien pueda anidar scopes),
      // y `database` no la tiene: el mismo árbol es legal en un driver y una
      // caída en el otro.
      await rejects(
        assert,
        () => driver.authorize(alice, 'docs:read', nodes[nodes.length - 1]),
        { status: 503, code: 'E_AUTHZ_BACKEND_UNAVAILABLE' }
      )
      // Y por debajo de la cota, la misma pregunta responde.
      assert.isTrue(await driver.authorize(alice, 'docs:read', nodes[FACTS_MAX_RESOLVE_DEPTH]))
    }).timeout(120_000)

    test(`\`authorizeMany\` pasa del tope de ${FGA_MAX_BATCH_CHECK} checks por lote sin truncar ni desordenar`, async ({
      assert,
    }) => {
      const { driver, nodes, alice } = await chainStore(3)
      // 120 scopes: el SDK trocea a 50 por request. Lo que no puede pasar es
      // que la posición 51 traiga la respuesta de otra pregunta (L0.14) ni
      // que el lote se corte en silencio.
      const fuera = Array.from({ length: 60 }, () => orgScope())
      const scopes = [...Array.from({ length: 60 }, (_, i) => nodes[i % nodes.length]), ...fuera]
      assert.isAbove(scopes.length, FGA_MAX_BATCH_CHECK * 2)

      const many = await driver.authorizeMany(alice, 'docs:read', scopes)
      assert.lengthOf(many, scopes.length, 'una respuesta por posición, sin truncar')
      assert.deepEqual(many, [...Array(60).fill(true), ...Array(60).fill(false)])
    }).timeout(120_000)
  })
}
