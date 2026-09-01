/**
 * **La spec PUENTE de la Fase 4-4** — construye a la vez el `AuthorizationDriver`
 * (roles) y el `RelationsDriver` (ReBAC) sobre el MISMO backend y, en `openfga`,
 * el MISMO store, para probar las dos cosas que ningún driver suelto puede:
 *
 *  1. **El caso-exploit del auditor** (la condición dura del veredicto): sin
 *     F-05, un `relate(evil, assignee, {role_binding})` escala a
 *     `roles.authorize` (ROJO reproducido); con F-05 (el manager) es 422 y
 *     `authorize` sigue `false` con el binding legítimo intacto (VERDE),
 *     MEDIDO contra el `:8101` en el store compartido.
 *  2. **La PARIDAD `database` ↔ `openfga`**: la MISMA pregunta a los dos
 *     drivers de relaciones sobre el mismo catálogo/árbol/tuplas ⇒ la MISMA
 *     respuesta.
 *
 * Corre el exploit y la paridad-openfga solo con `OPENFGA_TEST_URL`; la
 * paridad se ejecuta en el motor de `TEST_DB` para `database`.
 */
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { RelationsManager } from '../src/relations/manager.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { openFgaFactsModel } from '../src/drivers/openfga_facts.js'
import { OpenFgaRelationsDriver } from '../src/drivers/openfga_relations_driver.js'
import { OpenFgaAuthorizationDriver } from '../src/drivers/openfga_driver.js'
import { RelationTypeUnknownError } from '../src/errors.js'
import { APP_SCOPE } from '../src/types.js'
import type { RelationsConfig } from '../src/relations/define_relations_config.js'
import type { RelObject, RelSubject, RelationsDriver, ScopeRef } from '../src/types.js'

const HOLDER_MAP = { user: 'user', admin: 'admin', integration: 'integration' } as const

/** La config de relaciones del puente: un `document` con owner ⊆ editor ⊆ viewer. */
function bridgeConfig(): RelationsConfig {
  return defineRelationsConfig({
    objectTypes: [
      {
        type: 'document',
        relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }],
      },
    ],
    holderTypes: ['user', 'admin', 'integration'],
    database: { membersOf: true },
  })
}

const openFgaTestUrl = process.env.OPENFGA_TEST_URL

/* ── 1 · EL CASO-EXPLOIT (rojo→verde) en el store COMPARTIDO ─────────────── */

if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  /**
   * Un store con el modelo FUSIONADO (facts con el permiso `p0` + la config de
   * relaciones), el catálogo sincronizado con su proyección (marcador de raíz
   * incluido), y AMBOS drivers openfga sobre él. Devuelve también el uuid del
   * rol que vincula `p0`.
   */
  async function sharedStore(config: RelationsConfig): Promise<{
    storeId: string
    roles: OpenFgaAuthorizationDriver
    relations: OpenFgaRelationsDriver
    roleUuid: string
  }> {
    const { OpenFgaClient } = await import('@openfga/sdk')
    const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `bridge-${Date.now()}` })
    const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
      openFgaFactsModel(HOLDER_MAP, ['p0'], { objectTypes: config.objectTypes })
    )
    const modelId = model.authorization_model_id!
    const catalog = {
      permissions: [{ slug: 'p0' }],
      roles: [{ slug: 'r0', scopeType: 'app', permissions: ['p0'] }],
    }
    await syncAuthzCatalog(catalog)
    const roles = new OpenFgaAuthorizationDriver({
      apiUrl,
      storeId: store.id!,
      modelId,
      holderTypes: HOLDER_MAP,
      acceptScopeDriftRisk: true,
      logger: { warn: () => {} },
    })
    // La proyección (permits_p0 + el marcador `scope:app#rooted`): sin ella el store deniega.
    await syncAuthzCatalog(catalog, { projection: roles.catalogProjection() })
    const relations = new OpenFgaRelationsDriver(config, {
      apiUrl,
      storeId: store.id!,
      modelId,
      holderTypes: HOLDER_MAP,
      logger: { warn: () => {} },
    })
    const role: any = await db.from('authz_roles').where('slug', 'r0').where('scope_type', 'app').first()
    return { storeId: store.id!, roles, relations, roleUuid: role.uuid }
  }

  test.group('relaciones · 4-4 — el caso-exploit del auditor, en el store COMPARTIDO', (group) => {
    const stores: string[] = []
    group.each.setup(async () => {
      await cleanAuthzTables()
    })
    group.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
    })

    test('🔴 ROJO reproducido: relate(evil, assignee, role_binding, S) EN DIRECTO al driver ⇒ escalada a can_p0', async ({
      assert,
    }) => {
      const config = bridgeConfig()
      const { storeId, roles, relations, roleUuid } = await sharedStore(config)
      stores.push(storeId)
      const alice = { type: 'user', uuid: uuidv7() }
      const evil = { type: 'user', uuid: uuidv7() }
      // Grant legítimo de alice a nivel app (mono-tenant: la partición `app`).
      await roles.grant(alice, 'r0', APP_SCOPE, { expiresAt: null })
      assert.isTrue(await roles.authorize(alice, 'p0', APP_SCOPE), 'CONTROL: alice concede')
      assert.isFalse(await roles.authorize(evil, 'p0', APP_SCOPE), 'evil aún NO concede')

      // El ATAQUE: llamar al driver EN DIRECTO (saltándose el manager y su F-05)
      // con object.type='role_binding' compone `role_binding:app|<roleUuid>`
      // —byte a byte el binding real— y escribe un `assignee` plano.
      await relations.relate(evil, 'assignee', { type: 'role_binding', id: roleUuid }, APP_SCOPE)

      // Sin F-05, la escritura de relations CRUZA a roles.authorize: escalada.
      assert.isTrue(
        await roles.authorize(evil, 'p0', APP_SCOPE),
        'ROJO: una escritura de relations concedió en roles.authorize (la escalada del auditor)'
      )
    })

    test('🟢 VERDE: el manager corta con F-05 (422) y authorize(evil, p0, S) sigue false, alice intacto', async ({
      assert,
    }) => {
      const config = bridgeConfig()
      const { storeId, roles, relations, roleUuid } = await sharedStore(config)
      stores.push(storeId)
      const manager = new RelationsManager(relations, config)
      const alice = { type: 'user', uuid: uuidv7() }
      const evil = { type: 'user', uuid: uuidv7() }
      await roles.grant(alice, 'r0', APP_SCOPE, { expiresAt: null })
      assert.isTrue(await roles.authorize(alice, 'p0', APP_SCOPE))

      // El MISMO ataque, ahora por el manager: F-05 lo corta ANTES del driver.
      let caught: any
      try {
        await manager.relate(evil, 'assignee', { type: 'role_binding', id: roleUuid }, APP_SCOPE)
        assert.fail('debería haber lanzado F-05')
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 422)
      assert.equal(caught.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN')
      assert.instanceOf(caught, RelationTypeUnknownError)

      // La condición dura: evil NO concede, y el binding legítimo de alice
      // sigue intacto — MEDIDO contra el `:8101` en el store compartido.
      assert.isFalse(await roles.authorize(evil, 'p0', APP_SCOPE), 'VERDE: evil no escaló')
      assert.isTrue(await roles.authorize(alice, 'p0', APP_SCOPE), 'el binding legítimo intacto')
    })
  })

  /* ── 1b · F-01/F-02 · la frontera roles↔relations CON DIENTES (4-5) ─────── */

  /**
   * F-01/F-02 anclados en `openfga` (store COMPARTIDO, donde SÍ hay riesgo
   * real): en `database` son DECORATIVOS (tablas disjuntas `authz_assignments`
   * ≠ `authz_relations`, pasarían sin frontera), así que se degradan a
   * documentación (ver `relations_database.spec.ts`). Aquí tienen dientes: un
   * mutante de CONFLACIÓN —que una mitad LEA las tuplas de la otra— los pone
   * ROJOS. La conflación se planta mutando el driver (rojo→verde por pieza, en
   * el informe con la salida roja literal); en verde, la frontera se sostiene
   * por CONSTRUCCIÓN (tipos de objeto disjuntos: `scope`/`role_binding` de
   * facts ≠ `document`/`group` de relaciones, y relaciones disjuntas:
   * `can_<P>`/`assignee` ≠ `viewer`/`member`).
   */
  test.group('relaciones · 4-5 — la frontera roles↔relations CON DIENTES (F-01/F-02)', (group) => {
    const stores: string[] = []
    group.each.setup(async () => {
      await cleanAuthzTables()
    })
    group.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
    })

    test('F-01 · una tupla de relación (document#viewer) NO hace roles.authorize true', async ({ assert }) => {
      const config = bridgeConfig()
      const { storeId, roles, relations } = await sharedStore(config)
      stores.push(storeId)
      const u = { type: 'user', uuid: uuidv7() }
      const doc: RelObject = { type: 'document', id: uuidv7() }
      // Una relación ReBAC de `u` sobre un documento — SIN ningún grant de rol.
      await relations.relate(u, 'viewer', doc, APP_SCOPE)
      assert.isTrue(await relations.check(u, 'viewer', doc, APP_SCOPE), 'CONTROL: la relación existe')
      // La frontera: esa tupla NO concede NINGÚN permiso en roles.authorize.
      assert.isFalse(
        await roles.authorize(u, 'p0', APP_SCOPE),
        'F-01: una tupla document#viewer no puede conceder can_p0 (la mitad de relaciones NO alimenta roles)'
      )
    })

    test('F-02 · un grant de rol NO crea una relación (relations.check sigue false)', async ({ assert }) => {
      const config = bridgeConfig()
      const { storeId, roles, relations } = await sharedStore(config)
      stores.push(storeId)
      const u = { type: 'user', uuid: uuidv7() }
      const doc: RelObject = { type: 'document', id: uuidv7() }
      await roles.grant(u, 'r0', APP_SCOPE, { expiresAt: null })
      assert.isTrue(await roles.authorize(u, 'p0', APP_SCOPE), 'CONTROL: el rol concede el permiso')
      // La frontera recíproca: el grant no fabrica ninguna relación ReBAC.
      assert.isFalse(
        await relations.check(u, 'viewer', doc, APP_SCOPE),
        'F-02: un rol no crea una relación (la mitad de roles NO alimenta relaciones)'
      )
    })
  })
}

/* ── 2 · PARIDAD database ↔ openfga ──────────────────────────────────────── */

/**
 * Aplica la MISMA secuencia de escrituras a los dos drivers y hace las MISMAS
 * preguntas; devuelve el par de respuestas para comparar. Es lo que ha cazado
 * los defectos serios de la fase (la misma pregunta, la misma respuesta).
 */
async function bothAnswerSame(
  assert: any,
  a: RelationsDriver,
  b: RelationsDriver,
  seed: (driver: RelationsDriver) => Promise<void>,
  ask: (driver: RelationsDriver) => Promise<unknown>
) {
  await seed(a)
  await seed(b)
  const ra = await ask(a)
  const rb = await ask(b)
  assert.deepEqual(ra, rb)
  return ra
}

if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('relaciones · 4-4 — paridad database ↔ openfga (misma pregunta ⇒ misma respuesta)', (group) => {
    const stores: string[] = []
    let openfga: OpenFgaRelationsDriver
    let database: DatabaseRelationsDriver
    const config = bridgeConfig()

    group.each.setup(async () => {
      await db.from('authz_relations').delete()
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `parity-${Date.now()}` })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDER_MAP, [], { objectTypes: config.objectTypes })
      )
      openfga = new OpenFgaRelationsDriver(config, {
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id,
        holderTypes: HOLDER_MAP,
        logger: { warn: () => {} },
      })
      database = new DatabaseRelationsDriver(config)
    })
    group.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
    })

    test('check con includes (editor ⊆ viewer): la misma respuesta', async ({ assert }) => {
      const u: RelSubject = { type: 'user', uuid: uuidv7() }
      const doc: RelObject = { type: 'document', id: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const yes = await bothAnswerSame(
        assert,
        database,
        openfga,
        (d) => d.relate(u, 'editor', doc, p),
        (d) => d.check(u, 'viewer', doc, p)
      )
      assert.isTrue(yes)
      // El inverso NO en los dos.
      const v: RelSubject = { type: 'user', uuid: uuidv7() }
      const no = await bothAnswerSame(
        assert,
        database,
        openfga,
        (d) => d.relate(v, 'viewer', doc, p),
        (d) => d.check(v, 'editor', doc, p)
      )
      assert.isFalse(no)
    })

    test('check con userset anidado (grupos): la misma respuesta', async ({ assert }) => {
      const u: RelSubject = { type: 'user', uuid: uuidv7() }
      const doc: RelObject = { type: 'document', id: uuidv7() }
      const g1: RelObject = { type: 'group', id: uuidv7() }
      const g2: RelObject = { type: 'group', id: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const yes = await bothAnswerSame(
        assert,
        database,
        openfga,
        async (d) => {
          await d.relate(u, 'member', g1, p)
          await d.relate({ object: g1, relation: 'member' }, 'member', g2, p)
          await d.relate({ object: g2, relation: 'member' }, 'viewer', doc, p)
        },
        (d) => d.check(u, 'viewer', doc, p)
      )
      assert.isTrue(yes)
    })

    test('aislamiento de partición: la misma respuesta (false en B)', async ({ assert }) => {
      const u: RelSubject = { type: 'user', uuid: uuidv7() }
      const doc: RelObject = { type: 'document', id: uuidv7() }
      const a: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const b: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const no = await bothAnswerSame(
        assert,
        database,
        openfga,
        (d) => d.relate(u, 'viewer', doc, a),
        (d) => d.check(u, 'viewer', doc, b)
      )
      assert.isFalse(no)
    })

    test('listObjects: el mismo conjunto de ids', async ({ assert }) => {
      const u: RelSubject = { type: 'user', uuid: uuidv7() }
      const d1: RelObject = { type: 'document', id: uuidv7() }
      const d2: RelObject = { type: 'document', id: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      await bothAnswerSame(
        assert,
        database,
        openfga,
        async (d) => {
          await d.relate(u, 'editor', d1, p)
          await d.relate(u, 'viewer', d2, p)
        },
        async (d) => {
          const page = await d.listObjects(u, 'viewer', 'document', p)
          return page.objects.map((o) => o.id).sort()
        }
      )
    })

    test('R-15 · caducidad con el MISMO reloj: T−1 ms / T / T+1 ms, renovación y membresía caducada — la misma respuesta en los dos', async ({
      assert,
    }) => {
      // La caducidad es donde la Fase 2.5 sacó defectos de MOTOR (precisión,
      // zona horaria) y aquí además hay dos MECANISMOS distintos (SQL
      // `expires_at > now` vs la condición `not_expired` con `current_time`):
      // la paridad se mide con el mismo reloj inyectado en los dos drivers.
      const T = new Date('2031-03-03T03:03:03.333Z')
      let current = new Date(T.getTime() - 60_000)
      const clock = () => new Date(current.getTime())
      const dbClocked = database.withClock!(clock)
      const fgaClocked = openfga.withClock!(clock)
      const u: RelSubject = { type: 'user', uuid: uuidv7() }
      const doc: RelObject = { type: 'document', id: uuidv7() }
      const shared: RelObject = { type: 'document', id: uuidv7() }
      const g: RelObject = { type: 'group', id: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      for (const d of [dbClocked, fgaClocked]) {
        await d.relate(u, 'editor', doc, p, { expiresAt: T })
        await d.relate(u, 'member', g, p, { expiresAt: T })
        await d.relate({ object: g, relation: 'member' }, 'viewer', shared, p)
      }
      const observe = async (d: RelationsDriver) => ({
        check: await d.check(u, 'viewer', doc, p),
        listObjects: (await d.listObjects(u, 'viewer', 'document', p)).objects.map((o) => o.id).sort(),
        listSubjects: (await d.listSubjects('editor', doc, p)).subjects.length,
        viaGroup: await d.check(u, 'viewer', shared, p),
      })
      const same = async (label: string) => {
        const a = await observe(dbClocked)
        const b = await observe(fgaClocked)
        assert.deepEqual(a, b, `${label}: database y openfga divergen`)
        return a
      }
      current = new Date(T.getTime() - 1)
      assert.deepEqual(await same('T−1 ms'), { check: true, listObjects: [doc.id, shared.id].sort(), listSubjects: 1, viaGroup: true })
      current = T
      assert.deepEqual(await same('T'), { check: false, listObjects: [], listSubjects: 0, viaGroup: false })
      current = new Date(T.getTime() + 1)
      assert.deepEqual(await same('T+1 ms'), { check: false, listObjects: [], listSubjects: 0, viaGroup: false })
      // Renovación (omitido sobre la CADUCADA revive sin caducidad, invariante 10).
      for (const d of [dbClocked, fgaClocked]) {
        await d.relate(u, 'editor', doc, p)
        await d.relate(u, 'member', g, p)
      }
      current = new Date('2099-01-01T00:00:00.000Z')
      assert.deepEqual(await same('revivida'), { check: true, listObjects: [doc.id, shared.id].sort(), listSubjects: 1, viaGroup: true })
      // Y `enumerateRelations` de los dos enumera la caducidad igual (null tras revivir).
      const enumerated = async (d: RelationsDriver) =>
        (await d.enumerateRelations!(p)).tuples.map((t) => `${t.relation}@${t.object.id}:${t.expiresAt ? t.expiresAt.toISOString() : 'null'}`).sort()
      assert.deepEqual(await enumerated(dbClocked), await enumerated(fgaClocked))
    })

    test('unrelate retira: la misma respuesta (false en los dos)', async ({ assert }) => {
      const u: RelSubject = { type: 'user', uuid: uuidv7() }
      const doc: RelObject = { type: 'document', id: uuidv7() }
      const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
      const no = await bothAnswerSame(
        assert,
        database,
        openfga,
        async (d) => {
          await d.relate(u, 'viewer', doc, p)
          await d.unrelate(u, 'viewer', doc, p)
        },
        (d) => d.check(u, 'viewer', doc, p)
      )
      assert.isFalse(no)
    })
  })
}
