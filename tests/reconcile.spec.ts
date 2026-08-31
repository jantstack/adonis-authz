/**
 * 3b-3a — **`authz:reconcile --to=openfga`**: la migración DB → FGA.
 *
 * Es el motivo por el que existe la fase: «todo en un driver o todo en otro,
 * con una migración idempotente y bidireccional». Aquí va la dirección
 * DB → FGA y la infraestructura común (`freeze()`, `scopes.enumerateEdges`);
 * la inversa y el contrato de migración son el 3b-3b.
 *
 * Nada de esto se juzga con un doble en memoria: el store es el `:8101` real
 * (`OPENFGA_TEST_URL`) y el árbol, además del `Map` de `memoryScopeTree`, el
 * SQL del harness (PG/MySQL).
 */

import { test } from '@japa/runner'
import db from '@adonisjs/lucid/services/db'
import { AuthorizationManager } from '../src/manager.js'
import { sqlScopeEdges } from '../src/sql_descendants.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import type { ScopeEdge } from '../src/types.js'
import { cleanSqlScopeTree, sqlScopeTree } from './helpers/sql_scope_tree.js'
import { cleanAuthzTables, cleanScopeOutbox } from './helpers/schema.js'
import { sqlScopeOutbox } from '../src/scope_outbox.js'
import { reconcileLines } from '../commands/authz_reconcile.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { OpenFgaAuthorizationDriver, openFgaFactsModel } from '../src/openfga.js'
import { v7 as uuidv7 } from 'uuid'

const HOLDERS = { users: 'user' }
/** Los tres holders del modelo publicado: el marcador de raíz lleva uno por tipo. */
const HOLDERS_3 = { users: 'user', admins: 'admin', integrations: 'integration' }
const PERMISSIONS = ['docs:read', 'docs:write']
const orgScope = () => ({ type: 'organization', uuid: uuidv7() })

/** Todas las tuplas del store, como `user#relation@object`, ordenadas. */
async function todoElStore(driver: any): Promise<string[]> {
  const out: string[] = []
  let continuationToken: string | undefined
  do {
    const page = await driver.client.read({}, { pageSize: 100, continuationToken })
    for (const t of page.tuples ?? []) out.push(`${t.key.user}#${t.key.relation}@${t.key.object}`)
    continuationToken = page.continuation_token || undefined
  } while (continuationToken)
  return out.sort()
}

/** `scopes.enumerateEdges` sobre la tabla del harness (`demo_scopes`). */
const edgesOfDemoScopes = () =>
  sqlScopeEdges({ table: 'demo_scopes', uuidColumn: 'uuid', parentColumn: 'parent_uuid', typeColumn: 'type' })

/** Un driver de laboratorio que cuenta lo que le llega; nada sale a la red. */
function spyDriver(): any {
  const calls: string[] = []
  return {
    calls,
    capabilities: {
      hierarchyFacts: false,
      singleCheckAuthorize: false,
      roleInheritanceNative: false,
      listObjectsInherited: false,
      purgeRole: true,
      countRoleAssignments: false,
      canonicalScopeReads: true,
    },
    async authorize() {
      calls.push('authorize')
      return true
    },
    async grant() {
      calls.push('grant')
      return { existed: false, expiresAt: null }
    },
    async revoke() {
      calls.push('revoke')
    },
    async hasRole() {
      calls.push('hasRole')
      return false
    },
    async deny() {
      calls.push('deny')
    },
    async removeDeny() {
      calls.push('removeDeny')
    },
    async listSubjects() {
      calls.push('listSubjects')
      return []
    },
    async listRoles() {
      calls.push('listRoles')
      return []
    },
    async listRoleScopes() {
      calls.push('listRoleScopes')
      return []
    },
    async listScopes() {
      calls.push('listScopes')
      return []
    },
    async purgeScope() {
      calls.push('purgeScope')
    },
    async onScopeAttached() {
      calls.push('onScopeAttached')
    },
    async onScopeMoved() {
      calls.push('onScopeMoved')
    },
    async onScopeDetached() {
      calls.push('onScopeDetached')
    },
  }
}

function frozenManager() {
  const tree = memoryScopeTree()
  const driver = spyDriver()
  const manager = new AuthorizationManager({
    default: 'spy',
    drivers: { spy: () => driver },
    holderTypes: HOLDERS,
    scopes: { resolveChain: resolveChainFrom(tree) },
    warnOnOptInSecurity: false,
  })
  return { manager, driver, tree }
}

async function rejects(assert: any, run: () => unknown, code: string, status: number) {
  try {
    await run()
    assert.fail(`se esperaba ${code} y no lanzó`)
  } catch (error: any) {
    assert.equal(error.code, code)
    assert.equal(error.status, status)
    return error
  }
}

/* ════════════════════════════════════════════════════════════════════════
 * P1 · `manager.freeze()` — la migración no compite con las escrituras.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('3b-3a · freeze()', () => {
  test('congelado: las ESCRITURAS son 503 reintentable y no llegan al driver', async ({ assert }) => {
    const { manager, driver, tree } = frozenManager()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const subject = { type: 'users', uuid: uuidv7() }

    manager.freeze('reconcile de prueba')

    for (const write of [
      () => manager.grant(subject, 'org-editor', org),
      () => manager.revoke(subject, 'org-editor', org),
      () => manager.deny(subject, 'docs:read', org),
      () => manager.removeDeny(subject, 'docs:read', org),
      () => manager.scopes.attached(orgScope(), APP_SCOPE),
      () => manager.scopes.moved(org, APP_SCOPE),
      () => manager.scopes.detached(org),
    ]) {
      const error = await rejects(assert, write, 'E_AUTHZ_FROZEN', 503)
      assert.isTrue(error.retryable, 'un 503 de freeze tiene que declararse reintentable')
      assert.include(error.message, 'reconcile de prueba')
    }
    assert.deepEqual(driver.calls, [], 'ninguna escritura puede haber llegado al driver')
  })

  test('congelado: las LECTURAS siguen funcionando', async ({ assert }) => {
    const { manager, driver, tree } = frozenManager()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const subject = { type: 'users', uuid: uuidv7() }

    manager.freeze()

    assert.isTrue(await manager.authorize(subject, 'docs:read', org))
    assert.deepEqual(await manager.listRoles(subject, org), [])
    assert.isFalse(await manager.hasRole(subject, 'org-editor', org))
    assert.deepEqual(driver.calls, ['authorize', 'listRoles', 'hasRole'])
  })

  test('unfreeze devuelve las escrituras, y una vista de forRequest hereda el estado del manager', async ({
    assert,
  }) => {
    const { manager, driver, tree } = frozenManager()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const subject = { type: 'users', uuid: uuidv7() }
    const view = manager.forRequest()

    manager.freeze()
    // La vista NO es otro manager para esto: congelar el motor congela todo
    // lo que escribe por él.
    await rejects(assert, () => view.grant(subject, 'org-editor', org), 'E_AUTHZ_FROZEN', 503)
    assert.isTrue(await view.authorize(subject, 'docs:read', org))

    manager.unfreeze()
    await view.grant(subject, 'org-editor', org)
    assert.include(driver.calls, 'grant')
  })

  test('la excepción de dentro del freeze no deja el motor congelado', async ({ assert }) => {
    const { manager, tree } = frozenManager()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    await assert.rejects(
      () =>
        manager.withFrozenWrites('migración', async () => {
          throw new Error('la migración explotó a la mitad')
        }),
      'la migración explotó a la mitad'
    )
    assert.isFalse(manager.frozen, 'el finally tiene que descongelar pase lo que pase')
    await manager.grant({ type: 'users', uuid: uuidv7() }, 'org-editor', org)
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * P2 · `scopes.enumerateEdges` — el árbol ENTERO, paginado.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('3b-3a · scopes.enumerateEdges', (group) => {
  group.each.setup(async () => {
    await cleanSqlScopeTree(db)
    return async () => cleanSqlScopeTree(db)
  })

  /** Los nodos van con uuid v7: el orden por uuid es el orden de creación. */
  async function seedTree(): Promise<{ org: any; units: any[] }> {
    const org = { type: 'organization', uuid: uuidv7() }
    await db.table('demo_scopes').insert({ uuid: org.uuid, type: org.type, parent_uuid: null })
    const units = []
    for (let i = 0; i < 4; i++) {
      const unit = { type: 'unit', uuid: uuidv7() }
      await db.table('demo_scopes').insert({ uuid: unit.uuid, type: unit.type, parent_uuid: org.uuid })
      units.push(unit)
    }
    return { org, units }
  }

  const edges = sqlScopeEdges({
    table: 'demo_scopes',
    uuidColumn: 'uuid',
    parentColumn: 'parent_uuid',
    typeColumn: 'type',
  })

  /** Pasea TODAS las páginas y devuelve las aristas y cuántas páginas hicieron falta. */
  async function walk(limit: number): Promise<{ all: ScopeEdge[]; pages: number }> {
    const all: ScopeEdge[] = []
    let after: string | undefined
    let pages = 0
    for (;;) {
      const page = await edges({ limit, after })
      pages += 1
      assert_max(page.edges.length, limit)
      all.push(...page.edges)
      if (page.cursor === undefined) return { all, pages }
      after = page.cursor
      if (pages > 50) throw new Error('sqlScopeEdges no termina de paginar')
    }
  }

  function assert_max(value: number, limit: number) {
    if (value > limit) throw new Error(`una página devolvió ${value} aristas con limit=${limit}`)
  }

  test('pagina el árbol entero por cursor y no repite ni se salta ninguna arista', async ({ assert }) => {
    const { org, units } = await seedTree()
    const label = (e: ScopeEdge) => `${e.child.type}:${e.child.uuid}→${e.parent.type}:${e.parent.uuid ?? ''}`
    const completa = (await walk(100)).all.map(label).sort()

    assert.lengthOf(completa, 5)
    assert.include(completa, `organization:${org.uuid}→app:`)
    for (const unit of units) assert.include(completa, `unit:${unit.uuid}→organization:${org.uuid}`)

    // Y el MISMO conjunto paginando de dos en dos: es lo que hace que una
    // pasada reanudada no se salte nodos.
    const troceada = await walk(2)
    assert.isAtLeast(troceada.pages, 3, 'con limit=2 y 5 filas tiene que haber al menos 3 páginas')
    assert.deepEqual(troceada.all.map(label).sort(), completa)
  })

  test('una fila cuyo padre NO existe no produce arista (resolveChain tampoco la resuelve)', async ({
    assert,
  }) => {
    const { org, units } = await seedTree()
    const huerfano = { type: 'unit', uuid: uuidv7() }
    await db.table('demo_scopes').insert({ uuid: huerfano.uuid, type: huerfano.type, parent_uuid: uuidv7() })

    const all = (await walk(100)).all
    assert.lengthOf(all, 5, 'el huérfano no añade arista')
    assert.isUndefined(all.find((e) => e.child.uuid === huerfano.uuid))
    assert.isDefined(all.find((e) => e.child.uuid === org.uuid))
    assert.lengthOf(all.filter((e) => e.child.type === 'unit'), units.length)
  })

  test('el cursor avanza aunque la última fila de la página no produzca arista', async ({ assert }) => {
    // Un huérfano PRIMERO (uuid v1 más bajo) y dos nodos buenos detrás: con
    // limit=1 la primera página trae 0 aristas y tiene que traer cursor, o la
    // paginación se para y el árbol se migra a medias.
    const huerfano = { type: 'unit', uuid: '00000000-0000-7000-8000-000000000001' }
    await db.table('demo_scopes').insert({ uuid: huerfano.uuid, type: 'unit', parent_uuid: uuidv7() })
    const { org } = await seedTree()

    const first = await edges({ limit: 1 })
    assert.lengthOf(first.edges, 0)
    assert.isDefined(first.cursor, 'sin cursor aquí, el resto del árbol no se enumera nunca')
    const all = (await walk(1)).all
    assert.lengthOf(all, 5)
    assert.isDefined(all.find((e) => e.child.uuid === org.uuid))
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * P3 · `driver.reconcile()` — DB → FGA contra el servidor REAL.
 *
 * El origen es `authz_*` + el árbol SQL del consumidor (`demo_scopes`), y lo
 * escribe el driver `database` con el API del paquete: ni una fila a mano. El
 * destino es un store del `:8101`. Nada de esto se puede fingir con un doble.
 * ════════════════════════════════════════════════════════════════════════ */

const openFgaTestUrl = process.env.OPENFGA_TEST_URL

if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('3b-3a · reconcile --to=openfga (servidor real)', (group) => {
    const stores: string[] = []
    group.each.setup(async () => {
      await cleanAuthzTables()
      await cleanSqlScopeTree(db)
      return async () => {
        const { OpenFgaClient } = await import('@openfga/sdk')
        while (stores.length) await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
        await cleanAuthzTables()
        await cleanSqlScopeTree(db)
      }
    })

    /** Un store vacío con el modelo (c2r): ni catálogo, ni árbol, ni marcador. */
    async function emptyStore(permissions: string[] = PERMISSIONS) {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `reconcile-${Date.now()}-${stores.length}` })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS_3, permissions)
      )
      return { storeId: store.id!, modelId: model.authorization_model_id!, client: new OpenFgaClient({ apiUrl, storeId: store.id }) }
    }

    /**
     * El montaje completo: catálogo en `authz_*` (SIN proyección: es un
     * consumidor solo-database), árbol en `demo_scopes`, hechos escritos por
     * el driver `database`, y un store vacío al lado esperando la migración.
     */
    async function migrationSetup() {
      const tree = sqlScopeTree(db)
      const chain = resolveChainFrom(tree)
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
        roles: [
          { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] },
          { slug: 'unit-lead', scopeType: 'unit', permissions: ['docs:read', 'docs:write'] },
        ],
      })
      const org = { type: 'organization', uuid: uuidv7() }
      const unit = { type: 'unit', uuid: uuidv7() }
      await tree.attach(org, APP_SCOPE)
      await tree.attach(unit, org)

      const database = new DatabaseAuthorizationDriver({ resolveChain: chain })
      const ana = { type: 'users', uuid: uuidv7() }
      const bea = { type: 'users', uuid: uuidv7() }
      await database.grant(ana, 'org-editor', org, {})
      await database.grant(bea, 'unit-lead', unit, {})
      await database.deny(bea, 'docs:read', unit)

      const store = await emptyStore()
      const fga = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.storeId,
        modelId: store.modelId,
        holderTypes: HOLDERS_3,
        resolveChain: chain,
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      })
      const source = { enumerateEdges: edgesOfDemoScopes(), resolveChain: chain }
      return { tree, chain, database, fga, source, org, unit, ana, bea, store }
    }

    test('el store vacío no concede NADA, y una pasada de reconcile lo pone a la par del driver database', async ({
      assert,
    }) => {
      const { database, fga, source, org, unit, ana, bea } = await migrationSetup()

      assert.isFalse(await fga.authorize(ana, 'docs:read', org), 'el store todavía está vacío')

      const report = await fga.reconcile!(source, {})

      assert.equal(report.to, 'openfga')
      assert.isFalse(report.dryRun)
      assert.isAbove(report.written, 0)
      assert.equal(report.deleted, 0, 'un store vacío no tiene nada que sobre')
      assert.isTrue(report.drift.rootMarker, 'faltaba el marcador de raíz: sin él el store entero deniega')

      // PARIDAD: las mismas preguntas, las mismas respuestas.
      for (const [subject, permission, scope] of [
        [ana, 'docs:read', org],
        [ana, 'docs:read', unit],
        [ana, 'docs:write', unit],
        [bea, 'docs:write', unit],
        [bea, 'docs:read', unit],
        [bea, 'docs:read', org],
      ] as const) {
        assert.equal(
          await fga.authorize(subject as any, permission, scope as any),
          await database.authorize(subject as any, permission, scope as any),
          `paridad en ${permission}@${(scope as any).type}`
        )
      }
      assert.isTrue(await fga.authorize(ana, 'docs:read', unit), 'la herencia hacia abajo tiene que estar migrada')
      assert.isFalse(await fga.authorize(bea, 'docs:read', unit), 'el deny explícito también')
    })

    test('idempotencia: la SEGUNDA pasada escribe cero', async ({ assert }) => {
      const { fga, source } = await migrationSetup()

      const primera = await fga.reconcile!(source, {})
      const segunda = await fga.reconcile!(source, {})

      assert.isAbove(primera.written, 0)
      assert.equal(segunda.written, 0, 'la segunda pasada no escribe NADA')
      assert.equal(segunda.updated, 0)
      assert.equal(segunda.deleted, 0)
      assert.equal(segunda.extra, 0)
      assert.equal(segunda.unchanged, primera.written + primera.unchanged)
      assert.isFalse(segunda.drift.rootMarker)
    })

    test('lo que NO se migra sale contado y con su motivo (scope muerto, rol retirado, caducada)', async ({
      assert,
    }) => {
      const { fga, source, tree, database, unit, org, ana } = await migrationSetup()
      const carla = { type: 'users', uuid: uuidv7() }
      // (a) caducada: no concede, así que no se migra.
      await database.grant(carla, 'org-editor', org, { expiresAt: new Date(Date.now() - 60_000) })
      // (b) un holder que la base tiene y `holderTypes` no declara: no hay
      //     usuario FGA que escribir, y suponerlo sería inventar identidad.
      await database.grant({ type: 'bots', uuid: uuidv7() }, 'org-editor', org, {})

      await fga.reconcile!(source, {})

      // (c) scope muerto: el consumidor borra la unit y sus hechos sobreviven
      //     (3b-0b · AA4, «resurrección»).
      await tree.detach(unit)

      const report = await fga.reconcile!(source, {})

      assert.isAtLeast(report.skipped['expired'] ?? 0, 1, 'la caducada tiene que salir contada')
      assert.isAtLeast(report.skipped['unknown-holder-type'] ?? 0, 1, 'el holder no declarado también')
      assert.isAtLeast(report.skipped['unknown-scope'] ?? 0, 1, 'los hechos del scope muerto también')
      assert.isAbove(report.extra, 0, 'y sus tuplas sobran en el store')
      assert.equal(report.phases.facts.deleted, 0, 'sin --prune no se borra ni un hecho')
      const motivos = new Set(report.details.map((d) => d.reason))
      assert.isTrue(motivos.has('unknown-scope'), `motivos vistos: ${[...motivos].join(', ')}`)
      // Y el detalle nombra la fila, no solo el motivo.
      const detalle = report.details.find((d) => d.reason === 'unknown-scope')!
      assert.include(detalle.detail, unit.uuid)
      assert.equal(detalle.kind, 'assignment')
      assert.isTrue(await fga.authorize(ana, 'docs:read', org), 'el resto del store sigue en pie')
    })

    test('--prune borra los hechos del scope que ya no resuelve; sin él solo se reportan', async ({
      assert,
    }) => {
      const { fga, source, tree, unit, bea } = await migrationSetup()
      const unitKey = `unit|${unit.uuid}`
      await fga.reconcile!(source, {})
      const tuplasDe = async () => {
        const todas = await todoElStore(fga)
        return todas.filter((t) => t.includes(unitKey))
      }
      assert.isAbove((await tuplasDe()).length, 0)

      await tree.detach(unit)
      const sinPrune = await fga.reconcile!(source, {})
      assert.equal(sinPrune.phases.facts.deleted, 0)
      assert.isAbove((await tuplasDe()).length, 0, 'sin --prune los hechos siguen ahí')

      const conPrune = await fga.reconcile!(source, { prune: true })
      assert.isAbove(conPrune.phases.facts.deleted, 0)
      assert.lengthOf(await tuplasDe(), 0, 'con --prune no queda ni uno')
      assert.isFalse(await fga.authorize(bea, 'docs:write', unit))

      // Y sigue siendo idempotente: la pasada siguiente no encuentra nada.
      const tercera = await fga.reconcile!(source, { prune: true })
      assert.equal(tercera.deleted, 0)
      assert.equal(tercera.written, 0)
    })

    test('--prune con `authz_*` VACÍO se niega (origen ciego), y --allow-mass-delete es la salida', async ({
      assert,
    }) => {
      const { fga, source } = await migrationSetup()
      await fga.reconcile!(source, {})
      // El origen se queda sin hechos: base equivocada, o el driver que
      // escribe es el otro. Con --prune eso vaciaría el store entero.
      await db.from('authz_assignments').delete()
      await db.from('authz_denies').delete()

      const error = await rejects(
        assert,
        () => fga.reconcile!(source, { prune: true }),
        'E_AUTHZ_MASS_RECONCILE_REFUSED',
        500
      )
      assert.include(error.message, '--allow-mass-delete')
      assert.isAbove((await todoElStore(fga)).length, 0, 'no ha borrado nada antes de negarse')

      // El dry-run no lanza: lo marca.
      const seco = await fga.reconcile!(source, { prune: true, dryRun: true })
      assert.isTrue(seco.massDelete)

      const forzado = await fga.reconcile!(source, { prune: true, allowMassDelete: true })
      assert.isAbove(forzado.phases.facts.deleted, 0)
      assert.isTrue(forzado.massDelete)
    })

    test('el árbol: repara un nodo con DOS padres y borra las aristas que el consumidor ya no respalda', async ({
      assert,
    }) => {
      const { fga, source, org, unit, ana } = await migrationSetup()
      await fga.reconcile!(source, {})
      const unitObject = `scope:unit|${unit.uuid}`

      // Dos escritores del árbol (3b-2h · 🟠 4): la unit acaba colgando de la
      // organización Y de la raíz. Y una arista de un nodo que el consumidor
      // no conoce.
      const fantasma = uuidv7()
      await (fga as any).client.write({
        writes: [
          { user: 'scope:app', relation: 'parent', object: unitObject },
          { user: `scope:organization|${org.uuid}`, relation: 'parent', object: `scope:unit|${fantasma}` },
        ],
        deletes: [],
      })

      const seco = await fga.reconcile!(source, { dryRun: true })
      assert.deepEqual(seco.drift.multiParent, [unitObject], 'el nodo con dos padres se DENUNCIA')
      assert.isAtLeast(seco.phases.tree.extra, 2)

      const report = await fga.reconcile!(source, {})
      assert.isAtLeast(report.phases.tree.deleted, 2, 'lo derivado se rehace entero, sin --prune')
      const tuplas = await todoElStore(fga)
      assert.notInclude(tuplas, `scope:app#parent@${unitObject}`)
      assert.include(tuplas, `scope:organization|${org.uuid}#parent@${unitObject}`)
      assert.isUndefined(tuplas.find((t) => t.includes(fantasma)))
      assert.deepEqual((await fga.reconcile!(source, { dryRun: true })).drift.multiParent, [])
      assert.isTrue(await fga.authorize(ana, 'docs:read', unit), 'y la herencia buena sigue en pie')
    })

    test('un CICLO en el árbol del origen se reporta y NINGUNA de sus aristas se escribe', async ({
      assert,
    }) => {
      const { fga, source, org, unit, ana } = await migrationSetup()
      await fga.reconcile!(source, {})
      assert.isTrue(await fga.authorize(ana, 'docs:read', unit))

      // Alguien toca la tabla del consumidor y cierra un ciclo: la
      // organización pasa a colgar de su propia unit. FGA acepta el ciclo y
      // lo evalúa (cruce 3), así que la mitigación es NO escribirlo.
      await db.from('demo_scopes').where('uuid', org.uuid).update({ parent_uuid: unit.uuid })

      const report = await fga.reconcile!(source, {})
      assert.lengthOf(report.cycles, 1, `ciclos: ${JSON.stringify(report.cycles)}`)
      assert.sameMembers(report.cycles[0], [`organization|${org.uuid}`, `unit|${unit.uuid}`])
      assert.isAtLeast(report.skipped['cycle'] ?? 0, 1)

      const tuplas = await todoElStore(fga)
      assert.isUndefined(
        tuplas.find((t) => t.includes('#parent@scope:unit') || t.includes('#parent@scope:organization')),
        `no puede quedar ninguna arista del ciclo: ${tuplas.filter((t) => t.includes('parent')).join(' | ')}`
      )
      // Sin cadena a la raíz, (c2r) deniega: fail-CLOSED, que es lo que se compra.
      assert.isFalse(await fga.authorize(ana, 'docs:read', org))
      assert.isFalse(await fga.authorize(ana, 'docs:read', unit))
    })

    test('invariante 18: la arista de visibilidad que el relay pudo perder se borra SIN --prune', async ({
      assert,
    }) => {
      const { fga, source, org, unit } = await migrationSetup()
      await fga.reconcile!(source, {})
      // Una asignación escrita A MANO en `authz_*` con el rol de nivel `unit`
      // sobre una ORGANIZATION: `database` no la honra (la regla de
      // visibilidad se evalúa en cada pregunta) y `facts` la honraría si su
      // arista `scope#binding` existiera — que es exactamente la escritura
      // que `scopes.moved`/`projectCatalogRole` pierden si el relay no pasa.
      const rol = await db.from('authz_roles').where('slug', 'unit-lead').first()
      const eva = { type: 'users', uuid: uuidv7() }
      await db.table('authz_assignments').insert({
        uuid: uuidv7(),
        holder_type: eva.type,
        holder_uuid: eva.uuid,
        role_uuid: rol.uuid,
        scope_type: 'organization',
        scope_uuid: org.uuid,
        expires_at: null,
        created_at: new Date(),
      })
      const orgKey = `organization|${org.uuid}`
      await (fga as any).client.write({
        writes: [
          { user: `role_binding:${orgKey}|${rol.uuid}`, relation: 'binding', object: `scope:${orgKey}` },
          { user: `role:${rol.uuid}`, relation: 'role', object: `role_binding:${orgKey}|${rol.uuid}` },
          { user: `user:${eva.uuid}`, relation: 'assignee', object: `role_binding:${orgKey}|${rol.uuid}` },
        ],
        deletes: [],
      })
      assert.isTrue(await fga.authorize(eva, 'docs:write', org), 'el store concede lo que database no')

      const report = await fga.reconcile!(source, {})

      assert.isAtLeast(report.drift.roleVisibility, 1, 'la deriva de visibilidad se cuenta aparte')
      assert.isAtLeast(report.skipped['role-not-visible'] ?? 0, 1)
      assert.isFalse(await fga.authorize(eva, 'docs:write', org), 'y se cierra sin --prune: era fail-OPEN')
      assert.isFalse(await fga.authorize(eva, 'docs:write', unit), 'la asignación no cuelga de la unit')
      // La asignación NO desaparece: el hecho existe (invariante 18), lo que
      // no existe es su visibilidad ahí.
      const tuplas = await todoElStore(fga)
      assert.include(tuplas, `user:${eva.uuid}#assignee@role_binding:${orgKey}|${rol.uuid}`)
      assert.notInclude(tuplas, `role_binding:${orgKey}|${rol.uuid}#binding@scope:${orgKey}`)
    })

    /**
     * **La vía de salida de un store de la versión anterior.** Tras el 2k «un
     * store escrito por la versión anterior no se lee desde esta»: el modo
     * `resolver` guardaba la asignación sin las dos aristas de (c2) y los
     * denies en objetos `deny_binding` propios, que el modelo (c2r) ni
     * siquiera declara. `reconcile --to=openfga` reconstruye desde `authz_*`,
     * que es la fuente de verdad, y con `--prune` se lleva lo que sobra
     * (comprobado contra el servidor: una tupla de un tipo que el modelo de
     * hoy no declara se LEE y se BORRA, aunque no se pueda escribir).
     */
    test('un store con basura del formato viejo vuelve a conceder tras reconcile', async ({ assert }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const tree = sqlScopeTree(db)
      const chain = resolveChainFrom(tree)
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
        roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] }],
      })
      const org = { type: 'organization', uuid: uuidv7() }
      await tree.attach(org, APP_SCOPE)
      const database = new DatabaseAuthorizationDriver({ resolveChain: chain })
      const ana = { type: 'users', uuid: uuidv7() }
      await database.grant(ana, 'org-editor', org, {})
      const rol = await db.from('authz_roles').where('slug', 'org-editor').first()
      const permiso = await db.from('authz_permissions').where('slug', 'docs:write').first()
      const orgKey = `organization|${org.uuid}`

      // 1. El store, con el modelo VIEJO y sus tuplas.
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `reconcile-viejo-${Date.now()}` })
      stores.push(store.id!)
      const client = new OpenFgaClient({ apiUrl, storeId: store.id })
      const viejo = await client.writeAuthorizationModel({
        schema_version: '1.1',
        type_definitions: [
          { type: 'user', relations: {}, metadata: null },
          {
            type: 'role_binding',
            relations: { assignee: { this: {} } },
            metadata: { relations: { assignee: { directly_related_user_types: [{ type: 'user' }] } } },
          },
          {
            type: 'deny_binding',
            relations: { denied: { this: {} } },
            metadata: { relations: { denied: { directly_related_user_types: [{ type: 'user' }] } } },
          },
        ],
      } as any)
      const bea = { type: 'users', uuid: uuidv7() }
      await client.write(
        {
          writes: [
            // La asignación tal como la dejaba el importador borrado: sin las
            // dos aristas de (c2), sin árbol y sin marcador de raíz.
            { user: `user:${ana.uuid}`, relation: 'assignee', object: `role_binding:${orgKey}|${rol.uuid}` },
            // Y un deny en un objeto de un tipo que (c2r) ni declara.
            { user: `user:${bea.uuid}`, relation: 'denied', object: `deny_binding:${orgKey}|${permiso.uuid}` },
          ],
        },
        { authorizationModelId: viejo.authorization_model_id }
      )

      // 2. Se publica el modelo de hoy sobre el mismo store.
      const nuevo = await client.writeAuthorizationModel(openFgaFactsModel(HOLDERS_3, PERMISSIONS))
      const fga = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: nuevo.authorization_model_id,
        holderTypes: HOLDERS_3,
        resolveChain: chain,
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      })
      assert.isFalse(await fga.authorize(ana, 'docs:read', org), 'un store de la versión anterior no concede nada')

      // 3. La vía de salida.
      const source = { enumerateEdges: edgesOfDemoScopes(), resolveChain: chain }
      const report = await fga.reconcile!(source, { prune: true })

      assert.isTrue(await fga.authorize(ana, 'docs:read', org), 'reconstruido desde authz_*, vuelve a conceder')
      assert.equal(report.phases.facts.unchanged, 1, 'la única tupla que ya estaba bien no se reescribe')
      assert.isAtLeast(report.phases.facts.deleted, 1)
      const tuplas = await todoElStore(fga)
      assert.isUndefined(
        tuplas.find((t) => t.includes('deny_binding')),
        `la basura del modelo viejo tiene que irse: ${tuplas.join(' | ')}`
      )
      assert.equal((await fga.reconcile!(source, { prune: true })).written, 0, 'y queda idempotente')
    })

    test('de punta a punta por el manager: `authz:reconcile --to=openfga` con el motor congelado', async ({
      assert,
    }) => {
      const { fga, chain, org, ana } = await migrationSetup()
      const manager = new AuthorizationManager({
        default: 'database',
        drivers: {
          database: () => new DatabaseAuthorizationDriver({ resolveChain: chain }),
          openfga: () => fga,
        },
        holderTypes: HOLDERS_3,
        scopes: { resolveChain: chain, enumerateEdges: edgesOfDemoScopes() },
        warnOnOptInSecurity: false,
      })

      const report = await manager.reconcile({ to: 'openfga' })

      assert.equal(report.to, 'openfga')
      assert.isAbove(report.written, 0)
      assert.isFalse(manager.frozen)
      assert.isTrue(await fga.authorize(ana, 'docs:read', org))
      // El motor sigue siendo `database` y sigue escribiendo: migrar no lo apaga.
      await manager.grant({ type: 'users', uuid: uuidv7() }, 'org-editor', org)
      // Y el verificador ya no ve deriva salvo el grant recién hecho.
      const seco = await manager.reconcile({ to: 'openfga', dryRun: true })
      assert.equal(seco.deleted, 0)
      assert.equal(seco.updated, 0)
      assert.isAbove(seco.written, 0, 'el grant nuevo todavía no está en el store: eso es deriva')
    })

    test('--dry-run es el verificador: mismo recorrido, CERO escrituras', async ({ assert }) => {
      const { fga, source, store, ana, org } = await migrationSetup()

      const seco = await fga.reconcile!(source, { dryRun: true })
      assert.isTrue(seco.dryRun)
      assert.isAbove(seco.written, 0, 'dice lo que escribiría')
      const tuplas = await store.client.read({})
      assert.lengthOf(tuplas.tuples ?? [], 0, 'y no ha escrito ni una tupla')
      assert.isFalse(await fga.authorize(ana, 'docs:read', org))

      // Y sobre un store YA reconciliado, el verificador no ve deriva.
      await fga.reconcile!(source, {})
      const limpio = await fga.reconcile!(source, { dryRun: true })
      assert.equal(limpio.written, 0)
      assert.equal(limpio.extra, 0)
      assert.deepEqual(limpio.cycles, [])
      assert.deepEqual(limpio.drift.multiParent, [])
    })
  })

  /* ══════════════════════════════════════════════════════════════════════
   * 3b-5 · **Quién es la FUENTE DE VERDAD de los hechos** — los dos 🔴 del
   * auditor final de la Fase 3b, reproducidos como casos.
   *
   * El montaje es el que faltaba en toda la fase: un despliegue YA cortado a
   * `facts` (el driver `openfga` es el ACTIVO, `config.default`), con
   * `authz_assignments`/`authz_denies` congeladas en lo que dejó la migración
   * y con la outbox del gate. Ahí `authz_*` **no** es la fuente de verdad de
   * los hechos, y `authz:reconcile --to=openfga` lo tiene que saber.
   * ══════════════════════════════════════════════════════════════════════ */
  test.group('3b-5 · la fuente de verdad de los hechos (servidor real)', (group) => {
    const stores: string[] = []
    group.each.setup(async () => {
      await cleanAuthzTables()
      await cleanSqlScopeTree(db)
      await cleanScopeOutbox(db)
      return async () => {
        const { OpenFgaClient } = await import('@openfga/sdk')
        while (stores.length) await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
        await cleanAuthzTables()
        await cleanSqlScopeTree(db)
        await cleanScopeOutbox(db)
      }
    })

    const CATALOGO: any = {
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [
        { slug: 'org-admin', scopeType: 'organization', rank: 50, permissions: ['docs:read', 'docs:write'] },
        { slug: 'root-admin', scopeType: 'app', rank: 90, permissions: ['docs:write'] },
      ],
    }

    /**
     * Un despliegue en `facts`: `openfga` es el driver ACTIVO y los hechos
     * viven en el store. `database` sigue registrado —es lo normal después de
     * un cutover: nadie borra la entrada del config— y sus tablas siguen
     * ahí, congeladas, que es justo la precondición de los dos hallazgos.
     */
    async function factsDeployment() {
      const tree = sqlScopeTree(db)
      const chain = resolveChainFrom(tree)
      await syncAuthzCatalog(CATALOGO)
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `3b5-${Date.now()}-${stores.length}` })
      stores.push(store.id!)
      const client = new OpenFgaClient({ apiUrl, storeId: store.id })
      const model = await client.writeAuthorizationModel(openFgaFactsModel(HOLDERS_3, PERMISSIONS))
      const fga: any = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id!,
        holderTypes: HOLDERS_3,
        resolveChain: chain,
        outbox: sqlScopeOutbox(),
        logger: { warn: () => {} },
      })
      await syncAuthzCatalog(CATALOGO, { projection: fga.catalogProjection() })
      const database: any = new DatabaseAuthorizationDriver({ resolveChain: chain })
      const manager = new AuthorizationManager({
        // El cutover ya pasó: el motor SIRVE desde `openfga`.
        default: 'openfga',
        drivers: { openfga: () => fga, database: () => database },
        holderTypes: HOLDERS_3,
        scopes: { resolveChain: chain, outbox: sqlScopeOutbox(), enumerateEdges: edgesOfDemoScopes() },
        delegablePermissions: ['docs:write'],
        warnOnOptInSecurity: false,
      } as any)
      return { tree, chain, fga, database, manager, client }
    }

    test('🔴 2 — tras el cutover, `--to=openfga` NO resucita lo revocado ni `--prune` borra un deny vivo', async ({
      assert,
    }) => {
      const { tree, fga, database, manager, client } = await factsDeployment()
      const org = orgScope()
      const despedido = { type: 'users', uuid: uuidv7() }
      const empleado = { type: 'users', uuid: uuidv7() }
      await tree.attach(org, APP_SCOPE)
      await manager.scopes.attached(org, APP_SCOPE)
      await manager.relayScopeChanges()

      // 1. La era `database`, y la MIGRACIÓN documentada: el origen se dice.
      await database.grant(despedido, 'org-admin', org, {})
      await database.grant(empleado, 'org-admin', org, {})
      const migracion = await manager.reconcile({ to: 'openfga', from: 'database' })
      assert.equal(migracion.factsFrom, 'database', 'la migración lee los hechos del origen que se le nombra')
      assert.isTrue(await fga.authorize(despedido, 'docs:write', org))

      // 2. El cutover. Nadie vacía `authz_*`: ni el README ni el comando lo
      //    piden, y el catálogo vive en esas mismas tablas.
      await manager.revoke(despedido, 'org-admin', org)
      await manager.deny(empleado, 'docs:write', org)
      assert.isFalse(await fga.authorize(despedido, 'docs:write', org))
      assert.isFalse(await fga.authorize(empleado, 'docs:write', org))
      assert.lengthOf(await db.from('authz_assignments').select('uuid'), 2, 'las tablas siguen con lo de antes')
      assert.lengthOf(await db.from('authz_denies').select('uuid'), 0, 'y el deny vive SOLO en el store')

      // 3. El verificador que el README pone en CI: en un despliegue `facts`
      //    correcto tiene que salir LIMPIO (antes llamaba «deriva» al estado
      //    bueno y empujaba a repararlo).
      const seco = await manager.reconcile({ to: 'openfga', dryRun: true })
      assert.equal(seco.factsFrom, 'openfga', 'los hechos son los del propio driver activo')
      assert.equal(seco.written, 0)
      assert.equal(seco.deleted, 0)
      assert.deepEqual(seco.skipped, {})
      assert.isTrue(reconcileLines(seco).clean, 'sin deriva: el estado correcto no es deriva')

      // 4. Y la pasada de verdad no escribe: el `revoke` sigue hecho.
      const r = await manager.reconcile({ to: 'openfga' })
      assert.equal(r.written, 0)
      assert.equal(r.deleted, 0)
      assert.isFalse(await fga.authorize(despedido, 'docs:write', org), 'el revoke NO se deshace')

      // 5. Ni siquiera con `--prune`: el deny que solo vive en el store no lo
      //    respalda `authz_denies`, pero `authz_denies` no es su fuente.
      const podado = await manager.reconcile({ to: 'openfga', prune: true })
      assert.equal(podado.deleted, 0)
      assert.isFalse(podado.massDelete)
      assert.isFalse(await fga.authorize(empleado, 'docs:write', org), 'el deny vivo sigue vivo')
      const tuplas = await todoElStore(fga)
      assert.isDefined(
        tuplas.find((t) => t.includes('#denied_docs_write@')),
        `el deny tiene que seguir en el store: ${tuplas.join(' | ')}`
      )
      assert.lengthOf(
        tuplas.filter((t) => t.includes('#assignee@')),
        1,
        'y el revocado no ha vuelto'
      )
      void client
    })

    test('🔴 1 — `--to=openfga` aplica el barrido de visibilidad del `moved` que el relay perdió (invariante 18)', async ({
      assert,
    }) => {
      const { tree, fga, database, manager } = await factsDeployment()
      const orgA = orgScope()
      const orgB = orgScope()
      const unit = { type: 'unit', uuid: uuidv7() }
      const jefe = { type: 'users', uuid: uuidv7() }
      const victima = { type: 'users', uuid: uuidv7() }
      for (const [child, parent] of [
        [orgA, APP_SCOPE],
        [orgB, APP_SCOPE],
        [unit, orgA],
      ] as const) {
        await tree.attach(child as any, parent as any)
        await manager.scopes.attached(child as any, parent as any)
      }
      await manager.relayScopeChanges()

      // Un rol LOCAL de orgA, de nivel `unit`, asignado en una unit de orgA.
      await manager.grant(jefe, 'root-admin', APP_SCOPE)
      const local = await manager.defineScopedRole(
        jefe,
        orgA,
        { slug: 'unit-lead', scopeType: 'unit', rank: 10, permissions: ['docs:write'] },
        { actor: jefe } as any
      )
      await manager.grant(victima, { uuid: local.uuid }, unit)
      assert.isTrue(await fga.authorize(victima, 'docs:write', unit), 'dentro de su owner, concede')
      // Y `authz_assignments` sigue VACÍA: en `facts` los hechos son tuplas
      // del store (es la precondición del hallazgo, no un detalle del montaje).
      assert.lengthOf(await db.from('authz_assignments').select('uuid'), 0)

      // El consumidor mueve la unit al OTRO tenant y el relay APARCA la
      // entrada (3b-2h): es el único caso en el que el invariante 18 nombra a
      // `authz:reconcile` como remedio.
      await tree.move(unit, orgB)
      await manager.scopes.moved(unit, orgB)
      await db.from('authz_scope_outbox').whereNull('applied_at').update({ attempts: 5, last_error: 'aparcada' })
      assert.isTrue(await fga.authorize(victima, 'docs:write', unit), 'el rol de orgA sigue concediendo en orgB')

      const r = await manager.reconcile({ to: 'openfga' })

      assert.equal(r.factsFrom, 'openfga')
      assert.equal(r.drift.roleVisibility, 1, 'la arista de visibilidad estaba mal y la pasada lo DICE')
      assert.equal(r.skipped['role-not-visible'], 1)
      assert.equal(r.phases.facts.deleted, 1, 'la `scope#binding` se borra SIN --prune: dejarla es fail-OPEN')
      assert.equal(r.phases.tree.written, 1, 'y la mitad que concede del `moved` también se aplica')
      assert.isFalse(await fga.authorize(victima, 'docs:write', unit), 'el rol local de orgA ya no concede en orgB')

      // Idempotente: la segunda pasada no toca nada y ya no ve deriva de
      // visibilidad (el hecho sigue ahí; lo que se retiró es la visibilidad).
      const segunda = await manager.reconcile({ to: 'openfga' })
      assert.equal(segunda.written, 0)
      assert.equal(segunda.deleted, 0)
      assert.equal(segunda.drift.roleVisibility, 0)

      // **PARIDAD con el driver `database`** sobre el MISMO árbol y el MISMO
      // catálogo: el mismo hecho, escrito como llegó a existir (con la unit
      // todavía bajo orgA) y el mismo `moved` después.
      await tree.move(unit, orgA)
      await database.grant(jefe, 'root-admin', APP_SCOPE, {})
      await database.grant(victima, { uuid: local.uuid }, unit, {})
      await tree.move(unit, orgB)
      assert.equal(
        await fga.authorize(victima, 'docs:write', unit),
        await database.authorize(victima, 'docs:write', unit),
        'los dos drivers responden lo mismo al mismo `moved`'
      )
    })

    test('el ORIGEN se dice en el reporte, y `--from` sigue siendo la migración de un solo sentido', async ({
      assert,
    }) => {
      // La regla es observable por los dos lados: sin `--from` los hechos son
      // los del driver ACTIVO; con `--from=database` son las tablas, que es lo
      // que hace de `--to=openfga` una MIGRACIÓN y no un verificador.
      const { tree, fga, database, manager } = await factsDeployment()
      const org = orgScope()
      const ana = { type: 'users', uuid: uuidv7() }
      await tree.attach(org, APP_SCOPE)
      await manager.scopes.attached(org, APP_SCOPE)
      await manager.relayScopeChanges()
      await database.grant(ana, 'org-admin', org, {})

      const mantenimiento = await manager.reconcile({ to: 'openfga', dryRun: true })
      assert.equal(mantenimiento.factsFrom, 'openfga')
      assert.equal(mantenimiento.phases.facts.written, 0, 'lo que hay en `authz_*` no es un hecho de este despliegue')

      const migracion = await manager.reconcile({ to: 'openfga', from: 'database', dryRun: true })
      assert.equal(migracion.factsFrom, 'database')
      assert.isAbove(migracion.phases.facts.written, 0, 'nombrando el origen, las tablas SÍ mandan')
      assert.isFalse(await fga.authorize(ana, 'docs:write', org), '--dry-run no ha escrito nada')
    })
  })
}

/* ════════════════════════════════════════════════════════════════════════
 * P4 · `manager.reconcile()` y `node ace authz:reconcile`.
 * ════════════════════════════════════════════════════════════════════════ */

/** Un destino de mentira: para la fontanería del manager solo cuenta que se le llame. */
function targetDriver(onReconcile?: () => Promise<void>) {
  const seen: any[] = []
  const driver: any = {
    ...spyDriver(),
    async reconcile(source: any, options: any) {
      seen.push({ source, options })
      if (onReconcile) await onReconcile()
      return {
        to: 'destino',
        dryRun: options.dryRun === true,
        prune: options.prune === true,
        written: 3,
        updated: 0,
        unchanged: 1,
        extra: 0,
        deleted: 0,
        phases: {
          root: { written: 1, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
          catalog: { written: 1, updated: 0, unchanged: 1, extra: 0, deleted: 0 },
          tree: { written: 1, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
          facts: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
        },
        skipped: {},
        details: [],
        cycles: [],
        drift: { rootMarker: true, multiParent: [], roleVisibility: 0, pendingRelay: 0, deadRelay: 0 },
        massDelete: false,
      }
    },
  }
  return { driver, seen }
}

test.group('3b-3a · manager.reconcile', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
    await cleanSqlScopeTree(db)
    return async () => {
      await cleanScopeOutbox(db)
      await cleanSqlScopeTree(db)
    }
  })

  function managerWith(extra: any = {}, target = targetDriver()) {
    const tree = memoryScopeTree()
    const manager = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => spyDriver(), destino: () => target.driver },
      holderTypes: HOLDERS,
      scopes: {
        resolveChain: resolveChainFrom(tree),
        enumerateEdges: edgesOfDemoScopes(),
        ...extra,
      },
      warnOnOptInSecurity: false,
    })
    return { manager, tree, target }
  }

  test('el destino se nombra por el REGISTRO, no por el driver activo', async ({ assert }) => {
    const target = targetDriver()
    const { manager } = managerWith({}, target)

    const report = await manager.reconcile({ to: 'destino', dryRun: true })

    assert.equal(report.written, 3)
    assert.lengthOf(target.seen, 1)
    assert.isTrue(target.seen[0].options.dryRun)
    assert.isFunction(target.seen[0].source.enumerateEdges)
    assert.isFunction(target.seen[0].source.resolveChain)
  })

  test('un driver sin `reconcile` lo DICE (500 E_AUTHZ_UNSUPPORTED), no migra a medias', async ({ assert }) => {
    const { manager } = managerWith()
    const error = await rejects(assert, () => manager.reconcile({ to: 'spy' }), 'E_AUTHZ_UNSUPPORTED', 500)
    assert.include(error.message, 'reconcile')
  })

  test('un destino que no está en `drivers` es 500 y nombra los registrados', async ({ assert }) => {
    const { manager } = managerWith()
    const error = await rejects(assert, () => manager.reconcile({ to: 'marte' }), 'E_AUTHZ_CONFIG', 500)
    assert.include(error.message, 'spy, destino')
  })

  test('sin `scopes.enumerateEdges` NO se inventa un árbol plano: 500', async ({ assert }) => {
    const tree = memoryScopeTree()
    const target = targetDriver()
    const manager = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => spyDriver(), destino: () => target.driver },
      scopes: { resolveChain: resolveChainFrom(tree) },
      warnOnOptInSecurity: false,
    })
    const error = await rejects(assert, () => manager.reconcile({ to: 'destino' }), 'E_AUTHZ_CONFIG', 500)
    assert.include(error.message, 'enumerateEdges')
    assert.lengthOf(target.seen, 0, 'ni se llega a construir el destino')
  })

  test('durante la pasada las escrituras están congeladas y las lecturas no; el finally descongela', async ({
    assert,
  }) => {
    const org = orgScope()
    let dentro: any = null
    let leyoDentro = false
    const target = targetDriver(async () => {
      try {
        await manager.grant({ type: 'users', uuid: uuidv7() }, 'org-editor', org)
      } catch (error) {
        dentro = error
      }
      leyoDentro = await manager.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', org)
    })
    const { manager, tree } = managerWith({}, target)
    await tree.attach(org, APP_SCOPE)

    await manager.reconcile({ to: 'destino' })

    assert.equal(dentro?.code, 'E_AUTHZ_FROZEN', 'una escritura durante la migración es 503 reintentable')
    assert.equal(dentro?.status, 503)
    assert.isTrue(leyoDentro, 'las lecturas siguen funcionando durante la migración')
    assert.isFalse(manager.frozen, 'y al salir se descongela')
  })

  test('si el driver revienta a mitad, el motor NO se queda congelado', async ({ assert }) => {
    const target = targetDriver(async () => {
      throw new Error('el destino se cayó a mitad de la migración')
    })
    const { manager, tree } = managerWith({}, target)
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)

    await assert.rejects(() => manager.reconcile({ to: 'destino' }), 'el destino se cayó a mitad de la migración')

    assert.isFalse(manager.frozen)
    await manager.grant({ type: 'users', uuid: uuidv7() }, 'org-editor', org)
  })

  test('la VENTANA del relay se reporta como deriva (y lo aparcado, aparte)', async ({ assert }) => {
    const outbox = sqlScopeOutbox()
    const target = targetDriver()
    const { manager, tree } = managerWith({ outbox }, target)
    const orgA = orgScope()
    const orgB = orgScope()
    await tree.attach(orgA, APP_SCOPE)
    await tree.attach(orgB, APP_SCOPE)
    // Dos cambios encolados y sin relevar: el backend decide con el árbol viejo.
    await manager.scopes.attached(orgA, APP_SCOPE)
    await manager.scopes.attached(orgB, APP_SCOPE)

    const report = await manager.reconcile({ to: 'destino', dryRun: true })

    assert.equal(report.drift.pendingRelay, 2, 'la ventana del relay se MIDE, no se supone')
    assert.equal(report.drift.deadRelay, 0)
  })
})

test.group('3b-3a · authz:reconcile (las decisiones del comando)', () => {
  const base = (over: any = {}): any => ({
    to: 'openfga',
    dryRun: false,
    prune: false,
    written: 0,
    updated: 0,
    unchanged: 10,
    extra: 0,
    deleted: 0,
    phases: {
      root: { written: 0, updated: 0, unchanged: 1, extra: 0, deleted: 0 },
      catalog: { written: 0, updated: 0, unchanged: 3, extra: 0, deleted: 0 },
      tree: { written: 0, updated: 0, unchanged: 2, extra: 0, deleted: 0 },
      facts: { written: 0, updated: 0, unchanged: 4, extra: 0, deleted: 0 },
    },
    skipped: {},
    details: [],
    cycles: [],
    drift: { rootMarker: false, multiParent: [], roleVisibility: 0, pendingRelay: 0, deadRelay: 0 },
    massDelete: false,
    ...over,
  })

  test('un --dry-run sin nada que hacer es LIMPIO (exit 0)', ({ assert }) => {
    const { clean } = reconcileLines(base({ dryRun: true }))
    assert.isTrue(clean)
  })

  test('un --dry-run con algo que escribir es DERIVA (exit 1)', ({ assert }) => {
    const { clean } = reconcileLines(base({ dryRun: true, written: 1 }))
    assert.isFalse(clean, 'para eso está en CI')
  })

  test('una pasada REAL que escribe no es deriva, pero un ciclo o un aparcado sí', ({ assert }) => {
    assert.isTrue(reconcileLines(base({ written: 7 })).clean)
    assert.isFalse(reconcileLines(base({ cycles: [['a', 'b']] })).clean)
    assert.isFalse(reconcileLines(base({ drift: { ...base().drift, deadRelay: 1 } })).clean)
    assert.isFalse(reconcileLines(base({ skipped: { 'unknown-scope': 2 } })).clean)
    // La ventana del relay AVISA pero no tumba: es una ventana por diseño.
    const ventana = reconcileLines(base({ drift: { ...base().drift, pendingRelay: 5 } }))
    assert.isTrue(ventana.clean)
    assert.isTrue(ventana.lines.some((l) => l.level === 'warning' && l.message.includes('sin relevar')))
  })

  test('3b-3b: el aviso del origen ciego habla del ORIGEN cuando el destino es `database`', ({ assert }) => {
    const haciaLaBase = reconcileLines(base({ to: 'database', prune: true, massDelete: true }))
    assert.isTrue(haciaLaBase.lines.some((l) => l.level === 'error' && l.message.includes('--from')))
    const haciaFga = reconcileLines(base({ prune: true, massDelete: true }))
    assert.isTrue(haciaFga.lines.some((l) => l.level === 'error' && l.message.includes('authz_assignments')))
  })

  test('3b-5: la primera línea dice DE DÓNDE salieron los hechos, y avisa de la pasada de mantenimiento', ({
    assert,
  }) => {
    const migracion = reconcileLines(base({ factsFrom: 'authz_assignments/authz_denies' } as any))
    assert.equal(migracion.lines[0].message, 'hechos: leídos de authz_assignments/authz_denies')

    const mantenimiento = reconcileLines(base({ to: 'openfga', factsFrom: 'openfga' } as any))
    assert.include(mantenimiento.lines[0].message, "los del propio 'openfga'")
    assert.include(mantenimiento.lines[0].message, '--from=', 'y la receta para migrar de verdad')

    // Un reporte de un driver de terceros que no lo diga no rompe nada.
    assert.isFalse(
      reconcileLines(base()).lines.some(
        (l) => l.message.includes('hechos: leídos de') || l.message.includes('los del propio')
      )
    )
  })

  test('sin --prune, los hechos de un scope muerto llevan la receta al lado', ({ assert }) => {
    const { lines } = reconcileLines(base({ skipped: { 'unknown-scope': 3 } }))
    assert.isTrue(lines.some((l) => l.message.includes('--prune')))
    const conPrune = reconcileLines(base({ prune: true, skipped: { 'unknown-scope': 3 } }))
    assert.isFalse(conPrune.lines.some((l) => l.message.includes('repite con --prune')))
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * 3b-3b · B1/B2 — `authz:reconcile --to=database`: la dirección FGA → DB.
 *
 * La vuelta. Aquí el ORIGEN es el store (hechos por `Read` PAGINADO: no hay
 * `ListObjects` que valga, no trae `continuation_token`) y el DESTINO son
 * `authz_assignments`/`authz_denies`. **El árbol NO se migra**: en esta
 * dirección lo lee el driver `database` de las tablas del consumidor, que
 * son su fuente de verdad — y el catálogo tampoco, que es propiedad local
 * siempre.
 * ════════════════════════════════════════════════════════════════════════ */

if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('3b-3b · reconcile --to=database (servidor real)', (group) => {
    const stores: string[] = []
    group.each.setup(async () => {
      await cleanAuthzTables()
      await cleanSqlScopeTree(db)
      return async () => {
        const { OpenFgaClient } = await import('@openfga/sdk')
        while (stores.length) await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
        await cleanAuthzTables()
        await cleanSqlScopeTree(db)
      }
    })

    const CATALOG = {
      permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
      roles: [
        { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] },
        { slug: 'unit-lead', scopeType: 'unit', permissions: ['docs:read', 'docs:write'] },
      ],
    }

    /**
     * El montaje INVERSO: catálogo en `authz_*` (siempre local), árbol en
     * `demo_scopes` (del consumidor, no se migra), hechos SOLO en el store
     * —escritos por el driver `openfga`—, y `authz_assignments`/`authz_denies`
     * vacías esperando la migración.
     */
    async function inverseSetup() {
      const tree = sqlScopeTree(db)
      const chain = resolveChainFrom(tree)
      await syncAuthzCatalog(CATALOG)

      const org = { type: 'organization', uuid: uuidv7() }
      const unit = { type: 'unit', uuid: uuidv7() }
      await tree.attach(org, APP_SCOPE)
      await tree.attach(unit, org)

      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `reconcile-inv-${Date.now()}-${stores.length}` })
      stores.push(store.id!)
      const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS_3, PERMISSIONS)
      )
      const fga = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: model.authorization_model_id!,
        holderTypes: HOLDERS_3,
        resolveChain: chain,
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      })
      // Marcador de raíz + proyección del catálogo, y el árbol como hechos.
      await syncAuthzCatalog(CATALOG, { projection: fga.catalogProjection() })
      await fga.onScopeAttached!(org, APP_SCOPE)
      await fga.onScopeAttached!(unit, org)

      const ana = { type: 'users', uuid: uuidv7() }
      const bea = { type: 'users', uuid: uuidv7() }
      await fga.grant(ana, 'org-editor', org, {})
      await fga.grant(bea, 'unit-lead', unit, {})
      await fga.deny(bea, 'docs:read', unit)

      const database = new DatabaseAuthorizationDriver({ resolveChain: chain })
      const source = {
        enumerateEdges: edgesOfDemoScopes(),
        resolveChain: chain,
        facts: (page: any) => fga.enumerateFacts!(page),
      }
      return { tree, chain, database, fga, source, org, unit, ana, bea, store }
    }

    test('enumerateFacts: los hechos del ORIGEN salen paginados, con su caducidad y con el cursor avanzando', async ({
      assert,
    }) => {
      const { fga, ana, bea, org, unit } = await inverseSetup()

      const todos: any[] = []
      let after: string | undefined
      let paginas = 0
      for (;;) {
        const page = await fga.enumerateFacts!({ limit: 1, after })
        paginas += 1
        assert.isAtMost(page.facts.length, 1, 'nunca más de `limit` hechos por página')
        todos.push(...page.facts)
        if (!page.cursor) break
        assert.notEqual(page.cursor, after, 'el cursor tiene que AVANZAR')
        after = page.cursor
        assert.isBelow(paginas, 200, 'no puede pagear para siempre')
      }

      const asignaciones = todos.filter((f) => f.kind === 'assignment')
      const denies = todos.filter((f) => f.kind === 'deny')
      assert.lengthOf(asignaciones, 2)
      assert.lengthOf(denies, 1)
      assert.deepEqual(
        asignaciones.map((f) => `${f.holder.type}:${f.holder.uuid}@${f.scope.type}`).sort(),
        [`users:${ana.uuid}@organization`, `users:${bea.uuid}@unit`].sort()
      )
      assert.deepEqual(denies[0].permission, 'docs:read')
      assert.deepEqual(denies[0].scope, unit)
      assert.deepEqual(asignaciones[0].expiresAt ?? null, null)
      // Y de una sola página sale exactamente lo mismo.
      const deUnaVez = await fga.enumerateFacts!({ limit: 100 })
      assert.lengthOf(deUnaVez.facts, 3)
      assert.isUndefined(deUnaVez.cursor)
      void org
    })

    test('la base vacía no concede NADA, y una pasada de reconcile la pone a la par del driver openfga', async ({
      assert,
    }) => {
      const { database, fga, source, org, unit, ana, bea } = await inverseSetup()

      assert.isFalse(await database.authorize(ana, 'docs:read', org), 'authz_assignments está vacía')

      const report = await database.reconcile!(source, {})

      assert.equal(report.to, 'database')
      assert.isFalse(report.dryRun)
      assert.isAbove(report.written, 0)
      assert.equal(report.deleted, 0, 'una base vacía no tiene nada que sobre')

      for (const [subject, permission, scope] of [
        [ana, 'docs:read', org],
        [ana, 'docs:read', unit],
        [ana, 'docs:write', unit],
        [bea, 'docs:write', unit],
        [bea, 'docs:read', unit],
        [bea, 'docs:read', org],
      ] as const) {
        assert.equal(
          await database.authorize(subject as any, permission, scope as any),
          await fga.authorize(subject as any, permission, scope as any),
          `paridad en ${permission}@${(scope as any).type}`
        )
      }
      assert.isTrue(await database.authorize(ana, 'docs:read', unit), 'la herencia hacia abajo')
      assert.isFalse(await database.authorize(bea, 'docs:read', unit), 'el deny explícito')
    })

    test('el ÁRBOL no se migra en esta dirección: lo lee el driver database del consumidor', async ({
      assert,
    }) => {
      const { database, source } = await inverseSetup()
      const antes = await db.from('demo_scopes').select('uuid')

      const report = await database.reconcile!(source, {})

      assert.deepEqual(report.phases.tree, { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 })
      assert.deepEqual(report.phases.root, { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 })
      assert.deepEqual(report.phases.catalog, { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 })
      assert.equal(report.written, report.phases.facts.written, 'todo lo que se escribe son HECHOS')
      assert.lengthOf(await db.from('demo_scopes').select('uuid'), antes.length, 'y el árbol queda intacto')
    })

    test('idempotencia: la SEGUNDA pasada escribe cero', async ({ assert }) => {
      const { database, source } = await inverseSetup()

      const primera = await database.reconcile!(source, {})
      const segunda = await database.reconcile!(source, {})

      assert.isAbove(primera.written, 0)
      assert.equal(segunda.written, 0, 'la segunda pasada no escribe NADA')
      assert.equal(segunda.updated, 0)
      assert.equal(segunda.deleted, 0)
      assert.equal(segunda.extra, 0)
      assert.equal(segunda.unchanged, primera.written + primera.unchanged)
    })

    test('--dry-run es el verificador: mismo recorrido, CERO escrituras (y no hay --fix)', async ({
      assert,
    }) => {
      const { database, source, ana, org } = await inverseSetup()

      const seco = await database.reconcile!(source, { dryRun: true })

      assert.isTrue(seco.dryRun)
      assert.isAbove(seco.written, 0, 'dice lo que escribiría')
      assert.lengthOf(await db.from('authz_assignments').select('uuid'), 0, 'y no ha escrito ni una fila')
      assert.lengthOf(await db.from('authz_denies').select('uuid'), 0)
      assert.isFalse(await database.authorize(ana, 'docs:read', org))

      await database.reconcile!(source, {})
      const limpio = await database.reconcile!(source, { dryRun: true })
      assert.equal(limpio.written, 0)
      assert.equal(limpio.extra, 0)
    })

    test('la caducidad viaja con su instante: distinta en el destino ⇒ `updated`, igual ⇒ `unchanged`', async ({
      assert,
    }) => {
      const { database, fga, source, ana, org } = await inverseSetup()
      const cuando = new Date(Date.now() + 3_600_000)
      await fga.grant(ana, 'org-editor', org, { expiresAt: cuando })

      await database.reconcile!(source, {})
      const fila: any = (
        await db.from('authz_assignments').where('holder_uuid', ana.uuid).select('*')
      )[0]
      assert.isNotNull(fila.expires_at, 'la caducidad tiene que haberse migrado')

      // Se cambia a mano en el DESTINO: el origen manda, así que se rehace.
      await db.from('authz_assignments').where('uuid', fila.uuid).update({ expires_at: null })
      const segunda = await database.reconcile!(source, {})
      assert.equal(segunda.updated, 1, 'la caducidad que difiere se rehace')
      assert.equal(segunda.written, 0)

      const tercera = await database.reconcile!(source, {})
      assert.equal(tercera.updated, 0, 'y ya no vuelve a moverse')
    })

    test('lo que NO se migra sale contado y con su motivo', async ({ assert }) => {
      const { database, fga, source, tree, org, unit, ana } = await inverseSetup()
      const carla = { type: 'users', uuid: uuidv7() }
      // (a) caducada: no concede, así que no se migra.
      await fga.grant(carla, 'org-editor', org, { expiresAt: new Date(Date.now() - 60_000) })

      const report = await database.reconcile!(source, {})
      assert.isAtLeast(report.skipped['expired'] ?? 0, 1, 'la caducada tiene que salir contada')
      assert.isTrue(
        report.details.some((d) => d.reason === 'expired' && d.detail.includes(carla.uuid)),
        'y con la fila nombrada'
      )
      assert.lengthOf(await db.from('authz_assignments').where('holder_uuid', carla.uuid).select('uuid'), 0)

      // (b) scope muerto: el consumidor borra la unit; sus hechos siguen en el store.
      await db.from('demo_scopes').where('uuid', unit.uuid).delete()
      const segunda = await database.reconcile!(source, {})
      assert.isAtLeast(segunda.skipped['unknown-scope'] ?? 0, 1)
      void tree
      void ana
    })

    test('--prune borra las filas que el store ya no respalda; sin él solo se reportan', async ({
      assert,
    }) => {
      const { database, fga, source, ana, bea, org } = await inverseSetup()
      await database.reconcile!(source, {})
      // El store deja de respaldar la asignación de ana.
      await fga.revoke(ana, 'org-editor', org)

      const sinPrune = await database.reconcile!(source, {})
      assert.isAtLeast(sinPrune.extra, 1, 'lo que sobra se ve')
      assert.equal(sinPrune.deleted, 0, 'pero no se borra sin --prune')
      assert.isAtLeast(sinPrune.skipped['extra-fact'] ?? 0, 1)
      assert.lengthOf(await db.from('authz_assignments').where('holder_uuid', ana.uuid).select('uuid'), 1)

      const conPrune = await database.reconcile!(source, { prune: true })
      assert.isAtLeast(conPrune.deleted, 1)
      assert.lengthOf(await db.from('authz_assignments').where('holder_uuid', ana.uuid).select('uuid'), 0)
      // Y bea sigue: la purga es de lo que sobra, no de todo.
      assert.lengthOf(await db.from('authz_assignments').where('holder_uuid', bea.uuid).select('uuid'), 1)

      const tercera = await database.reconcile!(source, { prune: true })
      assert.equal(tercera.written, 0)
      assert.equal(tercera.deleted, 0)
    })

    test('--prune con el ORIGEN vacío se niega (store ciego), y --allow-mass-delete es la salida', async ({
      assert,
    }) => {
      const { database, source, fga } = await inverseSetup()
      await database.reconcile!(source, {})
      // El store se vacía de hechos (o se apunta al store equivocado).
      const vacio = {
        ...source,
        facts: async () => ({ facts: [] }),
      }

      const seco = await database.reconcile!(vacio as any, { dryRun: true, prune: true })
      assert.isTrue(seco.massDelete, 'el --dry-run lo marca, no lanza')

      await rejects(
        assert,
        () => database.reconcile!(vacio as any, { prune: true }),
        'E_AUTHZ_MASS_RECONCILE_REFUSED',
        500
      )
      assert.isAtLeast((await db.from('authz_assignments').select('uuid')).length, 1, 'no ha borrado nada')

      const forzado = await database.reconcile!(vacio as any, { prune: true, allowMassDelete: true })
      assert.isAtLeast(forzado.deleted, 1)
      void fga
    })

    test('los hechos de la RAÍZ se migran en las dos direcciones (el centinela de `app` no es un uuid)', async ({
      assert,
    }) => {
      // Regresión del 3b-3b: `authz_assignments.scope_uuid` es NOT NULL y la
      // raíz va con el centinela `00000000-…`, así que el `?? null` del 3a
      // nunca era null y `scopeKey` rechazaba `{app, uuid}` con un 422 A
      // MITAD de la migración. Lo cazó el contrato de migración (su siembra
      // fija concede en `app`); aquí queda como caso propio, en las dos
      // direcciones.
      const { database, fga, source, ana, org } = await inverseSetup()
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
        roles: [
          { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] },
          { slug: 'unit-lead', scopeType: 'unit', permissions: ['docs:read', 'docs:write'] },
          { slug: 'root-editor', scopeType: 'app', permissions: ['docs:write'] },
        ],
      })
      await syncAuthzCatalog(
        {
          permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
          roles: [
            { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] },
            { slug: 'unit-lead', scopeType: 'unit', permissions: ['docs:read', 'docs:write'] },
            { slug: 'root-editor', scopeType: 'app', permissions: ['docs:write'] },
          ],
        },
        { projection: fga.catalogProjection() }
      )
      await fga.grant(ana, 'root-editor', APP_SCOPE, {})
      await fga.deny(ana, 'docs:read', APP_SCOPE)

      // FGA → DB: la raíz llega.
      await database.reconcile!(source, {})
      assert.isTrue(await database.authorize(ana, 'docs:write', APP_SCOPE), 'el grant de la RAÍZ')
      assert.isFalse(await database.authorize(ana, 'docs:read', org), 'y el deny de la RAÍZ, heredado')

      // DB → FGA: y vuelve, sin reventar por el centinela.
      const { OpenFgaClient } = await import('@openfga/sdk')
      const store2 = await new OpenFgaClient({ apiUrl }).createStore({ name: `reconcile-raiz-${Date.now()}` })
      stores.push(store2.id!)
      const model2 = await new OpenFgaClient({ apiUrl, storeId: store2.id }).writeAuthorizationModel(
        openFgaFactsModel(HOLDERS_3, PERMISSIONS)
      )
      const destino = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store2.id!,
        modelId: model2.authorization_model_id!,
        holderTypes: HOLDERS_3,
        resolveChain: source.resolveChain,
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      })
      const report = await destino.reconcile!(source, {})
      assert.equal(report.skipped['invalid-scope'] ?? 0, 0)
      assert.isTrue(await destino.authorize(ana, 'docs:write', APP_SCOPE))
      assert.isFalse(await destino.authorize(ana, 'docs:read', org))
    })

    test('la caducidad viaja al MILISEGUNDO en los dos sentidos (la «precisión sub-segundo» que el panel declaró la cierra DATETIME(3))', async ({
      assert,
    }) => {
      // El panel 2 dio por declarada una pérdida por «precisión sub-segundo en
      // MySQL». Se mide aquí, en el motor de la corrida: `authz_assignments.
      // expires_at` es `DATETIME(3)` y el codec de MySQL escribe y lee la
      // cadena UTC con milisegundos (2.5-B · K2), y la condición `not_expired`
      // de FGA lleva un ISO-8601 con milisegundos. Un `Date` de JS no tiene
      // más resolución que esa, así que el viaje redondo es EXACTO y esa
      // pérdida no existe con el esquema publicado.
      const { database, fga, source, ana, org } = await inverseSetup()
      const conMilis = new Date(Date.now() + 3_600_000)
      conMilis.setMilliseconds(123)
      await fga.grant(ana, 'org-editor', org, { expiresAt: conMilis })

      await database.reconcile!(source, {})
      const fila: any = (
        await db
          .from('authz_assignments')
          .where('holder_uuid', ana.uuid)
          .select('uuid')
          .select(new DatabaseAuthorizationDriver({})['expiry'].select('expires_at') as any)
      )[0]
      const leida = new DatabaseAuthorizationDriver({})['expiry'].fromDb(fila.expires_at)
      assert.equal(leida?.getTime(), conMilis.getTime(), 'FGA → DB conserva el milisegundo')
      assert.equal(leida!.getMilliseconds(), 123)

      // Y de vuelta: la segunda pasada no ve ninguna diferencia (si se hubiera
      // truncado, la caducidad diferiría y saldría como `updated`).
      const segunda = await database.reconcile!(source, {})
      assert.equal(segunda.updated, 0, 'nada que rehacer: el instante es el mismo')
    })

    test('dos hechos del ORIGEN que colapsan en UNA fila salen contados (`folded-scope`) y se quedan con la caducidad que más dura', async ({
      assert,
    }) => {
      // S15 medido: el store distingue `scope:unit|aaa…` de `scope:unit|aaa-…`
      // y la tabla del consumidor no puede tener las dos (columna `uuid` en
      // PostgreSQL, collation `*_ci` en MySQL), así que la cadena canónica las
      // funde. Aquí el origen es un doble para que el caso corra en los CUATRO
      // motores; el disparador real está medido en el informe del lote.
      const { database, source, org, ana } = await inverseSetup()
      const rol: any = (await db.from('authz_roles').where('slug', 'org-editor').select('uuid'))[0]
      const pronto = new Date(Date.now() + 3_600_000)
      const tarde = new Date(Date.now() + 7_200_000)
      const dobles = {
        ...source,
        facts: async () => ({
          facts: [
            { kind: 'assignment', holder: ana, scope: org, roleUuid: String(rol.uuid), expiresAt: pronto, detail: 'ortografía A' },
            { kind: 'assignment', holder: ana, scope: org, roleUuid: String(rol.uuid), expiresAt: tarde, detail: 'ortografía B' },
          ],
        }),
      }

      const report = await database.reconcile!(dobles as any, {})

      assert.equal(report.skipped['folded-scope'], 1, 'el colapso se CUENTA, no se traga')
      assert.isTrue(report.details.some((d) => d.reason === 'folded-scope' && d.detail.includes('ortografía')))
      const codec = new DatabaseAuthorizationDriver({})['expiry']
      const filas: any[] = await db
        .from('authz_assignments')
        .where('holder_uuid', ana.uuid)
        .select('uuid')
        .select(codec.select('expires_at') as any)
      assert.lengthOf(filas, 1, 'y en el destino hay UNA fila, no dos')
      assert.equal(
        codec.fromDb(filas[0].expires_at)?.getTime(),
        tarde.getTime(),
        'con la caducidad que MÁS dura: el origen concedía mientras cualquiera siguiera viva'
      )
    })

    test('de punta a punta por el manager: authz:reconcile --to=database con el motor congelado', async ({
      assert,
    }) => {
      const { database, fga, source, org, unit, ana, bea } = await inverseSetup()
      const manager = new AuthorizationManager({
        // El motor sigue sirviendo con `openfga` mientras se llena la base.
        default: 'openfga',
        drivers: { openfga: () => fga, database: () => database },
        holderTypes: HOLDERS_3,
        scopes: { resolveChain: source.resolveChain, enumerateEdges: edgesOfDemoScopes() },
        warnOnOptInSecurity: false,
      })

      const report = await manager.reconcile({ to: 'database' })

      assert.equal(report.to, 'database')
      assert.isAbove(report.written, 0)
      assert.isFalse(manager.frozen, 'el finally descongela')
      for (const [subject, permission, scope] of [
        [ana, 'docs:read', org],
        [bea, 'docs:read', unit],
        [bea, 'docs:write', unit],
      ] as const) {
        assert.equal(
          await database.authorize(subject as any, permission, scope as any),
          await fga.authorize(subject as any, permission, scope as any)
        )
      }
      // Y el verificador ya no ve deriva.
      const limpio = await manager.reconcile({ to: 'database', dryRun: true })
      assert.equal(limpio.written, 0)
      assert.equal(limpio.extra, 0)
    })

    test('la cota del volcado es un 500 con nombre, no un OOM (B5)', async ({ assert }) => {
      const { database, source } = await inverseSetup()

      const error = await rejects(
        assert,
        () => database.reconcile!(source, { maxTuples: 2 } as any),
        'E_AUTHZ_RECONCILE_TOO_LARGE',
        500
      )
      assert.include(error.message, 'maxTuples')
    })
  })
}

/* ════════════════════════════════════════════════════════════════════════
 * 3b-3b · B4 — el ORIGEN de la migración: quién es y cómo se dice.
 *
 * `--to` nombra el destino por el registro (3b-3a, decisión 1). La vuelta
 * necesita además un ORIGEN, y elegirlo por ti es elegir de dónde sale lo
 * que va a quedar escrito: la regla es determinista y RUIDOSA.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('3b-3b · manager.reconcile: el ORIGEN', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
    await cleanSqlScopeTree(db)
    return async () => {
      await cleanScopeOutbox(db)
      await cleanSqlScopeTree(db)
    }
  })

  /** Un driver de laboratorio que SABE ser origen. */
  function sourceDriver(facts: any[] = []) {
    const asked: any[] = []
    return {
      asked,
      driver: {
        ...spyDriver(),
        async enumerateFacts(page: any) {
          asked.push(page)
          return { facts }
        },
      },
    }
  }

  /** Un destino que solo apunta qué `source` recibió. */
  function sinkDriver() {
    const seen: any[] = []
    return {
      seen,
      driver: {
        ...spyDriver(),
        async reconcile(source: any, options: any) {
          const page = await source.facts({ limit: 100 })
          seen.push({ facts: page.facts })
          return {
            to: 'sink',
            dryRun: options.dryRun === true,
            prune: false,
            written: page.facts.length,
            updated: 0,
            unchanged: 0,
            extra: 0,
            deleted: 0,
            phases: {
              root: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
              catalog: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
              tree: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
              facts: { written: page.facts.length, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
            },
            skipped: {},
            details: [],
            cycles: [],
            drift: { rootMarker: false, multiParent: [], roleVisibility: 0, pendingRelay: 0, deadRelay: 0 },
            massDelete: false,
          }
        },
      },
    }
  }

  function managerWithDrivers(drivers: any) {
    const tree = memoryScopeTree()
    return new AuthorizationManager({
      default: Object.keys(drivers)[0],
      drivers,
      holderTypes: HOLDERS,
      scopes: { resolveChain: resolveChainFrom(tree), enumerateEdges: edgesOfDemoScopes() },
      warnOnOptInSecurity: false,
    })
  }

  const HECHO = {
    kind: 'assignment',
    holder: { type: 'users', uuid: uuidv7() },
    scope: { type: 'organization', uuid: uuidv7() },
    roleUuid: uuidv7(),
    expiresAt: null,
    detail: 'de laboratorio',
  }

  test('con DOS drivers, el origen es el que no es el destino (y no hace falta decirlo)', async ({
    assert,
  }) => {
    const origen = sourceDriver([HECHO])
    const destino = sinkDriver()
    const manager = managerWithDrivers({ origen: () => origen.driver, sink: () => destino.driver })

    const report = await manager.reconcile({ to: 'sink' })

    assert.equal(report.written, 1)
    assert.lengthOf(destino.seen, 1)
    assert.deepEqual(destino.seen[0].facts, [HECHO])
    assert.deepEqual(origen.asked, [{ limit: 100 }])
  })

  test('con MÁS de un origen posible NO se adivina: 500 pidiendo --from', async ({ assert }) => {
    const manager = managerWithDrivers({
      a: () => sourceDriver([HECHO]).driver,
      b: () => sourceDriver([]).driver,
      sink: () => sinkDriver().driver,
    })

    const error = await rejects(assert, () => manager.reconcile({ to: 'sink' }), 'E_AUTHZ_CONFIG', 500)
    assert.include(error.message, '--from')
    assert.include(error.message, 'a, b')
  })

  test('--from manda: el origen es el que se nombra', async ({ assert }) => {
    const a = sourceDriver([HECHO])
    const b = sourceDriver([])
    const destino = sinkDriver()
    const manager = managerWithDrivers({ a: () => a.driver, b: () => b.driver, sink: () => destino.driver })

    const report = await manager.reconcile({ to: 'sink', from: 'b' })

    assert.equal(report.written, 0, 'los hechos son los de b, no los de a')
    assert.lengthOf(a.asked, 0)
    assert.lengthOf(b.asked, 1)
  })

  test('sin NINGÚN origen posible, la pasada lo DICE (500 E_AUTHZ_UNSUPPORTED) en vez de migrar cero', async ({
    assert,
  }) => {
    const destino = sinkDriver()
    const manager = managerWithDrivers({ solo: () => spyDriver(), sink: () => destino.driver })

    const error = await rejects(assert, () => manager.reconcile({ to: 'sink' }), 'E_AUTHZ_UNSUPPORTED', 500)
    assert.include(error.message, 'enumerateFacts')
  })

  test('un --from que no sabe ser origen es 500 nombrando el método, no una migración vacía', async ({
    assert,
  }) => {
    const destino = sinkDriver()
    const manager = managerWithDrivers({ mudo: () => spyDriver(), sink: () => destino.driver })

    const error = await rejects(
      assert,
      () => manager.reconcile({ to: 'sink', from: 'mudo' }),
      'E_AUTHZ_UNSUPPORTED',
      500
    )
    assert.include(error.message, 'enumerateFacts')
  })

  test('--from igual que --to es 500: no hay migración de un driver a sí mismo', async ({ assert }) => {
    const destino = sinkDriver()
    const manager = managerWithDrivers({ sink: () => destino.driver, otro: () => spyDriver() })
    await rejects(assert, () => manager.reconcile({ to: 'sink', from: 'sink' }), 'E_AUTHZ_CONFIG', 500)
  })

  test('3b-5: el destino ACTIVO cuyos hechos son suyos y no sabe enumerarlos es 500, no una reconstrucción desde authz_*', async ({
    assert,
  }) => {
    // Si el motor sirve desde ese driver, `authz_*` no es la fuente de verdad
    // de sus hechos: rehacerlo desde ellas es el defecto, así que la pasada
    // se niega en voz alta en vez de escribir.
    const target = targetDriver()
    target.driver.capabilities = { ...target.driver.capabilities, hierarchyFacts: true }
    const manager = managerWithDrivers({ destino: () => target.driver, otro: () => spyDriver() })

    const error = await rejects(assert, () => manager.reconcile({ to: 'destino' }), 'E_AUTHZ_UNSUPPORTED', 500)
    assert.include(error.message, 'enumerateFacts')
    assert.lengthOf(target.seen, 0, 'y no llega a llamar al destino')
  })

  test('el ORIGEN es PEREZOSO: `--to=openfga` no construye ningún driver de más', async ({ assert }) => {
    let construido = 0
    const target = targetDriver()
    const manager = managerWithDrivers({
      origen: () => {
        construido += 1
        return sourceDriver([HECHO]).driver
      },
      destino: () => target.driver,
    })

    await manager.reconcile({ to: 'destino', dryRun: true })

    assert.equal(construido, 0, 'el destino no pidió hechos, así que no se resolvió ningún origen')
    assert.isFunction(target.seen[0].source.facts, 'pero el puerto está ahí por si lo pide')
  })
})
