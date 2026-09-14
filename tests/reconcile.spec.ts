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
import { testEngine } from './helpers/app.js'
import { cleanAuthzTables, cleanScopeOutbox } from './helpers/schema.js'
import { sqlScopeOutbox } from '../src/scope_outbox.js'
import { reconcileLines } from '../commands/authz_reconcile.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { OpenFgaAuthorizationDriver, openFgaFactsModel, OpenFgaRelationsDriver } from '../src/openfga.js'
import { OWN_FACTS_OBJECT_TYPES } from '../src/drivers/openfga_driver.js'
import { FACTS_GROUP_TYPE, RESERVED_FACTS_TYPES } from '../src/drivers/openfga_facts.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
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
    withClock() {
      return this
    },
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

    const token = await manager.freeze('reconcile de prueba')

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
    await manager.unfreeze(token)
  })

  test('congelado: las LECTURAS siguen funcionando', async ({ assert }) => {
    const { manager, driver, tree } = frozenManager()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const subject = { type: 'users', uuid: uuidv7() }

    const token = await manager.freeze()

    assert.isTrue(await manager.authorize(subject, 'docs:read', org))
    assert.deepEqual(await manager.listRoles(subject, org), [])
    assert.isFalse(await manager.hasRole(subject, 'org-editor', org))
    assert.deepEqual(driver.calls, ['authorize', 'listRoles', 'hasRole'])
    await manager.unfreeze(token)
  })

  test('unfreeze devuelve las escrituras, y una vista de forRequest hereda el estado del manager', async ({
    assert,
  }) => {
    const { manager, driver, tree } = frozenManager()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const subject = { type: 'users', uuid: uuidv7() }
    const view = manager.forRequest()

    const token = await manager.freeze()
    // La vista NO es otro manager para esto: congelar el motor congela todo
    // lo que escribe por él.
    await rejects(assert, () => view.grant(subject, 'org-editor', org), 'E_AUTHZ_FROZEN', 503)
    assert.isTrue(await view.authorize(subject, 'docs:read', org))

    await manager.unfreeze(token)
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

  test('3b-7 · el freeze ANIDADO corre dentro y NO levanta la ventana exterior (auditor A1.1/A1.3)', async ({
    assert,
  }) => {
    // Hasta este lote `withFrozenWrites` hacía `unfreeze()` incondicional en
    // su finally: un `reconcile` dentro de una ventana congelada la
    // DESCONGELABA al terminar (A1.3 medido). Con el token de dueño, la
    // ventana interior detecta que el manager ya sostiene el freeze, corre
    // dentro y su cierre es un no-op.
    const { manager, tree } = frozenManager()
    const org = orgScope()
    await tree.attach(org, APP_SCOPE)
    const subject = { type: 'users', uuid: uuidv7() }

    const token = await manager.freeze('ventana exterior')
    await manager.withFrozenWrites('ventana interior', async () => {})
    const error = await rejects(assert, () => manager.grant(subject, 'org-editor', org), 'E_AUTHZ_FROZEN', 503)
    assert.include(error.message, 'ventana exterior', 'la exterior sigue en pie tras cerrar la interior')
    await manager.unfreeze(token)
    await manager.grant(subject, 'org-editor', org)
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

    /**
     * **alpha.5 · R0 (tester 4-6)**: el verificador ya camina el árbol del
     * origen, así que reporta como deriva las cadenas que superan el techo de
     * resolución del modelo (`FACTS_MAX_RESOLVE_DEPTH`, 22 saltos; o
     * `scopes.maxDepth` si el consumidor lo declara — un solo mando). Un
     * scope así es legal en `database` y un 503 en `openfga`: hay que verlo
     * en CI, no en el primer tenant que lo alcance.
     */
    test('R0 · un árbol con una cadena de 23 saltos sale en `drift.tooDeep` (dry-run, exit 1); a 22 no; y `scopes.maxDepth` del config manda sobre el techo', async ({
      assert,
    }) => {
      const tree = memoryScopeTree()
      const chain = resolveChainFrom(tree)
      let parent: any = APP_SCOPE
      const nodes: any[] = []
      for (let i = 0; i < 23; i++) {
        const node = i === 0 ? { type: 'organization', uuid: uuidv7() } : { type: 'unit', uuid: uuidv7() }
        await tree.attach(node, parent)
        nodes.push(node)
        parent = node
      }
      /** `scopes.enumerateEdges` sobre el árbol en memoria, paginado por índice. */
      const edgesOf = async ({ limit, after }: { limit: number; after?: string }) => {
        const all: any[] = []
        for await (const edge of tree.edges()) all.push(edge)
        const start = after === undefined ? 0 : Number(after)
        const edges = all.slice(start, start + limit)
        const next = start + limit
        return next < all.length ? { edges, cursor: String(next) } : { edges }
      }
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
      const deepest = `unit|${nodes[22].uuid}`
      const report = await fga.reconcile({ enumerateEdges: edgesOf, resolveChain: chain }, { dryRun: true })
      assert.deepEqual(report.drift.tooDeep, [deepest], 'solo el nodo a 23 saltos supera 22')
      assert.equal(report.drift.tooDeepLimit, 22)
      const lines = reconcileLines(report)
      assert.isFalse(lines.clean, 'en CI se ve')
      assert.isTrue(lines.lines.some((l) => l.level === 'error' && l.message.includes(deepest)))

      // Con el techo del consumidor (raised OPENFGA_RESOLVE_NODE_LIMIT): un solo mando.
      const relaxed = await fga.reconcile({ enumerateEdges: edgesOf, resolveChain: chain, maxDepth: 30 }, { dryRun: true })
      assert.deepEqual(relaxed.drift.tooDeep, [])
      assert.equal(relaxed.drift.tooDeepLimit, 30)
      // Y por el manager, que lee `scopes.maxDepth` y se lo pasa al driver.
      const manager = new AuthorizationManager({
        default: 'fga',
        drivers: { fga: () => fga },
        holderTypes: HOLDERS_3,
        scopes: { resolveChain: chain, enumerateEdges: edgesOf, acceptScopeDriftRisk: true, maxDepth: 23 },
        warnOnOptInSecurity: false,
      } as any)
      const viaManager = await manager.reconcile({ to: 'fga', dryRun: true })
      assert.deepEqual(viaManager.drift.tooDeep, [])
      assert.equal(viaManager.drift.tooDeepLimit, 23)
    }).timeout(60_000)

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

    /**
     * **3b-8 · B1 — el seguro mira los hechos UTILIZABLES, no el conteo
     * crudo.** El contador del origen se incrementaba ANTES de cada skip,
     * así que un origen cuyos hechos se descartan TODOS (el árbol ya no
     * resuelve ninguno de sus scopes: la firma de un resolutor ciego o de la
     * base equivocada) esquivaba `E_AUTHZ_MASS_RECONCILE_REFUSED` y
     * `--prune` vaciaba el destino sin una sola pregunta. Es el primo del 🔴
     * del lote 5, un escalón abajo.
     */
    test('3b-8 · B1: --prune con un origen cuyos hechos se DESCARTAN todos también se niega — el conteo crudo no desarma el seguro', async ({
      assert,
    }) => {
      const { tree, fga, source, org } = await migrationSetup()
      await fga.reconcile!(source, {})
      // El árbol deja de resolver los scopes de TODOS los hechos: el origen
      // sigue devolviendo filas (conteo crudo > 0) pero ninguna respalda
      // nada de lo que --prune va a borrar.
      await tree.detach(org)

      const error = await rejects(
        assert,
        () => fga.reconcile!(source, { prune: true }),
        'E_AUTHZ_MASS_RECONCILE_REFUSED',
        500
      )
      assert.include(error.message, 'utilizable', 'el error dice que se leyeron hechos y se descartaron todos')
      assert.isAbove((await todoElStore(fga)).length, 0, 'no ha borrado nada antes de negarse')

      // El dry-run no lanza: lo marca, y `skipped` dice el porqué.
      const seco = await fga.reconcile!(source, { prune: true, dryRun: true })
      assert.isTrue(seco.massDelete)
      assert.isAtLeast(seco.skipped['unknown-scope'] ?? 0, 1)
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
      const { tree, chain, fga, database, manager, client } = await factsDeployment()
      const org = orgScope()
      const despedido = { type: 'users', uuid: uuidv7() }
      const empleado = { type: 'users', uuid: uuidv7() }
      await tree.attach(org, APP_SCOPE)
      await manager.scopes.attached(org, APP_SCOPE)
      await manager.relayScopeChanges()

      // 1. La era `database`, y la MIGRACIÓN documentada: el origen se dice.
      await database.grant(despedido, 'org-admin', org, {})
      await database.grant(empleado, 'org-admin', org, {})
      // alpha.10 · 1 — ESTE CASO CODIFICABA EL DEFECTO y se le da la vuelta:
      // hasta alpha.9 hacía la migración con el manager que YA sirve desde
      // `openfga` (`--to=openfga --from=database` con `default: 'openfga'`), o
      // sea la dirección rancia dada por buena. Ahora esa llamada se NIEGA, y la
      // migración legítima se hace como en la vida real: con el motor todavía
      // sirviendo desde `database` (`default: 'database'`, `to` ≠ activo).
      await rejects(
        assert,
        () => manager.reconcile({ to: 'openfga', from: 'database' }),
        'E_AUTHZ_STALE_SOURCE_REFUSED',
        500
      )
      const antesDelCutover = new AuthorizationManager({
        default: 'database',
        drivers: { openfga: () => fga, database: () => database },
        holderTypes: HOLDERS_3,
        scopes: { resolveChain: chain, outbox: sqlScopeOutbox(), enumerateEdges: edgesOfDemoScopes() },
        warnOnOptInSecurity: false,
      } as any)
      const migracion = await antesDelCutover.reconcile({ to: 'openfga', from: 'database' })
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

      // 3b. alpha.10 · 1: la dirección RANCIA que COGNITIV midió —con `openfga`
      //     sirviendo, `--from=database` leía las tablas congeladas y re-escribía
      //     al revocado— se niega en el MANAGER, con o sin `--prune`, sin tocar
      //     el store; el verificador la marca en vez de lanzar.
      for (const prune of [false, true]) {
        await rejects(
          assert,
          () => manager.reconcile({ to: 'openfga', from: 'database', prune }),
          'E_AUTHZ_STALE_SOURCE_REFUSED',
          500
        )
        assert.isFalse(await fga.authorize(despedido, 'docs:write', org), 'el revocado NO resucita')
      }
      assert.isNull(await manager.freezeStatus(), 'negarse no congela la flota')

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

    test('alpha.10 · 4 · EFECTO: la pasada de MANTENIMIENTO con `--prune` BORRA los hechos de un scope que ya no resuelve, y la salida no dice «no borra»', async ({
      assert,
    }) => {
      const { tree, fga, manager } = await factsDeployment()
      const org = orgScope()
      const viva = orgScope()
      const ana = { type: 'users', uuid: uuidv7() }
      const eva = { type: 'users', uuid: uuidv7() }
      for (const scope of [org, viva]) {
        await tree.attach(scope, APP_SCOPE)
        await manager.scopes.attached(scope, APP_SCOPE)
      }
      await manager.relayScopeChanges()
      await manager.grant(ana, 'org-admin', org)
      // Un hecho VIVO que el origen sí respalda (COGNITIV: «iguales 78»): sin
      // él la pasada es el origen ciego y se niega (E_AUTHZ_MASS_RECONCILE_REFUSED).
      await manager.grant(eva, 'org-admin', viva)
      assert.isTrue(await fga.authorize(ana, 'docs:write', org))

      // La organización desaparece de las tablas del consumidor sin `detached`
      // (el caso medido por COGNITIV: un binding sobre una org inexistente).
      await db.from('demo_scopes').where('uuid', org.uuid).delete()

      const sinPrune = await manager.reconcile({ to: 'openfga' })
      assert.equal(sinPrune.factsFrom, 'openfga')
      assert.equal(sinPrune.phases.facts.deleted, 0, 'sin --prune no borra ningún hecho')
      assert.isAbove(sinPrune.skipped['extra-fact'] ?? 0, 0, 'los reporta')

      const podado = await manager.reconcile({ to: 'openfga', prune: true })
      assert.equal(podado.factsFrom, 'openfga', 'sigue siendo la pasada de MANTENIMIENTO')
      assert.equal(podado.phases.facts.extra, 3, 'sobran 3: assignee, role_binding#role y scope#binding')
      assert.equal(podado.phases.facts.deleted, 3, 'borradas 3')
      const tuplas = await todoElStore(fga)
      assert.isUndefined(tuplas.find((t) => t.includes(org.uuid) && t.includes('#assignee@')), tuplas.join(' | '))
      assert.isTrue(await fga.authorize(eva, 'docs:write', viva), 'lo vivo no se toca')

      const texto = reconcileLines(podado).lines.map((l) => l.message).join('\n')
      assert.notInclude(texto, 'ni borra', 'la salida no puede decir que no borra justo cuando borra')
      assert.include(texto, 'con --prune borra los de scopes que ya no resuelven')
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
      assert.deepEqual(
        migracion.staleSource,
        { to: 'openfga', from: 'database', allowed: false },
        'alpha.10 · 1: hacia el driver ACTIVO es la dirección rancia; el verificador la marca'
      )
      assert.isFalse(reconcileLines(migracion).clean)
      assert.isFalse(await fga.authorize(ana, 'docs:write', org), '--dry-run no ha escrito nada')
    })
  })

  /* ══════════════════════════════════════════════════════════════════════
   * **2.4.0-alpha.9 · lote B — el store COMPARTIDO** (🔴 3 del quinto informe
   * de COGNITIV; panel `panel-shared-store-{auditor,analista}`; decisión del
   * dueño del 2026-09-11 (2)).
   *
   * Con `openfga` los DOS subsistemas comparten store y el reconcile de
   * hechos lee el destino ENTERO (`Read({})` es la única forma de ver lo que
   * sobra). `familyOfTuple` tenía `return 'facts'` de CATCH-ALL, así que toda
   * tupla de `relations/` caía en `extra` y `--prune` la borraba: 60 de 60
   * medidas por el consumidor —`group` incluido, el tipo que el generador
   * emite SIEMPRE— y la pasada destructiva reportaba `clean = true` con exit
   * 0, porque borraba justo lo que causaba el `extra-fact`.
   *
   * La regla que fijan estos casos: la pasada gobierna CUATRO tipos de objeto
   * (`scope`, `role`, `role_binding` y el obsoleto `deny_binding`) y lo demás
   * es AJENO —ni se borra, ni es deriva, ni entra en `skipped`—, con la
   * prueba decisiva de que lo PROPIO obsoleto se sigue barriendo entero.
   * ══════════════════════════════════════════════════════════════════════ */
  test.group('alpha.9 · B · el store COMPARTIDO (servidor real)', (group) => {
    const stores: string[] = []
    group.each.setup(async () => {
      await cleanAuthzTables()
      return async () => {
        const { OpenFgaClient } = await import('@openfga/sdk')
        while (stores.length) await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
        await cleanAuthzTables()
      }
    })

    /** La config de relaciones del OTRO subsistema del mismo store. */
    const relacionesConfig = defineRelationsConfig({
      objectTypes: [
        { type: 'document', relations: [{ name: 'viewer' }] },
        { type: 'space', relations: [{ name: 'reader' }] },
      ],
      holderTypes: ['user', 'admin', 'integration'],
    })

    /**
     * Un despliegue con los dos subsistemas en el MISMO store: catálogo y
     * hechos en `authz_*` (los escribe el driver `database` por el API), el
     * árbol en memoria, y el store con el modelo FUSIONADO (hechos +
     * relaciones), que es lo que publica `openfga:provision` cuando hay
     * `relations.config`.
     *
     * Con `legado: true` el store nace con un modelo ANTERIOR que declara
     * `deny_binding` (el deny del modo `resolver` de 2.2) y un `legacy_thing`
     * de otro subsistema: las dos tuplas se escriben bajo ese modelo y
     * sobreviven al cambio de modelo (medido en
     * `.claude/reproducciones/shared-store-tipos-legado.sh`).
     */
    async function despliegueCompartido(opciones: { legado?: boolean } = {}) {
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
        roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] }],
      })
      const tree = memoryScopeTree()
      const chain = resolveChainFrom(tree)
      const org = orgScope()
      await tree.attach(org, APP_SCOPE)
      const edgesOf = async ({ limit, after }: { limit: number; after?: string }) => {
        const all: ScopeEdge[] = []
        for await (const edge of tree.edges()) all.push(edge)
        const start = after === undefined ? 0 : Number(after)
        const edges = all.slice(start, start + limit)
        const next = start + limit
        return next < all.length ? { edges, cursor: String(next) } : { edges }
      }
      const database = new DatabaseAuthorizationDriver({ resolveChain: chain })
      const ana = { type: 'users', uuid: uuidv7() }
      await database.grant(ana, 'org-editor', org, {})
      await database.deny(ana, 'docs:write', org)

      const { OpenFgaClient } = await import('@openfga/sdk')
      const store = await new OpenFgaClient({ apiUrl }).createStore({
        name: `compartido-${Date.now()}-${stores.length}`,
      })
      stores.push(store.id!)
      const client = new OpenFgaClient({ apiUrl, storeId: store.id })
      const legado: string[] = []
      if (opciones.legado === true) {
        const viejo = await client.writeAuthorizationModel({
          schema_version: '1.1',
          type_definitions: [
            { type: 'user', relations: {} },
            {
              type: 'deny_binding',
              relations: { denied: { this: {} } },
              metadata: { relations: { denied: { directly_related_user_types: [{ type: 'user' }] } } },
            },
            {
              type: 'legacy_thing',
              relations: { owner: { this: {} } },
              metadata: { relations: { owner: { directly_related_user_types: [{ type: 'user' }] } } },
            },
          ],
        } as any)
        const permisoUuid = uuidv7()
        const denyBinding = `deny_binding:organization|${org.uuid}|${permisoUuid}`
        const cosaAjena = `legacy_thing:${uuidv7()}`
        await client.write(
          {
            writes: [
              { user: `user:${ana.uuid}`, relation: 'denied', object: denyBinding },
              { user: `user:${ana.uuid}`, relation: 'owner', object: cosaAjena },
            ],
          },
          { authorizationModelId: viejo.authorization_model_id }
        )
        legado.push(`user:${ana.uuid}#denied@${denyBinding}`, `user:${ana.uuid}#owner@${cosaAjena}`)
      }
      const model = await client.writeAuthorizationModel(
        openFgaFactsModel(HOLDERS_3, PERMISSIONS, { objectTypes: relacionesConfig.objectTypes })
      )
      const modelId = model.authorization_model_id!
      const fga = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId,
        holderTypes: HOLDERS_3,
        resolveChain: chain,
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      })
      const relations = new OpenFgaRelationsDriver(relacionesConfig, {
        apiUrl,
        storeId: store.id!,
        modelId,
        holderTypes: HOLDERS_3,
        logger: { warn: () => {} },
      })
      const source = { enumerateEdges: edgesOf, resolveChain: chain }

      /** El otro subsistema escribe EN EL MISMO STORE, por su API real. */
      const documentos: string[] = []
      const grupo = uuidv7()
      async function plantarRelaciones() {
        for (let i = 0; i < 4; i++) {
          const id = uuidv7()
          documentos.push(id)
          await relations.relate({ type: 'users', uuid: uuidv7() }, 'viewer', { type: 'document', id }, org)
        }
        for (let i = 0; i < 2; i++) {
          await relations.relate({ type: 'users', uuid: uuidv7() }, 'reader', { type: 'space', id: uuidv7() }, org)
        }
        // El `group`: el tipo que el generador emite SIEMPRE y que el
        // consumidor no declara. Una tupla con OBJETO `group:` (la
        // pertenencia) y otra con el grupo como SUJETO (el userset que
        // concede a todos sus miembros).
        await relations.relate({ type: 'users', uuid: uuidv7() }, 'member', { type: 'group', id: grupo }, org)
        await relations.relate(
          { object: { type: 'group', id: grupo }, relation: 'member' },
          'viewer',
          { type: 'document', id: documentos[0] },
          org
        )
        return { document: 5, space: 2, group: 1 }
      }

      return { tree, chain, database, fga, relations, client, source, org, ana, legado, plantarRelaciones, grupo, documentos }
    }

    test('B-1 · `--prune` no borra NI UNA tupla ajena, el store queda intacto y `clean` vuelve a ser `true`', async ({
      assert,
    }) => {
      const s = await despliegueCompartido()
      // 1. La migración de los hechos: el store queda a la par del origen.
      await s.fga.reconcile!(s.source, {})
      // 2. El OTRO subsistema escribe en el MISMO store, por la vía real.
      const porTipo = await s.plantarRelaciones()
      const antes = await todoElStore(s.fga)

      // 3. El VERIFICADOR: ni una ajena en `skipped`, y la pasada es LIMPIA.
      const seco = await s.fga.reconcile!(s.source, { dryRun: true })
      assert.equal(seco.foreign?.tuples, 8)
      assert.deepEqual(seco.foreign?.types, porTipo, 'desglosadas por tipo, `group` incluido')
      assert.equal(seco.phases.facts.extra, 0, 'una tupla ajena no es un hecho que sobre')
      assert.isUndefined(seco.skipped['extra-fact'], 'ni entra en `skipped`')
      assert.deepEqual(
        Object.keys(seco.phases).sort(),
        ['catalog', 'facts', 'root', 'tree'],
        '`phases` NO crece: es tipo publicado'
      )
      const secas = reconcileLines(seco)
      assert.isTrue(secas.clean, 'un cutover perfecto sobre un store COMPARTIDO puede estar limpio')
      assert.isTrue(
        secas.lines.some((l) => l.message.includes('COMPARTIDO') && l.message.includes('document')),
        'y el operador se entera de que el store es compartido, con los tipos'
      )

      // 4. La pasada DESTRUCTIVA: cero ajenas borradas y el store idéntico.
      const podada = await s.fga.reconcile!(s.source, { prune: true })
      assert.equal(podada.deleted, 0)
      assert.equal(podada.phases.facts.deleted, 0)
      assert.equal(podada.foreign?.tuples, 8)
      assert.deepEqual(await todoElStore(s.fga), antes, 'el store entero, tupla a tupla')
      assert.isTrue(
        reconcileLines(podada).lines.some((l) => l.message.includes('respetado')),
        'la pasada con --prune lo AFIRMA en vez de callarse'
      )
      // Y lo que de verdad importa: las relaciones siguen concediendo.
      assert.isTrue(
        await s.relations.check(
          { object: { type: 'group', id: s.grupo }, relation: 'member' },
          'viewer',
          { type: 'document', id: s.documentos[0] },
          s.org
        )
      )
    }).timeout(60_000)

    test('B-2 · la prueba DECISIVA: el `deny_binding` de 2.2 y el `role_binding` con id de 1.x SIGUEN borrándose con `--prune`, mientras las ajenas sobreviven', async ({
      assert,
    }) => {
      const s = await despliegueCompartido({ legado: true })
      await s.fga.reconcile!(s.source, {})
      await s.plantarRelaciones()
      // Un binding con el id de 1.x (slug en vez de uuid): el TIPO es PROPIO,
      // el id es de otra versión. Hoy no concede nada (no tiene ni su
      // `role_binding#role` ni su `scope#binding`) y es justo la basura que
      // `authz:reconcile` promete limpiar.
      const bindingViejo = `role_binding:organization|${s.org.uuid}|org-editor`
      await s.client.write({ writes: [{ user: `user:${s.ana.uuid}`, relation: 'assignee', object: bindingViejo }] })

      const antes = await todoElStore(s.fga)
      assert.equal(antes.filter((t) => t.includes('@deny_binding:')).length, 1)
      assert.equal(antes.filter((t) => t.includes(`@${bindingViejo}`)).length, 1)

      const podada = await s.fga.reconcile!(s.source, { prune: true })

      assert.equal(podada.phases.facts.deleted, 2, 'las DOS propias obsoletas, y solo ésas')
      const despues = await todoElStore(s.fga)
      assert.lengthOf(
        despues.filter((t) => t.includes('@deny_binding:') || t.includes(`@${bindingViejo}`)),
        0,
        'la basura de un modelo anterior del PROPIO paquete se sigue barriendo'
      )
      assert.equal(despues.filter((t) => t.includes('@document:')).length, 5, 'las ajenas siguen ahí')
      assert.equal(despues.filter((t) => t.includes('@space:')).length, 2)
      assert.equal(despues.filter((t) => t.includes('@group:')).length, 1)
      assert.equal(
        despues.filter((t) => t.includes('@legacy_thing:')).length,
        1,
        'y un tipo que este paquete NUNCA escribió tampoco se toca'
      )
      assert.deepEqual(podada.foreign?.types, { document: 5, group: 1, legacy_thing: 1, space: 2 })
    }).timeout(60_000)

    test('B-3 · los tipos declarados parten el REPORTE en `relations`/`unknown` y no tocan la decisión de borrar', async ({
      assert,
    }) => {
      const s = await despliegueCompartido({ legado: true })
      await s.fga.reconcile!(s.source, {})
      await s.plantarRelaciones()

      // Sin la config de relaciones —el caso literal de COGNITIV— nadie
      // reclama esas tuplas: todas son `unknown`, y NINGUNA se borra.
      const sinConfig = await s.fga.reconcile!(s.source, { dryRun: true })
      assert.equal(sinConfig.foreign?.tuples, 9)
      assert.equal(sinConfig.foreign?.unknown, 9)
      assert.isUndefined(sinConfig.foreign?.relations, 'sin tipos declarados no se inventa el desglose')

      // Con ellos, el reporte distingue lo ajeno DECLARADO (más `group`, que
      // el generador emite siempre) de lo que no reclama nadie.
      const conConfig = await s.fga.reconcile!(
        { ...s.source, relationTypes: ['document', 'space'] },
        { dryRun: true }
      )
      assert.equal(conConfig.foreign?.tuples, 9)
      assert.equal(conConfig.foreign?.relations, 8)
      assert.equal(conConfig.foreign?.unknown, 1)
      const lineas = reconcileLines(conConfig)
      assert.isTrue(lineas.lines.some((l) => l.level === 'warning' && l.message.includes('nadie')))
      // Lo ajeno NO es deriva —ni siquiera lo desconocido—: la única que
      // queda es la tupla PROPIA obsoleta del store de 2.2, que es justo la
      // que `--prune` sí se lleva.
      assert.equal(conConfig.skipped['extra-fact'], 1, 'una sola: el `deny_binding` de 2.2, no las 9 ajenas')
      assert.isFalse(lineas.clean, 'y la deriva es ESA, no el store compartido')

      // Y la decisión de BORRAR no los mira: con la lista o sin ella, cero.
      const podada = await s.fga.reconcile!({ ...s.source, relationTypes: ['document', 'space'] }, { prune: true })
      assert.equal(podada.foreign?.tuples, 9)
      assert.equal(
        (await todoElStore(s.fga)).filter((t) => t.includes('@document:') || t.includes('@legacy_thing:')).length,
        6
      )
    }).timeout(60_000)
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

  test('3b-6 · `--dry-run` NO congela: el verificador read-only no puede parar las escrituras del proceso', async ({
    assert,
  }) => {
    // Panel 3 · juez §3: `--dry-run` está publicado como «the verifier, and it
    // is read-only by contract… Run it in CI or in a cron», y una pasada que
    // no escribe NADA no tiene nada que proteger. Congelar ahí compra cero y
    // paga un mecanismo de indisponibilidad de escrituras disparado por un
    // cron —hoy del proceso, y un outage de flota el día que el freeze sea
    // durable—. Mutante que muere: `withFrozenWrites` incondicional.
    const org = orgScope()
    const users = () => ({ type: 'users', uuid: uuidv7() })
    let congelado: Array<boolean | null> = []
    let resultado: any[] = []
    const target = targetDriver(async () => {
      congelado.push(manager.frozen)
      try {
        await manager.grant(users(), 'org-editor', org)
        resultado.push('entró')
      } catch (error: any) {
        resultado.push(error)
      }
    })
    const { manager, tree } = managerWith({}, target)
    await tree.attach(org, APP_SCOPE)

    await manager.reconcile({ to: 'destino', dryRun: true })
    await manager.reconcile({ to: 'destino' })

    assert.isFalse(congelado[0], 'con --dry-run el motor NO puede quedar congelado')
    assert.equal(resultado[0], 'entró', 'un grant concurrente durante el verificador tiene que ENTRAR')
    assert.isTrue(congelado[1], 'la pasada que SÍ escribe sigue congelando')
    assert.equal(resultado[1]?.code, 'E_AUTHZ_FROZEN')
    assert.equal(resultado[1]?.status, 503)
    assert.isFalse(manager.frozen)
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

  /**
   * **alpha.9 · B · S4** — los tipos de objeto de `relations.config` viajan al
   * destino para PARTIR el reporte (ajeno declarado vs. lo que no reclama
   * nadie), jamás para decidir un borrado: esa decisión es la lista blanca
   * congelada del driver y no lee nada en runtime (decisión del dueño del
   * 2026-09-11 (2), punto 2 — el caso de COGNITIV es justo el proceso que
   * corre el reconcile SIN esa config).
   */
  test('alpha.9 · B · los tipos de `relations.config` llegan al destino SOLO para el reporte (`source.relationTypes`)', async ({
    assert,
  }) => {
    const target = targetDriver()
    const tree = memoryScopeTree()
    const relaciones = defineRelationsConfig({
      objectTypes: [
        { type: 'document', relations: [{ name: 'viewer' }] },
        { type: 'space', relations: [{ name: 'reader' }] },
      ],
      holderTypes: ['user'],
    })
    const manager = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => spyDriver(), destino: () => target.driver },
      holderTypes: HOLDERS,
      scopes: { resolveChain: resolveChainFrom(tree), enumerateEdges: edgesOfDemoScopes() },
      relations: { config: relaciones },
      warnOnOptInSecurity: false,
    } as any)

    await manager.reconcile({ to: 'destino', dryRun: true })
    assert.deepEqual(target.seen[0].source.relationTypes, ['document', 'space'])

    // Sin `relations.config` no se inventa ninguna lista: el reporte no puede
    // fingir que sabe de quién es lo ajeno.
    const sin = targetDriver()
    const { manager: otro } = managerWith({}, sin)
    await otro.reconcile({ to: 'destino', dryRun: true })
    assert.isUndefined(sin.seen[0].source.relationTypes)
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * 3b-7 · El freeze de la PASADA: dueño, contexto del operador y fence.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('3b-7 · reconcile y el freeze durable', (group) => {
  group.each.setup(async () => {
    await cleanSqlScopeTree(db)
    const reset = async () => {
      try {
        await db
          .from('authz_catalog_version')
          .where('id', 2)
          .update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null })
      } catch {}
    }
    await reset()
    return async () => {
      await reset()
      await cleanSqlScopeTree(db)
    }
  })

  function managerWith(extra: any = {}, target = targetDriver(), clock?: () => Date) {
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
      ...(clock ? { clock } : {}),
    })
    return { manager, tree, target }
  }

  test('la pasada que escribe publica su garantía: report.frozen = { durable, lapsed: false, leaseMs, fence }', async ({
    assert,
  }) => {
    const { manager } = managerWith()
    const report = await manager.reconcile({ to: 'destino' })
    assert.isTrue(report.frozen?.durable, 'el freeze de la pasada es durable (la fila)')
    assert.isFalse(report.frozen?.lapsed, 'el lease no se perdió: la pasada se certifica')
    assert.equal(report.frozen?.leaseMs, 15_000, 'el lease por defecto, publicado')
    assert.isNumber(report.frozen?.fence)
    // Y el verificador NO congela, así que tampoco declara ventana.
    const dry = await manager.reconcile({ to: 'destino', dryRun: true })
    assert.isUndefined(dry.frozen, '--dry-run no congela: no hay garantía que publicar')
  })

  test('reconcile DENTRO de una ventana congelada corre dentro y NO la levanta al terminar (auditor A1.3)', async ({
    assert,
  }) => {
    const { manager } = managerWith()
    const otro = managerWith() // otro worker de la flota, mismo backend
    const subject = { type: 'users', uuid: uuidv7() }

    const token = await manager.freeze('ventana del operador de este proceso', { leaseMs: null })
    const report = await manager.reconcile({ to: 'destino' })
    assert.equal(report.frozen?.fence, token.fence, 'la pasada corre dentro de la ventana exterior')

    // La ventana exterior SIGUE en pie tras la pasada: eso es lo que A1.3 rompía.
    await rejects(assert, () => otro.manager.grant(subject, 'org-editor', APP_SCOPE), 'E_AUTHZ_FROZEN', 503)
    await manager.unfreeze(token)
    await otro.manager.grant(subject, 'org-editor', APP_SCOPE)
  })

  test('dos reconcile simultáneos NO se pisan: el segundo es 423 E_AUTHZ_FREEZE_HELD', async ({ assert }) => {
    let release!: () => void
    const gate = new Promise<void>((resolve) => (release = resolve))
    const primero = managerWith({}, targetDriver(() => gate))
    const segundo = managerWith()

    const enCurso = primero.manager.reconcile({ to: 'destino' })
    // Espera ACOTADA a que el primero haya tomado su freeze (su target ya fue
    // llamado): si no llega, el propio `enCurso` cuenta por qué — un bucle
    // sin cota convertiría una regresión en un cuelgue de la suite.
    for (let i = 0; primero.target.seen.length === 0 && i < 400; i++) await new Promise((r) => setTimeout(r, 5))
    if (primero.target.seen.length === 0) {
      release()
      await enCurso // lanza el motivo real
      throw new Error('la primera pasada nunca llegó a su target')
    }

    const error = await rejects(assert, () => segundo.manager.reconcile({ to: 'destino' }), 'E_AUTHZ_FREEZE_HELD', 423)
    assert.include(error.message, 'authz:reconcile --to=destino', 'el 423 nombra la pasada viva')

    release()
    await enCurso
    // Con la primera terminada, la segunda ya puede correr.
    const report = await segundo.manager.reconcile({ to: 'destino' })
    assert.isFalse(report.frozen?.lapsed)
  })

  test('el cutover (F6): reconcile reconoce el freeze de OPERADOR como contexto propio y no lo toca', async ({
    assert,
  }) => {
    const operador = managerWith() // el proceso del comando authz:freeze
    const migrador = managerWith() // el proceso de authz:reconcile
    const subject = { type: 'users', uuid: uuidv7() }

    const token = await operador.manager.freeze('cutover a openfga', { leaseMs: null, kind: 'operator' })

    const report = await migrador.manager.reconcile({ to: 'destino' })
    assert.equal(report.frozen?.fence, token.fence, 'la pasada corrió dentro de la ventana del operador')
    assert.isNull(report.frozen?.leaseMs, 'sin renovación: la ventana es del operador')
    assert.isFalse(report.frozen?.lapsed, 'la ventana siguió viva de punta a punta')

    // Y la ventana del operador SIGUE en pie: el intervalo pasada→cutover es suyo.
    await rejects(assert, () => migrador.manager.grant(subject, 'org-editor', APP_SCOPE), 'E_AUTHZ_FROZEN', 503)
    await operador.manager.unfreeze(token)
  })

  test('alpha.10 · 3 · la ventana del operador ADOPTADA con `--lease-ms` se reporta con su caducidad: `untilMs` real y `leaseMs` no null; la salida dice cuándo caduca', async ({
    assert,
  }) => {
    let wall = Date.parse('2030-06-15T12:00:00.000Z')
    const clock = () => new Date(wall)
    const operador = managerWith({}, targetDriver(), clock)
    const migrador = managerWith({}, targetDriver(), clock)

    const token = await operador.manager.freeze('cutover con lease', { leaseMs: 60_000, kind: 'operator' })
    try {
      wall += 10_000 // la pasada arranca 10 s después de abrir la ventana
      const report = await migrador.manager.reconcile({ to: 'destino' })
      assert.equal(report.frozen?.fence, token.fence, 'corrió dentro de la ventana del operador')
      assert.equal(report.frozen?.untilMs, Date.parse('2030-06-15T12:01:00.000Z'), 'el instante de caducidad de la fila')
      assert.equal(report.frozen?.leaseMs, 50_000, 'lo que le QUEDABA a la ventana al adoptarla — nunca null si caduca')
      assert.isFalse(report.frozen?.lapsed)

      const texto = reconcileLines(report).lines.map((l) => l.message).join('\n')
      assert.include(texto, '2030-06-15T12:01:00.000Z', 'la salida dice que la ventana adoptada caduca, y cuándo')
      assert.notInclude(texto, 'sin caducidad')
    } finally {
      await operador.manager.unfreeze(token)
    }

    // Y la ventana SIN caducidad sigue reportándose con `leaseMs: null` y `untilMs: null`.
    const sinLease = await operador.manager.freeze('cutover', { leaseMs: null, kind: 'operator' })
    try {
      const report = await migrador.manager.reconcile({ to: 'destino' })
      assert.isNull(report.frozen?.leaseMs)
      assert.isNull(report.frozen?.untilMs)
      assert.include(reconcileLines(report).lines.map((l) => l.message).join('\n'), 'sin caducidad')
    } finally {
      await operador.manager.unfreeze(sinLease)
    }
  })

  test('si el operador levanta su ventana A MITAD de la pasada, la pasada lo dice: lapsed=true (fence)', async ({
    assert,
  }) => {
    const operador = managerWith()
    let token: any = null
    const migrador = managerWith(
      {},
      targetDriver(async () => {
        // El operador se impacienta y descongela con la pasada en marcha:
        // desde ese instante los workers pueden escribir.
        await operador.manager.unfreeze(token)
      })
    )

    token = await operador.manager.freeze('cutover', { leaseMs: null, kind: 'operator' })
    const report = await migrador.manager.reconcile({ to: 'destino' })
    assert.isTrue(report.frozen?.lapsed, 'la garantía se DEMUESTRA: la ventana no aguantó la pasada entera')
  })

  test('el lease que caduca A MITAD de la pasada sale publicado: lapsed=true y el comando no certifica (juez C4)', async ({
    assert,
  }) => {
    // Reloj de pared inyectado y compartido: la pasada «tarda» más que el
    // lease sin renovación posible (el renovador va por setInterval real, que
    // aquí no llega a disparar) — el mismo efecto que el bucle de eventos
    // bloqueado del analista (m11), sin sleep.
    let wall = Date.parse('2030-06-15T12:00:00.000Z')
    const clock = () => new Date(wall)
    const { manager } = managerWith(
      {},
      targetDriver(async () => {
        wall += DEFAULT_FREEZE_LEASE_MS_TEST + 60_000 // el lease venció hace rato
      }),
      clock
    )

    const report = await manager.reconcile({ to: 'destino' })
    assert.isTrue(report.frozen?.lapsed, 'el fence caza el lease perdido')

    const { clean, lines } = reconcileLines(report)
    assert.isFalse(clean, 'lapsed=true ⇒ la pasada NO se certifica (exit ≠ 0)')
    assert.isTrue(
      lines.some((l) => l.level === 'error' && /lease/i.test(l.message)),
      'y el reporte lo dice con su nombre'
    )
  })
})

const DEFAULT_FREEZE_LEASE_MS_TEST = 15_000

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

  // alpha.10 · 4 (🟠 1 del sexto informe de COGNITIV, MEDIDO: «no escribe ni
  // borra un solo hecho» seguido de «sobran 3, borradas 3»). Lo publicado se
  // cumple o se reescribe: la letra del comando y del README dice qué borra
  // de verdad la pasada de mantenimiento con --prune.
  // alpha.10 · S3 (auditoría de sistema): el runbook del cutover omitía
  // `relations/`, que cambia de driver con `config.default` si no hay
  // `relations.default` — y `relations.default` no aparecía en el README.
  test('alpha.10 · S3 · letra: el runbook del cutover incluye `authz:relations:reconcile` por partición y dice qué clave manda (`relations.default ?? config.default`), igual que el provider', async ({
    assert,
  }) => {
    const { readFile } = await import('node:fs/promises')
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    const inicio = readme.indexOf('### The cutover window: `authz:freeze` / `authz:unfreeze`')
    assert.isAbove(inicio, 0)
    const fin = readme.indexOf('\n### ', inicio + 10)
    const seccion = readme.slice(inicio, fin === -1 ? undefined : fin)
    const bloque = seccion.slice(seccion.indexOf('```bash'), seccion.indexOf('```', seccion.indexOf('```bash') + 7))
    assert.include(bloque, 'authz:relations:reconcile --to=openfga', 'el paso de relaciones está DENTRO del runbook')
    assert.isBelow(bloque.indexOf('authz:relations:reconcile'), bloque.indexOf('authz:unfreeze'), 'y antes de cerrar la ventana')
    assert.include(bloque, 'relations.default')
    assert.include(seccion, '`relations.default ?? config.default`')
    assert.include(seccion, 'one partition per pass')
    // Y la clave que el README nombra es la que resuelve el código (un solo sitio).
    const { activeRelationsDriverKey } = await import('../src/define_config.js')
    assert.equal(activeRelationsDriverKey({ default: 'database' } as any), 'database')
    assert.equal(activeRelationsDriverKey({ default: 'database', relations: { default: 'openfga' } } as any), 'openfga')
    const provider = await readFile(new URL('../providers/authz_provider.ts', import.meta.url), 'utf8')
    assert.include(provider, 'activeRelationsDriverKey(config)', 'el provider usa la MISMA función que el guard')
  })

  // Cierre del auditor de alpha.10 · decisión (6) (pregunta 2 del auditor) + ⚪ 1 + R5: SIN excepción para la ventana
  // viva, así que el runbook verifica ANTES del switch (y tras él, solo el mantenimiento sin --from); la receta del
  // store viejo nombra el guard y su salida humana; y los dos puertos declaran que el guard lee el config del PROCESO.
  test('cierre · letra: el runbook verifica con `--from … --dry-run` ANTES del switch y tras él solo sin --from; nunca `--allow-stale-source`; la receta del store viejo y el límite del config del proceso, escritos', async ({
    assert,
  }) => {
    const { readFile } = await import('node:fs/promises')
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    const inicio = readme.indexOf('### The cutover window: `authz:freeze` / `authz:unfreeze`')
    const seccion = readme.slice(inicio, readme.indexOf('\n### ', inicio + 10))
    const bloque = seccion.slice(seccion.indexOf('```bash'), seccion.indexOf('```', seccion.indexOf('```bash') + 7))
    const lineas = bloque.split('\n')
    const switchAt = lineas.findIndex((l) => l.includes('switch config.default'))
    assert.isAbove(switchAt, 0, 'el switch está en el bloque')
    const conFromDry = lineas.map((l, i) => [l, i] as const).filter(([l]) => l.includes('--from=') && l.includes('--dry-run'))
    assert.lengthOf(conFromDry, 2, 'verificación de roles Y de relaciones con --from')
    for (const [l, i] of conFromDry) assert.isBelow(i, switchAt, `verifica ANTES del switch: ${l}`)
    for (const l of lineas.slice(switchAt + 1)) assert.notInclude(l, '--from=', `tras el switch nada con --from (sería la dirección rancia): ${l}`)
    assert.include(lineas.slice(switchAt + 1).join('\n'), 'authz:reconcile --to=openfga --dry-run', 'tras el switch, el verificador de mantenimiento')
    assert.notInclude(bloque, '--allow-stale-source', 'el runbook no normaliza la salida humana')
    assert.include(seccion, 'no exception for a live window')

    const receta = readme.slice(readme.indexOf('**The way out of a store written by the previous version.**'))
    const parrafo = receta.slice(0, receta.indexOf('\n\n'))
    assert.include(parrafo, '`E_AUTHZ_STALE_SOURCE_REFUSED`', 'la receta avisa de que con openfga activo se niega')
    assert.include(parrafo, '`--allow-stale-source`')
    assert.include(parrafo, 'still `config.default`')

    assert.include(readme, 'only as reliable as the `config.default` of the process that runs the command', 'R5 roles')
    assert.include(readme, 'The guard reads the config of the process that runs it', 'R5 relaciones')
    const changelog = await readFile(new URL('../CHANGELOG.md', import.meta.url), 'utf8')
    const unreleased = changelog.slice(0, changelog.indexOf('## [2.4.0-alpha.9]'))
    assert.include(unreleased, 'config of the process that runs')
  })

  // Cierre-2 · C1/C6/C7 (letra): los límites declarados y la superficie, escritos donde se leen.
  test('cierre-2 · letra: C1 identidad = referencia de la factory (dos factories sobre el mismo backend NO se detectan) en README ×2, CHANGELOG, CLAUDE.md y roadmap 2.5; C6 los dos métodos del manager junto a `driver()` y el manager falso; C7 raíz sin `RelationsReconcileOptions` y la lista de `/openfga` = exports reales', async ({
    assert,
  }) => {
    const { readFile } = await import('node:fs/promises')
    const read = (path: string) => readFile(new URL(`../${path}`, import.meta.url), 'utf8')
    const [readme, changelog, claude, roadmap, index, openfga] = await Promise.all([
      read('README.md'),
      read('CHANGELOG.md'),
      read('CLAUDE.md'),
      read('.claude/contexto/roadmap-2.0.md').catch(() => null),
      read('index.ts'),
      read('src/openfga.ts'),
    ])
    // C1: relaciones y roles, en el README.
    assert.include(readme, '**Declared limit: identity is the factory reference, not the\nbackend.**', 'C1 relaciones')
    assert.include(readme, 'Two *different* factories that build the same store')
    assert.include(readme, '(**declared limit**: identity is the factory *reference*, so two different factories that build the same backend are not detected', 'C1 roles')
    const unreleased = changelog.slice(0, changelog.indexOf('## [2.4.0-alpha.9]'))
    assert.include(unreleased, 'the stale-direction guard compares factory REFERENCES, not backends', 'C1 CHANGELOG')
    assert.include(claude, 'dos factories DISTINTAS sobre el mismo backend NO se detectan', 'C1 CLAUDE.md, junto a R5')
    if (roadmap !== null) assert.include(roadmap, 'Identidad de backend declarada por el driver', 'C1 roadmap 2.5 (fuera de git: solo si existe)')
    // C6.
    const driverParagraph = readme.slice(readme.indexOf('**`manager.driver()` is the documented way out of all of that.**'))
    const parrafo = driverParagraph.slice(0, driverParagraph.indexOf('\n\n'))
    assert.include(parrafo, '`relationsDriverFactory`')
    assert.include(parrafo, '`relationsDriverKeys`')
    assert.include(parrafo, 'fakes `relationsDriverKey` or `relationsDriverFactory` decides which driver is active')
    // C7.2: la raíz no exporta la forma del primitivo; la pública vive junto a la función.
    assert.notMatch(index, /export\s+type\s*\{[^}]*\bRelationsReconcileOptions\b/, 'C7.2: la raíz no exporta RelationsReconcileOptions')
    const cmd = await read('commands/authz_relations_reconcile.ts')
    assert.match(cmd, /export type RunRelationsReconcileOptions\b/)
    assert.match(cmd, /options: RunRelationsReconcileOptions\b/, 'la firma pública usa el tipo exportado')
    // C7.3: cada nombre que el README lista para `/openfga` es un export real de `src/openfga.ts`.
    const lista = /\*\*`@jantstack\/adonis-authz\/openfga` subpath\*\* \(([^)]*)\)/.exec(readme)?.[1]
    assert.isString(lista, 'la frase del subpath sigue ahí')
    const nombres = [...lista!.matchAll(/`([A-Za-z0-9_]+)`/g)].map((m) => m[1])
    assert.isAtLeast(nombres.length, 3)
    for (const nombre of nombres) assert.match(openfga, new RegExp(`\\b${nombre}\\b`), `README lista '${nombre}' en /openfga y no se exporta`)
    assert.notInclude(lista!, 'importAuthzFactsToOpenFga')
    assert.notInclude(lista!, 'openFgaAuthorizationModel')
  })

  test('alpha.10 · 4 · letra: la pasada de mantenimiento NO dice «no borra»; dice qué borra con --prune (comando y README)', async ({
    assert,
  }) => {
    const { readFile } = await import('node:fs/promises')
    for (const prune of [false, true]) {
      const line = reconcileLines(base({ to: 'openfga', factsFrom: 'openfga', prune } as any)).lines[0].message
      assert.notInclude(line, 'ni borra', `la frase falsa está FUERA (prune=${prune})`)
      assert.include(line, 'no escribe hechos')
      assert.include(line, 'con --prune borra los de scopes que ya no resuelven')
      assert.include(line, 'los caducados')
      assert.include(line, 'los que sobran')
    }
    const fuente = await readFile(new URL('../commands/authz_reconcile.ts', import.meta.url), 'utf8')
    assert.notInclude(fuente, 'ni borra un solo hecho')
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.notInclude(readme, 'writes and deletes no fact at all', 'la frase falsa del README está FUERA')
    assert.include(readme, 'it writes no fact; with `--prune` it deletes the facts of scopes that no longer resolve')
  })

  test('sin --prune, los hechos de un scope muerto llevan la receta al lado', ({ assert }) => {
    const { lines } = reconcileLines(base({ skipped: { 'unknown-scope': 3 } }))
    assert.isTrue(lines.some((l) => l.message.includes('--prune')))
    const conPrune = reconcileLines(base({ prune: true, skipped: { 'unknown-scope': 3 } }))
    assert.isFalse(conPrune.lines.some((l) => l.message.includes('repite con --prune')))
  })

  /**
   * **3b-8 · B2 — `expired` no clava el exit 1 para siempre.** Las dos
   * direcciones cuentan las asignaciones ya caducadas en `skipped['expired']`
   * y NADA barre las filas caducadas del origen (a propósito: expiración
   * observable sin scheduler, invariante 3). Con `clean` exigiendo `skipped`
   * vacío, a la primera caducidad real el verificador de CI que el CHANGELOG
   * promete verde salía 1 PARA SIEMPRE — dry-run incluido. `expired` es la
   * pérdida DECLARADA de la migración (la lista declarada del paquete es UNA):
   * se sigue contando en las líneas, pero no es deriva.
   */
  test('3b-8 · B2: `expired` se REPORTA pero no tumba la pasada; cualquier otro motivo de skipped sí', ({
    assert,
  }) => {
    const soloCaducadas = reconcileLines(base({ dryRun: true, skipped: { expired: 3 } }))
    assert.isTrue(
      soloCaducadas.clean,
      'la pérdida DECLARADA no puede dejar el verificador en rojo para siempre (3b-8 · B2)'
    )
    assert.isTrue(
      soloCaducadas.lines.some((l) => l.message.includes("3 sin migrar por 'expired'")),
      'pero se sigue diciendo: nunca silenciosa'
    )
    // Mezclada con deriva de verdad, la deriva manda.
    assert.isFalse(reconcileLines(base({ skipped: { 'expired': 1, 'unknown-role': 1 } })).clean)
    // Y las caducadas que SOBRAN en el destino siguen siendo deriva
    // (`extra-fact` las cuenta): su barrido es `--prune`, no una exención.
    assert.isFalse(reconcileLines(base({ skipped: { 'extra-fact': 1 } })).clean)
  })

  /**
   * **alpha.9 · B · S3** — lo AJENO de un store compartido se cuenta en un
   * campo PROPIO: fuera de `skipped` (si no, `clean` sería falso para siempre
   * en cualquier despliegue con relaciones: el corolario del 🔴 3) y fuera de
   * `details` (tope 200: miles de ajenas expulsarían los `extra-fact` reales,
   * que son los que conceden).
   */
  test('alpha.9 · B · lo AJENO se cuenta aparte, se imprime por tipo y NUNCA tumba la pasada', ({ assert }) => {
    const ajenas = reconcileLines(
      base({ dryRun: true, foreign: { tuples: 60, types: { document: 40, group: 10, space: 10 } } })
    )
    assert.isTrue(ajenas.clean, 'fuera de `skipped` A PROPÓSITO: ahí dentro el exit 1 quedaba clavado')
    const compartido = ajenas.lines.find((l) => l.message.includes('COMPARTIDO'))
    assert.isDefined(compartido)
    assert.notEqual(compartido!.level, 'error', 'el dueño de esas tuplas es otro subsistema, no una deriva nuestra')
    assert.include(compartido!.message, 'document (40)')
    assert.include(compartido!.message, 'group (10)')

    // Con `--prune` la pasada AFIRMA lo que respetó: el verde MUDO de alpha.8
    // era la mitad del defecto (borraba y decía `clean = true`).
    const podada = reconcileLines(base({ prune: true, foreign: { tuples: 60, types: { document: 60 } } }))
    assert.isTrue(podada.lines.some((l) => l.message.includes('--prune') && l.message.includes('60')))

    // `unknown` solo se AVISA cuando se sabe partir (hay tipos declarados):
    // sin ellos, «desconocida» no significa nada.
    const desconocidas = reconcileLines(
      base({ foreign: { tuples: 3, types: { legacy_thing: 3 }, relations: 0, unknown: 3 } })
    )
    assert.isTrue(desconocidas.clean)
    assert.isTrue(desconocidas.lines.some((l) => l.level === 'warning' && l.message.includes('nadie')))
    assert.isFalse(
      reconcileLines(base({ foreign: { tuples: 3, types: { legacy_thing: 3 } } })).lines.some((l) =>
        l.message.includes('nadie')
      )
    )

    // Y sin ajenas, ni una línea: el store no compartido no cambia de salida.
    assert.isFalse(reconcileLines(base()).lines.some((l) => l.message.includes('COMPARTIDO')))
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

    /**
     * **3b-8 · A2 — los denies del modo `resolver` de 2.2 se MIGRAN, no se
     * tiran en silencio.** `reconcile` es el sustituto documentado del
     * importador borrado en 3b-2k, y un store de aquella versión guarda los
     * denies en objetos `deny_binding:<scopeKey>|<permissionUuid>` con la
     * relación `denied` — un formato que el modelo (c2r) ni declara.
     * `enumerateFacts` los descartaba con el resto de la «estructura»: la
     * migración perdía los denies explícitos con el verificador en VERDE
     * (invariante 2 roto sin una línea en ningún contador).
     */
    test('3b-8 · A2: un deny del formato 2.2 (`deny_binding#denied`) LLEGA a authz_denies al migrar --to=database', async ({
      assert,
    }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const tree = sqlScopeTree(db)
      const chain = resolveChainFrom(tree)
      await syncAuthzCatalog(CATALOG)
      const org = { type: 'organization', uuid: uuidv7() }
      await tree.attach(org, APP_SCOPE)
      const orgKey = `organization|${org.uuid}`
      const rol = await db.from('authz_roles').where('slug', 'org-editor').first()
      const permiso = await db.from('authz_permissions').where('slug', 'docs:write').first()

      // 1. El store, con el modelo VIEJO y sus tuplas (asignación + deny).
      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `a2-legacy-${Date.now()}` })
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
      const ana = { type: 'users', uuid: uuidv7() }
      const bea = { type: 'users', uuid: uuidv7() }
      await client.write(
        {
          writes: [
            { user: `user:${ana.uuid}`, relation: 'assignee', object: `role_binding:${orgKey}|${rol.uuid}` },
            { user: `user:${bea.uuid}`, relation: 'denied', object: `deny_binding:${orgKey}|${permiso.uuid}` },
          ],
        },
        { authorizationModelId: viejo.authorization_model_id }
      )

      // 2. El modelo de hoy sobre el mismo store, y la migración de vuelta.
      const nuevo = await client.writeAuthorizationModel(openFgaFactsModel(HOLDERS_3, PERMISSIONS))
      const fga = new OpenFgaAuthorizationDriver({
        apiUrl,
        storeId: store.id!,
        modelId: nuevo.authorization_model_id!,
        holderTypes: HOLDERS_3,
        resolveChain: chain,
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      })
      const database = new DatabaseAuthorizationDriver({ resolveChain: chain })
      const source = {
        enumerateEdges: edgesOfDemoScopes(),
        resolveChain: chain,
        facts: (page: any) => fga.enumerateFacts!(page),
      }
      const report = await database.reconcile!(source, {})

      assert.deepEqual(
        await database.listDenies(bea, org),
        [{ permission: 'docs:write', scope: org }],
        'el deny explícito de 2.2 tiene que MIGRAR: perderlo con el verificador en verde es el fail-open del hallazgo A2'
      )
      assert.isTrue(await database.hasRole(ana, 'org-editor', org), 'y la asignación de 2.2 también')
      assert.equal(report.written, 2, 'las dos filas: la asignación y el deny')

      // Y un deny viejo de un permiso que el catálogo YA NO declara no se
      // migra, pero tampoco se calla: sale contado.
      const fantasmaStore = await client.write(
        {
          writes: [
            { user: `user:${bea.uuid}`, relation: 'denied', object: `deny_binding:${orgKey}|${uuidv7()}` },
          ],
        },
        { authorizationModelId: viejo.authorization_model_id }
      )
      void fantasmaStore
      const segunda = await database.reconcile!(source, {})
      assert.isAtLeast(segunda.skipped['unknown-permission'] ?? 0, 1, 'lo que no se entiende va CONTADO, jamás mudo')
    }).timeout(60_000)

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

    /**
     * **3b-8 · B1 (espejo)** — el mismo seguro, en la vuelta: un store cuyos
     * hechos se descartan TODOS (`unknown-scope`) no desarma el seguro por
     * el conteo crudo. Sin esto, `--prune` vaciaba
     * `authz_assignments`/`authz_denies` con el reporte en verde.
     */
    test('3b-8 · B1: --prune con un STORE cuyos hechos se descartan todos también se niega', async ({
      assert,
    }) => {
      const { database, source, tree, org } = await inverseSetup()
      await database.reconcile!(source, {})
      assert.isAtLeast((await db.from('authz_assignments').select('uuid')).length, 1, 'precondición: la base quedó poblada')
      // El árbol del consumidor deja de resolver los scopes del store: cada
      // hecho del origen LLEGA (conteo crudo > 0) y se descarta.
      await tree.detach(org)

      const error = await rejects(
        assert,
        () => database.reconcile!(source, { prune: true }),
        'E_AUTHZ_MASS_RECONCILE_REFUSED',
        500
      )
      assert.include(error.message, 'utilizable')
      assert.isAtLeast((await db.from('authz_assignments').select('uuid')).length, 1, 'no ha borrado nada antes de negarse')

      const seco = await database.reconcile!(source, { dryRun: true, prune: true })
      assert.isTrue(seco.massDelete, 'el --dry-run lo marca, no lanza')
      assert.isAtLeast(seco.skipped['unknown-scope'] ?? 0, 1)
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

      // alpha.10 · 1, fila 8 de la tabla contra el store REAL: tras el cambio de
      // `default` a `database`, repetir `--to=database` SIN --from (el origen,
      // `openfga`, se elige por descarte y quedó congelado en la vuelta) es la
      // dirección rancia y se niega sin tocar `authz_*`.
      const despues = new AuthorizationManager({
        default: 'database',
        drivers: { openfga: () => fga, database: () => database },
        holderTypes: HOLDERS_3,
        scopes: { resolveChain: source.resolveChain, enumerateEdges: edgesOfDemoScopes() },
        warnOnOptInSecurity: false,
      })
      const filas = (await db.from('authz_assignments').select('uuid')).length
      await rejects(assert, () => despues.reconcile({ to: 'database', prune: true }), 'E_AUTHZ_STALE_SOURCE_REFUSED', 500)
      assert.lengthOf(await db.from('authz_assignments').select('uuid'), filas, 'authz_* intactas')
      const seco = await despues.reconcile({ to: 'database', dryRun: true })
      assert.deepEqual(seco.staleSource, { to: 'database', from: 'openfga', allowed: false }, 'el origen RESUELTO por descarte')
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

/* ════════════════════════════════════════════════════════════════════════
 * **2.4.0-alpha.10 · 1 — la DIRECCIÓN RANCIA** (🔴 4 del sexto informe de
 * COGNITIV; decisión del 2026-09-13 (4)).
 *
 * Con `openfga` sirviendo, `--to=openfga --from=database` leía `authz_*` —
 * congeladas desde el cutover— y re-escribía en el store VIVO los roles
 * revocados después, con o sin `--prune`; el seguro de borrado masivo no salta
 * porque el origen no está vacío. La regla 3b-5 «con `--from` manda el
 * operador» tiene una excepción: HACIA EL DRIVER ACTIVO no. Lo decide el
 * MANAGER (la API es la puerta, no el comando): `to === config.default` y
 * `from !== to` ⇒ 500 `E_AUTHZ_STALE_SOURCE_REFUSED` antes de construir,
 * leer o congelar nada, salvo `allowStaleSource`; `dryRun` no lanza y lo
 * marca (`report.staleSource`, precedente `massPurge`).
 * ════════════════════════════════════════════════════════════════════════ */

test.group('alpha.10 · 1 · la dirección rancia: `--to=<activo> --from=<otro>`', (group) => {
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
    return async () => {
      await cleanScopeOutbox(db)
    }
  })

  /** Un ORIGEN que apunta si se construyó y si se le leyó algo. */
  function origen() {
    const state = { built: 0, asked: 0 }
    const hecho = {
      kind: 'assignment',
      holder: { type: 'users', uuid: uuidv7() },
      scope: { type: 'organization', uuid: uuidv7() },
      roleUuid: uuidv7(),
      expiresAt: null,
      detail: 'el rol REVOCADO tras el cutover, que authz_* todavía tiene',
    }
    const factory = () => {
      state.built += 1
      return {
        ...spyDriver(),
        async enumerateFacts() {
          state.asked += 1
          return { facts: [hecho] }
        },
      }
    }
    return { state, factory }
  }

  /** Un DESTINO que escribe en su store lo que el origen le da (salvo en --dry-run). */
  function destino() {
    const store = new Set<string>()
    const state = { built: 0, calls: 0 }
    const driver: any = {
      ...spyDriver(),
      async reconcile(source: any, options: any) {
        state.calls += 1
        const page = await source.facts({ limit: 100 })
        if (options.dryRun !== true) for (const f of page.facts) store.add(f.detail)
        return {
          to: 'activo',
          dryRun: options.dryRun === true,
          prune: options.prune === true,
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
    }
    const factory = () => {
      state.built += 1
      return driver
    }
    return { store, state, factory }
  }

  function managerWith(defaultKey: string, drivers: Record<string, () => any>) {
    const tree = memoryScopeTree()
    return new AuthorizationManager({
      default: defaultKey,
      drivers,
      holderTypes: HOLDERS,
      scopes: { resolveChain: resolveChainFrom(tree), enumerateEdges: edgesOfDemoScopes() },
      warnOnOptInSecurity: false,
    } as any)
  }

  test('🔴 por la API: `to` es el driver ACTIVO y `from` otro ⇒ 500 E_AUTHZ_STALE_SOURCE_REFUSED sin construir, leer, congelar ni escribir nada', async ({
    assert,
  }) => {
    const viejo = origen()
    const activo = destino()
    const manager = managerWith('activo', { activo: activo.factory, viejo: viejo.factory })

    const error = await rejects(
      assert,
      () => manager.reconcile({ to: 'activo', from: 'viejo', prune: true }),
      'E_AUTHZ_STALE_SOURCE_REFUSED',
      500
    )

    assert.equal(viejo.state.asked, 0, 'el origen rancio no se lee')
    assert.equal(viejo.state.built, 0, 'ni se construye')
    assert.equal(activo.state.calls, 0, 'el destino no llega a reconciliar')
    assert.equal(activo.store.size, 0, 'y no se re-escribe ningún hecho revocado')
    assert.isNull(await manager.freezeStatus(), 'ni se congela la flota para negarse')
    // La letra: la dirección, el riesgo y la salida correcta.
    assert.include(error.message, '--to=activo --from=viejo')
    assert.include(error.message, 'resucitaría las revocaciones hechas desde el cutover')
    assert.include(error.message, 'sin --from')
    assert.include(error.message, '--allow-stale-source')
  })

  // Cierre del auditor de alpha.10 · ⚪ 8: con UN solo driver registrado, `--to=<activo>` sin `--from` sigue
  // negándose, pero la letra no puede hablar de un origen «por descarte» que no existe.
  test('cierre · ⚪ 8 · un solo driver (`default: database`, solo `database`): se niega igual y la letra dice que NO hay otro driver, no «POR DESCARTE»; con dos, sí lo nombra', async ({
    assert,
  }) => {
    const solo = destino()
    const unico = managerWith('database', { database: solo.factory })
    const error = await rejects(assert, () => unico.reconcile({ to: 'database' }), 'E_AUTHZ_STALE_SOURCE_REFUSED', 500)
    assert.notInclude(error.message, 'POR DESCARTE')
    assert.include(error.message, 'no hay ningún otro driver registrado')
    assert.equal(solo.state.calls, 0)

    const viejo = origen()
    const dos = managerWith('activo', { activo: destino().factory, viejo: viejo.factory })
    const conOtro = await rejects(assert, () => dos.reconcile({ to: 'activo' }), 'E_AUTHZ_STALE_SOURCE_REFUSED', 500)
    assert.include(conOtro.message, 'POR DESCARTE')
    assert.include(conOtro.message, 'viejo', 'y nombra el candidato')
  })

  // Cierre del auditor de alpha.10 · R4, GEMELO en roles: la misma factory bajo dos claves es el mismo driver. Con la
  // comparación por etiqueta, `--to=<alias del activo> --from=viejo` pasaba el guard (el alias no es `config.default`).
  test('cierre · R4 gemelo roles · identidad RESUELTA: alias del activo con --from ⇒ STALE sin leer; origen alias del destino ⇒ E_AUTHZ_CONFIG; alias como candidato no cuenta en el descarte', async ({
    assert,
  }) => {
    const viejo = origen()
    const activo = destino()
    const manager = managerWith('activo', { activo: activo.factory, alias: activo.factory, viejo: viejo.factory })
    const stale = await rejects(assert, () => manager.reconcile({ to: 'alias', from: 'viejo', prune: true }), 'E_AUTHZ_STALE_SOURCE_REFUSED', 500)
    assert.include(stale.message, "resuelve la MISMA factory que 'activo'")
    assert.equal(viejo.state.built + viejo.state.asked, 0, 'el origen rancio ni se construye ni se lee')
    assert.equal(activo.store.size, 0)
    const dry = await manager.reconcile({ to: 'alias', from: 'viejo', dryRun: true })
    assert.deepEqual(dry.staleSource, { to: 'alias', from: 'viejo', allowed: false })

    const otro = destino()
    const noActivo = managerWith('viejo', { viejo: viejo.factory, destino: otro.factory, destinoBis: otro.factory })
    await rejects(assert, () => noActivo.reconcile({ to: 'destino', from: 'destinoBis' }), 'E_AUTHZ_CONFIG', 500)
    assert.equal(otro.state.calls, 0, 'origen = destino bajo dos claves: no reconcilia consigo mismo')
    // Descarte: con `destinoBis` alias del destino, el ÚNICO candidato distinto es `viejo` (no «más de un origen»).
    const leidas = viejo.state.asked
    const report = await noActivo.reconcile({ to: 'destino', dryRun: true })
    assert.isUndefined(report.staleSource)
    assert.equal(viejo.state.asked, leidas + 1, 'el descarte eligió `viejo`, no el alias')
  })

  // Cierre-2 · C1 gemelo roles: el límite DECLARADO, fijado — `#sameDriver` compara la REFERENCIA de la factory.
  test('cierre-2 · C1 gemelo roles · límite DECLARADO fijado: alias con la MISMA referencia ⇒ STALE; otra arrow que construye el mismo backend ⇒ no se detecta (dry-run sin `staleSource`)', async ({
    assert,
  }) => {
    const viejo = origen()
    const activo = destino()
    const manager = managerWith('activo', { activo: activo.factory, alias: activo.factory, fga: () => activo.factory(), viejo: viejo.factory })
    await rejects(assert, () => manager.reconcile({ to: 'alias', from: 'viejo' }), 'E_AUTHZ_STALE_SOURCE_REFUSED', 500)
    const report = await manager.reconcile({ to: 'fga', from: 'viejo', dryRun: true })
    assert.isUndefined(report.staleSource, 'LÍMITE DECLARADO: dos factories distintas sobre el mismo backend no se detectan')
  })

  // Cierre del auditor de alpha.10 · ⚪ 3: el docblock de E_AUTHZ_STALE_SOURCE_REFUSED quedó ENCIMA del de otra clase
  // y la suya sin documentar. Guardia: en src/errors.ts un docblock nunca va seguido de otro docblock.
  test('cierre · ⚪ 3 · guardia: ningún docblock huérfano en src/errors.ts, y cada clase del lote lleva el suyo', async ({ assert }) => {
    const { readFile } = await import('node:fs/promises')
    const fuente = await readFile(new URL('../src/errors.ts', import.meta.url), 'utf8')
    const huerfanos = [...fuente.matchAll(/\*\/\s*\/\*\*/g)].map((m) => fuente.slice(0, m.index).split('\n').length)
    assert.deepEqual(huerfanos, [], `docblock seguido de otro docblock en las líneas ${huerfanos.join(', ')}`)
    for (const [clase, palabra] of [
      ['StaleSourceRefusedError', 'DIRECCIÓN RANCIA'],
      ['OperatorWindowExpiredError', 'ventana del OPERADOR'],
    ]) {
      const i = fuente.indexOf(`export class ${clase}`)
      const doc = fuente.slice(fuente.lastIndexOf('/**', i), i)
      assert.include(doc, palabra, `${clase} lleva SU docblock`)
      assert.notInclude(doc.slice(doc.indexOf('*/') + 2), '/**')
    }
  })

  test('`allowStaleSource: true` es la decisión humana: la pasada entra y escribe', async ({ assert }) => {
    const viejo = origen()
    const activo = destino()
    const manager = managerWith('activo', { activo: activo.factory, viejo: viejo.factory })

    const report = await manager.reconcile({ to: 'activo', from: 'viejo', allowStaleSource: true })

    assert.equal(viejo.state.asked, 1)
    assert.equal(activo.store.size, 1)
    assert.deepEqual(report.staleSource, { to: 'activo', from: 'viejo', allowed: true }, 'el reporte lo sigue diciendo')
  })

  test('`dryRun` NO lanza: lo marca en `report.staleSource` y el verificador sale ≠ 0 (una pasada así haría daño)', async ({
    assert,
  }) => {
    const viejo = origen()
    const activo = destino()
    const manager = managerWith('activo', { activo: activo.factory, viejo: viejo.factory })

    const report = await manager.reconcile({ to: 'activo', from: 'viejo', dryRun: true })

    assert.deepEqual(report.staleSource, { to: 'activo', from: 'viejo', allowed: false })
    assert.equal(activo.store.size, 0, '--dry-run sigue siendo read-only')
    const { clean, lines } = reconcileLines(report)
    assert.isFalse(clean, 'es deriva: la pasada de verdad resucitaría revocaciones')
    assert.isTrue(
      lines.some((l) => l.level === 'warning' && l.message.includes('--allow-stale-source')),
      `y la salida lo avisa con su nombre: ${JSON.stringify(lines)}`
    )
  })

  test('negativo OBLIGATORIO · el cutover LEGÍTIMO (`default` = el origen, `--to=<nuevo> --from=<activo>`) sigue funcionando y no se marca', async ({
    assert,
  }) => {
    const viejo = origen()
    const nuevo = destino()
    // El motor SIGUE sirviendo desde el origen: es el día del cutover.
    const manager = managerWith('viejo', { viejo: viejo.factory, activo: nuevo.factory })

    const report = await manager.reconcile({ to: 'activo', from: 'viejo' })

    assert.equal(viejo.state.asked, 1)
    assert.equal(nuevo.store.size, 1, 'la migración de un solo sentido de siempre')
    assert.isUndefined(report.staleSource)
    const seco = await manager.reconcile({ to: 'activo', from: 'viejo', dryRun: true })
    assert.isUndefined(seco.staleSource, 'y su verificador tampoco lo llama rancio')
  })

  /* ── La TABLA DE VERDAD del linaje (regla del dueño: el tercer defecto de un
   * linaje se arregla estructuralmente). El guard mira el ORIGEN RESUELTO, no
   * la bandera: dirección × driver activo × cómo se eligió el origen. Las filas
   * «pasa» son los negativos obligatorios (verdes antes y después); las filas
   * «NIEGA» estaban rojas con alpha.9 (sin guard), y la 8 y la 9 —sin `--from`—
   * seguían rojas con el primer guard de alpha.10, el que miraba `from`: ése es
   * el mutante estructural. ── */

  /** `fga`: hechos en su backend (`hierarchyFacts`) y sabe ser origen. `db`: sus hechos son authz_* y lee el origen por el puerto. `plano`: un destino de terceros que reconstruye desde authz_*. */
  function par() {
    const log: string[] = []
    const write = (who: string, from: string) => log.push(`${who}<-${from}`)
    const report = (to: string, facts: number, options: any) => ({
      to,
      dryRun: options.dryRun === true,
      prune: options.prune === true,
      written: facts,
      updated: 0,
      unchanged: 0,
      extra: 0,
      deleted: 0,
      phases: {
        root: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
        catalog: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
        tree: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
        facts: { written: facts, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
      },
      skipped: {},
      details: [],
      cycles: [],
      drift: { rootMarker: false, multiParent: [], roleVisibility: 0, pendingRelay: 0, deadRelay: 0 },
      massDelete: false,
    })
    const fga: any = {
      ...spyDriver(),
      capabilities: { hierarchyFacts: true, enumerateFacts: true },
      async enumerateFacts() {
        log.push('lee fga')
        return { facts: [] }
      },
      async reconcile(source: any, options: any) {
        if (source.factsOrigin?.authzTables) log.push('lee authz_*')
        else await source.facts({ limit: 100 })
        if (options.dryRun !== true) write('fga', source.factsOrigin?.name ?? '?')
        return report('fga', 0, options)
      },
    }
    const plano: any = { ...fga, capabilities: {} }
    delete plano.enumerateFacts
    const db: any = {
      ...spyDriver(),
      capabilities: { hierarchyFacts: false },
      async reconcile(source: any, options: any) {
        await source.facts({ limit: 100 })
        if (options.dryRun !== true) write('db', 'puerto')
        return report('db', 0, options)
      },
    }
    return { log, fga, db, plano }
  }

  const TABLA: Array<{ fila: string; to: string; activo: string; from?: string; niega: boolean; origen: string; drivers?: 'plano' }> = [
    { fila: '1 · mantenimiento: --to=<activo facts> sin --from (origen = él mismo)', to: 'fga', activo: 'fga', niega: false, origen: 'fga' },
    { fila: '2 · cutover inicial: --to=<nuevo> --from=<activo>', to: 'fga', activo: 'db', from: 'db', niega: false, origen: 'db' },
    { fila: '3 · cutover inicial: --to=<nuevo> sin --from (authz_*)', to: 'fga', activo: 'db', niega: false, origen: 'authz_assignments/authz_denies' },
    { fila: '4 · vuelta atrás ANTES de cambiar default: --to=db --from=<activo>', to: 'db', activo: 'fga', from: 'fga', niega: false, origen: 'fga' },
    { fila: '5 · vuelta atrás ANTES de cambiar default: --to=db sin --from (por descarte)', to: 'db', activo: 'fga', niega: false, origen: 'fga' },
    { fila: '6 · re-ejecutar la ida DESPUÉS de cambiar default: --to=<activo> --from=<otro>', to: 'fga', activo: 'fga', from: 'db', niega: true, origen: 'db' },
    { fila: '7 · re-ejecutar la vuelta DESPUÉS de cambiar default: --to=<activo> --from=<otro>', to: 'db', activo: 'db', from: 'fga', niega: true, origen: 'fga' },
    { fila: '8 · re-ejecutar la vuelta DESPUÉS de cambiar default: --to=<activo> SIN --from (por descarte)', to: 'db', activo: 'db', niega: true, origen: 'fga' },
    { fila: '9 · destino activo que reconstruye desde authz_*, SIN --from', to: 'fga', activo: 'fga', niega: true, origen: 'authz_assignments/authz_denies', drivers: 'plano' },
  ]

  for (const row of TABLA) {
    test(`tabla de verdad · ${row.fila} ⇒ ${row.niega ? 'NIEGA (E_AUTHZ_STALE_SOURCE_REFUSED, dry-run marca)' : 'pasa'}`, async ({ assert }) => {
      const { log, fga, db, plano } = par()
      const drivers = { fga: () => (row.drivers === 'plano' ? plano : fga), db: () => db }
      const manager = managerWith(row.activo, drivers)
      const options: any = { to: row.to, ...(row.from ? { from: row.from } : {}) }

      if (row.niega) {
        const error = await rejects(assert, () => manager.reconcile(options), 'E_AUTHZ_STALE_SOURCE_REFUSED', 500)
        assert.deepEqual(log, [], 'ni una lectura del origen ni una escritura en el destino')
        assert.isNull(await manager.freezeStatus(), 'ni un freeze')
        assert.include(error.message, 'resucitaría las revocaciones hechas desde el cutover')
        if (!row.from) assert.include(error.message, 'POR DESCARTE', 'sin --from, el mensaje dice de dónde saldría el origen')
        const seco = await manager.reconcile({ ...options, dryRun: true })
        assert.deepEqual(seco.staleSource, { to: row.to, from: row.origen, allowed: false }, 'el verificador lo marca con el origen RESUELTO')
        assert.isFalse(reconcileLines(seco).clean)
        const levantada = await manager.reconcile({ ...options, allowStaleSource: true })
        assert.equal(levantada.staleSource?.allowed, true, 'la decisión humana entra')
      } else {
        const report = await manager.reconcile(options)
        assert.equal(report.factsFrom, row.origen)
        assert.isUndefined(report.staleSource, 'no es la dirección rancia')
        assert.lengthOf(log.filter((l) => l.includes('<-')), 1, 'escribió')
      }
    })
  }

  test('`--from` igual a `--to` no pasa por este guard: sigue siendo el 500 E_AUTHZ_CONFIG de 3b-3b', async ({ assert }) => {
    const viejo = origen()
    const activo = destino()
    const manager = managerWith('activo', { activo: activo.factory, viejo: viejo.factory })
    // `--from` = `--to` sigue siendo el 500 E_AUTHZ_CONFIG de 3b-3b, no este.
    await rejects(assert, () => manager.reconcile({ to: 'activo', from: 'activo' }), 'E_AUTHZ_CONFIG', 500)
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * 3b-6 · El ORIGEN se lee en UNA foto consistente (🔴 3 del panel 3).
 *
 * `readSourceFacts` recorre `authz_assignments` y DESPUÉS `authz_denies`.
 * Con dos barridos sueltos, el hueco entre ambos —el tiempo de pasear la
 * primera tabla entera por lotes— deja pasar operaciones de negocio COMPUESTAS
 * (un offboarding es `revoke` + `removeDeny`): la pasada se queda con la mitad
 * de cada una y compone un estado que **no existió nunca**. El caso medido por
 * el auditor: el destino se queda con el rol SIN su deny y concede
 * `docs:write`, que ni el estado de antes ni el de después concedían — la
 * migración no pierde un permiso, **fabrica** uno, y el reporte dice
 * `clean=true`. Es una escalada, no una deriva.
 *
 * El arreglo es local y barato: los dos barridos, en la MISMA transacción de
 * lectura repetible. Lo que eso garantiza NO es lo mismo en los tres motores
 * y se declara aquí:
 *   · PostgreSQL — `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ`: foto
 *     tomada en la primera sentencia; garantía del motor.
 *   · MySQL/InnoDB — `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ` + la
 *     lectura consistente de la primera consulta. REPEATABLE READ es su
 *     default, pero se DECLARA para no depender de la config del servidor.
 *   · SQLite — no acepta nivel de aislamiento (knex avisa y lo ignora): su
 *     transacción de LECTURA ya es una foto (en WAL, el lector conserva su
 *     snapshot mientras un escritor confirma; sin WAL, el escritor espera).
 *
 * Lo que esto NO cubre, y queda declarado: la dirección cuya fuente de hechos
 * es el STORE (`enumerateFacts`, `--to=database` y la pasada de mantenimiento)
 * pagina con `Read` y **tampoco es una foto consistente**; ahí no hay
 * REPEATABLE READ que valga y la instrumentación posible es `readChanges`.
 * ════════════════════════════════════════════════════════════════════════ */

/** Motores con pool > 1: los únicos donde un SEGUNDO escritor puede existir. */
const CONCURRENT_ENGINE = testEngine() !== 'sqlite'

test.group('3b-6 · foto consistente del origen', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    await cleanSqlScopeTree(db)
    return async () => {
      await cleanAuthzTables()
      await cleanSqlScopeTree(db)
    }
  })

  test('los DOS barridos de `authz_*` leen por el MISMO cliente, y ese cliente es una transacción', async ({
    assert,
  }) => {
    // El caso estructural, que corre en los CUATRO motores (también en el
    // SQLite en memoria de `npm test`, donde no cabe un segundo escritor).
    // Mutantes que mata: leer sin transacción (`build(db)`, el código de hoy)
    // y abrir una transacción POR barrido.
    const tree = sqlScopeTree(db)
    const chain = resolveChainFrom(tree)
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] }],
    })
    const fga = new OpenFgaAuthorizationDriver({
      apiUrl: 'http://127.0.0.1:9',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      holderTypes: HOLDERS_3,
      resolveChain: chain,
      acceptScopeDriftRisk: true,
      logger: { warn: () => {} },
    })

    const clientes: any[] = []
    const original = (fga as any).eachRow.bind(fga)
    ;(fga as any).eachRow = async (client: any, ...rest: any[]) => {
      clientes.push(client)
      return original(client, ...rest)
    }
    const ctx = {
      note: () => {},
      usable: () => true,
      chainOf: () => null,
      want: () => {},
      forbidden: new Set<string>(),
    }
    // Solo la lectura del origen: no se toca el store (no hay servidor aquí).
    await (fga as any).readSourceFacts(await (fga as any).catalog.view(), 100, new Date(), ctx)

    assert.lengthOf(clientes, 2, 'son dos barridos: asignaciones y denies')
    assert.isTrue(
      clientes[0]?.isTransaction === true,
      `el origen tiene que leerse dentro de una transacción y llegó ${String(clientes[0]?.isTransaction)}`
    )
    assert.strictEqual(clientes[0], clientes[1], 'los dos barridos tienen que compartir la MISMA foto')
  })
})

if (openFgaTestUrl && CONCURRENT_ENGINE) {
  const apiUrl: string = openFgaTestUrl

  test.group('3b-6 · foto consistente del origen (servidor real + segundo escritor)', (group) => {
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

    /** Zoe con el rol Y su deny: hoy NO puede escribir. Y un store vacío al lado. */
    async function offboardingSetup() {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const tree = sqlScopeTree(db)
      const chain = resolveChainFrom(tree)
      await syncAuthzCatalog({
        permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
        roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read', 'docs:write'] }],
      })
      const org = { type: 'organization', uuid: uuidv7() }
      await tree.attach(org, APP_SCOPE)

      const database = new DatabaseAuthorizationDriver({ resolveChain: chain })
      const zoe = { type: 'users', uuid: uuidv7() }
      await database.grant(zoe, 'org-editor', org, {})
      await database.deny(zoe, 'docs:write', org)
      // Ada no se va: sin ella el origen se quedaría sin UNA sola fila de
      // hechos tras el offboarding y `--prune` se negaría (origen ciego), que
      // es otro seguro y no lo que este caso mide.
      const ada = { type: 'users', uuid: uuidv7() }
      await database.grant(ada, 'org-editor', org, {})

      const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `snapshot-${Date.now()}` })
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
      const source = { enumerateEdges: edgesOfDemoScopes(), resolveChain: chain }
      return { tree, chain, database, fga, source, org, zoe, ada }
    }

    test('el offboarding COMPLETO entre los dos barridos no FABRICA un permiso en el destino', async ({
      assert,
    }) => {
      const { database, fga, source, org, zoe, ada } = await offboardingSetup()
      assert.isFalse(await database.authorize(zoe, 'docs:write', org), 'ANTES: el deny explícito gana')
      assert.isTrue(await database.authorize(zoe, 'docs:read', org), 'ANTES: el rol concede lo demás')

      // El hueco entre los dos barridos, hecho DETERMINISTA (sin sleeps, sin
      // carrera): en cuanto termina el de `authz_assignments`, RR.HH. hace el
      // offboarding entero desde OTRA conexión — `revoke` + `removeDeny`, dos
      // escrituras de UNA operación de negocio.
      let offboardings = 0
      const original = (fga as any).eachRow.bind(fga)
      ;(fga as any).eachRow = async (...args: any[]) => {
        const result = await original(...args)
        // La operación es el 2.º argumento tras el cliente (o el 1.º sin él).
        const operation = args.find((a) => typeof a === 'string')
        if (operation === 'reconcile.assignments' && offboardings === 0) {
          offboardings += 1
          await database.revoke(zoe, 'org-editor', org)
          await database.removeDeny(zoe, 'docs:write', org)
        }
        return result
      }

      const report = await fga.reconcile!(source, {})
      assert.equal(offboardings, 1, 'el offboarding tiene que haber caído ENTRE los dos barridos')

      // DESPUÉS, en el origen: ni antes ni después concedió `docs:write`.
      assert.isFalse(await database.authorize(zoe, 'docs:write', org), 'el origen sigue sin conceder docs:write')
      // Y el destino tampoco puede concederlo: la pasada compone un estado
      // que existió (el de `t0`, con rol Y deny), no dos mitades de dos.
      assert.isFalse(
        await fga.authorize(zoe, 'docs:write', org),
        `la migración FABRICÓ un permiso que nadie concedió (reporte: written=${report.written} ` +
          `extra=${report.extra} skipped=${JSON.stringify(report.skipped)})`
      )

      // Lo que SÍ queda es la deriva recuperable que ya estaba declarada: el
      // destino tiene el estado de `t0` (rol + deny), y una segunda pasada lo
      // pone al día. Eso es «atrasado», no «inventado».
      assert.isTrue(await fga.authorize(zoe, 'docs:read', org), 'el destino se queda en el estado de t0')
      const segunda = await fga.reconcile!(source, { prune: true })
      assert.isAbove(segunda.deleted, 0, 'la deriva de la ventana se repara repitiendo la pasada')
      assert.isFalse(await fga.authorize(zoe, 'docs:read', org))
      assert.isFalse(await fga.authorize(zoe, 'docs:write', org))
      assert.equal(
        await fga.authorize(zoe, 'docs:write', org),
        await database.authorize(zoe, 'docs:write', org),
        'y queda a la par del driver database'
      )
      assert.isTrue(await fga.authorize(ada, 'docs:read', org), 'quien no se fue conserva lo suyo')
    })
  })
}


/* ════════════════════════════════════════════════════════════════════════
 * 2.4.0-alpha.9 · B · S1 — **la lista blanca de tipos que el reconcile de
 * hechos GOBIERNA**, sin servidor. Es la guardia que mata al mutante «usa
 * `RESERVED_FACTS_TYPES` tal cual»: son DOS conjuntos con nombres parecidos
 * y propósitos distintos —«nadie puede declarar esto» vs. «esto lo gobierna
 * esta pasada»—, y el segundo NO lleva `group`, que es de relaciones.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('alpha.9 · B · los tipos que el reconcile de hechos gobierna', () => {
  test('la lista blanca es EXPLÍCITA, congelada y NO es `RESERVED_FACTS_TYPES`', ({ assert }) => {
    assert.deepEqual([...OWN_FACTS_OBJECT_TYPES].sort(), ['deny_binding', 'role', 'role_binding', 'scope'])
    assert.isFalse(
      OWN_FACTS_OBJECT_TYPES.has(FACTS_GROUP_TYPE),
      'reutilizar RESERVED_FACTS_TYPES reproduce el 🔴: `group` es el tipo de usersets de relaciones'
    )
    assert.isTrue(RESERVED_FACTS_TYPES.has(FACTS_GROUP_TYPE), 'son DOS conjuntos distintos, con nombres parecidos')
    // Y lo PROPIO es un subconjunto de lo reservado: un tipo nuevo del modelo
    // `facts` entra en las dos listas en el MISMO commit — si no,
    // `defineRelationsConfig` dejaría declararlo y esta pasada lo borraría.
    for (const type of OWN_FACTS_OBJECT_TYPES) {
      assert.isTrue(RESERVED_FACTS_TYPES.has(type), `${type} tiene que estar también en RESERVED_FACTS_TYPES`)
    }
  })

  test('y al revés: TODO tipo de objeto del modelo `facts` publicado está gobernado — un tipo nuevo que entre en RESERVED pero no en OWN quedaría sin gobernar para siempre (⚪ C del auditor de alpha.9)', ({ assert }) => {
    const holders = { users: 'user', bots: 'integration' }
    const model = openFgaFactsModel(holders, ['docs:read', 'docs:write'])
    const holderTypes = new Set(Object.values(holders))
    const gobernados = (model.type_definitions as Array<{ type: string }>)
      .map((definition) => definition.type)
      .filter((type) => !holderTypes.has(type))
    assert.isNotEmpty(gobernados)
    for (const type of gobernados) {
      assert.isTrue(
        OWN_FACTS_OBJECT_TYPES.has(type),
        `el modelo publica objetos de tipo '${type}' y esta pasada no lo gobierna: sus tuplas nunca se limpiarían ` +
          `(añádelo a OWN_FACTS_OBJECT_TYPES y a RESERVED_FACTS_TYPES en el mismo commit)`
      )
    }
    // Y el complemento: lo que el generador añade por RELACIONES no es nuestro.
    const fusionado = openFgaFactsModel(holders, ['docs:read'], {
      objectTypes: [{ type: 'document', relations: [{ name: 'viewer' }] }],
    } as any)
    const deRelaciones = (fusionado.type_definitions as Array<{ type: string }>)
      .map((definition) => definition.type)
      .filter((type) => !holderTypes.has(type) && !gobernados.includes(type))
    assert.includeMembers(deRelaciones, ['document'], 'el generador fusiona los tipos del consumidor')
    for (const type of deRelaciones) {
      assert.isFalse(OWN_FACTS_OBJECT_TYPES.has(type), `'${type}' es de relaciones: esta pasada NO puede borrarlo`)
    }
  })
})