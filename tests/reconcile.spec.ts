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

  test('sin --prune, los hechos de un scope muerto llevan la receta al lado', ({ assert }) => {
    const { lines } = reconcileLines(base({ skipped: { 'unknown-scope': 3 } }))
    assert.isTrue(lines.some((l) => l.message.includes('--prune')))
    const conPrune = reconcileLines(base({ prune: true, skipped: { 'unknown-scope': 3 } }))
    assert.isFalse(conPrune.lines.some((l) => l.message.includes('repite con --prune')))
  })
})
