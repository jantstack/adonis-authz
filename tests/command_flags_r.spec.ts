/**
 * **Lote R (plan 2.5) · los mutantes de banderas que estaban VIVOS** — los casos
 * que faltaban para que `scripts/check_flag_mutants.mjs` salga en verde.
 *
 * Medido sobre `0fbee6e` (alpha.10) con el mutante «bandera inerte» del harness
 * (`AUTHZ_INERT_FLAG`, `tests/helpers/ace.ts`): 36 banderas booteadas, 27 con un caso
 * que muere y **9 vivas** — `openfga:provision --url/--store-id/--name` (sin servidor),
 * `authz:catalog:sync --keep-links`, `authz:scopes:requeue --force`, `authz:reconcile
 * --from`, `authz:relations:reconcile --from/--prune/--allow-mass-delete`. Son las 7
 * «sin caso» y las presencias por reforzar del tester del panel de metodología
 * (§M2), con la receta que él mismo dio para `--from`: **tres drivers** en vez de
 * una exención (con dos, el origen se infiere por descarte y el mutante es
 * EQUIVALENTE).
 *
 * Las mismas reglas que `command_flags.spec.ts`: toda bandera entra por
 * `exec(['--<bandera>'])` del kernel de ace de verdad y se afirma el EFECTO (lo
 * que llegó a la red, lo que quedó en `authz_*`, lo que el doble escribió o borró,
 * el exit y la letra), o —donde el efecto es caro— las OPCIONES que llegan al
 * manager. Nunca `cmd.<prop>`. Lo que se sustituye del manager global es el
 * CABLEADO (qué manager), nunca el camino de la bandera.
 */

import { test } from '@japa/runner'
import db from '@adonisjs/lucid/services/db'
import { aceFor, fgaStub } from './helpers/ace.js'
import type { FgaStub } from './helpers/ace.js'
import authorization from '../services/main.js'
import { AuthorizationManager } from '../src/manager.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'
import OpenFgaProvision from '../commands/openfga_provision.js'
import AuthzCatalogSync from '../commands/authz_catalog_sync.js'
import AuthzScopesRequeue from '../commands/authz_scopes_requeue.js'
import AuthzReconcile from '../commands/authz_reconcile.js'
import AuthzRelationsReconcile from '../commands/authz_relations_reconcile.js'

/* ── El cableado (copiado de command_flags.spec.ts: es privado allí a propósito) ── */

function patchManager(method: string, impl: (...args: any[]) => any): () => void {
  const target: any = authorization
  const had = Object.prototype.hasOwnProperty.call(target, method)
  const previous = had ? Object.getOwnPropertyDescriptor(target, method) : undefined
  Object.defineProperty(target, method, { value: impl, writable: true, configurable: true, enumerable: false })
  return () => {
    if (previous) Object.defineProperty(target, method, previous)
    else delete target[method]
  }
}

function patchRelations(authorizationConfig: any): () => void {
  const fixture = new AuthorizationManager({
    default: authorizationConfig?.default ?? 'database',
    drivers: {},
    ...(authorizationConfig?.relations ? { relations: authorizationConfig.relations } : {}),
    warnOnOptInSecurity: false,
  } as any)
  const undo = ['relationsDriverKey', 'relationsDriverKeys', 'relationsDriverFactory'].map((method) =>
    patchManager(method, (...args: any[]) => (fixture as any)[method](...args))
  )
  return () => undo.reverse().forEach((restore) => restore())
}

async function relationsAce(options: { authorization?: any }) {
  const ace = await aceFor(AuthzRelationsReconcile, options)
  return {
    ...ace,
    async exec(argv: string[] = []) {
      const restore = patchRelations(options.authorization)
      try {
        return await ace.exec(argv)
      } finally {
        restore()
      }
    },
  }
}

function spyManager(method: string, reply: any = undefined) {
  const seen: any[] = []
  const restore = patchManager(method, async (...args: any[]) => {
    seen.push(args)
    return typeof reply === 'function' ? reply(...args) : reply
  })
  return { seen, restore }
}

/**
 * Un destino de roles que apunta lo que recibe (el `source` con `factsOrigin`
 * incluido) y LEE una página de hechos: la resolución del origen por descarte es
 * PEREZOSA (`#factsEnumerator`), así que un destino que no lea nunca sabría que
 * había dos candidatos.
 */
function destinoQueApunta() {
  const seen: any[] = []
  const driver: any = {
    authorize: async () => false,
    async reconcile(source: any, options: any) {
      const page = await source.facts({ limit: 100 })
      seen.push({ source, options, page })
      const zero = { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 }
      return {
        to: 'destino', dryRun: options.dryRun === true, prune: options.prune === true,
        ...zero, phases: { root: zero, catalog: zero, tree: zero, facts: zero },
        skipped: {}, details: [], cycles: [],
        drift: { rootMarker: false, multiParent: [], roleVisibility: 0, pendingRelay: 0, deadRelay: 0 }, massDelete: false,
      }
    },
  }
  return { driver, seen }
}

/** El doble de relaciones del auditor (S1): un driver con su «store», que apunta escrituras y borrados. */
const APP = { type: 'app', uuid: null }
const share = (uuid: string, doc: string) => ({
  subject: { type: 'user', uuid },
  relation: 'viewer',
  object: { type: 'document', id: doc },
  partition: APP,
  expiresAt: null,
})
const key = (t: any) => `${t.object.type}:${t.object.id}#${t.relation}@${t.subject.type}:${t.subject.uuid}`
function relationsDouble(initial: any[]) {
  const tuples = new Map<string, any>(initial.map((t) => [key(t), t]))
  const writes: string[] = []
  const deletes: string[] = []
  const driver: any = {
    capabilities: { enumerateRelations: true, expiry: true },
    async enumerateRelations() {
      return { tuples: [...tuples.values()], cursor: null }
    },
    async relate(subject: any, relation: string, object: any, partition: any) {
      const t = { subject, relation, object, partition, expiresAt: null }
      tuples.set(key(t), t)
      writes.push(key(t))
    },
    async unrelate(subject: any, relation: string, object: any, partition: any) {
      const k = key({ subject, relation, object, partition })
      tuples.delete(k)
      deletes.push(k)
    },
  }
  return { driver, tuples, writes, deletes }
}

const resetFreezeRow = async (): Promise<void> => {
  await db.from('authz_catalog_version').where('id', 2).update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null })
}

/* ══════════════════════════════════════════════════════════════════════════
 * R-1/R-2 · `openfga:provision --store-id` y `--name` SIN servidor: el stub
 * mudo dice a qué URL y con qué cuerpo llegó la request. Hasta aquí `--store-id`
 * solo tenía caso con `OPENFGA_TEST_URL` (B-2), o sea vivo en el job sin servidor.
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('lote R · `openfga:provision --store-id/--name` por el kernel, sin servidor', (group) => {
  let stub: FgaStub
  group.setup(async () => {
    stub = await fgaStub()
  })
  group.teardown(async () => stub.close())
  group.each.setup(() => {
    stub.seen.length = 0
  })
  const config = () => ({
    holderTypes: { users: 'user' },
    catalogs: [async () => ({ permissions: [{ slug: 'posts.read' }] })],
    openfga: { url: stub.url, storeName: 'nombre-del-config' },
  })

  test('R-1 · `--store-id=<id>` escribe el modelo en ESE store (POST /stores/<id>/authorization-models), no crea otro (POST /stores)', async ({
    assert,
  }) => {
    const run = await (await aceFor(OpenFgaProvision, { authorization: config() })).exec(['--store-id=01ARZ3NDEKTSV4RRFFQ69G5FAV'])
    assert.isDefined(run.error, 'el stub responde 400: el comando termina en error, lo que se juzga es la request')
    assert.lengthOf(stub.seen, 1)
    assert.equal(stub.seen[0].method, 'POST')
    assert.equal(stub.seen[0].url, '/stores/01ARZ3NDEKTSV4RRFFQ69G5FAV/authorization-models', 'con --store-id inerte iría a POST /stores (crear otro store)')
  })

  test('R-2 · `--name=<n>` es el nombre del store que se crea (cuerpo de POST /stores); sin la bandera manda `openfga.storeName`', async ({
    assert,
  }) => {
    const conBandera = await (await aceFor(OpenFgaProvision, { authorization: config() })).exec(['--name=nombre-de-la-bandera'])
    assert.isDefined(conBandera.error)
    assert.lengthOf(stub.seen, 1)
    assert.equal(stub.seen[0].url, '/stores')
    assert.equal(JSON.parse(stub.seen[0].body).name, 'nombre-de-la-bandera', 'el nombre que viaja es el de --name')

    stub.seen.length = 0
    const sinBandera = await (await aceFor(OpenFgaProvision, { authorization: config() })).exec([])
    assert.isDefined(sinBandera.error)
    assert.equal(JSON.parse(stub.seen[0].body).name, 'nombre-del-config')
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * R-3 · `authz:catalog:sync --keep-links`: el vínculo que el spec ya no lista
 * SOBREVIVE con la bandera y se poda sin ella (lo observable es `authz_role_permissions`).
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('lote R · `authz:catalog:sync --keep-links` por el kernel, con EFECTO en authz_*', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    return cleanAuthzTables
  })

  async function vinculosDe(slug: string): Promise<number> {
    const rows: any[] = await db
      .from('authz_role_permissions')
      .join('authz_roles', 'authz_roles.uuid', 'authz_role_permissions.role_uuid')
      .where('authz_roles.slug', slug)
      .select('authz_role_permissions.uuid')
    return rows.length
  }

  test('R-3 · con el rol vinculado a DOS permisos en la base y un spec que solo lista uno: `--keep-links` deja 2, sin la bandera queda 1', async ({
    assert,
  }) => {
    const catalogs = [
      async () => ({
        permissions: [{ slug: 'r.p1' }, { slug: 'r.p2' }],
        roles: [{ slug: 'r-role', scopeType: 'organization', permissions: ['r.p1'] }],
      }),
    ]
    for (const [argv, esperado] of [
      [['--keep-links'], 2],
      [[], 1],
    ] as const) {
      await cleanAuthzTables()
      await syncAuthzCatalog({
        permissions: [{ slug: 'r.p1' }, { slug: 'r.p2' }],
        roles: [{ slug: 'r-role', scopeType: 'organization', permissions: ['r.p1', 'r.p2'] }],
      })
      assert.equal(await vinculosDe('r-role'), 2, 'siembra: dos vínculos')

      const run = await (await aceFor(AuthzCatalogSync, { authorization: { catalogs } })).exec([...argv])

      assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
      assert.equal(run.exitCode ?? 0, 0, JSON.stringify(run.logs))
      assert.equal(await vinculosDe('r-role'), esperado, `${argv.join(' ') || '(sin bandera)'}: ${JSON.stringify(run.logs)}`)
      const texto = run.logs.join('\n')
      if (esperado === 2) assert.include(texto, 'sin poda de vínculos', 'la salida dice qué rama corrió (punto 7)')
      else assert.notInclude(texto, 'sin poda de vínculos')
    }
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * R-4 · `authz:scopes:requeue --force` llega al manager (el borde donde se consume).
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('lote R · `authz:scopes:requeue --force` por el kernel', (group) => {
  const restores: Array<() => void> = []
  group.each.setup(() => async () => {
    while (restores.length) restores.pop()!()
  })

  test('R-4 · `--id=12 --force` ⇒ `requeueScopeChanges([12], { force: true })`; sin la bandera, `force: false`', async ({ assert }) => {
    const spy = spyManager('requeueScopeChanges', { requeued: [], overrides: [], forced: false })
    restores.push(spy.restore)

    const con = await (await aceFor(AuthzScopesRequeue)).exec(['--id=12', '--force'])
    assert.isUndefined(con.error, `${con.error?.constructor?.name}: ${con.error?.message}`)
    assert.lengthOf(spy.seen, 1)
    assert.deepEqual(spy.seen[0][0], [12])
    assert.isTrue(spy.seen[0][1].force, '--force es la decisión de revertir el store a sabiendas: tiene que LLEGAR')

    const sin = await (await aceFor(AuthzScopesRequeue)).exec(['--id=12'])
    assert.isUndefined(sin.error)
    assert.lengthOf(spy.seen, 2)
    assert.isFalse(spy.seen[1][1].force)
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * R-5/R-6 · `--from` con TRES drivers (la receta del tester): sin la bandera no
 * hay descarte posible y los dos comandos lo dicen; con ella, el origen es el pedido.
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('lote R · `--from` con TRES drivers registrados (sin descarte posible)', (group) => {
  const restores: Array<() => void> = []
  group.each.setup(async () => {
    await resetFreezeRow()
    return async () => {
      while (restores.length) restores.pop()!()
      await resetFreezeRow()
    }
  })

  test('R-5 · `authz:reconcile --to=destino --from=origen2` ⇒ el origen que llega al destino es origen2; sin `--from` ⇒ 500 E_AUTHZ_CONFIG y cero llamadas', async ({
    assert,
  }) => {
    const destino = destinoQueApunta()
    const origen = (name: string) => () =>
      ({
        authorize: async () => false,
        withClock() {
          return this
        },
        async enumerateFacts() {
          return { facts: [{ origen: name }], cursor: null, skipped: [] }
        },
      }) as any
    const manager = new AuthorizationManager({
      default: 'origen1',
      drivers: { origen1: origen('origen1'), origen2: origen('origen2'), destino: () => destino.driver },
      scopes: { resolveChain: resolveChainFrom(memoryScopeTree()), enumerateEdges: async () => ({ edges: [], cursor: null }) },
      warnOnOptInSecurity: false,
    } as any)
    restores.push(patchManager('reconcile', (options: any) => manager.reconcile(options)))

    const con = await (await aceFor(AuthzReconcile)).exec(['--to=destino', '--from=origen2'])
    assert.isUndefined(con.error, `${con.error?.constructor?.name}: ${con.error?.message}`)
    assert.lengthOf(destino.seen, 1, JSON.stringify(con.logs))
    assert.equal(destino.seen[0].source.factsOrigin?.name, 'origen2', 'el ORIGEN resuelto es el de --from')
    assert.deepEqual(destino.seen[0].page.facts, [{ origen: 'origen2' }], 'y los hechos que llegan son los de origen2')

    const sin = await (await aceFor(AuthzReconcile)).exec(['--to=destino'])
    assert.equal(sin.error?.code, 'E_AUTHZ_CONFIG', `sin --from con dos candidatos no hay descarte: ${sin.error?.message}`)
    assert.lengthOf(destino.seen, 1, 'cero llamadas nuevas al destino')
  })

  test('R-6 · `authz:relations:reconcile --to=destino --from=origen2` ⇒ se escriben las tuplas de origen2; sin `--from` ⇒ exit 1 «No se puede elegir el ORIGEN» y cero escrituras', async ({
    assert,
  }) => {
    const origen1 = relationsDouble([share('u1', 'd-de-origen1')])
    const origen2 = relationsDouble([share('u2', 'd-de-origen2')])
    const destino = relationsDouble([])
    const ace = await relationsAce({
      authorization: {
        default: 'origen1',
        relations: { drivers: { origen1: () => origen1.driver, origen2: () => origen2.driver, destino: () => destino.driver } },
      },
    })

    const con = await ace.exec(['--to=destino', '--from=origen2'])
    assert.isUndefined(con.error, `${con.error?.constructor?.name}: ${con.error?.message}`)
    assert.equal(con.exitCode ?? 0, 0, JSON.stringify(con.logs))
    assert.deepEqual(destino.writes, [key(share('u2', 'd-de-origen2'))], 'lo escrito viene de origen2, no de origen1')

    const sin = await ace.exec(['--to=destino'])
    assert.equal(sin.exitCode, 1)
    assert.include(sin.logs.join('\n'), 'No se puede elegir el ORIGEN solo: hay 2 candidatos')
    assert.lengthOf(destino.writes, 1, 'cero escrituras nuevas')
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * R-7/R-8 · `authz:relations:reconcile --prune` y `--allow-mass-delete`, con EFECTO
 * sobre el store del doble (la gemela de M2-b y de A-6 en relaciones).
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('lote R · `authz:relations:reconcile --prune` / `--allow-mass-delete` por el kernel, con EFECTO', (group) => {
  group.each.setup(async () => {
    await resetFreezeRow()
    return resetFreezeRow
  })

  test('R-7 · la tupla SOBRANTE del destino se borra con `--prune`; sin la bandera se queda y la salida lo avisa', async ({ assert }) => {
    const vigente = share('u1', 'd1')
    const sobrante = share('u9', 'd-sobrante')
    for (const [argv, borrada] of [
      [['--to=destino', '--from=origen', '--prune'], true],
      [['--to=destino', '--from=origen'], false],
    ] as const) {
      const origen = relationsDouble([vigente])
      const destino = relationsDouble([vigente, sobrante])
      const ace = await relationsAce({
        authorization: { default: 'origen', relations: { drivers: { origen: () => origen.driver, destino: () => destino.driver } } },
      })
      const run = await ace.exec([...argv])
      assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
      assert.equal(run.exitCode ?? 0, 0, JSON.stringify(run.logs))
      assert.deepEqual(destino.deletes, borrada ? [key(sobrante)] : [], `${argv.join(' ')}: ${JSON.stringify(run.logs)}`)
      assert.equal(destino.tuples.has(key(sobrante)), !borrada)
      if (!borrada) assert.include(run.logs.join('\n'), '--prune', 'sin la bandera, la salida nombra --prune (sobra 1)')
    }
  })

  test('R-8 · origen VACÍO + destino lleno + `--prune` ⇒ exit 1 E_AUTHZ_MASS_RECONCILE_REFUSED y nada borrado; con `--allow-mass-delete` se vacía', async ({
    assert,
  }) => {
    const t = share('u1', 'd1')
    for (const [argv, vaciado] of [
      [['--to=destino', '--from=origen', '--prune'], false],
      [['--to=destino', '--from=origen', '--prune', '--allow-mass-delete'], true],
    ] as const) {
      const origen = relationsDouble([])
      const destino = relationsDouble([t])
      const ace = await relationsAce({
        authorization: { default: 'origen', relations: { drivers: { origen: () => origen.driver, destino: () => destino.driver } } },
      })
      const run = await ace.exec([...argv])
      assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
      if (vaciado) {
        // El EFECTO: la decisión humana levanta el seguro y la tupla se borra. Y desde el lote A
        // (F-R2, linaje L8) la LETRA dice eso mismo —«se LEVANTÓ … se han borrado 1»— y sale 0,
        // en vez de «borraría … En una pasada real es 500» con exit 1 sobre una pasada que YA borró.
        assert.deepEqual(destino.deletes, [key(t)], `la decisión humana levanta el seguro y la tupla se borra: ${JSON.stringify(run.logs)}`)
        assert.isFalse(destino.tuples.has(key(t)))
        assert.equal(run.exitCode ?? 0, 0, `F-R2: la pasada que borró a sabiendas sale 0: ${JSON.stringify(run.logs)}`)
        assert.include(run.logs.join('\n'), 'se LEVANTÓ con --allow-mass-delete: se han borrado 1 tupla(s)')
        assert.notInclude(run.logs.join('\n'), 'En una pasada real es 500', 'la letra no puede describir como hipótesis lo que acaba de hacer')
      } else {
        assert.equal(run.exitCode, 1, JSON.stringify(run.logs))
        assert.include(run.logs.join('\n'), 'no ha aportado NI UNA utilizable', 'la letra del seguro de borrado masivo')
        assert.deepEqual(destino.deletes, [], 'el seguro de borrado masivo: cero borrados')
      }
    }
  })
})
